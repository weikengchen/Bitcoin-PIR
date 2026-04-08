//! Mmap page residency monitoring and warmup.
//!
//! Uses the `mincore()` syscall to check how many pages of each memory-mapped
//! region are resident in RAM, and optionally touches every page to force them
//! into the page cache before the server starts accepting connections.

use std::io::{self, Write};
use std::sync::OnceLock;
use std::time::Instant;

/// A memory-mapped region to monitor or warm up.
pub struct MmapRegion {
    pub name: String,
    pub ptr: *const u8,
    pub len: usize,
    /// Warmup priority: lower = higher priority (warmed up first).
    pub priority: u32,
}

// SAFETY: The raw pointers come from `memmap2::Mmap` objects that live for the
// entire process lifetime (either in `MappedDatabase` behind an `Arc`, or moved
// into the OnionPIR worker thread). They are only used for read-only operations
// (`mincore`, `read_volatile`).
unsafe impl Send for MmapRegion {}
unsafe impl Sync for MmapRegion {}

fn page_size() -> usize {
    static PS: OnceLock<usize> = OnceLock::new();
    *PS.get_or_init(|| {
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if ps > 0 { ps as usize } else { 4096 }
    })
}

/// Check how many pages of a region are resident in RAM.
/// Returns `(resident_pages, total_pages)`.
pub fn page_residency(region: &MmapRegion) -> io::Result<(usize, usize)> {
    if region.len == 0 {
        return Ok((0, 0));
    }
    let ps = page_size();
    let total_pages = (region.len + ps - 1) / ps;
    // macOS mincore takes *mut c_char; libc crate reflects this per-platform.
    let mut vec: Vec<libc::c_char> = vec![0; total_pages];

    let ret = unsafe {
        libc::mincore(
            region.ptr as *mut libc::c_void,
            region.len,
            vec.as_mut_ptr(),
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let resident = vec.iter().filter(|&&b| (b & 1) != 0).count();
    Ok((resident, total_pages))
}

/// Print per-file and aggregate residency percentages.
pub fn report_residency(regions: &[MmapRegion]) {
    let ps = page_size();
    let mut total_resident = 0usize;
    let mut total_pages = 0usize;

    println!("[residency]");
    for region in regions {
        match page_residency(region) {
            Ok((resident, pages)) => {
                total_resident += resident;
                total_pages += pages;
                let pct = if pages > 0 { 100.0 * resident as f64 / pages as f64 } else { 0.0 };
                let resident_gb = resident as f64 * ps as f64 / 1e9;
                let total_gb = pages as f64 * ps as f64 / 1e9;
                println!("  {:40} {:5.1}%  ({:.2} / {:.2} GB)",
                    region.name, pct, resident_gb, total_gb);
            }
            Err(e) => {
                println!("  {:40} error: {}", region.name, e);
            }
        }
    }
    if total_pages > 0 {
        let pct = 100.0 * total_resident as f64 / total_pages as f64;
        let resident_gb = total_resident as f64 * ps as f64 / 1e9;
        let total_gb = total_pages as f64 * ps as f64 / 1e9;
        println!("  {:40} {:5.1}%  ({:.2} / {:.2} GB)",
            "TOTAL", pct, resident_gb, total_gb);
    }
}

/// Sequentially touch every page in every region to force them into the page cache.
/// Reports progress per-file and overall with throughput.
/// Regions are sorted by priority (lower = warmed first).
pub fn warmup_regions(regions: &mut [MmapRegion]) {
    // Sort by priority so high-priority regions warm up first
    regions.sort_by_key(|r| r.priority);

    let ps = page_size();
    let total_bytes: usize = regions.iter().map(|r| r.len).sum();
    let total_pages = (total_bytes + ps - 1) / ps;
    let mut pages_touched = 0usize;

    println!("[warmup] Warming {:.2} GB across {} regions...",
        total_bytes as f64 / 1e9, regions.len());
    let global_start = Instant::now();

    // Progress every ~256 MB (65536 pages at 4K)
    let progress_interval = 65536usize;

    for region in regions.iter() {
        let pages = (region.len + ps - 1) / ps;
        let region_start = Instant::now();

        for i in 0..pages {
            unsafe {
                std::ptr::read_volatile(region.ptr.add(i * ps));
            }
            pages_touched += 1;

            if pages_touched % progress_interval == 0 {
                let elapsed = global_start.elapsed().as_secs_f64();
                let touched_gb = pages_touched as f64 * ps as f64 / 1e9;
                let total_gb = total_bytes as f64 / 1e9;
                let rate = if elapsed > 0.0 { touched_gb / elapsed } else { 0.0 };
                print!("\r[warmup] {}: {:.1} / {:.1} GB  ({:.1}%)  {:.2} GB/s   ",
                    region.name,
                    touched_gb, total_gb,
                    100.0 * pages_touched as f64 / total_pages as f64,
                    rate);
                let _ = io::stdout().flush();
            }
        }

        let region_elapsed = region_start.elapsed();
        let region_gb = region.len as f64 / 1e9;
        let rate = if region_elapsed.as_secs_f64() > 0.0 {
            region_gb / region_elapsed.as_secs_f64()
        } else { 0.0 };
        println!("\r[warmup] {}: {:.2} GB in {:.1?} ({:.2} GB/s)                ",
            region.name, region_gb, region_elapsed, rate);
    }

    let total_elapsed = global_start.elapsed();
    let total_gb = total_bytes as f64 / 1e9;
    let rate = if total_elapsed.as_secs_f64() > 0.0 {
        total_gb / total_elapsed.as_secs_f64()
    } else { 0.0 };
    println!("[warmup] All regions warmed: {:.2} GB in {:.1?} ({:.2} GB/s avg)",
        total_gb, total_elapsed, rate);
}

/// Build a JSON string with per-region residency data.
/// Hand-built (no serde) to match the existing codebase pattern.
pub fn residency_json(regions: &[MmapRegion]) -> String {
    let ps = page_size();
    let mut total_size = 0usize;
    let mut total_resident_bytes = 0usize;

    let mut entries = Vec::new();
    for region in regions {
        let (resident, pages) = page_residency(region).unwrap_or((0, 0));
        let size = pages * ps;
        let resident_bytes = resident * ps;
        total_size += size;
        total_resident_bytes += resident_bytes;
        let pct = if pages > 0 { 100.0 * resident as f64 / pages as f64 } else { 0.0 };
        entries.push(format!(
            "{{\"name\":\"{}\",\"size\":{},\"resident\":{},\"pct\":{:.1}}}",
            region.name, size, resident_bytes, pct
        ));
    }

    let total_pct = if total_size > 0 {
        100.0 * total_resident_bytes as f64 / total_size as f64
    } else { 0.0 };

    format!(
        "{{\"page_size\":{},\"regions\":[{}],\"total_size\":{},\"total_resident\":{},\"total_pct\":{:.1}}}",
        ps,
        entries.join(","),
        total_size,
        total_resident_bytes,
        total_pct,
    )
}
