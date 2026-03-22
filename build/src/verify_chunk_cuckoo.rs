//! Verification for chunk-level Batch PIR cuckoo tables.
//!
//! Loads `chunk_pir_cuckoo.bin`, validates the header, then verifies that
//! every chunk_id (0..N) can be found in the cuckoo table of at least one
//! of its 3 assigned buckets.
//!
//! Usage:
//!   cargo run --release -p build --bin verify_chunk_cuckoo

mod common;

use common::*;
use memmap2::Mmap;
use std::fs::File;
use std::time::Instant;

const EMPTY: u32 = u32::MAX;

/// Number of random lookups for quick verification
const NUM_VERIFY: usize = 1_000_000;

// ─── Helpers ─────────────────────────────────────────────────────────────────

#[inline]
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[inline]
fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Check whether `chunk_id` is in one of its assigned buckets' cuckoo tables.
fn lookup_in_bucket(
    cuckoo_data: &[u8],
    bucket_id: usize,
    chunk_id: u32,
    bins_per_table: usize,
    cuckoo_bucket_size: usize,
    num_cuckoo_hashes: usize,
) -> bool {
    let slots_per_table = bins_per_table * cuckoo_bucket_size;
    let table_offset = CHUNK_HEADER_SIZE + bucket_id * slots_per_table * 4;

    for h in 0..num_cuckoo_hashes {
        let key = derive_chunk_cuckoo_key(bucket_id, h);
        let bin = cuckoo_hash_int(chunk_id, key, bins_per_table);
        let base = table_offset + bin * cuckoo_bucket_size * 4;
        for s in 0..cuckoo_bucket_size {
            let val = read_u32(cuckoo_data, base + s * 4);
            if val == chunk_id {
                return true;
            }
            if val == EMPTY {
                break;
            }
        }
    }

    false
}

fn main() {
    println!("=== Chunk PIR Cuckoo Table Verification ===");
    println!();

    let start = Instant::now();

    // ── Load the cuckoo file ─────────────────────────────────────────────
    println!("[1] Loading cuckoo file: {}", CHUNK_CUCKOO_FILE);
    let cuckoo_file = File::open(CHUNK_CUCKOO_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to open cuckoo file: {}", e);
        std::process::exit(1);
    });
    let cuckoo_mmap = unsafe { Mmap::map(&cuckoo_file) }.unwrap_or_else(|e| {
        eprintln!("Failed to mmap cuckoo file: {}", e);
        std::process::exit(1);
    });

    // ── Parse and validate header ────────────────────────────────────────
    if cuckoo_mmap.len() < CHUNK_HEADER_SIZE {
        eprintln!("Cuckoo file too small for header");
        std::process::exit(1);
    }

    let magic = read_u64(&cuckoo_mmap, 0);
    let k = read_u32(&cuckoo_mmap, 8) as usize;
    let cuckoo_bucket_size = read_u32(&cuckoo_mmap, 12) as usize;
    let bins_per_table = read_u32(&cuckoo_mmap, 16) as usize;
    let num_hashes = read_u32(&cuckoo_mmap, 20) as usize;
    let master_seed = read_u64(&cuckoo_mmap, 24);

    if magic != CHUNK_MAGIC {
        eprintln!(
            "Bad magic: expected 0x{:016X}, got 0x{:016X}",
            CHUNK_MAGIC, magic
        );
        std::process::exit(1);
    }

    let slots_per_table = bins_per_table * cuckoo_bucket_size;
    let expected_body = k * slots_per_table * 4;
    let expected_size = CHUNK_HEADER_SIZE + expected_body;

    println!("  Header OK:");
    println!("    k = {}", k);
    println!("    cuckoo_bucket_size = {}", cuckoo_bucket_size);
    println!("    bins_per_table = {}", bins_per_table);
    println!("    slots_per_table = {}", slots_per_table);
    println!("    num_hashes = {}", num_hashes);
    println!("    master_seed = 0x{:016X}", master_seed);
    println!(
        "    file size: {} bytes ({:.2} MB), expected: {}",
        cuckoo_mmap.len(),
        cuckoo_mmap.len() as f64 / (1024.0 * 1024.0),
        expected_size
    );

    if cuckoo_mmap.len() != expected_size {
        eprintln!("  ERROR: file size mismatch!");
        std::process::exit(1);
    }
    println!("    Size check: OK");
    println!();

    // ── Per-bucket occupancy ─────────────────────────────────────────────
    println!("[2] Per-bucket occupancy scan:");
    let mut total_occupied = 0usize;
    let mut min_occ = usize::MAX;
    let mut max_occ = 0usize;

    for b in 0..k {
        let table_offset = CHUNK_HEADER_SIZE + b * slots_per_table * 4;
        let mut occ = 0usize;
        for s in 0..slots_per_table {
            let val = read_u32(&cuckoo_mmap, table_offset + s * 4);
            if val != EMPTY {
                occ += 1;
            }
        }
        total_occupied += occ;
        if occ < min_occ {
            min_occ = occ;
        }
        if occ > max_occ {
            max_occ = occ;
        }
    }

    let total_slots = k * slots_per_table;
    println!(
        "  Total occupied: {} / {} slots ({:.2}%)",
        total_occupied,
        total_slots,
        total_occupied as f64 / total_slots as f64 * 100.0
    );
    println!(
        "  Per-bucket occupancy: min={}, max={} (out of {} slots/table)",
        min_occ, max_occ, slots_per_table
    );
    println!();

    // ── Determine N from chunks file ─────────────────────────────────────
    println!("[3] Reading chunks file size: {}", CHUNKS_DATA_FILE);
    let chunks_meta = std::fs::metadata(CHUNKS_DATA_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to stat chunks file: {}", e);
        std::process::exit(1);
    });
    let n = chunks_meta.len() as usize / CHUNK_SIZE;
    println!("  N = {} chunks", n);
    println!();

    // ── Verify random lookups ────────────────────────────────────────────
    let verify_count = NUM_VERIFY.min(n);
    println!(
        "[4] Verifying {} random chunk lookups...",
        verify_count
    );
    let verify_start = Instant::now();

    let mut rng_state: u64 = 0xdeadbeefcafe1234;
    let mut found = 0usize;
    let mut not_found = 0usize;

    for i in 0..verify_count {
        rng_state = splitmix64(rng_state);
        let chunk_id = (rng_state % n as u64) as u32;

        let assigned = derive_chunk_buckets(chunk_id);

        let mut entry_found = false;
        for &bucket_id in &assigned {
            if lookup_in_bucket(&cuckoo_mmap, bucket_id, chunk_id, bins_per_table, cuckoo_bucket_size, num_hashes) {
                entry_found = true;
                break;
            }
        }

        if entry_found {
            found += 1;
        } else {
            not_found += 1;
            if not_found <= 10 {
                eprintln!(
                    "  MISS: chunk {} (buckets {:?}) at verify iteration {}",
                    chunk_id, assigned, i
                );
            }
        }

        if (i + 1) % 100_000 == 0 {
            eprint!("\r  Verified: {}/{}", i + 1, verify_count);
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
    }
    eprintln!();

    println!("  Done in {:.2?}", verify_start.elapsed());
    println!("  Found:     {} / {}", found, verify_count);
    println!("  Not found: {} / {}", not_found, verify_count);

    if not_found == 0 {
        println!("  ✓ All random lookups successful!");
    } else {
        println!(
            "  ✗ {:.4}% miss rate",
            not_found as f64 / verify_count as f64 * 100.0
        );
    }

    // ── Full sweep ───────────────────────────────────────────────────────
    println!();
    println!("[5] Full sweep: verifying ALL {} chunks...", n);
    let sweep_start = Instant::now();

    let mut sweep_found = 0usize;
    let mut sweep_miss = 0usize;

    for chunk_id in 0..n as u32 {
        let assigned = derive_chunk_buckets(chunk_id);

        let mut entry_found = false;
        for &bucket_id in &assigned {
            if lookup_in_bucket(&cuckoo_mmap, bucket_id, chunk_id, bins_per_table, cuckoo_bucket_size, num_hashes) {
                entry_found = true;
                break;
            }
        }

        if entry_found {
            sweep_found += 1;
        } else {
            sweep_miss += 1;
            if sweep_miss <= 5 {
                eprintln!(
                    "  FULL SWEEP MISS: chunk {} (buckets {:?})",
                    chunk_id, assigned
                );
            }
        }

        if (chunk_id as usize + 1) % 10_000_000 == 0 {
            eprint!("\r  Swept: {}/{}", chunk_id + 1, n);
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
    }
    eprintln!();

    println!("  Done in {:.2?}", sweep_start.elapsed());
    println!("  Found:     {} / {}", sweep_found, n);
    println!("  Not found: {} / {}", sweep_miss, n);

    if sweep_miss == 0 {
        println!("  ✓ Full sweep passed — every chunk is findable!");
    } else {
        println!(
            "  ✗ {:.6}% chunks missing",
            sweep_miss as f64 / n as f64 * 100.0
        );
    }

    println!();
    println!("  Total verification time: {:.2?}", start.elapsed());
}
