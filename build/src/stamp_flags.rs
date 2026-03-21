//! Stamp placement bits into the index flags byte.
//!
//! For each index entry, computes which cuckoo hash function placed the
//! entry's first chunk in each of its 3 assigned groups, then encodes
//! this as 5 bits in the flags byte (byte 25 of each 26-byte entry).
//!
//! Encoding: flags = (1 << 5) | (h0 + 3*h1 + 9*h2)
//!   where h0, h1, h2 ∈ {0,1,2} are the cuckoo hash function indices
//!   for groups 0, 1, 2 respectively (from derive_chunk_buckets).
//!   Bit 5 = "valid" indicator.
//!
//! Must run AFTER gen_2_build_chunk_cuckoo and BEFORE gen_3_build_index_cuckoo.
//!
//! Usage:
//!   cargo run --release -p build --bin gen_2b_stamp_flags

mod common;

use common::*;
use memmap2::MmapMut;
use std::fs::{self, OpenOptions};
use std::time::Instant;

fn main() {
    println!("=== Stamp Placement Flags into Index ===");
    println!();

    let start = Instant::now();

    // ── 1. Memory-map the index file read-write ─────────────────────────
    println!("[1] Memory-mapping index file (read-write): {}", INDEX_FILE);
    let index_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(INDEX_FILE)
        .unwrap_or_else(|e| {
            eprintln!("Failed to open index file: {}", e);
            std::process::exit(1);
        });
    let mut index_mmap = unsafe { MmapMut::map_mut(&index_file) }.unwrap_or_else(|e| {
        eprintln!("Failed to mmap index: {}", e);
        std::process::exit(1);
    });

    let n = index_mmap.len() / INDEX_ENTRY_SIZE;
    assert_eq!(index_mmap.len() % INDEX_ENTRY_SIZE, 0);
    println!("  {} entries ({:.2} MB)", n, index_mmap.len() as f64 / (1024.0 * 1024.0));

    // ── 2. Load chunk cuckoo tables ─────────────────────────────────────
    println!("[2] Loading chunk cuckoo: {}", CHUNK_CUCKOO_FILE);
    let cuckoo_data = fs::read(CHUNK_CUCKOO_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to read chunk cuckoo: {}", e);
        std::process::exit(1);
    });
    let bins_per_table = read_chunk_cuckoo_header(&cuckoo_data);
    let slots_per_table = bins_per_table * CHUNK_CUCKOO_BUCKET_SIZE;
    println!("  bins_per_table = {}, bucket_size = {}", bins_per_table, CHUNK_CUCKOO_BUCKET_SIZE);
    println!();

    // ── 3. For each index entry, find placement of first chunk ──────────
    println!("[3] Stamping flags for {} entries...", n);
    let stamp_start = Instant::now();

    let mut stamped = 0u64;
    let mut not_found = 0u64;

    for i in 0..n {
        let base = i * INDEX_ENTRY_SIZE;

        let start_chunk_id = u32::from_le_bytes(
            index_mmap[base + 20..base + 24].try_into().unwrap(),
        );
        let num_chunks = index_mmap[base + 24];

        if num_chunks == 0 {
            // No chunks — leave flags as 0
            continue;
        }

        let first_chunk_id = start_chunk_id;
        let groups = derive_chunk_buckets(first_chunk_id);

        let mut encoded: u8 = 0;
        let mut all_found = true;

        for (gi, &group_id) in groups.iter().enumerate() {
            let table_offset = HEADER_SIZE + group_id * slots_per_table * CHUNK_SLOT_SIZE;

            let mut found_h: Option<usize> = None;
            for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                let key = derive_chunk_cuckoo_key(group_id, h);
                let bin = cuckoo_hash_int(first_chunk_id, key, bins_per_table);
                let bin_offset = table_offset + bin * CHUNK_CUCKOO_BUCKET_SIZE * CHUNK_SLOT_SIZE;

                for s in 0..CHUNK_CUCKOO_BUCKET_SIZE {
                    let slot_off = bin_offset + s * CHUNK_SLOT_SIZE;
                    let val = u32::from_le_bytes(
                        cuckoo_data[slot_off..slot_off + 4]
                            .try_into()
                            .unwrap(),
                    );
                    if val == first_chunk_id {
                        found_h = Some(h);
                        break;
                    }
                }
                if found_h.is_some() {
                    break;
                }
            }

            match found_h {
                Some(h) => {
                    let multiplier = [1u8, 3, 9][gi];
                    encoded += (h as u8) * multiplier;
                }
                None => {
                    all_found = false;
                    break;
                }
            }
        }

        if all_found {
            // Set bit 5 as "valid" indicator + 5-bit placement encoding
            index_mmap[base + 25] = (1 << 5) | encoded;
            stamped += 1;
        } else {
            not_found += 1;
            if not_found <= 10 {
                let sh: String = index_mmap[base..base + SCRIPT_HASH_SIZE]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                eprintln!("  WARNING: chunk {} not found in cuckoo for entry {} ({})",
                    start_chunk_id, i, sh);
            }
        }

        if (i + 1) % 10_000_000 == 0 {
            eprint!("\r  Progress: {}/{}", i + 1, n);
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
    }
    eprintln!();

    // Flush changes to disk
    index_mmap.flush().unwrap();

    println!("  Done in {:.2?}", stamp_start.elapsed());
    println!("  Stamped: {} ({:.2}%)", stamped, stamped as f64 / n as f64 * 100.0);
    println!("  Not found: {}", not_found);
    println!();
    println!("  Total time: {:.2?}", start.elapsed());
}
