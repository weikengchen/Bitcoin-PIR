//! Bucketed Cuckoo Hashing for gen2_utxo_chunks_index.bin
//!
//! Input: /Volumes/Bitcoin/data/gen2_utxo_chunks_index.bin
//!   Each entry: 24 bytes (20-byte script hash + 4-byte start_offset)
//!
//! Output: /Volumes/Bitcoin/data/gen2_utxo_chunks_cuckoo.bin
//!   m = ceil(n / 0.95) entries (rounded up to multiple of bucket size),
//!   each 24 bytes. Empty slots zero-filled.
//!
//! Parameters:
//!   - 2 hash functions (over the 20-byte script hash)
//!   - Bucket size = 4
//!   - Load factor α = 0.95
//!
//! Usage:
//!   gen2_3_cuckoo_chunks           # uses full-size gen2 files
//!   gen2_3_cuckoo_chunks --small   # uses small gen2 files

use memmap2::Mmap;
use std::fs::File;
use std::io::{self, Write};
use std::time::Instant;

const INPUT_FILE: &str = "/Volumes/Bitcoin/data/gen2_utxo_chunks_index.bin";
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/gen2_utxo_chunks_cuckoo.bin";
const INPUT_FILE_SMALL: &str = "/Volumes/Bitcoin/data/gen2_utxo_chunks_index_small.bin";
const OUTPUT_FILE_SMALL: &str = "/Volumes/Bitcoin/data/gen2_utxo_chunks_cuckoo_small.bin";
const ENTRY_SIZE: usize = 24;
const KEY_SIZE: usize = 20;
const BUCKET_SIZE: usize = 4;
const LOAD_FACTOR: f64 = 0.95;
const EMPTY: u32 = u32::MAX;
const MAX_KICKS: usize = 500;

/// Hash function 1 for 20-byte script hash.
/// Uses FNV-1a style mixing over the key bytes.
#[inline(always)]
fn hash1(mmap: &[u8], entry_idx: u32, num_buckets: usize) -> usize {
    let offset = entry_idx as usize * ENTRY_SIZE;
    let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis
    for i in 0..KEY_SIZE {
        h ^= mmap[offset + i] as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }
    // Extra mixing
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    (h as usize) % num_buckets
}

/// Hash function 2 for 20-byte script hash.
/// Different seed/constants.
#[inline(always)]
fn hash2(mmap: &[u8], entry_idx: u32, num_buckets: usize) -> usize {
    let offset = entry_idx as usize * ENTRY_SIZE;
    let mut h: u64 = 0x517cc1b727220a95; // Different seed
    for i in 0..KEY_SIZE {
        h ^= mmap[offset + i] as u64;
        h = h.wrapping_mul(0x9e3779b97f4a7c15); // Different prime
    }
    h ^= h >> 32;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^= h >> 32;
    (h as usize) % num_buckets
}

/// Find a free slot in a bucket
#[inline]
fn find_free_slot(table: &[u32], bucket: usize) -> Option<usize> {
    let base = bucket * BUCKET_SIZE;
    for i in 0..BUCKET_SIZE {
        if table[base + i] == EMPTY {
            return Some(i);
        }
    }
    None
}

/// Get the other bucket for an entry
#[inline(always)]
fn other_bucket(mmap: &[u8], entry_idx: u32, current_bucket: usize, num_buckets: usize) -> usize {
    let b1 = hash1(mmap, entry_idx, num_buckets);
    let b2 = hash2(mmap, entry_idx, num_buckets);
    if current_bucket == b1 {
        b2
    } else {
        b1
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let small = args.iter().any(|a| a == "--small");

    let input_file = if small { INPUT_FILE_SMALL } else { INPUT_FILE };
    let output_file = if small { OUTPUT_FILE_SMALL } else { OUTPUT_FILE };

    println!("=== Bucketed Cuckoo Hashing for gen2_utxo_chunks_index ===");
    if small {
        println!("  Mode: SMALL");
    }
    println!("  Bucket size: {}", BUCKET_SIZE);
    println!("  Load factor: {}", LOAD_FACTOR);
    println!("  Hash functions: 2");
    println!("  Key: 20-byte script hash");
    println!();

    // Step 1: Memory-map the input file
    println!("[1] Opening input file: {}", input_file);
    let start = Instant::now();

    let file = File::open(input_file).expect("Failed to open input file");
    let file_len = file.metadata().unwrap().len() as usize;
    let n = file_len / ENTRY_SIZE;

    println!("  File size: {} bytes", file_len);
    println!(
        "  Entry size: {} bytes ({}B key + 4B offset)",
        ENTRY_SIZE, KEY_SIZE
    );
    println!("  Number of entries (n): {}", n);

    if file_len % ENTRY_SIZE != 0 {
        eprintln!(
            "  Warning: file size not multiple of entry size ({} trailing bytes)",
            file_len % ENTRY_SIZE
        );
    }

    let mmap = unsafe { Mmap::map(&file).expect("Failed to mmap file") };

    // Calculate table dimensions
    let total_slots_needed = (n as f64 / LOAD_FACTOR).ceil() as usize;
    let num_buckets = (total_slots_needed + BUCKET_SIZE - 1) / BUCKET_SIZE;
    let total_slots = num_buckets * BUCKET_SIZE;
    let actual_load_factor = n as f64 / total_slots as f64;

    println!();
    println!("  Table dimensions:");
    println!("    Total slots:    {}", total_slots);
    println!(
        "    Num buckets:    {} (each holds {} entries)",
        num_buckets, BUCKET_SIZE
    );
    println!("    Actual max LF:  {:.6}", actual_load_factor);
    println!(
        "    Output file size: {:.2} GB ({} bytes)",
        (total_slots * ENTRY_SIZE) as f64 / (1024.0 * 1024.0 * 1024.0),
        total_slots * ENTRY_SIZE
    );

    // Step 2: Build bucketed cuckoo hash table
    println!();
    println!("[2] Building bucketed Cuckoo hash table...");
    let build_start = Instant::now();

    let mut table: Vec<u32> = vec![EMPTY; total_slots];
    let mut stash: Vec<u32> = Vec::new();

    // Simple xorshift32 RNG
    let mut rng_state: u32 = 0xDEADBEEF;
    let mut xorshift = || -> u32 {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 17;
        rng_state ^= rng_state << 5;
        rng_state
    };

    let report_interval = std::cmp::max(1, n / 100);

    for entry_idx in 0..n {
        let idx = entry_idx as u32;

        let b1 = hash1(&mmap, idx, num_buckets);
        let b2 = hash2(&mmap, idx, num_buckets);

        if let Some(slot) = find_free_slot(&table, b1) {
            table[b1 * BUCKET_SIZE + slot] = idx;
        } else if let Some(slot) = find_free_slot(&table, b2) {
            table[b2 * BUCKET_SIZE + slot] = idx;
        } else {
            // Eviction chain
            let mut current_idx = idx;
            let mut current_bucket = if xorshift() & 1 == 0 { b1 } else { b2 };
            let mut placed = false;

            for _kick in 0..MAX_KICKS {
                let evict_slot = (xorshift() as usize) % BUCKET_SIZE;
                let base = current_bucket * BUCKET_SIZE;

                let evicted_idx = table[base + evict_slot];
                table[base + evict_slot] = current_idx;

                current_idx = evicted_idx;

                let alt_bucket = other_bucket(&mmap, current_idx, current_bucket, num_buckets);
                if let Some(slot) = find_free_slot(&table, alt_bucket) {
                    table[alt_bucket * BUCKET_SIZE + slot] = current_idx;
                    placed = true;
                    break;
                }
                current_bucket = alt_bucket;
            }

            if !placed {
                stash.push(current_idx);
            }
        }

        // Progress
        if (entry_idx + 1) % report_interval == 0 || entry_idx + 1 == n {
            let elapsed = build_start.elapsed().as_secs_f64();
            let progress = (entry_idx + 1) as f64 / n as f64 * 100.0;
            let rate = (entry_idx + 1) as f64 / elapsed;
            let eta = if rate > 0.0 {
                (n - entry_idx - 1) as f64 / rate
            } else {
                0.0
            };
            print!(
                "\r  Progress: {:.1}% ({}/{}) | Stash: {} | {:.0} keys/s | ETA: {:.0}s   ",
                progress,
                entry_idx + 1,
                n,
                stash.len(),
                rate,
                eta
            );
            io::stdout().flush().ok();
        }
    }
    println!();
    println!("  Build completed in {:.2?}", build_start.elapsed());

    // Step 3: Statistics
    println!();
    println!("=== Results ===");
    let occupied = table.iter().filter(|&&v| v != EMPTY).count();
    println!("  Total keys:          {}", n);
    println!("  Total slots:         {}", total_slots);
    println!(
        "  Num buckets:         {} (x{} = {} slots)",
        num_buckets, BUCKET_SIZE, total_slots
    );
    println!("  Slots occupied:      {}", occupied);
    println!(
        "  Load factor:         {:.6}",
        occupied as f64 / total_slots as f64
    );
    println!("  Stash size:          {}", stash.len());

    // Verify
    println!();
    println!("[3] Verifying all entries can be found...");
    let verify_start = Instant::now();
    let mut errors = 0u64;
    let stash_set: std::collections::HashSet<u32> = stash.iter().copied().collect();

    for entry_idx in 0..n {
        let idx = entry_idx as u32;
        let b1 = hash1(&mmap, idx, num_buckets);
        let b2 = hash2(&mmap, idx, num_buckets);

        let mut found = false;
        for i in 0..BUCKET_SIZE {
            if table[b1 * BUCKET_SIZE + i] == idx || table[b2 * BUCKET_SIZE + i] == idx {
                found = true;
                break;
            }
        }
        if !found && !stash_set.contains(&idx) {
            errors += 1;
            if errors <= 10 {
                eprintln!("  ERROR: entry_idx={} not found", entry_idx);
            }
        }
    }
    println!("  Verification done in {:.2?}", verify_start.elapsed());
    println!("  Errors: {}", errors);

    // Step 4: Build output buffer and write file
    println!();
    let output_size = total_slots * ENTRY_SIZE;
    println!(
        "[4] Building output buffer ({:.2} MB)...",
        output_size as f64 / (1024.0 * 1024.0)
    );
    let output_start = Instant::now();

    let mut output: Vec<u8> = vec![0u8; output_size];
    let mut placed_count: usize = 0;
    for slot in 0..total_slots {
        let entry_idx = table[slot];
        if entry_idx != EMPTY {
            let src_offset = entry_idx as usize * ENTRY_SIZE;
            let dst_offset = slot * ENTRY_SIZE;
            output[dst_offset..dst_offset + ENTRY_SIZE]
                .copy_from_slice(&mmap[src_offset..src_offset + ENTRY_SIZE]);
            placed_count += 1;
        }
    }
    println!(
        "  Output buffer built in {:.2?} ({} entries placed)",
        output_start.elapsed(),
        placed_count
    );

    println!("  Writing to {}...", output_file);
    let write_start = Instant::now();
    let mut out_file = File::create(output_file).expect("Failed to create output file");
    out_file
        .write_all(&output)
        .expect("Failed to write output file");
    out_file.sync_all().expect("Failed to sync output file");
    println!(
        "  Written {:.2} MB in {:.2?}",
        output_size as f64 / (1024.0 * 1024.0),
        write_start.elapsed()
    );

    // Summary
    println!();
    println!("========================================");
    println!("  BUCKETED CUCKOO HASHING SUMMARY");
    println!("========================================");
    println!("  n = {} entries", n);
    println!("  Bucket size = {}", BUCKET_SIZE);
    println!("  Load factor target = {}", LOAD_FACTOR);
    println!(
        "  Total slots = {} ({:.4}x n)",
        total_slots,
        total_slots as f64 / n as f64
    );
    println!("  Stash size = {}", stash.len());
    println!();
    println!("  File sizes ({}-byte entries):", ENTRY_SIZE);
    println!(
        "    Original input:         {:.2} MB",
        (n * ENTRY_SIZE) as f64 / (1024.0 * 1024.0)
    );
    println!(
        "    Bucketed cuckoo output: {:.2} MB  ({:.4}x n)",
        (total_slots * ENTRY_SIZE) as f64 / (1024.0 * 1024.0),
        total_slots as f64 / n as f64
    );
    println!("  Total time: {:.2?}", start.elapsed());
    println!("========================================");
}
