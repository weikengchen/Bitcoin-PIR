//! Extract 50 random script_hash entries from the UTXO chunks index
//! and write them to a binary file for later use as PIR test queries.
//!
//! Output format: 50 × 20 bytes (raw HASH160 script hashes, no header).
//!
//! Usage:
//!   cargo run --release -p build --bin extract_test_queries

mod common;

use common::*;
use memmap2::Mmap;
use std::fs::File;
use std::io::Write;

const NUM_QUERIES: usize = 50;
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/test_queries_50.bin";

fn main() {
    println!("=== Extract {} Random Test Queries ===", NUM_QUERIES);
    println!();

    // Memory-map the index
    println!("[1] Memory-mapping index: {}", INDEX_FILE);
    let file = File::open(INDEX_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to open index file: {}", e);
        std::process::exit(1);
    });
    let mmap = unsafe { Mmap::map(&file) }.unwrap_or_else(|e| {
        eprintln!("Failed to mmap: {}", e);
        std::process::exit(1);
    });

    let n = mmap.len() / INDEX_ENTRY_SIZE;
    println!("  N = {} entries", n);
    println!();

    // Use a simple deterministic PRNG (splitmix64) to pick 50 distinct indices.
    // Seed with a fixed value so the test set is reproducible.
    let mut rng_state: u64 = 0xDEAD_BEEF_CAFE_1234;
    let mut chosen_indices: Vec<usize> = Vec::with_capacity(NUM_QUERIES);

    while chosen_indices.len() < NUM_QUERIES {
        rng_state = splitmix64(rng_state.wrapping_add(0x9e3779b97f4a7c15));
        let idx = (rng_state % n as u64) as usize;
        if !chosen_indices.contains(&idx) {
            chosen_indices.push(idx);
        }
    }

    // Extract script_hashes and write to file
    println!("[2] Selected entries:");
    println!("  {:>4}  {:>10}  {:>42}  {:}", "  # ", "Entry Idx", "Script Hash (hex)", "Buckets");
    println!("  {}  {}  {}  {}", "-".repeat(4), "-".repeat(10), "-".repeat(42), "-".repeat(16));

    let mut out_data = Vec::with_capacity(NUM_QUERIES * SCRIPT_HASH_SIZE);

    for (i, &idx) in chosen_indices.iter().enumerate() {
        let base = idx * INDEX_ENTRY_SIZE;
        let script_hash = &mmap[base..base + SCRIPT_HASH_SIZE];
        out_data.extend_from_slice(script_hash);

        let hex: String = script_hash.iter().map(|b| format!("{:02x}", b)).collect();
        let buckets = derive_buckets(script_hash);
        println!(
            "  {:>4}  {:>10}  {}  {:?}",
            i, idx, hex, buckets
        );
    }

    println!();

    // Write to file
    println!("[3] Writing to: {}", OUTPUT_FILE);
    let mut out = File::create(OUTPUT_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to create output file: {}", e);
        std::process::exit(1);
    });
    out.write_all(&out_data).unwrap();
    println!(
        "  Written {} bytes ({} queries x {} bytes)",
        out_data.len(),
        NUM_QUERIES,
        SCRIPT_HASH_SIZE
    );
    println!();
    println!("Done.");
}
