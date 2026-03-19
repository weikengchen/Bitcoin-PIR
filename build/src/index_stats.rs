//! Scan the UTXO chunks index and report addresses with the most chunks.
//!
//! Reads utxo_chunks_index_nodust.bin (28-byte entries) and prints the top N
//! entries by num_chunks, along with overall statistics.
//!
//! Usage:
//!   cargo run --release -p build --bin gen_0b_index_stats

mod common;

use common::*;
use memmap2::Mmap;
use std::fs::File;
use std::time::Instant;

/// How many top entries to display
const TOP_N: usize = 50;

fn main() {
    println!("=== UTXO Chunks Index Statistics ===");
    println!();

    let start = Instant::now();

    // ── Load index ───────────────────────────────────────────────────────
    println!("[1] Loading index: {}", INDEX_FILE);
    let file = File::open(INDEX_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to open index file: {}", e);
        std::process::exit(1);
    });
    let mmap = unsafe { Mmap::map(&file) }.unwrap_or_else(|e| {
        eprintln!("Failed to mmap: {}", e);
        std::process::exit(1);
    });

    let n = mmap.len() / INDEX_ENTRY_SIZE;
    println!("  Entries: {}", n);
    println!("  File size: {:.2} MB", mmap.len() as f64 / (1024.0 * 1024.0));
    println!();

    // ── Scan ─────────────────────────────────────────────────────────────
    println!("[2] Scanning for top {} entries by num_chunks...", TOP_N);

    // (num_chunks, entry_index) — min-heap by num_chunks
    let mut top: Vec<(u32, usize)> = Vec::with_capacity(TOP_N + 1);
    let mut total_chunks: u64 = 0;
    let mut max_chunks: u32 = 0;
    let mut single_chunk: u64 = 0;
    let mut multi_chunk: u64 = 0;

    // Chunk count distribution: how many addresses have exactly k chunks
    let mut chunk_dist: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();

    for i in 0..n {
        let base = i * INDEX_ENTRY_SIZE;
        let num_chunks = u32::from_le_bytes(
            mmap[base + 24..base + 28].try_into().unwrap(),
        );

        total_chunks += num_chunks as u64;
        *chunk_dist.entry(num_chunks).or_insert(0) += 1;

        if num_chunks == 1 {
            single_chunk += 1;
        } else {
            multi_chunk += 1;
        }
        if num_chunks > max_chunks {
            max_chunks = num_chunks;
        }

        // Maintain top-N
        if top.len() < TOP_N || num_chunks > top.last().unwrap().0 {
            top.push((num_chunks, i));
            top.sort_by(|a, b| b.0.cmp(&a.0));
            top.truncate(TOP_N);
        }

        if (i + 1) % 10_000_000 == 0 {
            eprint!("\r  Scanned: {}/{}", i + 1, n);
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
    }
    eprintln!();

    println!("  Done in {:.2?}", start.elapsed());
    println!();

    // ── Overall stats ────────────────────────────────────────────────────
    println!("[3] Overall statistics:");
    println!("  Total addresses:       {}", n);
    println!("  Total chunks:          {}", total_chunks);
    println!(
        "  Total chunk data:      {:.2} GB",
        total_chunks as f64 * CHUNK_SIZE as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    println!(
        "  Avg chunks/address:    {:.2}",
        total_chunks as f64 / n as f64
    );
    println!("  Max chunks:            {}", max_chunks);
    println!("  Single-chunk addrs:    {} ({:.2}%)", single_chunk, single_chunk as f64 / n as f64 * 100.0);
    println!("  Multi-chunk addrs:     {} ({:.2}%)", multi_chunk, multi_chunk as f64 / n as f64 * 100.0);
    println!();

    // ── Chunk count distribution ─────────────────────────────────────────
    println!("[4] Chunk count distribution:");
    println!(
        "  {:>10}  {:>12}  {:>8}  {:>14}  {:>8}",
        "Chunks", "Addresses", "% Addrs", "Total Chunks", "% Chunks"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "-".repeat(10),
        "-".repeat(12),
        "-".repeat(8),
        "-".repeat(14),
        "-".repeat(8)
    );

    let mut dist_sorted: Vec<(u32, u64)> = chunk_dist.into_iter().collect();
    dist_sorted.sort_by_key(|&(k, _)| k);

    // Show individual counts up to 20, then buckets
    let mut shown_up_to = 0u32;
    for &(nc, count) in &dist_sorted {
        if nc <= 20 {
            let tc = nc as u64 * count;
            println!(
                "  {:>10}  {:>12}  {:>7.2}%  {:>14}  {:>7.2}%",
                nc,
                count,
                count as f64 / n as f64 * 100.0,
                tc,
                tc as f64 / total_chunks as f64 * 100.0
            );
            shown_up_to = nc;
        }
    }

    // Buckets: 21-50, 51-100, 101-500, 501-1000, 1001-10000, 10000+
    let bucket_ranges: &[(u32, u32)] = &[
        (21, 50),
        (51, 100),
        (101, 500),
        (501, 1000),
        (1001, 10000),
        (10001, u32::MAX),
    ];

    for &(lo, hi) in bucket_ranges {
        if lo <= shown_up_to {
            continue;
        }
        let mut count = 0u64;
        let mut tc = 0u64;
        for &(nc, c) in &dist_sorted {
            if nc >= lo && nc <= hi {
                count += c;
                tc += nc as u64 * c;
            }
        }
        if count > 0 {
            let label = if hi == u32::MAX {
                format!("{}+", lo)
            } else {
                format!("{}-{}", lo, hi)
            };
            println!(
                "  {:>10}  {:>12}  {:>7.2}%  {:>14}  {:>7.2}%",
                label,
                count,
                count as f64 / n as f64 * 100.0,
                tc,
                tc as f64 / total_chunks as f64 * 100.0
            );
        }
    }
    println!();

    // ── Top N ────────────────────────────────────────────────────────────
    println!("[5] Top {} addresses by num_chunks:", TOP_N);
    println!(
        "  {:>4}  {:>8}  {:>10}  {:>12}  {}",
        "#", "Chunks", "Data (B)", "Offset/2", "Script Hash"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "-".repeat(4),
        "-".repeat(8),
        "-".repeat(10),
        "-".repeat(12),
        "-".repeat(42)
    );

    for (rank, &(nc, idx)) in top.iter().enumerate() {
        let base = idx * INDEX_ENTRY_SIZE;
        let sh = &mmap[base..base + SCRIPT_HASH_SIZE];
        let offset_half = u32::from_le_bytes(
            mmap[base + 20..base + 24].try_into().unwrap(),
        );
        let hex: String = sh.iter().map(|b| format!("{:02x}", b)).collect();
        let data_bytes = nc as u64 * CHUNK_SIZE as u64;

        println!(
            "  {:>4}  {:>8}  {:>10}  {:>12}  {}",
            rank + 1,
            nc,
            data_bytes,
            offset_half,
            hex
        );
    }

    println!();
    println!("  Total time: {:.2?}", start.elapsed());
}
