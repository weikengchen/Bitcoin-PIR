//! Assign chunk queries to 80 Batch PIR buckets using Cuckoo hashing.
//!
//! 1. Reads batch_pir_results.bin (50 × 28 bytes from the first-level PIR).
//! 2. Computes all needed chunk_ids from (offset_half, num_chunks), deduplicates.
//! 3. Cuckoo-assigns each unique chunk query to one of 80 buckets.
//! 4. Displays the assignment with per-bucket cuckoo locations (loc0, loc1).
//!
//! Usage:
//!   cargo run --release -p build --bin assign_chunk_queries

mod common;

use common::*;

use std::collections::BTreeSet;
use std::fs;

const MAX_KICKS: usize = 1000;

fn main() {
    println!("=== Assign Chunk Queries to Buckets (Cuckoo Hashing) ===");
    println!();

    // ── 1. Load first-level PIR results ──────────────────────────────────
    println!("[1] Loading first-level PIR results: {}", BATCH_PIR_RESULTS_FILE);
    let data = fs::read(BATCH_PIR_RESULTS_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to read results file: {}", e);
        std::process::exit(1);
    });

    let num_queries = data.len() / INDEX_ENTRY_SIZE;
    assert_eq!(data.len() % INDEX_ENTRY_SIZE, 0);
    println!("  {} first-level query results loaded", num_queries);

    // ── 2. Compute all needed chunk_ids ──────────────────────────────────
    println!("[2] Computing chunk_ids from (offset_half, num_chunks)...");

    // Collect per-query chunk ranges and all unique chunk_ids
    let mut all_chunk_ids = BTreeSet::new();
    let mut query_ranges: Vec<(u32, u32)> = Vec::with_capacity(num_queries);

    for i in 0..num_queries {
        let base = i * INDEX_ENTRY_SIZE;
        let offset_half = u32::from_le_bytes(
            data[base + 20..base + 24].try_into().unwrap(),
        );
        let num_chunks = u32::from_le_bytes(
            data[base + 24..base + 28].try_into().unwrap(),
        );

        if offset_half == 0 && num_chunks == 0 {
            // MISS from first-level PIR — skip
            query_ranges.push((0, 0));
            continue;
        }

        let byte_offset = offset_half as u64 * 2;
        let start_chunk = (byte_offset / CHUNK_SIZE as u64) as u32;

        query_ranges.push((start_chunk, num_chunks));

        for c in 0..num_chunks {
            all_chunk_ids.insert(start_chunk + c);
        }
    }

    let chunk_queries: Vec<u32> = all_chunk_ids.into_iter().collect();
    let num_chunk_queries = chunk_queries.len();

    println!("  Total unique chunk_ids to query: {}", num_chunk_queries);

    // Show per-query breakdown
    println!();
    println!("  Per-query chunk ranges:");
    for i in 0..num_queries {
        let (start, nc) = query_ranges[i];
        let sh = &data[i * INDEX_ENTRY_SIZE..i * INDEX_ENTRY_SIZE + SCRIPT_HASH_SIZE];
        let hex: String = sh.iter().map(|b| format!("{:02x}", b)).collect();
        if nc == 0 {
            println!("    q{:>3}: {} → MISS (skipped)", i, hex);
        } else {
            println!(
                "    q{:>3}: {} → chunks {}..{} ({} chunks)",
                i, hex, start, start + nc - 1, nc
            );
        }
    }
    println!();

    // ── 3. Load chunk cuckoo header ──────────────────────────────────────
    println!("[3] Loading chunk cuckoo header: {}", CHUNK_CUCKOO_FILE);
    let cuckoo_data = fs::read(CHUNK_CUCKOO_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to read chunk cuckoo file: {}", e);
        std::process::exit(1);
    });
    let bins_per_table = read_chunk_cuckoo_header(&cuckoo_data);
    println!("  bins_per_table = {}", bins_per_table);
    println!();

    // ── 4. Compute candidate buckets ─────────────────────────────────────
    let candidates: Vec<[usize; NUM_HASHES]> = chunk_queries
        .iter()
        .map(|&cid| derive_chunk_buckets(cid))
        .collect();

    // ── 5. Cuckoo assign ─────────────────────────────────────────────────
    println!(
        "[4] Running Cuckoo assignment ({} chunk queries → {} buckets)...",
        num_chunk_queries, K_CHUNK
    );

    let mut buckets: [Option<usize>; K_CHUNK] = [None; K_CHUNK];

    let mut success = true;
    for i in 0..num_chunk_queries {
        if !cuckoo_place(&candidates, &mut buckets, i) {
            eprintln!("  FAILED to place chunk query {} (chunk_id={}) after {} kicks",
                i, chunk_queries[i], MAX_KICKS);
            success = false;
            break;
        }
    }

    if !success {
        eprintln!("  Cuckoo assignment failed!");
        std::process::exit(1);
    }

    println!("  All {} chunk queries placed successfully!", num_chunk_queries);
    println!();

    // ── 6. Build reverse map ─────────────────────────────────────────────
    let mut assignment = vec![0usize; num_chunk_queries];
    for (bucket_id, slot) in buckets.iter().enumerate() {
        if let Some(qi) = slot {
            assignment[*qi] = bucket_id;
        }
    }

    // ── 7. Display assignment with cuckoo locations ──────────────────────
    println!("[5] Final assignment with cuckoo locations:");
    println!(
        "  {:>6}  {:>10}  {:>6}  {:>8}  {:>8}  {:}",
        "#", "Chunk ID", "Bucket", "loc0", "loc1", "Candidates"
    );
    println!(
        "  {}  {}  {}  {}  {}  {}",
        "-".repeat(6),
        "-".repeat(10),
        "-".repeat(6),
        "-".repeat(8),
        "-".repeat(8),
        "-".repeat(20)
    );

    for (i, &chunk_id) in chunk_queries.iter().enumerate() {
        let assigned_bucket = assignment[i];
        let key0 = derive_chunk_cuckoo_key(assigned_bucket, 0);
        let key1 = derive_chunk_cuckoo_key(assigned_bucket, 1);
        let loc0 = cuckoo_hash_int(chunk_id, key0, bins_per_table);
        let loc1 = cuckoo_hash_int(chunk_id, key1, bins_per_table);

        let candidates_str: Vec<String> = candidates[i]
            .iter()
            .map(|&c| {
                if c == assigned_bucket {
                    format!("[{}]", c)
                } else {
                    format!("{}", c)
                }
            })
            .collect();

        println!(
            "  {:>6}  {:>10}  {:>6}  {:>8}  {:>8}  {}",
            i, chunk_id, assigned_bucket, loc0, loc1, candidates_str.join(", ")
        );
    }
    println!();

    // ── 8. Summary ───────────────────────────────────────────────────────
    let used: usize = buckets.iter().filter(|b| b.is_some()).count();
    let empty = K_CHUNK - used;
    println!("[6] Summary:");
    println!("  First-level queries:     {}", num_queries);
    println!("  Unique chunk queries:    {}", num_chunk_queries);
    println!("  Buckets used:            {} / {}", used, K_CHUNK);
    println!("  Buckets empty:           {}", empty);
    println!("  Utilization:             {:.1}%", used as f64 / K_CHUNK as f64 * 100.0);
    println!("  bins_per_table:          {}", bins_per_table);
    println!();

    // ── 9. Bucket map ────────────────────────────────────────────────────
    println!("[7] Bucket map (. = empty, # = occupied):");
    print!("  ");
    for (i, slot) in buckets.iter().enumerate() {
        if slot.is_some() {
            print!("#");
        } else {
            print!(".");
        }
        if (i + 1) % 20 == 0 {
            println!();
            if i + 1 < K_CHUNK {
                print!("  ");
            }
        }
    }
    println!();
    println!("Done.");
}

/// Try to place query `qi` into one of its candidate buckets using cuckoo eviction.
fn cuckoo_place(
    candidates: &[[usize; NUM_HASHES]],
    buckets: &mut [Option<usize>; K_CHUNK],
    qi: usize,
) -> bool {
    let cands = &candidates[qi];

    for &c in cands {
        if buckets[c].is_none() {
            buckets[c] = Some(qi);
            return true;
        }
    }

    let mut current_qi = qi;
    let mut current_bucket = candidates[current_qi][0];

    for kick in 0..MAX_KICKS {
        let evicted_qi = buckets[current_bucket].unwrap();
        buckets[current_bucket] = Some(current_qi);

        let ev_cands = &candidates[evicted_qi];

        for offset in 0..NUM_HASHES {
            let c = ev_cands[(kick + offset) % NUM_HASHES];
            if c == current_bucket {
                continue;
            }
            if buckets[c].is_none() {
                buckets[c] = Some(evicted_qi);
                return true;
            }
        }

        let mut next_bucket = ev_cands[0];
        for offset in 0..NUM_HASHES {
            let c = ev_cands[(kick + offset) % NUM_HASHES];
            if c != current_bucket {
                next_bucket = c;
                break;
            }
        }
        current_qi = evicted_qi;
        current_bucket = next_bucket;
    }

    false
}
