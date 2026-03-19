//! Assign 50 test queries to 75 Batch PIR buckets using Cuckoo hashing,
//! then compute per-bucket cuckoo hash locations (loc0, loc1) for each query.
//!
//! Each query has 3 candidate buckets (from derive_buckets). Each bucket can
//! hold at most 1 query. We use cuckoo hashing with eviction to find a valid
//! assignment.
//!
//! For each assigned bucket, the query's script_hash is hashed with the two
//! per-bucket cuckoo keys to produce loc0 and loc1 — the two bin indices that
//! would be probed in that bucket's cuckoo table.
//!
//! Usage:
//!   cargo run --release -p build --bin assign_queries

mod common;

use common::*;

use std::fs;

const QUERIES_FILE: &str = "/Volumes/Bitcoin/data/test_queries_50.bin";
const MAX_KICKS: usize = 1000;

/// Represents a query's bucket assignment.
#[derive(Clone, Copy)]
struct QueryInfo {
    /// Index of this query in the 50-query list
    query_idx: usize,
    /// The 3 candidate buckets
    candidates: [usize; NUM_HASHES],
}

fn main() {
    println!("=== Assign Queries to Buckets (Cuckoo Hashing) ===");
    println!();

    // ── Load queries ─────────────────────────────────────────────────────
    println!("[1] Loading queries from: {}", QUERIES_FILE);
    let data = fs::read(QUERIES_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to read queries file: {}", e);
        std::process::exit(1);
    });

    let num_queries = data.len() / SCRIPT_HASH_SIZE;
    assert_eq!(data.len() % SCRIPT_HASH_SIZE, 0);
    println!("  {} queries loaded", num_queries);

    // ── Load cuckoo table header to get bins_per_table ───────────────────
    println!("[2] Loading cuckoo table header from: {}", CUCKOO_FILE);
    let cuckoo_data = fs::read(CUCKOO_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to read cuckoo file: {}", e);
        std::process::exit(1);
    });
    let bins_per_table = read_cuckoo_header(&cuckoo_data);
    println!("  bins_per_table = {}", bins_per_table);
    println!();

    // ── Compute candidate buckets for each query ─────────────────────────
    let mut queries: Vec<QueryInfo> = Vec::with_capacity(num_queries);
    for i in 0..num_queries {
        let sh = &data[i * SCRIPT_HASH_SIZE..(i + 1) * SCRIPT_HASH_SIZE];
        let candidates = derive_buckets(sh);
        queries.push(QueryInfo {
            query_idx: i,
            candidates,
        });
    }

    // ── Cuckoo assign queries to buckets ─────────────────────────────────
    println!("[3] Running Cuckoo assignment ({} queries → {} buckets)...", num_queries, K);

    let mut buckets: [Option<usize>; K] = [None; K];

    let mut success = true;
    for i in 0..num_queries {
        if !cuckoo_place(&queries, &mut buckets, i) {
            eprintln!("  FAILED to place query {} after {} kicks", i, MAX_KICKS);
            success = false;
            break;
        }
    }

    if !success {
        eprintln!("  Cuckoo assignment failed!");
        std::process::exit(1);
    }

    println!("  All {} queries placed successfully!", num_queries);
    println!();

    // ── Build reverse map ────────────────────────────────────────────────
    let mut assignment = vec![0usize; num_queries];
    for (bucket_id, slot) in buckets.iter().enumerate() {
        if let Some(qi) = slot {
            assignment[*qi] = bucket_id;
        }
    }

    // ── Display: assignment + per-bucket cuckoo locations ────────────────
    println!("[4] Final assignment with cuckoo locations:");
    println!(
        "  {:>4}  {:>6}  {:>8}  {:>8}  {:>42}  {:}",
        "#", "Bucket", "loc0", "loc1", "Script Hash", "Candidates"
    );
    println!(
        "  {}  {}  {}  {}  {}  {}",
        "-".repeat(4),
        "-".repeat(6),
        "-".repeat(8),
        "-".repeat(8),
        "-".repeat(42),
        "-".repeat(20)
    );

    for q in &queries {
        let i = q.query_idx;
        let sh = &data[i * SCRIPT_HASH_SIZE..(i + 1) * SCRIPT_HASH_SIZE];
        let hex: String = sh.iter().map(|b| format!("{:02x}", b)).collect();
        let assigned_bucket = assignment[i];

        // Compute the two cuckoo bin locations within this bucket's table
        let key0 = derive_cuckoo_key(assigned_bucket, 0);
        let key1 = derive_cuckoo_key(assigned_bucket, 1);
        let loc0 = cuckoo_hash(sh, key0, bins_per_table);
        let loc1 = cuckoo_hash(sh, key1, bins_per_table);

        // Mark which candidate was chosen
        let candidates_str: Vec<String> = q
            .candidates
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
            "  {:>4}  {:>6}  {:>8}  {:>8}  {}  {}",
            i, assigned_bucket, loc0, loc1, hex, candidates_str.join(", ")
        );
    }

    println!();

    // ── Summary ──────────────────────────────────────────────────────────
    let used: usize = buckets.iter().filter(|b| b.is_some()).count();
    let empty = K - used;
    println!("[5] Summary:");
    println!("  Queries:          {}", num_queries);
    println!("  Buckets used:     {} / {}", used, K);
    println!("  Buckets empty:    {}", empty);
    println!("  Utilization:      {:.1}%", used as f64 / K as f64 * 100.0);
    println!("  bins_per_table:   {}", bins_per_table);
    println!();

    // ── Bucket map ───────────────────────────────────────────────────────
    println!("[6] Bucket map (. = empty, # = occupied):");
    print!("  ");
    for (i, slot) in buckets.iter().enumerate() {
        if slot.is_some() {
            print!("#");
        } else {
            print!(".");
        }
        if (i + 1) % 25 == 0 {
            println!();
            if i + 1 < K {
                print!("  ");
            }
        }
    }
    println!();
    println!("Done.");
}

/// Try to place query `qi` into one of its candidate buckets using cuckoo eviction.
fn cuckoo_place(
    queries: &[QueryInfo],
    buckets: &mut [Option<usize>; K],
    qi: usize,
) -> bool {
    let cands = &queries[qi].candidates;

    // Try each candidate directly
    for &c in cands {
        if buckets[c].is_none() {
            buckets[c] = Some(qi);
            return true;
        }
    }

    // Eviction: kick from the first candidate
    let mut current_qi = qi;
    let mut current_bucket = queries[current_qi].candidates[0];

    for kick in 0..MAX_KICKS {
        // Place current in current_bucket, evicting whoever is there
        let evicted_qi = buckets[current_bucket].unwrap();
        buckets[current_bucket] = Some(current_qi);

        // Try to place evicted query in one of its OTHER candidate buckets
        let ev_cands = &queries[evicted_qi].candidates;

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

        // Pick an alternative bucket to continue evicting from
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
