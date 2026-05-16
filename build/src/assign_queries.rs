//! Assign 50 test queries to 75 Batch PIR groups using Cuckoo hashing,
//! then compute per-group cuckoo hash locations (loc0, loc1) for each query.
//!
//! Each query has 3 candidate groups (from derive_groups). Each group can
//! hold at most 1 query. We use cuckoo hashing with eviction to find a valid
//! assignment.
//!
//! For each assigned group, the query's script_hash is hashed with the two
//! per-group cuckoo keys to produce loc0 and loc1 — the two bin indices that
//! would be probed in that group's cuckoo table.
//!
//! Usage:
//!   cargo run --release -p build --bin assign_queries

mod common;

use common::*;

use std::fs;

const QUERIES_FILE: &str = "/Volumes/Bitcoin/data/intermediate/test_queries_50.bin";
const MAX_KICKS: usize = 1000;

/// Represents a query's group assignment.
#[derive(Clone, Copy)]
struct QueryInfo {
    /// Index of this query in the 50-query list
    query_idx: usize,
    /// The 3 candidate groups
    candidates: [usize; NUM_HASHES],
}

fn main() {
    println!("=== Assign Queries to Groups (Cuckoo Hashing) ===");
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
    let (bins_per_table, _tag_seed) = read_cuckoo_header(&cuckoo_data);
    println!("  bins_per_table = {}", bins_per_table);
    println!();

    // ── Compute candidate groups for each query ─────────────────────────
    let mut queries: Vec<QueryInfo> = Vec::with_capacity(num_queries);
    let mut candidate_groups: Vec<[usize; NUM_HASHES]> = Vec::with_capacity(num_queries);
    for i in 0..num_queries {
        let sh = &data[i * SCRIPT_HASH_SIZE..(i + 1) * SCRIPT_HASH_SIZE];
        let candidates = derive_groups(sh);
        queries.push(QueryInfo {
            query_idx: i,
            candidates,
        });
        candidate_groups.push(candidates);
    }

    // ── Cuckoo assign queries to groups ─────────────────────────────────
    println!("[3] Running Cuckoo assignment ({} queries → {} groups)...", num_queries, K);

    let mut groups: [Option<usize>; K] = [None; K];

    let mut success = true;
    for i in 0..num_queries {
        if !pbc_cuckoo_place(&candidate_groups, &mut groups, i, MAX_KICKS, NUM_HASHES) {
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
    for (group_id, slot) in groups.iter().enumerate() {
        if let Some(qi) = slot {
            assignment[*qi] = group_id;
        }
    }

    // ── Display: assignment + per-group cuckoo locations ────────────────
    println!("[4] Final assignment with cuckoo locations:");
    println!(
        "  {:>4}  {:>6}  {:>8}  {:>8}  {:>42}  Candidates",
        "#", "Group", "loc0", "loc1", "Script Hash"
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
        let assigned_group = assignment[i];

        // Compute the two cuckoo bin locations within this group's table
        let key0 = derive_cuckoo_key(assigned_group, 0);
        let key1 = derive_cuckoo_key(assigned_group, 1);
        let loc0 = cuckoo_hash(sh, key0, bins_per_table);
        let loc1 = cuckoo_hash(sh, key1, bins_per_table);

        // Mark which candidate was chosen
        let candidates_str: Vec<String> = q
            .candidates
            .iter()
            .map(|&c| {
                if c == assigned_group {
                    format!("[{}]", c)
                } else {
                    format!("{}", c)
                }
            })
            .collect();

        println!(
            "  {:>4}  {:>6}  {:>8}  {:>8}  {}  {}",
            i, assigned_group, loc0, loc1, hex, candidates_str.join(", ")
        );
    }

    println!();

    // ── Summary ──────────────────────────────────────────────────────────
    let used: usize = groups.iter().filter(|b| b.is_some()).count();
    let empty = K - used;
    println!("[5] Summary:");
    println!("  Queries:          {}", num_queries);
    println!("  Groups used:      {} / {}", used, K);
    println!("  Groups empty:     {}", empty);
    println!("  Utilization:      {:.1}%", used as f64 / K as f64 * 100.0);
    println!("  bins_per_table:   {}", bins_per_table);
    println!();

    // ── Group map ───────────────────────────────────────────────────────
    println!("[6] Group map (. = empty, # = occupied):");
    print!("  ");
    for (i, slot) in groups.iter().enumerate() {
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
