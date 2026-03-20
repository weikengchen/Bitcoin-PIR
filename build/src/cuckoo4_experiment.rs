//! Cuckoo hashing experiment with 75-group Batch PIR split.
//!
//! 1. Split entries into 75 groups (each entry copied to 3 groups, same as production).
//! 2. Build a cuckoo table per group with configurable hash functions and bucket size.
//!
//! Usage:
//!   cargo run --release -p build --bin cuckoo4_experiment

use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const INDEX_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_index_nodust.bin";
const INDEX_ENTRY_SIZE: usize = 28;
const SCRIPT_HASH_SIZE: usize = 20;

/// Batch PIR parameters (same as production)
const K: usize = 75;
const NUM_BATCH_HASHES: usize = 3;

/// Cuckoo parameters to test
const CUCKOO_NUM_HASHES: usize = 2;
const CUCKOO_BUCKET_SIZE: usize = 2;
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 2000;
const EMPTY: u32 = u32::MAX;

// ─── Hash utilities ──────────────────────────────────────────────────────────

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

#[inline]
fn sh_a(sh: &[u8]) -> u64 {
    u64::from_le_bytes([sh[0], sh[1], sh[2], sh[3], sh[4], sh[5], sh[6], sh[7]])
}

#[inline]
fn sh_b(sh: &[u8]) -> u64 {
    u64::from_le_bytes([sh[8], sh[9], sh[10], sh[11], sh[12], sh[13], sh[14], sh[15]])
}

#[inline]
fn sh_c(sh: &[u8]) -> u64 {
    u32::from_le_bytes([sh[16], sh[17], sh[18], sh[19]]) as u64
}

#[inline]
fn hash_for_bucket(sh: &[u8], nonce: u64) -> u64 {
    let mut h = sh_a(sh).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15));
    h ^= sh_b(sh);
    h = splitmix64(h ^ sh_c(sh));
    h
}

/// Derive 3 distinct Batch PIR bucket indices (same as production).
fn derive_buckets(sh: &[u8]) -> [usize; NUM_BATCH_HASHES] {
    let mut buckets = [0usize; NUM_BATCH_HASHES];
    let mut nonce: u64 = 0;
    let mut count = 0;
    while count < NUM_BATCH_HASHES {
        let h = hash_for_bucket(sh, nonce);
        let bucket = (h % K as u64) as usize;
        nonce += 1;
        let mut dup = false;
        for i in 0..count {
            if buckets[i] == bucket { dup = true; break; }
        }
        if dup { continue; }
        buckets[count] = bucket;
        count += 1;
    }
    buckets
}

/// Derive cuckoo hash key for a given (group, hash_fn).
#[inline]
fn derive_cuckoo_key(group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        0x71a2ef38b4c90d15_u64
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

#[inline]
fn cuckoo_hash(sh: &[u8], key: u64, num_bins: usize) -> usize {
    let mut h = sh_a(sh) ^ key;
    h ^= sh_b(sh);
    h = splitmix64(h ^ sh_c(sh));
    (h % num_bins as u64) as usize
}

struct GroupResult {
    group_id: usize,
    num_entries: usize,
    num_bins: usize,
    stash_size: usize,
    total_kicks: u64,
    max_kick_chain: u64,
    occupied: usize,
    occupancy_counts: Vec<u64>,
    hash_location_counts: Vec<u64>, // how many entries ended up in their i-th hash location
}

fn build_cuckoo_for_group(
    group_id: usize,
    entries: &[u32],
    mmap: &[u8],
    num_bins: usize,
) -> GroupResult {
    let num_entries = entries.len();
    let total_slots = num_bins * CUCKOO_BUCKET_SIZE;

    let mut keys = [0u64; CUCKOO_NUM_HASHES];
    for h in 0..CUCKOO_NUM_HASHES {
        keys[h] = derive_cuckoo_key(group_id, h);
    }

    let mut table = vec![EMPTY; total_slots];
    let mut stash: Vec<u32> = Vec::new();
    let mut total_kicks: u64 = 0;
    let mut max_kick_chain: u64 = 0;

    let get_sh = |i: u32| -> &[u8] {
        let base = i as usize * INDEX_ENTRY_SIZE;
        &mmap[base..base + SCRIPT_HASH_SIZE]
    };

    let compute_bins = |sh: &[u8]| -> Vec<usize> {
        (0..CUCKOO_NUM_HASHES)
            .map(|h| cuckoo_hash(sh, keys[h], num_bins))
            .collect()
    };

    for &idx in entries {
        let sh = get_sh(idx);
        let bins = compute_bins(sh);

        // Try empty slot
        let mut placed = false;
        for &bin in &bins {
            let base = bin * CUCKOO_BUCKET_SIZE;
            for s in 0..CUCKOO_BUCKET_SIZE {
                if table[base + s] == EMPTY {
                    table[base + s] = idx;
                    placed = true;
                    break;
                }
            }
            if placed { break; }
        }
        if placed { continue; }

        // Cuckoo kick — match production eviction strategy
        let mut current_idx = idx;
        let mut current_bin = bins[0]; // start evicting from first bin
        let mut kicks: u64 = 0;
        let mut success = false;

        for kick in 0..CUCKOO_MAX_KICKS {
            // Evict from current_bin, varying slot to avoid 2-cycles
            let base = current_bin * CUCKOO_BUCKET_SIZE;
            let slot = kick % CUCKOO_BUCKET_SIZE;
            let evicted_idx = table[base + slot];
            table[base + slot] = current_idx;

            // Find alternative bins for the evicted entry (not current_bin)
            let ev_sh = get_sh(evicted_idx);
            let ev_bins = compute_bins(ev_sh);

            // Try ALL alternative bins for empty slots
            let mut placed = false;
            let mut first_alt = current_bin; // fallback for continued eviction
            for &b in &ev_bins {
                if b == current_bin { continue; }
                if first_alt == current_bin { first_alt = b; }
                let alt_base = b * CUCKOO_BUCKET_SIZE;
                for s in 0..CUCKOO_BUCKET_SIZE {
                    if table[alt_base + s] == EMPTY {
                        table[alt_base + s] = evicted_idx;
                        placed = true;
                        break;
                    }
                }
                if placed { break; }
            }

            if placed {
                success = true;
                kicks = kick as u64 + 1;
                break;
            }

            // Continue evicting from first alternative bin
            // Cycle through alt bins to avoid loops
            let mut alt_bin = first_alt;
            if CUCKOO_NUM_HASHES > 2 {
                // Rotate through alternatives based on kick count
                let alts: Vec<usize> = ev_bins.iter().filter(|&&b| b != current_bin).copied().collect();
                if !alts.is_empty() {
                    alt_bin = alts[kick % alts.len()];
                }
            }
            current_idx = evicted_idx;
            current_bin = alt_bin;
            kicks = kick as u64 + 1;
        }

        total_kicks += kicks;
        if kicks > max_kick_chain {
            max_kick_chain = kicks;
        }

        if !success {
            stash.push(current_idx);
        }
    }

    // Occupancy stats
    let mut occupancy_counts = vec![0u64; CUCKOO_BUCKET_SIZE + 1];
    for bin in 0..num_bins {
        let base = bin * CUCKOO_BUCKET_SIZE;
        let occ = (0..CUCKOO_BUCKET_SIZE).filter(|&s| table[base + s] != EMPTY).count();
        occupancy_counts[occ] += 1;
    }

    let occupied = table.iter().filter(|&&x| x != EMPTY).count();

    // Hash location stats: for each placed entry, which hash function's bin is it in?
    let mut hash_location_counts = vec![0u64; CUCKOO_NUM_HASHES];
    for bin in 0..num_bins {
        let base = bin * CUCKOO_BUCKET_SIZE;
        for s in 0..CUCKOO_BUCKET_SIZE {
            let idx = table[base + s];
            if idx == EMPTY { continue; }
            let sh = get_sh(idx);
            let bins = compute_bins(sh);
            for h in 0..CUCKOO_NUM_HASHES {
                if bins[h] == bin {
                    hash_location_counts[h] += 1;
                    break;
                }
            }
        }
    }

    GroupResult {
        group_id,
        num_entries,
        num_bins,
        stash_size: stash.len(),
        total_kicks,
        max_kick_chain,
        occupied,
        occupancy_counts,
        hash_location_counts,
    }
}

fn main() {
    println!("=== Cuckoo Experiment: 75-group split, {} cuckoo hashes, bucket_size={}, LF={} ===\n",
        CUCKOO_NUM_HASHES, CUCKOO_BUCKET_SIZE, CUCKOO_LOAD_FACTOR);
    let start = Instant::now();

    // ── Load index ───────────────────────────────────────────────────────
    println!("[1] Loading index: {}", INDEX_FILE);
    let file = File::open(INDEX_FILE).unwrap();
    let mmap = unsafe { Mmap::map(&file) }.unwrap();
    let n = mmap.len() / INDEX_ENTRY_SIZE;
    println!("  Entries: {}\n", n);

    // ── Assign to 75 groups ──────────────────────────────────────────────
    println!("[2] Assigning entries to {} groups ({} copies each)...", K, NUM_BATCH_HASHES);
    let assign_start = Instant::now();

    let expected_per_group = (n * NUM_BATCH_HASHES) / K + 1;
    let mut groups: Vec<Vec<u32>> = (0..K).map(|_| Vec::with_capacity(expected_per_group)).collect();

    for i in 0..n {
        let base = i * INDEX_ENTRY_SIZE;
        let sh = &mmap[base..base + SCRIPT_HASH_SIZE];
        let buckets = derive_buckets(sh);
        for &b in &buckets {
            groups[b].push(i as u32);
        }
    }

    let group_loads: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    let min_load = *group_loads.iter().min().unwrap();
    let max_load = *group_loads.iter().max().unwrap();
    let avg_load = group_loads.iter().sum::<usize>() as f64 / K as f64;

    println!("  Done in {:.2?}", assign_start.elapsed());
    println!("  Group loads: min={}, max={}, avg={:.0}", min_load, max_load, avg_load);

    // Uniform bins_per_table from max load
    let bins_per_table = ((max_load as f64) / (CUCKOO_BUCKET_SIZE as f64 * CUCKOO_LOAD_FACTOR)).ceil() as usize;
    let slots_per_table = bins_per_table * CUCKOO_BUCKET_SIZE;
    println!("  Bins per table: {} (slots: {})\n", bins_per_table, slots_per_table);

    // ── Build cuckoo tables in parallel ──────────────────────────────────
    println!("[3] Building cuckoo tables for {} groups in parallel...", K);
    let cuckoo_start = Instant::now();

    let completed = AtomicUsize::new(0);
    let mmap_slice: &[u8] = &mmap;

    let results: Vec<GroupResult> = groups
        .into_par_iter()
        .enumerate()
        .map(|(gid, entries)| {
            let r = build_cuckoo_for_group(gid, &entries, mmap_slice, bins_per_table);
            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            if done % 10 == 0 || done == K {
                eprint!("\r  Progress: {}/{} groups", done, K);
            }
            r
        })
        .collect();

    eprintln!();
    println!("  Done in {:.2?}\n", cuckoo_start.elapsed());

    // ── Results ──────────────────────────────────────────────────────────
    let total_stash: usize = results.iter().map(|r| r.stash_size).sum();
    let total_kicks: u64 = results.iter().map(|r| r.total_kicks).sum();
    let global_max_kick: u64 = results.iter().map(|r| r.max_kick_chain).max().unwrap_or(0);
    let total_occupied: usize = results.iter().map(|r| r.occupied).sum();
    let total_slots = K * slots_per_table;
    let groups_with_stash = results.iter().filter(|r| r.stash_size > 0).count();

    println!("[4] Overall results:");
    println!("  Total entries placed: {}", total_occupied);
    println!("  Total stash: {}", total_stash);
    println!("  Groups with stash > 0: {}", groups_with_stash);
    println!("  Total kicks: {}", total_kicks);
    println!("  Max kick chain: {}", global_max_kick);
    println!("  Fill rate: {:.4}% ({} / {} slots)", total_occupied as f64 / total_slots as f64 * 100.0, total_occupied, total_slots);

    // Aggregate occupancy
    let mut agg_occupancy = vec![0u64; CUCKOO_BUCKET_SIZE + 1];
    for r in &results {
        for (occ, &count) in r.occupancy_counts.iter().enumerate() {
            agg_occupancy[occ] += count;
        }
    }
    let total_bins = K * bins_per_table;
    println!("\n[5] Bucket occupancy (across all {} groups, {} total bins):", K, total_bins);
    for occ in 0..=CUCKOO_BUCKET_SIZE {
        println!("  {}/{} slots used: {} bins ({:.2}%)",
            occ, CUCKOO_BUCKET_SIZE, agg_occupancy[occ],
            agg_occupancy[occ] as f64 / total_bins as f64 * 100.0);
    }

    // Show worst groups
    let mut worst: Vec<&GroupResult> = results.iter().filter(|r| r.stash_size > 0).collect();
    worst.sort_by(|a, b| b.stash_size.cmp(&a.stash_size));
    if !worst.is_empty() {
        println!("\n[6] Worst groups (stash > 0):");
        for r in worst.iter().take(10) {
            println!("  Group {}: {} entries, stash={}, kicks={}, max_chain={}",
                r.group_id, r.num_entries, r.stash_size, r.total_kicks, r.max_kick_chain);
        }
    }

    // Hash location stats
    let mut agg_hash_loc = vec![0u64; CUCKOO_NUM_HASHES];
    for r in &results {
        for (h, &count) in r.hash_location_counts.iter().enumerate() {
            agg_hash_loc[h] += count;
        }
    }
    println!("\n[6] Hash location distribution (which hash fn each entry landed in):");
    for h in 0..CUCKOO_NUM_HASHES {
        println!("  Hash {}: {} entries ({:.2}%)",
            h, agg_hash_loc[h], agg_hash_loc[h] as f64 / total_occupied as f64 * 100.0);
    }

    // Show worst groups
    let mut worst: Vec<&GroupResult> = results.iter().filter(|r| r.stash_size > 0).collect();
    worst.sort_by(|a, b| b.stash_size.cmp(&a.stash_size));
    if !worst.is_empty() {
        println!("\n[7] Worst groups (stash > 0):");
        for r in worst.iter().take(10) {
            println!("  Group {}: {} entries, stash={}, kicks={}, max_chain={}",
                r.group_id, r.num_entries, r.stash_size, r.total_kicks, r.max_kick_chain);
        }
    }

    // File size estimate
    let file_bytes = total_slots * 4; // each slot is a u32
    println!("\n[8] Storage estimate:");
    println!("  Cuckoo tables: {:.2} MB ({} groups x {} bins x {} slots x 4B)",
        file_bytes as f64 / (1024.0 * 1024.0), K, bins_per_table, CUCKOO_BUCKET_SIZE);

    println!("\n  Total time: {:.2?}", start.elapsed());
}
