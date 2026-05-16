//! Test the two new cuckoo table configurations for OnionPIR integration.
//!
//! A) Index level: 2 hash functions, slots_per_bin=256, load_factor=0.95
//!    - ~2M entries per group (matching 50M addresses × 3 / 75)
//!    - Each bin holds 256 × 15-byte slots = 3840 bytes = one OnionPIR entry
//!    - Client tries both bins, scans for tag match
//!
//! B) Chunk level: 6 hash functions, slots_per_bin=1, load_factor=0.95
//!    - ~43K entries per group (matching 1.09M entries × 3 / 80)
//!    - Client computes table deterministically → knows exact bin → 1 query
//!    - Test: rebuild from scratch on "client side" → verify identical placement
//!
//! Uses synthetic data (random entry IDs), no real UTXO files needed.
//!
//! Usage: cargo run --release -p build --bin test_onion_cuckoo

use std::time::Instant;

// ─── Hash utilities (same as common.rs) ──────────────────────────────────────

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

/// Derive a cuckoo hash key for a given (group_id, hash_fn_index).
#[inline]
fn derive_cuckoo_key(seed: u64, group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        seed.wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

/// Hash an integer entry_id to a bin index using a derived key.
#[inline]
fn cuckoo_hash_int(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

const EMPTY: u32 = u32::MAX;

// ═════════════════════════════════════════════════════════════════════════════
// A) INDEX CUCKOO: 2-hash, slots_per_bin=256, load=0.95
// ═════════════════════════════════════════════════════════════════════════════

fn test_index_cuckoo() {
    const NUM_HASHES: usize = 2;
    const SLOTS_PER_BIN: usize = 256;
    const LOAD_FACTOR: f64 = 0.95;
    const MAX_KICKS: usize = 5000;
    const ENTRIES_PER_GROUP: usize = 2_000_000; // ~50M × 3 / 75

    println!("=== A) Index Cuckoo: {}-hash, slots_per_bin={}, LF={} ===",
        NUM_HASHES, SLOTS_PER_BIN, LOAD_FACTOR);
    println!("  Entries per group: {}", ENTRIES_PER_GROUP);

    let num_bins = ((ENTRIES_PER_GROUP as f64) / (SLOTS_PER_BIN as f64 * LOAD_FACTOR)).ceil() as usize;
    let total_capacity = num_bins * SLOTS_PER_BIN;
    println!("  num_bins: {}", num_bins);
    println!("  total capacity: {} (entries/capacity = {:.4})",
        total_capacity, ENTRIES_PER_GROUP as f64 / total_capacity as f64);

    let group_id = 0;
    let seed = 0x71a2ef38b4c90d15_u64;

    let mut keys = [0u64; NUM_HASHES];
    for (h, key) in keys.iter_mut().enumerate() {
        *key = derive_cuckoo_key(seed, group_id, h);
    }

    // Each bin has SLOTS_PER_BIN slots; each slot holds an entry_id (u32).
    // table[bin * SLOTS_PER_BIN + slot] = entry_id or EMPTY
    let mut table = vec![EMPTY; num_bins * SLOTS_PER_BIN];
    // Track how many slots are used per bin
    let mut bin_occupancy = vec![0u16; num_bins];

    let t = Instant::now();
    let mut stash_count = 0usize;
    let mut total_kicks = 0u64;
    let mut max_chain = 0u64;

    // Generate synthetic entry IDs: 0..ENTRIES_PER_GROUP
    for entry_id in 0..ENTRIES_PER_GROUP as u32 {
        let bins: [usize; NUM_HASHES] = std::array::from_fn(|h| {
            cuckoo_hash_int(entry_id, keys[h], num_bins)
        });

        // Try to place in whichever bin has more space (2-choice hashing)
        let mut placed = false;
        // Sort by occupancy (prefer less full bin)
        let mut bin_order: Vec<usize> = bins.to_vec();
        bin_order.sort_by_key(|&b| bin_occupancy[b]);

        for &bin in &bin_order {
            let occ = bin_occupancy[bin] as usize;
            if occ < SLOTS_PER_BIN {
                table[bin * SLOTS_PER_BIN + occ] = entry_id;
                bin_occupancy[bin] += 1;
                placed = true;
                break;
            }
        }

        if !placed {
            // Both bins are full — try cuckoo eviction
            let mut current_id = entry_id;
            let mut current_bin = bins[0];
            let mut kicked = false;

            for kick in 0..MAX_KICKS {
                // Evict the last entry from current_bin
                let occ = bin_occupancy[current_bin] as usize;
                let evict_slot = kick % occ; // vary slot
                let evicted = table[current_bin * SLOTS_PER_BIN + evict_slot];
                table[current_bin * SLOTS_PER_BIN + evict_slot] = current_id;

                // Find alternative bin for evicted entry
                let ev_bins: [usize; NUM_HASHES] = std::array::from_fn(|h| {
                    cuckoo_hash_int(evicted, keys[h], num_bins)
                });
                let alt_bin = if ev_bins[0] == current_bin { ev_bins[1] } else { ev_bins[0] };

                let alt_occ = bin_occupancy[alt_bin] as usize;
                if alt_occ < SLOTS_PER_BIN {
                    table[alt_bin * SLOTS_PER_BIN + alt_occ] = evicted;
                    bin_occupancy[alt_bin] += 1;
                    kicked = true;
                    total_kicks += kick as u64 + 1;
                    if kick as u64 + 1 > max_chain {
                        max_chain = kick as u64 + 1;
                    }
                    break;
                }

                current_id = evicted;
                current_bin = alt_bin;
            }

            if !kicked {
                stash_count += 1;
            }
        }
    }
    let build_time = t.elapsed();

    // Stats
    let total_placed: usize = bin_occupancy.iter().map(|&o| o as usize).sum();
    let max_occ = *bin_occupancy.iter().max().unwrap();
    let min_occ = *bin_occupancy.iter().min().unwrap();
    let avg_occ = total_placed as f64 / num_bins as f64;

    // Occupancy distribution (sample some buckets)
    let mut occ_histogram = vec![0u32; SLOTS_PER_BIN + 1];
    for &occ in &bin_occupancy {
        occ_histogram[occ as usize] += 1;
    }

    println!("\n  Results:");
    println!("    Build time:       {:.2?}", build_time);
    println!("    Entries placed:   {} / {} ({:.4}%)",
        total_placed, ENTRIES_PER_GROUP,
        total_placed as f64 / ENTRIES_PER_GROUP as f64 * 100.0);
    println!("    Stash:            {}", stash_count);
    println!("    Total kicks:      {}", total_kicks);
    println!("    Max kick chain:   {}", max_chain);
    println!("    Bin occupancy:    min={}, max={}, avg={:.1}", min_occ, max_occ, avg_occ);

    // Show occupancy distribution (just the extremes)
    println!("\n    Occupancy distribution:");
    println!("      Empty bins (0 slots): {}", occ_histogram[0]);
    let low = occ_histogram.iter().enumerate()
        .take(SLOTS_PER_BIN / 2)
        .filter(|(_, &c)| c > 0)
        .take(5);
    for (occ, &count) in low {
        println!("      {} slots: {} bins", occ, count);
    }
    println!("      ...");
    let high_start = if avg_occ > 10.0 { avg_occ as usize - 5 } else { 0 };
    for (occ, &count) in occ_histogram.iter().enumerate().skip(high_start) {
        if count > 0 {
            println!("      {} slots: {} bins", occ, count);
        }
    }

    // Verify all entries are findable
    println!("\n    Verifying all entries findable by tag scan...");
    let t_verify = Instant::now();
    let mut found = 0usize;
    let mut not_found = 0usize;
    for entry_id in 0..ENTRIES_PER_GROUP as u32 {
        let bins: [usize; NUM_HASHES] = std::array::from_fn(|h| {
            cuckoo_hash_int(entry_id, keys[h], num_bins)
        });

        let mut entry_found = false;
        for &bin in &bins {
            let occ = bin_occupancy[bin] as usize;
            for s in 0..occ {
                if table[bin * SLOTS_PER_BIN + s] == entry_id {
                    entry_found = true;
                    break;
                }
            }
            if entry_found { break; }
        }

        if entry_found {
            found += 1;
        } else {
            not_found += 1;
        }
    }
    println!("    Verify time:  {:.2?}", t_verify.elapsed());
    println!("    Found: {}, Not found: {} (should be = stash count)", found, not_found);

    if stash_count == 0 {
        println!("    STATUS: PASS");
    } else {
        println!("    STATUS: FAIL ({} entries in stash)", stash_count);
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// B) CHUNK CUCKOO: 6-hash, slots_per_bin=1, load=0.95
// ═════════════════════════════════════════════════════════════════════════════

/// Build a cuckoo table with `num_hashes` hash functions, slots_per_bin=1.
/// Returns (table, success). Table maps bin → entry_id.
fn build_cuckoo_bs1(
    entries: &[u32],
    keys: &[u64],
    num_bins: usize,
    max_kicks: usize,
) -> (Vec<u32>, usize, u64, u64) {
    let num_hashes = keys.len();
    let mut table = vec![EMPTY; num_bins];
    let mut stash_count = 0usize;
    let mut total_kicks = 0u64;
    let mut max_chain = 0u64;

    for &entry_id in entries {
        // Try all hash positions for an empty slot
        let mut placed = false;
        for &key in keys {
            let bin = cuckoo_hash_int(entry_id, key, num_bins);
            if table[bin] == EMPTY {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if placed {
            continue;
        }

        // Cuckoo eviction
        let mut current_id = entry_id;
        let mut current_hash_fn = 0;
        let mut current_bin = cuckoo_hash_int(entry_id, keys[0], num_bins);
        let mut kicked = false;

        for kick in 0..max_kicks {
            // Evict from current_bin
            let evicted = table[current_bin];
            table[current_bin] = current_id;

            // Find alternative bins for evicted
            let mut found_empty = false;
            // Cycle through hash functions, skipping current_bin
            let mut next_hash_fn = 0;
            for h in 0..num_hashes {
                // Rotate based on kick count to avoid cycles
                let try_h = (current_hash_fn + 1 + h) % num_hashes;
                let bin = cuckoo_hash_int(evicted, keys[try_h], num_bins);
                if bin == current_bin {
                    continue;
                }
                if table[bin] == EMPTY {
                    table[bin] = evicted;
                    found_empty = true;
                    total_kicks += kick as u64 + 1;
                    if kick as u64 + 1 > max_chain {
                        max_chain = kick as u64 + 1;
                    }
                    kicked = true;
                    break;
                }
                if next_hash_fn == 0 || (kick + h) % 2 == 0 {
                    next_hash_fn = try_h;
                }
            }

            if found_empty {
                break;
            }

            // Continue evicting — pick a different bin
            let alt_h = (current_hash_fn + 1 + kick % (num_hashes - 1)) % num_hashes;
            let alt_bin = cuckoo_hash_int(evicted, keys[alt_h], num_bins);
            // If we happen to get the same bin, try another hash function
            let final_bin = if alt_bin == current_bin {
                let h2 = (alt_h + 1) % num_hashes;
                cuckoo_hash_int(evicted, keys[h2], num_bins)
            } else {
                alt_bin
            };

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        if !kicked {
            stash_count += 1;
        }
    }

    (table, stash_count, total_kicks, max_chain)
}

fn test_chunk_cuckoo() {
    const NUM_HASHES: usize = 6;
    const LOAD_FACTOR: f64 = 0.95;
    const MAX_KICKS: usize = 10000;
    const ENTRIES_PER_GROUP: usize = 40_900; // ~1.09M × 3 / 80

    println!("\n=== B) Chunk Cuckoo: {}-hash, slots_per_bin=1, LF={} ===",
        NUM_HASHES, LOAD_FACTOR);
    println!("  Entries per group: {}", ENTRIES_PER_GROUP);

    let num_bins = (ENTRIES_PER_GROUP as f64 / LOAD_FACTOR).ceil() as usize;
    println!("  num_bins: {}", num_bins);
    println!("  target fill: {:.4}%", ENTRIES_PER_GROUP as f64 / num_bins as f64 * 100.0);

    let group_id = 0;
    let seed = 0xa3f7c2d918e4b065_u64; // chunk master seed

    let mut keys = [0u64; NUM_HASHES];
    for (h, key) in keys.iter_mut().enumerate() {
        *key = derive_cuckoo_key(seed, group_id, h);
    }

    // Generate sorted entry IDs (deterministic order is key!)
    let mut entries: Vec<u32> = (0..ENTRIES_PER_GROUP as u32).collect();
    entries.sort(); // already sorted, but being explicit

    // ── Build 1: Server-side construction ────────────────────────────────
    println!("\n  [Build 1] Server-side construction...");
    let t1 = Instant::now();
    let (table1, stash1, kicks1, max_chain1) =
        build_cuckoo_bs1(&entries, &keys, num_bins, MAX_KICKS);
    let build1_time = t1.elapsed();

    let occupied1 = table1.iter().filter(|&&x| x != EMPTY).count();
    println!("    Build time:       {:.2?}", build1_time);
    println!("    Entries placed:   {} / {} ({:.4}%)",
        occupied1, ENTRIES_PER_GROUP,
        occupied1 as f64 / ENTRIES_PER_GROUP as f64 * 100.0);
    println!("    Stash:            {}", stash1);
    println!("    Total kicks:      {}", kicks1);
    println!("    Max kick chain:   {}", max_chain1);
    println!("    Fill rate:        {:.4}% ({}/{})",
        occupied1 as f64 / num_bins as f64 * 100.0, occupied1, num_bins);

    // ── Build 2: Client-side replay (must produce identical table) ───────
    println!("\n  [Build 2] Client-side replay (deterministic)...");
    let t2 = Instant::now();
    let (table2, stash2, _, _) =
        build_cuckoo_bs1(&entries, &keys, num_bins, MAX_KICKS);
    let build2_time = t2.elapsed();

    println!("    Build time:       {:.2?}", build2_time);

    // Verify identical placement
    let identical = table1 == table2;
    println!("    Tables identical: {}", if identical { "YES" } else { "NO !!!" });
    if stash1 != stash2 {
        println!("    Stash mismatch:   server={}, client={}", stash1, stash2);
    }

    if !identical {
        let mut diffs = 0;
        for i in 0..num_bins {
            if table1[i] != table2[i] {
                diffs += 1;
                if diffs <= 5 {
                    println!("    bin {}: server={}, client={}", i,
                        if table1[i] == EMPTY { "EMPTY".to_string() } else { table1[i].to_string() },
                        if table2[i] == EMPTY { "EMPTY".to_string() } else { table2[i].to_string() });
                }
            }
        }
        println!("    Total differing bins: {}", diffs);
    }

    // ── Verify all entries are findable with 1 query ─────────────────────
    println!("\n  [Verify] All entries findable by exact bin lookup...");
    let t_verify = Instant::now();
    let mut found = 0usize;
    let mut not_found = 0usize;
    for &entry_id in &entries {
        let mut entry_found = false;
        for &key in &keys {
            let bin = cuckoo_hash_int(entry_id, key, num_bins);
            if table1[bin] == entry_id {
                entry_found = true;
                break;
            }
        }
        if entry_found {
            found += 1;
        } else {
            not_found += 1;
        }
    }
    println!("    Verify time:  {:.2?}", t_verify.elapsed());
    println!("    Found: {}, Not found: {} (should be = stash count)", found, not_found);

    // ── Client lookup test: given an entry, client knows exact bin ────────
    println!("\n  [Client lookup] Client computes table, looks up specific entry...");
    let test_entry: u32 = 12345;
    // Client rebuilds the table (same as build 2)
    // Then looks up: for each hash fn, check if table[hash(entry, key)] == entry
    let mut lookup_bin = None;
    for (h, &key) in keys.iter().enumerate() {
        let bin = cuckoo_hash_int(test_entry, key, num_bins);
        if table2[bin] == test_entry {
            lookup_bin = Some((h, bin));
            break;
        }
    }
    match lookup_bin {
        Some((h, bin)) => println!("    Entry {} found at bin {} (hash fn {})", test_entry, bin, h),
        None => println!("    Entry {} NOT FOUND (in stash?)", test_entry),
    }

    // Overall status
    if stash1 == 0 && identical {
        println!("\n    STATUS: PASS");
    } else if stash1 > 0 {
        println!("\n    STATUS: FAIL ({} entries in stash — need larger table or more hash functions)", stash1);
    } else {
        println!("\n    STATUS: FAIL (tables not identical — deterministic replay broken)");
    }
}

// ═════════════════════════════════════════════════════════════════════════════

fn main() {
    println!("OnionPIR Cuckoo Table Design Validation");
    println!("========================================\n");

    test_index_cuckoo();
    test_chunk_cuckoo();

    println!("\n========================================");
    println!("Done.");
}
