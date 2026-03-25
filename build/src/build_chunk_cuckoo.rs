//! Build Batch-PIR cuckoo tables over the 40-byte UTXO chunks (inlined).
//!
//! 1. Reads the chunks file, computes N = file_size / 40.
//! 2. Assigns each chunk_id (0..N) to 3 distinct buckets out of K_CHUNK=80.
//! 3. Within each bucket, builds a cuckoo hash table (2 hash fns, bucket size 3,
//!    load factor 0.95).  Each slot stores a u32 chunk_id internally.
//! 4. Serialises all 80 tables to `chunk_pir_cuckoo.bin` with inlined data:
//!    each slot is [4B chunk_id LE | 40B chunk_data] = 44 bytes.
//!    Empty slots are all-zero.
//!
//! Usage:
//!   cargo run --release -p build --bin build_chunk_cuckoo

use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Path to the UTXO chunks data file (80-byte blocks, no dust)
const CHUNKS_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_nodust.bin";

/// Output file for the chunk-level cuckoo tables
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/chunk_pir_cuckoo.bin";

/// Size of one chunk in bytes
const CHUNK_SIZE: usize = 40;

/// Number of Batch PIR buckets for chunks
const K: usize = 80;

/// Number of bucket assignments per chunk
const NUM_HASHES: usize = 3;

/// Cuckoo hash table parameters
const CUCKOO_BUCKET_SIZE: usize = 3;
const CUCKOO_NUM_HASHES: usize = 2;
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 2000;
const EMPTY: u32 = u32::MAX;

/// Master PRG seed — different from the first-level (0x71a2ef38b4c90d15)
const MASTER_SEED: u64 = 0xa3f7c2d918e4b065;

/// File format magic (different from first-level 0xBA7C_C000_C000_0001)
const MAGIC: u64 = 0xBA7C_C000_C000_0002;

/// Header size in bytes
const HEADER_SIZE: usize = 32;

// ─── Hash utilities ──────────────────────────────────────────────────────────

/// Splitmix64 finalizer.
#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

/// Hash a chunk_id with a nonce for bucket assignment.
#[inline]
fn hash_chunk_for_bucket(chunk_id: u32, nonce: u64) -> u64 {
    splitmix64((chunk_id as u64).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15)))
}

/// Derive 3 distinct bucket indices for a chunk_id.
fn derive_chunk_buckets(chunk_id: u32) -> [usize; NUM_HASHES] {
    let mut buckets = [0usize; NUM_HASHES];
    let mut nonce: u64 = 0;
    let mut count = 0;

    while count < NUM_HASHES {
        let h = hash_chunk_for_bucket(chunk_id, nonce);
        let bucket = (h % K as u64) as usize;
        nonce += 1;

        let mut dup = false;
        for i in 0..count {
            if buckets[i] == bucket {
                dup = true;
                break;
            }
        }
        if dup {
            continue;
        }

        buckets[count] = bucket;
        count += 1;
    }

    buckets
}

/// Derive a cuckoo hash function key for (bucket, hash_fn).
#[inline]
fn derive_cuckoo_key(bucket_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        MASTER_SEED
            .wrapping_add((bucket_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

/// Cuckoo hash: map a chunk_id to a bin index using a derived key.
#[inline]
fn cuckoo_hash_int(chunk_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((chunk_id as u64) ^ key) % num_bins as u64) as usize
}

// ─── Cuckoo builder ──────────────────────────────────────────────────────────

struct CuckooResult {
    bucket_id: usize,
    num_entries: usize,
    num_bins: usize,
    _table_slots: usize,
    occupied: usize,
    success: bool,
}

fn build_cuckoo_for_bucket(
    bucket_id: usize,
    entries: &[u32],
    num_bins: usize,
) -> (Vec<u32>, CuckooResult) {
    let num_entries = entries.len();
    if num_entries == 0 {
        return (
            vec![EMPTY; num_bins * CUCKOO_BUCKET_SIZE],
            CuckooResult {
                bucket_id,
                num_entries: 0,
                num_bins,
                _table_slots: num_bins * CUCKOO_BUCKET_SIZE,
                occupied: 0,
                success: true,
            },
        );
    }

    let table_slots = num_bins * CUCKOO_BUCKET_SIZE;
    let mut table = vec![EMPTY; table_slots];

    let mut keys = [0u64; CUCKOO_NUM_HASHES];
    for h in 0..CUCKOO_NUM_HASHES {
        keys[h] = derive_cuckoo_key(bucket_id, h);
    }

    let mut success = true;

    for &chunk_id in entries {
        if !cuckoo_insert(&mut table, chunk_id, &keys, num_bins) {
            success = false;
            break;
        }
    }

    let occupied = table.iter().filter(|&&v| v != EMPTY).count();

    (
        table,
        CuckooResult {
            bucket_id,
            num_entries,
            num_bins,
            _table_slots: table_slots,
            occupied,
            success,
        },
    )
}

/// Compute all cuckoo bin positions for a chunk_id.
#[inline]
fn compute_bins(chunk_id: u32, keys: &[u64; CUCKOO_NUM_HASHES], num_bins: usize) -> [usize; CUCKOO_NUM_HASHES] {
    let mut bins = [0usize; CUCKOO_NUM_HASHES];
    for h in 0..CUCKOO_NUM_HASHES {
        bins[h] = cuckoo_hash_int(chunk_id, keys[h], num_bins);
    }
    bins
}

/// Cuckoo insert with eviction chain (supports N hash functions).
fn cuckoo_insert(
    table: &mut [u32],
    chunk_id: u32,
    keys: &[u64; CUCKOO_NUM_HASHES],
    num_bins: usize,
) -> bool {
    let bins = compute_bins(chunk_id, keys, num_bins);

    // Try all bins for an empty slot
    for h in 0..CUCKOO_NUM_HASHES {
        let base = bins[h] * CUCKOO_BUCKET_SIZE;
        for s in 0..CUCKOO_BUCKET_SIZE {
            if table[base + s] == EMPTY {
                table[base + s] = chunk_id;
                return true;
            }
        }
    }

    // Eviction loop
    let mut current_id = chunk_id;
    let mut current_bin = bins[0];

    for kick in 0..CUCKOO_MAX_KICKS {
        let base = current_bin * CUCKOO_BUCKET_SIZE;
        let slot = kick % CUCKOO_BUCKET_SIZE;
        let evicted_id = table[base + slot];
        table[base + slot] = current_id;

        let ev_bins = compute_bins(evicted_id, keys, num_bins);

        // Try all alternative bins for empty slots
        let mut placed = false;
        let mut first_alt = current_bin;
        for &b in &ev_bins {
            if b == current_bin { continue; }
            if first_alt == current_bin { first_alt = b; }
            let alt_base = b * CUCKOO_BUCKET_SIZE;
            for s in 0..CUCKOO_BUCKET_SIZE {
                if table[alt_base + s] == EMPTY {
                    table[alt_base + s] = evicted_id;
                    placed = true;
                    break;
                }
            }
            if placed { break; }
        }

        if placed {
            return true;
        }

        // Continue evicting — rotate through alternatives
        let alts: Vec<usize> = ev_bins.iter().filter(|&&b| b != current_bin).copied().collect();
        let alt_bin = if alts.is_empty() { current_bin } else { alts[kick % alts.len()] };
        current_id = evicted_id;
        current_bin = alt_bin;
    }

    false
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    println!("=== Chunk-level Batch PIR: Cuckoo Table Builder ===");
    println!();

    let start = Instant::now();

    // ── Step 1: Determine number of chunks ────────────────────────────────
    println!("[1] Reading chunks file: {}", CHUNKS_FILE);
    let file_meta = std::fs::metadata(CHUNKS_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to stat chunks file: {}", e);
        std::process::exit(1);
    });
    let file_size = file_meta.len() as usize;
    if file_size % CHUNK_SIZE != 0 {
        eprintln!(
            "Chunks file size ({}) is not a multiple of chunk size ({})",
            file_size, CHUNK_SIZE
        );
        std::process::exit(1);
    }

    let n_chunks = file_size / CHUNK_SIZE;
    println!(
        "  N = {} chunks ({:.2} GB)",
        n_chunks,
        file_size as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    if n_chunks > u32::MAX as usize {
        eprintln!("Too many chunks for u32 addressing: {}", n_chunks);
        std::process::exit(1);
    }
    println!("  k = {} buckets, {} hashes per chunk", K, NUM_HASHES);
    println!();

    // ── Step 2: Assign chunks to buckets ──────────────────────────────────
    println!("[2] Assigning {} chunks to {} buckets...", n_chunks, K);
    let assign_start = Instant::now();

    let expected_per_bucket = (n_chunks * NUM_HASHES) / K + 1;
    let mut buckets: Vec<Vec<u32>> = (0..K)
        .map(|_| Vec::with_capacity(expected_per_bucket))
        .collect();

    for chunk_id in 0..n_chunks as u32 {
        let bucket_indices = derive_chunk_buckets(chunk_id);
        for &b in &bucket_indices {
            buckets[b].push(chunk_id);
        }

        if (chunk_id as usize + 1) % 10_000_000 == 0 {
            eprint!("\r  Assigned: {}/{}", chunk_id + 1, n_chunks);
            let _ = io::stderr().flush();
        }
    }
    eprintln!();

    let bucket_loads: Vec<usize> = buckets.iter().map(|b| b.len()).collect();
    let min_load = *bucket_loads.iter().min().unwrap();
    let max_load = *bucket_loads.iter().max().unwrap();
    let total_refs: usize = bucket_loads.iter().sum();
    let expected = n_chunks as f64 * NUM_HASHES as f64 / K as f64;

    println!("  Done in {:.2?}", assign_start.elapsed());
    println!(
        "  Bucket loads: min={}, max={}, expected={:.0}, max/expected={:.4}",
        min_load,
        max_load,
        expected,
        max_load as f64 / expected
    );
    println!(
        "  Total refs: {} (check: {} = N*{})",
        total_refs,
        n_chunks * NUM_HASHES,
        NUM_HASHES
    );
    println!();

    // ── Step 3: Build cuckoo tables in parallel ───────────────────────────
    let bins_per_table =
        ((max_load as f64) / (CUCKOO_BUCKET_SIZE as f64 * CUCKOO_LOAD_FACTOR)).ceil() as usize;

    println!(
        "[3] Building Cuckoo tables ({} hash fns, bucket_size={}, load={}, uniform bins={})...",
        CUCKOO_NUM_HASHES,
        CUCKOO_BUCKET_SIZE, CUCKOO_LOAD_FACTOR, bins_per_table
    );
    let cuckoo_start = Instant::now();

    let completed = AtomicUsize::new(0);

    let results: Vec<(Vec<u32>, CuckooResult)> = buckets
        .into_par_iter()
        .enumerate()
        .map(|(bucket_id, entries)| {
            let result = build_cuckoo_for_bucket(bucket_id, &entries, bins_per_table);
            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            eprint!("\r  Progress: {}/{} buckets", done, K);
            let _ = io::stderr().flush();
            result
        })
        .collect();

    eprintln!();
    println!("  Done in {:.2?}", cuckoo_start.elapsed());
    println!();

    // ── Step 4: Statistics ────────────────────────────────────────────────
    println!("[4] Cuckoo table statistics:");
    let mut total_entries = 0usize;
    let mut total_occupied = 0usize;
    let mut failures = 0usize;

    for (_, res) in &results {
        total_entries += res.num_entries;
        total_occupied += res.occupied;
        if !res.success {
            failures += 1;
            eprintln!(
                "  WARNING: Bucket {} FAILED cuckoo insertion ({} entries, {} bins)",
                res.bucket_id, res.num_entries, res.num_bins
            );
        }
    }

    if failures > 0 {
        eprintln!(
            "  {} bucket(s) failed — output file will NOT be written.",
            failures
        );
        std::process::exit(1);
    }

    let slots_per_table = bins_per_table * CUCKOO_BUCKET_SIZE;
    let total_slots = K * slots_per_table;
    let fill_rate = if total_slots > 0 {
        total_occupied as f64 / total_slots as f64
    } else {
        0.0
    };
    let slot_bytes = 4 + CHUNK_SIZE; // 44 bytes: 4B chunk_id + 40B data
    let body_bytes = K * slots_per_table * slot_bytes;
    let total_file_bytes = HEADER_SIZE + body_bytes;

    println!("  Buckets:               {}", K);
    println!("  Total entries placed:   {}", total_entries);
    println!(
        "  Bins per table:        {} (uniform across all buckets)",
        bins_per_table
    );
    println!(
        "  Total cuckoo slots:    {} ({} buckets x {} bins x {})",
        total_slots, K, bins_per_table, CUCKOO_BUCKET_SIZE
    );
    println!("  Occupied slots:        {}", total_occupied);
    println!(
        "  Fill rate:             {:.4} ({:.2}%)",
        fill_rate,
        fill_rate * 100.0
    );
    println!(
        "  Output file size:      {:.2} MB (header {} + body {})",
        total_file_bytes as f64 / (1024.0 * 1024.0),
        HEADER_SIZE,
        body_bytes
    );
    println!("  Failed buckets:        {}", failures);
    println!();

    // ── Step 5: Mmap chunks data for inlining ──────────────────────────────
    println!("[5] Memory-mapping chunks data for inlining...");
    let chunks_file = File::open(CHUNKS_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to open chunks file: {}", e);
        std::process::exit(1);
    });
    let chunks_mmap = unsafe { Mmap::map(&chunks_file) }.expect("mmap chunks");

    // ── Step 6: Serialize to disk (inlined) ─────────────────────────────────
    println!("[6] Writing output file: {}", OUTPUT_FILE);
    let write_start = Instant::now();

    let out_file = File::create(OUTPUT_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to create output file: {}", e);
        std::process::exit(1);
    });
    let mut writer = BufWriter::with_capacity(4 * 1024 * 1024, out_file);

    // Write header (32 bytes)
    writer.write_all(&MAGIC.to_le_bytes()).unwrap();
    writer.write_all(&(K as u32).to_le_bytes()).unwrap();
    writer
        .write_all(&(CUCKOO_BUCKET_SIZE as u32).to_le_bytes())
        .unwrap();
    writer
        .write_all(&(bins_per_table as u32).to_le_bytes())
        .unwrap();
    writer
        .write_all(&(NUM_HASHES as u32).to_le_bytes())
        .unwrap();
    writer.write_all(&MASTER_SEED.to_le_bytes()).unwrap();

    // Write body: K tables with inlined chunk data (slot_bytes per slot).
    // Each slot: [4B chunk_id LE | 40B chunk_data], or all zeros for EMPTY.
    let mut sorted: Vec<&(Vec<u32>, CuckooResult)> = results.iter().collect();
    sorted.sort_by_key(|(_, res)| res.bucket_id);

    let empty_slot = [0u8; 44]; // 4 + CHUNK_SIZE
    for (table, _) in &sorted {
        assert_eq!(table.len(), slots_per_table);
        for &slot in table.iter() {
            if slot == EMPTY {
                writer.write_all(&empty_slot).unwrap();
            } else {
                writer.write_all(&slot.to_le_bytes()).unwrap();
                let data_offset = slot as usize * CHUNK_SIZE;
                writer.write_all(&chunks_mmap[data_offset..data_offset + CHUNK_SIZE]).unwrap();
            }
        }
    }

    writer.flush().unwrap();

    println!("  Done in {:.2?}", write_start.elapsed());
    println!(
        "  Written {:.2} MB ({:.2} GB)",
        total_file_bytes as f64 / (1024.0 * 1024.0),
        total_file_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    println!();
    println!("  Total time: {:.2?}", start.elapsed());
}
