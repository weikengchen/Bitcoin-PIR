//! Batch PIR bucket assignment + per-bucket Cuckoo hashing over UTXO chunks index.
//!
//! 1. Reads the UTXO chunks index (`utxo_chunks_index.bin`): N entries of 24 bytes.
//! 2. Assigns each entry to 3 distinct buckets out of k=75 (by hashing script_hash).
//! 3. Within each bucket, builds a Cuckoo hash table (2 hash functions, bucket size 4,
//!    load factor 0.95). Hash function parameters are derived from a master PRG seed.
//! 4. Serializes all 75 cuckoo tables into a single flat binary file, with every table
//!    padded to the same size (max num_bins across buckets).
//!
//! Output file layout:
//!   [Header: 32 bytes]
//!     magic:             u64   (0xBA7C_C000_C000_0001)
//!     k:                 u32   (75)
//!     cuckoo_bucket_size:u32   (4)
//!     bins_per_table:    u32   (max num_bins, all tables padded to this)
//!     num_hashes:        u32   (3 — Batch PIR hashes per entry)
//!     master_seed:       u64   (PRG seed for cuckoo key derivation)
//!   [Body: k * bins_per_table * cuckoo_bucket_size * 4 bytes]
//!     table[0], table[1], ..., table[k-1]   (each bins_per_table * bucket_size u32s)
//!     Unused slots are EMPTY (u32::MAX).
//!
//! Usage:
//!   cargo run --release -p build_batchdb --bin build_batchdb

use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Path to the UTXO chunks index file (nodust, 80-byte blocks)
const INDEX_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_index_nodust.bin";

/// Output file for the serialized Batch PIR cuckoo tables
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/batch_pir_cuckoo.bin";

/// Size of each index entry: 20B script_hash + 4B offset_half + 4B num_chunks
const INDEX_ENTRY_SIZE: usize = 28;

/// Size of the script hash portion
const SCRIPT_HASH_SIZE: usize = 20;

/// Number of Batch PIR buckets
const K: usize = 75;

/// Number of bucket assignments per entry
const NUM_HASHES: usize = 3;

/// Cuckoo hash table parameters
const CUCKOO_BUCKET_SIZE: usize = 4;
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 2000;
const EMPTY: u32 = u32::MAX;

/// Master PRG seed for deriving per-bucket hash function keys
const MASTER_SEED: u64 = 0x71a2ef38b4c90d15;

/// File format magic number
const MAGIC: u64 = 0xBA7C_C000_C000_0001;

/// Header size in bytes
const HEADER_SIZE: usize = 32;

// ─── Hash utilities ──────────────────────────────────────────────────────────

/// Splitmix64 finalizer — used to derive keys and as a general mixer.
#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

/// Read first 8 bytes of a script_hash as u64 (LE).
#[inline]
fn sh_a(script_hash: &[u8]) -> u64 {
    u64::from_le_bytes([
        script_hash[0], script_hash[1], script_hash[2], script_hash[3],
        script_hash[4], script_hash[5], script_hash[6], script_hash[7],
    ])
}

/// Read bytes 8..16 of a script_hash as u64 (LE).
#[inline]
fn sh_b(script_hash: &[u8]) -> u64 {
    u64::from_le_bytes([
        script_hash[8], script_hash[9], script_hash[10], script_hash[11],
        script_hash[12], script_hash[13], script_hash[14], script_hash[15],
    ])
}

/// Read bytes 16..20 of a script_hash as u32 (LE), zero-extended to u64.
#[inline]
fn sh_c(script_hash: &[u8]) -> u64 {
    u32::from_le_bytes([
        script_hash[16], script_hash[17], script_hash[18], script_hash[19],
    ]) as u64
}

/// Hash script_hash with a nonce for Batch PIR bucket assignment.
#[inline]
fn hash_for_bucket(script_hash: &[u8], nonce: u64) -> u64 {
    let mut h = sh_a(script_hash).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15));
    h ^= sh_b(script_hash);
    h = splitmix64(h ^ sh_c(script_hash));
    h
}

/// Derive 3 distinct Batch PIR bucket indices for a script_hash.
fn derive_buckets(script_hash: &[u8]) -> [usize; NUM_HASHES] {
    let mut buckets = [0usize; NUM_HASHES];
    let mut nonce: u64 = 0;
    let mut count = 0;

    while count < NUM_HASHES {
        let h = hash_for_bucket(script_hash, nonce);
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

// ─── Per-bucket Cuckoo hashing ───────────────────────────────────────────────

/// Derive a hash function key for a given (batch-PIR bucket, cuckoo hash fn index).
#[inline]
fn derive_cuckoo_key(bucket_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        MASTER_SEED
            .wrapping_add((bucket_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

/// Cuckoo hash: hash a script_hash with a derived key, return a bin index.
#[inline]
fn cuckoo_hash(script_hash: &[u8], key: u64, num_bins: usize) -> usize {
    let mut h = sh_a(script_hash) ^ key;
    h ^= sh_b(script_hash);
    h = splitmix64(h ^ sh_c(script_hash));
    (h % num_bins as u64) as usize
}

/// Result of building a cuckoo table for one Batch PIR bucket.
struct CuckooResult {
    bucket_id: usize,
    num_entries: usize,
    num_bins: usize,
    _table_slots: usize,
    occupied: usize,
    success: bool,
}

fn main() {
    println!("=== Batch PIR: Bucket Assignment + Cuckoo Hashing ===");
    println!();

    let start = Instant::now();

    // ── Step 1: Memory-map index ─────────────────────────────────────────
    println!("[1] Memory-mapping index file: {}", INDEX_FILE);
    let file = File::open(INDEX_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to open index file: {}", e);
        std::process::exit(1);
    });

    let mmap = unsafe { Mmap::map(&file) }.unwrap_or_else(|e| {
        eprintln!("Failed to mmap index file: {}", e);
        std::process::exit(1);
    });

    let file_size = mmap.len();
    if file_size % INDEX_ENTRY_SIZE != 0 {
        eprintln!(
            "Index file size ({}) is not a multiple of entry size ({})",
            file_size, INDEX_ENTRY_SIZE
        );
        std::process::exit(1);
    }

    let n = file_size / INDEX_ENTRY_SIZE;
    println!(
        "  N = {} entries ({:.2} MB)",
        n,
        file_size as f64 / (1024.0 * 1024.0)
    );
    println!("  k = {} buckets, {} hashes per entry", K, NUM_HASHES);
    println!();

    // ── Step 2: Assign entries to Batch PIR buckets ──────────────────────
    println!("[2] Assigning entries to {} buckets...", K);
    let assign_start = Instant::now();

    let expected_per_bucket = (n * NUM_HASHES) / K + 1;
    let mut buckets: Vec<Vec<u32>> = (0..K)
        .map(|_| Vec::with_capacity(expected_per_bucket))
        .collect();

    for i in 0..n {
        let base = i * INDEX_ENTRY_SIZE;
        let script_hash = &mmap[base..base + SCRIPT_HASH_SIZE];
        let bucket_indices = derive_buckets(script_hash);
        for &b in &bucket_indices {
            buckets[b].push(i as u32);
        }
    }

    let bucket_loads: Vec<usize> = buckets.iter().map(|b| b.len()).collect();
    let min_load = *bucket_loads.iter().min().unwrap();
    let max_load = *bucket_loads.iter().max().unwrap();
    let total_refs: usize = bucket_loads.iter().sum();
    let expected = n as f64 * NUM_HASHES as f64 / K as f64;

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
        n * NUM_HASHES,
        NUM_HASHES
    );
    println!();

    // ── Step 3: Build Cuckoo tables in parallel ──────────────────────────
    // Compute a uniform bins_per_table from the max bucket load so all 75
    // tables use the same num_bins (required for correct lookup after
    // serialization — the verifier/server only knows bins_per_table).
    let bins_per_table =
        ((max_load as f64) / (CUCKOO_BUCKET_SIZE as f64 * CUCKOO_LOAD_FACTOR)).ceil() as usize;

    println!(
        "[3] Building Cuckoo tables (2 hash fns, bucket_size={}, load={}, uniform bins={})...",
        CUCKOO_BUCKET_SIZE, CUCKOO_LOAD_FACTOR, bins_per_table
    );
    let cuckoo_start = Instant::now();

    let mmap_slice: &[u8] = &mmap;
    let completed = AtomicUsize::new(0);

    let results: Vec<(Vec<u32>, CuckooResult)> = buckets
        .into_par_iter()
        .enumerate()
        .map(|(bucket_id, entries)| {
            let result =
                build_cuckoo_for_bucket(bucket_id, &entries, mmap_slice, bins_per_table);
            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            eprint!("\r  Progress: {}/{} buckets", done, K);
            let _ = io::stderr().flush();
            result
        })
        .collect();

    eprintln!();
    println!("  Done in {:.2?}", cuckoo_start.elapsed());
    println!();

    // ── Step 4: Statistics ───────────────────────────────────────────────
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
        eprintln!("  {} bucket(s) failed — output file will NOT be written.", failures);
        std::process::exit(1);
    }

    let slots_per_table = bins_per_table * CUCKOO_BUCKET_SIZE;
    let total_slots = K * slots_per_table;
    let fill_rate = if total_slots > 0 {
        total_occupied as f64 / total_slots as f64
    } else {
        0.0
    };
    let body_bytes = K * slots_per_table * 4;
    let total_file_bytes = HEADER_SIZE + body_bytes;

    println!("  Buckets:               {}", K);
    println!("  Total entries placed:  {}", total_entries);
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

    // ── Step 5: Serialize to disk ────────────────────────────────────────
    println!("[5] Writing output file: {}", OUTPUT_FILE);
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

    // Write body: K tables, each exactly slots_per_table u32s (uniform size).
    // Sort results by bucket_id so tables are in order 0..K-1.
    let mut sorted: Vec<&(Vec<u32>, CuckooResult)> = results.iter().collect();
    sorted.sort_by_key(|(_, res)| res.bucket_id);

    for (table, _) in &sorted {
        assert_eq!(table.len(), slots_per_table);
        for &slot in table.iter() {
            writer.write_all(&slot.to_le_bytes()).unwrap();
        }
    }

    writer.flush().unwrap();

    println!("  Done in {:.2?}", write_start.elapsed());
    println!(
        "  Written {:.2} MB",
        total_file_bytes as f64 / (1024.0 * 1024.0)
    );
    println!();
    println!("  Total time:            {:.2?}", start.elapsed());
}

// ─── Cuckoo builder ──────────────────────────────────────────────────────────

fn build_cuckoo_for_bucket(
    bucket_id: usize,
    entries: &[u32],
    mmap: &[u8],
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

    let key0 = derive_cuckoo_key(bucket_id, 0);
    let key1 = derive_cuckoo_key(bucket_id, 1);

    let mut success = true;

    for &entry_idx in entries {
        let base = entry_idx as usize * INDEX_ENTRY_SIZE;
        let sh = &mmap[base..base + SCRIPT_HASH_SIZE];

        if !cuckoo_insert(&mut table, sh, entry_idx, key0, key1, num_bins, mmap) {
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

/// Cuckoo insert with full eviction chain.
fn cuckoo_insert(
    table: &mut [u32],
    script_hash: &[u8],
    entry_idx: u32,
    key0: u64,
    key1: u64,
    num_bins: usize,
    mmap: &[u8],
) -> bool {
    // Try bin 0
    let bin0 = cuckoo_hash(script_hash, key0, num_bins);
    let base0 = bin0 * CUCKOO_BUCKET_SIZE;
    for s in 0..CUCKOO_BUCKET_SIZE {
        if table[base0 + s] == EMPTY {
            table[base0 + s] = entry_idx;
            return true;
        }
    }

    // Try bin 1
    let bin1 = cuckoo_hash(script_hash, key1, num_bins);
    let base1 = bin1 * CUCKOO_BUCKET_SIZE;
    for s in 0..CUCKOO_BUCKET_SIZE {
        if table[base1 + s] == EMPTY {
            table[base1 + s] = entry_idx;
            return true;
        }
    }

    // Eviction loop — vary which slot is evicted to avoid 2-cycles
    let mut current_idx = entry_idx;
    let mut current_bin = bin0;

    for kick in 0..CUCKOO_MAX_KICKS {
        let base = current_bin * CUCKOO_BUCKET_SIZE;
        let slot = kick % CUCKOO_BUCKET_SIZE;
        let evicted_idx = table[base + slot];
        table[base + slot] = current_idx;

        // Find the alternative bin for the evicted entry
        let ev_base = evicted_idx as usize * INDEX_ENTRY_SIZE;
        let ev_sh = &mmap[ev_base..ev_base + SCRIPT_HASH_SIZE];
        let ev_bin0 = cuckoo_hash(ev_sh, key0, num_bins);
        let ev_bin1 = cuckoo_hash(ev_sh, key1, num_bins);
        let alt_bin = if ev_bin0 == current_bin { ev_bin1 } else { ev_bin0 };

        // Try to place evicted entry in its alternative bin
        let alt_base = alt_bin * CUCKOO_BUCKET_SIZE;
        let mut placed = false;
        for s in 0..CUCKOO_BUCKET_SIZE {
            if table[alt_base + s] == EMPTY {
                table[alt_base + s] = evicted_idx;
                placed = true;
                break;
            }
        }

        if placed {
            return true;
        }

        // Continue evicting from alt_bin
        current_idx = evicted_idx;
        current_bin = alt_bin;
    }

    false
}
