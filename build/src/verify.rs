//! Verification loader for Batch PIR cuckoo tables.
//!
//! Loads the serialized `batch_pir_cuckoo.bin` file via mmap, validates the header,
//! then picks random entries from the original UTXO chunks index and verifies that
//! each entry can be found in the cuckoo table of at least one of its 3 assigned buckets.
//!
//! Usage:
//!   cargo run --release -p build --bin verify_batchdb

use memmap2::Mmap;
use std::fs::File;
use std::time::Instant;

/// Path to the UTXO chunks index file (nodust, 80-byte blocks)
const INDEX_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_index_nodust.bin";

/// Path to the serialized Batch PIR cuckoo tables
const CUCKOO_FILE: &str = "/Volumes/Bitcoin/data/batch_pir_cuckoo.bin";

const INDEX_ENTRY_SIZE: usize = 25;
const SCRIPT_HASH_SIZE: usize = 20;
const MAGIC: u64 = 0xBA7C_C000_C000_0001;
const HEADER_SIZE: usize = 32;
const EMPTY: u32 = u32::MAX;

/// Number of random lookups for verification
const NUM_VERIFY: usize = 1_000_000;

// ─── Hash utilities (must match the builder) ─────────────────────────────────

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
fn hash_for_bucket(script_hash: &[u8], nonce: u64) -> u64 {
    let mut h = sh_a(script_hash).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15));
    h ^= sh_b(script_hash);
    h = splitmix64(h ^ sh_c(script_hash));
    h
}

fn derive_buckets(script_hash: &[u8], k: usize, num_hashes: usize) -> Vec<usize> {
    let mut buckets = Vec::with_capacity(num_hashes);
    let mut nonce: u64 = 0;

    while buckets.len() < num_hashes {
        let h = hash_for_bucket(script_hash, nonce);
        let bucket = (h % k as u64) as usize;
        nonce += 1;
        if !buckets.contains(&bucket) {
            buckets.push(bucket);
        }
    }

    buckets
}

#[inline]
fn derive_cuckoo_key(master_seed: u64, bucket_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        master_seed
            .wrapping_add((bucket_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

#[inline]
fn cuckoo_hash(script_hash: &[u8], key: u64, num_bins: usize) -> usize {
    let mut h = sh_a(script_hash) ^ key;
    h ^= sh_b(script_hash);
    h = splitmix64(h ^ sh_c(script_hash));
    (h % num_bins as u64) as usize
}

// ─── Cuckoo table accessor ──────────────────────────────────────────────────

/// Read a u32 from a byte slice at the given byte offset (little-endian).
#[inline]
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[inline]
fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Look up an entry_index in a specific bucket's cuckoo table.
/// Returns true if found.
fn lookup_in_bucket(
    cuckoo_data: &[u8],
    bucket_id: usize,
    script_hash: &[u8],
    entry_idx: u32,
    bins_per_table: usize,
    cuckoo_bucket_size: usize,
    master_seed: u64,
) -> bool {
    let slots_per_table = bins_per_table * cuckoo_bucket_size;
    let table_offset = HEADER_SIZE + bucket_id * slots_per_table * 4;

    let key0 = derive_cuckoo_key(master_seed, bucket_id, 0);
    let key1 = derive_cuckoo_key(master_seed, bucket_id, 1);

    // Check bin 0
    let bin0 = cuckoo_hash(script_hash, key0, bins_per_table);
    let base0 = table_offset + bin0 * cuckoo_bucket_size * 4;
    for s in 0..cuckoo_bucket_size {
        let val = read_u32(cuckoo_data, base0 + s * 4);
        if val == entry_idx {
            return true;
        }
        if val == EMPTY {
            break;
        }
    }

    // Check bin 1
    let bin1 = cuckoo_hash(script_hash, key1, bins_per_table);
    let base1 = table_offset + bin1 * cuckoo_bucket_size * 4;
    for s in 0..cuckoo_bucket_size {
        let val = read_u32(cuckoo_data, base1 + s * 4);
        if val == entry_idx {
            return true;
        }
        if val == EMPTY {
            break;
        }
    }

    false
}

fn main() {
    println!("=== Batch PIR Cuckoo Table Verification ===");
    println!();

    let start = Instant::now();

    // ── Load the cuckoo file ─────────────────────────────────────────────
    println!("[1] Loading cuckoo file: {}", CUCKOO_FILE);
    let cuckoo_file = File::open(CUCKOO_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to open cuckoo file: {}", e);
        std::process::exit(1);
    });
    let cuckoo_mmap = unsafe { Mmap::map(&cuckoo_file) }.unwrap_or_else(|e| {
        eprintln!("Failed to mmap cuckoo file: {}", e);
        std::process::exit(1);
    });

    // ── Parse and validate header ────────────────────────────────────────
    if cuckoo_mmap.len() < HEADER_SIZE {
        eprintln!("Cuckoo file too small for header");
        std::process::exit(1);
    }

    let magic = read_u64(&cuckoo_mmap, 0);
    let k = read_u32(&cuckoo_mmap, 8) as usize;
    let cuckoo_bucket_size = read_u32(&cuckoo_mmap, 12) as usize;
    let bins_per_table = read_u32(&cuckoo_mmap, 16) as usize;
    let num_hashes = read_u32(&cuckoo_mmap, 20) as usize;
    let master_seed = read_u64(&cuckoo_mmap, 24);

    if magic != MAGIC {
        eprintln!(
            "Bad magic: expected 0x{:016X}, got 0x{:016X}",
            MAGIC, magic
        );
        std::process::exit(1);
    }

    let slots_per_table = bins_per_table * cuckoo_bucket_size;
    let expected_body = k * slots_per_table * 4;
    let expected_size = HEADER_SIZE + expected_body;

    println!("  Header OK:");
    println!("    k = {}", k);
    println!("    cuckoo_bucket_size = {}", cuckoo_bucket_size);
    println!("    bins_per_table = {}", bins_per_table);
    println!("    slots_per_table = {}", slots_per_table);
    println!("    num_hashes = {}", num_hashes);
    println!("    master_seed = 0x{:016X}", master_seed);
    println!(
        "    file size: {} bytes ({:.2} MB), expected: {}",
        cuckoo_mmap.len(),
        cuckoo_mmap.len() as f64 / (1024.0 * 1024.0),
        expected_size
    );

    if cuckoo_mmap.len() != expected_size {
        eprintln!("  ERROR: file size mismatch!");
        std::process::exit(1);
    }
    println!("    Size check: OK");
    println!();

    // ── Per-bucket occupancy ─────────────────────────────────────────────
    println!("[2] Per-bucket occupancy scan:");
    let mut total_occupied = 0usize;
    let mut min_occ = usize::MAX;
    let mut max_occ = 0usize;

    for b in 0..k {
        let table_offset = HEADER_SIZE + b * slots_per_table * 4;
        let mut occ = 0usize;
        for s in 0..slots_per_table {
            let val = read_u32(&cuckoo_mmap, table_offset + s * 4);
            if val != EMPTY {
                occ += 1;
            }
        }
        total_occupied += occ;
        if occ < min_occ {
            min_occ = occ;
        }
        if occ > max_occ {
            max_occ = occ;
        }
    }

    let total_slots = k * slots_per_table;
    println!(
        "  Total occupied: {} / {} slots ({:.2}%)",
        total_occupied,
        total_slots,
        total_occupied as f64 / total_slots as f64 * 100.0
    );
    println!(
        "  Per-bucket occupancy: min={}, max={} (out of {} slots/table)",
        min_occ, max_occ, slots_per_table
    );
    println!();

    // ── Load original index for verification ─────────────────────────────
    println!("[3] Loading original index: {}", INDEX_FILE);
    let index_file = File::open(INDEX_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to open index file: {}", e);
        std::process::exit(1);
    });
    let index_mmap = unsafe { Mmap::map(&index_file) }.unwrap_or_else(|e| {
        eprintln!("Failed to mmap index file: {}", e);
        std::process::exit(1);
    });

    let n = index_mmap.len() / INDEX_ENTRY_SIZE;
    println!("  N = {} entries", n);
    println!();

    // ── Verify random lookups ────────────────────────────────────────────
    let verify_count = NUM_VERIFY.min(n);
    println!(
        "[4] Verifying {} random entry lookups...",
        verify_count
    );
    let verify_start = Instant::now();

    // Deterministic pseudo-random sampling using splitmix64
    let mut rng_state: u64 = 0xdeadbeefcafe1234;
    let mut found = 0usize;
    let mut not_found = 0usize;

    for i in 0..verify_count {
        rng_state = splitmix64(rng_state);
        let entry_idx = (rng_state % n as u64) as u32;

        let base = entry_idx as usize * INDEX_ENTRY_SIZE;
        let script_hash = &index_mmap[base..base + SCRIPT_HASH_SIZE];

        // Determine which buckets this entry should be in
        let assigned_buckets = derive_buckets(script_hash, k, num_hashes);

        // Try to find it in at least one of its assigned buckets
        let mut entry_found = false;
        for &bucket_id in &assigned_buckets {
            if lookup_in_bucket(
                &cuckoo_mmap,
                bucket_id,
                script_hash,
                entry_idx,
                bins_per_table,
                cuckoo_bucket_size,
                master_seed,
            ) {
                entry_found = true;
                break;
            }
        }

        if entry_found {
            found += 1;
        } else {
            not_found += 1;
            if not_found <= 10 {
                eprintln!(
                    "  MISS: entry {} (buckets {:?}) at verify iteration {}",
                    entry_idx, assigned_buckets, i
                );
            }
        }

        if (i + 1) % 100_000 == 0 {
            eprint!("\r  Verified: {}/{}", i + 1, verify_count);
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
    }
    eprintln!();

    println!("  Done in {:.2?}", verify_start.elapsed());
    println!("  Found:     {} / {}", found, verify_count);
    println!("  Not found: {} / {}", not_found, verify_count);

    if not_found == 0 {
        println!("  ✓ All lookups successful!");
    } else {
        println!(
            "  ✗ {:.4}% miss rate",
            not_found as f64 / verify_count as f64 * 100.0
        );
    }

    // ── Full sweep: verify every entry exists ────────────────────────────
    println!();
    println!("[5] Full sweep: verifying ALL {} entries...", n);
    let sweep_start = Instant::now();

    let mut sweep_found = 0usize;
    let mut sweep_miss = 0usize;

    for entry_idx in 0..n as u32 {
        let base = entry_idx as usize * INDEX_ENTRY_SIZE;
        let script_hash = &index_mmap[base..base + SCRIPT_HASH_SIZE];

        let assigned_buckets = derive_buckets(script_hash, k, num_hashes);

        let mut entry_found = false;
        for &bucket_id in &assigned_buckets {
            if lookup_in_bucket(
                &cuckoo_mmap,
                bucket_id,
                script_hash,
                entry_idx,
                bins_per_table,
                cuckoo_bucket_size,
                master_seed,
            ) {
                entry_found = true;
                break;
            }
        }

        if entry_found {
            sweep_found += 1;
        } else {
            sweep_miss += 1;
            if sweep_miss <= 5 {
                eprintln!(
                    "  FULL SWEEP MISS: entry {} (buckets {:?})",
                    entry_idx, assigned_buckets
                );
            }
        }

        if (entry_idx as usize + 1) % 5_000_000 == 0 {
            eprint!("\r  Swept: {}/{}", entry_idx + 1, n);
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
    }
    eprintln!();

    println!("  Done in {:.2?}", sweep_start.elapsed());
    println!("  Found:     {} / {}", sweep_found, n);
    println!("  Not found: {} / {}", sweep_miss, n);

    if sweep_miss == 0 {
        println!("  ✓ Full sweep passed — every entry is findable!");
    } else {
        println!(
            "  ✗ {:.6}% entries missing",
            sweep_miss as f64 / n as f64 * 100.0
        );
    }

    println!();
    println!("  Total verification time: {:.2?}", start.elapsed());
}
