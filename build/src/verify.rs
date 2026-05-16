//! Verification loader for Batch PIR cuckoo tables.
//!
//! Loads the serialized `batch_pir_cuckoo.bin` file via mmap, validates the header,
//! then picks random entries from the original UTXO chunks index and verifies that
//! each entry can be found in the cuckoo table of at least one of its 3 assigned groups.
//!
//! Usage:
//!   cargo run --release -p build --bin verify_batchdb

use memmap2::Mmap;
use std::fs::File;
use std::time::Instant;

/// Path to the UTXO chunks index file (nodust, 80-byte blocks)
const INDEX_FILE: &str = "/Volumes/Bitcoin/data/intermediate/utxo_chunks_index_nodust.bin";

/// Path to the serialized Batch PIR cuckoo tables
const CUCKOO_FILE: &str = "/Volumes/Bitcoin/data/batch_pir_cuckoo.bin";

const INDEX_RECORD_SIZE: usize = 25;
const SCRIPT_HASH_SIZE: usize = 20;
const MAGIC: u64 = 0xBA7C_C000_C000_0004;
const HEADER_SIZE: usize = 40; // includes tag_seed

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
fn hash_for_group(script_hash: &[u8], nonce: u64) -> u64 {
    let mut h = sh_a(script_hash).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15));
    h ^= sh_b(script_hash);
    h = splitmix64(h ^ sh_c(script_hash));
    h
}

fn derive_groups(script_hash: &[u8], k: usize, num_hashes: usize) -> Vec<usize> {
    let mut groups = Vec::with_capacity(num_hashes);
    let mut nonce: u64 = 0;

    while groups.len() < num_hashes {
        let h = hash_for_group(script_hash, nonce);
        let group = (h % k as u64) as usize;
        nonce += 1;
        if !groups.contains(&group) {
            groups.push(group);
        }
    }

    groups
}

#[inline]
fn derive_cuckoo_key(master_seed: u64, group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        master_seed
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
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

#[inline]
fn compute_tag(tag_seed: u64, script_hash: &[u8]) -> u64 {
    let mut h = sh_a(script_hash) ^ tag_seed;
    h ^= sh_b(script_hash);
    splitmix64(h ^ sh_c(script_hash))
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

/// Look up a script_hash in a specific group's cuckoo table by tag match.
/// Slot layout: [8B tag LE][4B start_chunk_id LE][1B num_chunks][4B tree_loc LE] = 17B.
/// Returns true if found (tag matches).
fn lookup_in_group(
    cuckoo_data: &[u8],
    group_id: usize,
    script_hash: &[u8],
    _entry_idx: u32,
    bins_per_table: usize,
    slots_per_bin: usize,
    master_seed: u64,
    tag_seed: u64,
) -> bool {
    let slot_size = 17;
    let slots_per_table = bins_per_table * slots_per_bin;
    let table_offset = HEADER_SIZE + group_id * slots_per_table * slot_size;
    let expected_tag = compute_tag(tag_seed, script_hash);

    let key0 = derive_cuckoo_key(master_seed, group_id, 0);
    let key1 = derive_cuckoo_key(master_seed, group_id, 1);

    for &bin in &[
        cuckoo_hash(script_hash, key0, bins_per_table),
        cuckoo_hash(script_hash, key1, bins_per_table),
    ] {
        let base = table_offset + bin * slots_per_bin * slot_size;
        for s in 0..slots_per_bin {
            let slot_off = base + s * slot_size;
            let tag = read_u64(cuckoo_data, slot_off);
            if tag == expected_tag && tag != 0 {
                return true;
            }
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
    let slots_per_bin = read_u32(&cuckoo_mmap, 12) as usize;
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

    let slot_size = 17; // [8B tag][4B chunk_id][1B num_chunks][4B tree_loc]
    let tag_seed = read_u64(&cuckoo_mmap, 32);
    let slots_per_table = bins_per_table * slots_per_bin;
    let expected_body = k * slots_per_table * slot_size;
    let expected_size = HEADER_SIZE + expected_body;

    println!("  Header OK:");
    println!("    k = {}", k);
    println!("    slots_per_bin = {}", slots_per_bin);
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

    // ── Per-group occupancy ─────────────────────────────────────────────
    println!("[2] Per-group occupancy scan:");
    let mut total_occupied = 0usize;
    let mut min_occ = usize::MAX;
    let mut max_occ = 0usize;

    for b in 0..k {
        let table_offset = HEADER_SIZE + b * slots_per_table * slot_size;
        let mut occ = 0usize;
        for s in 0..slots_per_table {
            let slot_off = table_offset + s * slot_size;
            let tag = read_u64(&cuckoo_mmap, slot_off);
            if tag != 0 {
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
        "  Per-group occupancy: min={}, max={} (out of {} slots/table)",
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

    let n = index_mmap.len() / INDEX_RECORD_SIZE;
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

        let base = entry_idx as usize * INDEX_RECORD_SIZE;
        let script_hash = &index_mmap[base..base + SCRIPT_HASH_SIZE];

        // Determine which groups this entry should be in
        let assigned_groups = derive_groups(script_hash, k, num_hashes);

        // Try to find it in at least one of its assigned groups
        let mut entry_found = false;
        for &group_id in &assigned_groups {
            if lookup_in_group(
                &cuckoo_mmap,
                group_id,
                script_hash,
                entry_idx,
                bins_per_table,
                slots_per_bin,
                master_seed,
                tag_seed,
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
                    "  MISS: entry {} (groups {:?}) at verify iteration {}",
                    entry_idx, assigned_groups, i
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
        let base = entry_idx as usize * INDEX_RECORD_SIZE;
        let script_hash = &index_mmap[base..base + SCRIPT_HASH_SIZE];

        let assigned_groups = derive_groups(script_hash, k, num_hashes);

        let mut entry_found = false;
        for &group_id in &assigned_groups {
            if lookup_in_group(
                &cuckoo_mmap,
                group_id,
                script_hash,
                entry_idx,
                bins_per_table,
                slots_per_bin,
                master_seed,
                tag_seed,
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
                    "  FULL SWEEP MISS: entry {} (groups {:?})",
                    entry_idx, assigned_groups
                );
            }
        }

        if (entry_idx as usize + 1).is_multiple_of(5_000_000) {
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
