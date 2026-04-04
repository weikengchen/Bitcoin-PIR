//! Build OnionPIR index database: 75 groups with 2-hash cuckoo (bucket_size=256).
//!
//! Reads the OnionPIR index file (27-byte entries from gen_1_onion), assigns
//! entries to 75 PBC groups, builds per-group cuckoo tables, and produces
//! OnionPIR preprocessed databases (one per group).
//!
//! Each cuckoo bin holds 256 × 15-byte tagged index slots = 3840 bytes,
//! which is exactly one OnionPIR entry.
//!
//! Index slot format (15 bytes):
//!   [8B tag | 4B entry_id | 2B byte_offset | 1B num_entries]
//!
//! Output:
//!   - onion_index_pir/bucket_N.bin: preprocessed OnionPIR databases (one per group)
//!   - onion_index_meta.bin: header with parameters for the server to load
//!
//! Usage:
//!   cargo run --release -p build --bin gen_3_onion

use memmap2::Mmap;
use onionpir::{self, Server as PirServer, Client as PirClient};
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

// ─── Constants ──────────────────────────────────────────────────────────────

const INDEX_FILE: &str = "/Volumes/Bitcoin/data/intermediate/onion_index.bin";
const TREE_LOCS_FILE: &str = "/Volumes/Bitcoin/data/intermediate/tree_locs.bin";
const OUTPUT_DIR: &str = "/Volumes/Bitcoin/data/onion_index_pir";
const META_FILE: &str = "/Volumes/Bitcoin/data/onion_index_meta.bin";

/// OnionPIR index entry from gen_1_onion: 20B script_hash + 4B entry_id + 2B offset + 1B num_entries
const ONION_INDEX_ENTRY_SIZE: usize = 27;
const SCRIPT_HASH_SIZE: usize = 20;

/// Index slot in the cuckoo table: 8B tag + 4B entry_id + 2B offset + 1B num_entries + 4B tree_loc
const INDEX_SLOT_SIZE: usize = 19;

/// PBC parameters
const K: usize = 75;
const NUM_HASHES: usize = 3;
const MASTER_SEED: u64 = 0x71a2ef38b4c90d15;

/// Cuckoo parameters for index level
const CUCKOO_NUM_HASHES: usize = 2;
const CUCKOO_BUCKET_SIZE: usize = 202; // 202 × 19B = 3838B ≤ 3840B
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 5000;
const EMPTY: u32 = u32::MAX;

/// Tag seed for fingerprint computation
const TAG_SEED: u64 = 0xd4e5f6a7b8c91023;

/// OnionPIR entry size (must equal CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE)
const ONIONPIR_ENTRY_SIZE: usize = 3840;

const FLAG_WHALE: u8 = 0x40;

// ─── Hash utilities ─────────────────────────────────────────────────────────

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
    splitmix64(h ^ sh_c(sh))
}

fn derive_buckets(sh: &[u8]) -> [usize; NUM_HASHES] {
    let mut buckets = [0usize; NUM_HASHES];
    let mut nonce: u64 = 0;
    let mut count = 0;
    while count < NUM_HASHES {
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

#[inline]
fn derive_cuckoo_key(bucket_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        MASTER_SEED
            .wrapping_add((bucket_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
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

#[inline]
fn compute_tag(tag_seed: u64, sh: &[u8]) -> u64 {
    let mut h = sh_a(sh) ^ tag_seed;
    h ^= sh_b(sh);
    splitmix64(h ^ sh_c(sh))
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1e9)
    } else if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1e6)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1e3)
    } else {
        format!("{} B", bytes)
    }
}

// ─── Cuckoo table builder (2-hash, bucket_size=256) ─────────────────────────

/// Build a 2-hash cuckoo table with large bucket_size.
/// Returns (table, success). table[bin * CUCKOO_BUCKET_SIZE + slot] = entry index.
fn build_index_cuckoo(
    bucket_id: usize,
    entries: &[u32],
    mmap: &[u8],
    num_bins: usize,
) -> (Vec<u32>, bool) {
    let total_slots = num_bins * CUCKOO_BUCKET_SIZE;
    let mut table = vec![EMPTY; total_slots];
    let mut bin_occupancy = vec![0u16; num_bins];

    let key0 = derive_cuckoo_key(bucket_id, 0);
    let key1 = derive_cuckoo_key(bucket_id, 1);

    let get_sh = |idx: u32| -> &[u8] {
        let base = idx as usize * ONION_INDEX_ENTRY_SIZE;
        &mmap[base..base + SCRIPT_HASH_SIZE]
    };

    let mut stash = 0usize;

    for &idx in entries {
        let sh = get_sh(idx);
        let bin0 = cuckoo_hash(sh, key0, num_bins);
        let bin1 = cuckoo_hash(sh, key1, num_bins);

        // Place in whichever bin has more room (2-choice)
        let (first, second) = if bin_occupancy[bin0] <= bin_occupancy[bin1] {
            (bin0, bin1)
        } else {
            (bin1, bin0)
        };

        let occ0 = bin_occupancy[first] as usize;
        if occ0 < CUCKOO_BUCKET_SIZE {
            table[first * CUCKOO_BUCKET_SIZE + occ0] = idx;
            bin_occupancy[first] += 1;
            continue;
        }

        let occ1 = bin_occupancy[second] as usize;
        if occ1 < CUCKOO_BUCKET_SIZE {
            table[second * CUCKOO_BUCKET_SIZE + occ1] = idx;
            bin_occupancy[second] += 1;
            continue;
        }

        // Both bins full — try cuckoo eviction
        let mut current_idx = idx;
        let mut current_bin = first;
        let mut success = false;

        for kick in 0..CUCKOO_MAX_KICKS {
            let occ = bin_occupancy[current_bin] as usize;
            let evict_slot = kick % occ;
            let evicted = table[current_bin * CUCKOO_BUCKET_SIZE + evict_slot];
            table[current_bin * CUCKOO_BUCKET_SIZE + evict_slot] = current_idx;

            let ev_sh = get_sh(evicted);
            let ev_bin0 = cuckoo_hash(ev_sh, key0, num_bins);
            let ev_bin1 = cuckoo_hash(ev_sh, key1, num_bins);
            let alt_bin = if ev_bin0 == current_bin { ev_bin1 } else { ev_bin0 };

            let alt_occ = bin_occupancy[alt_bin] as usize;
            if alt_occ < CUCKOO_BUCKET_SIZE {
                table[alt_bin * CUCKOO_BUCKET_SIZE + alt_occ] = evicted;
                bin_occupancy[alt_bin] += 1;
                success = true;
                break;
            }

            current_idx = evicted;
            current_bin = alt_bin;
        }

        if !success {
            stash += 1;
        }
    }

    (table, stash == 0)
}

/// Serialize a cuckoo table into OnionPIR entries.
/// Each bin (202 slots × 19 bytes) becomes one 3840-byte OnionPIR entry.
fn serialize_cuckoo_bin(
    table: &[u32],
    bin: usize,
    mmap: &[u8],
    tree_locs: &[u8],
) -> [u8; ONIONPIR_ENTRY_SIZE] {
    let mut entry = [0u8; ONIONPIR_ENTRY_SIZE];
    let base = bin * CUCKOO_BUCKET_SIZE;

    for slot in 0..CUCKOO_BUCKET_SIZE {
        let idx = table[base + slot];
        let slot_offset = slot * INDEX_SLOT_SIZE;

        if idx == EMPTY {
            // Zero-filled (already initialized)
            continue;
        }

        let entry_base = idx as usize * ONION_INDEX_ENTRY_SIZE;
        let sh = &mmap[entry_base..entry_base + SCRIPT_HASH_SIZE];

        // Tag (8 bytes)
        let tag = compute_tag(TAG_SEED, sh);
        entry[slot_offset..slot_offset + 8].copy_from_slice(&tag.to_le_bytes());

        // entry_id (4 bytes) + byte_offset (2 bytes) + num_entries (1 byte)
        // These are at bytes 20..27 of the onion index entry
        entry[slot_offset + 8..slot_offset + 15]
            .copy_from_slice(&mmap[entry_base + 20..entry_base + 27]);

        // tree_loc (4 bytes) — from tree_locs.bin sidecar (indexed by onion_index position)
        let tl_off = idx as usize * 4;
        entry[slot_offset + 15..slot_offset + 19]
            .copy_from_slice(&tree_locs[tl_off..tl_off + 4]);
    }

    entry
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    assert!(
        CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE <= ONIONPIR_ENTRY_SIZE,
        "bucket_size * slot_size must fit within OnionPIR entry size ({}*{}={} > {})",
        CUCKOO_BUCKET_SIZE, INDEX_SLOT_SIZE,
        CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE, ONIONPIR_ENTRY_SIZE,
    );

    println!("=== gen_3_onion: Build OnionPIR Index Database ===\n");
    let total_start = Instant::now();

    // ── 1. Read index file ──────────────────────────────────────────────
    println!("[1] Memory-mapping index file: {}", INDEX_FILE);
    let file = File::open(INDEX_FILE).expect("open index file");
    let mmap = unsafe { Mmap::map(&file) }.expect("mmap index");
    let n = mmap.len() / ONION_INDEX_ENTRY_SIZE;
    assert_eq!(mmap.len() % ONION_INDEX_ENTRY_SIZE, 0, "index file not aligned");
    println!("  {} entries ({})", n, format_bytes(mmap.len() as u64));

    // Count non-whale entries
    let mut non_whale = 0usize;
    for i in 0..n {
        let base = i * ONION_INDEX_ENTRY_SIZE;
        let num_entries_byte = mmap[base + 26]; // last byte = num_entries or FLAG_WHALE
        // Whale entries have num_entries = FLAG_WHALE (0x40) from gen_1_onion
        // Actually, gen_1_onion writes: entry_id=0, offset=0, num_entries=FLAG_WHALE
        // So the last byte (num_entries field) is 0x40 for whales
        if num_entries_byte != FLAG_WHALE {
            non_whale += 1;
        }
    }
    println!("  Non-whale entries: {} (whale: {})", non_whale, n - non_whale);

    // Load tree_locs sidecar (4 bytes per entry, indexed by onion_index position)
    let tree_locs_file = File::open(TREE_LOCS_FILE).expect("open tree_locs.bin");
    let tree_locs = unsafe { Mmap::map(&tree_locs_file) }.expect("mmap tree_locs");
    assert_eq!(tree_locs.len(), n * 4, "tree_locs.bin size mismatch (expected {} entries)", n);
    println!("  tree_locs.bin: {} entries loaded", n);

    // ── 2. Assign entries to PBC groups ─────────────────────────────────
    println!("\n[2] Assigning entries to {} PBC groups...", K);
    let t_assign = Instant::now();

    let expected_per_group = (n * NUM_HASHES) / K + 1;
    let mut groups: Vec<Vec<u32>> = (0..K)
        .map(|_| Vec::with_capacity(expected_per_group))
        .collect();

    // Include whale entries — they must be findable in the index so clients
    // can detect them and skip the chunk phase.
    for i in 0..n {
        let base = i * ONION_INDEX_ENTRY_SIZE;
        let sh = &mmap[base..base + SCRIPT_HASH_SIZE];
        let buckets = derive_buckets(sh);
        for &b in &buckets {
            groups[b].push(i as u32);
        }
    }

    let group_sizes: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    let max_group = *group_sizes.iter().max().unwrap();
    let min_group = *group_sizes.iter().min().unwrap();
    let avg_group = group_sizes.iter().sum::<usize>() as f64 / K as f64;
    println!("  Done in {:.2?}", t_assign.elapsed());
    println!("  Group sizes: min={}, max={}, avg={:.0}", min_group, max_group, avg_group);

    // ── 3. Build cuckoo tables in parallel ──────────────────────────────
    let bins_per_table =
        ((max_group as f64) / (CUCKOO_BUCKET_SIZE as f64 * CUCKOO_LOAD_FACTOR)).ceil() as usize;

    println!("\n[3] Building cuckoo tables ({}-hash, bs={}, bins_per_table={})...",
        CUCKOO_NUM_HASHES, CUCKOO_BUCKET_SIZE, bins_per_table);
    let t_cuckoo = Instant::now();

    let mmap_slice: &[u8] = &mmap;
    let tree_locs_slice: &[u8] = &tree_locs;
    let completed = AtomicUsize::new(0);

    let cuckoo_results: Vec<(usize, Vec<u32>, bool)> = groups
        .into_par_iter()
        .enumerate()
        .map(|(bucket_id, entries)| {
            let (table, success) = build_index_cuckoo(bucket_id, &entries, mmap_slice, bins_per_table);
            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            if done % 10 == 0 || done == K {
                eprint!("\r  Progress: {}/{} groups", done, K);
                let _ = io::stderr().flush();
            }
            (bucket_id, table, success)
        })
        .collect();

    eprintln!();
    println!("  Done in {:.2?}", t_cuckoo.elapsed());

    // Check for failures
    let failures: Vec<_> = cuckoo_results.iter().filter(|(_, _, s)| !s).collect();
    if !failures.is_empty() {
        for (bid, _, _) in &failures {
            eprintln!("  FAILED: group {}", bid);
        }
        panic!("{} groups failed cuckoo insertion!", failures.len());
    }

    // ── 4. Build OnionPIR databases ─────────────────────────────────────
    println!("\n[4] Building OnionPIR databases (push_chunk → preprocess → save)...");
    fs::create_dir_all(OUTPUT_DIR).expect("create output dir");

    let t_pir = Instant::now();
    let p = onionpir::params_info(bins_per_table as u64);
    let padded_num = p.num_entries as usize;
    let entry_size = p.entry_size as usize;
    let fst_dim = p.fst_dim_sz as usize;
    let other_dim = p.other_dim_sz as usize;

    println!("  OnionPIR params: padded={}, entry_size={}, fst_dim={}, other_dim={}",
        padded_num, entry_size, fst_dim, other_dim);
    println!("  Physical size per group: {:.2} MB", p.physical_size_mb);
    println!("  Total for {} groups: {:.2} GB", K, p.physical_size_mb * K as f64 / 1024.0);

    // Process groups sequentially (OnionPIR Server is not Send)
    for (bucket_id, table, _) in &cuckoo_results {
        let preproc_path = Path::new(OUTPUT_DIR).join(format!("bucket_{}.bin", bucket_id));

        // Check if already preprocessed
        let mut server = PirServer::new(bins_per_table as u64);
        if preproc_path.exists() && server.load_db(preproc_path.to_str().unwrap()) {
            if *bucket_id == 0 {
                println!("  Loading existing preprocessed databases...");
            }
            continue;
        }

        if *bucket_id == 0 {
            println!("  Building new databases (this takes a while)...");
        }

        let t_group = Instant::now();

        // Populate: each cuckoo bin → one OnionPIR entry
        let chunk_size = fst_dim * entry_size;
        for chunk_idx in 0..other_dim {
            let mut chunk_data = vec![0u8; chunk_size];
            for i in 0..fst_dim {
                let global_bin = chunk_idx * fst_dim + i;
                if global_bin < bins_per_table {
                    let entry_bytes = serialize_cuckoo_bin(table, global_bin, mmap_slice, tree_locs_slice);
                    let offset = i * entry_size;
                    chunk_data[offset..offset + entry_size].copy_from_slice(&entry_bytes);
                }
            }
            server.push_chunk(&chunk_data, chunk_idx);
        }

        server.preprocess();
        server.save_db(preproc_path.to_str().unwrap());

        if *bucket_id % 10 == 0 || *bucket_id + 1 == K {
            eprintln!("  Group {}/{} preprocessed in {:.2?}", bucket_id + 1, K, t_group.elapsed());
        }
    }
    println!("  All groups built in {:.2?}", t_pir.elapsed());

    // ── 5. Save metadata ────────────────────────────────────────────────
    println!("\n[5] Saving metadata to {}...", META_FILE);
    {
        let meta_file = File::create(META_FILE).expect("create meta file");
        let mut w = BufWriter::new(meta_file);
        let magic: u64 = 0xBA7C_0010_0000_0002;
        w.write_all(&magic.to_le_bytes()).unwrap();
        w.write_all(&(K as u32).to_le_bytes()).unwrap();
        w.write_all(&(CUCKOO_NUM_HASHES as u32).to_le_bytes()).unwrap();
        w.write_all(&(CUCKOO_BUCKET_SIZE as u32).to_le_bytes()).unwrap();
        w.write_all(&(bins_per_table as u32).to_le_bytes()).unwrap();
        w.write_all(&MASTER_SEED.to_le_bytes()).unwrap();
        w.write_all(&TAG_SEED.to_le_bytes()).unwrap();
        w.write_all(&(INDEX_SLOT_SIZE as u32).to_le_bytes()).unwrap();
        w.flush().unwrap();
    }
    println!("  Done");

    // ── 6. Verify with test query ───────────────────────────────────────
    println!("\n[6] Verification: test query against group 0...");

    // Find a non-whale entry assigned to group 0
    let mut test_idx = None;
    for i in 0..n {
        let base = i * ONION_INDEX_ENTRY_SIZE;
        if mmap[base + 26] == FLAG_WHALE { continue; }
        let sh = &mmap[base..base + SCRIPT_HASH_SIZE];
        let buckets = derive_buckets(sh);
        if buckets.contains(&0) {
            test_idx = Some(i);
            break;
        }
    }
    let test_idx = test_idx.expect("no entries in group 0");
    let test_base = test_idx * ONION_INDEX_ENTRY_SIZE;
    let test_sh = &mmap[test_base..test_base + SCRIPT_HASH_SIZE];
    let test_tag = compute_tag(TAG_SEED, test_sh);

    // Find which bin this entry is in
    let test_table = &cuckoo_results[0].1;
    let key0 = derive_cuckoo_key(0, 0);
    let key1 = derive_cuckoo_key(0, 1);
    let bin0 = cuckoo_hash(test_sh, key0, bins_per_table);
    let bin1 = cuckoo_hash(test_sh, key1, bins_per_table);

    let mut found_bin = None;
    for &candidate_bin in &[bin0, bin1] {
        let base = candidate_bin * CUCKOO_BUCKET_SIZE;
        for slot in 0..CUCKOO_BUCKET_SIZE {
            if test_table[base + slot] == test_idx as u32 {
                found_bin = Some(candidate_bin);
                break;
            }
        }
        if found_bin.is_some() { break; }
    }
    let test_bin = found_bin.expect("test entry not found in cuckoo table");

    println!("  Test entry: index={}, bin={}, tag=0x{:016x}", test_idx, test_bin, test_tag);

    // Load the preprocessed database and query
    let preproc_path = Path::new(OUTPUT_DIR).join("bucket_0.bin");
    let mut server = PirServer::new(bins_per_table as u64);
    assert!(server.load_db(preproc_path.to_str().unwrap()), "failed to load bucket_0.bin");

    let mut client = PirClient::new(bins_per_table as u64);
    let client_id = client.id();
    server.set_galois_key(client_id, &client.generate_galois_keys());
    server.set_gsw_key(client_id, &client.generate_gsw_keys());

    let query = client.generate_query(test_bin as u64);
    let response = server.answer_query(client_id, &query);
    let decrypted = client.decrypt_response(test_bin as u64, &response);

    // The decrypted data is a 3840-byte bin with 256 × 15-byte slots.
    // Scan for our tag.
    let mut tag_found = false;
    for slot in 0..CUCKOO_BUCKET_SIZE {
        let offset = slot * INDEX_SLOT_SIZE;
        if offset + 8 > decrypted.len() { break; }
        let slot_tag = u64::from_le_bytes(decrypted[offset..offset + 8].try_into().unwrap());
        if slot_tag == test_tag {
            let entry_id = u32::from_le_bytes(decrypted[offset + 8..offset + 12].try_into().unwrap());
            let byte_offset = u16::from_le_bytes(decrypted[offset + 12..offset + 14].try_into().unwrap());
            let num_entries = decrypted[offset + 14];
            let tree_loc = u32::from_le_bytes(decrypted[offset + 15..offset + 19].try_into().unwrap());
            println!("  Tag match at slot {}: entry_id={}, offset={}, num_entries={}, tree_loc={}",
                slot, entry_id, byte_offset, num_entries, tree_loc);

            // Verify against original index entry
            let orig_entry_id = u32::from_le_bytes(mmap[test_base + 20..test_base + 24].try_into().unwrap());
            let orig_offset = u16::from_le_bytes(mmap[test_base + 24..test_base + 26].try_into().unwrap());
            let orig_num = mmap[test_base + 26];
            let orig_tree_loc = u32::from_le_bytes(tree_locs[test_idx * 4..(test_idx + 1) * 4].try_into().unwrap());

            if entry_id == orig_entry_id && byte_offset == orig_offset && num_entries == orig_num && tree_loc == orig_tree_loc {
                println!("  Verification: PASS (matches original index entry)");
            } else {
                println!("  Verification: MISMATCH!");
                println!("    Expected: entry_id={}, offset={}, num={}, tree_loc={}", orig_entry_id, orig_offset, orig_num, orig_tree_loc);
            }
            tag_found = true;
            break;
        }
    }
    if !tag_found {
        println!("  Verification: FAIL (tag 0x{:016x} not found in decrypted bin)", test_tag);
    }

    // ── Summary ─────────────────────────────────────────────────────────
    println!("\n=== Summary ===");
    println!("Index entries:     {} ({} non-whale)", n, non_whale);
    println!("PBC groups:        {}", K);
    println!("Bins per table:    {} ({} slots × {} bytes = {} B/bin)",
        bins_per_table, CUCKOO_BUCKET_SIZE, INDEX_SLOT_SIZE, ONIONPIR_ENTRY_SIZE);
    println!("OnionPIR per group: {:.2} MB (NTT-expanded)", p.physical_size_mb);
    println!("Total NTT storage: {:.2} GB", p.physical_size_mb * K as f64 / 1024.0);
    println!("Total time:        {:.2?}", total_start.elapsed());
}
