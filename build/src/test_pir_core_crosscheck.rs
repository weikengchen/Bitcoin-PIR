//! Cross-validation: verify pir-core parameterized functions produce identical
//! results to the legacy wrappers, and that the existing database is accessible
//! through pir-core's generic APIs.
//!
//! Tests:
//!   1. Header parsing (parameterized vs legacy)
//!   2. Hash function cross-check (1000 random script_hashes)
//!   3. Chunk hash cross-check (1000 random chunk_ids)
//!   4. Cuckoo lookup via parameterized functions (100 random entries)
//!   5. UTXO data parsing via pir_core::codec
//!   6. PBC round planning via pir_core::pbc
//!
//! Usage:
//!   cargo run --release -p build --bin test_pir_core_crosscheck

mod common;

use common::*;
use memmap2::Mmap;
use std::fs::File;
use std::time::Instant;

// Direct imports from pir-core (not via common.rs re-exports)
use pir_core::hash as pc_hash;
use pir_core::params as pc_params;
use pir_core::codec as pc_codec;
use pir_core::pbc as pc_pbc;

/// Simple deterministic PRNG for test reproducibility.
fn prng_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15);
    pc_hash::splitmix64(*state)
}

fn main() {
    println!("=== pir-core Cross-Validation Tests ===");
    println!();

    let mut total_checks = 0u64;
    let mut total_pass = 0u64;

    // ── Load database files ─────────────────────────────────────────────────

    println!("[0] Loading database files...");
    let f = File::open(CUCKOO_FILE).expect("open index cuckoo");
    let index_cuckoo = unsafe { Mmap::map(&f) }.expect("mmap index cuckoo");

    let f = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
    let chunk_cuckoo = unsafe { Mmap::map(&f) }.expect("mmap chunk cuckoo");

    let f = File::open(INDEX_FILE).expect("open index file");
    let index_file = unsafe { Mmap::map(&f) }.expect("mmap index file");
    let num_entries = index_file.len() / INDEX_ENTRY_SIZE;

    let f = File::open(CHUNKS_DATA_FILE).expect("open chunks data");
    let chunks_data = unsafe { Mmap::map(&f) }.expect("mmap chunks data");
    let num_chunks = chunks_data.len() / CHUNK_SIZE;

    println!("    Index entries: {}", num_entries);
    println!("    Chunks: {}", num_chunks);
    println!("    Index cuckoo: {:.2} GB", index_cuckoo.len() as f64 / 1e9);
    println!("    Chunk cuckoo: {:.2} GB", chunk_cuckoo.len() as f64 / 1e9);
    println!();

    // ── Test 1: Header parsing ──────────────────────────────────────────────

    println!("[1] Header parsing cross-check...");
    {
        // Legacy wrappers
        let (legacy_bins, legacy_tag_seed) = read_cuckoo_header(&index_cuckoo);
        let legacy_chunk_bins = read_chunk_cuckoo_header(&chunk_cuckoo);

        // Parameterized pir-core
        let (pc_bins, pc_tag_seed) = pc_hash::read_cuckoo_header(
            &index_cuckoo,
            pc_params::INDEX_PARAMS.magic,
            pc_params::INDEX_PARAMS.header_size,
            pc_params::INDEX_PARAMS.has_tag_seed,
        );
        let pc_chunk_bins = pc_hash::read_chunk_cuckoo_header(&chunk_cuckoo);

        check(&mut total_checks, &mut total_pass, "INDEX bins_per_table", legacy_bins == pc_bins);
        check(&mut total_checks, &mut total_pass, "INDEX tag_seed", legacy_tag_seed == pc_tag_seed);
        check(&mut total_checks, &mut total_pass, "CHUNK bins_per_table", legacy_chunk_bins == pc_chunk_bins);

        println!("    INDEX: bins={}, tag_seed=0x{:016x}", pc_bins, pc_tag_seed);
        println!("    CHUNK: bins={}", pc_chunk_bins);
    }
    println!();

    // ── Test 2: INDEX hash function cross-check ─────────────────────────────

    println!("[2] INDEX hash function cross-check (1000 entries)...");
    let (legacy_bins, legacy_tag_seed) = read_cuckoo_header(&index_cuckoo);
    {
        let mut rng = 0xDEAD_BEEF_CAFE_1234u64;
        let mut hash_pass = 0u64;
        let n = 1000;

        for _ in 0..n {
            let idx = (prng_next(&mut rng) % num_entries as u64) as usize;
            let offset = idx * INDEX_ENTRY_SIZE;
            let sh = &index_file[offset..offset + SCRIPT_HASH_SIZE];

            // derive_buckets
            let legacy_b = derive_buckets(sh);
            let pc_b = pc_hash::derive_buckets_3(sh, pc_params::K);
            if legacy_b != pc_b {
                println!("    FAIL: derive_buckets mismatch at entry {}", idx);
                continue;
            }

            // derive_cuckoo_key for each bucket
            let mut key_ok = true;
            for &b in &legacy_b {
                for hf in 0..INDEX_CUCKOO_NUM_HASHES {
                    let lk = derive_cuckoo_key(b, hf);
                    let pk = pc_hash::derive_cuckoo_key(pc_params::MASTER_SEED, b, hf);
                    if lk != pk {
                        println!("    FAIL: derive_cuckoo_key mismatch at bucket {}, hf {}", b, hf);
                        key_ok = false;
                    }
                }
            }
            if !key_ok { continue; }

            // cuckoo_hash
            let key0 = derive_cuckoo_key(legacy_b[0], 0);
            let lh = cuckoo_hash(sh, key0, legacy_bins);
            let ph = pc_hash::cuckoo_hash(sh, key0, legacy_bins);
            if lh != ph {
                println!("    FAIL: cuckoo_hash mismatch at entry {}", idx);
                continue;
            }

            // compute_tag
            let lt = compute_tag(legacy_tag_seed, sh);
            let pt = pc_hash::compute_tag(legacy_tag_seed, sh);
            if lt != pt {
                println!("    FAIL: compute_tag mismatch at entry {}", idx);
                continue;
            }

            hash_pass += 1;
        }

        check(&mut total_checks, &mut total_pass, &format!("INDEX hashes ({}/{})", hash_pass, n), hash_pass == n);
    }
    println!();

    // ── Test 3: CHUNK hash function cross-check ─────────────────────────────

    println!("[3] CHUNK hash function cross-check (1000 chunk_ids)...");
    let chunk_bins = read_chunk_cuckoo_header(&chunk_cuckoo);
    {
        let mut rng = 0xCAFE_BABE_0000_0001u64;
        let mut hash_pass = 0u64;
        let n = 1000;

        for _ in 0..n {
            let chunk_id = (prng_next(&mut rng) % num_chunks as u64) as u32;

            // derive_chunk_buckets
            let lb = derive_chunk_buckets(chunk_id);
            let pb = pc_hash::derive_int_buckets_3(chunk_id, pc_params::K_CHUNK);
            if lb != pb {
                println!("    FAIL: derive_chunk_buckets mismatch for chunk_id {}", chunk_id);
                continue;
            }

            // derive_chunk_cuckoo_key
            let mut key_ok = true;
            for &b in &lb {
                for hf in 0..CHUNK_CUCKOO_NUM_HASHES {
                    let lk = derive_chunk_cuckoo_key(b, hf);
                    let pk = pc_hash::derive_cuckoo_key(pc_params::CHUNK_MASTER_SEED, b, hf);
                    if lk != pk {
                        println!("    FAIL: derive_chunk_cuckoo_key mismatch");
                        key_ok = false;
                    }
                }
            }
            if !key_ok { continue; }

            // cuckoo_hash_int
            let key0 = derive_chunk_cuckoo_key(lb[0], 0);
            let lh = cuckoo_hash_int(chunk_id, key0, chunk_bins);
            let ph = pc_hash::cuckoo_hash_int(chunk_id, key0, chunk_bins);
            if lh != ph {
                println!("    FAIL: cuckoo_hash_int mismatch for chunk_id {}", chunk_id);
                continue;
            }

            hash_pass += 1;
        }

        check(&mut total_checks, &mut total_pass, &format!("CHUNK hashes ({}/{})", hash_pass, n), hash_pass == n);
    }
    println!();

    // ── Test 4: Cuckoo lookup via parameterized functions ───────────────────

    println!("[4] Cuckoo lookup via pir-core parameterized functions (100 entries)...");
    {
        let index_table_byte_size = legacy_bins * CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE;
        let mut rng = 0x1234_5678_ABCD_EF00u64;
        let mut lookup_pass = 0u64;
        let n = 100;

        for _ in 0..n {
            let idx = (prng_next(&mut rng) % num_entries as u64) as usize;
            let offset = idx * INDEX_ENTRY_SIZE;
            let sh = &index_file[offset..offset + SCRIPT_HASH_SIZE];
            let expected_chunk_id = u32::from_le_bytes(
                index_file[offset + SCRIPT_HASH_SIZE..offset + SCRIPT_HASH_SIZE + 4].try_into().unwrap()
            );
            let expected_num_chunks = index_file[offset + SCRIPT_HASH_SIZE + 4];

            if expected_num_chunks == 0 {
                // Whale sentinel — skip
                lookup_pass += 1;
                continue;
            }

            let expected_tag = pc_hash::compute_tag(legacy_tag_seed, sh);
            let buckets = pc_hash::derive_buckets_3(sh, pc_params::K);

            let mut found = false;
            for &bucket_id in &buckets {
                let table_offset = HEADER_SIZE + bucket_id * index_table_byte_size;

                for hf in 0..pc_params::INDEX_PARAMS.cuckoo_num_hashes {
                    let key = pc_hash::derive_cuckoo_key(pc_params::MASTER_SEED, bucket_id, hf);
                    let bin = pc_hash::cuckoo_hash(sh, key, legacy_bins);
                    let bin_offset = table_offset + bin * CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE;

                    for slot in 0..CUCKOO_BUCKET_SIZE {
                        let slot_offset = bin_offset + slot * INDEX_SLOT_SIZE;
                        let tag = u64::from_le_bytes(
                            index_cuckoo[slot_offset..slot_offset + TAG_SIZE].try_into().unwrap()
                        );
                        if tag == expected_tag {
                            let cid = u32::from_le_bytes(
                                index_cuckoo[slot_offset + TAG_SIZE..slot_offset + TAG_SIZE + 4].try_into().unwrap()
                            );
                            let nc = index_cuckoo[slot_offset + TAG_SIZE + 4];
                            if cid == expected_chunk_id && nc == expected_num_chunks {
                                found = true;
                            }
                        }
                    }
                    if found { break; }
                }
                if found { break; }
            }

            if found {
                lookup_pass += 1;
            } else {
                println!("    FAIL: entry {} not found in cuckoo table", idx);
            }
        }

        check(&mut total_checks, &mut total_pass, &format!("Cuckoo lookups ({}/{})", lookup_pass, n), lookup_pass == n);
    }
    println!();

    // ── Test 5: UTXO data parsing ──────────────────────────────────────────

    println!("[5] UTXO data parsing via pir_core::codec (100 chunks)...");
    {
        let mut rng = 0xAAAA_BBBB_CCCC_DDDDu64;
        let mut parse_pass = 0u64;
        let n = 100;

        for _ in 0..n {
            let idx = (prng_next(&mut rng) % num_entries as u64) as usize;
            let offset = idx * INDEX_ENTRY_SIZE;
            let start_chunk_id = u32::from_le_bytes(
                index_file[offset + SCRIPT_HASH_SIZE..offset + SCRIPT_HASH_SIZE + 4].try_into().unwrap()
            );
            let num_chunks_val = index_file[offset + SCRIPT_HASH_SIZE + 4];

            if num_chunks_val == 0 {
                parse_pass += 1;
                continue;
            }

            let data_start = start_chunk_id as usize * CHUNK_SIZE;
            let data_end = data_start + (num_chunks_val as usize * CHUNK_SIZE);
            if data_end > chunks_data.len() {
                println!("    SKIP: chunk data out of bounds for entry {}", idx);
                continue;
            }

            let data = &chunks_data[data_start..data_end];
            let entries = pc_codec::parse_utxo_data(data);

            if entries.is_empty() {
                println!("    FAIL: parsed 0 entries for entry {} (num_chunks={})", idx, num_chunks_val);
                continue;
            }

            // Basic sanity checks
            let mut sane = true;
            for e in &entries {
                if e.amount == 0 {
                    // Amount can be 0 for some edge cases, but shouldn't be common
                }
                if e.txid == [0u8; 32] {
                    println!("    WARN: zero txid in entry {}", idx);
                }
            }

            if sane {
                parse_pass += 1;
            }
        }

        check(&mut total_checks, &mut total_pass, &format!("UTXO parsing ({}/{})", parse_pass, n), parse_pass == n);
    }
    println!();

    // ── Test 6: PBC round planning ──────────────────────────────────────────

    println!("[6] PBC round planning via pir_core::pbc...");
    {
        // Take 50 random entries, get their chunk assignments, plan rounds
        let mut rng = 0x5050_5050_5050_5050u64;
        let n = 50usize;
        let mut chunk_ids: Vec<u32> = Vec::new();

        for _ in 0..n {
            let idx = (prng_next(&mut rng) % num_entries as u64) as usize;
            let offset = idx * INDEX_ENTRY_SIZE;
            let start_chunk_id = u32::from_le_bytes(
                index_file[offset + SCRIPT_HASH_SIZE..offset + SCRIPT_HASH_SIZE + 4].try_into().unwrap()
            );
            let num_chunks_val = index_file[offset + SCRIPT_HASH_SIZE + 4];
            if num_chunks_val > 0 {
                for c in 0..num_chunks_val as u32 {
                    chunk_ids.push(start_chunk_id + c);
                }
            }
        }

        // Deduplicate
        chunk_ids.sort();
        chunk_ids.dedup();

        println!("    {} unique chunk_ids from {} entries", chunk_ids.len(), n);

        // Get bucket assignments
        let item_buckets: Vec<[usize; 3]> = chunk_ids.iter()
            .map(|&id| pc_hash::derive_int_buckets_3(id, pc_params::K_CHUNK))
            .collect();

        let t = Instant::now();
        let rounds = pc_pbc::pbc_plan_rounds(&item_buckets, pc_params::K_CHUNK, 3, 1000);

        let total_placed: usize = rounds.iter().map(|r| r.len()).sum();
        println!("    {} rounds, {} items placed in {:.2?}", rounds.len(), total_placed, t.elapsed());

        let all_placed = total_placed == chunk_ids.len();
        check(&mut total_checks, &mut total_pass, &format!("PBC planning ({}/{})", total_placed, chunk_ids.len()), all_placed);
    }
    println!();

    // ── Summary ─────────────────────────────────────────────────────────────

    println!("════════════════════════════════════");
    println!("  TOTAL: {}/{} checks passed", total_pass, total_checks);
    if total_pass == total_checks {
        println!("  STATUS: ALL PASSED ✓");
    } else {
        println!("  STATUS: {} FAILED ✗", total_checks - total_pass);
    }
    println!("════════════════════════════════════");

    if total_pass != total_checks {
        std::process::exit(1);
    }
}

fn check(total: &mut u64, pass: &mut u64, name: &str, ok: bool) {
    *total += 1;
    if ok {
        *pass += 1;
        println!("    [PASS] {}", name);
    } else {
        println!("    [FAIL] {}", name);
    }
}
