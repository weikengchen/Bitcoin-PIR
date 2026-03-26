//! End-to-end test for the Batch PIR protocol (v2: inlined 14-byte tagged entries).
//!
//! 1. Loads the cuckoo tables (batch_pir_cuckoo.bin) with inlined tagged entries.
//! 2. Loads the 50 test queries and runs cuckoo assignment (query → bucket, loc0, loc1).
//! 3. For each of the 75 buckets, generates DPF keys for both servers.
//!    - Occupied buckets: DPF keys target loc0 and loc1 of the assigned query.
//!    - Empty buckets: DPF keys target position 0 (dummy).
//! 4. Calls the server processing function TWICE (once per server).
//! 5. XORs the two servers' results and verifies correctness by tag matching.
//!
//! Usage:
//!   cargo run --release -p build --bin test_batch_pir

mod common;

use common::*;
use libdpf::{Block, Dpf, DpfKey};
use std::fs;
use std::io::Write;
use std::time::Instant;
use rayon::prelude::*;

const QUERIES_FILE: &str = "/Volumes/Bitcoin/data/test_queries_50.bin";
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/batch_pir_results.bin";

/// Each cuckoo bin has 3 slots, each a 13-byte inlined tagged entry.
/// Result per DPF query = 3 * 13 = 39 bytes.
const SLOT_SIZE: usize = INDEX_SLOT_SIZE; // 13
const SLOTS: usize = CUCKOO_BUCKET_SIZE;  // 3
const RESULT_SIZE: usize = SLOTS * SLOT_SIZE; // 42

/// We need 2^n >= bins_per_table. bins_per_table ≈ 616423, so n = 20 (2^20 = 1048576).
const DPF_N: u8 = 20;

// ─── DPF bit extraction ─────────────────────────────────────────────────────

/// Check whether bit `pos` is set in the DPF eval_full result.
#[inline]
fn get_dpf_bit(block: &Block, bit_within_block: usize) -> bool {
    if bit_within_block < 64 {
        (block.low >> bit_within_block) & 1 == 1
    } else {
        (block.high >> (bit_within_block - 64)) & 1 == 1
    }
}

// ─── Server processing ──────────────────────────────────────────────────────

/// Process one bucket: evaluate two DPF keys and produce two XOR-accumulated
/// results by scanning the inlined cuckoo table.
///
/// The scan is parallelized across 128-bin blocks; each thread maintains its
/// own pair of accumulators which are reduced at the end.
fn process_bucket(
    dpf_result_0: &[Block], // eval_full of DPF key for query 0
    dpf_result_1: &[Block], // eval_full of DPF key for query 1
    table_bytes: &[u8],     // this bucket's inlined cuckoo table
    bins_per_table: usize,
) -> ([u8; RESULT_SIZE], [u8; RESULT_SIZE]) {
    let num_blocks = dpf_result_0.len();

    (0..num_blocks)
        .into_par_iter()
        .fold(
            || ([0u8; RESULT_SIZE], [0u8; RESULT_SIZE]),
            |(mut acc0, mut acc1), block_idx| {
                let blk0 = &dpf_result_0[block_idx];
                let blk1 = &dpf_result_1[block_idx];

                // If both blocks are zero, skip all 128 bins
                if blk0.is_equal(&Block::zero()) && blk1.is_equal(&Block::zero()) {
                    return (acc0, acc1);
                }

                let base_bin = block_idx * 128;
                let end_bin = (base_bin + 128).min(bins_per_table);

                for bin in base_bin..end_bin {
                    let bit_within = bin - base_bin;
                    let b0 = get_dpf_bit(blk0, bit_within);
                    let b1 = get_dpf_bit(blk1, bit_within);

                    if !b0 && !b1 {
                        continue;
                    }

                    // Fetch the inlined bin: SLOTS * SLOT_SIZE bytes
                    let bin_offset = bin * RESULT_SIZE;
                    let bin_data: &[u8] = &table_bytes[bin_offset..bin_offset + RESULT_SIZE];

                    if b0 {
                        xor_into(&mut acc0, bin_data);
                    }
                    if b1 {
                        xor_into(&mut acc1, bin_data);
                    }
                }

                (acc0, acc1)
            },
        )
        .reduce(
            || ([0u8; RESULT_SIZE], [0u8; RESULT_SIZE]),
            |(mut a0, mut a1), (b0, b1)| {
                xor_into(&mut a0, &b0);
                xor_into(&mut a1, &b1);
                (a0, a1)
            },
        )
}

/// XOR `src` into `dst` in-place, using u64 chunks for speed.
#[inline]
fn xor_into(dst: &mut [u8; RESULT_SIZE], src: &[u8]) {
    // RESULT_SIZE = 39 = 4 * 8 + 7, so handle remainder
    const N: usize = RESULT_SIZE / 8;
    let d = unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u64, N) };
    let s = unsafe { std::slice::from_raw_parts(src.as_ptr() as *const u64, N) };
    for i in 0..N {
        d[i] ^= s[i];
    }
    for i in (N * 8)..RESULT_SIZE {
        dst[i] ^= src[i];
    }
}

/// Run the full server for all 75 buckets.
///
/// `dpf_keys` — one DPF key per (bucket, query), i.e. dpf_keys[b] = (key_for_q0, key_for_q1).
///
/// Returns results[b] = (result_q0, result_q1), each RESULT_SIZE bytes.
fn server_process(
    dpf_keys: &[(DpfKey, DpfKey)],
    cuckoo_data: &[u8],
    bins_per_table: usize,
) -> Vec<([u8; RESULT_SIZE], [u8; RESULT_SIZE])> {
    let dpf = Dpf::with_default_key();
    let table_byte_size = bins_per_table * SLOTS * SLOT_SIZE;

    let mut results = Vec::with_capacity(K);

    for b in 0..K {
        let table_offset = HEADER_SIZE + b * table_byte_size;
        let table_bytes = &cuckoo_data[table_offset..table_offset + table_byte_size];

        // Evaluate both DPF keys (full domain)
        let eval0 = dpf.eval_full(&dpf_keys[b].0);
        let eval1 = dpf.eval_full(&dpf_keys[b].1);

        let (r0, r1) = process_bucket(&eval0, &eval1, table_bytes, bins_per_table);
        results.push((r0, r1));

        eprint!("\r  Bucket {}/{}", b + 1, K);
    }
    eprintln!();

    results
}

// ─── Cuckoo assignment (same logic as assign_queries.rs) ─────────────────────

const MAX_KICKS: usize = 1000;

fn cuckoo_assign(
    queries: &[[usize; NUM_HASHES]],
) -> Result<[Option<usize>; K], &'static str> {
    let mut buckets: [Option<usize>; K] = [None; K];
    let num = queries.len();

    for i in 0..num {
        if !pbc_cuckoo_place(queries, &mut buckets, i, MAX_KICKS, NUM_HASHES) {
            return Err("Cuckoo assignment failed");
        }
    }
    Ok(buckets)
}

// ─── Main test ───────────────────────────────────────────────────────────────

fn main() {
    println!("=== Batch PIR End-to-End Test (v2: inlined tagged entries) ===");
    println!();
    let start = Instant::now();

    // ── 1. Load data ─────────────────────────────────────────────────────
    println!("[1] Loading data files...");

    let cuckoo_data = fs::read(CUCKOO_FILE).expect("read cuckoo file");
    let (bins_per_table, tag_seed) = read_cuckoo_header(&cuckoo_data);
    let table_byte_size = bins_per_table * SLOTS * SLOT_SIZE;
    println!("  Cuckoo: bins_per_table = {}, tag_seed = 0x{:016x}", bins_per_table, tag_seed);
    println!("  Table size per bucket: {:.2} MB", table_byte_size as f64 / (1024.0 * 1024.0));

    let query_data = fs::read(QUERIES_FILE).expect("read queries");
    let num_queries = query_data.len() / SCRIPT_HASH_SIZE;
    println!("  Queries: {}", num_queries);
    println!();

    // ── 2. Assign queries to buckets ─────────────────────────────────────
    println!("[2] Cuckoo-assigning {} queries to {} buckets...", num_queries, K);

    let mut candidate_buckets: Vec<[usize; NUM_HASHES]> = Vec::with_capacity(num_queries);
    for i in 0..num_queries {
        let sh = &query_data[i * SCRIPT_HASH_SIZE..(i + 1) * SCRIPT_HASH_SIZE];
        candidate_buckets.push(derive_buckets(sh));
    }

    let bucket_assignment = cuckoo_assign(&candidate_buckets).expect("assign");
    println!("  All queries placed.");

    // Build: query_idx → assigned_bucket
    let mut query_bucket = vec![0usize; num_queries];
    for (b, slot) in bucket_assignment.iter().enumerate() {
        if let Some(qi) = slot {
            query_bucket[*qi] = b;
        }
    }

    // Compute loc0, loc1 for each query in its assigned bucket
    let mut query_locs: Vec<(usize, usize)> = Vec::with_capacity(num_queries);
    for i in 0..num_queries {
        let sh = &query_data[i * SCRIPT_HASH_SIZE..(i + 1) * SCRIPT_HASH_SIZE];
        let b = query_bucket[i];
        let key0 = derive_cuckoo_key(b, 0);
        let key1 = derive_cuckoo_key(b, 1);
        let loc0 = cuckoo_hash(sh, key0, bins_per_table);
        let loc1 = cuckoo_hash(sh, key1, bins_per_table);
        query_locs.push((loc0, loc1));
    }

    println!();

    // ── 3. Generate DPF keys ─────────────────────────────────────────────
    println!("[3] Generating DPF keys (n={}, domain=2^{} = {})...", DPF_N, DPF_N, 1u64 << DPF_N);
    let dpf = Dpf::with_default_key();
    let gen_start = Instant::now();

    let mut server0_keys: Vec<(DpfKey, DpfKey)> = Vec::with_capacity(K);
    let mut server1_keys: Vec<(DpfKey, DpfKey)> = Vec::with_capacity(K);

    for b in 0..K {
        let (alpha_q0, alpha_q1) = if let Some(qi) = bucket_assignment[b] {
            (query_locs[qi].0 as u64, query_locs[qi].1 as u64)
        } else {
            (0u64, 0u64) // dummy for empty buckets
        };

        let (k0_q0, k1_q0) = dpf.gen(alpha_q0, DPF_N);
        let (k0_q1, k1_q1) = dpf.gen(alpha_q1, DPF_N);

        server0_keys.push((k0_q0, k0_q1));
        server1_keys.push((k1_q0, k1_q1));
    }

    println!("  Generated {} key pairs in {:.2?}", K * 2, gen_start.elapsed());
    println!();

    // ── 4. Server 0 processing ───────────────────────────────────────────
    println!("[4] Server 0 processing...");
    let s0_start = Instant::now();
    let server0_results = server_process(&server0_keys, &cuckoo_data, bins_per_table);
    println!("  Done in {:.2?}", s0_start.elapsed());

    // ── 5. Server 1 processing ───────────────────────────────────────────
    println!("[5] Server 1 processing...");
    let s1_start = Instant::now();
    let server1_results = server_process(&server1_keys, &cuckoo_data, bins_per_table);
    println!("  Done in {:.2?}", s1_start.elapsed());
    println!();

    // ── 6. Client: XOR, verify by tag, and extract chunk offsets ─────────
    println!("[6] Client: XOR server results, verify by tag, and extract chunk offsets...");
    let mut found = 0;
    let mut not_found = 0;

    // Output: (script_hash[20], start_chunk_id[4], num_chunks[1])
    let mut output_entries: Vec<(Vec<u8>, [u8; 4], u8)> = Vec::with_capacity(num_queries);

    for qi in 0..num_queries {
        let b = query_bucket[qi];
        let sh = &query_data[qi * SCRIPT_HASH_SIZE..(qi + 1) * SCRIPT_HASH_SIZE];
        let expected_tag = compute_tag(tag_seed, sh);
        let (loc0, loc1) = query_locs[qi];

        // XOR server0 and server1 results for query q0 (loc0)
        let mut result_q0 = server0_results[b].0;
        xor_into(&mut result_q0, &server1_results[b].0);

        // XOR server0 and server1 results for query q1 (loc1)
        let mut result_q1 = server0_results[b].1;
        xor_into(&mut result_q1, &server1_results[b].1);

        // Check if our tag appears in either result
        let mut matched = false;
        for result in [&result_q0, &result_q1] {
            if let Some((start_chunk_id, num_chunks)) =
                find_entry_in_result(result, expected_tag)
            {
                output_entries.push((sh.to_vec(), start_chunk_id, num_chunks));
                matched = true;
                found += 1;
                break;
            }
        }

        if !matched {
            not_found += 1;
            output_entries.push((sh.to_vec(), [0u8; 4], 0u8));
            let hex: String = sh.iter().map(|x| format!("{:02x}", x)).collect();
            println!(
                "  MISS: query {} bucket {} loc0={} loc1={} hash={}",
                qi, b, loc0, loc1, hex
            );
        }
    }

    println!();
    println!("=== Results ===");
    println!("  Found:     {} / {}", found, num_queries);
    println!("  Not found: {} / {}", not_found, num_queries);
    if not_found == 0 {
        println!("  All {} queries recovered correctly!", num_queries);
    } else {
        println!("  {} queries failed", not_found);
    }

    // ── 7. Write results to file ─────────────────────────────────────────
    println!();
    println!("[7] Writing results to: {}", OUTPUT_FILE);

    // File format: for each query, 25 bytes = [20B script_hash | 4B start_chunk_id | 1B num_chunks]
    let mut out_file = std::fs::File::create(OUTPUT_FILE).expect("create output");
    for (sh, start_chunk_id, num_chunks) in &output_entries {
        out_file.write_all(sh).unwrap();
        out_file.write_all(start_chunk_id).unwrap();
        out_file.write_all(&[*num_chunks]).unwrap();
    }
    println!(
        "  Written {} bytes ({} queries x 25 bytes)",
        num_queries * 25,
        num_queries
    );

    // Print the results for inspection
    println!();
    println!("[8] Recovered entries:");
    println!(
        "  {:>4}  {:>42}  {:>12}  {:>10}",
        "#", "Script Hash", "Offset/2", "Chunks"
    );
    println!(
        "  {}  {}  {}  {}",
        "-".repeat(4),
        "-".repeat(42),
        "-".repeat(12),
        "-".repeat(10)
    );
    for (qi, (sh, start_chunk_id, num_chunks)) in output_entries.iter().enumerate() {
        let hex: String = sh.iter().map(|x| format!("{:02x}", x)).collect();
        let offset = u32::from_le_bytes(*start_chunk_id);
        println!("  {:>4}  {}  {:>12}  {:>10}", qi, hex, offset, *num_chunks);
    }

    println!();
    println!("  Total time: {:.2?}", start.elapsed());
}

/// Find the expected tag in the result's slots and return (start_chunk_id bytes, num_chunks).
/// Slot layout: [8B tag | 4B start_chunk_id | 1B num_chunks]
fn find_entry_in_result(
    result: &[u8; RESULT_SIZE],
    expected_tag: u64,
) -> Option<([u8; 4], u8)> {
    for slot in 0..SLOTS {
        let base = slot * SLOT_SIZE;
        let slot_tag = u64::from_le_bytes(result[base..base + TAG_SIZE].try_into().unwrap());
        if slot_tag == expected_tag {
            let mut start_chunk_id = [0u8; 4];
            start_chunk_id.copy_from_slice(&result[base + TAG_SIZE..base + TAG_SIZE + 4]);
            let num_chunks = result[base + TAG_SIZE + 4];
            return Some((start_chunk_id, num_chunks));
        }
    }
    None
}
