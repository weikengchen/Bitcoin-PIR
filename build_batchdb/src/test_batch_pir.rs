//! End-to-end test for the Batch PIR protocol.
//!
//! 1. Loads the cuckoo tables (batch_pir_cuckoo.bin) and the index (utxo_chunks_index.bin).
//! 2. Loads the 50 test queries and runs cuckoo assignment (query → bucket, loc0, loc1).
//! 3. For each of the 75 buckets, generates DPF keys for both servers.
//!    - Occupied buckets: DPF keys target loc0 and loc1 of the assigned query.
//!    - Empty buckets: DPF keys target position 0 (dummy).
//! 4. Calls the server processing function TWICE (once per server).
//! 5. XORs the two servers' results and verifies correctness.
//!
//! Usage:
//!   cargo run --release -p build_batchdb --bin test_batch_pir

mod common;

use common::*;
use libdpf::{Block, Dpf, DpfKey};
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::Write;
use std::time::Instant;

const QUERIES_FILE: &str = "/Volumes/Bitcoin/data/test_queries_50.bin";
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/batch_pir_results.bin";

/// Each cuckoo bin has 4 slots, each referencing a 28-byte index entry.
/// Result per DPF query = 4 * 28 = 112 bytes.
const ENTRY_SIZE: usize = INDEX_ENTRY_SIZE; // 28
const SLOTS: usize = CUCKOO_BUCKET_SIZE; // 4
const RESULT_SIZE: usize = SLOTS * ENTRY_SIZE; // 112

/// We need 2^n >= bins_per_table. bins_per_table ≈ 616423, so n = 20 (2^20 = 1048576).
const DPF_N: u8 = 20;

const EMPTY: u32 = u32::MAX;

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
/// results by scanning the cuckoo table and looking up index entries.
///
/// The scan is parallelized across 128-bin blocks; each thread maintains its
/// own pair of accumulators which are reduced at the end.
fn process_bucket(
    dpf_result_0: &[Block], // eval_full of DPF key for query 0
    dpf_result_1: &[Block], // eval_full of DPF key for query 1
    table_bytes: &[u8],     // this bucket's cuckoo table raw bytes
    index_data: &[u8],      // the full utxo_chunks_index
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
                        continue; // neither query needs this bin → skip fetch
                    }

                    // Fetch the 4 entries at this bin
                    let bin_entries = fetch_bin_entries(table_bytes, bin, index_data);

                    if b0 {
                        xor_into(&mut acc0, &bin_entries);
                    }
                    if b1 {
                        xor_into(&mut acc1, &bin_entries);
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

/// Fetch the 4 entries at `bin` from the cuckoo table, resolving u32 refs
/// through the index. EMPTY slots contribute 24 zero bytes.
#[inline]
fn fetch_bin_entries(
    table_bytes: &[u8],
    bin: usize,
    index_data: &[u8],
) -> [u8; RESULT_SIZE] {
    let mut out = [0u8; RESULT_SIZE];
    for slot in 0..SLOTS {
        let slot_offset = (bin * SLOTS + slot) * 4;
        let ref_u32 = u32::from_le_bytes(
            table_bytes[slot_offset..slot_offset + 4]
                .try_into()
                .unwrap(),
        );
        if ref_u32 != EMPTY {
            let entry_offset = ref_u32 as usize * ENTRY_SIZE;
            let dst = slot * ENTRY_SIZE;
            out[dst..dst + ENTRY_SIZE]
                .copy_from_slice(&index_data[entry_offset..entry_offset + ENTRY_SIZE]);
        }
    }
    out
}

/// XOR `src` into `dst` in-place, using u64 chunks for speed.
#[inline]
fn xor_into(dst: &mut [u8; RESULT_SIZE], src: &[u8; RESULT_SIZE]) {
    // RESULT_SIZE = 112 = 14 * 8, so we can work in u64 chunks
    const N: usize = RESULT_SIZE / 8;
    let d = unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u64, N) };
    let s = unsafe { std::slice::from_raw_parts(src.as_ptr() as *const u64, N) };
    for i in 0..N {
        d[i] ^= s[i];
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
    index_data: &[u8],
    bins_per_table: usize,
) -> Vec<([u8; RESULT_SIZE], [u8; RESULT_SIZE])> {
    let dpf = Dpf::with_default_key();
    let slots_per_table = bins_per_table * SLOTS;
    let table_byte_size = slots_per_table * 4;

    let mut results = Vec::with_capacity(K);

    for b in 0..K {
        let table_offset = HEADER_SIZE + b * table_byte_size;
        let table_bytes = &cuckoo_data[table_offset..table_offset + table_byte_size];

        // Evaluate both DPF keys (full domain)
        let eval0 = dpf.eval_full(&dpf_keys[b].0);
        let eval1 = dpf.eval_full(&dpf_keys[b].1);

        let (r0, r1) = process_bucket(&eval0, &eval1, table_bytes, index_data, bins_per_table);
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
        if !cuckoo_place(queries, &mut buckets, i) {
            return Err("Cuckoo assignment failed");
        }
    }
    Ok(buckets)
}

fn cuckoo_place(
    queries: &[[usize; NUM_HASHES]],
    buckets: &mut [Option<usize>; K],
    qi: usize,
) -> bool {
    let cands = &queries[qi];
    for &c in cands {
        if buckets[c].is_none() {
            buckets[c] = Some(qi);
            return true;
        }
    }
    let mut current_qi = qi;
    let mut current_bucket = queries[current_qi][0];

    for kick in 0..MAX_KICKS {
        let evicted_qi = buckets[current_bucket].unwrap();
        buckets[current_bucket] = Some(current_qi);
        let ev_cands = &queries[evicted_qi];

        for offset in 0..NUM_HASHES {
            let c = ev_cands[(kick + offset) % NUM_HASHES];
            if c == current_bucket {
                continue;
            }
            if buckets[c].is_none() {
                buckets[c] = Some(evicted_qi);
                return true;
            }
        }

        let mut next_bucket = ev_cands[0];
        for offset in 0..NUM_HASHES {
            let c = ev_cands[(kick + offset) % NUM_HASHES];
            if c != current_bucket {
                next_bucket = c;
                break;
            }
        }
        current_qi = evicted_qi;
        current_bucket = next_bucket;
    }
    false
}

// ─── Main test ───────────────────────────────────────────────────────────────

fn main() {
    println!("=== Batch PIR End-to-End Test ===");
    println!();
    let start = Instant::now();

    // ── 1. Load data ─────────────────────────────────────────────────────
    println!("[1] Loading data files...");

    let index_file = File::open(INDEX_FILE).expect("open index");
    let index_mmap = unsafe { Mmap::map(&index_file) }.expect("mmap index");
    let n_entries = index_mmap.len() / INDEX_ENTRY_SIZE;
    println!("  Index: {} entries ({:.1} MB)", n_entries, index_mmap.len() as f64 / 1e6);

    let cuckoo_data = fs::read(CUCKOO_FILE).expect("read cuckoo file");
    let bins_per_table = read_cuckoo_header(&cuckoo_data);
    println!("  Cuckoo: bins_per_table = {}", bins_per_table);

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

    // For each bucket: (key_for_server0_q0, key_for_server0_q1)
    //                  (key_for_server1_q0, key_for_server1_q1)
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
    let server0_results =
        server_process(&server0_keys, &cuckoo_data, &index_mmap, bins_per_table);
    println!("  Done in {:.2?}", s0_start.elapsed());

    // ── 5. Server 1 processing ───────────────────────────────────────────
    println!("[5] Server 1 processing...");
    let s1_start = Instant::now();
    let server1_results =
        server_process(&server1_keys, &cuckoo_data, &index_mmap, bins_per_table);
    println!("  Done in {:.2?}", s1_start.elapsed());
    println!();

    // ── 6. Client: XOR, verify, and extract chunk offsets ───────────────
    println!("[6] Client: XOR server results, verify, and extract chunk offsets...");
    let mut found = 0;
    let mut not_found = 0;

    // For each query: (script_hash[20], offset_half[4], num_chunks[4])
    // Output file: num_queries entries of [20B script_hash | 4B offset_half | 4B num_chunks]
    let mut output_entries: Vec<(Vec<u8>, [u8; 4], [u8; 4])> = Vec::with_capacity(num_queries);

    for qi in 0..num_queries {
        let b = query_bucket[qi];
        let sh = &query_data[qi * SCRIPT_HASH_SIZE..(qi + 1) * SCRIPT_HASH_SIZE];
        let (loc0, loc1) = query_locs[qi];

        // XOR server0 and server1 results for query q0 (loc0)
        let mut result_q0 = server0_results[b].0;
        xor_into(&mut result_q0, &server1_results[b].0);

        // XOR server0 and server1 results for query q1 (loc1)
        let mut result_q1 = server0_results[b].1;
        xor_into(&mut result_q1, &server1_results[b].1);

        // Check if our script_hash appears in either result; extract offset_half + num_chunks
        let mut matched = false;
        for result in [&result_q0, &result_q1] {
            if let Some((offset_half, num_chunks)) = find_entry_in_result(result, sh) {
                output_entries.push((sh.to_vec(), offset_half, num_chunks));
                matched = true;
                found += 1;
                break;
            }
        }

        if !matched {
            not_found += 1;
            output_entries.push((sh.to_vec(), [0u8; 4], [0u8; 4]));
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
        println!("  ✓ All {} queries recovered correctly!", num_queries);
    } else {
        println!("  ✗ {} queries failed", not_found);
    }

    // ── 7. Write results to file ─────────────────────────────────────────
    println!();
    println!("[7] Writing results to: {}", OUTPUT_FILE);

    // File format: for each query, 28 bytes = [20B script_hash | 4B offset_half | 4B num_chunks]
    let mut out_file = File::create(OUTPUT_FILE).expect("create output");
    for (sh, offset_half, num_chunks) in &output_entries {
        out_file.write_all(sh).unwrap();
        out_file.write_all(offset_half).unwrap();
        out_file.write_all(num_chunks).unwrap();
    }
    println!(
        "  Written {} bytes ({} queries x 28 bytes)",
        num_queries * 28,
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
    for (qi, (sh, offset_half, num_chunks)) in output_entries.iter().enumerate() {
        let hex: String = sh.iter().map(|x| format!("{:02x}", x)).collect();
        let offset = u32::from_le_bytes(*offset_half);
        let chunks = u32::from_le_bytes(*num_chunks);
        println!("  {:>4}  {}  {:>12}  {:>10}", qi, hex, offset, chunks);
    }

    println!();
    println!("  Total time: {:.2?}", start.elapsed());
}

/// Find the script_hash in the result's 4 slots and return (offset_half, num_chunks).
/// Index entry layout: [20B script_hash][4B offset_half][4B num_chunks]
fn find_entry_in_result(result: &[u8; RESULT_SIZE], script_hash: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    for slot in 0..SLOTS {
        let base = slot * ENTRY_SIZE;
        let entry_sh = &result[base..base + SCRIPT_HASH_SIZE];
        if entry_sh == script_hash {
            let mut offset_half = [0u8; 4];
            offset_half.copy_from_slice(&result[base + 20..base + 24]);
            let mut num_chunks = [0u8; 4];
            num_chunks.copy_from_slice(&result[base + 24..base + 28]);
            return Some((offset_half, num_chunks));
        }
    }
    None
}
