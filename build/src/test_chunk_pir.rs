//! End-to-end test for the chunk-level Batch PIR protocol.
//!
//! 1. Loads chunk_pir_cuckoo.bin and utxo_chunks_nodust.bin.
//! 2. Reads batch_pir_results.bin (first-level PIR output), computes the set
//!    of unique chunk_ids needed, and cuckoo-assigns them to 80 buckets.
//! 3. Generates DPF keys (2 per bucket: one per cuckoo hash fn).
//! 4. Runs server processing twice (one per server).
//! 5. XORs results, verifies each chunk matches the actual file data.
//!
//! Each cuckoo bin has 4 slots.  The server produces 84 bytes per slot:
//!   [4B chunk_id LE | 80B chunk_data]
//! so the result per bin = 4 × 84 = 336 bytes.
//!
//! Usage:
//!   cargo run --release -p build --bin test_chunk_pir

mod common;

use common::*;
use libdpf::{Block, Dpf, DpfKey};
use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;
use std::time::Instant;

/// Each slot: [4B chunk_id | 80B data] = 84 bytes
const SLOT_SIZE: usize = 4 + CHUNK_SIZE; // 84
const SLOTS: usize = CUCKOO_BUCKET_SIZE; // 4
const RESULT_SIZE: usize = SLOTS * SLOT_SIZE; // 336

/// 2^20 = 1,048,576 >= bins_per_table (~710K)
const DPF_N: u8 = 20;

const EMPTY: u32 = u32::MAX;

const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/chunk_pir_results.bin";

// ─── DPF bit extraction ─────────────────────────────────────────────────────

#[inline]
fn get_dpf_bit(block: &Block, bit_within_block: usize) -> bool {
    if bit_within_block < 64 {
        (block.low >> bit_within_block) & 1 == 1
    } else {
        (block.high >> (bit_within_block - 64)) & 1 == 1
    }
}

// ─── Server processing ──────────────────────────────────────────────────────

/// Fetch 4 slots at `bin` from the cuckoo table, dereferencing chunk_ids to
/// produce [4B chunk_id LE | 80B chunk_data] per slot.  EMPTY → 84 zero bytes.
#[inline]
fn fetch_bin_entries(
    table_bytes: &[u8],
    bin: usize,
    chunks_data: &[u8],
) -> [u8; RESULT_SIZE] {
    let mut out = [0u8; RESULT_SIZE];
    for slot in 0..SLOTS {
        let slot_offset = (bin * SLOTS + slot) * 4;
        let chunk_id = u32::from_le_bytes(
            table_bytes[slot_offset..slot_offset + 4]
                .try_into()
                .unwrap(),
        );
        if chunk_id != EMPTY {
            let dst = slot * SLOT_SIZE;
            // Write chunk_id (4 bytes LE)
            out[dst..dst + 4].copy_from_slice(&chunk_id.to_le_bytes());
            // Write chunk data (80 bytes)
            let data_offset = chunk_id as usize * CHUNK_SIZE;
            out[dst + 4..dst + SLOT_SIZE]
                .copy_from_slice(&chunks_data[data_offset..data_offset + CHUNK_SIZE]);
        }
    }
    out
}

/// Process one bucket: evaluate two DPF keys, scan the cuckoo table,
/// XOR-accumulate results.
fn process_bucket(
    dpf_result_0: &[Block],
    dpf_result_1: &[Block],
    table_bytes: &[u8],
    chunks_data: &[u8],
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

                    let bin_entries = fetch_bin_entries(table_bytes, bin, chunks_data);

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

/// XOR `src` into `dst` in-place using u64 chunks.
/// RESULT_SIZE = 336 = 42 * 8, so perfectly divisible.
#[inline]
fn xor_into(dst: &mut [u8; RESULT_SIZE], src: &[u8; RESULT_SIZE]) {
    const N: usize = RESULT_SIZE / 8; // 42
    let d = unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u64, N) };
    let s = unsafe { std::slice::from_raw_parts(src.as_ptr() as *const u64, N) };
    for i in 0..N {
        d[i] ^= s[i];
    }
}

/// Run the full server for all 80 buckets.
fn server_process(
    dpf_keys: &[(DpfKey, DpfKey)],
    cuckoo_data: &[u8],
    chunks_data: &[u8],
    bins_per_table: usize,
) -> Vec<([u8; RESULT_SIZE], [u8; RESULT_SIZE])> {
    let dpf = Dpf::with_default_key();
    let slots_per_table = bins_per_table * SLOTS;
    let table_byte_size = slots_per_table * 4;

    let mut results = Vec::with_capacity(K_CHUNK);

    for b in 0..K_CHUNK {
        let table_offset = CHUNK_HEADER_SIZE + b * table_byte_size;
        let table_bytes = &cuckoo_data[table_offset..table_offset + table_byte_size];

        let eval0 = dpf.eval_full(&dpf_keys[b].0);
        let eval1 = dpf.eval_full(&dpf_keys[b].1);

        let (r0, r1) = process_bucket(&eval0, &eval1, table_bytes, chunks_data, bins_per_table);
        results.push((r0, r1));

        eprint!("\r  Bucket {}/{}", b + 1, K_CHUNK);
    }
    eprintln!();

    results
}

// ─── Cuckoo assignment ──────────────────────────────────────────────────────

const MAX_KICKS: usize = 1000;

fn cuckoo_assign(
    candidates: &[[usize; NUM_HASHES]],
) -> Result<[Option<usize>; K_CHUNK], &'static str> {
    let mut buckets: [Option<usize>; K_CHUNK] = [None; K_CHUNK];
    let num = candidates.len();

    for i in 0..num {
        if !pbc_cuckoo_place(candidates, &mut buckets, i, MAX_KICKS, NUM_HASHES) {
            return Err("Cuckoo assignment failed");
        }
    }
    Ok(buckets)
}

// ─── Find chunk in result ───────────────────────────────────────────────────

/// Scan the 4 slots in a result for a matching chunk_id.
/// Returns a reference to the 80-byte chunk data if found.
fn find_chunk_in_result(result: &[u8; RESULT_SIZE], chunk_id: u32) -> Option<Vec<u8>> {
    let target = chunk_id.to_le_bytes();
    for slot in 0..SLOTS {
        let base = slot * SLOT_SIZE;
        if result[base..base + 4] == target {
            return Some(result[base + 4..base + SLOT_SIZE].to_vec());
        }
    }
    None
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() {
    println!("=== Chunk-level Batch PIR End-to-End Test ===");
    println!();
    let start = Instant::now();

    // ── 1. Load data ─────────────────────────────────────────────────────
    println!("[1] Loading data files...");

    let chunks_file = File::open(CHUNKS_DATA_FILE).expect("open chunks");
    let chunks_mmap = unsafe { Mmap::map(&chunks_file) }.expect("mmap chunks");
    let n_chunks = chunks_mmap.len() / CHUNK_SIZE;
    println!(
        "  Chunks: {} ({:.2} GB)",
        n_chunks,
        chunks_mmap.len() as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    let cuckoo_data = fs::read(CHUNK_CUCKOO_FILE).expect("read chunk cuckoo file");
    let bins_per_table = read_chunk_cuckoo_header(&cuckoo_data);
    println!("  Chunk cuckoo: bins_per_table = {}", bins_per_table);

    let results_data = fs::read(BATCH_PIR_RESULTS_FILE).expect("read batch pir results");
    let num_first_queries = results_data.len() / INDEX_ENTRY_SIZE;
    println!("  First-level results: {} queries", num_first_queries);
    println!();

    // ── 2. Compute unique chunk_ids from first-level results ─────────────
    println!("[2] Computing chunk queries from first-level results...");

    let mut all_chunk_ids = BTreeSet::new();
    let mut query_ranges: Vec<(u32, u32)> = Vec::with_capacity(num_first_queries); // (start_chunk, num_chunks)

    for i in 0..num_first_queries {
        let base = i * INDEX_ENTRY_SIZE;
        let start_chunk = u32::from_le_bytes(
            results_data[base + 20..base + 24].try_into().unwrap(),
        );
        let num_chunks = results_data[base + 24] as u32;

        if num_chunks == 0 {
            query_ranges.push((0, 0));
            continue;
        }
        query_ranges.push((start_chunk, num_chunks));

        for c in 0..num_chunks {
            all_chunk_ids.insert(start_chunk + c);
        }
    }

    let chunk_queries: Vec<u32> = all_chunk_ids.into_iter().collect();
    let num_chunk_queries = chunk_queries.len();
    println!("  Unique chunk queries: {}", num_chunk_queries);
    println!();

    // ── 3. Cuckoo-assign chunk queries to buckets ────────────────────────
    println!(
        "[3] Cuckoo-assigning {} chunk queries to {} buckets...",
        num_chunk_queries, K_CHUNK
    );

    let candidates: Vec<[usize; NUM_HASHES]> = chunk_queries
        .iter()
        .map(|&cid| derive_chunk_buckets(cid))
        .collect();

    let bucket_assignment = cuckoo_assign(&candidates).expect("chunk cuckoo assign");
    println!("  All chunk queries placed.");

    // Build: chunk_query_idx → assigned_bucket
    let mut query_bucket = vec![0usize; num_chunk_queries];
    for (b, slot) in bucket_assignment.iter().enumerate() {
        if let Some(qi) = slot {
            query_bucket[*qi] = b;
        }
    }

    // Compute loc0, loc1 for each chunk query
    let mut query_locs: Vec<(usize, usize)> = Vec::with_capacity(num_chunk_queries);
    for (i, &chunk_id) in chunk_queries.iter().enumerate() {
        let b = query_bucket[i];
        let key0 = derive_chunk_cuckoo_key(b, 0);
        let key1 = derive_chunk_cuckoo_key(b, 1);
        let loc0 = cuckoo_hash_int(chunk_id, key0, bins_per_table);
        let loc1 = cuckoo_hash_int(chunk_id, key1, bins_per_table);
        query_locs.push((loc0, loc1));
    }
    println!();

    // ── 4. Generate DPF keys ─────────────────────────────────────────────
    println!(
        "[4] Generating DPF keys (n={}, domain=2^{} = {})...",
        DPF_N, DPF_N, 1u64 << DPF_N
    );
    let dpf = Dpf::with_default_key();
    let gen_start = Instant::now();

    let mut server0_keys: Vec<(DpfKey, DpfKey)> = Vec::with_capacity(K_CHUNK);
    let mut server1_keys: Vec<(DpfKey, DpfKey)> = Vec::with_capacity(K_CHUNK);

    for b in 0..K_CHUNK {
        let (alpha_q0, alpha_q1) = if let Some(qi) = bucket_assignment[b] {
            (query_locs[qi].0 as u64, query_locs[qi].1 as u64)
        } else {
            (0u64, 0u64)
        };

        let (k0_q0, k1_q0) = dpf.gen(alpha_q0, DPF_N);
        let (k0_q1, k1_q1) = dpf.gen(alpha_q1, DPF_N);

        server0_keys.push((k0_q0, k0_q1));
        server1_keys.push((k1_q0, k1_q1));
    }

    println!("  Generated {} key pairs in {:.2?}", K_CHUNK * 2, gen_start.elapsed());
    println!();

    // ── 5. Server 0 processing ───────────────────────────────────────────
    println!("[5] Server 0 processing...");
    let s0_start = Instant::now();
    let server0_results =
        server_process(&server0_keys, &cuckoo_data, &chunks_mmap, bins_per_table);
    println!("  Done in {:.2?}", s0_start.elapsed());

    // ── 6. Server 1 processing ───────────────────────────────────────────
    println!("[6] Server 1 processing...");
    let s1_start = Instant::now();
    let server1_results =
        server_process(&server1_keys, &cuckoo_data, &chunks_mmap, bins_per_table);
    println!("  Done in {:.2?}", s1_start.elapsed());
    println!();

    // ── 7. Client: XOR, verify, extract ──────────────────────────────────
    println!("[7] Client: XOR server results, verify chunk data...");
    let mut found = 0usize;
    let mut not_found = 0usize;
    let mut data_mismatch = 0usize;

    // Build chunk_id → index into chunk_queries
    let mut chunk_id_to_qi: std::collections::HashMap<u32, usize> =
        std::collections::HashMap::with_capacity(num_chunk_queries);
    for (i, &cid) in chunk_queries.iter().enumerate() {
        chunk_id_to_qi.insert(cid, i);
    }

    // Recovered chunk data: chunk_id → 80 bytes
    let mut recovered_chunks: std::collections::HashMap<u32, Vec<u8>> =
        std::collections::HashMap::with_capacity(num_chunk_queries);

    for (qi, &chunk_id) in chunk_queries.iter().enumerate() {
        let b = query_bucket[qi];
        let (loc0, loc1) = query_locs[qi];

        // XOR server results for query q0 (loc0)
        let mut result_q0 = server0_results[b].0;
        xor_into(&mut result_q0, &server1_results[b].0);

        // XOR server results for query q1 (loc1)
        let mut result_q1 = server0_results[b].1;
        xor_into(&mut result_q1, &server1_results[b].1);

        // Try to find our chunk_id in either result
        let mut matched = false;
        for result in [&result_q0, &result_q1] {
            if let Some(data) = find_chunk_in_result(result, chunk_id) {
                // Verify against actual file data
                let actual_offset = chunk_id as usize * CHUNK_SIZE;
                let actual = &chunks_mmap[actual_offset..actual_offset + CHUNK_SIZE];
                if data == actual {
                    found += 1;
                } else {
                    data_mismatch += 1;
                    eprintln!(
                        "  DATA MISMATCH: chunk {} bucket {} loc0={} loc1={}",
                        chunk_id, b, loc0, loc1
                    );
                }
                recovered_chunks.insert(chunk_id, data);
                matched = true;
                break;
            }
        }

        if !matched {
            not_found += 1;
            eprintln!(
                "  MISS: chunk {} bucket {} loc0={} loc1={}",
                chunk_id, b, loc0, loc1
            );
        }
    }

    println!();
    println!("=== Chunk Query Results ===");
    println!("  Found (correct):  {} / {}", found, num_chunk_queries);
    println!("  Data mismatch:    {} / {}", data_mismatch, num_chunk_queries);
    println!("  Not found:        {} / {}", not_found, num_chunk_queries);
    if not_found == 0 && data_mismatch == 0 {
        println!("  ✓ All {} chunk queries recovered and verified!", num_chunk_queries);
    } else {
        println!("  ✗ {} queries failed", not_found + data_mismatch);
    }

    // ── 8. Write recovered chunks to output ──────────────────────────────
    println!();
    println!("[8] Writing recovered chunks to: {}", OUTPUT_FILE);

    // File format: for each first-level query, write all its chunks contiguously
    // Header: [4B num_first_queries]
    // Per query: [4B start_chunk][4B num_chunks][num_chunks × 80B data]
    let mut out_file = File::create(OUTPUT_FILE).expect("create output");
    out_file
        .write_all(&(num_first_queries as u32).to_le_bytes())
        .unwrap();

    let mut total_bytes_written = 4usize;

    for i in 0..num_first_queries {
        let (start_chunk, nc) = query_ranges[i];
        out_file.write_all(&start_chunk.to_le_bytes()).unwrap();
        out_file.write_all(&nc.to_le_bytes()).unwrap();
        total_bytes_written += 8;

        for c in 0..nc {
            let cid = start_chunk + c;
            if let Some(data) = recovered_chunks.get(&cid) {
                out_file.write_all(data).unwrap();
            } else {
                // Write zeros for missing chunks
                out_file.write_all(&[0u8; CHUNK_SIZE]).unwrap();
            }
            total_bytes_written += CHUNK_SIZE;
        }
    }

    println!(
        "  Written {} bytes ({:.2} KB)",
        total_bytes_written,
        total_bytes_written as f64 / 1024.0
    );

    // ── 9. Display per-query summary ─────────────────────────────────────
    println!();
    println!("[9] Per-query chunk recovery summary:");
    println!(
        "  {:>4}  {:>42}  {:>12}  {:>8}  {:>10}",
        "#", "Script Hash", "Start Chunk", "Chunks", "Status"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "-".repeat(4),
        "-".repeat(42),
        "-".repeat(12),
        "-".repeat(8),
        "-".repeat(10)
    );

    for i in 0..num_first_queries {
        let sh = &results_data[i * INDEX_ENTRY_SIZE..i * INDEX_ENTRY_SIZE + SCRIPT_HASH_SIZE];
        let hex: String = sh.iter().map(|b| format!("{:02x}", b)).collect();
        let (start_chunk, nc) = query_ranges[i];

        if nc == 0 {
            let label = "no chunks (whale or miss)";
            println!(
                "  {:>4}  {}  {:>12}  {:>8}  {}",
                i, hex, "-", "-", label
            );
            continue;
        }

        // Check if all chunks for this query were recovered
        let mut all_ok = true;
        for c in 0..nc {
            if !recovered_chunks.contains_key(&(start_chunk + c)) {
                all_ok = false;
                break;
            }
        }

        println!(
            "  {:>4}  {}  {:>12}  {:>8}  {}",
            i,
            hex,
            start_chunk,
            nc,
            if all_ok { "✓ OK" } else { "✗ INCOMPLETE" }
        );
    }

    println!();
    println!("  Total time: {:.2?}", start.elapsed());
}
