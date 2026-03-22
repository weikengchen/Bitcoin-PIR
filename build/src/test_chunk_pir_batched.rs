//! Chunk-level PIR test: executes the plan from gen_9_plan_chunk_rounds.
//!
//! Runs ROUNDS_PER_BATCH rounds with full DPF server simulation (bucket-major
//! parallelization), verifies correctness, then extrapolates the total time
//! for all rounds.
//!
//! Bucket-major: for each bucket, all rounds in the batch are processed
//! sequentially so the bucket's cuckoo table (~11MB) stays in L3 cache.
//! Parallelism is across the 80 buckets via rayon.
//!
//! Each PIR query retrieves a "unit" of CHUNKS_PER_UNIT consecutive 80-byte
//! chunks.  The cuckoo table stores individual chunk_ids; we query the first
//! chunk_id of each unit.
//!
//! Buckets not occupied by a real query in a given round still send a dummy
//! DPF request with fresh random targets (for privacy).
//!
//! Usage:
//!   cargo run --release -p build --bin gen_10b_test_chunk_pir_batched

mod common;

use common::*;
use libdpf::{Block, Dpf, DpfKey};
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::{self, File};
use std::time::Instant;

/// Each slot: [4B chunk_id LE | UNIT_DATA_SIZE data]
const SLOT_SIZE: usize = 4 + UNIT_DATA_SIZE;
const SLOTS: usize = CUCKOO_BUCKET_SIZE; // 4
const RESULT_SIZE: usize = SLOTS * SLOT_SIZE;

/// DPF domain: 2^20 = 1,048,576 >= bins_per_table
const DPF_N: u8 = 20;

const EMPTY: u32 = u32::MAX;

// ─── Plan file reader ───────────────────────────────────────────────────────

struct SpkInfo {
    _script_hash: [u8; SCRIPT_HASH_SIZE],
    start_chunk: u32,
    num_chunks: u32,
}

struct Plan {
    spks: Vec<SpkInfo>,
    rounds: Vec<Vec<(u32, u8)>>, // per round: Vec of (unit_start_chunk_id, bucket_id)
    total_placed: u32,
}

fn read_plan(path: &str) -> Plan {
    let data = fs::read(path).unwrap_or_else(|e| {
        eprintln!("Failed to read plan file: {}", e);
        std::process::exit(1);
    });

    let mut pos = 0usize;

    let magic = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    assert_eq!(magic, PLAN_MAGIC, "Bad plan magic");

    let num_spks = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let num_rounds = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    let total_placed = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
    pos += 4;

    let mut spks = Vec::with_capacity(num_spks);
    for _ in 0..num_spks {
        let mut sh = [0u8; SCRIPT_HASH_SIZE];
        sh.copy_from_slice(&data[pos..pos + SCRIPT_HASH_SIZE]);
        pos += SCRIPT_HASH_SIZE;
        let start_chunk = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let num_chunks = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        spks.push(SpkInfo {
            _script_hash: sh,
            start_chunk,
            num_chunks,
        });
    }

    let mut rounds = Vec::with_capacity(num_rounds);
    for _ in 0..num_rounds {
        let num_placed = data[pos] as usize;
        pos += 1;
        let mut entries = Vec::with_capacity(num_placed);
        for _ in 0..num_placed {
            let chunk_id = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            pos += 4;
            let bucket_id = data[pos];
            pos += 1;
            entries.push((chunk_id, bucket_id));
        }
        rounds.push(entries);
    }

    assert_eq!(pos, data.len(), "Plan file has trailing data");

    Plan { spks, rounds, total_placed }
}

// ─── DPF helpers ────────────────────────────────────────────────────────────

#[inline]
fn get_dpf_bit(block: &Block, bit_within_block: usize) -> bool {
    if bit_within_block < 64 {
        (block.low >> bit_within_block) & 1 == 1
    } else {
        (block.high >> (bit_within_block - 64)) & 1 == 1
    }
}

// ─── Server processing ─────────────────────────────────────────────────────

/// Fetch 4 slots at `bin`, dereferencing chunk_ids to [4B id | UNIT_DATA_SIZE data].
#[inline]
fn fetch_bin_entries(table_bytes: &[u8], bin: usize, chunks_data: &[u8], out: &mut [u8]) {
    let data_len = chunks_data.len();
    for slot in 0..SLOTS {
        let slot_offset = (bin * SLOTS + slot) * 4;
        let chunk_id = u32::from_le_bytes(
            table_bytes[slot_offset..slot_offset + 4].try_into().unwrap(),
        );
        if chunk_id != EMPTY {
            let dst = slot * SLOT_SIZE;
            out[dst..dst + 4].copy_from_slice(&chunk_id.to_le_bytes());
            let data_offset = chunk_id as usize * CHUNK_SIZE;
            let avail = data_len.saturating_sub(data_offset).min(UNIT_DATA_SIZE);
            if avail > 0 {
                out[dst + 4..dst + 4 + avail]
                    .copy_from_slice(&chunks_data[data_offset..data_offset + avail]);
            }
        }
    }
}

/// XOR src into dst using u64 chunks.
#[inline]
fn xor_into(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    let n = dst.len() / 8;
    let d = unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u64, n) };
    let s = unsafe { std::slice::from_raw_parts(src.as_ptr() as *const u64, n) };
    for i in 0..n {
        d[i] ^= s[i];
    }
}

/// Process one bucket across one round: eval two DPF keys, XOR-accumulate.
fn process_one_bucket_round(
    key_q0: &DpfKey,
    key_q1: &DpfKey,
    table_bytes: &[u8],
    chunks_data: &[u8],
    bins_per_table: usize,
) -> (Vec<u8>, Vec<u8>) {
    let dpf = Dpf::with_default_key();
    let eval0 = dpf.eval_full(key_q0);
    let eval1 = dpf.eval_full(key_q1);

    let num_blocks = eval0.len();
    let mut acc0 = vec![0u8; RESULT_SIZE];
    let mut acc1 = vec![0u8; RESULT_SIZE];
    let mut bin_buf = vec![0u8; RESULT_SIZE];

    for block_idx in 0..num_blocks {
        let blk0 = &eval0[block_idx];
        let blk1 = &eval1[block_idx];

        if blk0.is_equal(&Block::zero()) && blk1.is_equal(&Block::zero()) {
            continue;
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

            for v in bin_buf.iter_mut() {
                *v = 0;
            }
            fetch_bin_entries(table_bytes, bin, chunks_data, &mut bin_buf);

            if b0 {
                xor_into(&mut acc0, &bin_buf);
            }
            if b1 {
                xor_into(&mut acc1, &bin_buf);
            }
        }
    }

    (acc0, acc1)
}

/// Simple PRNG for dummy query targets.
struct DummyRng {
    state: u64,
}

impl DummyRng {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        Self { state: splitmix64(seed) }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        splitmix64(self.state)
    }
}

fn find_chunk_in_result(result: &[u8], chunk_id: u32) -> Option<&[u8]> {
    let target = chunk_id.to_le_bytes();
    for slot in 0..SLOTS {
        let base = slot * SLOT_SIZE;
        if result[base..base + 4] == target {
            return Some(&result[base + 4..base + SLOT_SIZE]);
        }
    }
    None
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() {
    println!("=== Chunk PIR Test (bucket-major, sample {} rounds) ===", ROUNDS_PER_BATCH);
    println!("  CHUNKS_PER_UNIT = {} ({} bytes/unit)", CHUNKS_PER_UNIT, UNIT_DATA_SIZE);
    println!("  SLOT_SIZE = {} bytes, RESULT_SIZE = {} bytes", SLOT_SIZE, RESULT_SIZE);
    println!();
    // ── 1. Load plan ─────────────────────────────────────────────────────
    println!("[1] Loading plan: {}", CHUNK_PIR_PLAN_FILE);
    let plan = read_plan(CHUNK_PIR_PLAN_FILE);
    let num_rounds = plan.rounds.len();
    let sample_rounds = ROUNDS_PER_BATCH.min(num_rounds);
    println!("  SPKs: {}", plan.spks.len());
    println!("  Total rounds in plan: {}", num_rounds);
    println!("  Rounds to run (sample): {}", sample_rounds);
    println!("  Total units placed: {}", plan.total_placed);
    println!();

    // ── 2. Load cuckoo table + chunks data ───────────────────────────────
    println!("[2] Loading data files...");
    let cuckoo_data = fs::read(CHUNK_CUCKOO_FILE).expect("read chunk cuckoo");
    let bins_per_table = read_chunk_cuckoo_header(&cuckoo_data);
    println!("  Chunk cuckoo: bins_per_table = {}", bins_per_table);

    let chunks_file = File::open(CHUNKS_DATA_FILE).expect("open chunks");
    let chunks_mmap = unsafe { Mmap::map(&chunks_file) }.expect("mmap chunks");
    let n_chunks = chunks_mmap.len() / CHUNK_SIZE;
    println!(
        "  Chunks data: {} chunks ({:.2} GB)",
        n_chunks,
        chunks_mmap.len() as f64 / (1024.0 * 1024.0 * 1024.0)
    );

    // Warmup: touch every page to bring data into OS page cache
    print!("  Warming up page cache...");
    let warmup_start = Instant::now();
    let page_size = 4096usize;
    let mut _sink: u8 = 0;
    // Touch cuckoo (already in memory via fs::read, but ensure hot in cache)
    for off in (0..cuckoo_data.len()).step_by(page_size) {
        _sink ^= cuckoo_data[off];
    }
    // Touch chunks mmap
    for off in (0..chunks_mmap.len()).step_by(page_size) {
        _sink ^= chunks_mmap[off];
    }
    // Prevent optimization from removing the loop
    std::hint::black_box(_sink);
    println!(" done in {:.2?}", warmup_start.elapsed());
    println!();

    // ── 3. Generate DPF keys for sample rounds ───────────────────────────
    println!("[3] Generating DPF keys for {} rounds × {} buckets...", sample_rounds, K_CHUNK);
    let keygen_start = Instant::now();

    let dpf = Dpf::with_default_key();
    let mut rng = DummyRng::new();

    let mut keys_s0: Vec<Vec<(DpfKey, DpfKey)>> = Vec::with_capacity(sample_rounds);
    let mut keys_s1: Vec<Vec<(DpfKey, DpfKey)>> = Vec::with_capacity(sample_rounds);

    for ri in 0..sample_rounds {
        let round_plan = &plan.rounds[ri];

        let mut bucket_targets: Vec<Option<(u64, u64)>> = vec![None; K_CHUNK];
        for &(chunk_id, bucket_id) in round_plan {
            let b = bucket_id as usize;
            let key0 = derive_chunk_cuckoo_key(b, 0);
            let key1 = derive_chunk_cuckoo_key(b, 1);
            let loc0 = cuckoo_hash_int(chunk_id, key0, bins_per_table) as u64;
            let loc1 = cuckoo_hash_int(chunk_id, key1, bins_per_table) as u64;
            bucket_targets[b] = Some((loc0, loc1));
        }

        let mut s0_round = Vec::with_capacity(K_CHUNK);
        let mut s1_round = Vec::with_capacity(K_CHUNK);

        for b in 0..K_CHUNK {
            let (alpha0, alpha1) = match bucket_targets[b] {
                Some(targets) => targets,
                None => {
                    let r0 = rng.next_u64() % bins_per_table as u64;
                    let r1 = rng.next_u64() % bins_per_table as u64;
                    (r0, r1)
                }
            };
            let (k0_q0, k1_q0) = dpf.gen(alpha0, DPF_N);
            let (k0_q1, k1_q1) = dpf.gen(alpha1, DPF_N);
            s0_round.push((k0_q0, k0_q1));
            s1_round.push((k1_q0, k1_q1));
        }

        keys_s0.push(s0_round);
        keys_s1.push(s1_round);
    }

    let dpf_key_wire_size = (DPF_N as usize + 2) * 16 + (DPF_N as usize + 7) / 8;
    let keygen_elapsed = keygen_start.elapsed();
    println!("  Key generation: {:.2?}", keygen_elapsed);
    println!("  DPF key wire size (est.): {} bytes", dpf_key_wire_size);
    println!();

    // ── 4. Server processing: bucket-major over sample rounds ────────────
    let slots_per_table = bins_per_table * SLOTS;
    let table_byte_size = slots_per_table * 4;

    println!("[4] Both servers: {} buckets × {} rounds (bucket-major, concurrent)...", K_CHUNK, sample_rounds);
    let servers_start = Instant::now();

    let (results_s0, results_s1) = rayon::join(
        || -> Vec<Vec<(Vec<u8>, Vec<u8>)>> {
            (0..K_CHUNK)
                .into_par_iter()
                .map(|bi| {
                    let table_offset = CHUNK_HEADER_SIZE + bi * table_byte_size;
                    let table_bytes = &cuckoo_data[table_offset..table_offset + table_byte_size];

                    (0..sample_rounds)
                        .map(|ri| {
                            process_one_bucket_round(
                                &keys_s0[ri][bi].0,
                                &keys_s0[ri][bi].1,
                                table_bytes,
                                &chunks_mmap,
                                bins_per_table,
                            )
                        })
                        .collect()
                })
                .collect()
        },
        || -> Vec<Vec<(Vec<u8>, Vec<u8>)>> {
            (0..K_CHUNK)
                .into_par_iter()
                .map(|bi| {
                    let table_offset = CHUNK_HEADER_SIZE + bi * table_byte_size;
                    let table_bytes = &cuckoo_data[table_offset..table_offset + table_byte_size];

                    (0..sample_rounds)
                        .map(|ri| {
                            process_one_bucket_round(
                                &keys_s1[ri][bi].0,
                                &keys_s1[ri][bi].1,
                                table_bytes,
                                &chunks_mmap,
                                bins_per_table,
                            )
                        })
                        .collect()
                })
                .collect()
        },
    );

    let servers_elapsed = servers_start.elapsed();
    println!("  Both servers done: {:.2?}", servers_elapsed);
    println!();

    // ── 5. Client: XOR and verify ────────────────────────────────────────
    println!("[6] Client: XOR and verify {} rounds...", sample_rounds);

    let mut unit_to_spk: std::collections::HashMap<u32, usize> =
        std::collections::HashMap::new();
    for (si, spk) in plan.spks.iter().enumerate() {
        let num_units = (spk.num_chunks as usize + CHUNKS_PER_UNIT - 1) / CHUNKS_PER_UNIT;
        for u in 0..num_units {
            let unit_start = spk.start_chunk + (u * CHUNKS_PER_UNIT) as u32;
            unit_to_spk.insert(unit_start, si);
        }
    }

    let mut total_found = 0usize;
    let mut total_mismatch = 0usize;
    let mut total_not_found = 0usize;

    for ri in 0..sample_rounds {
        let round_plan = &plan.rounds[ri];

        for &(chunk_id, bucket_id) in round_plan {
            let b = bucket_id as usize;

            let mut r0 = results_s0[b][ri].0.clone();
            xor_into(&mut r0, &results_s1[b][ri].0);

            let mut r1 = results_s0[b][ri].1.clone();
            xor_into(&mut r1, &results_s1[b][ri].1);

            let mut matched = false;
            for result in [&r0, &r1] {
                if let Some(data) = find_chunk_in_result(result, chunk_id) {
                    let data_offset = chunk_id as usize * CHUNK_SIZE;
                    let avail = chunks_mmap.len().saturating_sub(data_offset).min(UNIT_DATA_SIZE);
                    let actual = &chunks_mmap[data_offset..data_offset + avail];
                    if data[..avail] == *actual {
                        total_found += 1;
                    } else {
                        total_mismatch += 1;
                        eprintln!(
                            "  DATA MISMATCH: unit chunk {} round {} bucket {}",
                            chunk_id, ri + 1, b
                        );
                    }
                    matched = true;
                    break;
                }
            }

            if !matched {
                total_not_found += 1;
                if total_not_found <= 10 {
                    eprintln!(
                        "  MISS: unit chunk {} round {} bucket {}",
                        chunk_id, ri + 1, b
                    );
                }
            }
        }
    }

    let sample_units: usize = plan.rounds[..sample_rounds]
        .iter()
        .map(|r| r.len())
        .sum();

    println!(
        "  {} rounds: found {}/{}, miss {}, mismatch {}",
        sample_rounds, total_found, sample_units, total_not_found, total_mismatch
    );
    println!();

    // ── 6. Time estimates ────────────────────────────────────────────────
    let sample_ok = total_mismatch == 0 && total_not_found == 0;

    // Per-round times (averaged over sample)
    let keygen_per_round = keygen_elapsed.as_secs_f64() / sample_rounds as f64;
    let server_per_round = servers_elapsed.as_secs_f64() / sample_rounds as f64;
    let total_per_round = keygen_per_round + server_per_round;

    // Extrapolate to all rounds
    let est_keygen_all = keygen_per_round * num_rounds as f64;
    let est_server_all = server_per_round * num_rounds as f64;
    let est_total_all = total_per_round * num_rounds as f64;

    println!("=== Time Estimates ===");
    println!("  Sample: {} rounds", sample_rounds);
    println!();
    println!("  Per round:");
    println!("    Key generation:   {:.2} s", keygen_per_round);
    println!("    Server (both):    {:.2} s", server_per_round);
    println!("    Total:            {:.2} s", total_per_round);
    println!();
    println!("  Estimated for all {} rounds:", num_rounds);
    println!("    Key generation:   {:.1} s  ({:.1} min)", est_keygen_all, est_keygen_all / 60.0);
    println!("    Server (both):    {:.1} s  ({:.1} min)", est_server_all, est_server_all / 60.0);
    println!("    Total:            {:.1} s  ({:.1} min)", est_total_all, est_total_all / 60.0);

    // ── 7. Communication cost ────────────────────────────────────────────
    let keys_per_round_per_server = K_CHUNK * 2;
    let client_upload_per_round = keys_per_round_per_server * dpf_key_wire_size;
    let server_response_per_round = keys_per_round_per_server * RESULT_SIZE;

    let total_client_upload = num_rounds as u64 * 2 * client_upload_per_round as u64;
    let total_server_download = num_rounds as u64 * 2 * server_response_per_round as u64;
    let total_comm = total_client_upload + total_server_download;

    println!();
    println!("=== Communication Cost (chunk-level PIR, all {} rounds) ===", num_rounds);
    println!("  DPF key size (est.):           {} bytes (n={})", dpf_key_wire_size, DPF_N);
    println!("  Result size per bucket:        {} bytes ({}×{}B slots)", RESULT_SIZE, SLOTS, SLOT_SIZE);
    println!("  Buckets per round:             {}", K_CHUNK);
    println!("  Queries per bucket per round:  2 (q0, q1)");
    println!();
    println!("  Per round, per server:");
    println!("    Client → server:  {} keys × {}B = {:.1} KB",
        keys_per_round_per_server, dpf_key_wire_size,
        client_upload_per_round as f64 / 1024.0);
    println!("    Server → client:  {} results × {}B = {:.1} KB",
        keys_per_round_per_server, RESULT_SIZE,
        server_response_per_round as f64 / 1024.0);
    println!();
    println!("  Total across {} rounds × 2 servers:", num_rounds);
    println!("    Client upload:   {:.2} MB", total_client_upload as f64 / (1024.0 * 1024.0));
    println!("    Client download: {:.2} MB", total_server_download as f64 / (1024.0 * 1024.0));
    println!("    Total comm:      {:.2} MB", total_comm as f64 / (1024.0 * 1024.0));

    let total_payload = plan.total_placed as u64 * UNIT_DATA_SIZE as u64;
    println!();
    println!("  Useful payload retrieved:      {:.2} MB ({} units × {} bytes)",
        total_payload as f64 / (1024.0 * 1024.0),
        plan.total_placed, UNIT_DATA_SIZE);
    if total_comm > 0 {
        println!("  Communication overhead:        {:.1}× payload",
            total_comm as f64 / total_payload as f64);
    }

    // ── 8. Final verdict ─────────────────────────────────────────────────
    println!();
    if sample_ok {
        println!("  Sample {} rounds: ALL {} units verified OK!", sample_rounds, total_found);
    } else {
        println!("  Sample {} rounds: FAILURES detected!", sample_rounds);
        std::process::exit(1);
    }
}
