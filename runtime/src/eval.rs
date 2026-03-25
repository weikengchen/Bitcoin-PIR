//! DPF evaluation for both index-level and chunk-level PIR.
//!
//! Ported from build test_batch_pir.rs and test_chunk_pir_batched.rs.

use build::common::*;
use libdpf::{Block, Dpf, DpfKey};
use std::time::{Duration, Instant};

// ─── Software prefetch intrinsics ────────────────────────────────────────────

/// Prefetch a memory address into the CPU cache for reading.
/// Uses `_mm_prefetch` on x86_64, no-op on other architectures.
#[inline(always)]
fn prefetch_read(ptr: *const u8) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::x86_64::_mm_prefetch(ptr as *const i8, std::arch::x86_64::_MM_HINT_T0);
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = ptr;
    }
}

/// DPF domain for index level: 2^20 = 1,048,576 >= 753,707 index bins.
pub const DPF_N: u8 = 20;

/// DPF domain for chunk level: 2^21 = 2,097,152 >= 1,286,191 chunk bins.
pub const CHUNK_DPF_N: u8 = 21;

// ─── Index-level constants ──────────────────────────────────────────────────

/// Each cuckoo bin has CUCKOO_BUCKET_SIZE (3) slots, each INDEX_SLOT_SIZE (13) bytes.
pub const INDEX_SLOTS: usize = CUCKOO_BUCKET_SIZE; // 3
pub const INDEX_RESULT_SIZE: usize = INDEX_SLOTS * INDEX_SLOT_SIZE; // 3 * 13 = 39

// ─── Chunk-level constants ──────────────────────────────────────────────────

/// Each slot: [4B chunk_id LE | UNIT_DATA_SIZE data]
pub const CHUNK_SLOT_SIZE: usize = 4 + UNIT_DATA_SIZE;
pub const CHUNK_SLOTS: usize = CHUNK_CUCKOO_BUCKET_SIZE; // 3
pub const CHUNK_RESULT_SIZE: usize = CHUNK_SLOTS * CHUNK_SLOT_SIZE;

// ─── DPF bit extraction ────────────────────────────────────────────────────

#[inline]
fn get_dpf_bit(block: &Block, bit_within_block: usize) -> bool {
    if bit_within_block < 64 {
        (block.low >> bit_within_block) & 1 == 1
    } else {
        (block.high >> (bit_within_block - 64)) & 1 == 1
    }
}

/// XOR src into dst using u64 chunks.
#[inline]
pub fn xor_into(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    let n = dst.len() / 8;
    let d = unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr() as *mut u64, n) };
    let s = unsafe { std::slice::from_raw_parts(src.as_ptr() as *const u64, n) };
    for i in 0..n {
        d[i] ^= s[i];
    }
    // Handle remaining bytes
    for i in (n * 8)..dst.len() {
        dst[i] ^= src[i];
    }
}

// ─── Generic DPF evaluation (supports N queries) ──────────────────────────

/// Lookahead distance for software prefetching (in bins).
/// Issue prefetch for bin N+LOOKAHEAD while processing bin N.
const PREFETCH_LOOKAHEAD: usize = 4;

/// Per-bucket timing breakdown.
pub struct BucketTiming {
    pub dpf_eval: Duration,
    pub fetch_xor: Duration,
}

/// Evaluate N DPF keys over a table, XOR-accumulating results.
/// Returns Vec of N accumulators, each `result_size` bytes, plus timing.
/// `prefetch_bin` is an optional callback to prefetch data for an upcoming bin.
fn process_bucket_generic(
    keys: &[&DpfKey],
    table_bytes: &[u8],
    bins_per_table: usize,
    result_size: usize,
    fetch_bin: &dyn Fn(&[u8], usize, &mut [u8]),
    prefetch_bin: Option<&dyn Fn(&[u8], usize)>,
) -> (Vec<Vec<u8>>, BucketTiming) {
    let dpf = Dpf::with_default_key();
    let num_keys = keys.len();

    let t_dpf = Instant::now();
    let evals: Vec<Vec<Block>> = keys.iter().map(|k| dpf.eval_partial(k, bins_per_table as u64)).collect();
    let dpf_eval = t_dpf.elapsed();

    let num_blocks = evals[0].len();

    let t_fetch = Instant::now();
    let mut accs: Vec<Vec<u8>> = (0..num_keys).map(|_| vec![0u8; result_size]).collect();
    let mut bin_buf = vec![0u8; result_size];

    for block_idx in 0..num_blocks {
        // Skip if all blocks are zero
        let all_zero = (0..num_keys).all(|i| evals[i][block_idx].is_equal(&Block::zero()));
        if all_zero {
            continue;
        }

        let base_bin = block_idx * 128;
        let end_bin = (base_bin + 128).min(bins_per_table);

        for bin in base_bin..end_bin {
            let bit_within = bin - base_bin;

            // Software prefetch: issue read for a future bin's data
            if let Some(pf) = prefetch_bin {
                let ahead = bin + PREFETCH_LOOKAHEAD;
                if ahead < end_bin {
                    pf(table_bytes, ahead);
                }
            }

            // Check which keys have bit set
            let mut any_set = false;
            let mut bits = [false; 8]; // max 8 keys
            for i in 0..num_keys {
                bits[i] = get_dpf_bit(&evals[i][block_idx], bit_within);
                if bits[i] { any_set = true; }
            }

            if !any_set {
                continue;
            }

            for v in bin_buf.iter_mut() { *v = 0; }
            fetch_bin(table_bytes, bin, &mut bin_buf);

            for i in 0..num_keys {
                if bits[i] {
                    xor_into(&mut accs[i], &bin_buf);
                }
            }
        }
    }
    let fetch_xor = t_fetch.elapsed();

    (accs, BucketTiming { dpf_eval, fetch_xor })
}

// ─── Index-level evaluation (inlined cuckoo tables) ─────────────────────────

/// Fetch INDEX_SLOTS inlined index entries at `bin` directly from the table.
/// Each slot is INDEX_SLOT_SIZE (13) bytes, stored contiguously.
#[inline]
fn fetch_index_bin(table_bytes: &[u8], bin: usize, out: &mut [u8]) {
    let src_offset = bin * INDEX_RESULT_SIZE;
    out.copy_from_slice(&table_bytes[src_offset..src_offset + INDEX_RESULT_SIZE]);
}

/// Process one index-level bucket: evaluate two DPF keys, XOR-accumulate.
/// Returns (result_q0, result_q1, timing).
pub fn process_index_bucket(
    key_q0: &DpfKey,
    key_q1: &DpfKey,
    table_bytes: &[u8],
    bins_per_table: usize,
) -> (Vec<u8>, Vec<u8>, BucketTiming) {
    let (results, timing) = process_bucket_generic(
        &[key_q0, key_q1],
        table_bytes,
        bins_per_table,
        INDEX_RESULT_SIZE,
        &|tbl, bin, out| fetch_index_bin(tbl, bin, out),
        None,
    );
    (results[0].clone(), results[1].clone(), timing)
}

// ─── Chunk-level evaluation (inlined cuckoo tables) ─────────────────────────

/// Prefetch inlined chunk data for a future bin so it's in cache when we need it.
#[inline]
fn prefetch_chunk_bin(table_bytes: &[u8], bin: usize) {
    let src_offset = bin * CHUNK_RESULT_SIZE;
    if src_offset < table_bytes.len() {
        prefetch_read(table_bytes[src_offset..].as_ptr());
    }
}

/// Fetch CHUNK_SLOTS inlined slots at `bin` directly from the table.
/// Each slot is CHUNK_SLOT_SIZE (44) bytes: [4B chunk_id | 40B data], stored contiguously.
#[inline]
fn fetch_chunk_bin(table_bytes: &[u8], bin: usize, out: &mut [u8]) {
    let src_offset = bin * CHUNK_RESULT_SIZE;
    out.copy_from_slice(&table_bytes[src_offset..src_offset + CHUNK_RESULT_SIZE]);
}

/// Process one chunk-level bucket: evaluate CHUNK_CUCKOO_NUM_HASHES (2) DPF keys, XOR-accumulate.
/// Returns Vec of 2 results, each CHUNK_RESULT_SIZE bytes, plus timing.
pub fn process_chunk_bucket(
    keys: &[&DpfKey],
    table_bytes: &[u8],
    bins_per_table: usize,
) -> (Vec<Vec<u8>>, BucketTiming) {
    process_bucket_generic(
        keys,
        table_bytes,
        bins_per_table,
        CHUNK_RESULT_SIZE,
        &|tbl, bin, out| fetch_chunk_bin(tbl, bin, out),
        Some(&|tbl, bin| prefetch_chunk_bin(tbl, bin)),
    )
}

// ─── Result parsing helpers (client-side) ───────────────────────────────────

/// Find a matching tag in an index-level result's slots.
/// `expected_tag` is the 8-byte fingerprint computed by the client.
/// Returns (start_chunk_id, num_chunks) if found.
pub fn find_entry_in_index_result(result: &[u8], expected_tag: u64) -> Option<(u32, u32)> {
    for slot in 0..INDEX_SLOTS {
        let base = slot * INDEX_SLOT_SIZE;
        let slot_tag = u64::from_le_bytes(result[base..base + TAG_SIZE].try_into().unwrap());
        if slot_tag == expected_tag {
            let start_chunk_id = u32::from_le_bytes(
                result[base + TAG_SIZE..base + TAG_SIZE + 4].try_into().unwrap(),
            );
            let num_chunks = result[base + TAG_SIZE + 4] as u32;
            return Some((start_chunk_id, num_chunks));
        }
    }
    None
}

/// Find a chunk_id in a chunk-level result's slots.
/// Returns the UNIT_DATA_SIZE data if found.
pub fn find_chunk_in_result(result: &[u8], chunk_id: u32) -> Option<&[u8]> {
    let target = chunk_id.to_le_bytes();
    for slot in 0..CHUNK_SLOTS {
        let base = slot * CHUNK_SLOT_SIZE;
        if result[base..base + 4] == target {
            return Some(&result[base + 4..base + CHUNK_SLOT_SIZE]);
        }
    }
    None
}
