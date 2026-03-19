//! DPF evaluation for both index-level and chunk-level PIR.
//!
//! Ported from build_batchdb test_batch_pir.rs and test_chunk_pir_batched.rs.

use build_batchdb::common::*;
use libdpf::{Block, Dpf, DpfKey};

/// DPF domain: 2^20 = 1,048,576 >= bins_per_table for both levels.
pub const DPF_N: u8 = 20;

// ─── Index-level constants ──────────────────────────────────────────────────

/// Each cuckoo bin has 4 slots, each referencing a 28-byte index entry.
pub const INDEX_SLOTS: usize = CUCKOO_BUCKET_SIZE; // 4
pub const INDEX_RESULT_SIZE: usize = INDEX_SLOTS * INDEX_ENTRY_SIZE; // 4 * 28 = 112

// ─── Chunk-level constants ──────────────────────────────────────────────────

/// Each slot: [4B chunk_id LE | UNIT_DATA_SIZE data]
pub const CHUNK_SLOT_SIZE: usize = 4 + UNIT_DATA_SIZE;
pub const CHUNK_SLOTS: usize = CUCKOO_BUCKET_SIZE; // 4
pub const CHUNK_RESULT_SIZE: usize = CHUNK_SLOTS * CHUNK_SLOT_SIZE;

const EMPTY: u32 = u32::MAX;

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

// ─── Index-level evaluation ─────────────────────────────────────────────────

/// Fetch 4 index entries at `bin`, resolving u32 refs through the index data.
#[inline]
fn fetch_index_bin(table_bytes: &[u8], bin: usize, index_data: &[u8], out: &mut [u8]) {
    for slot in 0..INDEX_SLOTS {
        let slot_offset = (bin * INDEX_SLOTS + slot) * 4;
        let ref_u32 = u32::from_le_bytes(
            table_bytes[slot_offset..slot_offset + 4].try_into().unwrap(),
        );
        if ref_u32 != EMPTY {
            let entry_offset = ref_u32 as usize * INDEX_ENTRY_SIZE;
            let dst = slot * INDEX_ENTRY_SIZE;
            out[dst..dst + INDEX_ENTRY_SIZE]
                .copy_from_slice(&index_data[entry_offset..entry_offset + INDEX_ENTRY_SIZE]);
        }
    }
}

/// Process one index-level bucket: evaluate two DPF keys, XOR-accumulate.
///
/// Returns (result_q0, result_q1), each INDEX_RESULT_SIZE bytes.
pub fn process_index_bucket(
    key_q0: &DpfKey,
    key_q1: &DpfKey,
    table_bytes: &[u8],
    index_data: &[u8],
    bins_per_table: usize,
) -> (Vec<u8>, Vec<u8>) {
    let dpf = Dpf::with_default_key();
    let eval0 = dpf.eval_full(key_q0);
    let eval1 = dpf.eval_full(key_q1);

    let num_blocks = eval0.len();
    let mut acc0 = vec![0u8; INDEX_RESULT_SIZE];
    let mut acc1 = vec![0u8; INDEX_RESULT_SIZE];
    let mut bin_buf = vec![0u8; INDEX_RESULT_SIZE];

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
            fetch_index_bin(table_bytes, bin, index_data, &mut bin_buf);

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

// ─── Chunk-level evaluation ─────────────────────────────────────────────────

/// Fetch 4 slots at `bin`, dereferencing chunk_ids to [4B id | UNIT_DATA_SIZE data].
#[inline]
fn fetch_chunk_bin(table_bytes: &[u8], bin: usize, chunks_data: &[u8], out: &mut [u8]) {
    let data_len = chunks_data.len();
    for slot in 0..CHUNK_SLOTS {
        let slot_offset = (bin * CHUNK_SLOTS + slot) * 4;
        let chunk_id = u32::from_le_bytes(
            table_bytes[slot_offset..slot_offset + 4].try_into().unwrap(),
        );
        if chunk_id != EMPTY {
            let dst = slot * CHUNK_SLOT_SIZE;
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

/// Process one chunk-level bucket: evaluate two DPF keys, XOR-accumulate.
///
/// Returns (result_q0, result_q1), each CHUNK_RESULT_SIZE bytes.
pub fn process_chunk_bucket(
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
    let mut acc0 = vec![0u8; CHUNK_RESULT_SIZE];
    let mut acc1 = vec![0u8; CHUNK_RESULT_SIZE];
    let mut bin_buf = vec![0u8; CHUNK_RESULT_SIZE];

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
            fetch_chunk_bin(table_bytes, bin, chunks_data, &mut bin_buf);

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

// ─── Result parsing helpers (client-side) ───────────────────────────────────

/// Find a script_hash in an index-level result's 4 slots.
/// Returns (offset_half, num_chunks) if found.
pub fn find_entry_in_index_result(result: &[u8], script_hash: &[u8]) -> Option<(u32, u32)> {
    for slot in 0..INDEX_SLOTS {
        let base = slot * INDEX_ENTRY_SIZE;
        if result[base..base + SCRIPT_HASH_SIZE] == *script_hash {
            let offset_half = u32::from_le_bytes(
                result[base + 20..base + 24].try_into().unwrap(),
            );
            let num_chunks = u32::from_le_bytes(
                result[base + 24..base + 28].try_into().unwrap(),
            );
            return Some((offset_half, num_chunks));
        }
    }
    None
}

/// Find a chunk_id in a chunk-level result's 4 slots.
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
