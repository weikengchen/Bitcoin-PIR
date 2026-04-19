//! DPF evaluation for both index-level and chunk-level PIR.
//!
//! Ported from build test_batch_pir.rs and test_chunk_pir_batched.rs.

use libdpf::{Block, Dpf, DpfKey};
use pir_core::params::{
    CHUNK_SLOTS_PER_BIN, INDEX_SLOTS_PER_BIN, INDEX_SLOT_SIZE, TAG_SIZE, UNIT_DATA_SIZE,
};
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

/// DPF domain for index level (legacy constant for the main UTXO database).
/// New code should use `pir_core::params::compute_dpf_n(bins_per_table)` instead.
pub const DPF_N: u8 = 20;

/// DPF domain for chunk level (legacy constant for the main UTXO database).
/// New code should use `pir_core::params::compute_dpf_n(bins_per_table)` instead.
pub const CHUNK_DPF_N: u8 = 21;

// ─── Index-level constants ──────────────────────────────────────────────────

/// Each cuckoo bin has INDEX_SLOTS_PER_BIN (4) slots, each INDEX_SLOT_SIZE (13) bytes.
pub const INDEX_SLOTS: usize = INDEX_SLOTS_PER_BIN; // 4
pub const INDEX_RESULT_SIZE: usize = INDEX_SLOTS * INDEX_SLOT_SIZE; // 4 * 13 = 52

// ─── Chunk-level constants ──────────────────────────────────────────────────

/// Each slot: [4B chunk_id LE | UNIT_DATA_SIZE data]
pub const CHUNK_SLOT_SIZE: usize = 4 + UNIT_DATA_SIZE;
pub const CHUNK_SLOTS: usize = CHUNK_SLOTS_PER_BIN; // 3
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

/// Per-group timing breakdown.
pub struct GroupTiming {
    pub dpf_eval: Duration,
    pub fetch_xor: Duration,
}

/// Evaluate N DPF keys over a table, XOR-accumulating results.
/// Returns Vec of N accumulators, each `result_size` bytes, plus timing.
/// `prefetch_bin` is an optional callback to prefetch data for an upcoming bin.
fn process_group_generic(
    keys: &[&DpfKey],
    table_bytes: &[u8],
    bins_per_table: usize,
    result_size: usize,
    fetch_bin: &dyn Fn(&[u8], usize, &mut [u8]),
    prefetch_bin: Option<&dyn Fn(&[u8], usize)>,
) -> (Vec<Vec<u8>>, GroupTiming) {
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

    (accs, GroupTiming { dpf_eval, fetch_xor })
}

// ─── Index-level evaluation (inlined cuckoo tables) ─────────────────────────

/// Fetch INDEX_SLOTS inlined index entries at `bin` directly from the table.
/// Each slot is INDEX_SLOT_SIZE (17) bytes, stored contiguously.
#[inline]
fn fetch_index_bin(table_bytes: &[u8], bin: usize, out: &mut [u8]) {
    let src_offset = bin * INDEX_RESULT_SIZE;
    out.copy_from_slice(&table_bytes[src_offset..src_offset + INDEX_RESULT_SIZE]);
}

/// Process one index-level group: evaluate two DPF keys, XOR-accumulate.
/// Returns (result_q0, result_q1, timing).
pub fn process_index_group(
    key_q0: &DpfKey,
    key_q1: &DpfKey,
    table_bytes: &[u8],
    bins_per_table: usize,
) -> (Vec<u8>, Vec<u8>, GroupTiming) {
    let (results, timing) = process_group_generic(
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

/// Process one chunk-level group: evaluate CHUNK_CUCKOO_NUM_HASHES (2) DPF keys, XOR-accumulate.
/// Returns Vec of 2 results, each CHUNK_RESULT_SIZE bytes, plus timing.
pub fn process_chunk_group(
    keys: &[&DpfKey],
    table_bytes: &[u8],
    bins_per_table: usize,
) -> (Vec<Vec<u8>>, GroupTiming) {
    process_group_generic(
        keys,
        table_bytes,
        bins_per_table,
        CHUNK_RESULT_SIZE,
        &|tbl, bin, out| fetch_chunk_bin(tbl, bin, out),
        Some(&|tbl, bin| prefetch_chunk_bin(tbl, bin)),
    )
}

// ─── Merkle sibling evaluation ────────────────────────────────────────────

/// Process one Merkle sibling group: evaluate 2 DPF keys, XOR-accumulate.
/// `result_size` = slots_per_bin × slot_size (e.g. 4 × 260 = 1040 for arity=8).
pub fn process_merkle_sibling_group(
    keys: &[&DpfKey],
    table_bytes: &[u8],
    bins_per_table: usize,
    result_size: usize,
) -> (Vec<Vec<u8>>, GroupTiming) {
    process_group_generic(
        keys,
        table_bytes,
        bins_per_table,
        result_size,
        &|tbl, bin, out| {
            let src = bin * result_size;
            out.copy_from_slice(&tbl[src..src + result_size]);
        },
        None,
    )
}

/// Find a group_id in a Merkle sibling result's slots.
///
/// Each slot: [4B group_id LE][arity × 32B child hashes].
/// Returns the arity child hashes as a flat byte slice if found.
pub fn find_group_in_sibling_result(
    result: &[u8],
    group_id: u32,
    arity: usize,
    slots_per_bin: usize,
) -> Option<Vec<[u8; 32]>> {
    let slot_size = 4 + arity * 32;
    let target = group_id.to_le_bytes();
    for slot in 0..slots_per_bin {
        let base = slot * slot_size;
        if base + 4 > result.len() { break; }
        if result[base..base + 4] == target {
            let mut children = Vec::with_capacity(arity);
            for c in 0..arity {
                let off = base + 4 + c * 32;
                let mut h = [0u8; 32];
                h.copy_from_slice(&result[off..off + 32]);
                children.push(h);
            }
            return Some(children);
        }
    }
    None
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
