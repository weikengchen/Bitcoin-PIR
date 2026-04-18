//! Generic cuckoo table building utilities.
//!
//! Provides the core cuckoo insertion algorithm used by both INDEX and CHUNK
//! level table builders, parameterized by `TableParams`.

use crate::hash;
use crate::params::TableParams;

/// Maximum number of eviction kicks before declaring insertion failure.
pub const CUCKOO_MAX_KICKS: usize = 10000;

/// Default load factor for sizing cuckoo tables.
pub const CUCKOO_LOAD_FACTOR: f64 = 0.95;

/// An empty slot sentinel value.
pub const EMPTY: u32 = u32::MAX;

/// Compute the required number of bins per table given the max load across groups.
pub fn compute_bins_per_table(max_load: usize, slots_per_bin: usize) -> usize {
    let capacity_per_bin = slots_per_bin as f64 * CUCKOO_LOAD_FACTOR;
    (max_load as f64 / capacity_per_bin).ceil() as usize
}

/// Insert an entry into a cuckoo table with eviction.
///
/// `table[bin * slots_per_bin + slot]` holds item indices (u32).
/// Returns true if insertion succeeded.
///
/// # Arguments
/// * `table` - Flat array of slots, length = `num_bins * slots_per_bin`.
/// * `num_bins` - Number of bins in this table.
/// * `slots_per_bin` - Slots per bin.
/// * `entry_idx` - The item index to insert.
/// * `hash_fns` - Closure that maps (entry_idx) → bin index for each hash function.
/// * `num_hash_fns` - Number of cuckoo hash functions (typically 2).
/// * `max_kicks` - Maximum eviction chain length.
pub fn cuckoo_insert<F>(
    table: &mut [u32],
    _num_bins: usize,
    slots_per_bin: usize,
    entry_idx: u32,
    hash_fns: &F,
    num_hash_fns: usize,
    max_kicks: usize,
) -> bool
where
    F: Fn(u32, usize) -> usize,
{
    // Try each hash function for a free slot
    for hf in 0..num_hash_fns {
        let bin = hash_fns(entry_idx, hf);
        let base = bin * slots_per_bin;
        for s in 0..slots_per_bin {
            if table[base + s] == EMPTY {
                table[base + s] = entry_idx;
                return true;
            }
        }
    }

    // Eviction chain — vary eviction slot to avoid 2-cycles
    let mut current = entry_idx;
    let mut current_bin = hash_fns(current, 0);

    for kick in 0..max_kicks {
        let base = current_bin * slots_per_bin;
        let evict_slot = kick % slots_per_bin;
        let evicted = table[base + evict_slot];
        table[base + evict_slot] = current;

        // Find the alternative bin for the evicted entry
        let mut alt_bin = current_bin;
        for hf in 0..num_hash_fns {
            let bin = hash_fns(evicted, hf);
            if bin != current_bin {
                alt_bin = bin;
                break;
            }
        }

        // Try to place evicted entry in its alternative bin
        let alt_base = alt_bin * slots_per_bin;
        let mut placed = false;
        for s in 0..slots_per_bin {
            if table[alt_base + s] == EMPTY {
                table[alt_base + s] = evicted;
                placed = true;
                break;
            }
        }

        if placed {
            return true;
        }

        current = evicted;
        current_bin = alt_bin;
    }

    false
}

/// Build a cuckoo table for byte-keyed items (e.g., script hashes in INDEX level).
///
/// Returns the flat table of entry indices and the number of bins.
///
/// # Arguments
/// * `entries` - Slice of 20-byte script hashes assigned to this group.
/// * `group_id` - Which PBC group this table serves.
/// * `params` - Table parameters.
/// * `num_bins` - Pre-computed number of bins for this table.
pub fn build_byte_keyed_table(
    entries: &[&[u8]],
    group_id: usize,
    params: &TableParams,
    num_bins: usize,
) -> Vec<u32> {
    let table_size = num_bins * params.slots_per_bin;
    let mut table = vec![EMPTY; table_size];

    // Derive cuckoo keys for this group
    let keys: Vec<u64> = (0..params.cuckoo_num_hashes)
        .map(|hf| hash::derive_cuckoo_key(params.master_seed, group_id, hf))
        .collect();

    let hash_fn = |entry_idx: u32, hf: usize| -> usize {
        hash::cuckoo_hash(entries[entry_idx as usize], keys[hf], num_bins)
    };

    for i in 0..entries.len() {
        if !cuckoo_insert(
            &mut table,
            num_bins,
            params.slots_per_bin,
            i as u32,
            &hash_fn,
            params.cuckoo_num_hashes,
            CUCKOO_MAX_KICKS,
        ) {
            panic!(
                "Cuckoo insertion failed for entry {} in group {} after {} kicks",
                i, group_id, CUCKOO_MAX_KICKS
            );
        }
    }

    table
}

/// Build a cuckoo table for integer-keyed items (e.g., chunk IDs in CHUNK level).
///
/// Returns the flat table of entry indices and the number of bins.
pub fn build_int_keyed_table(
    ids: &[u32],
    group_id: usize,
    params: &TableParams,
    num_bins: usize,
) -> Vec<u32> {
    let table_size = num_bins * params.slots_per_bin;
    let mut table = vec![EMPTY; table_size];

    let keys: Vec<u64> = (0..params.cuckoo_num_hashes)
        .map(|hf| hash::derive_cuckoo_key(params.master_seed, group_id, hf))
        .collect();

    let hash_fn = |entry_idx: u32, hf: usize| -> usize {
        hash::cuckoo_hash_int(ids[entry_idx as usize], keys[hf], num_bins)
    };

    // Enumerate to avoid clippy::needless_range_loop — both the
    // `i as u32` cuckoo entry index and the panic's `ids[i]` lookup
    // are satisfied by the (i, id) pair from enumerate.
    for (i, id) in ids.iter().enumerate() {
        if !cuckoo_insert(
            &mut table,
            num_bins,
            params.slots_per_bin,
            i as u32,
            &hash_fn,
            params.cuckoo_num_hashes,
            CUCKOO_MAX_KICKS,
        ) {
            panic!(
                "Cuckoo insertion failed for chunk_id {} in group {} after {} kicks",
                id, group_id, CUCKOO_MAX_KICKS
            );
        }
    }

    table
}

/// Write a cuckoo table file header.
///
/// Layout depends on `params.header_size` and `params.has_tag_seed`:
/// - Bytes 0..8: magic (u64 LE)
/// - Bytes 8..12: k (u32 LE)
/// - Bytes 12..16: slots_per_bin (u32 LE)
/// - Bytes 16..20: bins_per_table (u32 LE)
/// - Bytes 20..24: num_hashes (u32 LE)
/// - Bytes 24..32: master_seed (u64 LE)
/// - Bytes 32..40: tag_seed (u64 LE) — only if has_tag_seed
pub fn write_header(params: &TableParams, bins_per_table: usize, tag_seed: u64) -> Vec<u8> {
    let mut header = vec![0u8; params.header_size];
    header[0..8].copy_from_slice(&params.magic.to_le_bytes());
    header[8..12].copy_from_slice(&(params.k as u32).to_le_bytes());
    header[12..16].copy_from_slice(&(params.slots_per_bin as u32).to_le_bytes());
    header[16..20].copy_from_slice(&(bins_per_table as u32).to_le_bytes());
    header[20..24].copy_from_slice(&(params.num_hashes as u32).to_le_bytes());
    header[24..32].copy_from_slice(&params.master_seed.to_le_bytes());
    if params.has_tag_seed && params.header_size >= 40 {
        header[32..40].copy_from_slice(&tag_seed.to_le_bytes());
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{INDEX_PARAMS, CHUNK_PARAMS};
    use crate::hash::read_cuckoo_header;

    #[test]
    fn test_compute_bins_per_table() {
        let bins = compute_bins_per_table(100, 4);
        // 100 / (4 * 0.95) = 26.3 → 27
        assert_eq!(bins, 27);
    }

    #[test]
    fn test_header_roundtrip_index() {
        let header = write_header(&INDEX_PARAMS, 753707, 0xd4e5f6a7b8c91023);
        let (bins, tag_seed) = read_cuckoo_header(
            &header,
            INDEX_PARAMS.magic,
            INDEX_PARAMS.header_size,
            INDEX_PARAMS.has_tag_seed,
        );
        assert_eq!(bins, 753707);
        assert_eq!(tag_seed, 0xd4e5f6a7b8c91023);
    }

    #[test]
    fn test_header_roundtrip_chunk() {
        let header = write_header(&CHUNK_PARAMS, 1286191, 0);
        let (bins, tag_seed) = read_cuckoo_header(
            &header,
            CHUNK_PARAMS.magic,
            CHUNK_PARAMS.header_size,
            CHUNK_PARAMS.has_tag_seed,
        );
        assert_eq!(bins, 1286191);
        assert_eq!(tag_seed, 0); // CHUNK has no tag_seed
    }

    #[test]
    fn test_build_byte_keyed_table() {
        // Small test: 10 items, 4 bins
        let items: Vec<[u8; 20]> = (0..10u8).map(|i| {
            let mut sh = [0u8; 20];
            sh[0] = i;
            sh
        }).collect();
        let refs: Vec<&[u8]> = items.iter().map(|s| s.as_slice()).collect();

        let table = build_byte_keyed_table(&refs, 0, &INDEX_PARAMS, 10);
        // All items should be placed (no EMPTY for them)
        let placed: Vec<u32> = table.iter().filter(|&&v| v != EMPTY).copied().collect();
        assert_eq!(placed.len(), 10);
    }

    #[test]
    fn test_build_int_keyed_table() {
        let ids: Vec<u32> = (0..10).collect();
        let table = build_int_keyed_table(&ids, 0, &CHUNK_PARAMS, 10);
        let placed: Vec<u32> = table.iter().filter(|&&v| v != EMPTY).copied().collect();
        assert_eq!(placed.len(), 10);
    }
}
