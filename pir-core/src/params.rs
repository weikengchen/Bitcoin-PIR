//! Table parameters for Batch PIR cuckoo tables.
//!
//! Each sub-table in the system (INDEX, CHUNK, MERKLE_DATA, MERKLE_SIBLING_*)
//! is parameterized by a `TableParams` struct. This allows the same build/serve
//! code to work across different database types and sizes.

/// Runtime-configurable parameters for a single Batch PIR cuckoo sub-table.
#[derive(Clone, Debug)]
pub struct TableParams {
    /// Number of Batch PIR buckets (e.g. 75 for INDEX, 80 for CHUNK).
    pub k: usize,
    /// Number of bucket assignments per item (always 3).
    pub num_hashes: usize,
    /// Master PRG seed for deriving per-bucket cuckoo hash function keys.
    pub master_seed: u64,
    /// Slots per cuckoo bin (e.g. 4 for INDEX, 3 for CHUNK).
    pub cuckoo_bucket_size: usize,
    /// Number of cuckoo hash functions (always 2).
    pub cuckoo_num_hashes: usize,
    /// Bytes per slot in the final cuckoo table.
    pub slot_size: usize,
    /// DPF domain exponent (2^dpf_n >= bins_per_table).
    pub dpf_n: u8,
    /// File header magic number.
    pub magic: u64,
    /// File header byte count.
    pub header_size: usize,
    /// Whether the header contains a tag_seed field.
    pub has_tag_seed: bool,
}

impl TableParams {
    /// Byte size of one cuckoo bin (all slots).
    pub fn bin_size(&self) -> usize {
        self.cuckoo_bucket_size * self.slot_size
    }

    /// Byte size of one sub-table given the number of bins.
    pub fn table_byte_size(&self, bins_per_table: usize) -> usize {
        bins_per_table * self.bin_size()
    }

    /// Result size returned per bucket in a PIR query.
    pub fn result_size(&self) -> usize {
        self.bin_size()
    }
}

/// Compute the minimum DPF domain exponent such that 2^n >= bins_per_table.
///
/// This should be used instead of hardcoding DPF_N, since different databases
/// (main UTXO, delta, Merkle siblings) have very different sizes.
pub fn compute_dpf_n(bins_per_table: usize) -> u8 {
    if bins_per_table <= 1 {
        return 1;
    }
    let mut n = 0u8;
    let mut v = 1usize;
    while v < bins_per_table {
        v <<= 1;
        n += 1;
    }
    n
}

// ─── Known configurations ───────────────────────────────────────────────────

/// Size of a script hash (HASH160 output).
pub const SCRIPT_HASH_SIZE: usize = 20;

/// Size of the fingerprint tag in INDEX slots.
pub const TAG_SIZE: usize = 8;

/// Size of one chunk of UTXO data.
pub const CHUNK_SIZE: usize = 40;

/// INDEX-level slot size: 8B tag + 4B start_chunk_id + 1B num_chunks + 4B tree_loc.
pub const INDEX_SLOT_SIZE: usize = TAG_SIZE + 4 + 1 + 4; // 17

/// CHUNK-level slot size: 4B chunk_id + 40B data.
pub const CHUNK_SLOT_SIZE: usize = 4 + CHUNK_SIZE; // 44

/// Size of each entry in the intermediate index file: 20B script_hash + 4B start_chunk_id + 1B num_chunks.
pub const INDEX_ENTRY_SIZE: usize = SCRIPT_HASH_SIZE + 4 + 1; // 25

/// Standard INDEX-level parameters for the main UTXO database.
pub const INDEX_PARAMS: TableParams = TableParams {
    k: 75,
    num_hashes: 3,
    master_seed: 0x71a2ef38b4c90d15,
    cuckoo_bucket_size: 4,
    cuckoo_num_hashes: 2,
    slot_size: INDEX_SLOT_SIZE,
    dpf_n: 20,
    magic: 0xBA7C_C000_C000_0004,
    header_size: 40,
    has_tag_seed: true,
};

/// Standard CHUNK-level parameters for the main UTXO database.
pub const CHUNK_PARAMS: TableParams = TableParams {
    k: 80,
    num_hashes: 3,
    master_seed: 0xa3f7c2d918e4b065,
    cuckoo_bucket_size: 3,
    cuckoo_num_hashes: 2,
    slot_size: CHUNK_SLOT_SIZE,
    dpf_n: 21,
    magic: 0xBA7C_C000_C000_0002,
    header_size: 32,
    has_tag_seed: false,
};

// ─── File path constants (kept for backward compatibility) ──────────────────

/// Path to the UTXO chunks index file (intermediate).
pub const INDEX_FILE: &str = "/Volumes/Bitcoin/data/intermediate/utxo_chunks_index_nodust.bin";

/// Path to the serialized INDEX-level Batch PIR cuckoo tables (server).
pub const CUCKOO_FILE: &str = "/Volumes/Bitcoin/data/batch_pir_cuckoo.bin";

/// Path to the CHUNK-level cuckoo tables (server).
pub const CHUNK_CUCKOO_FILE: &str = "/Volumes/Bitcoin/data/chunk_pir_cuckoo.bin";

/// Path to the UTXO chunks data file (intermediate).
pub const CHUNKS_DATA_FILE: &str = "/Volumes/Bitcoin/data/intermediate/utxo_chunks_nodust.bin";

/// Path to the batch PIR results (intermediate/test output).
pub const BATCH_PIR_RESULTS_FILE: &str = "/Volumes/Bitcoin/data/intermediate/batch_pir_results.bin";

/// Path to the chunk PIR execution plan (intermediate).
pub const CHUNK_PIR_PLAN_FILE: &str = "/Volumes/Bitcoin/data/intermediate/chunk_pir_plan.bin";

/// Magic number for plan files.
pub const PLAN_MAGIC: u64 = 0xBA7C_01A0_0000_0001;

/// Number of rounds to batch together for server processing.
pub const ROUNDS_PER_BATCH: usize = 5;

/// Number of consecutive 40-byte chunks grouped into one PIR query unit.
pub const CHUNKS_PER_UNIT: usize = 1;

/// Byte size of one unit's payload.
pub const UNIT_DATA_SIZE: usize = CHUNKS_PER_UNIT * CHUNK_SIZE;

// ─── Legacy constant aliases ────────────────────────────────────────────────
// These exist so that code using the old `common::K`, `common::MASTER_SEED`,
// etc. continues to compile without changes during migration.

pub const K: usize = INDEX_PARAMS.k;
pub const NUM_HASHES: usize = INDEX_PARAMS.num_hashes;
pub const MASTER_SEED: u64 = INDEX_PARAMS.master_seed;
pub const CUCKOO_BUCKET_SIZE: usize = INDEX_PARAMS.cuckoo_bucket_size;
pub const INDEX_CUCKOO_NUM_HASHES: usize = INDEX_PARAMS.cuckoo_num_hashes;
pub const MAGIC: u64 = INDEX_PARAMS.magic;
pub const HEADER_SIZE: usize = INDEX_PARAMS.header_size;

pub const K_CHUNK: usize = CHUNK_PARAMS.k;
pub const CHUNK_MASTER_SEED: u64 = CHUNK_PARAMS.master_seed;
pub const CHUNK_CUCKOO_BUCKET_SIZE: usize = CHUNK_PARAMS.cuckoo_bucket_size;
pub const CHUNK_CUCKOO_NUM_HASHES: usize = CHUNK_PARAMS.cuckoo_num_hashes;
pub const CHUNK_MAGIC: u64 = CHUNK_PARAMS.magic;
pub const CHUNK_HEADER_SIZE: usize = CHUNK_PARAMS.header_size;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_dpf_n() {
        assert_eq!(compute_dpf_n(0), 1);
        assert_eq!(compute_dpf_n(1), 1);
        assert_eq!(compute_dpf_n(2), 1);
        assert_eq!(compute_dpf_n(3), 2);
        assert_eq!(compute_dpf_n(4), 2);
        assert_eq!(compute_dpf_n(5), 3);
        assert_eq!(compute_dpf_n(1024), 10);
        assert_eq!(compute_dpf_n(1025), 11);
        // Main UTXO database INDEX: ~565K bins → dpf_n=20
        assert_eq!(compute_dpf_n(565684), 20);
        // Main UTXO database CHUNK: ~1.06M bins → dpf_n=21
        assert_eq!(compute_dpf_n(1064454), 21);
        // A small delta database: ~10K bins → dpf_n=14
        assert_eq!(compute_dpf_n(10000), 14);
        // Merkle sibling level 15: ~1K nodes → dpf_n=10
        assert_eq!(compute_dpf_n(1000), 10);
    }

    #[test]
    fn test_dpf_n_covers_bins() {
        for bins in [1, 2, 100, 1000, 565684, 1064454, 2_000_000] {
            let n = compute_dpf_n(bins);
            assert!((1usize << n) >= bins, "2^{} = {} < {}", n, 1usize << n, bins);
            if n > 1 {
                assert!((1usize << (n - 1)) < bins, "2^{} = {} >= {}", n - 1, 1usize << (n - 1), bins);
            }
        }
    }
}
