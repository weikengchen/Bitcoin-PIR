#![allow(dead_code)]
//! Shared constants and hash utilities for Batch PIR tools.

/// Path to the UTXO chunks index file (nodust, 40-byte blocks)
pub const INDEX_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_index_nodust.bin";

/// Size of each index entry in the intermediate file: 20B script_hash + 4B start_chunk_id + 1B num_chunks
pub const INDEX_ENTRY_SIZE: usize = 25;

/// Size of the script hash portion (in intermediate file and for bucket/cuckoo derivation)
pub const SCRIPT_HASH_SIZE: usize = 20;

/// Size of the fingerprint tag stored in the final cuckoo table
pub const TAG_SIZE: usize = 8;

/// Number of Batch PIR buckets
pub const K: usize = 75;

/// Number of bucket assignments per entry
pub const NUM_HASHES: usize = 3;

/// Master PRG seed for deriving per-bucket cuckoo hash function keys
pub const MASTER_SEED: u64 = 0x71a2ef38b4c90d15;

/// Cuckoo hash table bucket size for INDEX level (slots per bin)
pub const CUCKOO_BUCKET_SIZE: usize = 3;

/// Number of cuckoo hash functions for INDEX level
pub const INDEX_CUCKOO_NUM_HASHES: usize = 2;

/// Cuckoo hash table bucket size for CHUNK level (slots per bin)
pub const CHUNK_CUCKOO_BUCKET_SIZE: usize = 3;

/// Number of cuckoo hash functions for CHUNK level
pub const CHUNK_CUCKOO_NUM_HASHES: usize = 2;

/// File format magic number for the batch_pir_cuckoo.bin file (v2: 8-byte fingerprint tags)
pub const MAGIC: u64 = 0xBA7C_C000_C000_0003;

/// Header size in bytes for the batch_pir_cuckoo.bin file (v2: includes tag_seed)
pub const HEADER_SIZE: usize = 40;

/// Path to the serialized Batch PIR cuckoo tables
pub const CUCKOO_FILE: &str = "/Volumes/Bitcoin/data/batch_pir_cuckoo.bin";

/// Splitmix64 finalizer — used to derive keys and as a general mixer.
#[inline]
pub fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

/// Read first 8 bytes of a script_hash as u64 (LE).
#[inline]
pub fn sh_a(script_hash: &[u8]) -> u64 {
    u64::from_le_bytes([
        script_hash[0], script_hash[1], script_hash[2], script_hash[3],
        script_hash[4], script_hash[5], script_hash[6], script_hash[7],
    ])
}

/// Read bytes 8..16 of a script_hash as u64 (LE).
#[inline]
pub fn sh_b(script_hash: &[u8]) -> u64 {
    u64::from_le_bytes([
        script_hash[8], script_hash[9], script_hash[10], script_hash[11],
        script_hash[12], script_hash[13], script_hash[14], script_hash[15],
    ])
}

/// Read bytes 16..20 of a script_hash as u32 (LE), zero-extended to u64.
#[inline]
pub fn sh_c(script_hash: &[u8]) -> u64 {
    u32::from_le_bytes([
        script_hash[16], script_hash[17], script_hash[18], script_hash[19],
    ]) as u64
}

/// Hash script_hash with a nonce for Batch PIR bucket assignment.
#[inline]
pub fn hash_for_bucket(script_hash: &[u8], nonce: u64) -> u64 {
    let mut h = sh_a(script_hash).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15));
    h ^= sh_b(script_hash);
    h = splitmix64(h ^ sh_c(script_hash));
    h
}

/// Derive `NUM_HASHES` (3) distinct Batch PIR bucket indices for a script_hash.
pub fn derive_buckets(script_hash: &[u8]) -> [usize; NUM_HASHES] {
    let mut buckets = [0usize; NUM_HASHES];
    let mut nonce: u64 = 0;
    let mut count = 0;

    while count < NUM_HASHES {
        let h = hash_for_bucket(script_hash, nonce);
        let bucket = (h % K as u64) as usize;
        nonce += 1;

        let mut dup = false;
        for i in 0..count {
            if buckets[i] == bucket {
                dup = true;
                break;
            }
        }
        if dup {
            continue;
        }

        buckets[count] = bucket;
        count += 1;
    }

    buckets
}

/// Derive a hash function key for a given (batch-PIR bucket, cuckoo hash fn index).
#[inline]
pub fn derive_cuckoo_key(bucket_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        MASTER_SEED
            .wrapping_add((bucket_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

/// Cuckoo hash: hash a script_hash with a derived key, return a bin index.
#[inline]
pub fn cuckoo_hash(script_hash: &[u8], key: u64, num_bins: usize) -> usize {
    let mut h = sh_a(script_hash) ^ key;
    h ^= sh_b(script_hash);
    h = splitmix64(h ^ sh_c(script_hash));
    (h % num_bins as u64) as usize
}

/// Size of one inlined index slot in the final cuckoo table: 8B tag + 4B + 1B = 13 bytes
pub const INDEX_SLOT_SIZE: usize = TAG_SIZE + 4 + 1;

/// Size of one inlined chunk slot: 4B chunk_id + CHUNK_SIZE data
pub const CHUNK_SLOT_SIZE: usize = 4 + CHUNK_SIZE; // 44

/// Read bins_per_table and tag_seed from a batch_pir_cuckoo.bin header.
/// Returns (bins_per_table, tag_seed).
pub fn read_cuckoo_header(data: &[u8]) -> (usize, u64) {
    assert!(data.len() >= HEADER_SIZE, "File too small for header");
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(magic, MAGIC, "Bad magic number");
    let bins_per_table = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    let tag_seed = u64::from_le_bytes(data[32..40].try_into().unwrap());
    (bins_per_table, tag_seed)
}

/// Compute an 8-byte fingerprint tag for a script_hash using a keyed hash.
/// Uses splitmix64 mixing with an independent seed for collision resistance.
#[inline]
pub fn compute_tag(tag_seed: u64, script_hash: &[u8]) -> u64 {
    let mut h = sh_a(script_hash) ^ tag_seed;
    h ^= sh_b(script_hash);
    splitmix64(h ^ sh_c(script_hash))
}

// ─── Chunk-level Batch PIR constants ─────────────────────────────────────────

/// Number of Batch PIR buckets for chunks
pub const K_CHUNK: usize = 80;

/// Master PRG seed for chunk-level cuckoo key derivation (distinct from first-level)
pub const CHUNK_MASTER_SEED: u64 = 0xa3f7c2d918e4b065;

/// File format magic for chunk_pir_cuckoo.bin
pub const CHUNK_MAGIC: u64 = 0xBA7C_C000_C000_0002;

/// Header size in bytes for chunk_pir_cuckoo.bin (no tag_seed field)
pub const CHUNK_HEADER_SIZE: usize = 32;

/// Size of one chunk in bytes
pub const CHUNK_SIZE: usize = 40;

/// Path to the chunk-level cuckoo tables
pub const CHUNK_CUCKOO_FILE: &str = "/Volumes/Bitcoin/data/chunk_pir_cuckoo.bin";

/// Path to the UTXO chunks data file
pub const CHUNKS_DATA_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_nodust.bin";

/// Path to the first-level PIR results (50 × 26 bytes)
pub const BATCH_PIR_RESULTS_FILE: &str = "/Volumes/Bitcoin/data/batch_pir_results.bin";

// ─── Chunk-level hash utilities ──────────────────────────────────────────────

/// Hash a chunk_id with a nonce for chunk-level bucket assignment.
#[inline]
pub fn hash_chunk_for_bucket(chunk_id: u32, nonce: u64) -> u64 {
    splitmix64((chunk_id as u64).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15)))
}

/// Derive 3 distinct chunk-level bucket indices for a chunk_id.
pub fn derive_chunk_buckets(chunk_id: u32) -> [usize; NUM_HASHES] {
    let mut buckets = [0usize; NUM_HASHES];
    let mut nonce: u64 = 0;
    let mut count = 0;

    while count < NUM_HASHES {
        let h = hash_chunk_for_bucket(chunk_id, nonce);
        let bucket = (h % K_CHUNK as u64) as usize;
        nonce += 1;

        let mut dup = false;
        for i in 0..count {
            if buckets[i] == bucket {
                dup = true;
                break;
            }
        }
        if dup {
            continue;
        }

        buckets[count] = bucket;
        count += 1;
    }

    buckets
}

/// Derive a cuckoo hash function key for a chunk-level (bucket, hash_fn).
#[inline]
pub fn derive_chunk_cuckoo_key(bucket_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        CHUNK_MASTER_SEED
            .wrapping_add((bucket_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

/// Cuckoo hash for chunk_ids: map a chunk_id to a bin index using a derived key.
#[inline]
pub fn cuckoo_hash_int(chunk_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((chunk_id as u64) ^ key) % num_bins as u64) as usize
}

/// Read bins_per_table from a chunk_pir_cuckoo.bin header.
pub fn read_chunk_cuckoo_header(data: &[u8]) -> usize {
    assert!(data.len() >= CHUNK_HEADER_SIZE, "File too small for header");
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(magic, CHUNK_MAGIC, "Bad chunk cuckoo magic number");
    let bins_per_table = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    bins_per_table
}

// ─── Plan file constants ─────────────────────────────────────────────────────

/// Path to the chunk PIR execution plan
pub const CHUNK_PIR_PLAN_FILE: &str = "/Volumes/Bitcoin/data/chunk_pir_plan.bin";

/// Magic number for plan files
pub const PLAN_MAGIC: u64 = 0xBA7C_01A0_0000_0001;

/// Number of rounds to batch together for server processing
pub const ROUNDS_PER_BATCH: usize = 5;

/// Number of consecutive 40-byte chunks grouped into one PIR query unit.
/// Set to 1 for original per-chunk behaviour, 10 for 400-byte units, etc.
/// The cuckoo table (gen_7) is always built at chunk granularity; this
/// constant only affects planning (gen_9) and retrieval (gen_10b).
pub const CHUNKS_PER_UNIT: usize = 1;

/// Byte size of one unit's payload: CHUNKS_PER_UNIT × CHUNK_SIZE.
pub const UNIT_DATA_SIZE: usize = CHUNKS_PER_UNIT * CHUNK_SIZE;
