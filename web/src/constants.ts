/**
 * Constants for the Batch PIR system.
 *
 * Must match build/src/common.rs exactly.
 */

// ─── Index-level constants ─────────────────────────────────────────────────

/** Number of Batch PIR buckets (index level) */
export const K = 75;

/** Number of bucket assignments per entry */
export const NUM_HASHES = 3;

/** Master PRG seed for deriving per-bucket cuckoo hash function keys */
export const MASTER_SEED = 0x71a2ef38b4c90d15n;

/** Cuckoo hash table bucket size for INDEX level (slots per bin) */
export const CUCKOO_BUCKET_SIZE = 4;

/** Number of cuckoo hash functions for INDEX level */
export const INDEX_CUCKOO_NUM_HASHES = 2;

/** Cuckoo hash table bucket size for CHUNK level (slots per bin) */
export const CHUNK_CUCKOO_BUCKET_SIZE = 3;

/** Number of cuckoo hash functions for CHUNK level */
export const CHUNK_CUCKOO_NUM_HASHES = 2;

/** Script hash size in bytes (used for computing script_hash and bucket derivation) */
export const SCRIPT_HASH_SIZE = 20;

/** Size of the fingerprint tag in the final cuckoo table */
export const TAG_SIZE = 8;

/** Size of each tagged index entry: 8B tag + 4B start_chunk_id + 1B num_chunks + 4B tree_loc */
export const INDEX_ENTRY_SIZE = 17;

/** Index result size: 4 slots * 13 bytes = 52 bytes */
export const INDEX_RESULT_SIZE = CUCKOO_BUCKET_SIZE * INDEX_ENTRY_SIZE;

// ─── Chunk-level constants ─────────────────────────────────────────────────

/** Number of Batch PIR buckets for chunks */
export const K_CHUNK = 80;

/** Master PRG seed for chunk-level cuckoo key derivation */
export const CHUNK_MASTER_SEED = 0xa3f7c2d918e4b065n;

/** Size of one chunk in bytes */
export const CHUNK_SIZE = 40;

/** Number of consecutive chunks grouped into one PIR query unit */
export const CHUNKS_PER_UNIT = 1;

/** Byte size of one unit's payload */
export const UNIT_DATA_SIZE = CHUNKS_PER_UNIT * CHUNK_SIZE;

/** Each chunk slot: 4B chunk_id + UNIT_DATA_SIZE data */
export const CHUNK_SLOT_SIZE = 4 + UNIT_DATA_SIZE;

/** Chunk result size: 3 slots * slot_size */
export const CHUNK_RESULT_SIZE = CHUNK_CUCKOO_BUCKET_SIZE * CHUNK_SLOT_SIZE;

// ─── DPF ───────────────────────────────────────────────────────────────────

/** DPF domain for index level: 2^20 = 1,048,576 */
export const DPF_N = 20;

/** DPF domain for chunk level: 2^21 = 2,097,152 */
export const CHUNK_DPF_N = 21;

// ─── Protocol constants ────────────────────────────────────────────────────

export const REQ_PING = 0x00;
export const REQ_GET_INFO = 0x01;
export const REQ_GET_INFO_JSON = 0x03;
export const REQ_INDEX_BATCH = 0x11;
export const REQ_CHUNK_BATCH = 0x21;

export const RESP_PONG = 0x00;
export const RESP_INFO = 0x01;
export const RESP_INFO_JSON = 0x03;
export const RESP_INDEX_BATCH = 0x11;
export const RESP_CHUNK_BATCH = 0x21;
export const RESP_ERROR = 0xFF;

// ─── HarmonyPIR constants ─────────────────────────────────────────────────

/** HarmonyPIR entry size for index level: one cuckoo bin = CUCKOO_BUCKET_SIZE * INDEX_ENTRY_SIZE */
export const HARMONY_INDEX_W = CUCKOO_BUCKET_SIZE * INDEX_ENTRY_SIZE; // 52

/** HarmonyPIR entry size for chunk level: one cuckoo bin = CHUNK_CUCKOO_BUCKET_SIZE * CHUNK_SLOT_SIZE */
export const HARMONY_CHUNK_W = CHUNK_CUCKOO_BUCKET_SIZE * CHUNK_SLOT_SIZE; // 132

/** EMPTY sentinel for HarmonyPIR requests (u32::MAX) */
export const HARMONY_EMPTY = 0xFFFFFFFF;

// ─── HarmonyPIR protocol codes ────────────────────────────────────────────

export const REQ_HARMONY_GET_INFO = 0x40;
export const REQ_HARMONY_HINTS = 0x41;
export const REQ_HARMONY_QUERY = 0x42;
export const REQ_HARMONY_BATCH_QUERY = 0x43;

export const RESP_HARMONY_INFO = 0x40;
export const RESP_HARMONY_HINTS = 0x41;
export const RESP_HARMONY_QUERY = 0x42;
export const RESP_HARMONY_BATCH_QUERY = 0x43;

// ─── Merkle sibling constants (DPF, arity=8) ─────────────────────────────

export const REQ_MERKLE_SIBLING_BATCH = 0x31;
export const RESP_MERKLE_SIBLING_BATCH = 0x31;
export const REQ_MERKLE_TREE_TOP = 0x32;
export const RESP_MERKLE_TREE_TOP = 0x32;

/** Merkle tree branching factor for DPF */
export const MERKLE_ARITY = 8;

/** K for Merkle sibling PBC groups (same as INDEX) */
export const MERKLE_SIBLING_K = 75;

/** Cuckoo bucket size for sibling tables (same as INDEX) */
export const MERKLE_SIBLING_BUCKET_SIZE = 4;

/** Cuckoo hash functions for sibling tables */
export const MERKLE_SIBLING_CUCKOO_NUM_HASHES = 2;

/** Sibling slot: [4B group_id][arity x 32B hashes] */
export const MERKLE_SIBLING_SLOT_SIZE = 4 + MERKLE_ARITY * 32; // 260

/** Sibling result: bucket_size x slot_size */
export const MERKLE_SIBLING_RESULT_SIZE = MERKLE_SIBLING_BUCKET_SIZE * MERKLE_SIBLING_SLOT_SIZE; // 1040

// ─── Default server URLs ───────────────────────────────────────────────────

export const DEFAULT_SERVER0_URL = 'wss://pir1.chenweikeng.com';
export const DEFAULT_SERVER1_URL = 'wss://pir2.chenweikeng.com';
