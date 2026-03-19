/**
 * Constants for the Bitcoin PIR system
 */

// Database IDs
export const CUCKOO_DB_ID = "utxo_cuckoo_index";
export const CHUNKS_DB_ID = "utxo_chunks_data";

// Database sizes
export const CUCKOO_NUM_BUCKETS = 15_385_139;
export const CUCKOO_BUCKET_SIZE = 4; // 4 entries per bucket
export const CUCKOO_ENTRY_SIZE = 20 + 4; // 20-byte key + 4-byte offset

export const CHUNKS_NUM_ENTRIES = 181_833;
export const CHUNK_SIZE = 32 * 1024; // 32 KB

// Hash constants
export const DEFAULT_HASH1_SEED = 0xcbf29ce484222325n;
export const DEFAULT_HASH1_PRIME = 0x100000001b3n;
export const DEFAULT_HASH2_SEED = 0x517cc1b727220a95n;
export const DEFAULT_HASH2_PRIME = 0x9e3779b97f4a7c15n;

// Script hash size
export const KEY_SIZE = 20;

// Server ports (default)
export const SERVER1_PORT = 8081;
export const SERVER2_PORT = 8082;

// WebSocket ports (default)
export const WS_SERVER1_PORT = 8091;
export const WS_SERVER2_PORT = 8092;
