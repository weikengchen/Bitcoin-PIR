package com.bitcoinpir;

/**
 * Constants for the Batch PIR system.
 * Must match build/src/common.rs and web/src/constants.ts exactly.
 */
public final class PirConstants {
    private PirConstants() {}

    // ── Index-level constants ───────────────────────────────────────────────

    /** Number of Batch PIR buckets (index level). */
    public static final int K = 75;

    /** Number of bucket assignments per entry. */
    public static final int NUM_HASHES = 3;

    /** Master PRG seed for deriving per-bucket cuckoo hash function keys. */
    public static final long MASTER_SEED = 0x71a2ef38b4c90d15L;

    /** Cuckoo hash table bucket size for INDEX level (slots per bin). */
    public static final int CUCKOO_BUCKET_SIZE = 3;

    /** Number of cuckoo hash functions for INDEX level. */
    public static final int INDEX_CUCKOO_NUM_HASHES = 2;

    /** Cuckoo hash table bucket size for CHUNK level (slots per bin). */
    public static final int CHUNK_CUCKOO_BUCKET_SIZE = 3;

    /** Number of cuckoo hash functions for CHUNK level. */
    public static final int CHUNK_CUCKOO_NUM_HASHES = 2;

    /** Script hash size in bytes (HASH160 output). */
    public static final int SCRIPT_HASH_SIZE = 20;

    /** Size of the fingerprint tag in the cuckoo table (bytes). */
    public static final int TAG_SIZE = 8;

    /** Size of each tagged index entry: 8B tag + 4B start_chunk_id + 1B num_chunks. */
    public static final int INDEX_ENTRY_SIZE = 13;

    /** Index result size: 3 slots * 13 bytes = 39 bytes. */
    public static final int INDEX_RESULT_SIZE = CUCKOO_BUCKET_SIZE * INDEX_ENTRY_SIZE;

    // ── Chunk-level constants ───────────────────────────────────────────────

    /** Number of Batch PIR buckets for chunks. */
    public static final int K_CHUNK = 80;

    /** Master PRG seed for chunk-level cuckoo key derivation. */
    public static final long CHUNK_MASTER_SEED = 0xa3f7c2d918e4b065L;

    /** Size of one chunk in bytes. */
    public static final int CHUNK_SIZE = 40;

    /** Number of consecutive chunks grouped into one PIR query unit. */
    public static final int CHUNKS_PER_UNIT = 1;

    /** Byte size of one unit's payload. */
    public static final int UNIT_DATA_SIZE = CHUNKS_PER_UNIT * CHUNK_SIZE;

    /** Each chunk slot: 4B chunk_id + UNIT_DATA_SIZE data. */
    public static final int CHUNK_SLOT_SIZE = 4 + UNIT_DATA_SIZE;

    /** Chunk result size: 3 slots * slot_size. */
    public static final int CHUNK_RESULT_SIZE = CHUNK_CUCKOO_BUCKET_SIZE * CHUNK_SLOT_SIZE;

    // ── DPF ─────────────────────────────────────────────────────────────────

    /** DPF domain for index level: 2^20 = 1,048,576. */
    public static final int DPF_N = 20;

    /** DPF domain for chunk level: 2^21 = 2,097,152. */
    public static final int CHUNK_DPF_N = 21;

    // ── Protocol variant bytes ──────────────────────────────────────────────

    public static final byte REQ_PING         = 0x00;
    public static final byte REQ_GET_INFO     = 0x01;
    public static final byte REQ_INDEX_BATCH  = 0x11;
    public static final byte REQ_CHUNK_BATCH  = 0x21;

    public static final byte RESP_PONG        = 0x00;
    public static final byte RESP_INFO        = 0x01;
    public static final byte RESP_INDEX_BATCH = 0x11;
    public static final byte RESP_CHUNK_BATCH = 0x21;
    public static final byte RESP_ERROR       = (byte) 0xFF;

    // ── HarmonyPIR PRP backend constants (server-side) ─────────────────────
    // These differ from HarmonyBucket.PRP_* (JNI-side).  Use when encoding
    // hint requests for the server.

    /** Server-side PRP_HOANG constant. */
    public static final int SERVER_PRP_HOANG = 0;
    /** Server-side PRP_FASTPRP constant. */
    public static final int SERVER_PRP_FASTPRP = 1;
    /** Server-side PRP_ALF constant. */
    public static final int SERVER_PRP_ALF = 2;

    // ── HarmonyPIR constants ────────────────────────────────────────────────

    /** HarmonyPIR entry size for index level: CUCKOO_BUCKET_SIZE * INDEX_ENTRY_SIZE = 39. */
    public static final int HARMONY_INDEX_W = CUCKOO_BUCKET_SIZE * INDEX_ENTRY_SIZE;

    /** HarmonyPIR entry size for chunk level: CHUNK_CUCKOO_BUCKET_SIZE * CHUNK_SLOT_SIZE = 132. */
    public static final int HARMONY_CHUNK_W = CHUNK_CUCKOO_BUCKET_SIZE * CHUNK_SLOT_SIZE;

    /** EMPTY sentinel for HarmonyPIR requests (u32::MAX). */
    public static final int HARMONY_EMPTY = 0xFFFFFFFF;

    // ── HarmonyPIR protocol codes ───────────────────────────────────────────

    public static final byte REQ_HARMONY_GET_INFO     = 0x40;
    public static final byte REQ_HARMONY_HINTS        = 0x41;
    public static final byte REQ_HARMONY_QUERY        = 0x42;
    public static final byte REQ_HARMONY_BATCH_QUERY  = 0x43;

    public static final byte RESP_HARMONY_INFO        = 0x40;
    public static final byte RESP_HARMONY_HINTS       = 0x41;
    public static final byte RESP_HARMONY_QUERY       = 0x42;
    public static final byte RESP_HARMONY_BATCH_QUERY = 0x43;

    // ── OnionPIR protocol codes ─────────────────────────────────────────────

    public static final byte REQ_REGISTER_KEYS             = 0x30;
    public static final byte REQ_ONIONPIR_INDEX_QUERY      = 0x31;
    public static final byte REQ_ONIONPIR_CHUNK_QUERY      = 0x32;

    public static final byte RESP_KEYS_ACK                 = 0x30;
    public static final byte RESP_ONIONPIR_INDEX_RESULT    = 0x31;
    public static final byte RESP_ONIONPIR_CHUNK_RESULT    = 0x32;

    // ── Default server URLs ─────────────────────────────────────────────────

    public static final String DEFAULT_DPF_SERVER0_URL = "wss://dpf1.chenweikeng.com";
    public static final String DEFAULT_DPF_SERVER1_URL = "wss://dpf2.chenweikeng.com";
}
