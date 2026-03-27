package com.bitcoinpir.hash;

import com.bitcoinpir.PirConstants;

import static com.bitcoinpir.hash.PirHash.*;

/**
 * Cuckoo hash functions for index-level and chunk-level tables.
 * Ports deriveCuckooKey / cuckooHash from web/src/hash.ts.
 */
public final class CuckooHash {
    private CuckooHash() {}

    // ── Index-level cuckoo hashing ──────────────────────────────────────────

    /** Derive a cuckoo hash function key for (bucketId, hashFn) at index level. */
    public static long deriveCuckooKey(int bucketId, int hashFn) {
        return splitmix64(
            PirConstants.MASTER_SEED
            + ((long) bucketId * 0x9e3779b97f4a7c15L)
            + ((long) hashFn * 0x517cc1b727220a95L)
        );
    }

    /** Cuckoo hash: hash a script_hash with a derived key, return a bin index. */
    public static int cuckooHash(byte[] scriptHash, long key, int numBins) {
        long h = shA(scriptHash) ^ key;
        h ^= shB(scriptHash);
        h = splitmix64(h ^ shC(scriptHash));
        return (int) Long.remainderUnsigned(h, numBins);
    }

    // ── Chunk-level cuckoo hashing ──────────────────────────────────────────

    /** Derive a cuckoo hash function key for chunk-level (bucketId, hashFn). */
    public static long deriveChunkCuckooKey(int bucketId, int hashFn) {
        return splitmix64(
            PirConstants.CHUNK_MASTER_SEED
            + ((long) bucketId * 0x9e3779b97f4a7c15L)
            + ((long) hashFn * 0x517cc1b727220a95L)
        );
    }

    /** Cuckoo hash for chunk_ids: map a chunk_id to a bin index using a derived key. */
    public static int cuckooHashInt(int chunkId, long key, int numBins) {
        return (int) Long.remainderUnsigned(
            splitmix64(Integer.toUnsignedLong(chunkId) ^ key),
            numBins
        );
    }
}
