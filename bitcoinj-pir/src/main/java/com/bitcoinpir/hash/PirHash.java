package com.bitcoinpir.hash;

import com.bitcoinpir.PirConstants;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;

/**
 * Hash functions for the Batch PIR system.
 * Ports the splitmix64-based functions from web/src/hash.ts and build/src/common.rs.
 *
 * All 64-bit arithmetic uses Java {@code long} (signed). Since splitmix64 only uses
 * XOR, shift, and multiplication (which are sign-agnostic in two's complement),
 * only modulo operations need {@link Long#remainderUnsigned}.
 */
public final class PirHash {
    private PirHash() {}

    // ── Core hash function ──────────────────────────────────────────────────

    /** splitmix64 finalizer (matches Rust exactly). */
    public static long splitmix64(long x) {
        x ^= (x >>> 30);
        x *= 0xbf58476d1ce4e5b9L;
        x ^= (x >>> 27);
        x *= 0x94d049bb133111ebL;
        x ^= (x >>> 31);
        return x;
    }

    // ── Script hash helpers ─────────────────────────────────────────────────

    /** Read first 8 bytes of a 20-byte script_hash as u64 LE. */
    static long shA(byte[] data) {
        return ByteBuffer.wrap(data, 0, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

    /** Read bytes 8..16 of a 20-byte script_hash as u64 LE. */
    static long shB(byte[] data) {
        return ByteBuffer.wrap(data, 8, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

    /** Read bytes 16..20 of a 20-byte script_hash as u32 LE, zero-extended to u64. */
    static long shC(byte[] data) {
        int v = ByteBuffer.wrap(data, 16, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        return Integer.toUnsignedLong(v);
    }

    // ── Tag computation ─────────────────────────────────────────────────────

    /** Compute an 8-byte fingerprint tag for a script_hash using a keyed hash. */
    public static long computeTag(long tagSeed, byte[] scriptHash) {
        long h = shA(scriptHash) ^ tagSeed;
        h ^= shB(scriptHash);
        h = splitmix64(h ^ shC(scriptHash));
        return h;
    }

    // ── Index-level bucket assignment ────────────────────────────────────────

    /** Hash script_hash with a nonce for bucket assignment. */
    private static long hashForBucket(byte[] scriptHash, long nonce) {
        long h = shA(scriptHash) + (nonce * 0x9e3779b97f4a7c15L);
        h ^= shB(scriptHash);
        h = splitmix64(h ^ shC(scriptHash));
        return h;
    }

    /** Derive NUM_HASHES (3) distinct bucket indices for a script_hash. */
    public static int[] deriveBuckets(byte[] scriptHash) {
        int[] buckets = new int[PirConstants.NUM_HASHES];
        int count = 0;
        long nonce = 0;

        while (count < PirConstants.NUM_HASHES) {
            long h = hashForBucket(scriptHash, nonce);
            int bucket = (int) Long.remainderUnsigned(h, PirConstants.K);
            nonce++;

            boolean dup = false;
            for (int i = 0; i < count; i++) {
                if (buckets[i] == bucket) { dup = true; break; }
            }
            if (!dup) {
                buckets[count++] = bucket;
            }
        }
        return buckets;
    }

    // ── Chunk-level bucket assignment ────────────────────────────────────────

    /** Hash a chunk_id with a nonce for chunk-level bucket assignment. */
    private static long hashChunkForBucket(int chunkId, long nonce) {
        return splitmix64(Integer.toUnsignedLong(chunkId) + (nonce * 0x9e3779b97f4a7c15L));
    }

    /** Derive 3 distinct chunk-level bucket indices for a chunk_id. */
    public static int[] deriveChunkBuckets(int chunkId) {
        int[] buckets = new int[PirConstants.NUM_HASHES];
        int count = 0;
        long nonce = 0;

        while (count < PirConstants.NUM_HASHES) {
            long h = hashChunkForBucket(chunkId, nonce);
            int bucket = (int) Long.remainderUnsigned(h, PirConstants.K_CHUNK);
            nonce++;

            boolean dup = false;
            for (int i = 0; i < count; i++) {
                if (buckets[i] == bucket) { dup = true; break; }
            }
            if (!dup) {
                buckets[count++] = bucket;
            }
        }
        return buckets;
    }

    // ── Script hash computation ─────────────────────────────────────────────

    /**
     * Compute HASH160 = RIPEMD160(SHA256(scriptPubKey)).
     * Uses bitcoinj's built-in RIPEMD160 implementation.
     */
    public static byte[] hash160(byte[] scriptPubKey) {
        try {
            // SHA256
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] sha = sha256.digest(scriptPubKey);
            // RIPEMD160 via Bouncy Castle (bitcoinj dependency)
            org.bouncycastle.crypto.digests.RIPEMD160Digest ripemd = new org.bouncycastle.crypto.digests.RIPEMD160Digest();
            ripemd.update(sha, 0, sha.length);
            byte[] out = new byte[20];
            ripemd.doFinal(out, 0);
            return out;
        } catch (Exception e) {
            throw new RuntimeException("Hash computation failed", e);
        }
    }

    // ── Hex utilities ───────────────────────────────────────────────────────

    /** Convert byte array to lowercase hex string. */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    /** Convert hex string to byte array. */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /** Reverse a byte array (for Bitcoin TXID display). */
    public static byte[] reverseBytes(byte[] data) {
        byte[] reversed = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            reversed[i] = data[data.length - 1 - i];
        }
        return reversed;
    }
}
