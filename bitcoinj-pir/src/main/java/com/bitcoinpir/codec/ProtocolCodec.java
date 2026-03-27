package com.bitcoinpir.codec;

import com.bitcoinpir.PirConstants;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Binary message encoding/decoding for the PIR WebSocket protocol.
 * All messages: [4B length LE][1B variant][payload...]
 */
public final class ProtocolCodec {
    private ProtocolCodec() {}

    // ── Message framing ─────────────────────────────────────────────────────

    /** Wrap a payload (variant + data) in a length-prefixed message. */
    public static byte[] frame(byte[] payload) {
        byte[] msg = new byte[4 + payload.length];
        ByteBuffer.wrap(msg, 0, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(payload.length);
        System.arraycopy(payload, 0, msg, 4, payload.length);
        return msg;
    }

    /** Extract the variant byte from a raw message (after removing length prefix). */
    public static byte variant(byte[] payload) {
        return payload[0];
    }

    // ── GetInfo ──────────────────────────────────────────────────────────────

    /** Encode a GetInfo request. */
    public static byte[] encodeGetInfo() {
        return frame(new byte[]{PirConstants.REQ_GET_INFO});
    }

    /** Encode a HarmonyPIR GetInfo request. */
    public static byte[] encodeHarmonyGetInfo() {
        return frame(new byte[]{PirConstants.REQ_HARMONY_GET_INFO});
    }

    /** Parsed server info response. */
    public record ServerInfo(int indexBins, int chunkBins, int indexK, int chunkK, long tagSeed) {}

    /** Decode a ServerInfo response payload (after length prefix). */
    public static ServerInfo decodeServerInfo(byte[] payload) {
        // payload[0] = variant (0x01 or 0x40)
        ByteBuffer bb = ByteBuffer.wrap(payload, 1, payload.length - 1).order(ByteOrder.LITTLE_ENDIAN);
        int indexBins = bb.getInt();
        int chunkBins = bb.getInt();
        int indexK = bb.get() & 0xFF;
        int chunkK = bb.get() & 0xFF;
        long tagSeed = bb.getLong();
        return new ServerInfo(indexBins, chunkBins, indexK, chunkK, tagSeed);
    }

    // ── Ping ─────────────────────────────────────────────────────────────────

    /** Encode a Ping request. */
    public static byte[] encodePing() {
        return frame(new byte[]{PirConstants.REQ_PING});
    }

    /** Check if a payload is a Pong response. */
    public static boolean isPong(byte[] payload) {
        return payload.length == 1 && payload[0] == PirConstants.RESP_PONG;
    }

    // ── DPF Batch ────────────────────────────────────────────────────────────

    /**
     * Encode an IndexBatch or ChunkBatch request.
     *
     * @param variant  REQ_INDEX_BATCH (0x11) or REQ_CHUNK_BATCH (0x21)
     * @param roundId  round identifier
     * @param keys     keys[bucket][keyIndex] = DPF key bytes
     */
    public static byte[] encodeBatchRequest(byte variant, int roundId, byte[][][] keys) {
        int numBuckets = keys.length;
        int keysPerBucket = keys[0].length;

        // Calculate total size
        int payloadSize = 1 + 2 + 1 + 1; // variant + roundId + numBuckets + keysPerBucket
        for (byte[][] bucketKeys : keys) {
            for (byte[] key : bucketKeys) {
                payloadSize += 2 + key.length; // keyLen + keyData
            }
        }

        byte[] payload = new byte[payloadSize];
        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(variant);
        bb.putShort((short) roundId);
        bb.put((byte) numBuckets);
        bb.put((byte) keysPerBucket);

        for (byte[][] bucketKeys : keys) {
            for (byte[] key : bucketKeys) {
                bb.putShort((short) key.length);
                bb.put(key);
            }
        }

        return frame(payload);
    }

    /** Parsed batch result: results[bucket][resultIndex] = result bytes. */
    public record BatchResult(int roundId, byte[][][] results) {}

    /** Decode a BatchResult response payload. */
    public static BatchResult decodeBatchResult(byte[] payload) {
        ByteBuffer bb = ByteBuffer.wrap(payload, 1, payload.length - 1).order(ByteOrder.LITTLE_ENDIAN);
        int roundId = bb.getShort() & 0xFFFF;
        int numBuckets = bb.get() & 0xFF;
        int resultsPerBucket = bb.get() & 0xFF;

        byte[][][] results = new byte[numBuckets][resultsPerBucket][];
        for (int b = 0; b < numBuckets; b++) {
            for (int r = 0; r < resultsPerBucket; r++) {
                int len = bb.getShort() & 0xFFFF;
                byte[] data = new byte[len];
                bb.get(data);
                results[b][r] = data;
            }
        }
        return new BatchResult(roundId, results);
    }

    // ── HarmonyPIR Hint Request ─────────────────────────────────────────────

    /**
     * Encode a HarmonyPIR hint request.
     *
     * Wire: [0x41][16B prpKey][1B prpBackend][1B level][1B numBuckets][per bucket: 1B id]
     *
     * @param prpKey     16-byte master PRP key
     * @param prpBackend server-side PRP backend constant (0=Hoang, 1=FastPRP, 2=ALF)
     * @param level      0 = index, 1 = chunk
     * @param bucketIds  which buckets to generate hints for
     */
    public static byte[] encodeHarmonyHintRequest(byte[] prpKey, int prpBackend,
            int level, int[] bucketIds) {
        int payloadSize = 1 + 16 + 1 + 1 + 1 + bucketIds.length;
        byte[] payload = new byte[payloadSize];
        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(PirConstants.REQ_HARMONY_HINTS);
        bb.put(prpKey);
        bb.put((byte) prpBackend);
        bb.put((byte) level);
        bb.put((byte) bucketIds.length);
        for (int id : bucketIds) bb.put((byte) id);
        return frame(payload);
    }

    /** Parsed hint response from the hint server. */
    public record HintData(int bucketId, int n, int t, int m, byte[] hintBytes) {}

    /**
     * Decode a HarmonyPIR hint response payload.
     *
     * Wire: [0x41][1B bucketId][4B n LE][4B t LE][4B m LE][flat hints...]
     */
    public static HintData decodeHarmonyHintResponse(byte[] payload) {
        ByteBuffer bb = ByteBuffer.wrap(payload, 1, payload.length - 1).order(ByteOrder.LITTLE_ENDIAN);
        int bucketId = bb.get() & 0xFF;
        int n = bb.getInt();
        int t = bb.getInt();
        int m = bb.getInt();
        byte[] hints = new byte[payload.length - 14];
        System.arraycopy(payload, 14, hints, 0, hints.length);
        return new HintData(bucketId, n, t, m, hints);
    }

    // ── HarmonyPIR Batch Query ──────────────────────────────────────────────

    /**
     * Encode a HarmonyPIR batch query request.
     *
     * Wire format:
     *   [0x43][1B level][2B roundId LE][2B numBuckets LE][1B subQueriesPerBucket]
     *   per bucket:
     *     [1B bucketId]
     *     per sub-query:
     *       [4B count LE]             (number of u32 indices)
     *       [count × 4B u32 LE]       (sorted indices from buildRequest)
     *
     * @param level              0 = index, 1 = chunk
     * @param roundId            round identifier
     * @param subQueriesPerBucket number of sub-queries per bucket (always 1)
     * @param bucketIds          bucket identifiers
     * @param requests           requests[i] = raw request bytes for bucket bucketIds[i]
     *                           (sequence of 4-byte LE u32 from buildRequest)
     */
    public static byte[] encodeHarmonyBatchQuery(int level, int roundId,
            int subQueriesPerBucket, int[] bucketIds, byte[][] requests) {
        // Calculate size
        int payloadSize = 1 + 1 + 2 + 2 + 1; // variant + level + roundId + numBuckets + subQPerBucket
        for (byte[] req : requests) {
            payloadSize += 1 + 4 + req.length; // bucketId + count(u32) + data
        }

        byte[] payload = new byte[payloadSize];
        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(PirConstants.REQ_HARMONY_BATCH_QUERY);
        bb.put((byte) level);
        bb.putShort((short) roundId);
        bb.putShort((short) bucketIds.length);
        bb.put((byte) subQueriesPerBucket);

        for (int i = 0; i < bucketIds.length; i++) {
            bb.put((byte) bucketIds[i]);
            int indexCount = requests[i].length / 4; // number of u32 indices
            bb.putInt(indexCount);
            bb.put(requests[i]);
        }

        return frame(payload);
    }

    /** Parsed HarmonyPIR batch result item. */
    public record HarmonyBatchResultItem(int bucketId, byte[][] subResults) {}

    /** Parsed HarmonyPIR batch result. */
    public record HarmonyBatchResult(int level, int roundId, HarmonyBatchResultItem[] items) {}

    /**
     * Decode a HarmonyPIR batch query response.
     *
     * Wire format (after length prefix):
     *   [0x43][1B level][2B roundId LE][2B numBuckets LE][1B subResultsPerBucket]
     *   per bucket:
     *     [1B bucketId]
     *     per sub-result:
     *       [4B dataLen LE]
     *       [dataLen bytes]
     */
    public static HarmonyBatchResult decodeHarmonyBatchResult(byte[] payload) {
        int level = payload[1] & 0xFF;
        int roundId = ByteBuffer.wrap(payload, 2, 2).order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        int numBuckets = ByteBuffer.wrap(payload, 4, 2).order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;
        int subResultsPerBucket = payload[6] & 0xFF;

        int pos = 7;
        HarmonyBatchResultItem[] items = new HarmonyBatchResultItem[numBuckets];
        for (int b = 0; b < numBuckets; b++) {
            int bucketId = payload[pos] & 0xFF;
            pos++;
            byte[][] subResults = new byte[subResultsPerBucket][];
            for (int sr = 0; sr < subResultsPerBucket; sr++) {
                int dataLen = ByteBuffer.wrap(payload, pos, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
                pos += 4;
                subResults[sr] = new byte[dataLen];
                System.arraycopy(payload, pos, subResults[sr], 0, dataLen);
                pos += dataLen;
            }
            items[b] = new HarmonyBatchResultItem(bucketId, subResults);
        }
        return new HarmonyBatchResult(level, roundId, items);
    }

    // ── OnionPIR ────────────────────────────────────────────────────────────

    /**
     * Encode an OnionPIR key registration request.
     */
    public static byte[] encodeOnionPirRegisterKeys(byte[] galoisKeys, byte[] gswKeys) {
        int payloadSize = 1 + 4 + galoisKeys.length + 4 + gswKeys.length;
        byte[] payload = new byte[payloadSize];
        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(PirConstants.REQ_REGISTER_KEYS);
        bb.putInt(galoisKeys.length);
        bb.put(galoisKeys);
        bb.putInt(gswKeys.length);
        bb.put(gswKeys);
        return frame(payload);
    }

    /**
     * Encode an OnionPIR index or chunk query request.
     *
     * @param variant  REQ_ONIONPIR_INDEX_QUERY or REQ_ONIONPIR_CHUNK_QUERY
     * @param roundId  round identifier
     * @param queries  FHE-encrypted queries
     */
    public static byte[] encodeOnionPirQuery(byte variant, int roundId, byte[][] queries) {
        int payloadSize = 1 + 2 + 1; // variant + roundId + numQueries
        for (byte[] q : queries) {
            payloadSize += 4 + q.length;
        }

        byte[] payload = new byte[payloadSize];
        ByteBuffer bb = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN);
        bb.put(variant);
        bb.putShort((short) roundId);
        bb.put((byte) queries.length);
        for (byte[] q : queries) {
            bb.putInt(q.length);
            bb.put(q);
        }
        return frame(payload);
    }

    /** Decode an OnionPIR query result. */
    public static byte[][] decodeOnionPirResult(byte[] payload) {
        ByteBuffer bb = ByteBuffer.wrap(payload, 1, payload.length - 1).order(ByteOrder.LITTLE_ENDIAN);
        int roundId = bb.getShort() & 0xFFFF;
        int numResults = bb.get() & 0xFF;
        byte[][] results = new byte[numResults][];
        for (int i = 0; i < numResults; i++) {
            int len = bb.getInt();
            results[i] = new byte[len];
            bb.get(results[i]);
        }
        return results;
    }

    // ── Error ────────────────────────────────────────────────────────────────

    /** Decode an error message from payload. */
    public static String decodeError(byte[] payload) {
        if (payload.length < 5) return "Unknown error";
        int msgLen = ByteBuffer.wrap(payload, 1, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        return new String(payload, 5, Math.min(msgLen, payload.length - 5));
    }
}
