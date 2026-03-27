package com.bitcoinpir.codec;

import com.bitcoinpir.PirConstants;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * Decodes UTXO data from PIR chunk results.
 */
public final class UtxoDecoder {
    private UtxoDecoder() {}

    /** A single UTXO entry parsed from chunk data. */
    public record UtxoEntry(byte[] txid, int vout, long amount) {}

    /** Result of decoding chunk data: list of entries and total satoshis. */
    public record DecodeResult(List<UtxoEntry> entries, long totalSats) {}

    /**
     * Decode UTXO entries from raw chunk data.
     * Format: [varint numEntries] [32B txid][varint vout][varint amount] × numEntries
     */
    public static DecodeResult decode(byte[] data) {
        int pos = 0;
        long[] vr = Varint.read(data, pos);
        int numEntries = (int) vr[0];
        pos += (int) vr[1];

        List<UtxoEntry> entries = new ArrayList<>(numEntries);
        long totalSats = 0;

        for (int i = 0; i < numEntries; i++) {
            if (pos + 32 > data.length) break;

            byte[] txid = new byte[32];
            System.arraycopy(data, pos, txid, 0, 32);
            pos += 32;

            long[] voutVr = Varint.read(data, pos);
            int vout = (int) voutVr[0];
            pos += (int) voutVr[1];

            long[] amountVr = Varint.read(data, pos);
            long amount = amountVr[0];
            pos += (int) amountVr[1];

            totalSats += amount;
            entries.add(new UtxoEntry(txid, vout, amount));
        }
        return new DecodeResult(entries, totalSats);
    }

    /**
     * Scan an index-level result (39 bytes = 3 slots × 13 bytes) for a matching tag.
     *
     * @return int[2] = {startChunkId, numChunks}, or null if not found
     */
    public static int[] findEntryInIndexResult(byte[] result, long expectedTag) {
        for (int slot = 0; slot < PirConstants.CUCKOO_BUCKET_SIZE; slot++) {
            int base = slot * PirConstants.INDEX_ENTRY_SIZE;
            ByteBuffer bb = ByteBuffer.wrap(result, base, PirConstants.INDEX_ENTRY_SIZE)
                    .order(ByteOrder.LITTLE_ENDIAN);
            long slotTag = bb.getLong();
            if (slotTag == expectedTag) {
                int startChunkId = bb.getInt();
                int numChunks = result[base + PirConstants.TAG_SIZE + 4] & 0xFF;
                return new int[]{startChunkId, numChunks};
            }
        }
        return null;
    }

    /**
     * Scan a chunk-level result (132 bytes = 3 slots × 44 bytes) for a matching chunk_id.
     *
     * @return the 40-byte chunk data, or null if not found
     */
    public static byte[] findChunkInResult(byte[] result, int chunkId) {
        for (int slot = 0; slot < PirConstants.CHUNK_CUCKOO_BUCKET_SIZE; slot++) {
            int base = slot * PirConstants.CHUNK_SLOT_SIZE;
            int resultChunkId = ByteBuffer.wrap(result, base, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt();
            if (resultChunkId == chunkId) {
                byte[] data = new byte[PirConstants.CHUNK_SIZE];
                System.arraycopy(result, base + 4, data, 0, PirConstants.CHUNK_SIZE);
                return data;
            }
        }
        return null;
    }
}
