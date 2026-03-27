package com.bitcoinpir.codec;

/**
 * LEB128 variable-length integer encoding/decoding.
 * Matches the varint format used in UTXO chunk data.
 */
public final class Varint {
    private Varint() {}

    /**
     * Read a LEB128-encoded unsigned varint from {@code data} starting at {@code offset}.
     *
     * @return array of [value, bytesRead]
     */
    public static long[] read(byte[] data, int offset) {
        long result = 0;
        int shift = 0;
        int bytesRead = 0;

        while (true) {
            if (offset + bytesRead >= data.length) {
                throw new IllegalArgumentException("Unexpected end of data in varint");
            }
            int b = data[offset + bytesRead] & 0xFF;
            bytesRead++;
            result |= (long) (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
            if (shift >= 64) {
                throw new IllegalArgumentException("VarInt too large");
            }
        }
        return new long[]{result, bytesRead};
    }
}
