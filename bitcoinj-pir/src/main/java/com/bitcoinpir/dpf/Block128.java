package com.bitcoinpir.dpf;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * 128-bit block represented as two 64-bit longs (high, low).
 * Memory layout matches the C / TypeScript / Python implementation:
 *   bytes 0-7  = low  (little-endian uint64)
 *   bytes 8-15 = high (little-endian uint64)
 */
public record Block128(long high, long low) {

    public static final Block128 ZERO = new Block128(0, 0);

    public static Block128 fromBytes(byte[] data, int offset) {
        ByteBuffer bb = ByteBuffer.wrap(data, offset, 16).order(ByteOrder.LITTLE_ENDIAN);
        long lo = bb.getLong();
        long hi = bb.getLong();
        return new Block128(hi, lo);
    }

    public static Block128 fromBytes(byte[] data) {
        return fromBytes(data, 0);
    }

    public byte[] toBytes() {
        byte[] out = new byte[16];
        ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN).putLong(low).putLong(high);
        return out;
    }

    public void toBytes(byte[] dst, int offset) {
        ByteBuffer.wrap(dst, offset, 16).order(ByteOrder.LITTLE_ENDIAN).putLong(low).putLong(high);
    }

    public Block128 xor(Block128 other) {
        return new Block128(high ^ other.high, low ^ other.low);
    }

    public int lsb() {
        return (int) (low & 1);
    }

    public Block128 reverseLsb() {
        return new Block128(high, low ^ 1);
    }

    public Block128 setLsbZero() {
        return (low & 1) == 1 ? reverseLsb() : this;
    }

    public Block128 leftShift(int n) {
        if (n == 0) return this;
        if (n >= 128) return ZERO;
        if (n >= 64) {
            return new Block128(low << (n - 64), 0);
        }
        long newLow = low << n;
        long newHigh = (high << n) | (low >>> (64 - n));
        return new Block128(newHigh, newLow);
    }
}
