package com.bitcoinpir.dpf;

/**
 * A DPF key for evaluation.
 *
 * Key format (matching C / TypeScript / Rust / Python):
 *   Byte 0:            n  (domain parameter)
 *   Bytes 1-16:        s0 (initial seed block, 16 bytes)
 *   Byte 17:           t0 (initial control bit)
 *   For each layer i in 1..maxlayer:
 *     Bytes [18*i .. 18*i+16):  scw[i-1]       (correction word block)
 *     Byte  18*i+16:            tcw[i-1][0]     (left correction bit)
 *     Byte  18*i+17:            tcw[i-1][1]     (right correction bit)
 *   Final 16 bytes:    finalBlock
 */
public final class DpfKey {
    public final int n;
    public final Block128 s0;
    public final int t0;
    public final Block128[] scw;
    public final int[][] tcw; // tcw[i] = {left, right}
    public final Block128 finalBlock;

    public DpfKey(int n, Block128 s0, int t0, Block128[] scw, int[][] tcw, Block128 finalBlock) {
        this.n = n;
        this.s0 = s0;
        this.t0 = t0;
        this.scw = scw;
        this.tcw = tcw;
        this.finalBlock = finalBlock;
    }

    public int maxLayer() {
        return n - 7;
    }

    public int size() {
        return 1 + 16 + 1 + 18 * maxLayer() + 16;
    }

    public byte[] toBytes() {
        byte[] buf = new byte[size()];
        buf[0] = (byte) n;
        s0.toBytes(buf, 1);
        buf[17] = (byte) t0;

        int ml = maxLayer();
        for (int i = 0; i < ml; i++) {
            int off = 18 * (i + 1);
            scw[i].toBytes(buf, off);
            buf[off + 16] = (byte) tcw[i][0];
            buf[off + 17] = (byte) tcw[i][1];
        }

        int finalOff = 18 * (ml + 1);
        finalBlock.toBytes(buf, finalOff);
        return buf;
    }

    public static DpfKey fromBytes(byte[] data) {
        int n = data[0] & 0xFF;
        int ml = n - 7;

        Block128 s0 = Block128.fromBytes(data, 1);
        int t0 = data[17] & 0xFF;

        Block128[] scw = new Block128[ml];
        int[][] tcw = new int[ml][2];
        for (int i = 0; i < ml; i++) {
            int off = 18 * (i + 1);
            scw[i] = Block128.fromBytes(data, off);
            tcw[i][0] = data[off + 16] & 0xFF;
            tcw[i][1] = data[off + 17] & 0xFF;
        }

        int finalOff = 18 * (ml + 1);
        Block128 fb = Block128.fromBytes(data, finalOff);
        return new DpfKey(n, s0, t0, scw, tcw, fb);
    }
}
