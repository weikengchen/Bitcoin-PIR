package com.bitcoinpir.dpf;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * DPF (Distributed Point Function) key generation.
 * Implements the Boyle et al. CCS'16 construction using AES-128-ECB as PRG.
 *
 * Produces keys that are byte-identical to the TypeScript, Python, and Rust implementations.
 */
public final class DpfKeyGen {
    // Default AES key (from C implementation)
    private static final long DEFAULT_KEY_HIGH = 597349;
    private static final long DEFAULT_KEY_LOW = 121379;

    private final Cipher aesCipher;
    private final SecureRandom rng = new SecureRandom();

    public DpfKeyGen() {
        this(new Block128(DEFAULT_KEY_HIGH, DEFAULT_KEY_LOW));
    }

    public DpfKeyGen(Block128 aesKey) {
        try {
            aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
            aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey.toBytes(), "AES"));
        } catch (Exception e) {
            throw new RuntimeException("Failed to init AES cipher", e);
        }
    }

    /** AES-ECB encrypt a single 16-byte block. */
    private Block128 aesEncrypt(Block128 block) {
        try {
            byte[] ct = aesCipher.doFinal(block.toBytes());
            return Block128.fromBytes(ct);
        } catch (Exception e) {
            throw new RuntimeException("AES encryption failed", e);
        }
    }

    /**
     * PRG: expand one seed block into two output blocks and two control bits.
     *
     * @return {output0, output1, bit0, bit1} encoded as PrgOutput
     */
    private PrgOutput prg(Block128 input) {
        Block128 stash0 = input.setLsbZero();
        Block128 stash1 = stash0.reverseLsb();

        stash0 = aesEncrypt(stash0);
        stash1 = aesEncrypt(stash1);

        Block128 inputZeroed = input.setLsbZero();
        stash0 = stash0.xor(inputZeroed);
        stash1 = stash1.xor(inputZeroed);
        stash1 = stash1.reverseLsb();

        int bit0 = stash0.lsb();
        int bit1 = stash1.lsb();

        Block128 output0 = stash0.setLsbZero();
        Block128 output1 = stash1.setLsbZero();

        return new PrgOutput(output0, output1, bit0, bit1);
    }

    /** Get bit b (1-indexed from MSB side) of an n-bit value x. */
    private static int getBit(int x, int n, int b) {
        return (x >> (n - b)) & 1;
    }

    /**
     * Generate two DPF keys for a point function where f(alpha) = 1.
     *
     * @param alpha target index (the point where f evaluates to 1)
     * @param n     domain parameter — domain size is 2^n
     * @return pair of DPF keys [k0, k1]
     */
    public DpfKey[] gen(int alpha, int n) {
        int maxlayer = n - 7;

        // Seeds and control bits per layer, for both parties
        Block128[][] s = new Block128[maxlayer + 1][2];
        int[][] t = new int[maxlayer + 1][2];
        for (int i = 0; i <= maxlayer; i++) {
            s[i][0] = Block128.ZERO;
            s[i][1] = Block128.ZERO;
        }

        // Correction words
        Block128[] scw = new Block128[maxlayer];
        int[][] tcw = new int[maxlayer][2];

        // Random initial seeds
        byte[] rand0 = new byte[16], rand1 = new byte[16];
        rng.nextBytes(rand0);
        rng.nextBytes(rand1);
        s[0][0] = Block128.fromBytes(rand0);
        s[0][1] = Block128.fromBytes(rand1);

        // Initial control bits
        t[0][0] = s[0][0].lsb();
        t[0][1] = t[0][0] ^ 1;

        // Zero LSBs of initial seeds
        s[0][0] = s[0][0].setLsbZero();
        s[0][1] = s[0][1].setLsbZero();

        // Iterate through layers
        for (int i = 1; i <= maxlayer; i++) {
            PrgOutput prg0 = prg(s[i - 1][0]);
            PrgOutput prg1 = prg(s[i - 1][1]);

            int alphaBit = getBit(alpha, n, i);
            int keep = alphaBit;
            int lose = 1 - keep;

            Block128[] s0 = {prg0.output0, prg0.output1};
            Block128[] s1 = {prg1.output0, prg1.output1};
            int[] t0 = {prg0.bit0, prg0.bit1};
            int[] t1 = {prg1.bit0, prg1.bit1};

            // Correction word for seeds
            scw[i - 1] = s0[lose].xor(s1[lose]);

            // Correction bits
            tcw[i - 1][0] = t0[0] ^ t1[0] ^ alphaBit ^ 1;
            tcw[i - 1][1] = t0[1] ^ t1[1] ^ alphaBit;

            // Propagate for party 0
            if (t[i - 1][0] == 1) {
                s[i][0] = s0[keep].xor(scw[i - 1]);
                t[i][0] = t0[keep] ^ tcw[i - 1][keep];
            } else {
                s[i][0] = s0[keep];
                t[i][0] = t0[keep];
            }

            // Propagate for party 1
            if (t[i - 1][1] == 1) {
                s[i][1] = s1[keep].xor(scw[i - 1]);
                t[i][1] = t1[keep] ^ tcw[i - 1][keep];
            } else {
                s[i][1] = s1[keep];
                t[i][1] = t1[keep];
            }
        }

        // Compute final correction block
        Block128 finalBlock = Block128.ZERO.reverseLsb(); // block with LSB = 1
        int shift = alpha & 127;
        finalBlock = finalBlock.leftShift(shift);
        finalBlock = finalBlock.reverseLsb();

        // XOR with final seeds
        finalBlock = finalBlock.xor(s[maxlayer][0]);
        finalBlock = finalBlock.xor(s[maxlayer][1]);

        // Build keys
        DpfKey k0 = new DpfKey(n, s[0][0], t[0][0], scw.clone(), cloneTcw(tcw), finalBlock);
        DpfKey k1 = new DpfKey(n, s[0][1], t[0][1], scw.clone(), cloneTcw(tcw), finalBlock);
        return new DpfKey[]{k0, k1};
    }

    private static int[][] cloneTcw(int[][] tcw) {
        int[][] copy = new int[tcw.length][2];
        for (int i = 0; i < tcw.length; i++) {
            copy[i][0] = tcw[i][0];
            copy[i][1] = tcw[i][1];
        }
        return copy;
    }

    // ── Inner types ──────────────────────────────────────────────────────────

    private record PrgOutput(Block128 output0, Block128 output1, int bit0, int bit1) {}
}
