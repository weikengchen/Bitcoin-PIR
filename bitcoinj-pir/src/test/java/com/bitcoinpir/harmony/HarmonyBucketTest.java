package com.bitcoinpir.harmony;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link HarmonyBucket}.
 *
 * <p>The JNI-dependent tests are skipped if the native library isn't
 * available (e.g. on CI without the Rust build). Run the pure-Java
 * tests unconditionally.
 */
class HarmonyBucketTest {

    // ── Pure Java helper tests (no native library required) ─────────────

    @Test
    void testFindBestT() {
        // For n=8, 2n=16, sqrt(16)=4. 4 divides 16 → T=4.
        assertEquals(4, HarmonyBucket.findBestT(8));

        // For n=1<<20, 2n=2^21, sqrt(2^21)≈1448. T should divide 2^21.
        int t = HarmonyBucket.findBestT(1 << 20);
        assertEquals(0, (2 * (1 << 20)) % t, "T must divide 2N");
    }

    @Test
    void testComputeRounds() {
        // Rounds must be a multiple of 4.
        int r = HarmonyBucket.computeRounds(64);
        assertEquals(0, r % 4);
        assertTrue(r >= 44, "rounds should be >= ceil(log2(128)) + 40 = 47 → 48");
    }

    @Test
    void testFindNearbyDivisor() {
        assertEquals(4, HarmonyBucket.findNearbyDivisor(16, 4));
        assertEquals(4, HarmonyBucket.findNearbyDivisor(16, 5)); // 5 doesn't divide 16, 4 does
        assertEquals(1, HarmonyBucket.findNearbyDivisor(7, 3));  // 7 is prime, only 1 and 7
    }

    @Test
    void testCeilLog2() {
        assertEquals(0, HarmonyBucket.ceilLog2(1));
        assertEquals(1, HarmonyBucket.ceilLog2(2));
        assertEquals(4, HarmonyBucket.ceilLog2(16));
        assertEquals(5, HarmonyBucket.ceilLog2(17));
        assertEquals(7, HarmonyBucket.ceilLog2(128));
        assertEquals(8, HarmonyBucket.ceilLog2(129));
    }

    // ── JNI-dependent tests ─────────────────────────────────────────────

    private void assumeNative() {
        Assumptions.assumeTrue(HarmonyBucket.isNativeLoaded(),
            "harmonypir_jni native library not available — skipping JNI test");
    }

    @Test
    void testCreateAndClose() {
        assumeNative();
        byte[] key = new byte[16];
        java.util.Arrays.fill(key, (byte) 0x42);

        try (var bucket = new HarmonyBucket(64, 32, 8, key, 0, HarmonyBucket.PRP_HOANG)) {
            assertTrue(bucket.getM() > 0, "m should be positive");
            assertTrue(bucket.getMaxQueries() > 0, "maxQueries should be positive");
            assertEquals(32, bucket.getW());
        }
    }

    @Test
    void testAutoComputeT() {
        assumeNative();
        byte[] key = new byte[16];
        java.util.Arrays.fill(key, (byte) 0xAB);

        try (var bucket = new HarmonyBucket(1024, 40, 0, key, 0, HarmonyBucket.PRP_HOANG)) {
            int t = bucket.getT();
            int n = bucket.getN();
            assertEquals(0, (2 * n) % t, "T must divide 2N");
            assertTrue(t > 1, "auto-computed T should be > 1");
        }
    }

    @Test
    void testBuildDummy() {
        assumeNative();
        byte[] key = new byte[16];
        java.util.Arrays.fill(key, (byte) 0xCD);

        try (var bucket = new HarmonyBucket(64, 32, 8, key, 0, HarmonyBucket.PRP_HOANG)) {
            // Load zero hints so we can call buildDummy.
            int hintSize = bucket.getM() * bucket.getW();
            bucket.loadHints(new byte[hintSize]);

            byte[] dummy = bucket.buildSyntheticDummy();
            assertNotNull(dummy);
            assertTrue(dummy.length > 0, "dummy should have at least one index");
            assertEquals(0, dummy.length % 4, "dummy must be a sequence of u32 LE");
        }
    }

    @Test
    void testInvalidKeyLength() {
        assumeNative();
        assertThrows(IllegalArgumentException.class,
            () -> new HarmonyBucket(64, 32, 8, new byte[8], 0));
    }

    @Test
    void testNullKey() {
        assumeNative();
        assertThrows(IllegalArgumentException.class,
            () -> new HarmonyBucket(64, 32, 8, null, 0));
    }

    @Test
    void testUseAfterClose() {
        assumeNative();
        byte[] key = new byte[16];
        var bucket = new HarmonyBucket(64, 32, 8, key, 0, HarmonyBucket.PRP_HOANG);
        bucket.close();
        assertThrows(IllegalStateException.class, () -> bucket.getM());
    }
}
