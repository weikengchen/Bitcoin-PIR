package com.bitcoinpir;

import com.bitcoinpir.codec.UtxoDecoder;
import com.bitcoinpir.dpf.Block128;
import com.bitcoinpir.dpf.DpfKey;
import com.bitcoinpir.dpf.DpfKeyGen;
import com.bitcoinpir.dpf.DpfPirClient;
import com.bitcoinpir.hash.CuckooHash;
import com.bitcoinpir.hash.PirHash;
import com.bitcoinpir.placement.PbcPlanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the bitcoinj PIR integration library.
 *
 * Unit tests run without network access.
 * Integration tests (marked @Disabled by default) require live PIR servers.
 */
class PirUtxoProviderTest {

    // ── Unit: splitmix64 ────────────────────────────────────────────────────

    @Test
    void testSplitmix64KnownValues() {
        // splitmix64(0) = 0 because XOR with right-shift of 0 stays 0,
        // and multiplication by any constant stays 0.
        assertEquals(0, PirHash.splitmix64(0));

        // splitmix64 is deterministic
        long r1 = PirHash.splitmix64(1);
        assertEquals(r1, PirHash.splitmix64(1));

        // Non-zero input produces non-zero output
        assertNotEquals(0, r1);

        // Different inputs produce different outputs
        assertNotEquals(PirHash.splitmix64(1), PirHash.splitmix64(2));
    }

    // ── Unit: deriveBuckets ─────────────────────────────────────────────────

    @Test
    void testDeriveBucketsProduces3Distinct() {
        byte[] scriptHash = new byte[20];
        scriptHash[0] = 0x42;
        scriptHash[7] = (byte) 0xAB;

        int[] buckets = PirHash.deriveBuckets(scriptHash);
        assertEquals(3, buckets.length);

        // All distinct
        assertNotEquals(buckets[0], buckets[1]);
        assertNotEquals(buckets[0], buckets[2]);
        assertNotEquals(buckets[1], buckets[2]);

        // All in range [0, K)
        for (int b : buckets) {
            assertTrue(b >= 0 && b < PirConstants.K, "bucket " + b + " out of range");
        }
    }

    @Test
    void testDeriveChunkBucketsProduces3Distinct() {
        int[] buckets = PirHash.deriveChunkBuckets(12345);
        assertEquals(3, buckets.length);
        assertNotEquals(buckets[0], buckets[1]);
        assertNotEquals(buckets[0], buckets[2]);
        assertNotEquals(buckets[1], buckets[2]);
        for (int b : buckets) {
            assertTrue(b >= 0 && b < PirConstants.K_CHUNK);
        }
    }

    // ── Unit: computeTag ────────────────────────────────────────────────────

    @Test
    void testComputeTagDeterministic() {
        byte[] scriptHash = new byte[20];
        for (int i = 0; i < 20; i++) scriptHash[i] = (byte) i;

        long tag1 = PirHash.computeTag(0x1234567890ABCDEFL, scriptHash);
        long tag2 = PirHash.computeTag(0x1234567890ABCDEFL, scriptHash);
        assertEquals(tag1, tag2);

        // Different seed → different tag
        long tag3 = PirHash.computeTag(0xFEDCBA0987654321L, scriptHash);
        assertNotEquals(tag1, tag3);
    }

    // ── Unit: CuckooHash ────────────────────────────────────────────────────

    @Test
    void testCuckooHashInRange() {
        byte[] scriptHash = new byte[20];
        scriptHash[0] = 0x55;

        long key = CuckooHash.deriveCuckooKey(5, 0);
        int bin = CuckooHash.cuckooHash(scriptHash, key, 1_000_000);
        assertTrue(bin >= 0 && bin < 1_000_000);
    }

    @Test
    void testCuckooHashIntInRange() {
        long key = CuckooHash.deriveChunkCuckooKey(3, 1);
        int bin = CuckooHash.cuckooHashInt(999, key, 2_000_000);
        assertTrue(bin >= 0 && bin < 2_000_000);
    }

    // ── Unit: Block128 ──────────────────────────────────────────────────────

    @Test
    void testBlock128RoundTrip() {
        Block128 block = new Block128(0x123456789ABCDEF0L, 0xFEDCBA9876543210L);
        byte[] bytes = block.toBytes();
        assertEquals(16, bytes.length);

        Block128 restored = Block128.fromBytes(bytes);
        assertEquals(block.high(), restored.high());
        assertEquals(block.low(), restored.low());
    }

    @Test
    void testBlock128Xor() {
        Block128 a = new Block128(0xFF, 0xFF);
        Block128 b = new Block128(0x0F, 0xF0);
        Block128 c = a.xor(b);
        assertEquals(0xF0, c.high());
        assertEquals(0x0F, c.low());
    }

    @Test
    void testBlock128Lsb() {
        assertEquals(0, new Block128(0, 0).lsb());
        assertEquals(1, new Block128(0, 1).lsb());
        assertEquals(0, new Block128(0, 2).lsb());
        assertEquals(1, new Block128(0, 3).lsb());
    }

    // ── Unit: DPF key generation ────────────────────────────────────────────

    @Test
    void testDpfKeyGenRoundTrip() {
        DpfKeyGen gen = new DpfKeyGen();
        DpfKey[] keys = gen.gen(42, PirConstants.DPF_N);

        // Both keys should serialize and deserialize correctly
        byte[] k0bytes = keys[0].toBytes();
        byte[] k1bytes = keys[1].toBytes();

        DpfKey k0restored = DpfKey.fromBytes(k0bytes);
        DpfKey k1restored = DpfKey.fromBytes(k1bytes);

        assertEquals(keys[0].n, k0restored.n);
        assertEquals(keys[1].n, k1restored.n);
        assertEquals(PirConstants.DPF_N, k0restored.n);
    }

    @Test
    void testDpfKeySize() {
        DpfKeyGen gen = new DpfKeyGen();
        DpfKey[] keys = gen.gen(0, PirConstants.DPF_N);

        // Expected size: 1 + 16 + 1 + 18 * (20-7) + 16 = 34 + 18*13 = 268
        int expectedSize = 1 + 16 + 1 + 18 * (PirConstants.DPF_N - 7) + 16;
        assertEquals(expectedSize, keys[0].size());
        assertEquals(expectedSize, keys[0].toBytes().length);
    }

    // ── Unit: PBC planning ──────────────────────────────────────────────────

    @Test
    void testPbcPlannerSingleItem() {
        int[][] itemBuckets = {{0, 5, 10}};
        var rounds = PbcPlanner.planRounds(itemBuckets, PirConstants.K);
        assertEquals(1, rounds.size());
        assertEquals(1, rounds.get(0).length);
    }

    @Test
    void testPbcPlannerMultipleItems() {
        // 10 items with random buckets
        int[][] itemBuckets = new int[10][];
        for (int i = 0; i < 10; i++) {
            byte[] hash = new byte[20];
            hash[0] = (byte) i;
            itemBuckets[i] = PirHash.deriveBuckets(hash);
        }

        var rounds = PbcPlanner.planRounds(itemBuckets, PirConstants.K);
        assertFalse(rounds.isEmpty());

        // All 10 items should be placed across all rounds
        java.util.Set<Integer> placedItems = new java.util.HashSet<>();
        for (var round : rounds) {
            for (int[] entry : round) {
                placedItems.add(entry[0]);
            }
        }
        assertEquals(10, placedItems.size());
    }

    // ── Unit: Varint ────────────────────────────────────────────────────────

    @Test
    void testVarintDecode() {
        // Single byte: 0x05 = 5
        long[] r1 = com.bitcoinpir.codec.Varint.read(new byte[]{0x05}, 0);
        assertEquals(5, r1[0]);
        assertEquals(1, r1[1]);

        // Two bytes: 0x80 0x01 = 128
        long[] r2 = com.bitcoinpir.codec.Varint.read(new byte[]{(byte) 0x80, 0x01}, 0);
        assertEquals(128, r2[0]);
        assertEquals(2, r2[1]);

        // 0xAC 0x02 = 300
        long[] r3 = com.bitcoinpir.codec.Varint.read(new byte[]{(byte) 0xAC, 0x02}, 0);
        assertEquals(300, r3[0]);
        assertEquals(2, r3[1]);
    }

    // ── Unit: UtxoDecoder ───────────────────────────────────────────────────

    @Test
    void testUtxoDecoderEmpty() {
        // numEntries = 0
        byte[] data = {0x00};
        var result = UtxoDecoder.decode(data);
        assertTrue(result.entries().isEmpty());
        assertEquals(0, result.totalSats());
    }

    // ── Unit: hex utilities ─────────────────────────────────────────────────

    @Test
    void testHexRoundTrip() {
        byte[] original = {0x00, 0x01, (byte) 0xAB, (byte) 0xFF};
        String hex = PirHash.bytesToHex(original);
        assertEquals("0001abff", hex);

        byte[] restored = PirHash.hexToBytes(hex);
        assertArrayEquals(original, restored);
    }

    // ── Integration: DPF query against live servers ─────────────────────────

    @Disabled("Requires live PIR servers — enable manually for integration testing")
    @Test
    void testDpfQueryLiveServers() throws Exception {
        try (var client = new DpfPirClient(
                PirConstants.DEFAULT_DPF_SERVER0_URL,
                PirConstants.DEFAULT_DPF_SERVER1_URL)) {

            client.connect();
            assertTrue(client.isConnected());

            // Query a known address that should have UTXOs
            // Use Satoshi's address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
            // scriptPubKey: 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
            byte[] spk = PirHash.hexToBytes("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac");
            byte[] hash = PirHash.hash160(spk);

            Map<Integer, List<UtxoDecoder.UtxoEntry>> results = client.queryBatch(List.of(hash));
            assertNotNull(results.get(0));
            // Satoshi's address is likely a whale (>100 UTXOs), so may be empty
        }
    }

    @Disabled("Requires live PIR servers — enable manually for integration testing")
    @Test
    void testPirUtxoProviderWithBitcoinj() throws Exception {
        try (var provider = new PirUtxoProvider(new PirBackendConfig.Dpf())) {
            provider.connect();

            int height = provider.getChainHeadHeight();
            assertTrue(height > 800_000, "Chain height should be recent");

            assertEquals(org.bitcoinj.base.BitcoinNetwork.MAINNET, provider.network());
        }
    }
}
