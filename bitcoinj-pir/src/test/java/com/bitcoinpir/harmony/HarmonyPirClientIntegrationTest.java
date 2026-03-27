package com.bitcoinpir.harmony;

import com.bitcoinpir.PirConstants;
import com.bitcoinpir.codec.ProtocolCodec;
import com.bitcoinpir.codec.UtxoDecoder;
import com.bitcoinpir.hash.PirHash;
import com.bitcoinpir.net.PirWebSocket;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for HarmonyPIR client against live servers.
 *
 * Requires:
 *   - Hint server at ws://localhost:8094
 *   - Query server at ws://localhost:8095
 *   - Native library (harmonypir_jni) available
 *
 * Enable tests manually when servers are running.
 */
class HarmonyPirClientIntegrationTest {

    private static final String HINT_SERVER = "ws://localhost:8094";
    private static final String QUERY_SERVER = "ws://localhost:8095";

    // ── Connectivity test ────────────────────────────────────────────────

    @Disabled("Requires live HarmonyPIR servers — enable manually for integration testing")
    @Test
    void testConnectAndGetInfo() throws Exception {
        try (var ws = new PirWebSocket(QUERY_SERVER)) {
            ws.connect();
            assertTrue(ws.isConnected(), "WebSocket should be connected");

            // Send GetInfo request
            byte[] infoPayload = ws.sendSync(ProtocolCodec.encodeHarmonyGetInfo());
            assertNotNull(infoPayload, "GetInfo response should not be null");

            var info = ProtocolCodec.decodeServerInfo(infoPayload);
            assertEquals(PirConstants.K, info.indexK(), "indexK should be 75");
            assertEquals(PirConstants.K_CHUNK, info.chunkK(), "chunkK should be 80");
            assertTrue(info.indexBins() > 0, "indexBins should be positive");
            assertTrue(info.chunkBins() > 0, "chunkBins should be positive");
            assertTrue(info.tagSeed() != 0, "tagSeed should be non-zero");

            System.out.printf("Server info: indexBins=%d chunkBins=%d indexK=%d chunkK=%d tagSeed=0x%016x%n",
                    info.indexBins(), info.chunkBins(), info.indexK(), info.chunkK(), info.tagSeed());
        }
    }

    // ── Hint download test ───────────────────────────────────────────────

    @Disabled("Requires live HarmonyPIR servers — enable manually for integration testing")
    @Test
    void testHintDownloadSingleBucket() throws Exception {
        assumeNative();

        byte[] prpKey = new byte[16];
        new java.security.SecureRandom().nextBytes(prpKey);

        // Download hint for bucket 0 first (to learn server's T and padded_n)
        int serverPrp = PirConstants.SERVER_PRP_ALF;
        byte[] hintReq = ProtocolCodec.encodeHarmonyHintRequest(
                prpKey, serverPrp, 0, new int[]{0});

        ProtocolCodec.HintData hint;
        try (var hintWs = new PirWebSocket(HINT_SERVER)) {
            hintWs.connect();
            var futures = hintWs.sendExpectingN(hintReq, 1);
            byte[] payload = futures.get(0).get();
            hint = ProtocolCodec.decodeHarmonyHintResponse(payload);
        }

        assertEquals(0, hint.bucketId(), "bucket id should match");
        assertTrue(hint.hintBytes().length > 0, "hint data should not be empty");
        System.out.printf("Hint for bucket 0: n=%d t=%d m=%d data=%d bytes%n",
                hint.n(), hint.t(), hint.m(), hint.hintBytes().length);

        // Create bucket using server's (padded_n, t) to ensure parameters match
        try (var bucket = new HarmonyBucket(hint.n(), PirConstants.HARMONY_INDEX_W, hint.t(),
                prpKey, 0, HarmonyBucket.PRP_ALF)) {

            int m = bucket.getM();
            int w = bucket.getW();
            System.out.printf("Bucket 0: n=%d t=%d m=%d w=%d%n", bucket.getN(), bucket.getT(), m, w);

            assertEquals(hint.m(), m, "m should match server's m");
            assertEquals(m * w, hint.hintBytes().length,
                    "hint size should be m*w = " + (m * w));

            // Load hints
            bucket.loadHints(hint.hintBytes());

            // Build a dummy request (verifies internal state is valid)
            byte[] dummy = bucket.buildSyntheticDummy();
            assertNotNull(dummy, "dummy request should not be null");
            assertTrue(dummy.length > 0, "dummy request should have content");
            assertEquals(0, dummy.length % 4, "dummy request must be multiple of 4 bytes");

            System.out.printf("Dummy request: %d indices%n", dummy.length / 4);
        }
    }

    // ── Single-bucket query round-trip ───────────────────────────────────

    @Disabled("Requires live HarmonyPIR servers — enable manually for integration testing")
    @Test
    void testSingleBucketQueryRoundTrip() throws Exception {
        assumeNative();

        byte[] prpKey = new byte[16];
        new java.security.SecureRandom().nextBytes(prpKey);

        int indexBins;
        try (var ws = new PirWebSocket(QUERY_SERVER)) {
            ws.connect();
            var info = ProtocolCodec.decodeServerInfo(
                    ws.sendSync(ProtocolCodec.encodeHarmonyGetInfo()));
            indexBins = info.indexBins();
        }

        try (var bucket = new HarmonyBucket(indexBins, PirConstants.HARMONY_INDEX_W, 0, prpKey, 0,
                HarmonyBucket.PRP_ALF)) {

            // Download and load hints
            try (var hintWs = new PirWebSocket(HINT_SERVER)) {
                hintWs.connect();
                var futures = hintWs.sendExpectingN(
                        ProtocolCodec.encodeHarmonyHintRequest(
                                prpKey, PirConstants.SERVER_PRP_ALF, 0, new int[]{0}), 1);
                var hint = ProtocolCodec.decodeHarmonyHintResponse(futures.get(0).get());
                bucket.loadHints(hint.hintBytes());
            }

            // Build a real request for bin 0
            byte[] request = bucket.buildRequest(0);
            assertNotNull(request);
            assertTrue(request.length > 0);
            int indexCount = request.length / 4;
            System.out.printf("Request for bin 0: %d indices%n", indexCount);

            // Send to query server as a batch of 1 bucket
            try (var queryWs = new PirWebSocket(QUERY_SERVER)) {
                queryWs.connect();
                byte[] batchMsg = ProtocolCodec.encodeHarmonyBatchQuery(
                        0, 0, 1, new int[]{0}, new byte[][]{request});
                byte[] batchResp = queryWs.sendSync(batchMsg);

                var result = ProtocolCodec.decodeHarmonyBatchResult(batchResp);
                assertEquals(1, result.items().length, "should have 1 bucket result");
                assertEquals(0, result.items()[0].bucketId(), "bucket id should be 0");

                byte[] responseData = result.items()[0].subResults()[0];
                assertEquals(indexCount * PirConstants.HARMONY_INDEX_W, responseData.length,
                        "response should be indexCount * w bytes");

                // Process the response to recover the entry
                byte[] entry = bucket.processResponse(responseData);
                assertNotNull(entry);
                assertEquals(PirConstants.HARMONY_INDEX_W, entry.length,
                        "recovered entry should be w bytes");

                System.out.printf("Recovered entry: %d bytes (3 slots × 13)%n", entry.length);
                System.out.printf("  Slot 0: tag=%016x%n",
                        java.nio.ByteBuffer.wrap(entry, 0, 8)
                                .order(java.nio.ByteOrder.LITTLE_ENDIAN).getLong());
            }
        }
    }

    // ── Full query test ──────────────────────────────────────────────────

    @Disabled("Run manually: requires live HarmonyPIR servers + hint download (~30s)")
    @Test
    void testFullQuerySatoshiAddress() throws Exception {
        assumeNative();

        try (var client = new HarmonyPirClient(HINT_SERVER, QUERY_SERVER, HarmonyBucket.PRP_ALF)) {
            long t0 = System.currentTimeMillis();
            client.connect();
            long connectMs = System.currentTimeMillis() - t0;
            assertTrue(client.isConnected());
            System.out.printf("Connected in %d ms (includes hint download)%n", connectMs);

            // Query Satoshi's address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
            // scriptPubKey: 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
            byte[] spk = PirHash.hexToBytes("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac");
            byte[] hash = PirHash.hash160(spk);

            long qt0 = System.currentTimeMillis();
            Map<Integer, List<UtxoDecoder.UtxoEntry>> results = client.queryBatch(List.of(hash));
            long queryMs = System.currentTimeMillis() - qt0;

            System.out.printf("Query completed in %d ms%n", queryMs);

            assertNotNull(results.get(0), "result for query 0 should not be null");
            System.out.printf("UTXOs found: %d%n", results.get(0).size());
            for (var utxo : results.get(0)) {
                String txid = PirHash.bytesToHex(PirHash.reverseBytes(utxo.txid()));
                System.out.printf("  txid=%s vout=%d amount=%d sats%n",
                        txid, utxo.vout(), utxo.amount());
            }
        }
    }

    // ── Multi-address query test ─────────────────────────────────────────

    @Disabled("Run manually: requires live HarmonyPIR servers + hint download (~30s)")
    @Test
    void testMultiAddressQuery() throws Exception {
        assumeNative();

        try (var client = new HarmonyPirClient(HINT_SERVER, QUERY_SERVER, HarmonyBucket.PRP_ALF)) {
            client.connect();

            // Query a few different addresses
            // Address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 (random known address)
            byte[] spk1 = PirHash.hexToBytes("76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac");
            byte[] hash1 = PirHash.hash160(spk1);

            // Address: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy (P2SH)
            byte[] spk2 = PirHash.hexToBytes("a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87");
            byte[] hash2 = PirHash.hash160(spk2);

            long qt0 = System.currentTimeMillis();
            Map<Integer, List<UtxoDecoder.UtxoEntry>> results =
                    client.queryBatch(List.of(hash1, hash2));
            long queryMs = System.currentTimeMillis() - qt0;

            System.out.printf("Multi-address query completed in %d ms%n", queryMs);
            for (int i = 0; i < 2; i++) {
                List<UtxoDecoder.UtxoEntry> entries = results.get(i);
                System.out.printf("  Address %d: %d UTXOs%n", i,
                        entries != null ? entries.size() : 0);
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static void assumeNative() {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                HarmonyBucket.isNativeLoaded(),
                "harmonypir_jni native library not available");
    }
}
