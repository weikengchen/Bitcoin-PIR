package com.bitcoinpir.harmony;

import com.bitcoinpir.PirClient;
import com.bitcoinpir.PirConstants;
import com.bitcoinpir.codec.ProtocolCodec;
import com.bitcoinpir.codec.ProtocolCodec.HarmonyBatchResult;
import com.bitcoinpir.codec.ProtocolCodec.HarmonyBatchResultItem;
import com.bitcoinpir.codec.ProtocolCodec.HintData;
import com.bitcoinpir.codec.UtxoDecoder;
import com.bitcoinpir.hash.CuckooHash;
import com.bitcoinpir.hash.PirHash;
import com.bitcoinpir.net.PirWebSocket;
import com.bitcoinpir.placement.PbcPlanner;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

/**
 * HarmonyPIR 2-server stateful PIR client.
 *
 * <p>Uses {@link HarmonyBucket} (backed by the harmonypir-jni native library)
 * for the core bucket operations: hint storage, query request generation,
 * and response processing.
 *
 * <p>Build the native library:
 * <pre>
 *   cd harmonypir-jni && cargo build --release
 * </pre>
 *
 * <p>The overall query flow (index → chunk) is identical to DPF, but instead of
 * DPF keys, each bucket generates a HarmonyPIR request via the native bucket.
 */
public class HarmonyPirClient implements PirClient {
    private static final Logger log = Logger.getLogger(HarmonyPirClient.class.getName());

    private final String hintServerUrl;
    private final String queryServerUrl;
    private final int prpBackend;

    private PirWebSocket hintWs;
    private PirWebSocket queryWs;
    private boolean connected;

    // Server parameters
    private int indexBins;
    private int chunkBins;
    private long tagSeed;

    // PRP key (generated randomly per session)
    private byte[] prpKey;

    // HarmonyBucket arrays — one per index/chunk bucket
    private HarmonyBucket[] indexBuckets;
    private HarmonyBucket[] chunkBuckets;

    public HarmonyPirClient(String hintServerUrl, String queryServerUrl, int prpBackend) {
        this.hintServerUrl = hintServerUrl;
        this.queryServerUrl = queryServerUrl;
        this.prpBackend = prpBackend;
    }

    @Override
    public void connect() throws Exception {
        if (!HarmonyBucket.isNativeLoaded()) {
            throw new UnsatisfiedLinkError(
                "harmonypir_jni native library not available. " +
                "Build with: cd harmonypir-jni && cargo build --release");
        }

        hintWs = new PirWebSocket(hintServerUrl);
        queryWs = new PirWebSocket(queryServerUrl);
        hintWs.connect();
        queryWs.connect();

        // Fetch server info from query server
        byte[] infoPayload = queryWs.sendSync(ProtocolCodec.encodeHarmonyGetInfo());
        var info = ProtocolCodec.decodeServerInfo(infoPayload);
        indexBins = info.indexBins();
        chunkBins = info.chunkBins();
        tagSeed = info.tagSeed();

        // Generate random PRP key for this session
        prpKey = new byte[16];
        new SecureRandom().nextBytes(prpKey);

        // Download hints first (to learn server's T and padded_n),
        // then create buckets with matching parameters and load hints.
        downloadHintsAndCreateBuckets();

        connected = true;
        log.info("HarmonyPIR connected: indexBins=" + indexBins + " chunkBins=" + chunkBins);
    }

    @Override
    public boolean isConnected() {
        return connected;
    }

    @Override
    public Map<Integer, List<UtxoDecoder.UtxoEntry>> queryBatch(List<byte[]> scriptHashes) throws Exception {
        if (scriptHashes.isEmpty()) return Map.of();

        // ── Level 1: Index PIR ──────────────────────────────────────────────

        // Derive PBC candidate buckets for each query (NUM_HASHES=3 candidates per K=75 buckets)
        int[][] itemBuckets = new int[scriptHashes.size()][];
        for (int i = 0; i < scriptHashes.size(); i++) {
            itemBuckets[i] = PirHash.deriveBuckets(scriptHashes.get(i));
        }

        // Plan rounds via PBC cuckoo placement
        List<int[][]> rounds = PbcPlanner.planRounds(itemBuckets, PirConstants.K);

        // Track index results: queryIndex → {startChunkId, numChunks}
        Map<Integer, int[]> indexResults = new HashMap<>();

        int roundId = 0;
        for (int[][] round : rounds) {
            // Build bucket-to-query mapping for this round
            Map<Integer, Integer> bucketToQuery = new HashMap<>();
            for (int[] entry : round) {
                bucketToQuery.put(entry[1], entry[0]); // bucketId → queryIndex
            }

            // For each cuckoo hash function, query all K buckets
            for (int h = 0; h < PirConstants.INDEX_CUCKOO_NUM_HASHES; h++) {
                int[] bucketIds = new int[PirConstants.K];
                byte[][] requests = new byte[PirConstants.K][];
                boolean[] isReal = new boolean[PirConstants.K];

                for (int b = 0; b < PirConstants.K; b++) {
                    bucketIds[b] = b;
                    Integer qi = bucketToQuery.get(b);
                    if (qi != null && !indexResults.containsKey(qi)) {
                        // Real query — compute cuckoo bin index for hash function h
                        long ck = CuckooHash.deriveCuckooKey(b, h);
                        int binIndex = CuckooHash.cuckooHash(scriptHashes.get(qi), ck, indexBins);
                        requests[b] = indexBuckets[b].buildRequest(binIndex);
                        isReal[b] = true;
                    } else {
                        // Dummy — pad unused bucket
                        requests[b] = indexBuckets[b].buildSyntheticDummy();
                        isReal[b] = false;
                    }
                }

                // Send batch to query server
                byte[] batchMsg = ProtocolCodec.encodeHarmonyBatchQuery(
                        0, roundId, 1, bucketIds, requests);
                byte[] batchResp = queryWs.sendSync(batchMsg);

                HarmonyBatchResult result = ProtocolCodec.decodeHarmonyBatchResult(batchResp);

                // Process responses
                for (HarmonyBatchResultItem item : result.items()) {
                    int b = item.bucketId();
                    if (isReal[b]) {
                        byte[] entry = indexBuckets[b].processResponse(item.subResults()[0]);

                        // Scan 3 slots for matching tag
                        Integer qi = bucketToQuery.get(b);
                        if (qi != null) {
                            long expectedTag = PirHash.computeTag(tagSeed, scriptHashes.get(qi));
                            int[] found = UtxoDecoder.findEntryInIndexResult(entry, expectedTag);
                            if (found != null && !indexResults.containsKey(qi)) {
                                indexResults.put(qi, found);
                            }
                        }
                    }
                    // Dummies: response is discarded (no processResponse needed)
                }

                roundId++;
            }
        }

        // ── Level 2: Chunk PIR ──────────────────────────────────────────────

        // Collect all unique chunk IDs needed
        Map<Integer, Set<Integer>> queryToChunkIds = new HashMap<>();
        Set<Integer> allChunkIds = new TreeSet<>();

        for (var e : indexResults.entrySet()) {
            int queryIdx = e.getKey();
            int startChunkId = e.getValue()[0];
            int numChunks = e.getValue()[1];
            if (numChunks == 0) continue; // whale or not found

            Set<Integer> chunks = new LinkedHashSet<>();
            int numUnits = (numChunks + PirConstants.CHUNKS_PER_UNIT - 1) / PirConstants.CHUNKS_PER_UNIT;
            for (int u = 0; u < numUnits; u++) {
                int cid = startChunkId + u * PirConstants.CHUNKS_PER_UNIT;
                chunks.add(cid);
                allChunkIds.add(cid);
            }
            queryToChunkIds.put(queryIdx, chunks);
        }

        Map<Integer, byte[]> recoveredChunks = new HashMap<>();

        if (!allChunkIds.isEmpty()) {
            List<Integer> chunkList = new ArrayList<>(allChunkIds);

            // Derive PBC candidate buckets for chunk-level
            int[][] chunkBucketCands = new int[chunkList.size()][];
            for (int i = 0; i < chunkList.size(); i++) {
                chunkBucketCands[i] = PirHash.deriveChunkBuckets(chunkList.get(i));
            }

            List<int[][]> chunkRounds = PbcPlanner.planRounds(chunkBucketCands, PirConstants.K_CHUNK);

            for (int[][] cRound : chunkRounds) {
                Map<Integer, Integer> bucketToChunkLocalIdx = new HashMap<>();
                for (int[] entry : cRound) {
                    bucketToChunkLocalIdx.put(entry[1], entry[0]);
                }

                for (int h = 0; h < PirConstants.CHUNK_CUCKOO_NUM_HASHES; h++) {
                    int[] bucketIds = new int[PirConstants.K_CHUNK];
                    byte[][] requests = new byte[PirConstants.K_CHUNK][];
                    boolean[] isReal = new boolean[PirConstants.K_CHUNK];

                    for (int b = 0; b < PirConstants.K_CHUNK; b++) {
                        bucketIds[b] = b;
                        Integer ci = bucketToChunkLocalIdx.get(b);
                        if (ci != null && !recoveredChunks.containsKey(chunkList.get(ci))) {
                            long ck = CuckooHash.deriveChunkCuckooKey(b, h);
                            int binIndex = CuckooHash.cuckooHashInt(chunkList.get(ci), ck, chunkBins);
                            requests[b] = chunkBuckets[b].buildRequest(binIndex);
                            isReal[b] = true;
                        } else {
                            requests[b] = chunkBuckets[b].buildSyntheticDummy();
                            isReal[b] = false;
                        }
                    }

                    byte[] batchMsg = ProtocolCodec.encodeHarmonyBatchQuery(
                            1, roundId, 1, bucketIds, requests);
                    byte[] batchResp = queryWs.sendSync(batchMsg);

                    HarmonyBatchResult result = ProtocolCodec.decodeHarmonyBatchResult(batchResp);

                    for (HarmonyBatchResultItem item : result.items()) {
                        int b = item.bucketId();
                        if (isReal[b]) {
                            byte[] entry = chunkBuckets[b].processResponse(item.subResults()[0]);

                            Integer ci = bucketToChunkLocalIdx.get(b);
                            if (ci != null) {
                                int chunkId = chunkList.get(ci);
                                byte[] chunkData = UtxoDecoder.findChunkInResult(entry, chunkId);
                                if (chunkData != null && !recoveredChunks.containsKey(chunkId)) {
                                    recoveredChunks.put(chunkId, chunkData);
                                }
                            }
                        }
                    }

                    roundId++;
                }
            }
        }

        // ── Reassemble results ──────────────────────────────────────────────

        Map<Integer, List<UtxoDecoder.UtxoEntry>> results = new HashMap<>();

        for (int qi = 0; qi < scriptHashes.size(); qi++) {
            int[] ir = indexResults.get(qi);
            if (ir == null || ir[1] == 0) {
                results.put(qi, List.of());
                continue;
            }

            int startChunkId = ir[0];
            int numChunks = ir[1];
            int numUnits = (numChunks + PirConstants.CHUNKS_PER_UNIT - 1) / PirConstants.CHUNKS_PER_UNIT;

            byte[] fullData = new byte[numUnits * PirConstants.UNIT_DATA_SIZE];
            for (int u = 0; u < numUnits; u++) {
                int cid = startChunkId + u * PirConstants.CHUNKS_PER_UNIT;
                byte[] d = recoveredChunks.get(cid);
                if (d != null) {
                    System.arraycopy(d, 0, fullData, u * PirConstants.UNIT_DATA_SIZE,
                            Math.min(d.length, PirConstants.UNIT_DATA_SIZE));
                }
            }

            UtxoDecoder.DecodeResult dr = UtxoDecoder.decode(fullData);
            results.put(qi, dr.entries());
        }

        return results;
    }

    @Override
    public void close() {
        connected = false;
        if (hintWs != null) hintWs.close();
        if (queryWs != null) queryWs.close();
        closeBuckets();
    }

    // ── Internal ─────────────────────────────────────────────────────────

    /**
     * Download hints from the hint server, create buckets with the server's
     * T and padded_n values, and load the hints.
     *
     * <p>The hint server computes T using a different algorithm than the JNI
     * bridge's find_nearby_divisor: it pads n up instead. The hint response
     * includes (n_padded, t, m) so we use those to create matching buckets.
     */
    private void downloadHintsAndCreateBuckets() throws Exception {
        int serverPrp = toServerPrpBackend(prpBackend);
        log.info("Downloading HarmonyPIR hints (prpBackend=" + serverPrp + ")...");

        long startMs = System.currentTimeMillis();

        // ── Index-level hints ────────────────────────────────────────────
        int[] indexIds = new int[PirConstants.K];
        for (int b = 0; b < PirConstants.K; b++) indexIds[b] = b;

        byte[] indexHintReq = ProtocolCodec.encodeHarmonyHintRequest(prpKey, serverPrp, 0, indexIds);
        List<CompletableFuture<byte[]>> indexFutures = hintWs.sendExpectingN(indexHintReq, PirConstants.K);

        // Collect all hint responses (may arrive out of order from rayon workers)
        HintData[] indexHints = new HintData[PirConstants.K];
        for (CompletableFuture<byte[]> f : indexFutures) {
            byte[] payload = f.get();
            HintData hint = ProtocolCodec.decodeHarmonyHintResponse(payload);
            indexHints[hint.bucketId()] = hint;
        }

        long indexMs = System.currentTimeMillis() - startMs;
        log.info("Index hints downloaded in " + indexMs + " ms");

        // Create index buckets using server's (padded_n, t) values
        indexBuckets = new HarmonyBucket[PirConstants.K];
        for (int b = 0; b < PirConstants.K; b++) {
            HintData hint = indexHints[b];
            // Use explicit T from server to match hint parameters
            indexBuckets[b] = new HarmonyBucket(
                    hint.n(), PirConstants.HARMONY_INDEX_W, hint.t(),
                    prpKey, b, prpBackend);
            indexBuckets[b].loadHints(hint.hintBytes());
        }

        // ── Chunk-level hints ────────────────────────────────────────────
        int[] chunkIds = new int[PirConstants.K_CHUNK];
        for (int b = 0; b < PirConstants.K_CHUNK; b++) chunkIds[b] = b;

        byte[] chunkHintReq = ProtocolCodec.encodeHarmonyHintRequest(prpKey, serverPrp, 1, chunkIds);
        List<CompletableFuture<byte[]>> chunkFutures = hintWs.sendExpectingN(chunkHintReq, PirConstants.K_CHUNK);

        HintData[] chunkHintData = new HintData[PirConstants.K_CHUNK];
        for (CompletableFuture<byte[]> f : chunkFutures) {
            byte[] payload = f.get();
            HintData hint = ProtocolCodec.decodeHarmonyHintResponse(payload);
            chunkHintData[hint.bucketId()] = hint;
        }

        // Create chunk buckets using server's (padded_n, t) values
        chunkBuckets = new HarmonyBucket[PirConstants.K_CHUNK];
        for (int b = 0; b < PirConstants.K_CHUNK; b++) {
            HintData hint = chunkHintData[b];
            chunkBuckets[b] = new HarmonyBucket(
                    hint.n(), PirConstants.HARMONY_CHUNK_W, hint.t(),
                    prpKey, b, prpBackend);
            chunkBuckets[b].loadHints(hint.hintBytes());
        }

        long totalMs = System.currentTimeMillis() - startMs;
        log.info("All hints downloaded and loaded in " + totalMs + " ms (" +
                PirConstants.K + " index + " + PirConstants.K_CHUNK + " chunk buckets)");
    }

    /**
     * Map Java-side PRP backend constants to server-side constants.
     *
     * Java (HarmonyBucket):  ALF=0, HOANG=1, FASTPRP=2
     * Server (harmonypir_wasm): HOANG=0, FASTPRP=1, ALF=2
     */
    private static int toServerPrpBackend(int javaPrpBackend) {
        return switch (javaPrpBackend) {
            case HarmonyBucket.PRP_ALF     -> PirConstants.SERVER_PRP_ALF;
            case HarmonyBucket.PRP_HOANG   -> PirConstants.SERVER_PRP_HOANG;
            case HarmonyBucket.PRP_FASTPRP -> PirConstants.SERVER_PRP_FASTPRP;
            default -> PirConstants.SERVER_PRP_HOANG;
        };
    }

    private void closeBuckets() {
        if (indexBuckets != null) {
            for (HarmonyBucket b : indexBuckets) {
                if (b != null) b.close();
            }
            indexBuckets = null;
        }
        if (chunkBuckets != null) {
            for (HarmonyBucket b : chunkBuckets) {
                if (b != null) b.close();
            }
            chunkBuckets = null;
        }
    }
}
