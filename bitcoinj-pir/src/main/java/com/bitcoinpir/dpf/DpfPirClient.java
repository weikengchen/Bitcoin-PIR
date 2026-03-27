package com.bitcoinpir.dpf;

import com.bitcoinpir.PirClient;
import com.bitcoinpir.PirConstants;
import com.bitcoinpir.codec.ProtocolCodec;
import com.bitcoinpir.codec.ProtocolCodec.BatchResult;
import com.bitcoinpir.codec.ProtocolCodec.ServerInfo;
import com.bitcoinpir.codec.UtxoDecoder;
import com.bitcoinpir.hash.CuckooHash;
import com.bitcoinpir.hash.PirHash;
import com.bitcoinpir.net.PirWebSocket;
import com.bitcoinpir.placement.PbcPlanner;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

/**
 * DPF 2-server Batch PIR client.
 * Implements the two-level query (index → chunk) using DPF keys.
 * Pure Java — no native dependencies.
 */
public class DpfPirClient implements PirClient {
    private static final Logger log = Logger.getLogger(DpfPirClient.class.getName());

    private final String server0Url;
    private final String server1Url;

    private PirWebSocket ws0;
    private PirWebSocket ws1;
    private final DpfKeyGen dpfGen = new DpfKeyGen();

    // Server parameters (from GetInfo)
    private int indexBins;
    private int chunkBins;
    private long tagSeed;

    public DpfPirClient(String server0Url, String server1Url) {
        this.server0Url = server0Url;
        this.server1Url = server1Url;
    }

    @Override
    public void connect() throws Exception {
        ws0 = new PirWebSocket(server0Url);
        ws1 = new PirWebSocket(server1Url);
        ws0.connect();
        ws1.connect();

        // Fetch server info from server 0
        byte[] infoPayload = ws0.sendSync(ProtocolCodec.encodeGetInfo());
        ServerInfo info = ProtocolCodec.decodeServerInfo(infoPayload);
        indexBins = info.indexBins();
        chunkBins = info.chunkBins();
        tagSeed = info.tagSeed();

        log.info("Connected: indexBins=" + indexBins + " chunkBins=" + chunkBins);
    }

    @Override
    public boolean isConnected() {
        return ws0 != null && ws0.isConnected() && ws1 != null && ws1.isConnected();
    }

    @Override
    public Map<Integer, List<UtxoDecoder.UtxoEntry>> queryBatch(List<byte[]> scriptHashes) throws Exception {
        if (scriptHashes.isEmpty()) return Map.of();

        // ── Level 1: Index PIR ──────────────────────────────────────────────

        // Derive candidate buckets for each query
        int[][] itemBuckets = new int[scriptHashes.size()][];
        for (int i = 0; i < scriptHashes.size(); i++) {
            itemBuckets[i] = PirHash.deriveBuckets(scriptHashes.get(i));
        }

        // Plan rounds
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

            // Generate DPF keys for all K buckets × INDEX_CUCKOO_NUM_HASHES
            byte[][][] keys0 = new byte[PirConstants.K][PirConstants.INDEX_CUCKOO_NUM_HASHES][];
            byte[][][] keys1 = new byte[PirConstants.K][PirConstants.INDEX_CUCKOO_NUM_HASHES][];

            for (int b = 0; b < PirConstants.K; b++) {
                Integer qi = bucketToQuery.get(b);
                for (int h = 0; h < PirConstants.INDEX_CUCKOO_NUM_HASHES; h++) {
                    int alpha;
                    if (qi != null) {
                        long ck = CuckooHash.deriveCuckooKey(b, h);
                        alpha = CuckooHash.cuckooHash(scriptHashes.get(qi), ck, indexBins);
                    } else {
                        alpha = dpfGen.gen(0, PirConstants.DPF_N)[0].n; // dummy — just use 0
                        alpha = 0;
                    }
                    DpfKey[] pair = dpfGen.gen(alpha, PirConstants.DPF_N);
                    keys0[b][h] = pair[0].toBytes();
                    keys1[b][h] = pair[1].toBytes();
                }
            }

            // Send to both servers in parallel
            byte[] req0 = ProtocolCodec.encodeBatchRequest(PirConstants.REQ_INDEX_BATCH, roundId, keys0);
            byte[] req1 = ProtocolCodec.encodeBatchRequest(PirConstants.REQ_INDEX_BATCH, roundId, keys1);

            CompletableFuture<byte[]> f0 = ws0.send(req0);
            CompletableFuture<byte[]> f1 = ws1.send(req1);

            byte[] resp0 = f0.get();
            byte[] resp1 = f1.get();

            BatchResult br0 = ProtocolCodec.decodeBatchResult(resp0);
            BatchResult br1 = ProtocolCodec.decodeBatchResult(resp1);

            // XOR results and scan for matching tags
            for (int[] entry : round) {
                int queryIdx = entry[0];
                int bucketId = entry[1];
                long expectedTag = PirHash.computeTag(tagSeed, scriptHashes.get(queryIdx));

                for (int h = 0; h < PirConstants.INDEX_CUCKOO_NUM_HASHES; h++) {
                    byte[] r0 = br0.results()[bucketId][h];
                    byte[] r1 = br1.results()[bucketId][h];
                    byte[] xored = xorBytes(r0, r1);

                    int[] found = UtxoDecoder.findEntryInIndexResult(xored, expectedTag);
                    if (found != null && !indexResults.containsKey(queryIdx)) {
                        indexResults.put(queryIdx, found);
                    }
                }
            }
            roundId++;
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

        // Query chunks
        Map<Integer, byte[]> recoveredChunks = new HashMap<>();

        if (!allChunkIds.isEmpty()) {
            List<Integer> chunkList = new ArrayList<>(allChunkIds);
            int[][] chunkBuckets = new int[chunkList.size()][];
            for (int i = 0; i < chunkList.size(); i++) {
                chunkBuckets[i] = PirHash.deriveChunkBuckets(chunkList.get(i));
            }

            List<int[][]> chunkRounds = PbcPlanner.planRounds(chunkBuckets, PirConstants.K_CHUNK);

            for (int[][] cRound : chunkRounds) {
                Map<Integer, Integer> bucketToChunkLocalIdx = new HashMap<>();
                for (int[] entry : cRound) {
                    bucketToChunkLocalIdx.put(entry[1], entry[0]);
                }

                byte[][][] ck0 = new byte[PirConstants.K_CHUNK][PirConstants.CHUNK_CUCKOO_NUM_HASHES][];
                byte[][][] ck1 = new byte[PirConstants.K_CHUNK][PirConstants.CHUNK_CUCKOO_NUM_HASHES][];

                for (int b = 0; b < PirConstants.K_CHUNK; b++) {
                    Integer ci = bucketToChunkLocalIdx.get(b);
                    for (int h = 0; h < PirConstants.CHUNK_CUCKOO_NUM_HASHES; h++) {
                        int alpha;
                        if (ci != null) {
                            long ck = CuckooHash.deriveChunkCuckooKey(b, h);
                            alpha = CuckooHash.cuckooHashInt(chunkList.get(ci), ck, chunkBins);
                        } else {
                            alpha = 0;
                        }
                        DpfKey[] pair = dpfGen.gen(alpha, PirConstants.CHUNK_DPF_N);
                        ck0[b][h] = pair[0].toBytes();
                        ck1[b][h] = pair[1].toBytes();
                    }
                }

                byte[] creq0 = ProtocolCodec.encodeBatchRequest(PirConstants.REQ_CHUNK_BATCH, roundId, ck0);
                byte[] creq1 = ProtocolCodec.encodeBatchRequest(PirConstants.REQ_CHUNK_BATCH, roundId, ck1);

                CompletableFuture<byte[]> cf0 = ws0.send(creq0);
                CompletableFuture<byte[]> cf1 = ws1.send(creq1);

                BatchResult cbr0 = ProtocolCodec.decodeBatchResult(cf0.get());
                BatchResult cbr1 = ProtocolCodec.decodeBatchResult(cf1.get());

                for (int[] entry : cRound) {
                    int localIdx = entry[0];
                    int bucketId = entry[1];
                    int chunkId = chunkList.get(localIdx);

                    for (int h = 0; h < PirConstants.CHUNK_CUCKOO_NUM_HASHES; h++) {
                        byte[] cr0 = cbr0.results()[bucketId][h];
                        byte[] cr1 = cbr1.results()[bucketId][h];
                        byte[] xored = xorBytes(cr0, cr1);

                        byte[] chunkData = UtxoDecoder.findChunkInResult(xored, chunkId);
                        if (chunkData != null && !recoveredChunks.containsKey(chunkId)) {
                            recoveredChunks.put(chunkId, chunkData);
                        }
                    }
                }
                roundId++;
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
        if (ws0 != null) ws0.close();
        if (ws1 != null) ws1.close();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static byte[] xorBytes(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }
}
