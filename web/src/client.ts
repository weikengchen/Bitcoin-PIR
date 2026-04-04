/**
 * Two-level Batch PIR WebSocket client.
 *
 * Supports true batching: multiple script hashes are packed into a single
 * batch of K=75 index buckets (Level 1) and K_CHUNK=80 chunk buckets
 * (Level 2) using cuckoo placement, minimizing round-trips.
 */

import {
  K, K_CHUNK, NUM_HASHES,
  CHUNKS_PER_UNIT, UNIT_DATA_SIZE,
  INDEX_CUCKOO_NUM_HASHES,
  CHUNK_CUCKOO_NUM_HASHES,
} from './constants.js';

import {
  deriveBuckets, deriveCuckooKey, cuckooHash,
  deriveChunkBuckets, deriveChunkCuckooKey, cuckooHashInt,
  computeTag,
} from './hash.js';

import { genDpfKeys, genChunkDpfKeys } from './dpf.js';

import {
  encodeRequest, decodeResponse,
  type Request, type Response, type BatchQuery, type BatchResult, type ServerInfo,
} from './protocol.js';

import { cuckooPlace, planRounds } from './pbc.js';
import { readVarint, decodeUtxoData, DummyRng } from './codec.js';
import { findEntryInIndexResult, findChunkInResult } from './scan.js';
import { ManagedWebSocket } from './ws.js';
import { fetchServerInfoJson, type ServerInfoJson, type MerkleInfoJson } from './server-info.js';
import { verifyMerkleDpf } from './merkle-verify-dpf.js';

// ─── Types ─────────────────────────────────────────────────────────────────

export interface UtxoEntry {
  txid: Uint8Array;    // 32-byte raw TXID (internal byte order)
  vout: number;
  amount: bigint;      // satoshis
}

export interface QueryResult {
  entries: UtxoEntry[];
  totalSats: bigint;
  startChunkId: number;
  numChunks: number;
  numRounds: number;
  /** True if this address was excluded from the database due to too many UTXOs */
  isWhale: boolean;
  /** Merkle verification result (undefined if not verified yet) */
  merkleVerified?: boolean;
  /** Merkle root hash hex (from server, for display) */
  merkleRootHex?: string;
  /** tree_loc in the Merkle tree */
  treeLoc?: number;
  /** Raw chunk data (kept for Merkle verification) */
  rawChunkData?: Uint8Array;
  /** Script hash used for this query */
  scriptHash?: Uint8Array;
}

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting';

export interface BatchPirClientConfig {
  server0Url: string;
  server1Url: string;
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  onLog?: (message: string, level: 'info' | 'success' | 'error') => void;
}

// ─── Client ────────────────────────────────────────────────────────────────

export class BatchPirClient {
  private ws0: ManagedWebSocket | null = null;
  private ws1: ManagedWebSocket | null = null;
  private config: BatchPirClientConfig;
  private connectionState: ConnectionState = 'disconnected';
  private rng = new DummyRng();

  // Server info (fetched on connect via JSON)
  private serverInfo: ServerInfoJson | null = null;
  private indexBins = 0;
  private chunkBins = 0;
  private tagSeed = 0n;

  constructor(config: BatchPirClientConfig) {
    this.config = config;
  }

  private log(message: string, level: 'info' | 'success' | 'error' = 'info'): void {
    if (this.config.onLog) {
      this.config.onLog(message, level);
    }
    console.log(`[BatchPIR] ${message}`);
  }

  private setConnectionState(state: ConnectionState, message?: string): void {
    this.connectionState = state;
    this.config.onConnectionStateChange?.(state, message);
  }

  getConnectionState(): ConnectionState {
    return this.connectionState;
  }

  isConnected(): boolean {
    return (this.ws0?.isOpen() ?? false) && (this.ws1?.isOpen() ?? false);
  }

  // ─── Connection (delegates to shared ws.ts) ────────────────────────────

  async connect(): Promise<void> {
    this.setConnectionState('connecting', 'Connecting to servers...');

    try {
      this.ws0 = new ManagedWebSocket({
        url: this.config.server0Url,
        label: 'server0',
        onLog: (msg, level) => this.log(msg, level),
        onClose: () => {
          this.ws0 = null;
          this.setConnectionState('disconnected', 'Server 0 closed');
        },
      });
      this.ws1 = new ManagedWebSocket({
        url: this.config.server1Url,
        label: 'server1',
        onLog: (msg, level) => this.log(msg, level),
        onClose: () => {
          this.ws1 = null;
          this.setConnectionState('disconnected', 'Server 1 closed');
        },
      });

      await Promise.all([this.ws0.connect(), this.ws1.connect()]);

      this.setConnectionState('connected', 'Connected to both servers');
      this.log('Connected to both servers', 'success');

      // Fetch server info
      await this.fetchServerInfo();
    } catch (error) {
      this.setConnectionState('disconnected', `Connection failed: ${error}`);
      throw error;
    }
  }

  disconnect(): void {
    this.ws0?.disconnect();
    this.ws1?.disconnect();
    this.ws0 = null;
    this.ws1 = null;
    this.setConnectionState('disconnected', 'Disconnected');
  }

  // ─── Raw WebSocket send/receive ────────────────────────────────────────

  private sendRaw(serverNum: 0 | 1, encoded: Uint8Array): Promise<Uint8Array> {
    const ws = serverNum === 0 ? this.ws0 : this.ws1;
    if (!ws) throw new Error(`Not connected to server ${serverNum}`);
    return ws.sendRaw(encoded);
  }

  private async sendRequest(serverNum: 0 | 1, request: Request): Promise<Response> {
    const encoded = encodeRequest(request);
    const raw = await this.sendRaw(serverNum, encoded);
    return decodeResponse(raw.slice(4));
  }

  private async sendBoth(
    encoded0: Uint8Array,
    encoded1: Uint8Array,
  ): Promise<[Uint8Array, Uint8Array]> {
    const [raw0, raw1] = await Promise.all([
      this.sendRaw(0, encoded0),
      this.sendRaw(1, encoded1),
    ]);
    return [raw0, raw1];
  }

  // ─── Server info ───────────────────────────────────────────────────────

  private async fetchServerInfo(): Promise<void> {
    const info = await fetchServerInfoJson(this.ws0!);
    this.serverInfo = info;
    this.indexBins = info.index_bins_per_table;
    this.chunkBins = info.chunk_bins_per_table;
    this.tagSeed = info.tag_seed;
    this.log(`Server info (JSON): index_bins=${this.indexBins}, chunk_bins=${this.chunkBins}, index_K=${info.index_k}, chunk_K=${info.chunk_k}, tag_seed=0x${this.tagSeed.toString(16)}`);

    // Also fetch from server 1 to keep connection in sync
    await fetchServerInfoJson(this.ws1!);
  }

  getServerInfo(): { indexBins: number; chunkBins: number } {
    return { indexBins: this.indexBins, chunkBins: this.chunkBins };
  }

  // ─── XOR utility ──────────────────────────────────────────────────────

  private xorBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(Math.max(a.length, b.length));
    for (let i = 0; i < result.length; i++) {
      result[i] = (a[i] || 0) ^ (b[i] || 0);
    }
    return result;
  }

  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  // ─── Index result parsing ─────────────────────────────────────────────

  // ─── Index/chunk result parsing (delegates to shared scan.ts) ──────────

  // ─── Cuckoo placement and round planning (delegates to shared pbc.ts) ──

  // ─── Decode UTXO data (delegates to shared codec.ts) ──────────────────

  // ─── Single-query method (for backward compat) ────────────────────────

  async query(
    scriptHashBytes: Uint8Array,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<QueryResult | null> {
    const results = await this.queryBatch([scriptHashBytes], onProgress);
    return results[0];
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TRUE BATCH QUERY — multiple script hashes in one batch
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Query multiple script hashes in true batched mode.
   *
   * Level 1: Packs multiple queries into K=75 index buckets using
   *   cuckoo placement. If >K queries, uses multiple index rounds.
   * Level 2: Collects ALL chunk IDs across all queries and fetches
   *   them in batched chunk rounds (K_CHUNK=80 per round).
   *
   * Returns an array parallel to the input, with results or null.
   */
  async queryBatch(
    scriptHashes: Uint8Array[],
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    if (!this.isConnected()) throw new Error('Not connected');
    if (this.indexBins === 0) throw new Error('Server info not loaded');

    const N = scriptHashes.length;
    const progress = onProgress || (() => {});

    this.log(`=== Batch query: ${N} script hashes ===`);

    // ════════════════════════════════════════════════════════════════════
    // LEVEL 1: Index PIR (batched)
    // ════════════════════════════════════════════════════════════════════
    progress('Level 1', `Planning index batch for ${N} queries...`);

    // Compute candidate index buckets for each query
    const indexCandBuckets = scriptHashes.map(sh => deriveBuckets(sh));

    // Plan index rounds using cuckoo placement
    const indexRounds = planRounds(indexCandBuckets, K, NUM_HASHES, (msg) => this.log(msg, 'error'));
    this.log(`Level 1: ${N} queries → ${indexRounds.length} index round(s)`);

    // Per-query results from Level 1
    const indexResults: Map<number, { startChunkId: number; numChunks: number; treeLoc: number }> = new Map();

    for (let ir = 0; ir < indexRounds.length; ir++) {
      const round = indexRounds[ir];
      progress('Level 1', `Index round ${ir + 1}/${indexRounds.length} (${round.length} queries)...`);
      this.log(`  Index round ${ir + 1}: ${round.length} queries in ${K} buckets`);

      // Build bucket → query mapping: which query goes in which bucket
      const bucketToQuery: Map<number, number> = new Map();
      for (const [queryIdx, bucketId] of round) {
        bucketToQuery.set(bucketId, queryIdx);
      }

      // Generate DPF keys for all K buckets (INDEX_CUCKOO_NUM_HASHES keys per bucket)
      progress('Level 1', `Round ${ir + 1}: generating DPF keys...`);
      const s0Keys: Uint8Array[][] = [];
      const s1Keys: Uint8Array[][] = [];

      for (let b = 0; b < K; b++) {
        const qi = bucketToQuery.get(b);
        const s0Bucket: Uint8Array[] = [];
        const s1Bucket: Uint8Array[] = [];

        for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
          let alpha: number;
          if (qi !== undefined) {
            const sh = scriptHashes[qi];
            const ck = deriveCuckooKey(b, h);
            alpha = cuckooHash(sh, ck, this.indexBins);
          } else {
            alpha = Number(this.rng.nextU64() % BigInt(this.indexBins));
          }
          const keys = await genDpfKeys(alpha);
          s0Bucket.push(keys.key0);
          s1Bucket.push(keys.key1);
        }

        s0Keys.push(s0Bucket);
        s1Keys.push(s1Bucket);
      }

      // Send to both servers
      progress('Level 1', `Round ${ir + 1}: querying servers...`);
      const req0 = encodeRequest({ type: 'IndexBatch', query: { level: 0, roundId: ir, keys: s0Keys } });
      const req1 = encodeRequest({ type: 'IndexBatch', query: { level: 0, roundId: ir, keys: s1Keys } });

      const [raw0, raw1] = await this.sendBoth(req0, req1);
      const resp0 = decodeResponse(raw0.slice(4));
      const resp1 = decodeResponse(raw1.slice(4));

      if (resp0.type !== 'IndexBatch' || resp1.type !== 'IndexBatch') {
        throw new Error(`Unexpected index response: ${resp0.type}, ${resp1.type}`);
      }

      // XOR and extract results for each real query bucket
      for (const [queryIdx, bucketId] of round) {
        const r0 = resp0.result.results[bucketId];
        const r1 = resp1.result.results[bucketId];

        let found: { startChunkId: number; numChunks: number; treeLoc: number } | null = null;
        const expectedTag = computeTag(this.tagSeed, scriptHashes[queryIdx]);
        for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
          const result = this.xorBuffers(r0[h], r1[h]);
          found = findEntryInIndexResult(result, expectedTag, this.serverInfo!.index_cuckoo_bucket_size, this.serverInfo!.index_slot_size);
          if (found) break;
        }

        if (found) {
          indexResults.set(queryIdx, found);
        } else {
          this.log(`  Query ${queryIdx}: not found in index`, 'error');
        }
      }
    }

    this.log(`Level 1 complete: ${indexResults.size}/${N} found`);

    // ════════════════════════════════════════════════════════════════════
    // LEVEL 2: Chunk PIR (batched across ALL queries)
    // ════════════════════════════════════════════════════════════════════
    progress('Level 2', 'Collecting chunk IDs...');

    // Build a global list of unique chunk IDs needed, and track which
    // query needs which chunks
    const queryChunkInfo: Map<number, { startChunk: number; numUnits: number; startChunkId: number; numChunks: number; treeLoc: number }> = new Map();
    const allChunkIdsSet = new Set<number>();

    // Track whale-excluded queries separately
    const whaleQueries = new Set<number>();

    for (const [qi, info] of indexResults) {
      // Detect whale: num_chunks == 0
      if (info.numChunks === 0) {
        whaleQueries.add(qi);
        this.log(`  Query ${qi}: whale address (excluded, too many UTXOs)`);
        continue;
      }

      const startChunk = info.startChunkId;
      const numUnits = Math.ceil(info.numChunks / CHUNKS_PER_UNIT);
      const chunkIds: number[] = [];
      for (let u = 0; u < numUnits; u++) {
        const cid = startChunk + u * CHUNKS_PER_UNIT;
        chunkIds.push(cid);
        allChunkIdsSet.add(cid);
      }
      queryChunkInfo.set(qi, { startChunk, numUnits, startChunkId: info.startChunkId, numChunks: info.numChunks, treeLoc: info.treeLoc });
    }

    const allChunkIds = Array.from(allChunkIdsSet).sort((a, b) => a - b);
    this.log(`Level 2: ${allChunkIds.length} unique chunks to fetch across ${indexResults.size} queries`);

    // Plan chunk rounds collectively
    const chunkCandBuckets = allChunkIds.map(cid => deriveChunkBuckets(cid));
    const chunkRounds = planRounds(
      chunkCandBuckets,
      K_CHUNK,
      NUM_HASHES,
      (msg) => this.log(msg, 'error'),
    );
    // chunkRounds[r][i] = [chunkListIndex, bucketId]
    this.log(`  ${allChunkIds.length} chunks → ${chunkRounds.length} chunk round(s)`);

    // Execute chunk rounds
    const recoveredChunks = new Map<number, Uint8Array>();

    for (let ri = 0; ri < chunkRounds.length; ri++) {
      const roundPlan = chunkRounds[ri];
      progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length} (${roundPlan.length} chunks)...`);

      // Always send CHUNK_CUCKOO_NUM_HASHES (2) DPF keys per bucket (uniform, no placement optimization)
      const bucketTargets: Map<number, number[]> = new Map();
      for (const [chunkListIdx, bucketId] of roundPlan) {
        const chunkId = allChunkIds[chunkListIdx];
        const locs: number[] = [];
        for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
          const ck = deriveChunkCuckooKey(bucketId, h);
          locs.push(cuckooHashInt(chunkId, ck, this.chunkBins));
        }
        bucketTargets.set(bucketId, locs);
      }

      // Generate DPF keys
      const s0Keys: Uint8Array[][] = [];
      const s1Keys: Uint8Array[][] = [];

      for (let b = 0; b < K_CHUNK; b++) {
        const target = bucketTargets.get(b);
        const s0Bucket: Uint8Array[] = [];
        const s1Bucket: Uint8Array[] = [];

        for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
          const alpha = target
            ? target[h]
            : Number(this.rng.nextU64() % BigInt(this.chunkBins));
          const keys = await genChunkDpfKeys(alpha);
          s0Bucket.push(keys.key0);
          s1Bucket.push(keys.key1);
        }

        s0Keys.push(s0Bucket);
        s1Keys.push(s1Bucket);
      }

      // Send
      const cReq0 = encodeRequest({ type: 'ChunkBatch', query: { level: 1, roundId: ri, keys: s0Keys } });
      const cReq1 = encodeRequest({ type: 'ChunkBatch', query: { level: 1, roundId: ri, keys: s1Keys } });

      const [craw0, craw1] = await this.sendBoth(cReq0, cReq1);
      const cresp0 = decodeResponse(craw0.slice(4));
      const cresp1 = decodeResponse(craw1.slice(4));

      if (cresp0.type !== 'ChunkBatch' || cresp1.type !== 'ChunkBatch') {
        throw new Error(`Unexpected chunk response: ${cresp0.type}, ${cresp1.type}`);
      }

      // XOR and extract
      for (const [chunkListIdx, bucketId] of roundPlan) {
        const chunkId = allChunkIds[chunkListIdx];
        const cr0 = cresp0.result.results[bucketId];
        const cr1 = cresp1.result.results[bucketId];

        let data: Uint8Array | null = null;
        const numResults = cr0.length;
        for (let h = 0; h < numResults; h++) {
          const result = this.xorBuffers(cr0[h], cr1[h]);
          data = findChunkInResult(result, chunkId, this.serverInfo!.chunk_cuckoo_bucket_size, this.serverInfo!.chunk_slot_size);
          if (data) break;
        }

        if (data) {
          recoveredChunks.set(chunkId, data);
        } else {
          this.log(`  WARNING: chunk ${chunkId} not found in round ${ri} bucket ${bucketId}`, 'error');
        }
      }
    }

    this.log(`Level 2 complete: recovered ${recoveredChunks.size}/${allChunkIds.length} chunks`);

    // ════════════════════════════════════════════════════════════════════
    // Reassemble per-query results
    // ════════════════════════════════════════════════════════════════════
    progress('Decode', 'Reassembling UTXO data...');

    const totalChunkRounds = chunkRounds.length;
    const results: (QueryResult | null)[] = new Array(N).fill(null);

    for (let qi = 0; qi < N; qi++) {
      // Return a whale result if this address was excluded
      if (whaleQueries.has(qi)) {
        results[qi] = {
          entries: [],
          totalSats: 0n,
          startChunkId: 0,
          numChunks: 0,
          numRounds: 0,
          isWhale: true,
        };
        continue;
      }

      const info = queryChunkInfo.get(qi);
      if (!info) {
        // Not found in index
        continue;
      }

      const { startChunk, numUnits, startChunkId, numChunks } = info;
      const fullData = new Uint8Array(numUnits * UNIT_DATA_SIZE);
      let missing = 0;

      for (let u = 0; u < numUnits; u++) {
        const cid = startChunk + u * CHUNKS_PER_UNIT;
        const d = recoveredChunks.get(cid);
        if (d) {
          fullData.set(d, u * UNIT_DATA_SIZE);
        } else {
          missing++;
        }
      }

      if (missing > 0) {
        this.log(`Query ${qi}: ${missing} chunks missing`, 'error');
      }

      const { entries, totalSats } = decodeUtxoData(fullData, (msg) => this.log(msg, 'error'));
      results[qi] = {
        entries,
        totalSats,
        startChunkId,
        numChunks,
        numRounds: totalChunkRounds,
        isWhale: false,
        merkleRootHex: this.serverInfo?.merkle?.root,
        treeLoc: info.treeLoc,
        rawChunkData: fullData,
        scriptHash: scriptHashes[qi],
      };
    }

    const found = results.filter(r => r !== null).length;
    this.log(`=== Batch complete: ${found}/${N} queries returned results ===`, 'success');

    return results;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // MERKLE VERIFICATION — separate from query (user-triggered)
  // ═══════════════════════════════════════════════════════════════════════

  /** Check if server supports Merkle verification */
  hasMerkle(): boolean {
    return !!(this.serverInfo?.merkle && this.serverInfo.merkle.sibling_levels > 0);
  }

  /** Get the Merkle root hash hex (for display) */
  getMerkleRootHex(): string | undefined {
    return this.serverInfo?.merkle?.root;
  }

  /**
   * Verify a single query result against the Merkle tree.
   * Fetches the tree-top cache from the server, runs sibling PIR rounds,
   * and verifies the full proof to the root.
   *
   * Call this after query() / queryBatch() with the result you want to verify.
   */
  async verifyMerkle(
    result: QueryResult,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<boolean> {
    if (!this.isConnected()) throw new Error('Not connected');
    const merkle = this.serverInfo?.merkle;
    if (!merkle || merkle.sibling_levels === 0) throw new Error('Server does not support Merkle');
    if (!result.scriptHash || !result.rawChunkData || result.treeLoc === undefined) {
      throw new Error('Result missing data for Merkle verification (scriptHash, rawChunkData, treeLoc)');
    }
    if (result.isWhale) throw new Error('Cannot verify whale addresses');

    const verified = await verifyMerkleDpf(
      this.ws0!, this.ws1!, merkle,
      result.scriptHash, result.rawChunkData, result.treeLoc,
      onProgress,
      (msg, level) => this.log(msg, level),
    );
    result.merkleVerified = verified;
    return verified;
  }
}

/**
 * Create a Batch PIR client
 */
export function createBatchPirClient(
  server0Url: string = 'wss://pir1.chenweikeng.com',
  server1Url: string = 'wss://pir2.chenweikeng.com',
): BatchPirClient {
  return new BatchPirClient({ server0Url, server1Url });
}
