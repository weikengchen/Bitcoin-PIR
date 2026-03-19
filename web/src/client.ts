/**
 * Two-level Batch PIR WebSocket client.
 *
 * Supports true batching: multiple script hashes are packed into a single
 * batch of K=75 index buckets (Level 1) and K_CHUNK=80 chunk buckets
 * (Level 2) using cuckoo placement, minimizing round-trips.
 */

import {
  K, K_CHUNK, NUM_HASHES,
  SCRIPT_HASH_SIZE, INDEX_ENTRY_SIZE, INDEX_RESULT_SIZE,
  CHUNK_SIZE, CHUNKS_PER_UNIT, UNIT_DATA_SIZE,
  CHUNK_SLOT_SIZE, CHUNK_RESULT_SIZE,
  CUCKOO_BUCKET_SIZE,
  DPF_N,
} from './constants.js';

import {
  deriveBuckets, deriveCuckooKey, cuckooHash,
  deriveChunkBuckets, deriveChunkCuckooKey, cuckooHashInt,
  splitmix64,
} from './hash.js';

import { genDpfKeys } from './dpf.js';

import {
  encodeRequest, decodeResponse,
  type Request, type Response, type BatchQuery, type BatchResult, type ServerInfo,
} from './protocol.js';

// ─── Types ─────────────────────────────────────────────────────────────────

export interface UtxoEntry {
  txid: Uint8Array;    // 32-byte raw TXID (internal byte order)
  vout: number;
  amount: bigint;      // satoshis
}

export interface QueryResult {
  entries: UtxoEntry[];
  totalSats: bigint;
  offsetHalf: number;
  numChunks: number;
  numRounds: number;
}

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting';

export interface BatchPirClientConfig {
  server0Url: string;
  server1Url: string;
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  onLog?: (message: string, level: 'info' | 'success' | 'error') => void;
}

// ─── PRNG for dummy queries ────────────────────────────────────────────────

class DummyRng {
  private state: bigint;

  constructor() {
    this.state = splitmix64(BigInt(Date.now()));
  }

  nextU64(): bigint {
    this.state = (this.state + 0x9e3779b97f4a7c15n) & 0xFFFFFFFFFFFFFFFFn;
    return splitmix64(this.state);
  }
}

// ─── Client ────────────────────────────────────────────────────────────────

export class BatchPirClient {
  private ws0: WebSocket | null = null;
  private ws1: WebSocket | null = null;
  private config: BatchPirClientConfig;
  private connectionState: ConnectionState = 'disconnected';
  private rng = new DummyRng();

  // Server info (fetched on connect)
  private indexBins = 0;
  private chunkBins = 0;

  // Pending response queues (FIFO)
  private pending0: Array<(data: Uint8Array) => void> = [];
  private pending1: Array<(data: Uint8Array) => void> = [];

  // Heartbeat
  private heartbeatTimers: Map<0 | 1, ReturnType<typeof setInterval>> = new Map();

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
    return (
      this.ws0 !== null && this.ws1 !== null &&
      this.ws0.readyState === WebSocket.OPEN &&
      this.ws1.readyState === WebSocket.OPEN
    );
  }

  // ─── Connection ────────────────────────────────────────────────────────

  async connect(): Promise<void> {
    this.setConnectionState('connecting', 'Connecting to servers...');

    try {
      await Promise.all([
        this.connectToServer(0),
        this.connectToServer(1),
      ]);

      this.setConnectionState('connected', 'Connected to both servers');
      this.log('Connected to both servers', 'success');

      // Fetch server info
      await this.fetchServerInfo();

      // Start heartbeats
      this.startHeartbeat(0);
      this.startHeartbeat(1);
    } catch (error) {
      this.setConnectionState('disconnected', `Connection failed: ${error}`);
      throw error;
    }
  }

  private connectToServer(serverNum: 0 | 1): Promise<void> {
    const url = serverNum === 0 ? this.config.server0Url : this.config.server1Url;
    this.log(`Connecting to server ${serverNum}: ${url}`);

    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';

      ws.onopen = () => {
        if (serverNum === 0) {
          this.ws0 = ws;
          this.pending0 = [];
        } else {
          this.ws1 = ws;
          this.pending1 = [];
        }
        resolve();
      };

      ws.onerror = (event) => {
        reject(new Error(`Failed to connect to server ${serverNum}`));
      };

      ws.onmessage = (event) => {
        const data = new Uint8Array(event.data as ArrayBuffer);

        // Skip Pong responses from our heartbeat Ping requests.
        // Protocol: [4B len LE][1B variant] — Pong variant is 0x00 with len=1.
        // Without this check, Pong responses steal query callbacks from the
        // pending queue, corrupting in-flight queries.
        if (data.length >= 5) {
          const len = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
          if (len === 1 && data[4] === 0x00) {
            return; // Pong — silently discard
          }
        }

        const queue = serverNum === 0 ? this.pending0 : this.pending1;
        const cb = queue.shift();
        if (cb) cb(data);
      };

      ws.onclose = () => {
        if (serverNum === 0) this.ws0 = null;
        else this.ws1 = null;
        this.stopHeartbeat(serverNum);
      };
    });
  }

  disconnect(): void {
    this.stopHeartbeat(0);
    this.stopHeartbeat(1);
    this.ws0?.close();
    this.ws1?.close();
    this.ws0 = null;
    this.ws1 = null;
    this.pending0 = [];
    this.pending1 = [];
    this.setConnectionState('disconnected', 'Disconnected');
  }

  private startHeartbeat(serverNum: 0 | 1): void {
    this.stopHeartbeat(serverNum);
    const timer = setInterval(() => {
      const ws = serverNum === 0 ? this.ws0 : this.ws1;
      if (ws && ws.readyState === WebSocket.OPEN) {
        const pingMsg = encodeRequest({ type: 'Ping' });
        ws.send(pingMsg);
      }
    }, 30000);
    this.heartbeatTimers.set(serverNum, timer);
  }

  private stopHeartbeat(serverNum: 0 | 1): void {
    const timer = this.heartbeatTimers.get(serverNum);
    if (timer) {
      clearInterval(timer);
      this.heartbeatTimers.delete(serverNum);
    }
  }

  // ─── Raw WebSocket send/receive ────────────────────────────────────────

  private sendRaw(serverNum: 0 | 1, encoded: Uint8Array): Promise<Uint8Array> {
    const ws = serverNum === 0 ? this.ws0 : this.ws1;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      throw new Error(`Not connected to server ${serverNum}`);
    }

    const queue = serverNum === 0 ? this.pending0 : this.pending1;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        const idx = queue.indexOf(cb);
        if (idx !== -1) queue.splice(idx, 1);
        reject(new Error(`Request to server ${serverNum} timed out`));
      }, 120000);

      const cb = (data: Uint8Array) => {
        clearTimeout(timeout);
        resolve(data);
      };

      queue.push(cb);
      ws.send(encoded);
    });
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
    const resp = await this.sendRequest(0, { type: 'GetInfo' });
    if (resp.type !== 'Info') {
      throw new Error(`Unexpected response for GetInfo: ${resp.type}`);
    }
    this.indexBins = resp.info.indexBinsPerTable;
    this.chunkBins = resp.info.chunkBinsPerTable;
    this.log(`Server info: index_bins=${this.indexBins}, chunk_bins=${this.chunkBins}, index_K=${resp.info.indexK}, chunk_K=${resp.info.chunkK}`);

    await this.sendRequest(1, { type: 'GetInfo' });
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

  // ─── Index result parsing ─────────────────────────────────────────────

  private findEntryInIndexResult(
    result: Uint8Array,
    scriptHash: Uint8Array,
  ): { offsetHalf: number; numChunks: number } | null {
    for (let slot = 0; slot < CUCKOO_BUCKET_SIZE; slot++) {
      const base = slot * INDEX_ENTRY_SIZE;
      let match = true;
      for (let j = 0; j < SCRIPT_HASH_SIZE; j++) {
        if (result[base + j] !== scriptHash[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        const dv = new DataView(result.buffer, result.byteOffset + base, INDEX_ENTRY_SIZE);
        const offsetHalf = dv.getUint32(20, true);
        const numChunks = dv.getUint32(24, true);
        return { offsetHalf, numChunks };
      }
    }
    return null;
  }

  // ─── Chunk result parsing ─────────────────────────────────────────────

  private findChunkInResult(result: Uint8Array, chunkId: number): Uint8Array | null {
    const target = new Uint8Array(4);
    new DataView(target.buffer).setUint32(0, chunkId, true);

    for (let slot = 0; slot < CUCKOO_BUCKET_SIZE; slot++) {
      const base = slot * CHUNK_SLOT_SIZE;
      if (
        result[base] === target[0] &&
        result[base + 1] === target[1] &&
        result[base + 2] === target[2] &&
        result[base + 3] === target[3]
      ) {
        return result.slice(base + 4, base + CHUNK_SLOT_SIZE);
      }
    }
    return null;
  }

  // ─── Cuckoo placement (generic) ───────────────────────────────────────

  /** Cuckoo placement with eviction. Returns true if qi was placed. */
  private cuckooPlace(
    candBuckets: number[][],
    buckets: (number | null)[],
    qi: number,
    maxKicks: number,
  ): boolean {
    const cands = candBuckets[qi];

    // Try direct placement
    for (const c of cands) {
      if (buckets[c] === null) {
        buckets[c] = qi;
        return true;
      }
    }

    // Eviction loop
    let currentQi = qi;
    let currentBucket = candBuckets[currentQi][0];

    for (let kick = 0; kick < maxKicks; kick++) {
      const evictedQi = buckets[currentBucket]!;
      buckets[currentBucket] = currentQi;
      const evCands = candBuckets[evictedQi];

      for (let offset = 0; offset < NUM_HASHES; offset++) {
        const c = evCands[(kick + offset) % NUM_HASHES];
        if (c === currentBucket) continue;
        if (buckets[c] === null) {
          buckets[c] = evictedQi;
          return true;
        }
      }

      let nextBucket = evCands[0];
      for (let offset = 0; offset < NUM_HASHES; offset++) {
        const c = evCands[(kick + offset) % NUM_HASHES];
        if (c !== currentBucket) {
          nextBucket = c;
          break;
        }
      }
      currentQi = evictedQi;
      currentBucket = nextBucket;
    }

    return false;
  }

  /**
   * Plan multi-round placement for items with NUM_HASHES candidate buckets.
   * Returns rounds, each round is array of [itemIndex, bucketId].
   */
  private planRounds(
    itemBuckets: number[][],
    numBuckets: number,
  ): [number, number][][] {
    let remaining = itemBuckets.map((_, i) => i);
    const rounds: [number, number][][] = [];

    while (remaining.length > 0) {
      const candBuckets = remaining.map(i => itemBuckets[i]);
      const bucketOwner: (number | null)[] = new Array(numBuckets).fill(null);
      const placedLocal: number[] = [];

      for (let li = 0; li < candBuckets.length; li++) {
        if (placedLocal.length >= numBuckets) break;
        const savedBuckets = [...bucketOwner];
        if (this.cuckooPlace(candBuckets, bucketOwner, li, 500)) {
          placedLocal.push(li);
        } else {
          for (let b = 0; b < numBuckets; b++) bucketOwner[b] = savedBuckets[b];
        }
      }

      const roundEntries: [number, number][] = [];
      for (let b = 0; b < numBuckets; b++) {
        const localIdx = bucketOwner[b];
        if (localIdx !== null) {
          roundEntries.push([remaining[localIdx], b]);
        }
      }

      if (roundEntries.length === 0) {
        this.log(`ERROR: could not place any items, ${remaining.length} remaining`, 'error');
        break;
      }

      const placedOrigIdx = new Set(placedLocal.map(li => remaining[li]));
      remaining = remaining.filter(i => !placedOrigIdx.has(i));
      rounds.push(roundEntries);
    }

    return rounds;
  }

  // ─── Varint decoder ───────────────────────────────────────────────────

  private readVarint(data: Uint8Array, offset: number): { value: bigint; bytesRead: number } {
    let result = 0n;
    let shift = 0;
    let bytesRead = 0;

    while (true) {
      if (offset + bytesRead >= data.length) {
        throw new Error('Unexpected end of data while reading varint');
      }
      const byte = data[offset + bytesRead];
      bytesRead++;
      result |= BigInt(byte & 0x7F) << BigInt(shift);
      if ((byte & 0x80) === 0) break;
      shift += 7;
      if (shift >= 64) throw new Error('VarInt too large');
    }

    return { value: result, bytesRead };
  }

  // ─── Decode UTXO data from chunk bytes ────────────────────────────────

  private decodeUtxoData(fullData: Uint8Array): { entries: UtxoEntry[]; totalSats: bigint } {
    let pos = 0;
    const { value: numEntries, bytesRead: countBytes } = this.readVarint(fullData, pos);
    pos += countBytes;

    const entries: UtxoEntry[] = [];
    let totalSats = 0n;

    for (let i = 0; i < Number(numEntries); i++) {
      if (pos + 32 > fullData.length) {
        this.log(`Data truncated at entry ${i}`, 'error');
        break;
      }

      const txid = fullData.slice(pos, pos + 32);
      pos += 32;

      const { value: vout, bytesRead: vr } = this.readVarint(fullData, pos);
      pos += vr;

      const { value: amount, bytesRead: ar } = this.readVarint(fullData, pos);
      pos += ar;

      totalSats += amount;
      entries.push({
        txid: new Uint8Array(txid),
        vout: Number(vout),
        amount,
      });
    }

    return { entries, totalSats };
  }

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
    const indexRounds = this.planRounds(indexCandBuckets, K);
    this.log(`Level 1: ${N} queries → ${indexRounds.length} index round(s)`);

    // Per-query results from Level 1: query index → { offsetHalf, numChunks }
    const indexResults: Map<number, { offsetHalf: number; numChunks: number }> = new Map();

    for (let ir = 0; ir < indexRounds.length; ir++) {
      const round = indexRounds[ir];
      progress('Level 1', `Index round ${ir + 1}/${indexRounds.length} (${round.length} queries)...`);
      this.log(`  Index round ${ir + 1}: ${round.length} queries in ${K} buckets`);

      // Build bucket → query mapping: which query goes in which bucket
      const bucketToQuery: Map<number, number> = new Map();
      for (const [queryIdx, bucketId] of round) {
        bucketToQuery.set(bucketId, queryIdx);
      }

      // Generate DPF keys for all K buckets
      progress('Level 1', `Round ${ir + 1}: generating DPF keys...`);
      const s0Keys: [Uint8Array, Uint8Array][] = [];
      const s1Keys: [Uint8Array, Uint8Array][] = [];

      for (let b = 0; b < K; b++) {
        const qi = bucketToQuery.get(b);
        let alpha0: number, alpha1: number;

        if (qi !== undefined) {
          // Real query in this bucket
          const sh = scriptHashes[qi];
          const ck0 = deriveCuckooKey(b, 0);
          const ck1 = deriveCuckooKey(b, 1);
          alpha0 = cuckooHash(sh, ck0, this.indexBins);
          alpha1 = cuckooHash(sh, ck1, this.indexBins);
        } else {
          // Dummy — random targets for privacy
          alpha0 = Number(this.rng.nextU64() % BigInt(this.indexBins));
          alpha1 = Number(this.rng.nextU64() % BigInt(this.indexBins));
        }

        const keys0 = await genDpfKeys(alpha0);
        const keys1 = await genDpfKeys(alpha1);
        s0Keys.push([keys0.key0, keys1.key0]);
        s1Keys.push([keys0.key1, keys1.key1]);
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

        const resultQ0 = this.xorBuffers(r0[0], r1[0]);
        const resultQ1 = this.xorBuffers(r0[1], r1[1]);

        const found = this.findEntryInIndexResult(resultQ0, scriptHashes[queryIdx])
          || this.findEntryInIndexResult(resultQ1, scriptHashes[queryIdx]);

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
    const queryChunkInfo: Map<number, { startChunk: number; numUnits: number; offsetHalf: number; numChunks: number }> = new Map();
    const allChunkIdsSet = new Set<number>();

    for (const [qi, info] of indexResults) {
      const startChunk = Math.floor((info.offsetHalf * 2) / CHUNK_SIZE);
      const numUnits = Math.ceil(info.numChunks / CHUNKS_PER_UNIT);
      const chunkIds: number[] = [];
      for (let u = 0; u < numUnits; u++) {
        const cid = startChunk + u * CHUNKS_PER_UNIT;
        chunkIds.push(cid);
        allChunkIdsSet.add(cid);
      }
      queryChunkInfo.set(qi, { startChunk, numUnits, offsetHalf: info.offsetHalf, numChunks: info.numChunks });
    }

    const allChunkIds = Array.from(allChunkIdsSet).sort((a, b) => a - b);
    this.log(`Level 2: ${allChunkIds.length} unique chunks to fetch across ${indexResults.size} queries`);

    // Plan chunk rounds collectively
    const chunkCandBuckets = allChunkIds.map(cid => deriveChunkBuckets(cid));
    const chunkRounds = this.planRounds(
      chunkCandBuckets,
      K_CHUNK,
    );
    // chunkRounds[r][i] = [chunkListIndex, bucketId]
    this.log(`  ${allChunkIds.length} chunks → ${chunkRounds.length} chunk round(s)`);

    // Execute chunk rounds
    const recoveredChunks = new Map<number, Uint8Array>();

    for (let ri = 0; ri < chunkRounds.length; ri++) {
      const roundPlan = chunkRounds[ri];
      progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length} (${roundPlan.length} chunks)...`);

      // Build target map: bucket → (loc0, loc1)
      const bucketTargets: Map<number, [number, number]> = new Map();
      for (const [chunkListIdx, bucketId] of roundPlan) {
        const chunkId = allChunkIds[chunkListIdx];
        const ck0 = deriveChunkCuckooKey(bucketId, 0);
        const ck1 = deriveChunkCuckooKey(bucketId, 1);
        const l0 = cuckooHashInt(chunkId, ck0, this.chunkBins);
        const l1 = cuckooHashInt(chunkId, ck1, this.chunkBins);
        bucketTargets.set(bucketId, [l0, l1]);
      }

      // Generate DPF keys for all K_CHUNK buckets
      const s0Keys: [Uint8Array, Uint8Array][] = [];
      const s1Keys: [Uint8Array, Uint8Array][] = [];

      for (let b = 0; b < K_CHUNK; b++) {
        const target = bucketTargets.get(b);
        let alpha0: number, alpha1: number;
        if (target) {
          [alpha0, alpha1] = target;
        } else {
          alpha0 = Number(this.rng.nextU64() % BigInt(this.chunkBins));
          alpha1 = Number(this.rng.nextU64() % BigInt(this.chunkBins));
        }

        const keys0 = await genDpfKeys(alpha0);
        const keys1 = await genDpfKeys(alpha1);
        s0Keys.push([keys0.key0, keys1.key0]);
        s1Keys.push([keys0.key1, keys1.key1]);
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

        const rq0 = this.xorBuffers(cr0[0], cr1[0]);
        const rq1 = this.xorBuffers(cr0[1], cr1[1]);

        const data = this.findChunkInResult(rq0, chunkId)
          || this.findChunkInResult(rq1, chunkId);

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
      const info = queryChunkInfo.get(qi);
      if (!info) {
        // Not found in index
        continue;
      }

      const { startChunk, numUnits, offsetHalf, numChunks } = info;
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

      const { entries, totalSats } = this.decodeUtxoData(fullData);
      results[qi] = {
        entries,
        totalSats,
        offsetHalf,
        numChunks,
        numRounds: totalChunkRounds,
      };
    }

    const found = results.filter(r => r !== null).length;
    this.log(`=== Batch complete: ${found}/${N} queries returned results ===`, 'success');

    return results;
  }
}

/**
 * Create a Batch PIR client
 */
export function createBatchPirClient(
  server0Url: string = 'wss://dpf1.chenweikeng.com',
  server1Url: string = 'wss://dpf2.chenweikeng.com',
): BatchPirClient {
  return new BatchPirClient({ server0Url, server1Url });
}
