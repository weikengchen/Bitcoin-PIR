/**
 * HarmonyPIR Web Client
 *
 * Two-server stateful PIR client for Bitcoin UTXO lookups.
 * - Hint Server: computes and sends hint parities (offline phase)
 * - Query Server: answers online queries (simple indexed lookups)
 *
 * Each PBC bucket is managed by a WASM HarmonyBucket instance that
 * handles the PRP-based relocation data structure and XOR operations.
 */

import {
  K, K_CHUNK, NUM_HASHES,
  CUCKOO_BUCKET_SIZE, INDEX_CUCKOO_NUM_HASHES,
  CHUNK_CUCKOO_BUCKET_SIZE, CHUNK_CUCKOO_NUM_HASHES,
  INDEX_ENTRY_SIZE, CHUNK_SLOT_SIZE, CHUNK_SIZE, TAG_SIZE,
  HARMONY_INDEX_W, HARMONY_CHUNK_W, HARMONY_EMPTY,
  REQ_HARMONY_GET_INFO, REQ_HARMONY_HINTS,
  REQ_HARMONY_BATCH_QUERY, RESP_HARMONY_BATCH_QUERY,
  RESP_HARMONY_INFO, RESP_HARMONY_HINTS, RESP_ERROR,
} from './constants.js';

import {
  deriveBuckets, deriveCuckooKey, cuckooHash, computeTag,
  deriveChunkBuckets, deriveChunkCuckooKey, cuckooHashInt,
  scriptHash as computeScriptHash, addressToScriptPubKey,
  hexToBytes, bytesToHex,
} from './hash.js';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface HarmonyPirClientConfig {
  hintServerUrl: string;
  queryServerUrl: string;
  onProgress?: (msg: string) => void;
  /** PRP backend: 0=Hoang (default), 1=FastPRP, 2=ALF */
  prpBackend?: number;
}

export interface UtxoEntry {
  txid: string;
  vout: number;
  value: number;
}

export interface HarmonyQueryResult {
  address: string;
  scriptHash: string;
  utxos: UtxoEntry[];
  whale: boolean;
}

// ─── WASM module type (loaded dynamically) ──────────────────────────────────

interface HarmonyWasmModule {
  HarmonyBucket: {
    new(n: number, w: number, t: number, prpKey: Uint8Array, bucketId: number): HarmonyBucketWasm;
  };
  compute_balanced_t(n: number): number;
  verify_protocol(n: number, w: number): boolean;
}

interface HarmonyBucketWasm {
  load_hints(hintsData: Uint8Array): void;
  build_request(q: number): HarmonyRequestWasm;
  build_synthetic_dummy(): Uint8Array;
  process_response(response: Uint8Array): Uint8Array;
  queries_remaining(): number;
  queries_used(): number;
  real_n(): number;
  n(): number;
  w(): number;
  t(): number;
  m(): number;
  max_queries(): number;
  free(): void;
}

interface HarmonyRequestWasm {
  request: Uint8Array;
  segment: number;
  position: number;
  query_index: number;
  free(): void;
}

// ─── Client class ───────────────────────────────────────────────────────────

export class HarmonyPirClient {
  private config: HarmonyPirClientConfig;
  private wasm: HarmonyWasmModule | null = null;
  private queryWs: WebSocket | null = null;
  private hintWs: WebSocket | null = null;

  // Per-bucket WASM state
  private indexBuckets: Map<number, HarmonyBucketWasm> = new Map();
  private chunkBuckets: Map<number, HarmonyBucketWasm> = new Map();

  // Server params
  private indexBinsPerTable = 0;
  private chunkBinsPerTable = 0;
  private tagSeed = 0n;
  private prpKey: Uint8Array;

  // Pending response callbacks
  private pendingCallbacks: Map<string, (data: Uint8Array) => void> = new Map();
  private callbackId = 0;

  constructor(config: HarmonyPirClientConfig) {
    this.config = config;
    // Generate random PRP key.
    this.prpKey = new Uint8Array(16);
    crypto.getRandomValues(this.prpKey);
  }

  private log(msg: string) {
    this.config.onProgress?.(msg);
  }

  /** Load the HarmonyPIR WASM module for the selected PRP backend. */
  async loadWasm(): Promise<void> {
    if (this.wasm) return;
    const backend = this.config.prpBackend ?? 0;

    // Each PRP backend has its own WASM build in a separate directory.
    const wasmDirs: Record<number, string> = {
      0: '/wasm/harmonypir',          // Hoang (default)
      1: '/wasm/harmonypir-fastprp',  // FastPRP
      2: '/wasm/harmonypir-alf',      // ALF
    };
    const wasmDir = wasmDirs[backend] ?? wasmDirs[0];
    const jsUrl = `${wasmDir}/harmonypir_wasm.js`;

    // Remove any previously loaded wasm_bindgen script to avoid conflicts.
    const oldScript = document.getElementById('harmonypir-wasm-script');
    if (oldScript) oldScript.remove();
    (globalThis as any).wasm_bindgen = undefined;

    // Dynamically load the WASM JS file.
    await new Promise<void>((resolve, reject) => {
      const script = document.createElement('script');
      script.id = 'harmonypir-wasm-script';
      script.src = jsUrl;
      script.onload = () => resolve();
      script.onerror = () => reject(new Error(`Failed to load WASM from ${jsUrl}`));
      document.head.appendChild(script);
    });

    const wb = (globalThis as any).wasm_bindgen;
    if (!wb) {
      throw new Error(`HarmonyPIR WASM did not initialize from ${jsUrl}`);
    }
    // Initialize the WASM module (loads .wasm from the same directory).
    await wb(`${wasmDir}/harmonypir_wasm_bg.wasm`);
    this.wasm = wb as any;
    this.log(`WASM loaded: ${['Hoang', 'FastPRP', 'ALF'][backend]} (${jsUrl})`);
  }

  /** Connect to the Query Server via WebSocket. */
  async connectQueryServer(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.queryWs = new WebSocket(this.config.queryServerUrl);
      this.queryWs.binaryType = 'arraybuffer';
      this.queryWs.onopen = () => {
        this.log('Connected to Query Server');
        resolve();
      };
      this.queryWs.onerror = (e) => reject(e);
      this.queryWs.onmessage = (ev) => this.handleQueryResponse(ev);
    });
  }

  /** Fetch server info (bins_per_table, tag_seed) from Query Server. */
  async fetchServerInfo(): Promise<void> {
    const info = await this.sendQueryRequest(
      new Uint8Array([REQ_HARMONY_GET_INFO])
    );
    if (info[0] === RESP_ERROR) {
      throw new Error('Server returned error for HarmonyGetInfo');
    }
    const view = new DataView(info.buffer, info.byteOffset);
    this.indexBinsPerTable = view.getUint32(1, true);
    this.chunkBinsPerTable = view.getUint32(5, true);
    this.tagSeed = view.getBigUint64(11, true);
    this.log(`Server info: indexBins=${this.indexBinsPerTable}, chunkBins=${this.chunkBinsPerTable}`);
  }

  /** Initialize WASM bucket instances for all PBC groups. */
  initBuckets(): void {
    if (!this.wasm) throw new Error('WASM not loaded');

    for (let b = 0; b < K; b++) {
      const bucket = new this.wasm.HarmonyBucket(
        this.indexBinsPerTable, HARMONY_INDEX_W, 0, this.prpKey, b
      );
      this.indexBuckets.set(b, bucket);
    }

    for (let b = 0; b < K_CHUNK; b++) {
      const bucket = new this.wasm.HarmonyBucket(
        this.chunkBinsPerTable, HARMONY_CHUNK_W, 0, this.prpKey, K + b
      );
      this.chunkBuckets.set(b, bucket);
    }

    this.log(`Initialized ${K} index + ${K_CHUNK} chunk HarmonyPIR buckets`);
  }

  /**
   * Fetch hints from the Hint Server for all buckets.
   * This is the offline phase — typically done once per session.
   */
  async fetchHints(): Promise<void> {
    this.log('Fetching hints from Hint Server...');

    // Connect to Hint Server.
    const hintWs = await this.connectHintServer();

    // Request index hints.
    await this.requestHints(hintWs, 0, K, this.indexBuckets, HARMONY_INDEX_W);
    this.log('Index hints loaded');

    // Request chunk hints.
    await this.requestHints(hintWs, 1, K_CHUNK, this.chunkBuckets, HARMONY_CHUNK_W);
    this.log('Chunk hints loaded');

    hintWs.close();
    this.log('Hints complete (~' + this.estimateHintSize() + ' MB)');
  }

  /**
   * Query a single Bitcoin address via HarmonyPIR.
   * Delegates to queryBatch with a single address.
   */
  async query(address: string): Promise<HarmonyQueryResult> {
    const results = await this.queryBatch([address]);
    return results.get(0) ?? { address, scriptHash: '', utxos: [], whale: false };
  }

  // ─── Private helpers ────────────────────────────────────────────────────

  /** Scan a bin (w bytes) for a matching tag and extract index entry metadata. */
  private findTagInBin(
    binData: Uint8Array,
    scriptHashBytes: Uint8Array,
    w: number,
  ): { startChunkId: number; numChunks: number } | null {
    const expectedTag = computeTag(this.tagSeed, scriptHashBytes);
    const view = new DataView(binData.buffer, binData.byteOffset, binData.byteLength);

    const numSlots = w / INDEX_ENTRY_SIZE;
    for (let slot = 0; slot < numSlots; slot++) {
      const offset = slot * INDEX_ENTRY_SIZE;
      if (offset + INDEX_ENTRY_SIZE > binData.length) break;

      const tag = view.getBigUint64(offset, true);
      if (tag === expectedTag) {
        const startChunkId = view.getUint32(offset + TAG_SIZE, true);
        const numChunks = binData[offset + TAG_SIZE + 4];
        return { startChunkId, numChunks };
      }
    }

    return null;
  }

  /** Scan a chunk bin for matching chunk_id and extract the chunk data. */
  private findChunkInBin(binData: Uint8Array, targetChunkId: number): Uint8Array | null {
    const view = new DataView(binData.buffer, binData.byteOffset, binData.byteLength);
    const numSlots = binData.length / CHUNK_SLOT_SIZE;

    for (let slot = 0; slot < numSlots; slot++) {
      const offset = slot * CHUNK_SLOT_SIZE;
      if (offset + CHUNK_SLOT_SIZE > binData.length) break;

      const chunkId = view.getUint32(offset, true);
      if (chunkId === targetChunkId) {
        return binData.slice(offset + 4, offset + 4 + CHUNK_SIZE);
      }
    }

    return null;
  }

  /** Decode UTXOs from chunk data. Simple varint-encoded format. */
  private decodeUtxos(chunks: Uint8Array[]): UtxoEntry[] {
    if (chunks.length === 0) return [];

    // Concatenate all chunk data.
    const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
    const data = new Uint8Array(totalLen);
    let pos = 0;
    for (const chunk of chunks) {
      data.set(chunk, pos);
      pos += chunk.length;
    }

    // Decode: each UTXO is [32B txid][4B vout LE][8B value LE] = 44 bytes
    // But the actual format depends on the build pipeline encoding.
    // For now, return raw data as a single entry.
    const utxos: UtxoEntry[] = [];
    let offset = 0;
    while (offset + 44 <= data.length) {
      const view = new DataView(data.buffer, data.byteOffset + offset);
      const txidBytes = data.slice(offset, offset + 32);
      // Check if all zeros (padding).
      if (txidBytes.every(b => b === 0)) break;
      const txid = bytesToHex(new Uint8Array([...txidBytes].reverse()));
      const vout = view.getUint32(32, true);
      const value = Number(view.getBigUint64(36, true));
      utxos.push({ txid, vout, value });
      offset += 44;
    }

    return utxos;
  }

  /** Send a request to Query Server and wait for the response. */
  private sendQueryRequest(payload: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      if (!this.queryWs || this.queryWs.readyState !== WebSocket.OPEN) {
        return reject(new Error('Query Server not connected'));
      }

      // Length-prefix the payload.
      const msg = new Uint8Array(4 + payload.length);
      new DataView(msg.buffer).setUint32(0, payload.length, true);
      msg.set(payload, 4);

      const id = String(this.callbackId++);
      this.pendingCallbacks.set(id, resolve);

      // For simplicity, treat the next response as this request's answer.
      // (Production would use round_id for multiplexing.)
      this.queryWs.send(msg);
    });
  }

  private handleQueryResponse(ev: MessageEvent) {
    const data = new Uint8Array(ev.data as ArrayBuffer);
    if (data.length < 4) return;
    const payload = data.slice(4); // skip length prefix

    // Route to first pending callback (FIFO).
    const firstKey = this.pendingCallbacks.keys().next().value;
    if (firstKey !== undefined) {
      const cb = this.pendingCallbacks.get(firstKey)!;
      this.pendingCallbacks.delete(firstKey);
      cb(payload);
    }
  }

  private connectHintServer(): Promise<WebSocket> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.config.hintServerUrl);
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => {
        this.log('Connected to Hint Server');
        resolve(ws);
      };
      ws.onerror = (e) => reject(e);
    });
  }

  /** Request hints from the Hint Server for a set of buckets at one level. */
  private async requestHints(
    ws: WebSocket,
    level: number,
    numBuckets: number,
    buckets: Map<number, HarmonyBucketWasm>,
    w: number,
  ): Promise<void> {
    // Build hint request.
    const bucketIds = Array.from({ length: numBuckets }, (_, i) => i);
    const msg = new Uint8Array(1 + 16 + 1 + 1 + numBuckets);
    msg[0] = REQ_HARMONY_HINTS;
    msg.set(this.prpKey, 1);
    msg[17] = level;
    msg[18] = numBuckets;
    for (let i = 0; i < numBuckets; i++) {
      msg[19 + i] = bucketIds[i];
    }

    // Length-prefix and send.
    const fullMsg = new Uint8Array(4 + msg.length);
    new DataView(fullMsg.buffer).setUint32(0, msg.length, true);
    fullMsg.set(msg, 4);

    // Listen for hint responses.
    return new Promise((resolve, reject) => {
      let received = 0;
      ws.onmessage = (ev) => {
        const data = new Uint8Array(ev.data as ArrayBuffer);
        if (data.length < 4) return;
        const payload = data.slice(4);

        if (payload[0] === RESP_HARMONY_HINTS) {
          const bucketId = payload[1];
          const view = new DataView(payload.buffer, payload.byteOffset);
          const n = view.getUint32(2, true);
          const t = view.getUint32(6, true);
          const m = view.getUint32(10, true);
          const hintsData = payload.slice(14);

          const bucket = buckets.get(bucketId);
          if (bucket) {
            bucket.load_hints(hintsData);
          }

          received++;
          this.log(`  Hints: ${received}/${numBuckets} (level ${level})`);
          if (received === numBuckets) {
            resolve();
          }
        } else if (payload[0] === RESP_ERROR) {
          reject(new Error('Hint server error'));
        }
      };

      ws.send(fullMsg);
    });
  }

  estimateHintSize(): string {
    let total = 0;
    for (const [_, bucket] of this.indexBuckets) {
      total += bucket.m() * bucket.w();
    }
    for (const [_, bucket] of this.chunkBuckets) {
      total += bucket.m() * bucket.w();
    }
    return (total / (1024 * 1024)).toFixed(1);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Batch query — full Batch PIR flow matching DPF-PIR structure
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Query a batch of Bitcoin addresses in one go.
   *
   * Protocol flow (matching the Rust harmonypir_batch_trace):
   *
   * INDEX:
   *   For each placement round:
   *     For h = 0 .. INDEX_CUCKOO_NUM_HASHES-1:
   *       - Real query (build_request) for buckets whose tag is NOT yet found
   *       - Fake query (build_synthetic_dummy) for buckets whose tag WAS found
   *       - Synthetic dummy for unassigned buckets
   *       → 1 batch message with K buckets × 1 sub-query each
   *       → Server responds, client calls process_response for real queries
   *
   * CHUNK:
   *   Same structure with K_CHUNK buckets and CHUNK_CUCKOO_NUM_HASHES rounds.
   */
  async queryBatch(
    addresses: string[],
    progress?: (phase: string, detail: string) => void,
  ): Promise<Map<number, HarmonyQueryResult>> {
    const N = addresses.length;
    const results = new Map<number, HarmonyQueryResult>();

    // ── Prepare script hashes (accept both addresses and hex scriptPubKeys) ──
    const scriptHashes: Uint8Array[] = [];
    const shHexes: string[] = [];
    for (let i = 0; i < N; i++) {
      const input = addresses[i];
      let spkHex: string | null;
      // Detect raw hex scriptPubKey vs. Bitcoin address.
      if (/^[0-9a-fA-F]+$/.test(input) && input.length % 2 === 0) {
        spkHex = input.toLowerCase();
      } else {
        spkHex = addressToScriptPubKey(input);
      }
      if (!spkHex) { this.log(`Invalid input ${i}: ${input}`); continue; }
      const sh = computeScriptHash(hexToBytes(spkHex));
      scriptHashes.push(sh);
      shHexes.push(bytesToHex(sh));
    }

    // ══════════════════════════════════════════════════════════════════
    // PHASE 1: INDEX — batch queries
    // ══════════════════════════════════════════════════════════════════
    progress?.('Level 1', 'Planning index rounds...');

    const indexCandBuckets = scriptHashes.map(sh => deriveBuckets(sh));
    const indexRounds = this.planRounds(indexCandBuckets, K);
    this.log(`Level 1: ${N} queries → ${indexRounds.length} index placement round(s) × ${INDEX_CUCKOO_NUM_HASHES} hash-fn rounds`);

    const indexResults = new Map<number, { startChunkId: number; numChunks: number }>();
    const whaleQueries = new Set<number>();

    for (let ir = 0; ir < indexRounds.length; ir++) {
      const round = indexRounds[ir];
      const bucketToQuery = new Map<number, number>();
      for (const [qi, bucketId] of round) {
        bucketToQuery.set(bucketId, qi);
      }

      const foundThisPlacement = new Set<number>(); // qi already found in this placement round

      for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
        progress?.('Level 1', `Index placement ${ir + 1}/${indexRounds.length}, h=${h}...`);

        const batchItems: Array<{ bucketId: number; subQueryBytes: Uint8Array[] }> = [];
        // Track which buckets have real queries (need process_response).
        const realBuckets = new Map<number, number>(); // bucketId → qi

        for (let b = 0; b < K; b++) {
          const bucket = this.indexBuckets.get(b)!;
          const qi = bucketToQuery.get(b);

          if (qi !== undefined) {
            if (foundThisPlacement.has(qi) || indexResults.has(qi) || whaleQueries.has(qi)) {
              // Already found — send fake to keep traffic uniform.
              const dummy = new Uint8Array(bucket.build_synthetic_dummy());
              batchItems.push({ bucketId: b, subQueryBytes: [dummy] });
            } else {
              // Real query with hash function h.
              const ck = deriveCuckooKey(b, h);
              const binIndex = cuckooHash(scriptHashes[qi], ck, this.indexBinsPerTable);
              const req = bucket.build_request(binIndex);
              const reqBytes = new Uint8Array(req.request);
              req.free();
              realBuckets.set(b, qi);
              batchItems.push({ bucketId: b, subQueryBytes: [reqBytes] });
            }
          } else {
            // Unassigned bucket — dummy.
            const dummy = new Uint8Array(bucket.build_synthetic_dummy());
            batchItems.push({ bucketId: b, subQueryBytes: [dummy] });
          }
        }

        // Send batch and get response.
        const roundId = ir * INDEX_CUCKOO_NUM_HASHES + h;
        const reqMsg = this.encodeHarmonyBatchRequest(0, roundId, 1, batchItems);
        const respData = await this.sendQueryRequest(reqMsg);
        const batchResp = this.decodeHarmonyBatchResponse(respData);

        // Process real responses only (fake/dummy have no state to consume).
        for (const [bucketId, qi] of realBuckets) {
          const bucket = this.indexBuckets.get(bucketId)!;
          const respItem = batchResp.get(bucketId);
          if (!respItem || respItem.length === 0) continue;

          const answer = bucket.process_response(respItem[0]);
          const found = this.findTagInBin(answer, scriptHashes[qi], HARMONY_INDEX_W);
          if (found) {
            if (found.numChunks === 0) {
              whaleQueries.add(qi);
            } else {
              indexResults.set(qi, found);
            }
            foundThisPlacement.add(qi);
          }
        }
      }
    }

    this.log(`Level 1 done: ${indexResults.size} found, ${whaleQueries.size} whales`);

    // ══════════════════════════════════════════════════════════════════
    // PHASE 2: CHUNK — global batch across all queries
    // ══════════════════════════════════════════════════════════════════
    progress?.('Level 2', 'Collecting chunk IDs...');

    const queryChunkInfo = new Map<number, { startChunk: number; numChunks: number }>();
    const allChunkIdsSet = new Set<number>();

    for (const [qi, info] of indexResults) {
      for (let ci = 0; ci < info.numChunks; ci++) {
        allChunkIdsSet.add(info.startChunkId + ci);
      }
      queryChunkInfo.set(qi, { startChunk: info.startChunkId, numChunks: info.numChunks });
    }

    const allChunkIds = Array.from(allChunkIdsSet).sort((a, b) => a - b);
    this.log(`Level 2: ${allChunkIds.length} unique chunks to fetch`);

    const recoveredChunks = new Map<number, Uint8Array>();

    if (allChunkIds.length > 0) {
      const chunkCandBuckets = allChunkIds.map(cid => deriveChunkBuckets(cid));
      const chunkRounds = this.planRounds(chunkCandBuckets, K_CHUNK);
      this.log(`  ${allChunkIds.length} chunks → ${chunkRounds.length} chunk placement round(s) × ${CHUNK_CUCKOO_NUM_HASHES} hash-fn rounds`);

      for (let ri = 0; ri < chunkRounds.length; ri++) {
        const roundPlan = chunkRounds[ri];
        const bucketToChunk = new Map<number, number>(); // bucketId → chunkListIdx
        for (const [chunkListIdx, bucketId] of roundPlan) {
          bucketToChunk.set(bucketId, chunkListIdx);
        }

        const foundThisPlacement = new Set<number>(); // chunk_ids found in this placement round

        for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
          progress?.('Level 2', `Chunk placement ${ri + 1}/${chunkRounds.length}, h=${h}...`);

          const batchItems: Array<{ bucketId: number; subQueryBytes: Uint8Array[] }> = [];
          const realBuckets = new Map<number, { chunkListIdx: number; chunkId: number }>();

          for (let b = 0; b < K_CHUNK; b++) {
            const bucket = this.chunkBuckets.get(b)!;
            const chunkListIdx = bucketToChunk.get(b);

            if (chunkListIdx !== undefined) {
              const chunkId = allChunkIds[chunkListIdx];
              if (foundThisPlacement.has(chunkId) || recoveredChunks.has(chunkId)) {
                // Already found — send fake.
                const dummy = new Uint8Array(bucket.build_synthetic_dummy());
                batchItems.push({ bucketId: b, subQueryBytes: [dummy] });
              } else {
                // Real query with hash function h.
                const ck = deriveChunkCuckooKey(b, h);
                const binIndex = cuckooHashInt(chunkId, ck, this.chunkBinsPerTable);
                const req = bucket.build_request(binIndex);
                const reqBytes = new Uint8Array(req.request);
                req.free();
                realBuckets.set(b, { chunkListIdx, chunkId });
                batchItems.push({ bucketId: b, subQueryBytes: [reqBytes] });
              }
            } else {
              // Unassigned — dummy.
              const dummy = new Uint8Array(bucket.build_synthetic_dummy());
              batchItems.push({ bucketId: b, subQueryBytes: [dummy] });
            }
          }

          const roundId = ri * CHUNK_CUCKOO_NUM_HASHES + h;
          const reqMsg = this.encodeHarmonyBatchRequest(1, roundId, 1, batchItems);
          const respData = await this.sendQueryRequest(reqMsg);
          const batchResp = this.decodeHarmonyBatchResponse(respData);

          // Process real responses.
          for (const [bucketId, { chunkId }] of realBuckets) {
            const bucket = this.chunkBuckets.get(bucketId)!;
            const respItem = batchResp.get(bucketId);
            if (!respItem || respItem.length === 0) continue;

            const answer = bucket.process_response(respItem[0]);
            const found = this.findChunkInBin(answer, chunkId);
            if (found) {
              recoveredChunks.set(chunkId, found);
              foundThisPlacement.add(chunkId);
            }
          }
        }
      }
    }

    this.log(`Level 2 done: ${recoveredChunks.size}/${allChunkIds.length} chunks recovered`);

    // ══════════════════════════════════════════════════════════════════
    // PHASE 3: Reassemble per-query results
    // ══════════════════════════════════════════════════════════════════
    progress?.('Reassemble', 'Decoding UTXO data...');

    for (let qi = 0; qi < N; qi++) {
      if (whaleQueries.has(qi)) {
        results.set(qi, { address: addresses[qi], scriptHash: shHexes[qi], utxos: [], whale: true });
        continue;
      }
      const info = queryChunkInfo.get(qi);
      if (!info) {
        results.set(qi, { address: addresses[qi], scriptHash: shHexes[qi], utxos: [], whale: false });
        continue;
      }
      const chunks: Uint8Array[] = [];
      for (let ci = 0; ci < info.numChunks; ci++) {
        const d = recoveredChunks.get(info.startChunk + ci);
        if (d) chunks.push(d);
      }
      const utxos = this.decodeUtxos(chunks);
      results.set(qi, { address: addresses[qi], scriptHash: shHexes[qi], utxos, whale: false });
    }

    return results;
  }

  // ─── Cuckoo placement (from DPF-PIR client.ts) ────────────────────────────

  /**
   * Cuckoo-place item qi into one of its candidate buckets.
   * Returns true if placed, false if maxKicks exceeded.
   */
  private cuckooPlace(
    candBuckets: number[][],
    buckets: (number | null)[],
    qi: number,
    maxKicks: number,
  ): boolean {
    const cands = candBuckets[qi];

    // Try direct placement.
    for (const c of cands) {
      if (buckets[c] === null) {
        buckets[c] = qi;
        return true;
      }
    }

    // Eviction loop.
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
   * Returns rounds, each round = [[itemIndex, bucketId], ...].
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
        this.log(`ERROR: could not place any items, ${remaining.length} remaining`);
        break;
      }

      const placedOrigIdx = new Set(placedLocal.map(li => remaining[li]));
      remaining = remaining.filter(i => !placedOrigIdx.has(i));
      rounds.push(roundEntries);
    }

    return rounds;
  }

  // ─── Batch wire protocol ───────────────────────────────────────────────────

  /** Encode a HarmonyBatchQuery message (excluding the 4B length prefix). */
  private encodeHarmonyBatchRequest(
    level: number,
    roundId: number,
    subQueriesPerBucket: number,
    items: Array<{ bucketId: number; subQueryBytes: Uint8Array[] }>,
  ): Uint8Array {
    // Compute total size.
    let size = 1 + 1 + 2 + 2 + 1; // variant + level + round_id + num_buckets + subQ
    for (const item of items) {
      size += 1; // bucket_id
      for (const sq of item.subQueryBytes) {
        size += 4 + sq.length; // count + indices
      }
    }

    const buf = new Uint8Array(size);
    const view = new DataView(buf.buffer);
    let pos = 0;

    buf[pos++] = REQ_HARMONY_BATCH_QUERY;
    buf[pos++] = level;
    view.setUint16(pos, roundId, true); pos += 2;
    view.setUint16(pos, items.length, true); pos += 2;
    buf[pos++] = subQueriesPerBucket;

    for (const item of items) {
      buf[pos++] = item.bucketId;
      for (const sq of item.subQueryBytes) {
        const count = sq.length / 4;
        view.setUint32(pos, count, true); pos += 4;
        buf.set(sq, pos); pos += sq.length;
      }
    }

    return buf;
  }

  /** Decode a HarmonyBatchResult response payload. */
  private decodeHarmonyBatchResponse(
    data: Uint8Array,
  ): Map<number, Uint8Array[]> {
    // data = [1B variant][1B level][2B round_id][2B num_buckets][1B subResultsPerBucket]
    //        per bucket: [1B bucket_id] per sub_result: [4B data_len][data]
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let pos = 1; // skip variant
    /* const level = */ data[pos++];
    /* const roundId = */ view.getUint16(pos, true); pos += 2;
    const numBuckets = view.getUint16(pos, true); pos += 2;
    const subResultsPerBucket = data[pos++];

    const result = new Map<number, Uint8Array[]>();
    for (let i = 0; i < numBuckets; i++) {
      const bucketId = data[pos++];
      const subResults: Uint8Array[] = [];
      for (let s = 0; s < subResultsPerBucket; s++) {
        const len = view.getUint32(pos, true); pos += 4;
        subResults.push(data.slice(pos, pos + len));
        pos += len;
      }
      result.set(bucketId, subResults);
    }
    return result;
  }

  /** Disconnect and free resources. */
  disconnect(): void {
    this.queryWs?.close();
    this.hintWs?.close();
    for (const [_, b] of this.indexBuckets) b.free();
    for (const [_, b] of this.chunkBuckets) b.free();
    this.indexBuckets.clear();
    this.chunkBuckets.clear();
    // Reset WASM so loadWasm() reloads the correct backend on reconnect.
    this.wasm = null;
  }
}

/** Factory function to create a HarmonyPIR client. */
export function createHarmonyPirClient(config: HarmonyPirClientConfig): HarmonyPirClient {
  return new HarmonyPirClient(config);
}
