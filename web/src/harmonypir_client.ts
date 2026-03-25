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

import { HarmonyWorkerPool, BuildItem, ProcessItem } from './harmonypir_worker_pool.js';

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
    new_with_backend(n: number, w: number, t: number, prpKey: Uint8Array, bucketId: number, prpBackend: number): HarmonyBucketWasm;
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
  private pool: HarmonyWorkerPool | null = null;

  // Per-bucket WASM state (used in single-threaded fallback only)
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

  /** Resolve the WASM directory for the selected PRP backend. */
  private get wasmDir(): string {
    const backend = this.config.prpBackend ?? 0;
    const dirs: Record<number, string> = {
      0: '/wasm/harmonypir',
      1: '/wasm/harmonypir-fastprp',
      2: '/wasm/harmonypir-alf',
    };
    return dirs[backend] ?? dirs[0];
  }

  /** Load the HarmonyPIR WASM module + worker pool. */
  async loadWasm(): Promise<void> {
    if (this.pool) return; // already loaded
    const backend = this.config.prpBackend ?? 0;
    const backendName = ['Hoang', 'FastPRP', 'ALF'][backend] ?? 'Hoang';
    // Resolve to fully-qualified URLs so blob-URL workers can fetch them.
    const jsUrl = new URL(`${this.wasmDir}/harmonypir_wasm.js`, document.baseURI).href;
    const binaryUrl = new URL(`${this.wasmDir}/harmonypir_wasm_bg.wasm`, document.baseURI).href;

    // Also load WASM on main thread (for planning helpers like computeTag).
    const oldScript = document.getElementById('harmonypir-wasm-script');
    if (oldScript) oldScript.remove();

    const resp = await fetch(jsUrl);
    if (!resp.ok) throw new Error(`Failed to fetch WASM JS from ${jsUrl}: ${resp.status}`);
    let jsText = await resp.text();
    if (jsText.startsWith('let wasm_bindgen')) {
      jsText = 'var wasm_bindgen' + jsText.slice('let wasm_bindgen'.length);
    }
    const blob = new Blob([jsText], { type: 'application/javascript' });
    const blobUrl = URL.createObjectURL(blob);

    await new Promise<void>((resolve, reject) => {
      const script = document.createElement('script');
      script.id = 'harmonypir-wasm-script';
      script.src = blobUrl;
      script.onload = () => { URL.revokeObjectURL(blobUrl); resolve(); };
      script.onerror = () => { URL.revokeObjectURL(blobUrl); reject(new Error(`Failed to load WASM from ${jsUrl}`)); };
      document.head.appendChild(script);
    });

    const wb = (globalThis as any).wasm_bindgen;
    if (!wb) throw new Error(`HarmonyPIR WASM did not initialize from ${jsUrl}`);
    await wb(binaryUrl);
    this.wasm = wb as any;

    // Initialize worker pool.
    const useWorkers = typeof Worker !== 'undefined';
    if (useWorkers) {
      this.pool = new HarmonyWorkerPool();
      await this.pool.init(jsUrl, binaryUrl);
      this.log(`WASM loaded: ${backendName} + ${this.pool.size} workers`);
    } else {
      this.log(`WASM loaded: ${backendName} (no Worker support, single-threaded)`);
    }
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

  /** Initialize WASM bucket instances on workers (or main thread fallback). */
  async initBuckets(): Promise<void> {
    if (!this.wasm) throw new Error('WASM not loaded');
    const backend = this.config.prpBackend ?? 0;
    const backendName = ['Hoang', 'FastPRP', 'ALF'][backend] ?? 'Hoang';

    if (this.pool) {
      // Create buckets on workers.
      const promises: Promise<void>[] = [];
      for (let b = 0; b < K; b++) {
        promises.push(this.pool.createBucket(b, this.indexBinsPerTable, HARMONY_INDEX_W, 0, this.prpKey, backend));
      }
      for (let b = 0; b < K_CHUNK; b++) {
        // Chunk buckets use IDs K..K+K_CHUNK-1 for PRP derivation.
        promises.push(this.pool.createBucket(K + b, this.chunkBinsPerTable, HARMONY_CHUNK_W, 0, this.prpKey, backend));
      }
      await Promise.all(promises);
    } else {
      // Single-threaded fallback.
      for (let b = 0; b < K; b++) {
        const bucket = this.wasm.HarmonyBucket.new_with_backend(
          this.indexBinsPerTable, HARMONY_INDEX_W, 0, this.prpKey, b, backend
        );
        this.indexBuckets.set(b, bucket);
      }
      for (let b = 0; b < K_CHUNK; b++) {
        const bucket = this.wasm.HarmonyBucket.new_with_backend(
          this.chunkBinsPerTable, HARMONY_CHUNK_W, 0, this.prpKey, K + b, backend
        );
        this.chunkBuckets.set(b, bucket);
      }
    }

    this.log(`Initialized ${K} index + ${K_CHUNK} chunk buckets (PRP: ${backendName}${this.pool ? `, ${this.pool.size} workers` : ''})`);
  }

  /**
   * Fetch hints from the Hint Server for all buckets.
   * This is the offline phase — typically done once per session.
   */
  async fetchHints(): Promise<void> {
    const t0 = performance.now();
    this.log('Fetching hints from Hint Server...');

    const total = K + K_CHUNK; // 75 + 80 = 155 buckets total
    let globalReceived = 0;

    const onBucketDone = () => {
      globalReceived++;
      const pct = Math.round((globalReceived / total) * 100);
      this.log(`  Hints: ${globalReceived}/${total} (${pct}%)`);
    };

    // Connect to Hint Server.
    const hintWs = await this.connectHintServer();

    // Request index hints (75 buckets). Offset=0 for INDEX.
    const tIdx = performance.now();
    await this.requestHints(hintWs, 0, K, 0, this.indexBuckets, HARMONY_INDEX_W, onBucketDone);
    this.log(`  INDEX hints: ${K} buckets in ${((performance.now() - tIdx) / 1000).toFixed(1)}s`);

    // Request chunk hints (80 buckets). Offset=K for CHUNK.
    const tChk = performance.now();
    await this.requestHints(hintWs, 1, K_CHUNK, K, this.chunkBuckets, HARMONY_CHUNK_W, onBucketDone);
    this.log(`  CHUNK hints: ${K_CHUNK} buckets in ${((performance.now() - tChk) / 1000).toFixed(1)}s`);

    hintWs.close();
    const totalSec = ((performance.now() - t0) / 1000).toFixed(1);
    this.log(`Hints downloaded successfully (${totalSec}s, ~${this.estimateHintSize()} MB)`);
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

  /** Decode UTXOs from chunk data. Varint-encoded format matching DPF-PIR. */
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

    // Format: [varint numEntries][per entry: 32B txid, varint vout, varint amount]
    const { value: numEntries, bytesRead: countBytes } = this.readVarint(data, 0);
    pos = countBytes;

    const utxos: UtxoEntry[] = [];
    for (let i = 0; i < Number(numEntries); i++) {
      if (pos + 32 > data.length) break;

      const txidBytes = data.slice(pos, pos + 32);
      pos += 32;

      const { value: vout, bytesRead: vr } = this.readVarint(data, pos);
      pos += vr;

      const { value: amount, bytesRead: ar } = this.readVarint(data, pos);
      pos += ar;

      const txid = bytesToHex(new Uint8Array([...txidBytes].reverse()));
      utxos.push({ txid, vout: Number(vout), value: Number(amount) });
    }

    return utxos;
  }

  /** Read a LEB128 varint from data at offset. */
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

  /** Request hints from the Hint Server for a set of buckets at one level.
   *  bucketIdOffset: 0 for INDEX, K for CHUNK (maps local 0-based ID to global bucket ID for pool). */
  private async requestHints(
    ws: WebSocket,
    level: number,
    numBuckets: number,
    bucketIdOffset: number,
    buckets: Map<number, HarmonyBucketWasm>,
    w: number,
    onBucketDone?: () => void,
  ): Promise<void> {
    // Build hint request.
    const bucketIds = Array.from({ length: numBuckets }, (_, i) => i);
    // Wire: [1B variant][16B prp_key][1B prp_backend][1B level][1B num_buckets][per bucket: 1B id]
    const backend = this.config.prpBackend ?? 0;
    const msg = new Uint8Array(1 + 16 + 1 + 1 + 1 + numBuckets);
    msg[0] = REQ_HARMONY_HINTS;
    msg.set(this.prpKey, 1);
    msg[17] = backend;
    msg[18] = level;
    msg[19] = numBuckets;
    for (let i = 0; i < numBuckets; i++) {
      msg[20 + i] = bucketIds[i];
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
          const hintsData = payload.slice(14);

          if (this.pool) {
            // Forward hints to worker (global bucket ID = offset + local).
            this.pool.loadHints(bucketIdOffset + bucketId, hintsData);
          } else {
            // Single-threaded fallback: load directly.
            const bucket = buckets.get(bucketId);
            if (bucket) bucket.load_hints(hintsData);
          }

          received++;
          onBucketDone?.();
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
    const tBatchStart = performance.now();
    const N = addresses.length;
    const results = new Map<number, HarmonyQueryResult>();
    this.log(`Starting batch query for ${N} addresses...`);

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

    const tL1Start = performance.now();
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

        // Determine which buckets get real vs dummy queries.
        const realBuckets = new Map<number, number>(); // bucketId → qi
        const buildItems: BuildItem[] = [];

        for (let b = 0; b < K; b++) {
          const qi = bucketToQuery.get(b);
          if (qi !== undefined && !foundThisPlacement.has(qi) && !indexResults.has(qi) && !whaleQueries.has(qi)) {
            const ck = deriveCuckooKey(b, h);
            const binIndex = cuckooHash(scriptHashes[qi], ck, this.indexBinsPerTable);
            buildItems.push({ bucketId: b, binIndex });
            realBuckets.set(b, qi);
          } else {
            buildItems.push({ bucketId: b }); // dummy (binIndex undefined)
          }
        }

        // Build requests (parallel via workers or single-threaded fallback).
        const tBuild = performance.now();
        const reqBytesMap = await this.doBuildBatch(buildItems, 'index');
        const buildMs = performance.now() - tBuild;

        // Encode and send batch.
        const batchItems = buildItems.map(item => ({
          bucketId: item.bucketId,
          subQueryBytes: [reqBytesMap.get(item.bucketId) ?? new Uint8Array(0)],
        }));
        const roundId = ir * INDEX_CUCKOO_NUM_HASHES + h;
        const reqMsg = this.encodeHarmonyBatchRequest(0, roundId, 1, batchItems);
        const tNet = performance.now();
        const respData = await this.sendQueryRequest(reqMsg);
        const netMs = performance.now() - tNet;
        const batchResp = this.decodeHarmonyBatchResponse(respData);

        // Process real responses (parallel via workers or single-threaded fallback).
        const processItems: ProcessItem[] = [];
        for (const [bucketId] of realBuckets) {
          const respItem = batchResp.get(bucketId);
          if (respItem && respItem.length > 0) {
            processItems.push({ bucketId, response: respItem[0] });
          }
        }
        const tProc = performance.now();
        const answers = await this.doProcessBatch(processItems, 'index');
        const procMs = performance.now() - tProc;

        // Match answers against expected tags.
        for (const [bucketId, qi] of realBuckets) {
          const answer = answers.get(bucketId);
          if (!answer) continue;
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
        this.log(`  INDEX r${ir}h${h}: build=${buildMs.toFixed(0)}ms net=${netMs.toFixed(0)}ms proc=${procMs.toFixed(0)}ms (${realBuckets.size} real / ${K} total)`);
      }
    }

    const l1Ms = performance.now() - tL1Start;
    this.log(`Level 1 done: ${indexResults.size} found, ${whaleQueries.size} whales (${(l1Ms / 1000).toFixed(1)}s)`);

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
    const tL2Start = performance.now();

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

          const realBuckets = new Map<number, { chunkListIdx: number; chunkId: number }>();
          const buildItems: BuildItem[] = [];

          for (let b = 0; b < K_CHUNK; b++) {
            const chunkListIdx = bucketToChunk.get(b);
            if (chunkListIdx !== undefined) {
              const chunkId = allChunkIds[chunkListIdx];
              if (!foundThisPlacement.has(chunkId) && !recoveredChunks.has(chunkId)) {
                const ck = deriveChunkCuckooKey(b, h);
                const binIndex = cuckooHashInt(chunkId, ck, this.chunkBinsPerTable);
                buildItems.push({ bucketId: K + b, binIndex }); // global ID = K + b
                realBuckets.set(b, { chunkListIdx, chunkId });
              } else {
                buildItems.push({ bucketId: K + b }); // dummy
              }
            } else {
              buildItems.push({ bucketId: K + b }); // dummy
            }
          }

          const tBuild = performance.now();
          const reqBytesMap = await this.doBuildBatch(buildItems, 'chunk');
          const buildMs = performance.now() - tBuild;

          const batchItems = buildItems.map(item => ({
            bucketId: item.bucketId - K, // local bucket ID for wire protocol
            subQueryBytes: [reqBytesMap.get(item.bucketId) ?? new Uint8Array(0)],
          }));
          const roundId = ri * CHUNK_CUCKOO_NUM_HASHES + h;
          const reqMsg = this.encodeHarmonyBatchRequest(1, roundId, 1, batchItems);
          const tNet = performance.now();
          const respData = await this.sendQueryRequest(reqMsg);
          const netMs = performance.now() - tNet;
          const batchResp = this.decodeHarmonyBatchResponse(respData);

          const processItems: ProcessItem[] = [];
          for (const [localB] of realBuckets) {
            const respItem = batchResp.get(localB);
            if (respItem && respItem.length > 0) {
              processItems.push({ bucketId: K + localB, response: respItem[0] }); // global ID
            }
          }
          const tProc = performance.now();
          const answers = await this.doProcessBatch(processItems, 'chunk');
          const procMs = performance.now() - tProc;

          for (const [localB, { chunkId }] of realBuckets) {
            const answer = answers.get(K + localB); // global ID
            if (!answer) continue;
            const found = this.findChunkInBin(answer, chunkId);
            if (found) {
              recoveredChunks.set(chunkId, found);
              foundThisPlacement.add(chunkId);
            }
          }
          this.log(`  CHUNK r${ri}h${h}: build=${buildMs.toFixed(0)}ms net=${netMs.toFixed(0)}ms proc=${procMs.toFixed(0)}ms (${realBuckets.size} real / ${K_CHUNK} total)`);
        }
      }
    }

    const l2Ms = performance.now() - tL2Start;
    this.log(`Level 2 done: ${recoveredChunks.size}/${allChunkIds.length} chunks recovered (${(l2Ms / 1000).toFixed(1)}s)`);

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

    const totalMs = performance.now() - tBatchStart;
    this.log(`Batch complete: ${N} queries in ${(totalMs / 1000).toFixed(1)}s`);

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

  // ─── Worker/fallback dispatch helpers ────────────────────────────────────

  /**
   * Build requests for a batch of buckets.
   * Uses worker pool if available, otherwise direct WASM calls.
   * @param level 'index' or 'chunk' — determines which bucket map to use for fallback.
   */
  private async doBuildBatch(
    items: BuildItem[],
    level: 'index' | 'chunk',
  ): Promise<Map<number, Uint8Array>> {
    if (this.pool) {
      return this.pool.buildBatchRequests(items);
    }

    // Single-threaded fallback.
    const bucketMap = level === 'index' ? this.indexBuckets : this.chunkBuckets;
    const result = new Map<number, Uint8Array>();
    for (const item of items) {
      const localId = level === 'index' ? item.bucketId : item.bucketId - K;
      const bucket = bucketMap.get(localId);
      if (!bucket) continue;
      if (item.binIndex !== undefined) {
        const req = bucket.build_request(item.binIndex);
        result.set(item.bucketId, new Uint8Array(req.request));
        req.free();
      } else {
        result.set(item.bucketId, new Uint8Array(bucket.build_synthetic_dummy()));
      }
    }
    return result;
  }

  /**
   * Process responses for a batch of buckets.
   * Uses worker pool if available, otherwise direct WASM calls.
   */
  private async doProcessBatch(
    items: ProcessItem[],
    level: 'index' | 'chunk',
  ): Promise<Map<number, Uint8Array>> {
    if (this.pool) {
      return this.pool.processBatchResponses(items);
    }

    // Single-threaded fallback.
    const bucketMap = level === 'index' ? this.indexBuckets : this.chunkBuckets;
    const result = new Map<number, Uint8Array>();
    for (const item of items) {
      const localId = level === 'index' ? item.bucketId : item.bucketId - K;
      const bucket = bucketMap.get(localId);
      if (!bucket) continue;
      const answer = bucket.process_response(item.response);
      result.set(item.bucketId, answer);
    }
    return result;
  }

  /** Disconnect and free resources. */
  disconnect(): void {
    this.queryWs?.close();
    this.hintWs?.close();
    if (this.pool) {
      this.pool.terminate();
      this.pool = null;
    }
    for (const [_, b] of this.indexBuckets) b.free();
    for (const [_, b] of this.chunkBuckets) b.free();
    this.indexBuckets.clear();
    this.chunkBuckets.clear();
    this.wasm = null;
  }
}

/** Factory function to create a HarmonyPIR client. */
export function createHarmonyPirClient(config: HarmonyPirClientConfig): HarmonyPirClient {
  return new HarmonyPirClient(config);
}
