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
  REQ_HARMONY_HINTS,
  REQ_HARMONY_BATCH_QUERY, RESP_HARMONY_BATCH_QUERY,
  RESP_HARMONY_HINTS, RESP_ERROR,
} from './constants.js';

import {
  deriveBuckets, deriveCuckooKey, cuckooHash, computeTag,
  deriveChunkBuckets, deriveChunkCuckooKey, cuckooHashInt,
  scriptHash as computeScriptHash, addressToScriptPubKey,
  hexToBytes, bytesToHex,
} from './hash.js';

import { cuckooPlace, planRounds } from './pbc.js';
import { readVarint, decodeUtxoData } from './codec.js';
import { findEntryInIndexResult, findChunkInResult } from './scan.js';
import { ManagedWebSocket } from './ws.js';
import { fetchServerInfoJson, type ServerInfoJson } from './server-info.js';
import { verifyMerkleDpf, clearTreeTopCache } from './merkle-verify-dpf.js';

import { HarmonyWorkerPool, BuildItem, BuildResult, ProcessItem } from './harmonypir_worker_pool.js';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface HarmonyPirClientConfig {
  hintServerUrl: string;
  queryServerUrl: string;
  onProgress?: (msg: string) => void;
  /** PRP backend: 0=Hoang (default), 1=FastPRP, 2=ALF */
  prpBackend?: number;
}

export interface HarmonyUtxoEntry {
  txid: string;
  vout: number;
  value: number;
}

export interface HarmonyQueryResult {
  address: string;
  scriptHash: string;
  utxos: HarmonyUtxoEntry[];
  whale: boolean;
  /** Merkle verification result (undefined if not verified yet) */
  merkleVerified?: boolean;
  /** Merkle root hash hex (from server, for display) */
  merkleRootHex?: string;
  /** tree_loc in the Merkle tree */
  treeLoc?: number;
  /** Raw chunk data (kept for Merkle verification) */
  rawChunkData?: Uint8Array;
  /** Script hash as bytes (for Merkle leaf hash) */
  scriptHashBytes?: Uint8Array;
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
  process_response_xor_only(response: Uint8Array): Uint8Array;
  finish_relocation(): void;
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

// ─── Query Inspector types ──────────────────────────────────────────────────

export interface RoundTimingData {
  phase: 'index' | 'chunk';
  roundIdx: number;
  hashIdx: number;
  realCount: number;
  totalCount: number;
  buildMs: number;
  netMs: number;
  procMs: number;
  relocMs: number;
}

export interface QueryInspectorData {
  address: string;
  scriptPubKeyHex: string;
  scriptHashHex: string;
  candidateIndexBuckets: number[];
  assignedIndexBucket: number;
  indexPlacementRound: number;
  // INDEX details
  indexBinIndex?: number;
  indexHashRound?: number;
  indexSegment?: number;
  indexPosition?: number;
  indexSegmentSize?: number;   // T (segment size parameter)
  tagHex?: string;
  startChunkId?: number;
  numChunks?: number;
  isWhale: boolean;
  // CHUNK details (per chunk)
  chunkDetails?: Array<{
    chunkId: number;
    bucketId: number;
    segment?: number;
    position?: number;
  }>;
  // Timing (all rounds, shared across queries in same batch)
  roundTimings: RoundTimingData[];
  totalMs: number;
}

// ─── Client class ───────────────────────────────────────────────────────────

export class HarmonyPirClient {
  private config: HarmonyPirClientConfig;
  private wasm: HarmonyWasmModule | null = null;
  private queryWs: ManagedWebSocket | null = null;
  private hintWs: WebSocket | null = null;
  private pool: HarmonyWorkerPool | null = null;

  // Per-bucket WASM state (used in single-threaded fallback only)
  private indexBuckets: Map<number, HarmonyBucketWasm> = new Map();
  private chunkBuckets: Map<number, HarmonyBucketWasm> = new Map();

  // Server params
  private serverInfo: ServerInfoJson | null = null;
  private indexBinsPerTable = 0;
  private chunkBinsPerTable = 0;
  private tagSeed = 0n;
  private prpKey: Uint8Array;

  // Lazy ManagedWebSocket to primary server (for Merkle DPF queries)
  private primaryWs: ManagedWebSocket | null = null;

  // Actual hint bytes received during download.
  private totalHintBytes = 0;

  // Cache of serialized hint state per PRP backend.
  private hintCache: Map<number, {
    prpKey: Uint8Array;
    buckets: Map<number, Uint8Array>;
    totalHintBytes: number;
  }> = new Map();

  // Whether hints have been loaded for the current PRP backend.
  hintsLoaded = false;

  // Inspector data from the last queryBatch call.
  lastInspectorData: Map<number, QueryInspectorData> | null = null;

  // Generation counter to abort stale hint fetches.
  private hintFetchGen = 0;

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
    if (this.pool && this.wasm) return; // already loaded
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

  /** Connect to the Query Server via WebSocket (delegates to shared ws.ts). */
  async connectQueryServer(): Promise<void> {
    this.queryWs = new ManagedWebSocket({
      url: this.config.queryServerUrl,
      label: 'harmony-query',
      onLog: (msg) => this.log(msg),
      onClose: () => {
        this.queryWs = null;
        this._externalCloseCallback?.();
      },
    });
    await this.queryWs.connect();
    this.log('Connected to Query Server');
  }

  /** Fetch server info (bins_per_table, tag_seed) from Query Server via JSON. */
  async fetchServerInfo(): Promise<void> {
    const info = await fetchServerInfoJson(this.queryWs!);
    this.serverInfo = info;
    this.indexBinsPerTable = info.index_bins_per_table;
    this.chunkBinsPerTable = info.chunk_bins_per_table;
    this.tagSeed = info.tag_seed;
    this.log(`Server info (JSON): indexBins=${this.indexBinsPerTable}, chunkBins=${this.chunkBinsPerTable}`);
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
    // Abort any in-progress hint fetch.
    const gen = ++this.hintFetchGen;
    if (this.hintWs) {
      this.hintWs.close();
      this.hintWs = null;
    }

    const t0 = performance.now();
    this.totalHintBytes = 0;
    this.log('Fetching hints from Hint Server...');

    const total = K + K_CHUNK; // 75 + 80 = 155 buckets total
    let globalReceived = 0;

    const onBucketDone = () => {
      if (gen !== this.hintFetchGen) return; // stale fetch
      globalReceived++;
      const pct = Math.round((globalReceived / total) * 100);
      this.log(`  Hints: ${globalReceived}/${total} (${pct}%)`);
    };

    // Connect to Hint Server.
    const hintWs = await this.connectHintServer();
    this.hintWs = hintWs;

    // Request index hints (75 buckets). Offset=0 for INDEX.
    const tIdx = performance.now();
    await this.requestHints(hintWs, 0, K, 0, this.indexBuckets, HARMONY_INDEX_W, onBucketDone);
    if (gen !== this.hintFetchGen) { hintWs.close(); return; }
    this.log(`  INDEX hints: ${K} buckets in ${((performance.now() - tIdx) / 1000).toFixed(1)}s`);

    // Request chunk hints (80 buckets). Offset=K for CHUNK.
    const tChk = performance.now();
    await this.requestHints(hintWs, 1, K_CHUNK, K, this.chunkBuckets, HARMONY_CHUNK_W, onBucketDone);
    if (gen !== this.hintFetchGen) { hintWs.close(); return; }
    this.log(`  CHUNK hints: ${K_CHUNK} buckets in ${((performance.now() - tChk) / 1000).toFixed(1)}s`);

    hintWs.close();
    this.hintWs = null;
    this.hintsLoaded = true;
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

  // Index/chunk bin scanning delegates to shared scan.ts

  /** Decode UTXOs from chunk data. Uses shared codec, converts to HarmonyUtxoEntry format. */
  private decodeUtxos(chunks: Uint8Array[]): HarmonyUtxoEntry[] {
    if (chunks.length === 0) return [];

    // Concatenate all chunk data.
    const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
    const data = new Uint8Array(totalLen);
    let pos = 0;
    for (const chunk of chunks) {
      data.set(chunk, pos);
      pos += chunk.length;
    }

    const { entries } = decodeUtxoData(data);
    return entries.map(e => ({
      txid: bytesToHex(new Uint8Array([...e.txid].reverse())),
      vout: e.vout,
      value: Number(e.amount),
    }));
  }

  /** Send a request to Query Server and wait for the response.
   *  Prepends 4-byte LE length prefix, strips it from response.
   *  Returns the payload (after length prefix). */
  private async sendQueryRequest(payload: Uint8Array): Promise<Uint8Array> {
    // Auto-reconnect if WebSocket is closed.
    if (!this.queryWs || !this.queryWs.isOpen()) {
      this.log('Query server disconnected, reconnecting...');
      await this.reconnectQueryServer();
    }
    if (!this.queryWs) throw new Error('Query Server not connected');

    // Length-prefix the payload.
    const msg = new Uint8Array(4 + payload.length);
    new DataView(msg.buffer).setUint32(0, payload.length, true);
    msg.set(payload, 4);

    const raw = await this.queryWs.sendRaw(msg);
    // Strip length prefix from response (callers expect payload only).
    return raw.slice(4);
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
          this.totalHintBytes += hintsData.length;

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
    return (this.totalHintBytes / (1024 * 1024)).toFixed(1);
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

    // ── Pre-flight: check hint budget ──
    const remaining = await this.getMinQueriesRemaining();
    if (remaining === 0) {
      this.log('Hints exhausted — re-downloading...');
      await this.refreshHints();
    } else if (remaining < 4) {
      this.log(`Warning: only ${remaining} queries remaining per bucket`);
    }

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

    // ── Initialize inspector data ──
    const inspectorMap = new Map<number, QueryInspectorData>();
    const roundTimings: RoundTimingData[] = [];

    // ══════════════════════════════════════════════════════════════════
    // PHASE 1: INDEX — batch queries
    // ══════════════════════════════════════════════════════════════════
    progress?.('Level 1', 'Planning index rounds...');

    const tL1Start = performance.now();
    const indexCandBuckets = scriptHashes.map(sh => deriveBuckets(sh));
    const indexRounds = planRounds(indexCandBuckets, K, NUM_HASHES, (msg) => this.log(msg));
    this.log(`Level 1: ${N} queries → ${indexRounds.length} index placement round(s) × ${INDEX_CUCKOO_NUM_HASHES} hash-fn rounds`);

    // Pre-populate inspector data for each query.
    for (let qi = 0; qi < N; qi++) {
      inspectorMap.set(qi, {
        address: addresses[qi],
        scriptPubKeyHex: (/^[0-9a-fA-F]+$/.test(addresses[qi]) && addresses[qi].length % 2 === 0)
          ? addresses[qi].toLowerCase() : (addressToScriptPubKey(addresses[qi]) ?? ''),
        scriptHashHex: shHexes[qi],
        candidateIndexBuckets: indexCandBuckets[qi],
        assignedIndexBucket: -1,
        indexPlacementRound: -1,
        isWhale: false,
        roundTimings,
        totalMs: 0,
      });
    }

    const indexResults = new Map<number, { startChunkId: number; numChunks: number; treeLoc: number }>();
    const whaleQueries = new Set<number>();

    for (let ir = 0; ir < indexRounds.length; ir++) {
      const round = indexRounds[ir];
      const bucketToQuery = new Map<number, number>();
      for (const [qi, bucketId] of round) {
        bucketToQuery.set(bucketId, qi);
        // Inspector: record which bucket each query is assigned to.
        const qd = inspectorMap.get(qi);
        if (qd && qd.assignedIndexBucket < 0) {
          qd.assignedIndexBucket = bucketId;
          qd.indexPlacementRound = ir;
        }
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
            // Inspector: record which binIndex this query used.
            const qd = inspectorMap.get(qi);
            if (qd && qd.indexBinIndex === undefined) {
              qd.indexBinIndex = binIndex;
            }
          } else {
            buildItems.push({ bucketId: b }); // dummy (binIndex undefined)
          }
        }

        // Build requests (parallel via workers or single-threaded fallback).
        const tBuild = performance.now();
        const reqBytesMap = await this.doBuildBatch(buildItems, 'index');
        const buildMs = performance.now() - tBuild;

        // Inspector: capture segment/position from build results.
        for (const [bucketId, qi] of realBuckets) {
          const br = reqBytesMap.get(bucketId);
          const qd = inspectorMap.get(qi);
          if (br && qd && qd.indexSegment === undefined) {
            qd.indexSegment = br.segment;
            qd.indexPosition = br.position;
            qd.indexSegmentSize = br.bytes.length / 4; // T_eff (each index is 4 bytes u32 LE)
          }
        }

        // Encode and send batch.
        const batchItems = buildItems.map(item => ({
          bucketId: item.bucketId,
          subQueryBytes: [(reqBytesMap.get(item.bucketId)?.bytes) ?? new Uint8Array(0)],
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
          const expectedTag = computeTag(this.tagSeed, scriptHashes[qi]);
          const found = findEntryInIndexResult(answer, expectedTag, HARMONY_INDEX_W / INDEX_ENTRY_SIZE, INDEX_ENTRY_SIZE);
          if (found) {
            if (found.numChunks === 0) {
              whaleQueries.add(qi);
              const qd = inspectorMap.get(qi);
              if (qd) {
                qd.isWhale = true;
                qd.indexHashRound = h;
                qd.startChunkId = found.startChunkId;
                qd.numChunks = 0;
                qd.tagHex = computeTag(this.tagSeed, scriptHashes[qi]).toString(16).padStart(16, '0');
              }
            } else {
              indexResults.set(qi, found);
              // Inspector: record tag match details.
              const qd = inspectorMap.get(qi);
              if (qd) {
                qd.indexHashRound = h;
                qd.startChunkId = found.startChunkId;
                qd.numChunks = found.numChunks;
                // Compute tag hex for display.
                qd.tagHex = computeTag(this.tagSeed, scriptHashes[qi]).toString(16).padStart(16, '0');
              }
            }
            foundThisPlacement.add(qi);
          }
        }

        // Deferred relocation (expensive PRP work, after results are available).
        const tReloc = performance.now();
        await this.doFinishRelocation(processItems.map(i => i.bucketId), 'index');
        const relocMs = performance.now() - tReloc;

        // Inspector: record round timing.
        roundTimings.push({
          phase: 'index', roundIdx: ir, hashIdx: h,
          realCount: realBuckets.size, totalCount: K,
          buildMs, netMs, procMs, relocMs,
        });
        this.log(`  INDEX r${ir}h${h}: build=${buildMs.toFixed(0)}ms net=${netMs.toFixed(0)}ms proc=${procMs.toFixed(0)}ms reloc=${relocMs.toFixed(0)}ms (${realBuckets.size} real / ${K} total)`);
      }
    }

    const l1Ms = performance.now() - tL1Start;
    this.log(`Level 1 done: ${indexResults.size} found, ${whaleQueries.size} whales (${(l1Ms / 1000).toFixed(1)}s)`);

    // ══════════════════════════════════════════════════════════════════
    // PHASE 2: CHUNK — global batch across all queries
    // ══════════════════════════════════════════════════════════════════
    progress?.('Level 2', 'Collecting chunk IDs...');

    const queryChunkInfo = new Map<number, { startChunk: number; numChunks: number; treeLoc: number }>();
    const allChunkIdsSet = new Set<number>();

    for (const [qi, info] of indexResults) {
      for (let ci = 0; ci < info.numChunks; ci++) {
        allChunkIdsSet.add(info.startChunkId + ci);
      }
      queryChunkInfo.set(qi, { startChunk: info.startChunkId, numChunks: info.numChunks, treeLoc: info.treeLoc });
    }

    const allChunkIds = Array.from(allChunkIdsSet).sort((a, b) => a - b);
    this.log(`Level 2: ${allChunkIds.length} unique chunks to fetch`);
    const tL2Start = performance.now();

    const recoveredChunks = new Map<number, Uint8Array>();

    if (allChunkIds.length > 0) {
      const chunkCandBuckets = allChunkIds.map(cid => deriveChunkBuckets(cid));
      const chunkRounds = planRounds(chunkCandBuckets, K_CHUNK, NUM_HASHES, (msg) => this.log(msg));
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
            subQueryBytes: [(reqBytesMap.get(item.bucketId)?.bytes) ?? new Uint8Array(0)],
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
            const found = findChunkInResult(answer, chunkId, answer.length / CHUNK_SLOT_SIZE, CHUNK_SLOT_SIZE);
            if (found) {
              recoveredChunks.set(chunkId, found);
              foundThisPlacement.add(chunkId);
              // Inspector: record chunk recovery details.
              const br = reqBytesMap.get(K + localB);
              for (const [qi, info] of queryChunkInfo) {
                const qd = inspectorMap.get(qi);
                if (!qd) continue;
                if (chunkId >= info.startChunk && chunkId < info.startChunk + info.numChunks) {
                  if (!qd.chunkDetails) qd.chunkDetails = [];
                  qd.chunkDetails.push({
                    chunkId,
                    bucketId: localB,
                    segment: br?.segment,
                    position: br?.position,
                  });
                }
              }
            }
          }

          // Deferred relocation (expensive PRP work, after results are available).
          const tReloc = performance.now();
          await this.doFinishRelocation(processItems.map(i => i.bucketId), 'chunk');
          const relocMs = performance.now() - tReloc;

          // Inspector: record chunk round timing.
          roundTimings.push({
            phase: 'chunk', roundIdx: ri, hashIdx: h,
            realCount: realBuckets.size, totalCount: K_CHUNK,
            buildMs, netMs, procMs, relocMs,
          });
          this.log(`  CHUNK r${ri}h${h}: build=${buildMs.toFixed(0)}ms net=${netMs.toFixed(0)}ms proc=${procMs.toFixed(0)}ms reloc=${relocMs.toFixed(0)}ms (${realBuckets.size} real / ${K_CHUNK} total)`);
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
      // Keep raw assembled data for Merkle verification
      const totalLen = chunks.reduce((s, c) => s + c.length, 0);
      const rawChunkData = new Uint8Array(totalLen);
      let pos = 0;
      for (const c of chunks) { rawChunkData.set(c, pos); pos += c.length; }

      const utxos = this.decodeUtxos(chunks);
      results.set(qi, {
        address: addresses[qi],
        scriptHash: shHexes[qi],
        utxos,
        whale: false,
        merkleRootHex: this.serverInfo?.merkle?.root,
        treeLoc: info.treeLoc,
        rawChunkData,
        scriptHashBytes: scriptHashes[qi],
      });
    }

    const totalMs = performance.now() - tBatchStart;
    this.log(`Batch complete: ${N} queries in ${(totalMs / 1000).toFixed(1)}s`);

    // Store inspector data for the UI.
    for (const [qi, qd] of inspectorMap) { qd.totalMs = totalMs; }
    this.lastInspectorData = inspectorMap;

    return results;
  }

  // ─── Cuckoo placement and round planning (uses shared pbc.ts) ──────────────

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
  ): Promise<Map<number, BuildResult>> {
    if (this.pool) {
      return this.pool.buildBatchRequests(items);
    }

    // Single-threaded fallback.
    const bucketMap = level === 'index' ? this.indexBuckets : this.chunkBuckets;
    const result = new Map<number, BuildResult>();
    for (const item of items) {
      const localId = level === 'index' ? item.bucketId : item.bucketId - K;
      const bucket = bucketMap.get(localId);
      if (!bucket) continue;
      if (item.binIndex !== undefined) {
        const req = bucket.build_request(item.binIndex);
        const br: BuildResult = {
          bytes: new Uint8Array(req.request),
          segment: req.segment,
          position: req.position,
        };
        req.free();
        result.set(item.bucketId, br);
      } else {
        result.set(item.bucketId, { bytes: new Uint8Array(bucket.build_synthetic_dummy()) });
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
      // Workers use process_response_xor_only (fast, no relocation).
      return this.pool.processBatchResponses(items);
    }

    // Single-threaded fallback: also use xor-only path for consistent timing.
    const bucketMap = level === 'index' ? this.indexBuckets : this.chunkBuckets;
    const result = new Map<number, Uint8Array>();
    for (const item of items) {
      const localId = level === 'index' ? item.bucketId : item.bucketId - K;
      const bucket = bucketMap.get(localId);
      if (!bucket) continue;
      const answer = bucket.process_response_xor_only(item.response);
      result.set(item.bucketId, answer);
    }
    return result;
  }

  /** Complete deferred relocation for buckets that had xor-only processing. */
  private async doFinishRelocation(
    bucketIds: number[],
    level: 'index' | 'chunk',
  ): Promise<void> {
    if (this.pool) {
      return this.pool.finishRelocation(bucketIds);
    }

    // Single-threaded fallback.
    const bucketMap = level === 'index' ? this.indexBuckets : this.chunkBuckets;
    for (const id of bucketIds) {
      const localId = level === 'index' ? id : id - K;
      const bucket = bucketMap.get(localId);
      if (bucket) bucket.finish_relocation();
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Connection management
  // ═══════════════════════════════════════════════════════════════════════════

  /** Close query server WebSocket only, preserving workers and hints. */
  disconnectQueryServer(): void {
    this.queryWs?.disconnect();
    this.queryWs = null;
  }

  /** Check if the query server WebSocket is open. */
  isQueryServerConnected(): boolean {
    return this.queryWs?.isOpen() ?? false;
  }

  /** Set a callback for when the query server WebSocket closes.
   *  With ManagedWebSocket the onClose is set at construction time,
   *  so this registers an additional external callback. */
  onQueryServerClose(callback: () => void): void {
    // Store a reference; the ManagedWebSocket onClose already nulls queryWs.
    // We wrap by re-creating with the callback if needed.
    this._externalCloseCallback = callback;
  }
  private _externalCloseCallback: (() => void) | null = null;

  /** Reconnect to the query server without re-downloading hints. */
  async reconnectQueryServer(): Promise<void> {
    this.disconnectQueryServer();
    await this.connectQueryServer();
    await this.fetchServerInfo();
    this.log('Reconnected to Query Server (hints preserved)');
  }

  /** Disconnect and free all resources (full teardown). */
  disconnect(): void {
    this.hintFetchGen++; // abort any in-progress hint fetch
    this.queryWs?.disconnect();
    this.hintWs?.close();
    this.hintWs = null;
    this.primaryWs?.disconnect();
    this.primaryWs = null;
    if (this.pool) {
      this.pool.terminate();
      this.pool = null;
    }
    for (const [_, b] of this.indexBuckets) b.free();
    for (const [_, b] of this.chunkBuckets) b.free();
    this.indexBuckets.clear();
    this.chunkBuckets.clear();
    this.wasm = null;
    this.hintsLoaded = false;
  }

  /** Terminate worker pool only (for PRP switch), preserving hint cache. */
  terminatePool(): void {
    this.hintFetchGen++; // abort any in-progress hint fetch
    if (this.hintWs) { this.hintWs.close(); this.hintWs = null; }
    if (this.pool) {
      this.pool.terminate();
      this.pool = null;
    }
    for (const [_, b] of this.indexBuckets) b.free();
    for (const [_, b] of this.chunkBuckets) b.free();
    this.indexBuckets.clear();
    this.chunkBuckets.clear();
    this.wasm = null;
    this.hintsLoaded = false;
  }

  /** Update the PRP backend. Call before loadWasm() on PRP switch. */
  updatePrpBackend(backend: number): void {
    (this.config as any).prpBackend = backend;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Merkle verification (uses DPF sibling protocol via both servers)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Check if server supports DPF Merkle verification */
  hasMerkle(): boolean {
    return !!(this.serverInfo?.merkle && this.serverInfo.merkle.sibling_levels > 0);
  }

  /** Get the Merkle root hash hex (for display) */
  getMerkleRootHex(): string | undefined {
    return this.serverInfo?.merkle?.root;
  }

  /**
   * Verify a HarmonyPIR query result against the DPF Merkle tree.
   *
   * Opens a temporary ManagedWebSocket to the primary server (hint server URL)
   * since the hint server connection is not persistent. Uses both server connections
   * for the 2-server DPF sibling queries.
   */
  async verifyMerkle(
    result: HarmonyQueryResult,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<boolean> {
    const merkle = this.serverInfo?.merkle;
    if (!merkle || merkle.sibling_levels === 0) throw new Error('Server does not support Merkle');
    if (!result.scriptHashBytes || !result.rawChunkData || result.treeLoc === undefined) {
      throw new Error('Result missing data for Merkle verification');
    }
    if (result.whale) throw new Error('Cannot verify whale addresses');
    if (!this.queryWs) throw new Error('Not connected to query server');

    // queryWs → secondary (server1), primaryWs → primary (server0)
    if (!this.primaryWs) {
      this.primaryWs = new ManagedWebSocket({
        url: this.config.hintServerUrl,
        label: 'harmony-merkle',
        onLog: (msg) => this.log(msg),
        onClose: () => { this.primaryWs = null; },
      });
      await this.primaryWs.connect();
    }

    const verified = await verifyMerkleDpf(
      this.primaryWs, this.queryWs, merkle,
      result.scriptHashBytes, result.rawChunkData, result.treeLoc,
      onProgress,
      (msg) => this.log(msg),
    );
    result.merkleVerified = verified;
    return verified;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRP hint caching
  // ═══════════════════════════════════════════════════════════════════════════

  /** Save current hint state to cache for the current PRP backend. */
  async saveHintsToCache(): Promise<void> {
    if (!this.pool || !this.hintsLoaded) return;
    const backend = this.config.prpBackend ?? 0;
    const serialized = await this.pool.serializeAll();
    this.hintCache.set(backend, {
      prpKey: new Uint8Array(this.prpKey),
      buckets: serialized,
      totalHintBytes: this.totalHintBytes,
    });
    this.log(`Cached hints for PRP backend ${backend} (${serialized.size} buckets)`);
  }

  /** Try to restore hints from cache for a given PRP backend. Returns true on cache hit. */
  async restoreHintsFromCache(backend: number): Promise<boolean> {
    const cached = this.hintCache.get(backend);
    if (!cached || !this.pool) return false;
    this.prpKey = new Uint8Array(cached.prpKey);
    this.totalHintBytes = cached.totalHintBytes;
    await this.pool.deserializeAll(cached.buckets, this.prpKey);
    this.hintsLoaded = true;
    this.log(`Restored ${cached.buckets.size} buckets from cache`);
    return true;
  }

  /** Check if cached hints exist for a given PRP backend. */
  hasCachedHints(backend: number): boolean {
    return this.hintCache.has(backend);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Hint exhaustion detection
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get the minimum queries remaining across all buckets. */
  async getMinQueriesRemaining(): Promise<number> {
    if (this.pool) {
      return this.pool.getMinQueriesRemaining();
    }
    // Single-threaded fallback.
    let min = Infinity;
    for (const [_, b] of this.indexBuckets) min = Math.min(min, b.queries_remaining());
    for (const [_, b] of this.chunkBuckets) min = Math.min(min, b.queries_remaining());
    return min;
  }

  /** Re-initialize buckets and re-download hints (resets query budget). */
  async refreshHints(): Promise<void> {
    this.log('Refreshing hints (re-running offline phase)...');
    await this.initBuckets();
    await this.fetchHints();
  }
}

/** Factory function to create a HarmonyPIR client. */
export function createHarmonyPirClient(config: HarmonyPirClientConfig): HarmonyPirClient {
  return new HarmonyPirClient(config);
}
