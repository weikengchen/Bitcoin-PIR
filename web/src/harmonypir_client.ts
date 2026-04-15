/**
 * HarmonyPIR Web Client
 *
 * Two-server stateful PIR client for Bitcoin UTXO lookups.
 * - Hint Server: computes and sends hint parities (offline phase)
 * - Query Server: answers online queries (simple indexed lookups)
 *
 * Each PBC group is managed by a WASM HarmonyGroup instance that
 * handles the PRP-based relocation data structure and XOR operations.
 */

import {
  K, K_CHUNK, NUM_HASHES,
  INDEX_SLOTS_PER_BIN, INDEX_CUCKOO_NUM_HASHES,
  CHUNK_SLOTS_PER_BIN, CHUNK_CUCKOO_NUM_HASHES,
  INDEX_SLOT_SIZE, CHUNK_SLOT_SIZE, CHUNK_SIZE, TAG_SIZE,
  HARMONY_INDEX_W, HARMONY_CHUNK_W, HARMONY_EMPTY,
  REQ_HARMONY_HINTS,
  REQ_HARMONY_BATCH_QUERY, RESP_HARMONY_BATCH_QUERY,
  RESP_HARMONY_HINTS, RESP_ERROR,
  BUCKET_MERKLE_ARITY, BUCKET_MERKLE_SIB_ROW_SIZE,
  REQ_BUCKET_MERKLE_TREE_TOPS, RESP_BUCKET_MERKLE_TREE_TOPS,
} from './constants.js';

import {
  deriveGroups, deriveCuckooKey, cuckooHash, computeTag,
  deriveChunkGroups, deriveChunkCuckooKey, cuckooHashInt,
  scriptHash as computeScriptHash, addressToScriptPubKey,
  hexToBytes, bytesToHex,
} from './hash.js';

import { cuckooPlace, planRounds } from './pbc.js';
import { readVarint, decodeUtxoData } from './codec.js';
import { findEntryInIndexResult, findChunkInResult } from './scan.js';
import { ManagedWebSocket } from './ws.js';
import {
  fetchServerInfoJson, fetchDatabaseCatalog,
  type ServerInfoJson, type DatabaseCatalog, type DatabaseCatalogEntry,
} from './server-info.js';
import { computeBinLeafHash, computeParentN, ZERO_HASH } from './merkle.js';
import { sha256 } from './hash.js';

import { HarmonyWorkerPool, BuildItem, BuildResult, ProcessItem } from './harmonypir_worker_pool.js';
import {
  buildCacheKey as idbCacheKey,
  fingerprintsEqual,
  getHints as idbGetHints,
  putHints as idbPutHints,
  deleteHints as idbDeleteHints,
  HINT_SCHEMA_VERSION,
  type HintFingerprint,
} from './harmonypir_hint_db.js';

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
  /** Raw chunk data (kept for Merkle verification) */
  rawChunkData?: Uint8Array;
  /** Script hash as bytes (for Merkle leaf hash) */
  scriptHashBytes?: Uint8Array;
  // ── Per-bucket bin Merkle ─────────────────────────────────────────
  /** PBC group index for the INDEX query (when found) */
  indexPbcGroup?: number;
  /** Cuckoo bin index within the INDEX group (when found) */
  indexBinIndex?: number;
  /** Raw INDEX bin content (slotsPerBin × slotSize bytes, when found) */
  indexBinContent?: Uint8Array;
  /**
   * All INDEX bins checked (for "not found" verification).
   * When a scripthash is NOT found, all cuckoo positions must be verified.
   */
  allIndexBins?: { pbcGroup: number; binIndex: number; binContent: Uint8Array }[];
  /** PBC group indices for each CHUNK query */
  chunkPbcGroups?: number[];
  /** Cuckoo bin indices for each CHUNK query */
  chunkBinIndices?: number[];
  /** Raw CHUNK bin contents */
  chunkBinContents?: Uint8Array[];
}

// ─── WASM module type (loaded dynamically) ──────────────────────────────────

interface HarmonyWasmModule {
  HarmonyBucket: {
    // Note: parameter name matches pre-built WASM export; renamed to group_id in Rust source
    new(n: number, w: number, t: number, prpKey: Uint8Array, bucketId: number): HarmonyGroupWasm;
    new_with_backend(n: number, w: number, t: number, prpKey: Uint8Array, bucketId: number, prpBackend: number): HarmonyGroupWasm;
  };
  compute_balanced_t(n: number): number;
  verify_protocol(n: number, w: number): boolean;
}

interface HarmonyGroupWasm {
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
  candidateIndexGroups: number[];
  assignedIndexGroup: number;
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
    groupId: number;
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

  // Per-group WASM state (used in single-threaded fallback only)
  private indexGroups: Map<number, HarmonyGroupWasm> = new Map();
  private chunkGroups: Map<number, HarmonyGroupWasm> = new Map();

  // Server params
  private serverInfo: ServerInfoJson | null = null;
  private catalog: DatabaseCatalog | null = null;
  // Active params: reflect the currently selected database (main or delta).
  private indexBinsPerTable = 0;
  private chunkBinsPerTable = 0;
  private tagSeed = 0n;
  private prpKey: Uint8Array;
  /** Currently selected database ID (0 = main, 1+ = delta). */
  private dbId = 0;

  // Actual hint bytes received during download.
  private totalHintBytes = 0;

  // Cache of serialized hint state per (dbId, PRP backend) pair.
  // Each (dbId, prpBackend) combination needs its own hints because
  // the underlying tables (and thus cell layouts) differ between databases.
  private hintCache: Map<string, {
    prpKey: Uint8Array;
    groups: Map<number, Uint8Array>;
    totalHintBytes: number;
  }> = new Map();

  // Whether hints have been loaded for the current (dbId, PRP backend).
  hintsLoaded = false;

  // Test hook: one-shot override of the computed scripthashes for the next
  // queryBatch() call. Consumed on use and then cleared. Used by harnesses
  // that need to drive a query at a specific scripthash without reversing
  // HASH160. Production UI never sets this.
  private _scriptHashOverride: Uint8Array[] | undefined = undefined;
  setScriptHashOverrideForNextQuery(hashes: Uint8Array[]): void {
    this._scriptHashOverride = hashes;
  }

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
    // Load main DB params by default; switching dbs is done via setDbId().
    this.indexBinsPerTable = info.index_bins_per_table;
    this.chunkBinsPerTable = info.chunk_bins_per_table;
    this.tagSeed = info.tag_seed;
    this.log(`Server info (JSON): indexBins=${this.indexBinsPerTable}, chunkBins=${this.chunkBinsPerTable}`);

    // Fetch the database catalog (older servers may not support this).
    try {
      this.catalog = await fetchDatabaseCatalog(this.queryWs!);
      if (this.catalog.databases.length > 1) {
        this.log(`Database catalog: ${this.catalog.databases.length} databases available`);
        for (const db of this.catalog.databases) {
          this.log(`  [${db.dbId}] ${db.name} (height=${db.height}, index_bins=${db.indexBinsPerTable}, chunk_bins=${db.chunkBinsPerTable})`);
        }
      }
      // Re-apply current dbId in case the catalog tells us about non-zero DBs.
      this.applyDbParams(this.dbId);
    } catch {
      this.log('Database catalog not available (older server)');
      this.catalog = null;
    }
  }

  /** Return the database catalog (fetched on connect). */
  getCatalog(): DatabaseCatalog | null {
    return this.catalog;
  }

  /** Find a catalog entry by db_id. */
  getCatalogEntry(dbId: number): DatabaseCatalogEntry | undefined {
    return this.catalog?.databases.find(d => d.dbId === dbId);
  }

  /** Currently active database ID. */
  getDbId(): number {
    return this.dbId;
  }

  /**
   * Switch the active database. Hints from the previous DB stay cached so
   * switching back is cheap. Caller must call initGroups() and fetchHints()
   * (or restoreHintsFromCache) for the new DB before issuing queries.
   */
  setDbId(dbId: number): void {
    if (dbId !== 0 && this.catalog && !this.getCatalogEntry(dbId)) {
      throw new Error(`Unknown database dbId=${dbId}`);
    }
    this.dbId = dbId;
    this.applyDbParams(dbId);
    // The new DB has its own (potentially different) bin layout, so any
    // previously-loaded hints in the WASM groups are no longer valid.
    this.hintsLoaded = false;
    // Sibling Merkle groups also have per-DB bucket counts and per-DB
    // sibling tables on the server, so the cached sibling state from the
    // previous DB cannot be reused either. Force a re-download on the next
    // verifyMerkleBatch() call.
    this.siblingHintsLoaded = false;
  }

  /** Check if a specific database has per-bucket Merkle available. */
  hasMerkleForDb(dbId: number): boolean {
    const info = this.getBucketMerkleForDb(dbId);
    return !!(info && info.index_levels.length > 0);
  }

  /** Get BucketMerkleInfoJson for the given database, main or per-DB. */
  private getBucketMerkleForDb(dbId: number): import('./server-info.js').BucketMerkleInfoJson | undefined {
    if (dbId === 0) {
      return this.serverInfo?.merkle_bucket;
    }
    const dbInfo = this.serverInfo?.databases?.find(d => d.db_id === dbId);
    return dbInfo?.merkle_bucket;
  }

  /** Update active params from the catalog entry for the given dbId. */
  private applyDbParams(dbId: number): void {
    if (dbId === 0 || !this.catalog) {
      // Use main DB params from server-info JSON.
      if (this.serverInfo) {
        this.indexBinsPerTable = this.serverInfo.index_bins_per_table;
        this.chunkBinsPerTable = this.serverInfo.chunk_bins_per_table;
        this.tagSeed = this.serverInfo.tag_seed;
      }
      return;
    }
    const entry = this.getCatalogEntry(dbId);
    if (!entry) return;
    this.indexBinsPerTable = entry.indexBinsPerTable;
    this.chunkBinsPerTable = entry.chunkBinsPerTable;
    this.tagSeed = entry.tagSeed;
  }

  /** Cache key for hints: combines dbId + prpBackend. */
  private hintCacheKey(dbId: number, backend: number): string {
    return `${dbId}:${backend}`;
  }

  /** Initialize WASM group instances on workers (or main thread fallback). */
  async initGroups(): Promise<void> {
    if (!this.wasm) throw new Error('WASM not loaded');
    const backend = this.config.prpBackend ?? 0;
    const backendName = ['Hoang', 'FastPRP', 'ALF'][backend] ?? 'Hoang';

    if (this.pool) {
      // Create groups on workers.
      const promises: Promise<void>[] = [];
      for (let b = 0; b < K; b++) {
        promises.push(this.pool.createGroup(b, this.indexBinsPerTable, HARMONY_INDEX_W, 0, this.prpKey, backend));
      }
      for (let b = 0; b < K_CHUNK; b++) {
        // Chunk groups use IDs K..K+K_CHUNK-1 for PRP derivation.
        promises.push(this.pool.createGroup(K + b, this.chunkBinsPerTable, HARMONY_CHUNK_W, 0, this.prpKey, backend));
      }
      await Promise.all(promises);
    } else {
      // Single-threaded fallback.
      for (let b = 0; b < K; b++) {
        const group = this.wasm.HarmonyBucket.new_with_backend(
          this.indexBinsPerTable, HARMONY_INDEX_W, 0, this.prpKey, b, backend
        );
        this.indexGroups.set(b, group);
      }
      for (let b = 0; b < K_CHUNK; b++) {
        const group = this.wasm.HarmonyBucket.new_with_backend(
          this.chunkBinsPerTable, HARMONY_CHUNK_W, 0, this.prpKey, K + b, backend
        );
        this.chunkGroups.set(b, group);
      }
    }

    this.log(`Initialized ${K} index + ${K_CHUNK} chunk groups (PRP: ${backendName}${this.pool ? `, ${this.pool.size} workers` : ''})`);
  }

  /**
   * Fetch hints from the Hint Server for all groups.
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

    const total = K + K_CHUNK; // 75 + 80 = 155 groups total
    let globalReceived = 0;

    const onGroupDone = () => {
      if (gen !== this.hintFetchGen) return; // stale fetch
      globalReceived++;
      const pct = Math.round((globalReceived / total) * 100);
      this.log(`  Hints: ${globalReceived}/${total} (${pct}%)`);
    };

    // Connect to Hint Server.
    const hintWs = await this.connectHintServer();
    this.hintWs = hintWs;

    // Request index hints (75 groups). Offset=0 for INDEX.
    const tIdx = performance.now();
    await this.requestHints(hintWs, 0, K, 0, this.indexGroups, HARMONY_INDEX_W, onGroupDone);
    if (gen !== this.hintFetchGen) { hintWs.close(); return; }
    this.log(`  INDEX hints: ${K} groups in ${((performance.now() - tIdx) / 1000).toFixed(1)}s`);

    // Request chunk hints (80 groups). Offset=K for CHUNK.
    const tChk = performance.now();
    await this.requestHints(hintWs, 1, K_CHUNK, K, this.chunkGroups, HARMONY_CHUNK_W, onGroupDone);
    if (gen !== this.hintFetchGen) { hintWs.close(); return; }
    this.log(`  CHUNK hints: ${K_CHUNK} groups in ${((performance.now() - tChk) / 1000).toFixed(1)}s`);

    hintWs.close();
    this.hintWs = null;
    this.hintsLoaded = true;
    const totalSec = ((performance.now() - t0) / 1000).toFixed(1);
    this.log(`Hints downloaded successfully (${totalSec}s, ~${this.estimateHintSize()} MB)`);

    // Persist so a page reload can restore without re-downloading.
    try {
      await this.saveHintsToCache();
    } catch (e) {
      this.log(`Hint persist after download failed: ${(e as Error).message}`);
    }
  }

  /**
   * Query a single Bitcoin address via HarmonyPIR.
   * Delegates to queryBatch with a single address.
   */
  async query(address: string, dbId?: number): Promise<HarmonyQueryResult> {
    const results = await this.queryBatch([address], undefined, dbId);
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

  /** Request hints from the Hint Server for a set of groups at one level.
   *  groupIdOffset: 0 for INDEX, K for CHUNK (maps local 0-based ID to global group ID for pool). */
  private async requestHints(
    ws: WebSocket,
    level: number,
    numGroups: number,
    groupIdOffset: number,
    groups: Map<number, HarmonyGroupWasm>,
    w: number,
    onGroupDone?: () => void,
  ): Promise<void> {
    // Build hint request.
    const groupIds = Array.from({ length: numGroups }, (_, i) => i);
    // Wire: [1B variant][16B prp_key][1B prp_backend][1B level][1B num_groups][per group: 1B id]
    //       [optional trailing 1B db_id, only when non-zero — backward compatible]
    const backend = this.config.prpBackend ?? 0;
    const dbId = this.dbId;
    const baseLen = 1 + 16 + 1 + 1 + 1 + numGroups;
    const msgLen = baseLen + (dbId !== 0 ? 1 : 0);
    const msg = new Uint8Array(msgLen);
    msg[0] = REQ_HARMONY_HINTS;
    msg.set(this.prpKey, 1);
    msg[17] = backend;
    msg[18] = level;
    msg[19] = numGroups;
    for (let i = 0; i < numGroups; i++) {
      msg[20 + i] = groupIds[i];
    }
    if (dbId !== 0) {
      msg[baseLen] = dbId;
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
          const groupId = payload[1];
          const hintsData = payload.slice(14);
          this.totalHintBytes += hintsData.length;

          if (this.pool) {
            // Forward hints to worker (global group ID = offset + local).
            this.pool.loadHints(groupIdOffset + groupId, hintsData);
          } else {
            // Single-threaded fallback: load directly.
            const group = groups.get(groupId);
            if (group) group.load_hints(hintsData);
          }

          received++;
          onGroupDone?.();
          if (received === numGroups) {
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
   *       - Real query (build_request) for groups whose tag is NOT yet found
   *       - Fake query (build_synthetic_dummy) for groups whose tag WAS found
   *       - Synthetic dummy for unassigned groups
   *       → 1 batch message with K groups × 1 sub-query each
   *       → Server responds, client calls process_response for real queries
   *
   * CHUNK:
   *   Same structure with K_CHUNK groups and CHUNK_CUCKOO_NUM_HASHES rounds.
   */
  async queryBatch(
    addresses: string[],
    progress?: (phase: string, detail: string) => void,
    dbId?: number,
  ): Promise<Map<number, HarmonyQueryResult>> {
    // If a dbId is supplied it must match the active database — switching
    // databases requires re-running setDbId() + initGroups() + fetchHints()
    // (or restoreHintsFromCache) because hint state is per-(dbId, backend).
    if (dbId !== undefined && dbId !== this.dbId) {
      throw new Error(
        `queryBatch dbId=${dbId} does not match active dbId=${this.dbId}; ` +
        `call setDbId() and reload hints before querying a different database.`
      );
    }

    const tBatchStart = performance.now();
    const N = addresses.length;
    const results = new Map<number, HarmonyQueryResult>();
    this.log(`Starting batch query for ${N} addresses (dbId=${this.dbId})...`);
    this.log(`[PIR-AUDIT] Query parameters: K=${K} index groups, K_CHUNK=${K_CHUNK} chunk groups, INDEX_CUCKOO_NUM_HASHES=${INDEX_CUCKOO_NUM_HASHES}`);

    // ── Pre-flight: check hint budget ──
    const remaining = await this.getMinQueriesRemaining();
    if (remaining === 0) {
      this.log('Hints exhausted — re-downloading...');
      await this.refreshHints();
    } else if (remaining < 4) {
      this.log(`Warning: only ${remaining} queries remaining per group`);
    }

    // ── Prepare script hashes (accept both addresses and hex scriptPubKeys) ──
    // Test/debug hook: if an override array is set, it replaces the computed
    // scripthashes 1:1 with the override (same length). This lets harnesses
    // drive queries against known-present entries without needing a reverse
    // HASH160 preimage. Cleared after consumption so it never lingers.
    const scriptHashes: Uint8Array[] = [];
    const shHexes: string[] = [];
    const override = this._scriptHashOverride;
    this._scriptHashOverride = undefined;
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
      const sh = override && i < override.length ? override[i] : computeScriptHash(hexToBytes(spkHex));
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
    const indexCandGroups = scriptHashes.map(sh => deriveGroups(sh));
    const indexRounds = planRounds(indexCandGroups, K, NUM_HASHES, (msg) => this.log(msg));
    this.log(`Level 1: ${N} queries → ${indexRounds.length} index placement round(s) × ${INDEX_CUCKOO_NUM_HASHES} hash-fn rounds`);
    this.log(`[PIR-AUDIT] PADDING: Each index round sends exactly ${K} queries (real + dummy for privacy)`);

    // Pre-populate inspector data for each query.
    for (let qi = 0; qi < N; qi++) {
      inspectorMap.set(qi, {
        address: addresses[qi],
        scriptPubKeyHex: (/^[0-9a-fA-F]+$/.test(addresses[qi]) && addresses[qi].length % 2 === 0)
          ? addresses[qi].toLowerCase() : (addressToScriptPubKey(addresses[qi]) ?? ''),
        scriptHashHex: shHexes[qi],
        candidateIndexGroups: indexCandGroups[qi],
        assignedIndexGroup: -1,
        indexPlacementRound: -1,
        isWhale: false,
        roundTimings,
        totalMs: 0,
      });
    }

    const indexResults = new Map<number, { startChunkId: number; numChunks: number; pbcGroup: number; binIndex: number; binContent: Uint8Array }>();
    const whaleQueries = new Set<number>();
    // Track ALL bins checked per query for "not found" Merkle verification
    const allBinsChecked = new Map<number, { pbcGroup: number; binIndex: number; binContent: Uint8Array }[]>();

    for (let ir = 0; ir < indexRounds.length; ir++) {
      const round = indexRounds[ir];
      const groupToQuery = new Map<number, number>();
      for (const [qi, groupId] of round) {
        groupToQuery.set(groupId, qi);
        // Inspector: record which group each query is assigned to.
        const qd = inspectorMap.get(qi);
        if (qd && qd.assignedIndexGroup < 0) {
          qd.assignedIndexGroup = groupId;
          qd.indexPlacementRound = ir;
        }
      }

      const foundThisPlacement = new Set<number>(); // qi already found in this placement round

      for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
        progress?.('Level 1', `Index placement ${ir + 1}/${indexRounds.length}, h=${h}...`);

        // Determine which groups get real vs dummy queries.
        const realGroups = new Map<number, number>(); // groupId → qi
        const realBinIndices = new Map<number, number>(); // groupId → binIndex (for Merkle)
        const buildItems: BuildItem[] = [];

        for (let b = 0; b < K; b++) {
          const qi = groupToQuery.get(b);
          if (qi !== undefined && !foundThisPlacement.has(qi) && !indexResults.has(qi) && !whaleQueries.has(qi)) {
            const ck = deriveCuckooKey(b, h);
            const binIndex = cuckooHash(scriptHashes[qi], ck, this.indexBinsPerTable);
            buildItems.push({ groupId: b, binIndex });
            realGroups.set(b, qi);
            realBinIndices.set(b, binIndex);
            // Inspector: record which binIndex this query used.
            const qd = inspectorMap.get(qi);
            if (qd && qd.indexBinIndex === undefined) {
              qd.indexBinIndex = binIndex;
            }
          } else {
            buildItems.push({ groupId: b }); // dummy (binIndex undefined)
          }
        }

        // Build requests (parallel via workers or single-threaded fallback).
        const tBuild = performance.now();
        const reqBytesMap = await this.doBuildBatch(buildItems, 'index');
        const buildMs = performance.now() - tBuild;

        // Inspector: capture segment/position from build results.
        for (const [groupId, qi] of realGroups) {
          const br = reqBytesMap.get(groupId);
          const qd = inspectorMap.get(qi);
          if (br && qd && qd.indexSegment === undefined) {
            qd.indexSegment = br.segment;
            qd.indexPosition = br.position;
            qd.indexSegmentSize = br.bytes.length / 4; // T_eff (each index is 4 bytes u32 LE)
          }
        }

        // Encode and send batch.
        const batchItems = buildItems.map(item => ({
          groupId: item.groupId,
          subQueryBytes: [(reqBytesMap.get(item.groupId)?.bytes) ?? new Uint8Array(0)],
        }));
        const roundId = ir * INDEX_CUCKOO_NUM_HASHES + h;
        const reqMsg = this.encodeHarmonyBatchRequest(0, roundId, 1, batchItems);
        const tNet = performance.now();
        const respData = await this.sendQueryRequest(reqMsg);
        const netMs = performance.now() - tNet;
        const batchResp = this.decodeHarmonyBatchResponse(respData);

        // Process real responses (parallel via workers or single-threaded fallback).
        const processItems: ProcessItem[] = [];
        for (const [groupId] of realGroups) {
          const respItem = batchResp.get(groupId);
          if (respItem && respItem.length > 0) {
            processItems.push({ groupId: groupId, response: respItem[0] });
          }
        }
        const tProc = performance.now();
        const answers = await this.doProcessBatch(processItems, 'index');
        const procMs = performance.now() - tProc;

        // Match answers against expected tags.
        for (const [groupId, qi] of realGroups) {
          const answer = answers.get(groupId);
          if (!answer) continue;

          // Track every bin checked for this query
          const binInfo = {
            pbcGroup: groupId,
            binIndex: realBinIndices.get(groupId) ?? 0,
            binContent: answer,
          };
          const bins = allBinsChecked.get(qi) ?? [];
          bins.push(binInfo);
          allBinsChecked.set(qi, bins);

          const expectedTag = computeTag(this.tagSeed, scriptHashes[qi]);
          const found = findEntryInIndexResult(answer, expectedTag, HARMONY_INDEX_W / INDEX_SLOT_SIZE, INDEX_SLOT_SIZE);
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
              indexResults.set(qi, {
                ...found,
                pbcGroup: groupId,
                binIndex: realBinIndices.get(groupId) ?? 0,
                binContent: answer,
              });
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
        await this.doFinishRelocation(processItems.map(i => i.groupId), 'index');
        const relocMs = performance.now() - tReloc;

        // Inspector: record round timing.
        roundTimings.push({
          phase: 'index', roundIdx: ir, hashIdx: h,
          realCount: realGroups.size, totalCount: K,
          buildMs, netMs, procMs, relocMs,
        });
        this.log(`  INDEX r${ir}h${h}: build=${buildMs.toFixed(0)}ms net=${netMs.toFixed(0)}ms proc=${procMs.toFixed(0)}ms reloc=${relocMs.toFixed(0)}ms (${realGroups.size} real / ${K} total)`);
      }
    }

    const l1Ms = performance.now() - tL1Start;
    this.log(`Level 1 done: ${indexResults.size} found, ${whaleQueries.size} whales (${(l1Ms / 1000).toFixed(1)}s)`);
    // Audit log: which queries found vs not found
    for (let qi = 0; qi < N; qi++) {
      const bins = allBinsChecked.get(qi);
      const ir = indexResults.get(qi);
      if (ir) {
        this.log(`[PIR-AUDIT] Query ${qi}: FOUND at group=${ir.pbcGroup}, binIndex=${ir.binIndex}, startChunk=${ir.startChunkId}, numChunks=${ir.numChunks}`);
      } else if (whaleQueries.has(qi)) {
        this.log(`[PIR-AUDIT] Query ${qi}: WHALE (excluded due to too many UTXOs)`);
      } else {
        const checkedCount = bins?.length ?? 0;
        this.log(`[PIR-AUDIT] Query ${qi}: NOT FOUND (checked ${checkedCount} bins)`);
      }
    }

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
    // Track per-chunk Merkle info: chunkId → { pbcGroup, binIndex, binContent }
    const chunkMerkleInfo = new Map<number, { pbcGroup: number; binIndex: number; binContent: Uint8Array }>();

    if (allChunkIds.length > 0) {
      this.log(`[PIR-AUDIT] Chunk IDs to fetch: [${allChunkIds.slice(0, 10).join(', ')}${allChunkIds.length > 10 ? '...' : ''}]`);
      const chunkCandGroups = allChunkIds.map(cid => deriveChunkGroups(cid));
      const chunkRounds = planRounds(chunkCandGroups, K_CHUNK, NUM_HASHES, (msg) => this.log(msg));
      this.log(`  ${allChunkIds.length} chunks → ${chunkRounds.length} chunk placement round(s) × ${CHUNK_CUCKOO_NUM_HASHES} hash-fn rounds`);
      this.log(`[PIR-AUDIT] PADDING: Each chunk round sends exactly ${K_CHUNK} queries (real + dummy for privacy)`);

      for (let ri = 0; ri < chunkRounds.length; ri++) {
        const roundPlan = chunkRounds[ri];
        const groupToChunk = new Map<number, number>(); // groupId → chunkListIdx
        for (const [chunkListIdx, groupId] of roundPlan) {
          groupToChunk.set(groupId, chunkListIdx);
        }

        const foundThisPlacement = new Set<number>(); // chunk_ids found in this placement round

        for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
          progress?.('Level 2', `Chunk placement ${ri + 1}/${chunkRounds.length}, h=${h}...`);

          const realGroups = new Map<number, { chunkListIdx: number; chunkId: number; binIndex: number }>();
          const buildItems: BuildItem[] = [];

          for (let b = 0; b < K_CHUNK; b++) {
            const chunkListIdx = groupToChunk.get(b);
            if (chunkListIdx !== undefined) {
              const chunkId = allChunkIds[chunkListIdx];
              if (!foundThisPlacement.has(chunkId) && !recoveredChunks.has(chunkId)) {
                const ck = deriveChunkCuckooKey(b, h);
                const binIndex = cuckooHashInt(chunkId, ck, this.chunkBinsPerTable);
                buildItems.push({ groupId: K + b, binIndex }); // global ID = K + b
                realGroups.set(b, { chunkListIdx, chunkId, binIndex });
              } else {
                buildItems.push({ groupId: K + b }); // dummy
              }
            } else {
              buildItems.push({ groupId: K + b }); // dummy
            }
          }

          const tBuild = performance.now();
          const reqBytesMap = await this.doBuildBatch(buildItems, 'chunk');
          const buildMs = performance.now() - tBuild;

          const batchItems = buildItems.map(item => ({
            groupId: item.groupId - K, // local group ID for wire protocol
            subQueryBytes: [(reqBytesMap.get(item.groupId)?.bytes) ?? new Uint8Array(0)],
          }));
          const roundId = ri * CHUNK_CUCKOO_NUM_HASHES + h;
          const reqMsg = this.encodeHarmonyBatchRequest(1, roundId, 1, batchItems);
          const tNet = performance.now();
          const respData = await this.sendQueryRequest(reqMsg);
          const netMs = performance.now() - tNet;
          const batchResp = this.decodeHarmonyBatchResponse(respData);

          const processItems: ProcessItem[] = [];
          for (const [localB] of realGroups) {
            const respItem = batchResp.get(localB);
            if (respItem && respItem.length > 0) {
              processItems.push({ groupId: K + localB, response: respItem[0] }); // global ID
            }
          }
          const tProc = performance.now();
          const answers = await this.doProcessBatch(processItems, 'chunk');
          const procMs = performance.now() - tProc;

          for (const [localB, { chunkId, binIndex }] of realGroups) {
            const answer = answers.get(K + localB); // global ID
            if (!answer) continue;
            const found = findChunkInResult(answer, chunkId, answer.length / CHUNK_SLOT_SIZE, CHUNK_SLOT_SIZE);
            if (found) {
              recoveredChunks.set(chunkId, found);
              chunkMerkleInfo.set(chunkId, { pbcGroup: localB, binIndex, binContent: answer });
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
                    groupId: localB,
                    segment: br?.segment,
                    position: br?.position,
                  });
                }
              }
            }
          }

          // Deferred relocation (expensive PRP work, after results are available).
          const tReloc = performance.now();
          await this.doFinishRelocation(processItems.map(i => i.groupId), 'chunk');
          const relocMs = performance.now() - tReloc;

          // Inspector: record chunk round timing.
          roundTimings.push({
            phase: 'chunk', roundIdx: ri, hashIdx: h,
            realCount: realGroups.size, totalCount: K_CHUNK,
            buildMs, netMs, procMs, relocMs,
          });
          this.log(`  CHUNK r${ri}h${h}: build=${buildMs.toFixed(0)}ms net=${netMs.toFixed(0)}ms proc=${procMs.toFixed(0)}ms reloc=${relocMs.toFixed(0)}ms (${realGroups.size} real / ${K_CHUNK} total)`);
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
        // Not found — include ALL bins checked for Merkle verification
        const bins = allBinsChecked.get(qi);
        const firstBin = bins?.[0];
        results.set(qi, {
          address: addresses[qi],
          scriptHash: shHexes[qi],
          utxos: [],
          whale: false,
          merkleRootHex: this.serverInfo?.merkle_bucket?.super_root ?? this.serverInfo?.merkle?.root,
          scriptHashBytes: scriptHashes[qi],
          // Singular fields (backward compat) - first bin
          indexPbcGroup: firstBin?.pbcGroup,
          indexBinIndex: firstBin?.binIndex,
          indexBinContent: firstBin?.binContent,
          // ALL bins checked - needed for proper "not found" verification
          allIndexBins: bins,
          chunkPbcGroups: [],
          chunkBinIndices: [],
          chunkBinContents: [],
        });
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
      // Collect chunk-level Merkle info for this query
      const qChunkPbcGroups: number[] = [];
      const qChunkBinIndices: number[] = [];
      const qChunkBinContents: Uint8Array[] = [];
      for (let ci = 0; ci < info.numChunks; ci++) {
        const cid = info.startChunk + ci;
        const cmi = chunkMerkleInfo.get(cid);
        if (cmi) {
          qChunkPbcGroups.push(cmi.pbcGroup);
          qChunkBinIndices.push(cmi.binIndex);
          qChunkBinContents.push(cmi.binContent);
        }
      }

      const idxInfo = indexResults.get(qi);
      results.set(qi, {
        address: addresses[qi],
        scriptHash: shHexes[qi],
        utxos,
        whale: false,
        merkleRootHex: this.serverInfo?.merkle_bucket?.super_root ?? this.serverInfo?.merkle?.root,
        rawChunkData,
        scriptHashBytes: scriptHashes[qi],
        indexPbcGroup: idxInfo?.pbcGroup,
        indexBinIndex: idxInfo?.binIndex,
        indexBinContent: idxInfo?.binContent,
        // For "found", allIndexBins contains bins checked up to the match
        allIndexBins: allBinsChecked.get(qi),
        chunkPbcGroups: qChunkPbcGroups,
        chunkBinIndices: qChunkBinIndices,
        chunkBinContents: qChunkBinContents,
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

  /** Encode a HarmonyBatchQuery message (excluding the 4B length prefix).
   *  Wire format mirrors runtime/src/protocol.rs encode_harmony_batch_query:
   *    [1B variant][1B level][2B round_id][2B num_groups][1B sub_queries_per_group]
   *    per group: [1B group_id] per sub_query: [4B count][count × 4B u32 LE indices]
   *    [optional trailing 1B db_id, only when non-zero — backward compatible]
   */
  private encodeHarmonyBatchRequest(
    level: number,
    roundId: number,
    subQueriesPerGroup: number,
    items: Array<{ groupId: number; subQueryBytes: Uint8Array[] }>,
  ): Uint8Array {
    const dbId = this.dbId;

    // Compute total size.
    let size = 1 + 1 + 2 + 2 + 1; // variant + level + round_id + num_groups + subQ
    for (const item of items) {
      size += 1; // group_id
      for (const sq of item.subQueryBytes) {
        size += 4 + sq.length; // count + indices
      }
    }
    if (dbId !== 0) size += 1; // trailing db_id byte

    const buf = new Uint8Array(size);
    const view = new DataView(buf.buffer);
    let pos = 0;

    buf[pos++] = REQ_HARMONY_BATCH_QUERY;
    buf[pos++] = level;
    view.setUint16(pos, roundId, true); pos += 2;
    view.setUint16(pos, items.length, true); pos += 2;
    buf[pos++] = subQueriesPerGroup;

    for (const item of items) {
      buf[pos++] = item.groupId;
      for (const sq of item.subQueryBytes) {
        const count = sq.length / 4;
        view.setUint32(pos, count, true); pos += 4;
        buf.set(sq, pos); pos += sq.length;
      }
    }

    if (dbId !== 0) {
      buf[pos++] = dbId;
    }

    return buf;
  }

  /** Decode a HarmonyBatchResult response payload. */
  private decodeHarmonyBatchResponse(
    data: Uint8Array,
  ): Map<number, Uint8Array[]> {
    // data = [1B variant][1B level][2B round_id][2B num_groups][1B subResultsPerGroup]
    //        per group: [1B group_id] per sub_result: [4B data_len][data]
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let pos = 1; // skip variant
    /* const level = */ data[pos++];
    /* const roundId = */ view.getUint16(pos, true); pos += 2;
    const numGroups = view.getUint16(pos, true); pos += 2;
    const subResultsPerGroup = data[pos++];

    const result = new Map<number, Uint8Array[]>();
    for (let i = 0; i < numGroups; i++) {
      const groupId = data[pos++];
      const subResults: Uint8Array[] = [];
      for (let s = 0; s < subResultsPerGroup; s++) {
        const len = view.getUint32(pos, true); pos += 4;
        subResults.push(data.slice(pos, pos + len));
        pos += len;
      }
      result.set(groupId, subResults);
    }
    return result;
  }

  // ─── Worker/fallback dispatch helpers ────────────────────────────────────

  /**
   * Build requests for a batch of groups.
   * Uses worker pool if available, otherwise direct WASM calls.
   * @param level 'index' or 'chunk' — determines which group map to use for fallback.
   */
  private async doBuildBatch(
    items: BuildItem[],
    level: 'index' | 'chunk',
  ): Promise<Map<number, BuildResult>> {
    if (this.pool) {
      return this.pool.buildBatchRequests(items);
    }

    // Single-threaded fallback.
    const groupMap = level === 'index' ? this.indexGroups : this.chunkGroups;
    const result = new Map<number, BuildResult>();
    for (const item of items) {
      const localId = level === 'index' ? item.groupId : item.groupId - K;
      const group = groupMap.get(localId);
      if (!group) continue;
      if (item.binIndex !== undefined) {
        const req = group.build_request(item.binIndex);
        const br: BuildResult = {
          bytes: new Uint8Array(req.request),
          segment: req.segment,
          position: req.position,
        };
        req.free();
        result.set(item.groupId, br);
      } else {
        result.set(item.groupId, { bytes: new Uint8Array(group.build_synthetic_dummy()) });
      }
    }
    return result;
  }

  /**
   * Process responses for a batch of groups.
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
    const groupMap = level === 'index' ? this.indexGroups : this.chunkGroups;
    const result = new Map<number, Uint8Array>();
    for (const item of items) {
      const localId = level === 'index' ? item.groupId : item.groupId - K;
      const group = groupMap.get(localId);
      if (!group) continue;
      const answer = group.process_response_xor_only(item.response);
      result.set(item.groupId, answer);
    }
    return result;
  }

  /** Complete deferred relocation for groups that had xor-only processing. */
  private async doFinishRelocation(
    groupIds: number[],
    level: 'index' | 'chunk',
  ): Promise<void> {
    if (this.pool) {
      return this.pool.finishRelocation(groupIds);
    }

    // Single-threaded fallback.
    const groupMap = level === 'index' ? this.indexGroups : this.chunkGroups;
    for (const id of groupIds) {
      const localId = level === 'index' ? id : id - K;
      const group = groupMap.get(localId);
      if (group) group.finish_relocation();
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

  /** Return all open WebSocket connections (for diagnostics like residency check). */
  getConnectedSockets(): { label: string; ws: ManagedWebSocket }[] {
    const out: { label: string; ws: ManagedWebSocket }[] = [];
    if (this.queryWs?.isOpen()) out.push({ label: 'HarmonyPIR Query Server', ws: this.queryWs });
    return out;
  }

  /** Disconnect and free all resources (full teardown). */
  disconnect(): void {
    this.hintFetchGen++; // abort any in-progress hint fetch
    this.queryWs?.disconnect();
    this.hintWs?.close();
    this.hintWs = null;
    if (this.pool) {
      this.pool.terminate();
      this.pool = null;
    }
    for (const [_, b] of this.indexGroups) b.free();
    for (const [_, b] of this.chunkGroups) b.free();
    this.indexGroups.clear();
    this.chunkGroups.clear();
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
    for (const [_, b] of this.indexGroups) b.free();
    for (const [_, b] of this.chunkGroups) b.free();
    this.indexGroups.clear();
    this.chunkGroups.clear();
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

  /** Check if server supports per-bucket bin Merkle verification */
  hasMerkle(): boolean {
    return !!(this.serverInfo?.merkle_bucket && this.serverInfo.merkle_bucket.index_levels.length > 0);
  }

  /** Get the Merkle super-root hash hex for the currently active database. */
  getMerkleRootHex(): string | undefined {
    return this.getBucketMerkleForDb(this.dbId)?.super_root
      ?? this.serverInfo?.merkle_bucket?.super_root
      ?? this.serverInfo?.merkle?.root;
  }

  /** Whether sibling hints have been downloaded for bucket Merkle. */
  siblingHintsLoaded = false;

  /**
   * Batch-verify per-bucket bin Merkle proofs using native HarmonyPIR.
   *
   * On first call, downloads sibling hints from the Hint Server (lazy init).
   * Then issues HarmonyPIR batch queries to flat sibling tables, walks
   * tree-top cache to per-group root, and verifies super-root.
   */
  async verifyMerkleBatch(
    results: HarmonyQueryResult[],
    onProgress?: (step: string, detail: string) => void,
  ): Promise<boolean[]> {
    // Resolve per-DB Merkle info. For db_id=0 this falls back to the
    // top-level merkle_bucket (backward compatible with older servers).
    const merkle = this.getBucketMerkleForDb(this.dbId);
    if (!merkle) throw new Error(`Database dbId=${this.dbId} does not support bucket Merkle`);
    if (!this.queryWs) throw new Error('Not connected to query server');

    // Build verifiable items.
    // For "not found" (no utxos), we create one item PER INDEX BIN checked.
    const items: Array<{
      qi: number;
      indexPbcGroup: number; indexBinIndex: number; indexBinContent: Uint8Array;
      chunkPbcGroups: number[]; chunkBinIndices: number[]; chunkBinContents: Uint8Array[];
    }> = [];
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.whale) continue;

      // For "not found" (no utxos), verify ALL index bins
      if (r.allIndexBins && r.allIndexBins.length > 0 && r.utxos.length === 0) {
        for (const bin of r.allIndexBins) {
          items.push({
            qi: i,
            indexPbcGroup: bin.pbcGroup,
            indexBinIndex: bin.binIndex,
            indexBinContent: bin.binContent,
            chunkPbcGroups: [],
            chunkBinIndices: [],
            chunkBinContents: [],
          });
        }
      } else if (r.indexPbcGroup !== undefined && r.indexBinContent) {
        // For "found", verify the one bin where we found the match + chunks
        items.push({
          qi: i,
          indexPbcGroup: r.indexPbcGroup,
          indexBinIndex: r.indexBinIndex!,
          indexBinContent: r.indexBinContent,
          chunkPbcGroups: r.chunkPbcGroups ?? [],
          chunkBinIndices: r.chunkBinIndices ?? [],
          chunkBinContents: r.chunkBinContents ?? [],
        });
      }
    }
    if (items.length === 0) return results.map(() => false);

    // ── Step 1: Init sibling groups + hints (lazy, first call only) ──
    if (!this.siblingHintsLoaded) {
      onProgress?.('Merkle', 'Downloading sibling hints (one-time)...');
      await this.initAndFetchSiblingHints(merkle);
    }

    // ── Step 2: Fetch tree-top caches ──
    onProgress?.('Merkle', 'Fetching tree-top caches...');
    this.log(`Fetching bucket Merkle tree-tops (db=${this.dbId})...`);

    // [4B len][1B REQ_BUCKET_MERKLE_TREE_TOPS]([1B db_id] if non-zero)
    const topsLen = this.dbId !== 0 ? 2 : 1;
    const topsReq = new Uint8Array(4 + topsLen);
    new DataView(topsReq.buffer).setUint32(0, topsLen, true);
    topsReq[4] = REQ_BUCKET_MERKLE_TREE_TOPS;
    if (this.dbId !== 0) topsReq[5] = this.dbId;
    const topsRaw = await this.queryWs.sendRaw(topsReq);
    if (topsRaw.length < 6 || topsRaw[4] !== RESP_BUCKET_MERKLE_TREE_TOPS) {
      this.log('Failed to fetch bucket Merkle tree-tops');
      return results.map(() => false);
    }
    const topsData = topsRaw.slice(5);

    // Verify tree-tops integrity
    const topsHash = sha256(topsData);
    const expectedHash = hexToBytes(merkle.tree_tops_hash);
    if (!bytesEqual(topsHash, expectedHash)) {
      this.log('Tree-tops integrity check FAILED');
      return results.map(() => false);
    }
    this.log('Tree-top cache integrity: OK');

    const parsedTops = parseBucketTreeTops(topsData);

    // ── Step 3: Verify INDEX bins ──
    onProgress?.('Merkle', 'Verifying INDEX Merkle...');
    const indexVerified = await this.verifySiblingLevelsHarmony(
      items.map(it => ({ pbcGroup: it.indexPbcGroup, binIndex: it.indexBinIndex, binContent: it.indexBinContent })),
      merkle.index_levels, merkle.index_roots,
      parsedTops.slice(0, K),
      K, 10, // level offset 10 = INDEX siblings
    );

    // ── Step 4: Verify CHUNK bins ──
    onProgress?.('Merkle', 'Verifying CHUNK Merkle...');
    const chunkFlat: Array<{ pbcGroup: number; binIndex: number; binContent: Uint8Array }> = [];
    const chunkMap: Array<{ addrIdx: number }> = [];
    for (let i = 0; i < items.length; i++) {
      for (let c = 0; c < items[i].chunkPbcGroups.length; c++) {
        chunkFlat.push({
          pbcGroup: items[i].chunkPbcGroups[c],
          binIndex: items[i].chunkBinIndices[c],
          binContent: items[i].chunkBinContents[c],
        });
        chunkMap.push({ addrIdx: i });
      }
    }
    const chunkVerified = chunkFlat.length > 0
      ? await this.verifySiblingLevelsHarmony(
          chunkFlat, merkle.chunk_levels, merkle.chunk_roots,
          parsedTops.slice(K, K + K_CHUNK),
          K_CHUNK, 20, // level offset 20 = CHUNK siblings
        )
      : [];

    // ── Step 5: Combine results ──
    // For "not found" with multiple bins, ALL must pass.
    const out: boolean[] = new Array(results.length).fill(false);
    const resultBinCounts = new Map<number, { total: number; passed: number }>();

    for (let i = 0; i < items.length; i++) {
      const qi = items[i].qi;
      const counts = resultBinCounts.get(qi) ?? { total: 0, passed: 0 };
      counts.total++;
      if (indexVerified[i]) counts.passed++;
      resultBinCounts.set(qi, counts);
    }
    for (let j = 0; j < chunkMap.length; j++) {
      const qi = items[chunkMap[j].addrIdx].qi;
      const counts = resultBinCounts.get(qi)!;
      counts.total++;
      if (chunkVerified[j]) counts.passed++;
    }

    for (const [qi, counts] of resultBinCounts) {
      // Result passes only if ALL its bins were verified
      out[qi] = counts.passed === counts.total;
    }

    // Mark results
    for (let i = 0; i < results.length; i++) {
      results[i].merkleVerified = out[i];
    }

    const passed = out.filter(v => v).length;
    const totalResults = resultBinCounts.size;
    this.log(`Merkle: ${passed}/${totalResults} results verified`);
    return out;
  }

  /**
   * Initialize HarmonyPIR groups and download hints for sibling tables.
   * Called lazily on first verifyMerkleBatch() call.
   */
  private async initAndFetchSiblingHints(
    merkle: import('./server-info.js').BucketMerkleInfoJson,
  ): Promise<void> {
    if (!this.pool && !this.wasm) throw new Error('WASM not loaded');
    const backend = this.config.prpBackend ?? 0;
    const A = BUCKET_MERKLE_ARITY;
    const SIB_W = BUCKET_MERKLE_SIB_ROW_SIZE; // 256

    // Compute the PRP group ID offsets for sibling groups.
    // Main groups: 0..K-1 (INDEX), K..K+K_CHUNK-1 (CHUNK)
    // Sibling groups start at K + K_CHUNK = 155.
    let nextGroupId = K + K_CHUNK;

    // Create groups for INDEX sibling levels
    const indexSibGroupIds: number[][] = []; // [level][localGroup] → globalGroupId
    for (let level = 0; level < merkle.index_levels.length; level++) {
      const n = merkle.index_levels[level].bins_per_table;
      const ids: number[] = [];
      if (this.pool) {
        const promises: Promise<void>[] = [];
        for (let g = 0; g < K; g++) {
          const gid = nextGroupId + g;
          ids.push(gid);
          promises.push(this.pool.createGroup(gid, n, SIB_W, 0, this.prpKey, backend));
        }
        await Promise.all(promises);
      }
      indexSibGroupIds.push(ids);
      nextGroupId += K;
    }

    // Create groups for CHUNK sibling levels
    const chunkSibGroupIds: number[][] = [];
    for (let level = 0; level < merkle.chunk_levels.length; level++) {
      const n = merkle.chunk_levels[level].bins_per_table;
      const ids: number[] = [];
      if (this.pool) {
        const promises: Promise<void>[] = [];
        for (let g = 0; g < K_CHUNK; g++) {
          const gid = nextGroupId + g;
          ids.push(gid);
          promises.push(this.pool.createGroup(gid, n, SIB_W, 0, this.prpKey, backend));
        }
        await Promise.all(promises);
      }
      chunkSibGroupIds.push(ids);
      nextGroupId += K_CHUNK;
    }

    // Download hints for sibling groups
    this.log('Downloading sibling hints...');
    const hintWs = await this.connectHintServer();

    // INDEX sibling hints: level codes 10, 11, ...
    for (let level = 0; level < merkle.index_levels.length; level++) {
      const t = performance.now();
      await this.requestHints(hintWs, 10 + level, K, indexSibGroupIds[level][0], new Map(), SIB_W);
      this.log(`  INDEX sib L${level} hints: ${K} groups in ${((performance.now() - t) / 1000).toFixed(1)}s`);
    }

    // CHUNK sibling hints: level codes 20, 21, ...
    for (let level = 0; level < merkle.chunk_levels.length; level++) {
      const t = performance.now();
      await this.requestHints(hintWs, 20 + level, K_CHUNK, chunkSibGroupIds[level][0], new Map(), SIB_W);
      this.log(`  CHUNK sib L${level} hints: ${K_CHUNK} groups in ${((performance.now() - t) / 1000).toFixed(1)}s`);
    }

    hintWs.close();

    // Store group IDs for later use
    this._indexSibGroupIds = indexSibGroupIds;
    this._chunkSibGroupIds = chunkSibGroupIds;
    this.siblingHintsLoaded = true;
    this.log('Sibling hints loaded');

    // Re-persist so the IndexedDB record now includes sibling hints too.
    try {
      await this.saveHintsToCache();
    } catch (e) {
      this.log(`Hint persist after sibling download failed: ${(e as Error).message}`);
    }
  }

  // Stored sibling group IDs (set by initAndFetchSiblingHints)
  private _indexSibGroupIds: number[][] = [];
  private _chunkSibGroupIds: number[][] = [];

  /**
   * Verify one table type (INDEX or CHUNK) via native HarmonyPIR sibling queries.
   */
  private async verifySiblingLevelsHarmony(
    items: Array<{ pbcGroup: number; binIndex: number; binContent: Uint8Array }>,
    levelInfos: Array<{ dpf_n: number; bins_per_table: number }>,
    rootsHex: string[],
    treeTops: Array<{ cacheFromLevel: number; levels: Uint8Array[][] }>,
    tableK: number,
    levelOffset: number, // 10 for INDEX, 20 for CHUNK
  ): Promise<boolean[]> {
    const A = BUCKET_MERKLE_ARITY;
    const SIB_W = BUCKET_MERKLE_SIB_ROW_SIZE;
    const N = items.length;

    // Per-item state
    const currentHash: Uint8Array[] = new Array(N);
    const nodeIdx: number[] = new Array(N);

    // Compute leaf hashes
    for (let i = 0; i < N; i++) {
      currentHash[i] = computeBinLeafHash(items[i].binIndex, items[i].binContent);
      nodeIdx[i] = items[i].binIndex;
    }

    const sibGroupIds = levelOffset === 10 ? this._indexSibGroupIds : this._chunkSibGroupIds;

    // Group items by PBC group. PBC group is derived from the scripthash, so all
    // cuckoo positions for the same query share one PBC group; "not found"
    // verification needs INDEX_CUCKOO_NUM_HASHES bins per query and we must do
    // separate rounds for each, since each round's flat table holds one query
    // per group.
    const itemsByGroup = new Map<number, number[]>();
    for (let i = 0; i < N; i++) {
      const g = items[i].pbcGroup;
      const arr = itemsByGroup.get(g);
      if (arr) arr.push(i);
      else itemsByGroup.set(g, [i]);
    }
    const maxItemsPerGroup = Math.max(1, ...Array.from(itemsByGroup.values(), arr => arr.length));

    // For each sibling level, query via HarmonyPIR batch.
    // Run `maxItemsPerGroup` passes per level so items sharing a group each get
    // their own query; K-padding is preserved within each pass.
    for (let level = 0; level < levelInfos.length; level++) {
      const groupIds = sibGroupIds[level];
      if (!groupIds || groupIds.length === 0) continue;

      for (let pass = 0; pass < maxItemsPerGroup; pass++) {
        const passGroupToItem = new Map<number, number>();
        for (const [g, arr] of itemsByGroup) {
          if (pass < arr.length) passGroupToItem.set(g, arr[pass]);
        }

        const buildItems: BuildItem[] = [];
        for (let g = 0; g < tableK; g++) {
          const globalId = groupIds[g];
          const itemIdx = passGroupToItem.get(g);
          if (itemIdx !== undefined) {
            buildItems.push({ groupId: globalId, binIndex: Math.floor(nodeIdx[itemIdx] / A) });
          } else {
            buildItems.push({ groupId: globalId }); // dummy
          }
        }

        // Build HarmonyPIR requests
        const reqBytesMap = await this.doBuildBatch(buildItems, 'index'); // level doesn't matter for pool

        // Encode and send batch
        const batchItems = buildItems.map((item, g) => ({
          groupId: g, // local group ID for wire protocol
          subQueryBytes: [(reqBytesMap.get(item.groupId)?.bytes) ?? new Uint8Array(0)],
        }));
        const wireLevel = levelOffset + level;
        const reqMsg = this.encodeHarmonyBatchRequest(wireLevel, 0, 1, batchItems);
        const respData = await this.sendQueryRequest(reqMsg);
        const batchResp = this.decodeHarmonyBatchResponse(respData);

        // Process responses
        const processItems: ProcessItem[] = [];
        for (let g = 0; g < tableK; g++) {
          const itemIdx = passGroupToItem.get(g);
          if (itemIdx === undefined) continue;
          const respItem = batchResp.get(g);
          if (respItem && respItem.length > 0) {
            processItems.push({ groupId: groupIds[g], response: respItem[0] });
          }
        }
        const answers = await this.doProcessBatch(processItems, 'index');

        // Update state for items active in THIS pass only
        for (const [g, itemIdx] of passGroupToItem) {
          const globalId = groupIds[g];
          const row = answers.get(globalId);
          if (!row || row.length < SIB_W) {
            this.log(`Merkle L${level}: no sibling row for group ${g}`);
            currentHash[itemIdx] = ZERO_HASH;
            continue;
          }

          const childPos = nodeIdx[itemIdx] % A;
          const children: Uint8Array[] = [];
          for (let c = 0; c < A; c++) {
            if (c === childPos) {
              children.push(currentHash[itemIdx]);
            } else {
              children.push(row.slice(c * 32, (c + 1) * 32));
            }
          }
          currentHash[itemIdx] = computeParentN(children);
          nodeIdx[itemIdx] = Math.floor(nodeIdx[itemIdx] / A);
        }
      }
    }

    // Walk tree-top cache to root for each item
    const verified: boolean[] = new Array(N);
    for (let i = 0; i < N; i++) {
      const g = items[i].pbcGroup;
      const top = treeTops[g];
      if (!top) { verified[i] = false; continue; }

      let hash = currentHash[i];
      let idx = nodeIdx[i];

      for (let cl = 0; cl < top.levels.length - 1; cl++) {
        const levelNodes = top.levels[cl];
        const parentStart = Math.floor(idx / A) * A;
        const childPos = idx % A;
        const children: Uint8Array[] = [];
        for (let c = 0; c < A; c++) {
          const nodeI = parentStart + c;
          if (c === childPos) {
            children.push(hash);
          } else if (nodeI < levelNodes.length) {
            children.push(levelNodes[nodeI]);
          } else {
            children.push(ZERO_HASH);
          }
        }
        hash = computeParentN(children);
        idx = Math.floor(idx / A);
      }

      const expectedRoot = hexToBytes(rootsHex[g]);
      verified[i] = bytesEqual(hash, expectedRoot);
      if (!verified[i]) {
        this.log(`Merkle: group ${g} root mismatch`);
      }
    }

    return verified;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRP hint caching (in-memory + IndexedDB)
  // ═══════════════════════════════════════════════════════════════════════════

  /** Build the fingerprint that ties cached hints to a specific server DB state. */
  private currentFingerprint(): HintFingerprint {
    const fp: HintFingerprint = {
      indexBinsPerTable: this.indexBinsPerTable,
      chunkBinsPerTable: this.chunkBinsPerTable,
      tagSeed: this.tagSeed.toString(),
    };
    const merkle = this.getBucketMerkleForDb(this.dbId);
    if (merkle?.super_root) fp.superRoot = merkle.super_root;
    return fp;
  }

  /** Save current hint state to in-memory cache AND IndexedDB. */
  async saveHintsToCache(): Promise<void> {
    if (!this.pool || !this.hintsLoaded) return;
    const backend = this.config.prpBackend ?? 0;
    const key = this.hintCacheKey(this.dbId, backend);
    const serialized = await this.pool.serializeAll();
    this.hintCache.set(key, {
      prpKey: new Uint8Array(this.prpKey),
      groups: serialized,
      totalHintBytes: this.totalHintBytes,
    });
    this.log(`Cached hints for db=${this.dbId} backend=${backend} (${serialized.size} groups)`);

    // Also persist to IndexedDB so hints survive page reload.
    try {
      const hasSiblings = Array.from(serialized.keys()).some(id => id >= K + K_CHUNK);
      await idbPutHints({
        cacheKey: idbCacheKey(this.config.queryServerUrl, this.dbId, backend),
        serverUrl: this.config.queryServerUrl,
        dbId: this.dbId,
        backend,
        prpKey: new Uint8Array(this.prpKey),
        groups: serialized,
        totalHintBytes: this.totalHintBytes,
        fingerprint: this.currentFingerprint(),
        hasMainHints: this.hintsLoaded,
        hasSiblingHints: this.siblingHintsLoaded && hasSiblings,
        savedAt: Date.now(),
        schemaVersion: HINT_SCHEMA_VERSION,
      });
      this.log(`Persisted hints to IndexedDB (db=${this.dbId} backend=${backend}, siblings=${hasSiblings})`);
    } catch (e) {
      this.log(`IndexedDB persist failed (continuing with in-memory cache): ${(e as Error).message}`);
    }
  }

  /**
   * Restore hints from in-memory cache, falling back to IndexedDB.
   * Returns true on cache hit (from either source). Updates `hintsLoaded`
   * and `siblingHintsLoaded` based on which group families were restored.
   * IndexedDB entries are validated against the current server fingerprint;
   * mismatches are deleted so the caller can cleanly re-download.
   */
  async restoreHintsFromCache(backend: number): Promise<boolean> {
    if (!this.pool) return false;

    // In-memory cache first (cheapest).
    const memKey = this.hintCacheKey(this.dbId, backend);
    const memCached = this.hintCache.get(memKey);
    if (memCached) {
      this.prpKey = new Uint8Array(memCached.prpKey);
      this.totalHintBytes = memCached.totalHintBytes;
      await this.pool.deserializeAll(memCached.groups, this.prpKey);
      this.hintsLoaded = true;
      const hasSiblings = Array.from(memCached.groups.keys()).some(id => id >= K + K_CHUNK);
      if (hasSiblings) this.siblingHintsLoaded = true;
      this.log(`Restored ${memCached.groups.size} groups from memory cache (db=${this.dbId} backend=${backend})`);
      return true;
    }

    // Fall back to IndexedDB.
    const idbKey = idbCacheKey(this.config.queryServerUrl, this.dbId, backend);
    let stored;
    try {
      stored = await idbGetHints(idbKey);
    } catch (e) {
      this.log(`IndexedDB lookup failed: ${(e as Error).message}`);
      return false;
    }
    if (!stored) return false;

    // Validate against current server state.
    const current = this.currentFingerprint();
    if (!fingerprintsEqual(stored.fingerprint, current)) {
      this.log(`Persisted hints stale (server fingerprint changed); deleting entry.`);
      try { await idbDeleteHints(idbKey); } catch { /* best-effort */ }
      return false;
    }

    // Deserialize into workers.
    try {
      await this.pool.deserializeAll(stored.groups, stored.prpKey);
    } catch (e) {
      this.log(`Persisted hint deserialize failed (${(e as Error).message}); deleting entry.`);
      try { await idbDeleteHints(idbKey); } catch { /* best-effort */ }
      return false;
    }

    this.prpKey = new Uint8Array(stored.prpKey);
    this.totalHintBytes = stored.totalHintBytes;
    this.hintsLoaded = stored.hasMainHints;
    if (stored.hasSiblingHints) {
      // Reconstruct sibling group-ID tables from current server merkle info so
      // verifyMerkleBatch() knows which groups to query.
      const merkle = this.getBucketMerkleForDb(this.dbId);
      if (merkle) this.rebuildSiblingGroupIds(merkle);
      this.siblingHintsLoaded = true;
    }
    // Populate in-memory cache from the IDB hit so subsequent saves round-trip.
    this.hintCache.set(memKey, {
      prpKey: new Uint8Array(stored.prpKey),
      groups: stored.groups,
      totalHintBytes: stored.totalHintBytes,
    });

    const ageHrs = ((Date.now() - stored.savedAt) / 3600000).toFixed(1);
    this.log(
      `Restored ${stored.groups.size} groups from IndexedDB ` +
      `(db=${this.dbId} backend=${backend}, age=${ageHrs}h, siblings=${stored.hasSiblingHints})`
    );
    return true;
  }

  /**
   * Recompute the global group IDs used for each INDEX/CHUNK sibling level.
   * This mirrors the allocation logic in initAndFetchSiblingHints() so
   * verifyMerkleBatch() can locate restored sibling groups in the pool.
   */
  private rebuildSiblingGroupIds(
    merkle: import('./server-info.js').BucketMerkleInfoJson,
  ): void {
    let nextGroupId = K + K_CHUNK;
    const indexSib: number[][] = [];
    for (let level = 0; level < merkle.index_levels.length; level++) {
      const ids: number[] = [];
      for (let g = 0; g < K; g++) ids.push(nextGroupId + g);
      indexSib.push(ids);
      nextGroupId += K;
    }
    const chunkSib: number[][] = [];
    for (let level = 0; level < merkle.chunk_levels.length; level++) {
      const ids: number[] = [];
      for (let g = 0; g < K_CHUNK; g++) ids.push(nextGroupId + g);
      chunkSib.push(ids);
      nextGroupId += K_CHUNK;
    }
    this._indexSibGroupIds = indexSib;
    this._chunkSibGroupIds = chunkSib;
  }

  /** Check if cached hints exist in memory for the active dbId + given PRP backend. */
  hasCachedHints(backend: number): boolean {
    return this.hintCache.has(this.hintCacheKey(this.dbId, backend));
  }

  /**
   * Check if persisted hints exist in IndexedDB for the current server +
   * active dbId + given PRP backend. Async; validates fingerprint match.
   */
  async hasPersistedHints(backend: number): Promise<boolean> {
    try {
      const stored = await idbGetHints(
        idbCacheKey(this.config.queryServerUrl, this.dbId, backend)
      );
      if (!stored) return false;
      return fingerprintsEqual(stored.fingerprint, this.currentFingerprint());
    } catch {
      return false;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Hint exhaustion detection
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get the minimum queries remaining across all groups. */
  async getMinQueriesRemaining(): Promise<number> {
    if (this.pool) {
      return this.pool.getMinQueriesRemaining();
    }
    // Single-threaded fallback.
    let min = Infinity;
    for (const [_, b] of this.indexGroups) min = Math.min(min, b.queries_remaining());
    for (const [_, b] of this.chunkGroups) min = Math.min(min, b.queries_remaining());
    return min;
  }

  /** Re-initialize groups and re-download hints (resets query budget). */
  async refreshHints(): Promise<void> {
    this.log('Refreshing hints (re-running offline phase)...');
    await this.initGroups();
    await this.fetchHints();
  }
}

/** Factory function to create a HarmonyPIR client. */
export function createHarmonyPirClient(config: HarmonyPirClientConfig): HarmonyPirClient {
  return new HarmonyPirClient(config);
}

// ─── Bucket Merkle helpers ──────────────────────────────────────────────────

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Parse the per-bucket tree-top cache blob. */
function parseBucketTreeTops(data: Uint8Array): Array<{ cacheFromLevel: number; levels: Uint8Array[][] }> {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const numTrees = dv.getUint32(0, true);
  let off = 4;
  const tops: Array<{ cacheFromLevel: number; levels: Uint8Array[][] }> = [];
  for (let t = 0; t < numTrees; t++) {
    const cacheFromLevel = data[off]; off += 1;
    off += 4; // totalNodes
    off += 2; // arity
    const numCachedLevels = data[off]; off += 1;
    const levels: Uint8Array[][] = [];
    for (let l = 0; l < numCachedLevels; l++) {
      const numNodes = dv.getUint32(off, true); off += 4;
      const nodes: Uint8Array[] = [];
      for (let n = 0; n < numNodes; n++) {
        nodes.push(data.slice(off, off + 32));
        off += 32;
      }
      levels.push(nodes);
    }
    tops.push({ cacheFromLevel, levels });
  }
  return tops;
}
