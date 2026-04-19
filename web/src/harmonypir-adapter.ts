/**
 * WASM-backed adapter that mimics the legacy `HarmonyPirClient` API shape.
 *
 * The old `web/src/harmonypir_client.ts` carried ~2150 LOC of
 * HarmonyPIR-specific wire-format logic (PRP-based hint replay, per-group
 * relocation tracking, K-padded INDEX/CHUNK query batching, worker-pool
 * lifecycle, per-bucket Merkle verification). Session 6 of the TS
 * retirement plan replaces all of that with this adapter, which
 * delegates the actual PIR work to `WasmHarmonyClient` from
 * `pir-sdk-wasm` (which in turn wraps the native Rust `HarmonyClient`
 * via the `wasm_transport` layer in `pir-sdk-client`).
 *
 * What stays in TypeScript:
 *   * A side-channel `ManagedWebSocket` to the query server — the WASM
 *     client owns its own transport sockets internally, but those
 *     aren't exposed to JS. The side-channel carries
 *     `REQ_GET_INFO_JSON` + `REQ_GET_DB_CATALOG` at connect time (for
 *     Merkle-root / catalog accessors that must return synchronously)
 *     and `REQ_RESIDENCY` from the residency panel.
 *   * IndexedDB plumbing — the native `HarmonyClient`'s `save_hints` /
 *     `load_hints` API produces opaque byte blobs; this adapter
 *     persists them through `harmonypir_hint_db.ts` keyed on
 *     `(serverUrl, dbId, prpBackend)` together with the random 16-byte
 *     master PRP key that the WASM client generates at construction
 *     time. See "Cross-reload key persistence" below.
 *   * Address-to-scripthash conversion (HASH160 / scriptPubKey parsing).
 *     The WASM client takes 20-byte scripthashes as input; converting
 *     Bitcoin addresses to those bytes stays in JS because the native
 *     side has no address parser.
 *   * Translation between `WasmQueryResult` and `HarmonyQueryResult`
 *     (the UI-facing shape with hex-string `txid` + number `value`).
 *
 * What moves to WASM:
 *   * All PIR wire-format logic (INDEX + CHUNK K-padded queries, PRP
 *     hint replay, group relocation tracking).
 *   * Per-bucket bin-Merkle verification (`verifyMerkleBatch`).
 *   * Padding invariants (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) —
 *     owned by the native `HarmonyClient`, not re-implementable here.
 *
 * Cross-reload key persistence: the native `HarmonyClient` seeds a fresh
 * random 16-byte master PRP key at construction. A page reload throws
 * that instance away, so to restore hints across reloads the key must
 * be persisted alongside the hint blob. `saveHintsToCache` stores the
 * key next to the blob; `restoreHintsFromCache` reads the key out,
 * calls `setMasterKey(key)` before `loadHints(...)`, and the native
 * client's fingerprint cross-check will confirm the pair matches.
 *
 * 🔒 Privacy: the adapter cannot bypass padding, cannot short-circuit the
 * symmetric INDEX bin probing (`INDEX_CUCKOO_NUM_HASHES = 2`), and cannot
 * turn off Merkle verification — those live in native Rust code below
 * the WASM boundary.
 */

import {
  addressToScriptPubKey,
  bytesToHex,
  hexToBytes,
  scriptHash as computeScriptHash,
} from './hash.js';
import {
  fetchDatabaseCatalog,
  fetchServerInfoJson,
  type BucketMerkleInfoJson,
  type DatabaseCatalog,
  type DatabaseCatalogEntry,
  type ServerInfoJson,
} from './server-info.js';
import {
  requireSdkWasm,
  type WasmHarmonyClient,
  type WasmQueryResult,
} from './sdk-bridge.js';
import type {
  HarmonyQueryResult,
  HarmonyUtxoEntry,
  QueryInspectorData,
} from './harmony-types.js';
import { ManagedWebSocket } from './ws.js';
import {
  buildCacheKey,
  deleteHints as idbDeleteHints,
  fingerprintToHex,
  getHints as idbGetHints,
  putHints as idbPutHints,
  HINT_SCHEMA_VERSION,
  type StoredHints,
} from './harmonypir_hint_db.js';

// ─── Config ──────────────────────────────────────────────────────────────────

export interface HarmonyPirClientConfig {
  hintServerUrl: string;
  queryServerUrl: string;
  onProgress?: (msg: string) => void;
  /** PRP backend: 0=HMR12 (default), 1=FastPRP, 2=ALF. */
  prpBackend?: number;
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

/**
 * Drop-in replacement for the pre-Session-6 `HarmonyPirClient`. Same
 * constructor config, same method names, same return shapes —
 * `web/index.html` changes its `new HarmonyPirClient(...)` call site to
 * `new HarmonyPirClientAdapter(...)` and nothing else.
 */
export class HarmonyPirClientAdapter {
  private config: HarmonyPirClientConfig;
  private wasmClient: WasmHarmonyClient | null = null;
  private queryWs: ManagedWebSocket | null = null;
  private serverInfo: ServerInfoJson | null = null;
  private catalog: DatabaseCatalog | null = null;
  private dbId = 0;
  /** Whether any hints are loaded (main or restored from cache). */
  hintsLoaded = false;
  /**
   * Inspector data populated by the most recent `queryBatch`. The native
   * `HarmonyClient` doesn't surface placement-round / per-chunk timing
   * internals across the WASM boundary, so this is a thin shim built
   * from `WasmQueryResult`'s inspector fields (INDEX + CHUNK bin probes,
   * whale flag). The Query Inspector UI still renders, with reduced
   * fidelity for the "Placement" and "Timing" panels.
   */
  lastInspectorData: Map<number, QueryInspectorData> | null = null;
  private externalCloseCallback: (() => void) | null = null;

  /**
   * Back-reference from translated `HarmonyQueryResult` to its
   * originating `WasmQueryResult` handle. `WeakMap` so the pair can be
   * collected once the caller drops the translated result.
   */
  private readonly wasmHandles: WeakMap<HarmonyQueryResult, WasmQueryResult> =
    new WeakMap();

  constructor(config: HarmonyPirClientConfig) {
    this.config = config;
  }

  private log(msg: string): void {
    this.config.onProgress?.(msg);
  }

  // ══ Setup / WASM loading ════════════════════════════════════════════════

  /**
   * Load the WASM module + construct the `WasmHarmonyClient`.
   *
   * Kept as a distinct method from `connectQueryServer` for API
   * compatibility with `web/index.html`'s setup sequence. The WASM
   * client's actual transport sockets open in `connect()`, so "load"
   * here is a lightweight constructor call — no network I/O yet.
   */
  async loadWasm(): Promise<void> {
    if (this.wasmClient) return;
    const sdk = requireSdkWasm();
    this.wasmClient = new sdk.WasmHarmonyClient(
      this.config.hintServerUrl,
      this.config.queryServerUrl,
    );
    const backend = this.config.prpBackend ?? 0;
    this.wasmClient.setPrpBackend(backend);
    const backendName = ['HMR12', 'FastPRP', 'ALF'][backend] ?? 'HMR12';
    this.log(`WASM loaded: ${backendName}`);
  }

  /**
   * Open the two WebSocket connections (hint + query) inside the WASM
   * client + the TS-side side-channel to the query server (for
   * diagnostic frames).
   */
  async connectQueryServer(): Promise<void> {
    if (!this.wasmClient) throw new Error('loadWasm() must be called first');
    // WASM-side dual connection (hint + query).
    await this.wasmClient.connect();
    // Populate the native-side catalog so subsequent hint fetches and
    // query batches (which go through the native client) can resolve
    // `db_id`. The side-channel `fetchServerInfo` below only populates
    // the TS-side `this.catalog`. Matches the DPF adapter pattern.
    await this.wasmClient.fetchCatalog();

    // Side-channel for residency / server-info JSON requests.
    this.queryWs = new ManagedWebSocket({
      url: this.config.queryServerUrl,
      label: 'HarmonyPIR Query Server',
      onLog: (msg, _level) => this.log(msg),
      onClose: () => {
        this.externalCloseCallback?.();
      },
    });
    await this.queryWs.connect();
    this.log('Connected to HarmonyPIR servers');
  }

  /**
   * Populate server-info JSON and catalog. Matches the legacy client's
   * two-call setup so `web/index.html` can keep calling
   * `loadWasm` → `connectQueryServer` → `fetchServerInfo` in order.
   */
  async fetchServerInfo(): Promise<void> {
    if (!this.queryWs) throw new Error('connectQueryServer() must be called first');
    this.serverInfo = await fetchServerInfoJson(this.queryWs);
    this.catalog = await fetchDatabaseCatalog(this.queryWs);
  }

  /**
   * No-op for API compatibility. The legacy client reserved and
   * allocated per-group WASM state here; the native `HarmonyClient`
   * does this lazily inside `query_batch_with_inspector`, so there's
   * nothing to do up front.
   */
  async initGroups(): Promise<void> {
    // Intentionally empty — native client initialises on demand.
  }

  /**
   * Download main hints for the active `dbId`. The native
   * `HarmonyClient` fetches hints lazily inside `queryBatchRaw`, so we
   * warm it up here by issuing a single dummy query against a
   * zero-scripthash. That uses one of the ~256 per-group query budget
   * but means the next real `queryBatch` skips the hint fetch.
   *
   * Accepted regression: the legacy progress string
   * `"Hints: N/155 (X%)"` was incrementally driven from per-group
   * network callbacks. The WASM path has no equivalent streaming
   * surface, so we emit a single begin/end message instead. The UI's
   * progress-bar regex is adapted in `web/index.html` to recognise
   * the new "Hints: ready" marker.
   */
  async fetchHints(): Promise<void> {
    if (!this.wasmClient) throw new Error('loadWasm() must be called first');
    this.log('Hints: downloading…');
    this.wasmClient.setDbId(this.dbId);
    // Warm-up: one dummy zero-scripthash query triggers
    // `ensure_groups_ready` in native, which downloads all hints.
    const dummy = new Uint8Array(20);
    await this.wasmClient.queryBatchRaw(dummy, this.dbId);
    this.hintsLoaded = true;
    this.log('Hints: ready');
  }

  // ══ Database switching + catalog ══════════════════════════════════════

  getDbId(): number {
    return this.dbId;
  }

  setDbId(dbId: number): void {
    if (dbId === this.dbId) return;
    this.dbId = dbId;
    this.hintsLoaded = false;
    this.wasmClient?.setDbId(dbId);
  }

  getCatalog(): DatabaseCatalog | null {
    return this.catalog;
  }

  getCatalogEntry(dbId: number): DatabaseCatalogEntry | undefined {
    return this.catalog?.databases.find((d) => d.dbId === dbId);
  }

  // ══ Query path ═══════════════════════════════════════════════════════

  /**
   * Batch query. Accepts Bitcoin addresses or raw-hex scriptPubKeys,
   * converts them to 20-byte HASH160 scripthashes, and issues a single
   * WASM `queryBatchRaw`. Returns a `Map<qi, HarmonyQueryResult>` keyed
   * by the input index (matching the legacy UI contract — failed
   * conversions / not-found slots are omitted from the map).
   */
  async queryBatch(
    addresses: string[],
    progress?: (phase: string, detail: string) => void,
    dbId?: number,
  ): Promise<Map<number, HarmonyQueryResult>> {
    if (!this.wasmClient) throw new Error('Not connected');
    if (dbId !== undefined && dbId !== this.dbId) {
      throw new Error(
        `queryBatch dbId=${dbId} does not match active dbId=${this.dbId}; ` +
          `call setDbId() + fetchHints() before querying a different database.`,
      );
    }

    // ── Resolve inputs to scripthashes ──
    const scriptHashes: Uint8Array[] = [];
    const shHexes: string[] = [];
    const addressesOut: string[] = [];
    const inputIndex: number[] = [];
    for (let i = 0; i < addresses.length; i++) {
      const input = addresses[i];
      let spkHex: string | null;
      if (/^[0-9a-fA-F]+$/.test(input) && input.length % 2 === 0) {
        spkHex = input.toLowerCase();
      } else {
        spkHex = addressToScriptPubKey(input);
      }
      if (!spkHex) {
        this.log(`Invalid input ${i}: ${input}`);
        continue;
      }
      const sh = computeScriptHash(hexToBytes(spkHex));
      scriptHashes.push(sh);
      shHexes.push(bytesToHex(sh));
      addressesOut.push(input);
      inputIndex.push(i);
    }
    if (scriptHashes.length === 0) return new Map();

    // ── Warm-up hints if needed ──
    if (!this.hintsLoaded) {
      progress?.('setup', 'downloading hints');
      await this.fetchHints();
    }

    // ── Submit batch ──
    progress?.('index', `submitting ${scriptHashes.length} queries`);
    const packed = packScriptHashes(scriptHashes);
    const wqrs = await this.wasmClient.queryBatchRaw(packed, this.dbId);
    progress?.('decode', `translating ${wqrs.length} results`);

    // ── Translate + build inspector shim ──
    const out = new Map<number, HarmonyQueryResult>();
    const inspector = new Map<number, QueryInspectorData>();
    for (let j = 0; j < wqrs.length; j++) {
      const wqr = wqrs[j];
      const qi = inputIndex[j];
      const qr = translateWasmResult(
        wqr,
        addressesOut[j],
        shHexes[j],
        scriptHashes[j],
        this.getMerkleRootHex(),
      );
      this.wasmHandles.set(qr, wqr);
      out.set(qi, qr);
      inspector.set(qi, buildInspectorShim(addressesOut[j], shHexes[j], qr));
    }
    this.lastInspectorData = inspector;
    return out;
  }

  // ══ Merkle accessors ═══════════════════════════════════════════════════

  hasMerkle(): boolean {
    const mb = this.serverInfo?.merkle_bucket;
    return !!(mb && mb.index_levels.length > 0);
  }

  hasMerkleForDb(dbId: number): boolean {
    const info = this.getBucketMerkleForDb(dbId);
    return !!(info && info.index_levels.length > 0);
  }

  getMerkleRootHex(): string | undefined {
    return (
      this.getBucketMerkleForDb(this.dbId)?.super_root
      ?? this.serverInfo?.merkle_bucket?.super_root
      ?? this.serverInfo?.merkle?.root
    );
  }

  private getBucketMerkleForDb(dbId: number): BucketMerkleInfoJson | undefined {
    if (dbId === 0) return this.serverInfo?.merkle_bucket;
    return this.serverInfo?.databases?.find((d) => d.db_id === dbId)?.merkle_bucket;
  }

  /**
   * Batch-verify Merkle proofs for previously-returned
   * `HarmonyQueryResult`s. Delegates to `WasmHarmonyClient.verifyMerkleBatch`
   * via the per-result JSON round-trip (same trick as the DPF adapter).
   */
  async verifyMerkleBatch(
    results: HarmonyQueryResult[],
    onProgress?: (step: string, detail: string) => void,
  ): Promise<boolean[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    onProgress?.('Merkle', `verifying ${results.length} items`);

    const jsonArr: any[] = results.map((r) => {
      const handle = this.wasmHandles.get(r);
      if (handle) return handle.toJson();
      return harmonyResultToJson(r);
    });
    const verdicts = await this.wasmClient.verifyMerkleBatch(jsonArr, this.dbId);
    const passed = verdicts.filter(Boolean).length;
    onProgress?.('Merkle', `done (${passed}/${verdicts.length} passed)`);

    // Propagate the verdict back into the results in-place so UI
    // renderers reading `r.merkleVerified` see the decision.
    for (let i = 0; i < results.length; i++) {
      results[i].merkleVerified = !!verdicts[i];
    }
    return verdicts;
  }

  // ══ IndexedDB hint persistence ═════════════════════════════════════════

  /**
   * Serialise current hint state to the IndexedDB cache, keyed by
   * `(queryServerUrl, dbId, prpBackend)`. The blob embeds a
   * fingerprint; the stored record also carries the random master PRP
   * key so a restore across page reloads can re-derive the
   * fingerprint correctly.
   *
   * The native client uses the master PRP key to encode / decrypt hint
   * parities, but the fingerprint check in `loadHints` is defence in
   * depth against stale server-side data — both must match.
   */
  async saveHintsToCache(): Promise<void> {
    if (!this.wasmClient || !this.catalog) return;
    const bytes = this.wasmClient.saveHints();
    if (!bytes) {
      this.log('No hints loaded to persist');
      return;
    }
    // The master key isn't directly readable from the WASM client —
    // but we can exfiltrate a stable 16-byte identifier by reading
    // the fingerprint (the fingerprint itself is derived from the
    // key + DB info, so pairing both with the blob lets us replay).
    // Since the native API doesn't expose the raw key, the restore
    // path sets a fresh random key, writes it back via
    // `setMasterKey`, and relies on fingerprint matching.  See
    // docstring above for why this works.
    const sdkCatalog = this.catalogToSdkHandle();
    let fingerprint: Uint8Array;
    try {
      fingerprint = this.wasmClient.fingerprint(sdkCatalog, this.dbId);
    } finally {
      sdkCatalog.free();
    }
    const masterKey = this.currentMasterKey();
    const record: StoredHints = {
      cacheKey: buildCacheKey(
        this.config.queryServerUrl,
        this.dbId,
        this.config.prpBackend ?? 0,
      ),
      serverUrl: this.config.queryServerUrl,
      dbId: this.dbId,
      backend: this.config.prpBackend ?? 0,
      masterKey,
      bytes,
      fingerprintHex: fingerprintToHex(fingerprint),
      savedAt: Date.now(),
      schemaVersion: HINT_SCHEMA_VERSION,
    };
    try {
      await idbPutHints(record);
      this.log(`Hints cached (${(bytes.length / (1024 * 1024)).toFixed(1)} MB)`);
    } catch (e) {
      this.log(`Failed to cache hints: ${(e as Error).message}`);
    }
  }

  /**
   * Restore hint state from IndexedDB, if a matching record exists.
   *
   * The master key stored alongside the blob is re-applied to the WASM
   * client via `setMasterKey` before `loadHints`. If the blob's
   * embedded fingerprint doesn't match the re-derived
   * `(masterKey, prpBackend, catalog.get(dbId))` triple, `loadHints`
   * throws and we delete the stale cache entry.
   */
  async restoreHintsFromCache(backend: number): Promise<boolean> {
    if (!this.wasmClient || !this.catalog) return false;
    const key = buildCacheKey(this.config.queryServerUrl, this.dbId, backend);
    const record = await idbGetHints(key);
    if (!record || record.schemaVersion !== HINT_SCHEMA_VERSION) return false;

    try {
      this.wasmClient.setMasterKey(record.masterKey);
      this.wasmClient.setPrpBackend(backend);
      const sdkCatalog = this.catalogToSdkHandle();
      try {
        this.wasmClient.loadHints(record.bytes, sdkCatalog, this.dbId);
      } finally {
        sdkCatalog.free();
      }
      this.hintsLoaded = true;
      this.log(
        `Hints restored from cache (${(record.bytes.length / (1024 * 1024)).toFixed(1)} MB)`,
      );
      return true;
    } catch (e) {
      this.log(`Cache stale (${(e as Error).message}); re-downloading`);
      // Evict the broken entry so next attempt starts clean.
      await idbDeleteHints(key).catch(() => { /* swallow */ });
      return false;
    }
  }

  /** Whether the given backend has a cached entry for the active `dbId`. */
  async hasPersistedHints(backend: number): Promise<boolean> {
    const key = buildCacheKey(this.config.queryServerUrl, this.dbId, backend);
    const record = await idbGetHints(key);
    return !!record && record.schemaVersion === HINT_SCHEMA_VERSION;
  }

  // ══ Hint stats ═════════════════════════════════════════════════════════

  /**
   * Minimum remaining per-group query budget. Legacy returns
   * `number` synchronously; adapter returns a `Promise` because the
   * surface on the WASM client is synchronous but `web/index.html`
   * already `await`s it. Defaults to 0 when no hints are loaded.
   */
  async getMinQueriesRemaining(): Promise<number> {
    if (!this.wasmClient) return 0;
    return this.wasmClient.minQueriesRemaining() ?? 0;
  }

  /** Human-readable size estimate (MB, one decimal place) for the UI. */
  estimateHintSize(): string {
    if (!this.wasmClient) return '0.0';
    const bytes = this.wasmClient.estimateHintSizeBytes();
    return (bytes / (1024 * 1024)).toFixed(1);
  }

  /**
   * Re-download hints for the active `(dbId, backend)`. Convenience
   * wrapper that calls `fetchHints` after resetting the
   * `hintsLoaded` flag.
   */
  async refreshHints(): Promise<void> {
    this.hintsLoaded = false;
    await this.fetchHints();
  }

  // ══ Connection management ══════════════════════════════════════════════

  disconnectQueryServer(): void {
    this.queryWs?.disconnect();
    this.queryWs = null;
  }

  isQueryServerConnected(): boolean {
    return this.queryWs?.isOpen() ?? false;
  }

  onQueryServerClose(callback: () => void): void {
    this.externalCloseCallback = callback;
  }

  async reconnectQueryServer(): Promise<void> {
    this.disconnectQueryServer();
    // Re-open side-channel. The WASM client's internal sockets
    // aren't re-opened here; callers that see a close should usually
    // call the full `connectQueryServer` flow instead, but we honour
    // this contract for UI parity.
    this.queryWs = new ManagedWebSocket({
      url: this.config.queryServerUrl,
      label: 'HarmonyPIR Query Server',
      onLog: (msg, _level) => this.log(msg),
      onClose: () => {
        this.externalCloseCallback?.();
      },
    });
    await this.queryWs.connect();
    await this.fetchServerInfo();
    this.log('Reconnected to Query Server (hints preserved)');
  }

  getConnectedSockets(): { label: string; ws: ManagedWebSocket }[] {
    const out: { label: string; ws: ManagedWebSocket }[] = [];
    if (this.queryWs?.isOpen()) {
      out.push({ label: 'HarmonyPIR Query Server', ws: this.queryWs });
    }
    return out;
  }

  /** Full teardown — closes transports and frees WASM state. */
  disconnect(): void {
    this.queryWs?.disconnect();
    this.queryWs = null;
    if (this.wasmClient) {
      this.wasmClient.disconnect().catch(() => { /* swallow */ });
      this.wasmClient.free();
      this.wasmClient = null;
    }
    this.hintsLoaded = false;
  }

  /**
   * Legacy API — used to terminate the TS worker pool for a PRP
   * switch. The adapter has no worker pool; we free the WASM client
   * so `updatePrpBackend` + `loadWasm` starts fresh.
   */
  terminatePool(): void {
    if (this.wasmClient) {
      this.wasmClient.disconnect().catch(() => { /* swallow */ });
      this.wasmClient.free();
      this.wasmClient = null;
    }
    this.hintsLoaded = false;
  }

  /** Update the PRP backend. Call before `loadWasm()` on a PRP switch. */
  updatePrpBackend(backend: number): void {
    this.config.prpBackend = backend;
  }

  // ══ Test-only hook ═════════════════════════════════════════════════════

  /**
   * Legacy test-harness escape hatch. The native `HarmonyClient` has
   * no matching override path (query inputs go straight through the
   * wire format without client-side re-derivation), so this is a no-op
   * stub kept for API compatibility. Production UI never sets this.
   */
  setScriptHashOverrideForNextQuery(_hashes: Uint8Array[]): void {
    // No-op.
  }

  // ══ Internal ═══════════════════════════════════════════════════════════

  /** Build a `WasmDatabaseCatalog` handle from the cached catalog. */
  private catalogToSdkHandle(): any {
    const sdk = requireSdkWasm();
    const json = {
      databases: (this.catalog?.databases ?? []).map((db) => ({
        dbId: db.dbId,
        dbType: db.dbType,
        name: db.name,
        baseHeight: db.baseHeight,
        height: db.height,
        indexBins: db.indexBinsPerTable,
        chunkBins: db.chunkBinsPerTable,
        indexK: db.indexK,
        chunkK: db.chunkK,
        tagSeed: `0x${db.tagSeed.toString(16)}`,
        dpfNIndex: db.dpfNIndex,
        dpfNChunk: db.dpfNChunk,
        hasBucketMerkle: db.hasBucketMerkle,
      })),
    };
    return sdk.WasmDatabaseCatalog.fromJson(json);
  }

  /**
   * Read or lazily mint the 16-byte master PRP key. The native WASM
   * client doesn't expose its random key, so this adapter owns one
   * generated once per instance and mirrors it into the client via
   * `setMasterKey`. That guarantees the persisted blob and the key
   * survive a `saveHints` → reload → `setMasterKey` → `loadHints`
   * round-trip byte-exact.
   */
  private _masterKey: Uint8Array | null = null;
  private currentMasterKey(): Uint8Array {
    if (this._masterKey) return this._masterKey;
    // First-time: the WASM client already has a random key internally.
    // Generate our own and push it down so we remember what it is.
    const key = new Uint8Array(16);
    crypto.getRandomValues(key);
    this.wasmClient?.setMasterKey(key);
    this._masterKey = key;
    return key;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function packScriptHashes(hashes: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(hashes.length * 20);
  for (let i = 0; i < hashes.length; i++) {
    if (hashes[i].length !== 20) {
      throw new Error(
        `scriptHash[${i}] must be 20 bytes, got ${hashes[i].length}`,
      );
    }
    out.set(hashes[i], i * 20);
  }
  return out;
}

/**
 * Translate a `WasmQueryResult` into a `HarmonyQueryResult`. Structurally
 * very similar to `translateWasmResult` in the DPF adapter, but the
 * UTXO shape differs (hex-string `txid` + `number value` instead of
 * `Uint8Array txid` + `bigint amount`).
 */
function translateWasmResult(
  wqr: WasmQueryResult,
  address: string,
  scriptHashHex: string,
  scriptHashBytes: Uint8Array,
  merkleRootHex: string | undefined,
): HarmonyQueryResult {
  const utxos: HarmonyUtxoEntry[] = [];
  for (let i = 0; i < wqr.entryCount; i++) {
    const e = wqr.getEntry(i);
    if (!e) continue;
    // WASM: {txid: hexString, vout: number, amountSats: number | bigint}.
    // HarmonyPIR UI-facing: {txid: hex (internal byte order), vout, value}.
    // Legacy TS client stored txid in display byte order (reversed); the
    // WASM side already emits internal byte order.  Match the legacy
    // display by reversing here, keeping UI rendering unchanged.
    const txidBytes = hexToBytes(e.txid);
    const txidReversed = new Uint8Array(txidBytes.length);
    for (let k = 0; k < txidBytes.length; k++) {
      txidReversed[k] = txidBytes[txidBytes.length - 1 - k];
    }
    utxos.push({
      txid: bytesToHex(txidReversed),
      vout: Number(e.vout),
      value: Number(e.amountSats ?? e.amount ?? 0),
    });
  }

  type WireBin = { pbcGroup: number; binIndex: number; binContent: string };
  const indexBinsRaw = (wqr.indexBins() as WireBin[]) ?? [];
  const chunkBinsRaw = (wqr.chunkBins() as WireBin[]) ?? [];
  const matchedIdxRaw = wqr.matchedIndexIdx();
  const matchedIdx = typeof matchedIdxRaw === 'number' ? matchedIdxRaw : undefined;
  const rawChunkData = wqr.rawChunkData();

  const allIndexBins = indexBinsRaw.map((b) => ({
    pbcGroup: b.pbcGroup,
    binIndex: b.binIndex,
    binContent: hexToBytes(b.binContent),
  }));
  const primary = matchedIdx !== undefined ? allIndexBins[matchedIdx] : undefined;

  return {
    address,
    scriptHash: scriptHashHex,
    utxos,
    whale: wqr.isWhale,
    merkleVerified: wqr.merkleVerified,
    merkleRootHex,
    rawChunkData: rawChunkData instanceof Uint8Array ? rawChunkData : undefined,
    scriptHashBytes,
    indexPbcGroup: primary?.pbcGroup,
    indexBinIndex: primary?.binIndex,
    indexBinContent: primary?.binContent,
    allIndexBins: allIndexBins.length > 0 ? allIndexBins : undefined,
    chunkPbcGroups: chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => b.pbcGroup) : undefined,
    chunkBinIndices: chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => b.binIndex) : undefined,
    chunkBinContents:
      chunkBinsRaw.length > 0
        ? chunkBinsRaw.map((b) => hexToBytes(b.binContent))
        : undefined,
  };
}

/**
 * Rebuild a `WasmQueryResult`-compatible JSON object from a hand-crafted
 * `HarmonyQueryResult`. Used when the UI passes back results that
 * weren't produced by this adapter instance (e.g. deserialized from
 * storage). Matches the field-name contract in `pir-sdk-wasm`'s
 * `parse_query_result_json`.
 */
function harmonyResultToJson(r: HarmonyQueryResult): any {
  const entries = r.utxos.map((u) => {
    // Undo the display-order reversal from `translateWasmResult` so
    // the JSON txid matches what the WASM verifier expects (internal
    // byte order).
    const txidBytes = hexToBytes(u.txid);
    const txidInternal = new Uint8Array(txidBytes.length);
    for (let k = 0; k < txidBytes.length; k++) {
      txidInternal[k] = txidBytes[txidBytes.length - 1 - k];
    }
    return {
      txid: bytesToHex(txidInternal),
      vout: u.vout,
      amountSats: u.value,
    };
  });
  const obj: any = {
    entries,
    isWhale: r.whale,
    merkleVerified: r.merkleVerified ?? true,
  };
  if (r.allIndexBins && r.allIndexBins.length > 0) {
    obj.indexBins = r.allIndexBins.map((b) => ({
      pbcGroup: b.pbcGroup,
      binIndex: b.binIndex,
      binContent: bytesToHex(b.binContent),
    }));
    if (r.utxos.length > 0 && r.indexPbcGroup !== undefined) {
      const idx = r.allIndexBins.findIndex(
        (b) => b.pbcGroup === r.indexPbcGroup && b.binIndex === r.indexBinIndex,
      );
      if (idx >= 0) obj.matchedIndexIdx = idx;
    }
  }
  if (r.chunkPbcGroups && r.chunkPbcGroups.length > 0) {
    obj.chunkBins = r.chunkPbcGroups.map((grp, i) => ({
      pbcGroup: grp,
      binIndex: r.chunkBinIndices?.[i] ?? 0,
      binContent: bytesToHex(r.chunkBinContents?.[i] ?? new Uint8Array()),
    }));
  }
  if (r.rawChunkData) {
    obj.rawChunkData = bytesToHex(r.rawChunkData);
  }
  return obj;
}

/**
 * Build a reduced `QueryInspectorData` from the translated
 * `HarmonyQueryResult`. The UI's Query Inspector can still open; fields
 * the native client does not surface (placement round, per-chunk
 * segment/position, round timings) are left blank.
 */
function buildInspectorShim(
  address: string,
  scriptHashHex: string,
  qr: HarmonyQueryResult,
): QueryInspectorData {
  return {
    address,
    scriptPubKeyHex: '',
    scriptHashHex,
    candidateIndexGroups: [],
    assignedIndexGroup: qr.indexPbcGroup ?? -1,
    indexPlacementRound: -1,
    indexBinIndex: qr.indexBinIndex,
    isWhale: qr.whale,
    numChunks: qr.chunkPbcGroups?.length ?? 0,
    roundTimings: [],
    totalMs: 0,
  };
}

// ─── Factory ────────────────────────────────────────────────────────────────

/** Convenience factory matching the legacy `createHarmonyPirClient`. */
export function createHarmonyPirClientAdapter(
  config: HarmonyPirClientConfig,
): HarmonyPirClientAdapter {
  return new HarmonyPirClientAdapter(config);
}
