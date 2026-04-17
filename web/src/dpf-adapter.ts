/**
 * WASM-backed adapter that mimics the legacy `BatchPirClient` API shape.
 *
 * The old `web/src/client.ts` carried ~800 LOC of PIR wire-format logic
 * (encoding batched DPF queries, decoding responses, per-bucket Merkle
 * verification). Session 3 of the TS retirement plan replaced that with
 * this adapter, which delegates the actual PIR work to `WasmDpfClient`
 * from `pir-sdk-wasm` (which in turn wraps the native Rust `DpfClient`
 * via the `wasm_transport` layer in `pir-sdk-client`).
 *
 * What stays in TypeScript:
 *   * A pair of side-channel `ManagedWebSocket`s — the WASM client owns
 *     its own transport sockets internally, but those aren't exposed to
 *     the browser. The side-channel sockets are used for:
 *       - `REQ_GET_INFO_JSON` at connect time (to populate
 *         `serverInfo` so `hasMerkle` / `getMerkleRootHex` can answer
 *         synchronously without a roundtrip)
 *       - `REQ_GET_DB_CATALOG` at connect time (for the catalog
 *         accessors and the UI DB selector)
 *       - `REQ_RESIDENCY` via the residency panel in `web/index.html`
 *         (which iterates `getConnectedSockets()` across all backends
 *         and calls `fetchResidency(ws)`).
 *   * Translation between `WasmQueryResult` (the WASM-side opaque
 *     handle) and the legacy `QueryResult` shape consumed by the UI
 *     renderers + `sync-merge.ts`.
 *
 * What moves to WASM:
 *   * All PIR wire-format logic (INDEX + CHUNK batched queries).
 *   * Per-bucket bin-Merkle verification (`verifyMerkleBatch`).
 *   * Padding invariants (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) —
 *     owned by the native `DpfClient`, not re-implementable here.
 *
 * 🔒 Privacy: the adapter cannot bypass padding, cannot short-circuit the
 * symmetric INDEX bin probing (`INDEX_CUCKOO_NUM_HASHES = 2`), and cannot
 * turn off Merkle verification — those live in native Rust code below the
 * WASM boundary.
 */

import { bytesToHex, hexToBytes } from './hash.js';
import {
  fetchDatabaseCatalog,
  fetchServerInfoJson,
  type BucketMerkleInfoJson,
  type DatabaseCatalog,
  type DatabaseCatalogEntry,
  type ServerInfoJson,
} from './server-info.js';
import { requireSdkWasm, type WasmDpfClient, type WasmQueryResult } from './sdk-bridge.js';
import type { ConnectionState, QueryResult, UtxoEntry } from './types.js';
import { ManagedWebSocket } from './ws.js';

// ─── Config ──────────────────────────────────────────────────────────────────

export interface BatchPirClientConfig {
  server0Url: string;
  server1Url: string;
  /** Fires on every connection-state transition (from the adapter itself +
   * from the underlying `WasmDpfClient`). `disconnected` is also emitted on
   * errors during connect. */
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  /** Fires for adapter-level log events (connect messages, side-channel
   * errors). Audit events from the native client go to `console.log` —
   * we do not have an `onLog` hook on `WasmDpfClient` yet. */
  onLog?: (msg: string, level: 'info' | 'success' | 'error') => void;
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

/**
 * Drop-in replacement for the pre-Session-3 `BatchPirClient`. Same
 * constructor config, same method names, same return shapes —
 * `web/index.html` changes its `new BatchPirClient(...)` call site to
 * `new BatchPirClientAdapter(...)` and nothing else.
 */
export class BatchPirClientAdapter {
  private readonly config: BatchPirClientConfig;
  private readonly ws0: ManagedWebSocket;
  private readonly ws1: ManagedWebSocket;
  private wasmClient: WasmDpfClient | null = null;
  private catalog: DatabaseCatalog | null = null;
  private serverInfo: ServerInfoJson | null = null;
  /**
   * Back-reference from translated `QueryResult` to its originating
   * `WasmQueryResult` handle. `WeakMap` so the pair can be collected once
   * the caller drops the translated result. `verifyMerkleBatch` reaches
   * here to round-trip each result through `toJson()` without having to
   * re-serialise by hand.
   */
  private readonly wasmHandles: WeakMap<QueryResult, WasmQueryResult> = new WeakMap();
  private connected = false;

  constructor(config: BatchPirClientConfig) {
    this.config = config;
    this.ws0 = new ManagedWebSocket({
      url: config.server0Url,
      label: 'DPF server0',
      onLog: config.onLog,
    });
    this.ws1 = new ManagedWebSocket({
      url: config.server1Url,
      label: 'DPF server1',
      onLog: config.onLog,
    });
  }

  // ── Connection lifecycle ──────────────────────────────────────────────

  async connect(): Promise<void> {
    this.setState('connecting');
    try {
      // Side-channels first — these carry small diagnostic frames, so
      // they're useful even before the PIR client comes up.
      await Promise.all([this.ws0.connect(), this.ws1.connect()]);

      // Fetch server info + catalog from server0 (the primary role)
      // so the Merkle / catalog accessors can return cached data.
      this.serverInfo = await fetchServerInfoJson(this.ws0);
      this.catalog = await fetchDatabaseCatalog(this.ws0);

      // Construct + wire the WASM client. `onStateChange` replays the
      // native-side transitions; we remap the plain-string payload onto
      // the web `ConnectionState` enum.
      const sdk = requireSdkWasm();
      this.wasmClient = new sdk.WasmDpfClient(
        this.config.server0Url,
        this.config.server1Url,
      );
      this.wasmClient.onStateChange((state: string) => {
        if (
          state === 'connected'
          || state === 'disconnected'
          || state === 'connecting'
          || state === 'reconnecting'
        ) {
          this.setState(state);
        }
      });

      await this.wasmClient.connect();
      this.connected = true;
      // Emit a final `connected` in case the native client's own
      // `onStateChange` fired before we registered the listener or got
      // coalesced out.
      this.setState('connected');
    } catch (e) {
      this.log(`Connect failed: ${(e as Error)?.message ?? e}`, 'error');
      this.teardown();
      this.setState('disconnected', (e as Error)?.message);
      throw e;
    }
  }

  disconnect(): void {
    this.teardown();
    this.setState('disconnected');
  }

  /**
   * `true` iff every piece of the stack is up:
   *   * both side-channel sockets are open,
   *   * the WASM client holds live transport sockets.
   */
  isConnected(): boolean {
    return (
      this.connected
      && this.ws0.isOpen()
      && this.ws1.isOpen()
      && !!this.wasmClient?.isConnected
    );
  }

  /**
   * Used by the residency panel in `web/index.html` to run `REQ_RESIDENCY`
   * across every connected server. Only the side-channel sockets are
   * returned — the WASM client's internal sockets are not addressable
   * from JS.
   */
  getConnectedSockets(): Array<{ label: string; ws: ManagedWebSocket }> {
    const out: Array<{ label: string; ws: ManagedWebSocket }> = [];
    if (this.ws0.isOpen()) {
      out.push({ label: `DPF server0 (${this.config.server0Url})`, ws: this.ws0 });
    }
    if (this.ws1.isOpen()) {
      out.push({ label: `DPF server1 (${this.config.server1Url})`, ws: this.ws1 });
    }
    return out;
  }

  // ── Catalog accessors ─────────────────────────────────────────────────

  getCatalog(): DatabaseCatalog | null {
    return this.catalog;
  }

  getCatalogEntry(dbId: number): DatabaseCatalogEntry | undefined {
    return this.catalog?.databases.find((d) => d.dbId === dbId);
  }

  // ── Merkle accessors (all read cached server info) ────────────────────

  hasMerkle(): boolean {
    const mb = this.serverInfo?.merkle_bucket;
    return !!(mb && mb.index_levels.length > 0);
  }

  hasMerkleForDb(dbId: number): boolean {
    const info = this.getMerkleInfoForDb(dbId);
    return !!(info && info.index_levels.length > 0);
  }

  getMerkleRootHex(): string | undefined {
    return this.serverInfo?.merkle_bucket?.super_root ?? this.serverInfo?.merkle?.root;
  }

  getMerkleRootHexForDb(dbId: number): string | undefined {
    return this.getMerkleInfoForDb(dbId)?.super_root;
  }

  private getMerkleInfoForDb(dbId: number): BucketMerkleInfoJson | undefined {
    // Main DB (db_id = 0) lives at the top level; non-zero DBs are under
    // the `databases` array. Mirrors the legacy `BatchPirClient` lookup.
    if (dbId === 0 && this.serverInfo?.merkle_bucket) {
      return this.serverInfo.merkle_bucket;
    }
    return this.serverInfo?.databases?.find((d) => d.db_id === dbId)?.merkle_bucket;
  }

  // ── Query paths ───────────────────────────────────────────────────────

  /**
   * Full-snapshot batch query. `scriptHashes` is an array of 20-byte
   * HASH160 outputs (as `Uint8Array`). Returns an array of the same
   * length, each slot either a `QueryResult` or `null` ("not found and
   * nothing to verify").
   *
   * The `onProgress` callback fires for step transitions only — the WASM
   * client doesn't yet expose fine-grained per-batch progress, so the
   * step names are coarser than in the pre-Session-3 client. This is an
   * accepted regression.
   */
  async queryBatch(
    scriptHashes: Uint8Array[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = 0,
  ): Promise<(QueryResult | null)[]> {
    return this.queryBatchInternal(scriptHashes, dbId, onProgress);
  }

  /**
   * Delta-database batch query. Same shape as `queryBatch` but every
   * non-null result carries `rawChunkData` — the encoded delta payload
   * that `sync-merge.ts::applyDeltaData` consumes to apply changes on
   * top of a cached snapshot.
   */
  async queryDelta(
    scriptHashes: Uint8Array[],
    dbId: number = 1,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    return this.queryBatchInternal(scriptHashes, dbId, onProgress);
  }

  private async queryBatchInternal(
    scriptHashes: Uint8Array[],
    dbId: number,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    onProgress?.('Level 1', 'sending batched INDEX queries');

    const packed = packScriptHashes(scriptHashes);
    const wqrs = await this.wasmClient.queryBatchRaw(packed, dbId);
    onProgress?.('Decode', `translating ${wqrs.length} results`);

    const out: (QueryResult | null)[] = new Array(wqrs.length);
    for (let i = 0; i < wqrs.length; i++) {
      const wqr = wqrs[i];
      const qr = translateWasmResult(wqr);
      this.wasmHandles.set(qr, wqr);
      // The legacy BatchPirClient surfaced pure "not found" queries as
      // `null`. Preserve that contract for callers that do
      // `if (result) found++`. Queries that probed INDEX bins but found
      // no entries still carry verifiable absence-proof state, so we
      // keep the `QueryResult` for those — the UI filters with
      // `r && !r.isWhale && r.indexPbcGroup !== undefined` downstream.
      const hasInspectorState =
        (qr.allIndexBins?.length ?? 0) > 0 || qr.isWhale || qr.entries.length > 0;
      out[i] = hasInspectorState ? qr : null;
    }
    return out;
  }

  /**
   * Batch-verify per-bucket bin Merkle proofs for one or more
   * inspector-populated `QueryResult`s. `dbId` selects which database's
   * Merkle roots to verify against (0 = main, 1+ = delta).
   *
   * Each `QueryResult` is serialised to JSON via the stashed
   * `WasmQueryResult.toJson()` (or, for results that came from
   * elsewhere, via a manual `queryResultToJson` reconstruction) and
   * handed to `WasmDpfClient.verifyMerkleBatch`. The native verifier
   * drives the K-padded sibling-query rounds, parses the tree-tops
   * blob, walks every proof, and returns a `boolean[]` of verdicts.
   */
  async verifyMerkleBatch(
    results: QueryResult[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = 0,
  ): Promise<boolean[]> {
    if (!this.wasmClient) throw new Error('Not connected');
    onProgress?.('Merkle', `verifying ${results.length} items`);

    const jsonArr: any[] = results.map((r) => {
      const handle = this.wasmHandles.get(r);
      if (handle) return handle.toJson();
      return queryResultToJson(r);
    });

    const verdicts = await this.wasmClient.verifyMerkleBatch(jsonArr, dbId);
    const passed = verdicts.filter(Boolean).length;
    onProgress?.('Merkle', `done (${passed}/${verdicts.length} passed)`);
    return verdicts;
  }

  // ── Internal ──────────────────────────────────────────────────────────

  private teardown(): void {
    this.ws0.disconnect();
    this.ws1.disconnect();
    if (this.wasmClient) {
      // Best-effort async disconnect; `free()` is safe either way.
      this.wasmClient.disconnect().catch(() => { /* swallow */ });
      this.wasmClient.free();
      this.wasmClient = null;
    }
    this.connected = false;
  }

  private setState(state: ConnectionState, message?: string): void {
    this.config.onConnectionStateChange?.(state, message);
  }

  private log(msg: string, level: 'info' | 'success' | 'error' = 'info'): void {
    this.config.onLog?.(msg, level);
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Pack an `N`-entry `Uint8Array[]` of 20-byte HASH160 outputs into a
 * single `Uint8Array(20 * N)`, as expected by `WasmDpfClient.queryBatchRaw`.
 */
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
 * Translate a `WasmQueryResult` (opaque handle from
 * `WasmDpfClient.queryBatchRaw`) into the legacy `QueryResult` shape.
 *
 * The two shapes differ in:
 *   * `entries`: WASM uses `{txid: hex, vout, amountSats}`; web uses
 *     `{txid: Uint8Array, vout, amount: bigint}` (hash.ts-style).
 *   * Inspector fields: WASM keeps all probed bins in `indexBins()` +
 *     `chunkBins()` with a separate `matchedIndexIdx()`; web keeps
 *     `indexPbcGroup`/`indexBinIndex`/`indexBinContent` for the matched
 *     bin plus an `allIndexBins` array for absence proofs. We derive
 *     both by indexing `indexBins[matchedIdx]`.
 *   * `chunkBinContents`: WASM hex, web raw bytes.
 */
function translateWasmResult(wqr: WasmQueryResult): QueryResult {
  const entries: UtxoEntry[] = [];
  for (let i = 0; i < wqr.entryCount; i++) {
    const e = wqr.getEntry(i);
    if (!e) continue;
    entries.push({
      txid: hexToBytes(e.txid),
      vout: Number(e.vout),
      amount: BigInt(e.amountSats ?? e.amount ?? 0),
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
  // Primary match: prefer the explicitly matched bin, else fall back to
  // the first probed bin (legacy behaviour for not-found queries so
  // `indexPbcGroup !== undefined` still filters "verifiable" truthy).
  const primary = matchedIdx !== undefined ? allIndexBins[matchedIdx] : allIndexBins[0];

  return {
    entries,
    totalSats: wqr.totalBalance,
    // Display-only legacy fields — not read by any remaining consumer
    // for DPF results. Kept in the shape for type compatibility.
    startChunkId: 0,
    numChunks: chunkBinsRaw.length,
    numRounds: 0,
    isWhale: wqr.isWhale,
    merkleVerified: wqr.merkleVerified,
    rawChunkData: rawChunkData instanceof Uint8Array ? rawChunkData : undefined,
    indexPbcGroup: primary?.pbcGroup,
    indexBinIndex: primary?.binIndex,
    indexBinContent: primary?.binContent,
    allIndexBins: allIndexBins.length > 0 ? allIndexBins : undefined,
    chunkPbcGroups: chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => b.pbcGroup) : undefined,
    chunkBinIndices: chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => b.binIndex) : undefined,
    chunkBinContents:
      chunkBinsRaw.length > 0 ? chunkBinsRaw.map((b) => hexToBytes(b.binContent)) : undefined,
  };
}

/**
 * Rebuild a `WasmQueryResult`-compatible JSON object from a hand-crafted
 * `QueryResult` (one that doesn't have a stashed WASM handle, e.g.
 * persisted through localStorage). Matches the field-name contract that
 * `parse_query_result_json` accepts in `pir-sdk-wasm`.
 */
function queryResultToJson(r: QueryResult): any {
  const entries = r.entries.map((e) => ({
    txid: bytesToHex(e.txid),
    vout: e.vout,
    // `parse_query_result_json` reads via `as_u64()`, so we must pass a
    // number (not a bigint) in JSON. The hex / decimal representation
    // doesn't matter — `JSON.stringify` handles bigints by conversion.
    amountSats: Number(e.amount),
  }));
  const obj: any = {
    entries,
    isWhale: r.isWhale,
    merkleVerified: r.merkleVerified ?? true,
  };
  if (r.allIndexBins && r.allIndexBins.length > 0) {
    obj.indexBins = r.allIndexBins.map((b) => ({
      pbcGroup: b.pbcGroup,
      binIndex: b.binIndex,
      binContent: bytesToHex(b.binContent),
    }));
    // Derive the matched-idx by scanning for the bin whose
    // (pbcGroup, binIndex) matches the primary-match fields. Only emit
    // when the result is an actual match — a not-found with
    // `indexPbcGroup === allIndexBins[0].pbcGroup` would otherwise be
    // miscategorised as a match.
    if (r.entries.length > 0 && r.indexPbcGroup !== undefined) {
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
