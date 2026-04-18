/**
 * Bridge between the existing web client and pir-sdk-wasm.
 *
 * This module provides a migration path from the pure-TS implementation
 * to the Rust SDK via WASM. Functions check if the WASM module is loaded
 * and fall back to the TS implementation if not.
 */

import type { DatabaseCatalog, DatabaseCatalogEntry } from './server-info.js';
import type { SyncPlan, SyncStep } from './sync.js';
import { computeSyncPlan as computeSyncPlanTS } from './sync.js';

// ─── WASM module type ───────────────────────────────────────────────────────

interface PirSdkWasm {
  WasmDatabaseCatalog: {
    new(): WasmDatabaseCatalog;
    fromJson(json: any): WasmDatabaseCatalog;
  };
  WasmSyncPlan: WasmSyncPlan;
  WasmQueryResult: {
    new(): WasmQueryResult;
    fromJson(json: any): WasmQueryResult;
  };
  // Native-WASM DPF client — used by `dpf-adapter.ts` to retire the pure-TS
  // `BatchPirClient`. The class is constructed with two server URLs; its
  // `connect()` opens both WebSockets via the wasm32 transport layer in
  // `pir-sdk-client::wasm_transport`. The adapter owns padding invariants
  // (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) by delegating the query
  // machinery to the native `DpfClient` underneath — there is no way the
  // adapter could bypass them.
  WasmDpfClient: {
    new(server0Url: string, server1Url: string): WasmDpfClient;
  };
  // Native-WASM HarmonyPIR client — used by `harmonypir-adapter.ts` to
  // retire the pure-TS `HarmonyPirClient`. Constructed with two server
  // URLs (hint server + query server). Generates a fresh random master
  // PRP key at construction; callers that want to resume from a cached
  // hint blob must `setMasterKey(bytes)` before `loadHints(...)`. The
  // adapter owns HarmonyPIR's padding invariants (K=75 INDEX / K_CHUNK=80
  // CHUNK / 25-MERKLE) by delegating to the native `HarmonyClient`
  // underneath — the wrapper cannot bypass them.
  WasmHarmonyClient: {
    new(hintServerUrl: string, queryServerUrl: string): WasmHarmonyClient;
  };
  PRP_HOANG: () => number;
  PRP_FASTPRP: () => number;
  PRP_ALF: () => number;
  /**
   * Opaque wrapper around a parsed tree-tops blob. Obtain via
   * `WasmBucketMerkleTreeTops.fromBytes(...)` and reuse across all items that
   * belong to the same (db_id, height) — reparsing for every item is wasted
   * work.
   *
   * Remember to call `.free()` once you're done with it (or when the
   * containing FinalizationRegistry fires) so the WASM-side allocation can
   * be released.
   */
  WasmBucketMerkleTreeTops: {
    fromBytes(data: Uint8Array): WasmBucketMerkleTreeTops;
  };
  computeSyncPlan(catalog: WasmDatabaseCatalog, lastSyncedHeight?: number | null): WasmSyncPlan;
  mergeDelta(snapshot: WasmQueryResult, deltaRaw: Uint8Array): WasmQueryResult;
  decodeDeltaData(raw: Uint8Array): DeltaDataJson;
  // Hash functions
  splitmix64(xHi: number, xLo: number): Uint8Array;
  computeTag(tagSeedHi: number, tagSeedLo: number, scriptHash: Uint8Array): Uint8Array;
  deriveGroups(scriptHash: Uint8Array, k: number): Uint32Array;
  deriveCuckooKey(masterSeedHi: number, masterSeedLo: number, groupId: number, hashFn: number): Uint8Array;
  cuckooHash(scriptHash: Uint8Array, keyHi: number, keyLo: number, numBins: number): number;
  deriveChunkGroups(chunkId: number, k: number): Uint32Array;
  cuckooHashInt(chunkId: number, keyHi: number, keyLo: number, numBins: number): number;
  // PBC
  cuckooPlace(candGroupsFlat: Uint32Array, numItems: number, numGroups: number, maxKicks: number, numHashes: number): Int32Array;
  planRounds(itemGroupsFlat: Uint32Array, itemsPer: number, numGroups: number, numHashes: number, maxKicks: number): [number, number][][];
  // Codec
  readVarint(data: Uint8Array, offset: number): Uint32Array;
  decodeUtxoData(data: Uint8Array): UtxoEntryRaw[];
  // Per-bucket bin-Merkle primitives. The network-facing half of the verifier
  // (K-padded sibling batches over DPF) stays in JS; these bindings cover the
  // pure SHA-256 walk so the web client can drop its duplicate TS
  // implementation.
  bucketMerkleSha256(data: Uint8Array): Uint8Array;
  bucketMerkleLeafHash(binIndex: number, binContent: Uint8Array): Uint8Array;
  /** Arity-N parent hash. `childrenFlat.length` must be a multiple of 32. */
  bucketMerkleParentN(childrenFlat: Uint8Array): Uint8Array;
  /** XOR two equal-length buffers (for DPF `server0 ⊕ server1` folds). */
  xorBuffers(a: Uint8Array, b: Uint8Array): Uint8Array;
  /**
   * Verify one per-bucket Merkle proof from leaf → cached root.
   *
   * `siblingRowsFlat` is one 256B row per level below `cacheFromLevel`,
   * bottom-up, already XOR'd across server0 and server1. Returns `false`
   * (not throw) on any mismatch or shape error — treat `false` as a
   * verification failure and coerce the corresponding `QueryResult` to
   * `merkleFailed()`.
   */
  verifyBucketMerkleItem(
    binIndex: number,
    binContent: Uint8Array,
    pbcGroup: number,
    siblingRowsFlat: Uint8Array,
    treeTops: WasmBucketMerkleTreeTops,
  ): boolean;
}

interface WasmBucketMerkleTreeTops {
  free(): void;
  readonly treeCount: number;
  cacheFromLevel(groupIdx: number): number;
  root(groupIdx: number): Uint8Array;
}

interface WasmDatabaseCatalog {
  free(): void;
  readonly count: number;
  readonly latestTip: number | undefined;
  getDatabase(index: number): any;
  /** Look up a database by `db_id`; returns `null` if not in the catalog. */
  getEntry(dbId: number): any;
  /** Does the database with `db_id` publish per-bucket Merkle commitments? */
  hasBucketMerkle(dbId: number): boolean;
  toJson(): any;
}

/**
 * Native-WASM DPF client. See `PirSdkWasm.WasmDpfClient` for the constructor
 * signature. Only the subset used by `dpf-adapter.ts` is typed here; other
 * surfaces (`sync`, `syncWithProgress`, `queryBatch`, `fetchCatalog`) exist
 * on the actual class but aren't needed by the adapter.
 */
interface WasmDpfClient {
  free(): void;
  readonly isConnected: boolean;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  /** Inspector-path batch query. Returns an `Array<WasmQueryResult>` of
   * length `N` (one per packed scripthash). Every slot is non-null —
   * not-found queries are synthesised as empty inspector-populated
   * results so absence-proof bins are preserved. */
  queryBatchRaw(scriptHashes: Uint8Array, dbId: number): Promise<WasmQueryResult[]>;
  /** Standalone Merkle verifier — consumes inspector-populated results as
   * JSON (typically `wqr.toJson()`-serialised). Returns `boolean[]`. */
  verifyMerkleBatch(resultsJson: any[], dbId: number): Promise<boolean[]>;
  /** Register a JS callback for every `ConnectionState` transition; the
   * callback receives a single string (`"connecting"` / `"connected"` /
   * `"disconnected"`). Replaces any previously registered listener. */
  onStateChange(cb: (state: string) => void): void;
  /** Returns `[server0Url, server1Url]`. */
  serverUrls(): [string, string];
}

interface WasmSyncPlan {
  free(): void;
  readonly stepsCount: number;
  readonly isFreshSync: boolean;
  readonly targetHeight: number;
  readonly isEmpty: boolean;
  getStep(index: number): any;
  toJson(): any;
}

/**
 * Native-WASM HarmonyPIR client. See `PirSdkWasm.WasmHarmonyClient` for the
 * constructor signature. Fields used by `harmonypir-adapter.ts`; the full
 * surface exposed by `pir-sdk-wasm/src/client.rs::WasmHarmonyClient` is a
 * superset (notably `queryBatch` + `fetchCatalog`, which the adapter doesn't
 * need because PIR rounds go through `queryBatchRaw`).
 */
interface WasmHarmonyClient {
  free(): void;
  readonly isConnected: boolean;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  serverUrls(): [string, string];
  /** Returns the active `db_id`, or `undefined` if no hints are loaded. */
  dbId(): number | undefined;
  setDbId(dbId: number): void;
  /** Overwrite the random 16-byte master PRP key. Must happen before
   *  `loadHints(...)`. Throws on non-16-byte input. */
  setMasterKey(key: Uint8Array): void;
  setPrpBackend(backend: number): void;
  /** Inspector-path batch query — populates `indexBins`/`chunkBins`
   *  on every returned `WasmQueryResult`. Not-found slots are
   *  synthesised as empty inspector-populated results (never null)
   *  so Merkle absence proofs have something to verify against. */
  queryBatchRaw(scriptHashes: Uint8Array, dbId: number): Promise<WasmQueryResult[]>;
  /** Standalone Merkle verifier (mirrors `WasmDpfClient.verifyMerkleBatch`). */
  verifyMerkleBatch(resultsJson: any[], dbId: number): Promise<boolean[]>;
  /** 16-byte fingerprint derived from `(masterKey, prpBackend, catalog.get(dbId))`.
   *  Embedded in `saveHints()` output; exposed here so the IndexedDB
   *  bridge can tag cache entries for debugging. */
  fingerprint(catalog: WasmDatabaseCatalog, dbId: number): Uint8Array;
  /** Serialize the currently-loaded hint state to a self-describing
   *  binary blob. Returns `null` / `undefined` when nothing is loaded. */
  saveHints(): Uint8Array | undefined | null;
  /** Restore hint state from a `saveHints()` blob. Fingerprint is
   *  cross-checked against `(masterKey, prpBackend, catalog.get(dbId))`;
   *  a mismatch throws rather than silently loading stale hints. */
  loadHints(bytes: Uint8Array, catalog: WasmDatabaseCatalog, dbId: number): void;
  /** Minimum per-group query budget across every loaded HarmonyGroup.
   *  `undefined` when nothing is loaded. */
  minQueriesRemaining(): number | undefined;
  /** Size of the `saveHints()` blob that would be produced right now. */
  estimateHintSizeBytes(): number;
  /** Register a `ConnectionState` transition listener. */
  onStateChange(cb: (state: string) => void): void;
  /** Progress-reporting variant of `sync`; currently unused by the
   *  adapter (queryBatchRaw is the primary path). */
  syncWithProgress(
    scriptHashes: Uint8Array,
    lastHeight: number | null | undefined,
    progress: (step: string, detail: string) => void,
  ): Promise<any>;
}

interface WasmQueryResult {
  free(): void;
  readonly entryCount: number;
  readonly totalBalance: bigint;
  readonly isWhale: boolean;
  readonly merkleVerified: boolean;
  /** Returns `{txid: hexString, vout, amountSats}` or `null`. */
  getEntry(index: number): any;
  /** Inspector state: `[{pbcGroup, binIndex, binContent: hexString}, ...]`. */
  indexBins(): any;
  chunkBins(): any;
  /** The matched INDEX bin's position in `indexBins()`, or `undefined`
   * for not-found / inspector-free results. */
  matchedIndexIdx(): number | undefined;
  /** Raw chunk bytes for delta-database queries, else `undefined`. */
  rawChunkData(): Uint8Array | undefined;
  toJson(): any;
}

interface DeltaDataJson {
  spent: string[];
  newUtxos: UtxoEntryRaw[];
}

interface UtxoEntryRaw {
  txid: string;
  vout: number;
  amount?: number;
  amountSats?: number;
}

// ─── State ──────────────────────────────────────────────────────────────────

let sdkWasm: PirSdkWasm | null = null;
let sdkInitPromise: Promise<boolean> | null = null;

// ─── Initialization ─────────────────────────────────────────────────────────

/**
 * Initialize the PIR SDK WASM module.
 * Returns true if successful, false if WASM is not available.
 */
export async function initSdkWasm(): Promise<boolean> {
  if (sdkWasm) return true;
  if (sdkInitPromise) return sdkInitPromise;

  sdkInitPromise = (async () => {
    try {
      // Dynamic import - the bundler resolves the WASM package
      // @ts-ignore - pir-sdk-wasm may not be installed
      const mod = await import('pir-sdk-wasm');
      // wasm-pack generates a default export that initializes the module
      if (typeof (mod as any).default === 'function') {
        await (mod as any).default();
      }
      sdkWasm = mod as unknown as PirSdkWasm;
      console.log('[PIR-SDK] WASM module loaded successfully');
      return true;
    } catch (e) {
      console.warn('[PIR-SDK] Failed to load WASM module, using pure-TS fallback:', e);
      return false;
    }
  })();

  return sdkInitPromise;
}

/**
 * Check if SDK WASM is loaded and ready.
 */
export function isSdkWasmReady(): boolean {
  return sdkWasm !== null;
}

// ─── Catalog Conversion ─────────────────────────────────────────────────────

/**
 * Convert web client DatabaseCatalog to SDK format.
 */
function catalogToSdkFormat(catalog: DatabaseCatalog): any {
  return {
    databases: catalog.databases.map(db => ({
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
}

/**
 * Convert SDK SyncPlan to web client format.
 */
function sdkPlanToWebFormat(plan: WasmSyncPlan): SyncPlan {
  const steps: SyncStep[] = [];
  for (let i = 0; i < plan.stepsCount; i++) {
    const step = plan.getStep(i);
    if (step) {
      steps.push({
        dbId: step.dbId,
        dbType: step.dbType,
        name: step.name,
        baseHeight: step.baseHeight,
        tipHeight: step.tipHeight,
      });
    }
  }
  return {
    steps,
    isFreshSync: plan.isFreshSync,
    targetHeight: plan.targetHeight,
  };
}

// ─── SDK-backed Functions ───────────────────────────────────────────────────

/**
 * Compute sync plan using SDK WASM if available, otherwise fall back to TS.
 *
 * This is a drop-in replacement for the TS computeSyncPlan function.
 */
export function computeSyncPlanSdk(
  catalog: DatabaseCatalog,
  lastSyncedHeight?: number,
): SyncPlan {
  // Try WASM first
  if (sdkWasm) {
    try {
      const sdkCatalog = sdkWasm.WasmDatabaseCatalog.fromJson(catalogToSdkFormat(catalog));
      const sdkPlan = sdkWasm.computeSyncPlan(sdkCatalog, lastSyncedHeight ?? null);
      const result = sdkPlanToWebFormat(sdkPlan);
      // Free WASM objects
      sdkPlan.free();
      sdkCatalog.free();
      return result;
    } catch (e) {
      console.warn('[PIR-SDK] WASM computeSyncPlan failed, falling back to TS:', e);
    }
  }

  // Fall back to TypeScript implementation
  return computeSyncPlanTS(catalog, lastSyncedHeight);
}

// ─── Hash Function Wrappers ─────────────────────────────────────────────────

/**
 * Convert 8-byte LE array to BigInt.
 */
function leBytes8ToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 7; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Split BigInt into [hi, lo] u32 pair.
 */
function bigintToHiLo(v: bigint): [number, number] {
  const lo = Number(v & 0xFFFFFFFFn);
  const hi = Number((v >> 32n) & 0xFFFFFFFFn);
  return [hi, lo];
}

/**
 * SDK-backed splitmix64.
 */
export function sdkSplitmix64(x: bigint): bigint | undefined {
  if (!sdkWasm) return undefined;
  const [hi, lo] = bigintToHiLo(x);
  const result = sdkWasm.splitmix64(hi, lo);
  return leBytes8ToBigint(result);
}

/**
 * SDK-backed computeTag.
 */
export function sdkComputeTag(tagSeed: bigint, scriptHash: Uint8Array): bigint | undefined {
  if (!sdkWasm) return undefined;
  const [hi, lo] = bigintToHiLo(tagSeed);
  const result = sdkWasm.computeTag(hi, lo, scriptHash);
  return leBytes8ToBigint(result);
}

/**
 * SDK-backed deriveGroups.
 */
export function sdkDeriveGroups(scriptHash: Uint8Array, k: number): number[] | undefined {
  if (!sdkWasm) return undefined;
  const result = sdkWasm.deriveGroups(scriptHash, k);
  return Array.from(result);
}

/**
 * SDK-backed deriveCuckooKey.
 */
export function sdkDeriveCuckooKey(
  masterSeed: bigint,
  groupId: number,
  hashFn: number,
): bigint | undefined {
  if (!sdkWasm) return undefined;
  const [hi, lo] = bigintToHiLo(masterSeed);
  const result = sdkWasm.deriveCuckooKey(hi, lo, groupId, hashFn);
  return leBytes8ToBigint(result);
}

/**
 * SDK-backed cuckooHash.
 */
export function sdkCuckooHash(
  scriptHash: Uint8Array,
  key: bigint,
  numBins: number,
): number | undefined {
  if (!sdkWasm) return undefined;
  const [hi, lo] = bigintToHiLo(key);
  return sdkWasm.cuckooHash(scriptHash, hi, lo, numBins);
}

/**
 * SDK-backed deriveChunkGroups.
 */
export function sdkDeriveChunkGroups(chunkId: number, k: number): number[] | undefined {
  if (!sdkWasm) return undefined;
  const result = sdkWasm.deriveChunkGroups(chunkId, k);
  return Array.from(result);
}

/**
 * SDK-backed cuckooHashInt.
 */
export function sdkCuckooHashInt(
  chunkId: number,
  key: bigint,
  numBins: number,
): number | undefined {
  if (!sdkWasm) return undefined;
  const [hi, lo] = bigintToHiLo(key);
  return sdkWasm.cuckooHashInt(chunkId, hi, lo, numBins);
}

// ─── Codec / PBC Wrappers ───────────────────────────────────────────────────
//
// These wrap the Rust-native UTXO decoder and multi-round PBC planner so the
// web client can drop its duplicate TS implementations. Both wrappers return
// `undefined` when the WASM module isn't loaded so callers can fall through
// to the pure-TS implementation (same pattern as the hash wrappers above).
//
// Deliberately NOT wrapped:
//   - `readVarint`: WASM version panics on truncation while TS throws a typed
//     `Error('Unexpected end of data …')` that tests and error-handling code
//     depend on. Marshalling cost per call also rivals the work saved.
//   - `cuckooPlace`: TS API mutates a caller-supplied `groups` array for one
//     item at a time with eviction tracking; WASM API does bulk batch
//     placement and returns full assignments. Not a drop-in replacement.

/** Hex-decode a hex string of any even length to a `Uint8Array`. */
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length >>> 1);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

/**
 * SDK-backed UTXO data decoder.
 *
 * WASM returns `{txid: hexString, vout: number, amount: number}[]`; this
 * wrapper converts txids to `Uint8Array` (hex-decode) and amounts to `bigint`
 * so the result is bit-identical to the TS `decodeUtxoData` output shape.
 *
 * Precision: WASM `amount` crosses the JS boundary as a `number`. Bitcoin's
 * 21M BTC supply = 2.1e15 sats is well under JS `Number.MAX_SAFE_INTEGER`
 * (2^53 ≈ 9e15), so real mainnet values preserve full precision.
 *
 * Note: unlike the TS version, the WASM path has no way to call `onError` on
 * mid-stream truncation — the underlying `pir_core::codec::parse_utxo_data`
 * silently truncates. Truncation is extremely rare in practice (the build
 * pipeline zero-pads on BLOCK_SIZE boundaries), so callers that care about
 * the warning should fall back to the TS implementation.
 */
export function sdkDecodeUtxoData(
  data: Uint8Array,
): { entries: { txid: Uint8Array; vout: number; amount: bigint }[]; totalSats: bigint } | undefined {
  if (!sdkWasm) return undefined;
  // WASM returns `Array<{txid: hexString, vout: number, amount: number}>`.
  const raw = sdkWasm.decodeUtxoData(data) as unknown as Array<{
    txid: string;
    vout: number;
    amount?: number;
    amountSats?: number;
  }>;
  if (!Array.isArray(raw)) return undefined;
  const entries: { txid: Uint8Array; vout: number; amount: bigint }[] = [];
  let totalSats = 0n;
  for (const e of raw) {
    const amountNum = e.amount ?? e.amountSats ?? 0;
    const amount = BigInt(amountNum);
    entries.push({
      txid: hexToBytes(e.txid),
      vout: e.vout,
      amount,
    });
    totalSats += amount;
  }
  return { entries, totalSats };
}

/**
 * SDK-backed delta data decoder.
 *
 * WASM returns `{spent: hexString[], newUtxos: {txid: hexString, vout: number,
 * amountSats: number}[]}` where each `spent` hex string is 72 chars (36 bytes
 * = `[32B txid][4B vout_le]` — this is the in-memory shape `pir_sdk` packs
 * for `apply_delta_data`'s `HashSet<[u8; 36]>` lookup, not the on-wire
 * varint shape). This wrapper unpacks spent outpoints into the internal
 * `SpentRef` shape (`{txid: Uint8Array, vout: number}`) and converts
 * `amountSats` → `bigint` on each new UTXO so the result is bit-identical
 * to the TS `decodeDeltaData` output.
 *
 * Precision: WASM `amountSats` crosses as a JS `number`. Bitcoin 21M BTC
 * = 2.1e15 sats is well under `Number.MAX_SAFE_INTEGER` = 9e15.
 *
 * Errors: the underlying `pir_sdk::decode_delta_data` returns a typed
 * `PirError::Decode` on truncation / varint overflow; the WASM binding
 * wraps that in a `JsError` which surfaces here as a thrown exception.
 * The wrapper catches and returns `undefined` so the caller falls back to
 * the TS implementation, which throws its own typed `Error` — preserving
 * the "decode failures throw" contract.
 */
export function sdkDecodeDeltaData(
  data: Uint8Array,
): {
  spent: { txid: Uint8Array; vout: number }[];
  newUtxos: { txid: Uint8Array; vout: number; amount: bigint }[];
} | undefined {
  if (!sdkWasm) return undefined;
  let raw: {
    spent: string[];
    newUtxos: Array<{ txid: string; vout: number; amount?: number; amountSats?: number }>;
  };
  try {
    raw = sdkWasm.decodeDeltaData(data) as unknown as typeof raw;
  } catch {
    return undefined;
  }
  if (!raw || !Array.isArray(raw.spent) || !Array.isArray(raw.newUtxos)) return undefined;

  const spent: { txid: Uint8Array; vout: number }[] = [];
  for (const opHex of raw.spent) {
    // 36 bytes packed: [32B txid][4B vout_le]. Two hex chars per byte → 72.
    if (typeof opHex !== 'string' || opHex.length !== 72) return undefined;
    const full = hexToBytes(opHex);
    const dv = new DataView(full.buffer, full.byteOffset, full.byteLength);
    spent.push({
      txid: full.slice(0, 32),
      vout: dv.getUint32(32, true),
    });
  }

  const newUtxos: { txid: Uint8Array; vout: number; amount: bigint }[] = [];
  for (const e of raw.newUtxos) {
    const amountNum = e.amountSats ?? e.amount ?? 0;
    newUtxos.push({
      txid: hexToBytes(e.txid),
      vout: e.vout,
      amount: BigInt(amountNum),
    });
  }

  return { spent, newUtxos };
}

/**
 * SDK-backed multi-round PBC placement planner.
 *
 * Flattens the TS `number[][]` candidate-groups table to a `Uint32Array` for
 * the WASM binding, calls it with the TS-hardcoded `maxKicks = 500`, and
 * returns the tuple-pair rounds in the same shape as `pbc.ts::planRounds`.
 *
 * Preconditions enforced here (return `undefined` on violation so the caller
 * can fall back to TS):
 *   - Every `itemGroups[i]` must have the same length, which in turn must
 *     equal `numHashes`. The WASM binding derives `num_items` by dividing
 *     `flat.len() / itemsPer`, so ragged arrays would be silently truncated.
 *   - `numHashes > 0`.
 *
 * Empty `itemGroups` returns `[]` without calling WASM (WASM would need a
 * non-zero `itemsPer` to slice into zero items).
 *
 * Note: the TS `planRounds` accepts an optional `onError` callback for the
 * "could not place any remaining items" edge case. The WASM binding has no
 * equivalent hook — that diagnostic is silently dropped on the WASM path.
 */
export function sdkPlanRounds(
  itemGroups: number[][],
  numGroups: number,
  numHashes: number,
): [number, number][][] | undefined {
  if (!sdkWasm) return undefined;
  if (numHashes <= 0) return undefined;
  if (itemGroups.length === 0) return [];
  // Every row must have exactly `numHashes` candidates — ragged input would
  // desync the flat-array indexing inside the WASM binding.
  for (let i = 0; i < itemGroups.length; i++) {
    if (itemGroups[i].length !== numHashes) return undefined;
  }
  const flat = new Uint32Array(itemGroups.length * numHashes);
  for (let i = 0; i < itemGroups.length; i++) {
    const row = itemGroups[i];
    const base = i * numHashes;
    for (let h = 0; h < numHashes; h++) {
      flat[base + h] = row[h] >>> 0;
    }
  }
  // maxKicks = 500 matches the hardcoded constant in `pbc.ts::planRounds`.
  const rounds = sdkWasm.planRounds(flat, numHashes, numGroups, numHashes, 500);
  if (!Array.isArray(rounds)) return undefined;
  return rounds;
}

// ─── Per-bucket Merkle primitives ───────────────────────────────────────────
//
// These are the pure-crypto half of the per-bucket bin-Merkle verifier. They
// are thin wrappers around the `pir-sdk-wasm` bindings (which themselves
// delegate to `pir_core::merkle`), exposed so that `web/src/merkle-verify-bucket.ts`
// can drop its ~100+ LOC of duplicated TS crypto (tree-top parse, leaf hash,
// parent hash, walk-to-root) in favour of a single implementation shared with
// the native Rust and WASM verifiers.
//
// Unlike the hash functions above, these require the WASM module to be loaded
// — they `throw` rather than return `undefined` on a missing SDK, because the
// caller (the Merkle verifier wire loop) has no TS fallback worth keeping.
// `initSdkWasm()` must have been awaited at app startup (see `web/index.html`).

function requireSdkForMerkle(): PirSdkWasm {
  if (!sdkWasm) {
    throw new Error(
      '[PIR-SDK] WASM module required for bucket Merkle primitives. ' +
        'Call initSdkWasm() at app startup.',
    );
  }
  return sdkWasm;
}

/** SDK-backed SHA-256 (matches `pir_core::merkle::sha256`). */
export function sdkBucketMerkleSha256(data: Uint8Array): Uint8Array {
  return requireSdkForMerkle().bucketMerkleSha256(data);
}

/** SDK-backed bin leaf hash: `SHA256(bin_index_u32_LE || bin_content)`. */
export function sdkBucketMerkleLeafHash(
  binIndex: number,
  binContent: Uint8Array,
): Uint8Array {
  return requireSdkForMerkle().bucketMerkleLeafHash(binIndex, binContent);
}

/**
 * SDK-backed arity-N parent hash. Takes an array of 32-byte child hashes
 * (length = arity) and returns `SHA256(child_0 || child_1 || …)`. Flattens
 * the input before handing it to WASM.
 */
export function sdkBucketMerkleParentN(children: Uint8Array[]): Uint8Array {
  const flat = new Uint8Array(children.length * 32);
  for (let i = 0; i < children.length; i++) flat.set(children[i], i * 32);
  return requireSdkForMerkle().bucketMerkleParentN(flat);
}

/**
 * SDK-backed XOR of two equal-length buffers. Returns an empty `Uint8Array`
 * on length mismatch (so the caller can surface it as a verification failure).
 */
export function sdkXorBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
  return requireSdkForMerkle().xorBuffers(a, b);
}

/**
 * Parse a per-bucket Merkle tree-tops blob (payload of `REQ_BUCKET_MERKLE_TREE_TOPS`,
 * excluding the variant byte). Returns an opaque `WasmBucketMerkleTreeTops`
 * handle that can be passed to `sdkVerifyBucketMerkleItem` repeatedly.
 *
 * Remember to call `.free()` on the returned handle when done (or lean on a
 * `FinalizationRegistry`). Callers should wrap verification in
 * `try { … } finally { handle.free(); }` to avoid leaking WASM allocations.
 */
export function sdkParseBucketMerkleTreeTops(
  data: Uint8Array,
): WasmBucketMerkleTreeTops {
  return requireSdkForMerkle().WasmBucketMerkleTreeTops.fromBytes(data);
}

/**
 * SDK-backed per-item Merkle verifier.
 *
 * Walks one proof from leaf to the published per-group root. `siblingRowsFlat`
 * is the server0 ⊕ server1 XOR'd sibling-batch responses, one 256B row per
 * level below `cacheFromLevel`, concatenated bottom-up.
 *
 * Returns `false` (never throws) on any shape / cryptographic mismatch — the
 * caller should coerce a failed result to the equivalent of
 * `QueryResult::merkle_failed()`.
 */
export function sdkVerifyBucketMerkleItem(
  binIndex: number,
  binContent: Uint8Array,
  pbcGroup: number,
  siblingRowsFlat: Uint8Array,
  treeTops: WasmBucketMerkleTreeTops,
): boolean {
  return requireSdkForMerkle().verifyBucketMerkleItem(
    binIndex,
    binContent,
    pbcGroup,
    siblingRowsFlat,
    treeTops,
  );
}

// Re-export the opaque handle type so consumers don't have to reach into the
// `PirSdkWasm` interface directly.
export type { WasmBucketMerkleTreeTops };

// ─── DPF client accessor ───────────────────────────────────────────────────
//
// `dpf-adapter.ts` needs the loaded `PirSdkWasm` module to construct a
// `WasmDpfClient` at connect-time. This export mirrors the pattern used by
// the Merkle primitives above (`requireSdkForMerkle`) — `throw` rather than
// returning `undefined`, because the adapter has no TS fallback since
// `web/src/client.ts` is being deleted in Session 3.

/**
 * Return the loaded `PirSdkWasm` module, throwing if `initSdkWasm()` has
 * not resolved yet. Intended for consumers that cannot operate without
 * the WASM surface (e.g. `BatchPirClientAdapter`).
 */
export function requireSdkWasm(): PirSdkWasm {
  if (!sdkWasm) {
    throw new Error(
      '[PIR-SDK] WASM module required. Call initSdkWasm() at app startup.',
    );
  }
  return sdkWasm;
}

// Re-export the adapter-facing interface types so `dpf-adapter.ts` can
// import them without having to reach into this module's type-only
// `PirSdkWasm` shape.
export type { WasmDpfClient, WasmHarmonyClient, WasmQueryResult, WasmDatabaseCatalog };

// ─── Re-exports for convenience ─────────────────────────────────────────────

export { computeSyncPlanTS };
export type { SyncPlan, SyncStep } from './sync.js';
