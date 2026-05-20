/**
 * PIR SDK WASM TypeScript Definitions
 *
 * This file provides TypeScript type definitions for the pir-sdk-wasm module.
 * Import the module and use these types for type-safe access to PIR SDK functions.
 */

// ─── Initialization ─────────────────────────────────────────────────────────

/**
 * Initialize the WASM module.
 * Must be called before using any other functions.
 */
export default function init(): Promise<void>;

// ─── Database Catalog ───────────────────────────────────────────────────────

export interface DatabaseEntry {
  dbId: number;
  dbType: 0 | 1; // 0 = full, 1 = delta
  name: string;
  baseHeight: number;
  height: number;
  indexBins: number;
  chunkBins: number;
  indexK: number;
  chunkK: number;
  tagSeed?: string;
  dpfNIndex?: number;
  dpfNChunk?: number;
  hasBucketMerkle?: boolean;
}

export interface DatabaseCatalogJson {
  databases: DatabaseEntry[];
}

/**
 * WASM wrapper for DatabaseCatalog.
 */
export class WasmDatabaseCatalog {
  constructor();

  /**
   * Create a catalog from JSON.
   */
  static fromJson(json: DatabaseCatalogJson): WasmDatabaseCatalog;

  /**
   * Number of databases in the catalog.
   */
  readonly count: number;

  /**
   * Get latest tip height.
   */
  readonly latestTip: number | undefined;

  /**
   * Get database info as JSON.
   */
  getDatabase(index: number): DatabaseEntry | null;

  /**
   * Convert to JSON.
   */
  toJson(): DatabaseCatalogJson;

  /**
   * Free the WASM memory for this object.
   */
  free(): void;
}

// ─── Sync Plan ──────────────────────────────────────────────────────────────

export interface SyncStepJson {
  dbId: number;
  dbType: 'full' | 'delta';
  name: string;
  baseHeight: number;
  tipHeight: number;
}

export interface SyncPlanJson {
  steps: SyncStepJson[];
  isFreshSync: boolean;
  targetHeight: number;
}

/**
 * WASM wrapper for SyncPlan.
 */
export class WasmSyncPlan {
  /**
   * Number of steps in the plan.
   */
  readonly stepsCount: number;

  /**
   * Whether this is a fresh sync (starting from snapshot).
   */
  readonly isFreshSync: boolean;

  /**
   * Target height after sync.
   */
  readonly targetHeight: number;

  /**
   * Whether the plan is empty (already at tip).
   */
  readonly isEmpty: boolean;

  /**
   * Get a step by index.
   */
  getStep(index: number): SyncStepJson | null;

  /**
   * Convert to JSON.
   */
  toJson(): SyncPlanJson;

  /**
   * Free the WASM memory for this object.
   */
  free(): void;
}

/**
 * Compute an optimal sync plan from the catalog.
 *
 * @param catalog - Database catalog from server
 * @param lastSyncedHeight - Last synced height (undefined or 0 for fresh sync)
 * @returns A WasmSyncPlan with steps to execute
 */
export function computeSyncPlan(
  catalog: WasmDatabaseCatalog,
  lastSyncedHeight?: number
): WasmSyncPlan;

// ─── Query Result ───────────────────────────────────────────────────────────

export interface UtxoEntryJson {
  txid: string; // hex
  vout: number;
  amountSats: number;
}

export interface QueryResultJson {
  entries: UtxoEntryJson[];
  isWhale: boolean;
  totalBalance: number;
}

/**
 * WASM wrapper for QueryResult.
 */
export class WasmQueryResult {
  constructor();

  /**
   * Create from JSON.
   */
  static fromJson(json: QueryResultJson): WasmQueryResult;

  /**
   * Number of UTXO entries.
   */
  readonly entryCount: number;

  /**
   * Total balance in satoshis.
   */
  readonly totalBalance: number;

  /**
   * Whether this is a whale address.
   */
  readonly isWhale: boolean;

  /**
   * Get entry at index as JSON.
   */
  getEntry(index: number): UtxoEntryJson | null;

  /**
   * Convert to JSON.
   */
  toJson(): QueryResultJson;

  /**
   * Free the WASM memory for this object.
   */
  free(): void;
}

// ─── Delta Merging ──────────────────────────────────────────────────────────

export interface DeltaDataJson {
  spent: string[]; // hex outpoints (36 bytes each)
  newUtxos: UtxoEntryJson[];
}

/**
 * Decode delta data from raw bytes.
 */
export function decodeDeltaData(raw: Uint8Array): DeltaDataJson;

/**
 * Merge delta into a snapshot result.
 *
 * @param snapshot - The snapshot QueryResult
 * @param deltaRaw - Raw delta chunk data bytes
 * @returns A new WasmQueryResult with the delta applied
 */
export function mergeDelta(
  snapshot: WasmQueryResult,
  deltaRaw: Uint8Array
): WasmQueryResult;

// ─── Hash Functions ─────────────────────────────────────────────────────────

/**
 * Splitmix64 finalizer.
 * @returns 8 bytes (little-endian)
 */
export function splitmix64(xHi: number, xLo: number): Uint8Array;

/**
 * Compute fingerprint tag for a script hash.
 * @returns 8 bytes (little-endian)
 */
export function computeTag(
  tagSeedHi: number,
  tagSeedLo: number,
  scriptHash: Uint8Array
): Uint8Array;

/**
 * Derive 3 group indices for a script hash.
 */
export function deriveGroups(scriptHash: Uint8Array, k: number): Uint32Array;

/**
 * Derive cuckoo hash key.
 * @returns 8 bytes (little-endian)
 */
export function deriveCuckooKey(
  masterSeedHi: number,
  masterSeedLo: number,
  groupId: number,
  hashFn: number
): Uint8Array;

/**
 * Cuckoo hash a script hash.
 */
export function cuckooHash(
  scriptHash: Uint8Array,
  keyHi: number,
  keyLo: number,
  numBins: number
): number;

/**
 * Derive 3 group indices for a chunk ID.
 */
export function deriveChunkGroups(chunkId: number, k: number): Uint32Array;

/**
 * Cuckoo hash an integer chunk ID.
 */
export function cuckooHashInt(
  chunkId: number,
  keyHi: number,
  keyLo: number,
  numBins: number
): number;

// ─── PBC Utilities ──────────────────────────────────────────────────────────

/**
 * Cuckoo-place items into groups.
 *
 * @param candGroupsFlat - Flat array of candidate group indices
 * @param numItems - Number of items
 * @param numGroups - Number of groups (K)
 * @param maxKicks - Maximum cuckoo kicks
 * @param numHashes - Number of hash functions per item
 * @returns Array of group assignments (-1 if unplaced)
 */
export function cuckooPlace(
  candGroupsFlat: Uint32Array,
  numItems: number,
  numGroups: number,
  maxKicks: number,
  numHashes: number
): Int32Array;

/**
 * Plan multi-round PBC placement.
 * @returns Array of rounds, each round is array of [itemIndex, groupId]
 */
export function planRounds(
  itemGroupsFlat: Uint32Array,
  itemsPer: number,
  numGroups: number,
  numHashes: number,
  maxKicks: number
): [number, number][][];

// ─── Codec Utilities ────────────────────────────────────────────────────────

/**
 * Read a LEB128 varint.
 * @returns [valueLo, valueHi, bytesConsumed]
 */
export function readVarint(data: Uint8Array, offset: number): Uint32Array;

/**
 * Decode UTXO data from bytes.
 */
export function decodeUtxoData(data: Uint8Array): Array<{
  txid: string;
  vout: number;
  amount: number;
}>;

// ─── Wire Explorer Helpers ──────────────────────────────────────────────────

/**
 * Decode the per-group sub-query `count` fields from a
 * `REQ_HARMONY_BATCH_QUERY` (opcode `0x43`) frame, returning one entry
 * per `(group, sub_query)` slot in declaration order so JS can assert
 * the **HarmonyPIR Per-Group Request-Count Symmetry** privacy
 * invariant ("every per-group query slot — INDEX / CHUNK / sibling —
 * sends exactly `T − 1` sorted distinct `u32` indices") against live
 * captured traffic.
 *
 * Accepts three input shapes (auto-detected, see below) so callers
 * don't need to know whether they've already peeled the WebSocket
 * envelope:
 *   1. Full wire frame: `[4B payload_len LE][1B opcode = 0x43][payload]`
 *   2. Stripped envelope, opcode kept: `[1B opcode = 0x43][payload]`
 *   3. Raw payload: just `[payload]`
 *
 * Detection priority is (1) → (2) → (3); shape (1) wins when both (1)
 * and (2) would match — the length-prefix consistency check is the
 * tie-breaker.
 *
 * @param frame - Wire bytes captured from the WebSocket, in any of the
 *                three shapes above.
 * @returns A flat `Uint32Array` of length
 *          `num_groups × sub_queries_per_group`, row-major by group.
 * @throws If the input is empty, the opcode is wrong, the header is
 *         truncated, or any per-group `count` declares more bytes than
 *         remain in the payload.
 */
export function harmony_decode_counts(frame: Uint8Array): Uint32Array;
