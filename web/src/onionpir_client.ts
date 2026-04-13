/**
 * OnionPIR v2 WebSocket client for browser.
 *
 * Single-server FHE-based PIR using OnionPIRv2 WASM module.
 * Two-level query: index PIR → chunk PIR → decode UTXO data.
 * Multi-address batching via PBC cuckoo placement.
 */

import {
  K, K_CHUNK, NUM_HASHES, INDEX_CUCKOO_NUM_HASHES,
  CHUNK_MASTER_SEED,
  REQ_ONIONPIR_MERKLE_INDEX_SIBLING, RESP_ONIONPIR_MERKLE_INDEX_SIBLING,
  REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP, RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP,
  REQ_ONIONPIR_MERKLE_DATA_SIBLING, RESP_ONIONPIR_MERKLE_DATA_SIBLING,
  REQ_ONIONPIR_MERKLE_DATA_TREE_TOP, RESP_ONIONPIR_MERKLE_DATA_TREE_TOP,
  ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES,
} from './constants.js';

import {
  deriveGroups, deriveCuckooKey, cuckooHash,
  deriveChunkGroups,
  splitmix64, computeTag,
  deriveIntGroups3, deriveCuckooKeyGeneric, cuckooHashInt,
  sha256,
} from './hash.js';

import { cuckooPlace, planRounds } from './pbc.js';
import { readVarint, decodeUtxoData, DummyRng } from './codec.js';
import { findEntryInOnionPirIndexResult } from './scan.js';
import { ManagedWebSocket } from './ws.js';
import { fetchServerInfoJson } from './server-info.js';
import {
  computeParentN, parseTreeTopCache, ZERO_HASH,
  type TreeTopCache,
} from './merkle.js';

import type { UtxoEntry, QueryResult, ConnectionState } from './client.js';
import type {
  DatabaseCatalog,
  OnionPirMerkleInfoJson,
  OnionPirMerkleSubTreeInfo,
  ServerInfoJson,
} from './server-info.js';
import { fetchDatabaseCatalog } from './server-info.js';

// ─── Constants for OnionPIR v2 layout ─────────────────────────────────────

const PACKED_ENTRY_SIZE = 3840;

/** Chunk cuckoo: 6 hash functions, group_size=1 */
const CHUNK_CUCKOO_NUM_HASHES = 6;
const CHUNK_CUCKOO_MAX_KICKS = 10000;
const EMPTY = 0xFFFFFFFF;

const MASK64 = 0xFFFFFFFFFFFFFFFFn;

// ─── OnionPIR wire protocol constants ─────────────────────────────────────

// Protocol constants still used for OnionPIR-specific requests
// (Ping/pong/info handled by ManagedWebSocket + fetchServerInfoJson)

// NOTE: moved from 0x30-0x32 to 0x50-0x52 to avoid collision with
// REQ_MERKLE_SIBLING_BATCH (0x31) and REQ_MERKLE_TREE_TOP (0x32).
const REQ_REGISTER_KEYS         = 0x50;
const REQ_ONIONPIR_INDEX_QUERY  = 0x51;
const REQ_ONIONPIR_CHUNK_QUERY  = 0x52;

const RESP_KEYS_ACK             = 0x50;
const RESP_ONIONPIR_INDEX_RESULT  = 0x51;
const RESP_ONIONPIR_CHUNK_RESULT  = 0x52;

// ─── WASM module types ────────────────────────────────────────────────────

interface OnionPirModule {
  OnionPirClient: { new(numEntries: number): WasmPirClient };
  createClientFromSecretKey(numEntries: number, clientId: number, secretKey: Uint8Array): WasmPirClient;
  paramsInfo(numEntries: number): { numEntries: number; entrySize: number };
  buildCuckooBs1(entries: Uint32Array, keys: Uint32Array, numBins: number): Uint32Array;
}

interface WasmPirClient {
  id(): number;
  exportSecretKey(): Uint8Array;
  generateGaloisKeys(): Uint8Array;
  generateGswKeys(): Uint8Array;
  generateQuery(entryIndex: number): Uint8Array;
  decryptResponse(entryIndex: number, response: Uint8Array): Uint8Array;
  delete(): void;
}

// ─── WASM module loader ───────────────────────────────────────────────────

let wasmModulePromise: Promise<OnionPirModule> | null = null;

async function loadWasmModule(): Promise<OnionPirModule> {
  if (!wasmModulePromise) {
    wasmModulePromise = (async () => {
      const factory = (globalThis as any).createOnionPirModule;
      if (!factory) {
        throw new Error(
          'OnionPIR WASM not loaded. Add <script src="/wasm/onionpir_client.js"></script> to HTML.'
        );
      }
      return await factory();
    })();
  }
  return wasmModulePromise;
}

// ─── Main-thread yield that bypasses background-tab timer throttling ─────
//
// In background/hidden tabs Chromium throttles `setTimeout(..., 0)` callbacks
// to ≥1000ms (sometimes tens of seconds), which turns a 150-iter generation
// loop into a multi-minute stall. `MessageChannel.postMessage` is scheduled as
// a task rather than a timer and is not subject to that throttling, giving us
// a stable ~sub-ms yield point in both foreground and background tabs.
function yieldToMain(): Promise<void> {
  return new Promise<void>(resolve => {
    const ch = new MessageChannel();
    ch.port1.onmessage = () => { ch.port1.close(); resolve(); };
    ch.port2.postMessage(null);
  });
}

// ─── Chunk cuckoo hash functions (BigInt for 64-bit precision) ────────────

function chunkDeriveCuckooKey(groupId: number, hashFn: number): bigint {
  return splitmix64(
    (CHUNK_MASTER_SEED
      + ((BigInt(groupId) * 0x9e3779b97f4a7c15n) & MASK64)
      + ((BigInt(hashFn) * 0x517cc1b727220a95n) & MASK64)
    ) & MASK64
  );
}

function chunkCuckooHash(entryId: number, key: bigint, numBins: number): number {
  return Number(splitmix64((BigInt(entryId) ^ key) & MASK64) % BigInt(numBins));
}

// ─── Chunk reverse index: group → entry_ids (precomputed once) ────────────

let chunkReverseIndex: Map<number, number[]> | null = null;
let chunkReverseIndexTotalEntries = 0;

/**
 * Build reverse index mapping each chunk group to its entry_ids.
 * Single pass over all entries — 80× faster than per-group scanning.
 * Cached: only rebuilt if totalEntries changes.
 */
async function ensureChunkReverseIndex(
  totalEntries: number,
  onProgress?: (msg: string) => void,
): Promise<Map<number, number[]>> {
  if (chunkReverseIndex && chunkReverseIndexTotalEntries === totalEntries) {
    return chunkReverseIndex;
  }

  const index = new Map<number, number[]>();
  for (let g = 0; g < K_CHUNK; g++) {
    index.set(g, []);
  }

  for (let eid = 0; eid < totalEntries; eid++) {
    const groups = deriveChunkGroups(eid);
    for (const g of groups) {
      index.get(g)!.push(eid);
    }
    // Yield periodically — 815K iterations with BigInt hashing
    if (eid % 50000 === 49999) {
      onProgress?.(`Building chunk reverse index: ${eid + 1}/${totalEntries}...`);
      await yieldToMain();
    }
  }

  chunkReverseIndex = index;
  chunkReverseIndexTotalEntries = totalEntries;
  return index;
}

/**
 * Build the chunk cuckoo table for a specific group (deterministic).
 * Uses precomputed reverse index for the entry list, WASM for cuckoo insertion.
 */
function buildChunkCuckooForGroup(
  wasmModule: OnionPirModule,
  groupId: number,
  reverseIndex: Map<number, number[]>,
  binsPerTable: number,
): Uint32Array {
  const entries = reverseIndex.get(groupId) ?? [];
  // entries are already sorted since the reverse index is built in eid order

  // Derive 6 hash keys and encode as lo/hi u32 pairs for WASM
  const keysU32 = new Uint32Array(CHUNK_CUCKOO_NUM_HASHES * 2);
  for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
    const key64 = chunkDeriveCuckooKey(groupId, h);
    keysU32[h * 2]     = Number(key64 & 0xFFFFFFFFn);  // lo
    keysU32[h * 2 + 1] = Number(key64 >> 32n);          // hi
  }

  return wasmModule.buildCuckooBs1(new Uint32Array(entries), keysU32, binsPerTable);
}

function findEntryInCuckoo(
  table: Uint32Array,
  entryId: number,
  keys: bigint[],
  binsPerTable: number,
): number | null {
  for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
    const bin = chunkCuckooHash(entryId, keys[h], binsPerTable);
    if (table[bin] === entryId) return bin;
  }
  return null;
}

// ─── PBC batch placement (uses shared pbc.ts) ───────────────────────────────

function planPbcRounds(
  candidateGroups: number[][],
  k: number,
): [number, number][][] {
  return planRounds(candidateGroups, k, NUM_HASHES);
}

// DummyRng and readVarint imported from codec.ts

// ─── Wire protocol helpers ────────────────────────────────────────────────

function encodeRegisterKeys(galoisKeys: Uint8Array, gswKeys: Uint8Array, dbId: number = 0): Uint8Array {
  // Trailing db_id byte: only appended when non-zero for backward compatibility.
  const trailing = dbId !== 0 ? 1 : 0;
  const payloadLen = 1 + 4 + galoisKeys.length + 4 + gswKeys.length + trailing;
  const msg = new Uint8Array(4 + payloadLen);
  const dv = new DataView(msg.buffer);
  dv.setUint32(0, payloadLen, true);
  let pos = 4;
  msg[pos++] = REQ_REGISTER_KEYS;
  dv.setUint32(pos, galoisKeys.length, true); pos += 4;
  msg.set(galoisKeys, pos); pos += galoisKeys.length;
  dv.setUint32(pos, gswKeys.length, true); pos += 4;
  msg.set(gswKeys, pos); pos += gswKeys.length;
  if (dbId !== 0) {
    msg[pos] = dbId & 0xFF;
  }
  return msg;
}

function encodeBatchQuery(variant: number, roundId: number, queries: Uint8Array[], dbId: number = 0): Uint8Array {
  let payloadSize = 1 + 2 + 1; // variant + round_id + num_groups
  for (const q of queries) payloadSize += 4 + q.length;
  // Trailing db_id byte: only appended when non-zero for backward compatibility.
  if (dbId !== 0) payloadSize += 1;
  const msg = new Uint8Array(4 + payloadSize);
  const dv = new DataView(msg.buffer);
  dv.setUint32(0, payloadSize, true);
  let pos = 4;
  msg[pos++] = variant;
  dv.setUint16(pos, roundId, true); pos += 2;
  msg[pos++] = queries.length;
  for (const q of queries) {
    dv.setUint32(pos, q.length, true); pos += 4;
    msg.set(q, pos); pos += q.length;
  }
  if (dbId !== 0) {
    msg[pos] = dbId & 0xFF;
  }
  return msg;
}

function decodeBatchResult(data: Uint8Array, pos: number): { roundId: number; results: Uint8Array[]; pos: number } {
  const dv = new DataView(data.buffer, data.byteOffset);
  const roundId = dv.getUint16(pos, true); pos += 2;
  const numGroups = data[pos++];
  const results: Uint8Array[] = [];
  for (let i = 0; i < numGroups; i++) {
    const len = dv.getUint32(pos, true); pos += 4;
    results.push(data.slice(pos, pos + len));
    pos += len;
  }
  return { roundId, results, pos };
}

// ─── Client config ────────────────────────────────────────────────────────

export interface OnionPirClientConfig {
  serverUrl: string;
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  onLog?: (message: string, level: 'info' | 'success' | 'error') => void;
}

// ─── Client class ─────────────────────────────────────────────────────────

export class OnionPirWebClient {
  private ws: ManagedWebSocket | null = null;
  private config: OnionPirClientConfig;
  private connectionState: ConnectionState = 'disconnected';
  private rng = new DummyRng();

  // Server info (fetched via JSON)
  private serverInfo: ServerInfoJson | null = null;
  private indexK = 0;
  private chunkK = 0;
  private indexBins = 0;
  private chunkBins = 0;
  private tagSeed = 0n;
  private totalPacked = 0;
  private indexSlotsPerBin = 0;
  private indexSlotSize = 0;

  // WASM module
  private wasmModule: OnionPirModule | null = null;

  // FHE key state (saved after queryBatch for Merkle reuse).
  // Always reflects the most recent queryBatch call (Merkle verifies that batch).
  private fheClientId = 0;
  private fheSecretKey: Uint8Array | null = null;

  // Per-DB FHE registration state. Each entry is the dbId for which we have
  // already registered keys with the server (so we can skip re-registering).
  // Maps dbId → true once registered.
  private registeredDbs: Set<number> = new Set();

  // Active database ID. Controls both queryBatch (via getDbId()) and all
  // Merkle verification operations. Switch with setDbId().
  private dbId: number = 0;

  // Database catalog (populated after connect). Used by the UI selector.
  private catalog: DatabaseCatalog | null = null;

  // Test hook: one-shot override of the computed scripthashes for the next
  // queryBatch() call. Consumed on use and then cleared. Used by harnesses
  // that need to drive a query at a specific scripthash without reversing
  // HASH160. Production UI never sets this.
  private _scriptHashOverride: Uint8Array[] | undefined = undefined;

  /**
   * Set a one-shot scripthash override for the NEXT queryBatch call.
   * The override[] replaces the computed scripthashes 1:1 (same length).
   * Cleared after consumption.
   */
  setScriptHashOverrideForNextQuery(hashes: Uint8Array[]): void {
    this._scriptHashOverride = hashes;
  }

  constructor(config: OnionPirClientConfig) {
    this.config = config;
  }

  /** Return the currently active database ID (0 = main). */
  getDbId(): number { return this.dbId; }

  /**
   * Switch to a different database. Updates BFV params, invalidates cached
   * Merkle state, and forces fresh key registration on the next queryBatch.
   */
  setDbId(newDbId: number): void {
    if (newDbId === this.dbId) return;
    const oldDbId = this.dbId;
    this.dbId = newDbId;
    // Invalidate Merkle tree-top caches (each DB has its own tree tops).
    this.indexTreeTopCache = null;
    this.dataTreeTopCache = null;
    // Re-sync BFV params from the per-DB info, if available. Keeps the
    // existing values if this DB's params aren't exposed (e.g. if the
    // server is older and doesn't emit per-DB `onionpir` info).
    this.updateParamsForActiveDb();
    this.log(`Switched dbId=${oldDbId} -> dbId=${newDbId} (bins=${this.indexBins}/${this.chunkBins})`);
  }

  /** Return the parsed database catalog (fetched after connect). */
  getCatalog(): DatabaseCatalog | null { return this.catalog; }

  /** Internal: resolve per-DB OnionPIR params from serverInfo. */
  private getOnionPirForDb(dbId: number) {
    if (dbId === 0) return this.serverInfo?.onionpir;
    return this.serverInfo?.databases?.find(d => d.db_id === dbId)?.onionpir;
  }

  /** Internal: resolve per-DB OnionPIR Merkle info from serverInfo. */
  private getOnionPirMerkleForDb(dbId: number): OnionPirMerkleInfoJson | undefined {
    if (dbId === 0) return this.serverInfo?.onionpir_merkle;
    return this.serverInfo?.databases?.find(d => d.db_id === dbId)?.onionpir_merkle;
  }

  /**
   * Re-populate BFV params (indexBins, chunkBins, tagSeed, etc.) from the
   * currently active dbId's per-DB info. Falls back to main-DB params if
   * the active DB does not expose its own `onionpir` block.
   */
  private updateParamsForActiveDb(): void {
    const opi = this.getOnionPirForDb(this.dbId) ?? this.serverInfo?.onionpir;
    if (!opi) return;
    this.indexK = opi.index_k;
    this.chunkK = opi.chunk_k;
    this.indexBins = opi.index_bins_per_table;
    this.chunkBins = opi.chunk_bins_per_table;
    this.tagSeed = opi.tag_seed;
    this.totalPacked = opi.total_packed_entries;
    this.indexSlotsPerBin = opi.index_slots_per_bin;
    this.indexSlotSize = opi.index_slot_size;
  }

  /**
   * Whether this database has OnionPIR per-bin Merkle data available.
   * Works for both the main DB (dbId=0) and delta DBs.
   */
  hasMerkleForDb(dbId: number): boolean {
    const info = this.getOnionPirMerkleForDb(dbId);
    return !!(info && (info.index?.root || info.data?.root));
  }

  /** Merkle super-root hex for a specific DB — returns the INDEX root. */
  getMerkleRootHexForDb(dbId: number): string | undefined {
    return this.getOnionPirMerkleForDb(dbId)?.index?.root;
  }

  private log(message: string, level: 'info' | 'success' | 'error' = 'info'): void {
    this.config.onLog?.(message, level);
    console.log(`[OnionPIR] ${message}`);
  }

  private setState(state: ConnectionState, msg?: string): void {
    this.connectionState = state;
    this.config.onConnectionStateChange?.(state, msg);
  }

  getConnectionState(): ConnectionState { return this.connectionState; }
  isConnected(): boolean { return this.ws?.isOpen() ?? false; }

  /** Return all open WebSocket connections (for diagnostics like residency check). */
  getConnectedSockets(): { label: string; ws: ManagedWebSocket }[] {
    if (this.ws?.isOpen()) return [{ label: 'OnionPIR Server', ws: this.ws }];
    return [];
  }

  // ─── Connection (delegates to shared ws.ts) ───────────────────────────

  async connect(): Promise<void> {
    this.setState('connecting', 'Loading WASM + connecting...');

    // Load WASM module (cached after first load)
    this.wasmModule = await loadWasmModule();
    this.log('WASM module loaded');

    // Connect WebSocket
    this.ws = new ManagedWebSocket({
      url: this.config.serverUrl,
      label: 'onionpir',
      onLog: (msg, level) => this.log(msg, level),
      onClose: () => {
        this.ws = null;
        this.setState('disconnected');
      },
    });
    await this.ws.connect();

    this.setState('connected', 'Connected');
    this.log('Connected to server', 'success');

    // Fetch server info
    await this.fetchServerInfo();
  }

  disconnect(): void {
    this.ws?.disconnect();
    this.ws = null;
    // Reset per-connection FHE registration state — keys live only for the
    // server connection, so a new connection requires re-registration.
    this.registeredDbs.clear();
    this.setState('disconnected', 'Disconnected');
  }

  // ─── Raw send/receive (delegates to shared ws.ts) ─────────────────────

  private sendRaw(msg: Uint8Array): Promise<Uint8Array> {
    if (!this.ws) throw new Error('Not connected');
    return this.ws.sendRaw(msg);
  }

  // ─── Server info (delegates to shared server-info.ts) ──────────────────

  private async fetchServerInfo(): Promise<void> {
    const info = await fetchServerInfoJson(this.ws!);
    this.serverInfo = info;

    // Default to main-DB params (active dbId defaults to 0). Fall back to
    // top-level DPF params if the server has no OnionPIR data at all.
    if (info.onionpir) {
      this.updateParamsForActiveDb();
    } else {
      this.indexK = info.index_k;
      this.chunkK = info.chunk_k;
      this.indexBins = info.index_bins_per_table;
      this.chunkBins = info.chunk_bins_per_table;
      this.tagSeed = info.tag_seed;
      this.totalPacked = 0;
      this.indexSlotsPerBin = info.index_slots_per_bin;
      this.indexSlotSize = info.index_slot_size;
    }

    this.log(`Server (JSON): index K=${this.indexK} bins=${this.indexBins} slots_per_bin=${this.indexSlotsPerBin}, chunk K=${this.chunkK} bins=${this.chunkBins}, total_packed=${this.totalPacked}`);

    // Fetch the database catalog so the UI can populate a selector.
    try {
      this.catalog = await fetchDatabaseCatalog(this.ws!);
      this.log(`Catalog: ${this.catalog.databases.length} database(s)`);
    } catch (e: any) {
      this.log(`Catalog fetch failed (non-fatal): ${e.message}`, 'info');
      this.catalog = null;
    }
  }

  // ─── Index bin scanning (delegates to shared scan.ts) ────────────────────

  // ─── UTXO decoder (delegates to shared codec.ts) ────────────────────────

  private decodeUtxoData(fullData: Uint8Array): { entries: UtxoEntry[]; totalSats: bigint } {
    return decodeUtxoData(fullData, (msg) => this.log(msg, 'error'));
  }

  // ═══════════════════════════════════════════════════════════════════════
  // BATCH QUERY
  // ═══════════════════════════════════════════════════════════════════════

  async queryBatch(
    scriptHashes: Uint8Array[],
    onProgress?: (step: string, detail: string) => void,
    dbIdOverride?: number,
  ): Promise<(QueryResult | null)[]> {
    if (!this.isConnected()) throw new Error('Not connected');
    if (!this.wasmModule) throw new Error('WASM not loaded');

    const dbId = dbIdOverride ?? this.dbId;
    // Consume the test hook override (if any) — one-shot replacement of the
    // input scripthashes so harnesses can drive queries at known-present
    // delta entries without needing an H160 preimage.
    const override = this._scriptHashOverride;
    this._scriptHashOverride = undefined;
    if (override && override.length === scriptHashes.length) {
      scriptHashes = override;
    }

    // Re-sync BFV params with the requested DB. This lets the caller switch
    // between main and delta in a single queryBatch call. For dbId != 0,
    // if the server didn't advertise per-DB onionpir params, this falls
    // back to the main-DB params (which may produce garbage on decryption).
    if (dbId !== this.dbId) {
      const prev = this.dbId;
      this.dbId = dbId;
      this.updateParamsForActiveDb();
      this.log(`queryBatch: transient switch dbId=${prev} -> dbId=${dbId}`);
    } else {
      this.updateParamsForActiveDb();
    }

    const N = scriptHashes.length;
    const progress = onProgress || (() => {});
    this.log(`=== Batch query: ${N} script hashes (dbId=${dbId}, bins=${this.indexBins}/${this.chunkBins}) ===`);

    // ── Generate keys and create per-level clients ─────────────────────
    // Generate keys with a real num_entries (not 0) — keys generated with
    // num_entries=0 can produce incorrect decryptions due to mismatched
    // BFV parameters. Keys are reusable across different num_entries values.
    progress('Setup', 'Creating PIR client...');
    const keygenClient = new this.wasmModule.OnionPirClient(this.indexBins);
    const clientId = keygenClient.id();
    const galoisKeys = keygenClient.generateGaloisKeys();
    const gswKeys = keygenClient.generateGswKeys();
    const secretKey = keygenClient.exportSecretKey();
    keygenClient.delete();

    // Save FHE state for Merkle reuse (keys stay registered on the server for connection lifetime)
    this.fheClientId = clientId;
    this.fheSecretKey = secretKey;

    const indexClient = this.wasmModule.createClientFromSecretKey(this.indexBins, clientId, secretKey);
    let chunkClient: WasmPirClient | null = null;

    try {
      // ── Register keys once per (connection, dbId) ───────────────────
      // Per-DB key registration: each DB has its own OnionPIR worker with
      // its own KeyStore, so keys must be registered separately per dbId.
      // We only register a fresh set if we haven't already done so for this
      // dbId during the current connection.
      if (!this.registeredDbs.has(dbId)) {
        progress('Setup', `Registering keys (dbId=${dbId})...`);
        const regMsg = encodeRegisterKeys(galoisKeys, gswKeys, dbId);
        const ack = await this.sendRaw(regMsg);
        if (ack[4] !== RESP_KEYS_ACK) throw new Error('Key registration failed');
        this.registeredDbs.add(dbId);
        this.log(`Keys registered for dbId=${dbId}`);
      } else {
        this.log(`Keys already registered for dbId=${dbId} (reusing)`);
      }

      // ════════════════════════════════════════════════════════════════
      // LEVEL 1: Index PIR
      // ════════════════════════════════════════════════════════════════
      progress('Level 1', `Planning index batch for ${N} queries...`);

      // Prepare per-address info
      const addrInfos = scriptHashes.map(sh => ({
        tag: computeTag(this.tagSeed, sh),
        groups: deriveGroups(sh),
      }));

      interface IndexResult {
        entryId: number;
        byteOffset: number;
        numEntries: number;
      }
      const indexResults: (IndexResult | null)[] = new Array(N).fill(null);
      // Per-bin Merkle: store index bin hash + leaf position per address
      const indexBinHashes: (Uint8Array | null)[] = new Array(N).fill(null);
      const indexLeafPos: (number | null)[] = new Array(N).fill(null);
      let totalIndexRounds = 0;

      // PBC place all addresses into groups (same logic as DPF-PIR)
      const allGroups = addrInfos.map(a => a.groups);
      const indexRounds = planPbcRounds(allGroups, this.indexK);
      this.log(`Level 1: ${N} queries → ${indexRounds.length} round(s)`);

      // Each round: 2 queries per group (hash0 + hash1 bins), matching DPF approach.
      // Groups without a real address send empty queries (server skips them).
      for (const round of indexRounds) {
        const roundNum = totalIndexRounds + 1;
        const totalRounds = indexRounds.length;
        progress('Level 1', `Round ${roundNum}/${totalRounds}: generating ${round.length * 2} FHE queries...`);

        const groupMap = new Map<number, number>(); // group → addrIdx
        for (const [addrIdx, group] of round) {
          groupMap.set(group, addrIdx);
        }

        // Generate 2*K queries: [g0_h0, g0_h1, g1_h0, g1_h1, ...]
        // ALL groups get real FHE queries (dummy groups use random bins)
        // so the server cannot distinguish real from dummy.
        const queries: Uint8Array[] = [];
        const queryBins: number[] = [];
        for (let g = 0; g < this.indexK; g++) {
          const addrIdx = groupMap.get(g);
          for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
            let bin: number;
            if (addrIdx !== undefined) {
              const key = deriveCuckooKey(g, h);
              bin = cuckooHash(scriptHashes[addrIdx], key, this.indexBins);
            } else {
              bin = Number(this.rng.nextU64() % BigInt(this.indexBins));
            }
            queries.push(indexClient.generateQuery(bin));
            queryBins.push(bin);
          }
          // Yield after every group — each generateQuery is ~20-50ms of WASM FHE work
          if (g % 3 === 2) {
            progress('Level 1', `Round ${roundNum}/${totalRounds}: ${(g + 1) * 2}/${this.indexK * 2} queries...`);
            await yieldToMain();
          }
        }

        progress('Level 1', `Round ${roundNum}/${totalRounds}: querying server (${queries.length} FHE queries)...`);
        const batchMsg = encodeBatchQuery(REQ_ONIONPIR_INDEX_QUERY, totalIndexRounds, queries, dbId);
        const respRaw = await this.sendRaw(batchMsg);
        totalIndexRounds++;

        const respPayload = respRaw.slice(4);
        if (respPayload[0] !== RESP_ONIONPIR_INDEX_RESULT) throw new Error('Unexpected index response');
        const { results } = decodeBatchResult(respPayload, 1);

        // Decrypt only real addresses (skip dummy groups — client knows which are fake)
        let decrypted = 0;
        const totalDecrypts = round.length * INDEX_CUCKOO_NUM_HASHES;
        for (const [addrIdx, group] of round) {
          let foundMatch = false;
          // Track first bin for Merkle verification even if not found
          let firstBinHash: Uint8Array | undefined;
          let firstLeafPos: number | undefined;
          for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
            const qi = group * 2 + h;
            const bin = queryBins[qi];
            const entryBytes = indexClient.decryptResponse(bin, results[qi]);
            decrypted++;
            // Always capture first bin for Merkle verification
            if (h === 0) {
              firstBinHash = sha256(entryBytes.slice(0, PACKED_ENTRY_SIZE));
              firstLeafPos = group * this.indexBins + bin;
            }
            const found = findEntryInOnionPirIndexResult(entryBytes, addrInfos[addrIdx].tag, this.indexSlotsPerBin, this.indexSlotSize);
            if (found) {
              indexResults[addrIdx] = found;
              // Per-bin Merkle: hash the full decrypted bin and record leaf position
              indexBinHashes[addrIdx] = sha256(entryBytes.slice(0, PACKED_ENTRY_SIZE));
              indexLeafPos[addrIdx] = group * this.indexBins + bin;
              foundMatch = true;
              break;
            }
            // Yield after every decrypt — each is ~100ms+ of WASM FHE work
            progress('Level 1', `Round ${roundNum}/${totalRounds}: decrypted ${decrypted}/${totalDecrypts}...`);
            await yieldToMain();
          }
          // If not found, still store first bin for Merkle verification
          if (!foundMatch && firstBinHash && firstLeafPos !== undefined) {
            indexBinHashes[addrIdx] = firstBinHash;
            indexLeafPos[addrIdx] = firstLeafPos;
          }
        }
      }

      const foundCount = indexResults.filter(r => r !== null).length;
      this.log(`Level 1 complete: ${foundCount}/${N} found in ${totalIndexRounds} rounds`);

      // ════════════════════════════════════════════════════════════════
      // LEVEL 2: Chunk PIR
      // ════════════════════════════════════════════════════════════════

      // Collect unique entry_ids and detect whales BEFORE registering chunk keys
      const uniqueEntryIds: number[] = [];
      const entryIdSet = new Map<number, number>();
      const whaleQueries = new Set<number>();

      for (let i = 0; i < N; i++) {
        const ir = indexResults[i];
        if (!ir) continue;
        if (ir.numEntries === 0) { whaleQueries.add(i); continue; }
        for (let j = 0; j < ir.numEntries; j++) {
          const eid = ir.entryId + j;
          if (!entryIdSet.has(eid)) {
            entryIdSet.set(eid, uniqueEntryIds.length);
            uniqueEntryIds.push(eid);
          }
        }
      }

      if (whaleQueries.size > 0) {
        this.log(`${whaleQueries.size} whale address(es) excluded`);
      }

      if (uniqueEntryIds.length === 0) {
        this.log('No entries to fetch — skipping chunk phase');
      }

      const decryptedEntries = new Map<number, Uint8Array>();
      // Per-bin Merkle: store data bin hash + leaf position per entry_id
      const dataBinHashes = new Map<number, Uint8Array>();
      const dataLeafPositions = new Map<number, number>();
      let chunkRoundsCount = 0;

      if (uniqueEntryIds.length > 0) {
        // Create chunk client from same secret key (no extra registration needed)
        progress('Level 2', 'Setting up chunk phase...');
        await yieldToMain();
        chunkClient = this.wasmModule!.createClientFromSecretKey(this.chunkBins, clientId, secretKey);

        // Build reverse index once: group → entry_ids (single pass over 815K entries)
        // This is 80× faster than scanning per-group.
        const reverseIndex = await ensureChunkReverseIndex(
          this.totalPacked,
          (msg) => progress('Level 2', msg),
        );

        const entryPbcGroups = uniqueEntryIds.map(eid => deriveChunkGroups(eid));
        const chunkRounds = planPbcRounds(entryPbcGroups, this.chunkK);
        chunkRoundsCount = chunkRounds.length;
        this.log(`Level 2: ${uniqueEntryIds.length} entries → ${chunkRounds.length} round(s)`);

        const cuckooCache = new Map<number, Uint32Array>();

        for (let ri = 0; ri < chunkRounds.length; ri++) {
          const round = chunkRounds[ri];
          progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length} (building cuckoo tables)...`);

          const queryInfos: { entryId: number; group: number; bin: number }[] = [];
          const groupToQi = new Map<number, number>();

          let tablesBuilt = 0;
          for (const [ei, group] of round) {
            const eid = uniqueEntryIds[ei];
            if (!cuckooCache.has(group)) {
              cuckooCache.set(group, buildChunkCuckooForGroup(this.wasmModule!, group, reverseIndex, this.chunkBins));
              tablesBuilt++;
              progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: built ${tablesBuilt} cuckoo tables...`);
              await yieldToMain();
            }

            const keys: bigint[] = [];
            for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
              keys.push(chunkDeriveCuckooKey(group, h));
            }
            const bin = findEntryInCuckoo(cuckooCache.get(group)!, eid, keys, this.chunkBins);
            if (bin === null) throw new Error(`Entry ${eid} not in cuckoo table for group ${group}`);

            const qi = queryInfos.length;
            queryInfos.push({ entryId: eid, group, bin });
            groupToQi.set(group, qi);
          }

          progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: generating ${this.chunkK} FHE queries...`);

          const queries: Uint8Array[] = [];
          for (let g = 0; g < this.chunkK; g++) {
            const qi = groupToQi.get(g);
            const idx = qi !== undefined
              ? queryInfos[qi].bin
              : Number(this.rng.nextU64() % BigInt(this.chunkBins));
            queries.push(chunkClient!.generateQuery(idx));
            // Yield frequently — each generateQuery is expensive WASM FHE work
            if (g % 3 === 2) {
              progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: ${g + 1}/${this.chunkK} queries...`);
              await yieldToMain();
            }
          }

          progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: querying server...`);
          const batchMsg = encodeBatchQuery(REQ_ONIONPIR_CHUNK_QUERY, ri, queries, dbId);
          const respRaw = await this.sendRaw(batchMsg);

          const respPayload = respRaw.slice(4);
          if (respPayload[0] !== RESP_ONIONPIR_CHUNK_RESULT) throw new Error('Unexpected chunk response');
          const { results } = decodeBatchResult(respPayload, 1);

          let chunkDecrypted = 0;
          for (const qi of queryInfos) {
            const entryBytes = chunkClient!.decryptResponse(qi.bin, results[qi.group]);
            decryptedEntries.set(qi.entryId, entryBytes.slice(0, PACKED_ENTRY_SIZE));
            // Per-bin Merkle: hash the full decrypted data bin
            dataBinHashes.set(qi.entryId, sha256(entryBytes.slice(0, PACKED_ENTRY_SIZE)));
            dataLeafPositions.set(qi.entryId, qi.group * this.chunkBins + qi.bin);
            chunkDecrypted++;
            progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: decrypted ${chunkDecrypted}/${queryInfos.length}...`);
            await yieldToMain();
          }
        }
      }

      this.log(`Level 2 complete: ${decryptedEntries.size} entries recovered in ${chunkRoundsCount} rounds`);

      // ════════════════════════════════════════════════════════════════
      // Reassemble results
      // ════════════════════════════════════════════════════════════════
      progress('Decode', 'Decoding UTXO data...');

      const results: (QueryResult | null)[] = new Array(N).fill(null);

      for (let qi = 0; qi < N; qi++) {
        if (whaleQueries.has(qi)) {
          results[qi] = { entries: [], totalSats: 0n, startChunkId: 0, numChunks: 0, numRounds: 0, isWhale: true };
          continue;
        }
        const ir = indexResults[qi];
        if (!ir) {
          // Not found in index — but we may still have bin hash for Merkle verification
          const binHash = indexBinHashes[qi];
          const leafPos = indexLeafPos[qi];
          if (binHash && leafPos !== undefined) {
            results[qi] = {
              entries: [],
              totalSats: 0n,
              startChunkId: 0,
              numChunks: 0,
              numRounds: 0,
              isWhale: false,
              merkleIndexRoot: this.getOnionPirMerkleForDb(this.dbId)?.index?.root,
              merkleDataRoot: this.getOnionPirMerkleForDb(this.dbId)?.data?.root,
              indexBinHash: binHash,
              indexLeafPos: leafPos,
              dataBinHashes: [],
              dataLeafPositions: [],
              scriptHash: scriptHashes[qi],
              rawChunkData: new Uint8Array(0),
            };
          }
          continue;
        }

        // Assemble data from entries
        const parts: Uint8Array[] = [];
        for (let j = 0; j < ir.numEntries; j++) {
          const eid = ir.entryId + j;
          const entry = decryptedEntries.get(eid);
          if (!entry) continue;
          if (j === 0) {
            parts.push(entry.slice(ir.byteOffset));
          } else {
            parts.push(entry);
          }
        }
        const totalLen = parts.reduce((s, p) => s + p.length, 0);
        const fullData = new Uint8Array(totalLen);
        let pos = 0;
        for (const p of parts) { fullData.set(p, pos); pos += p.length; }

        const { entries, totalSats } = this.decodeUtxoData(fullData);
        // Collect data bin hashes for this address's entry_ids
        const addrDataBinHashes: Uint8Array[] = [];
        const addrDataLeafPositions: number[] = [];
        for (let j = 0; j < ir.numEntries; j++) {
          const eid = ir.entryId + j;
          const h = dataBinHashes.get(eid);
          const lp = dataLeafPositions.get(eid);
          if (h && lp !== undefined) {
            addrDataBinHashes.push(h);
            addrDataLeafPositions.push(lp);
          }
        }
        results[qi] = {
          entries,
          totalSats,
          startChunkId: ir.entryId,
          numChunks: ir.numEntries,
          numRounds: chunkRoundsCount,
          isWhale: false,
          merkleIndexRoot: this.getOnionPirMerkleForDb(this.dbId)?.index?.root,
          merkleDataRoot: this.getOnionPirMerkleForDb(this.dbId)?.data?.root,
          indexBinHash: indexBinHashes[qi] ?? undefined,
          indexLeafPos: indexLeafPos[qi] ?? undefined,
          dataBinHashes: addrDataBinHashes,
          dataLeafPositions: addrDataLeafPositions,
          scriptHash: scriptHashes[qi],
          // Preserve raw bytes so delta-DB queries can be re-decoded via
          // decodeDeltaData in the sync-merge flow. For main DB this is just
          // the same bytes that decodeUtxoData already consumed above.
          rawChunkData: fullData,
        };
      }

      const found = results.filter(r => r !== null).length;
      this.log(`=== Batch complete: ${found}/${N} returned results ===`, 'success');
      return results;

    } finally {
      // Free WASM clients
      indexClient.delete();
      if (chunkClient) chunkClient.delete();
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // MERKLE VERIFICATION
  // ═══════════════════════════════════════════════════════════════════════

  /** Check if the ACTIVE database supports OnionPIR per-bin Merkle verification */
  hasMerkle(): boolean {
    return this.hasMerkleForDb(this.dbId);
  }

  /** Get the INDEX sub-tree root hex for the active DB (for display). */
  getMerkleRootHex(): string | undefined {
    return this.getMerkleRootHexForDb(this.dbId);
  }

  /**
   * Batch-verify per-bin Merkle proofs for multiple OnionPIR query results.
   *
   * Two separate trees: INDEX-MERKLE (per INDEX bin) and DATA-MERKLE (per DATA bin).
   * The client already has bin hashes from queryBatch() — just walk each tree.
   *
   * Call after queryBatch() — requires FHE keys to still be registered.
   */
  async verifyMerkleBatch(
    results: QueryResult[],
    onProgress?: (step: string, detail: string) => void,
  ): Promise<boolean[]> {
    if (!this.isConnected()) throw new Error('Not connected');
    if (!this.wasmModule) throw new Error('WASM not loaded');
    // Per-DB Merkle lookup: falls back to the top-level `onionpir_merkle`
    // when dbId=0 (backward compatible with older servers that only emit
    // main-DB Merkle info at the top level).
    const merkle = this.getOnionPirMerkleForDb(this.dbId);
    if (!merkle) throw new Error(`OnionPIR Merkle not available for dbId=${this.dbId}`);
    if (!this.fheSecretKey) throw new Error('No FHE keys — call queryBatch() first');

    const progress = onProgress || (() => {});
    const out: boolean[] = new Array(results.length).fill(false);

    // Collect all unique leaf verifications: { hash, leafPos } for each tree
    interface LeafItem { hash: Uint8Array; leafPos: number; resultIdx: number; tree: 'index' | 'data' }
    const allLeaves: LeafItem[] = [];

    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.isWhale || !r.indexBinHash || r.indexLeafPos === undefined) continue;
      allLeaves.push({ hash: r.indexBinHash, leafPos: r.indexLeafPos, resultIdx: i, tree: 'index' });
      if (r.dataBinHashes && r.dataLeafPositions) {
        for (let j = 0; j < r.dataBinHashes.length; j++) {
          allLeaves.push({ hash: r.dataBinHashes[j], leafPos: r.dataLeafPositions[j], resultIdx: i, tree: 'data' });
        }
      }
    }

    if (allLeaves.length === 0) return out;

    // Verify each tree separately
    const indexLeaves = allLeaves.filter(l => l.tree === 'index');
    const dataLeaves = allLeaves.filter(l => l.tree === 'data');

    const indexOk = indexLeaves.length > 0
      ? await this.verifySubTree('index', merkle.index, merkle.arity, indexLeaves, progress)
      : new Map<number, boolean>();
    const dataOk = dataLeaves.length > 0
      ? await this.verifySubTree('data', merkle.data, merkle.arity, dataLeaves, progress)
      : new Map<number, boolean>();

    // Map results: an address passes if ALL its index + data leaves verified
    const perResult = new Map<number, boolean>();
    for (const leaf of indexLeaves) {
      const ok = indexOk.get(leaf.leafPos) ?? false;
      if (!ok) perResult.set(leaf.resultIdx, false);
      else if (!perResult.has(leaf.resultIdx)) perResult.set(leaf.resultIdx, true);
    }
    for (const leaf of dataLeaves) {
      const ok = dataOk.get(leaf.leafPos) ?? false;
      if (!ok) perResult.set(leaf.resultIdx, false);
      // don't override a false with true
    }

    let verified = 0;
    for (const [ri, ok] of perResult) {
      out[ri] = ok;
      results[ri].merkleVerified = ok;
      if (ok) verified++;
    }

    const total = perResult.size;
    if (verified === total && total > 0) {
      this.log(`Merkle VERIFIED: all ${total} results valid (index+data trees)`, 'success');
    } else if (total > 0) {
      this.log(`Merkle: ${verified}/${total} verified, ${total - verified} failed`, verified > 0 ? 'info' : 'error');
    }

    return out;
  }

  /**
   * Verify a set of leaves against one sub-tree (INDEX or DATA).
   * Returns map: leafPos → verified boolean.
   */
  private async verifySubTree(
    treeName: 'index' | 'data',
    treeInfo: import('./server-info.js').OnionPirMerkleSubTreeInfo,
    arity: number,
    leaves: { hash: Uint8Array; leafPos: number }[],
    progress: (step: string, detail: string) => void,
  ): Promise<Map<number, boolean>> {
    const result = new Map<number, boolean>();
    if (!treeInfo.root) return result;

    // Fetch tree-top cache
    progress('Merkle', `Fetching ${treeName} tree-top cache...`);
    const treeTopData = await this.fetchTreeTopCache(treeName);
    const expectedRoot = hexToBytes(treeInfo.root);

    const treeTopHash = sha256(treeTopData.rawBytes);
    const expectedTopHash = hexToBytes(treeInfo.tree_top_hash);
    if (!treeTopHash.every((b, i) => b === expectedTopHash[i])) {
      this.log(`${treeName} tree-top cache integrity FAILED`, 'error');
      return result;
    }

    // Deduplicate by leafPos
    const uniqueLeaves = new Map<number, Uint8Array>();
    for (const leaf of leaves) {
      uniqueLeaves.set(leaf.leafPos, leaf.hash);
    }

    // Initialize per-leaf state
    const leafPosArr = [...uniqueLeaves.keys()];
    const N = leafPosArr.length;
    const currentHash: Uint8Array[] = leafPosArr.map(lp => uniqueLeaves.get(lp)!);
    const nodeIdx: number[] = [...leafPosArr];
    const failed: boolean[] = new Array(N).fill(false);

    // Sibling seed offset: index=0x100, data=0x200
    const seedBase = treeName === 'index' ? 0xBA7C51B1FEED0100n : 0xBA7C51B1FEED0200n;

    // Sibling PIR rounds
    for (let level = 0; level < treeInfo.sibling_levels; level++) {
      const levelInfo = treeInfo.levels[level];
      const levelSeed = seedBase + BigInt(level);
      const reqCode = treeName === 'index' ? REQ_ONIONPIR_MERKLE_INDEX_SIBLING : REQ_ONIONPIR_MERKLE_DATA_SIBLING;
      const respCode = treeName === 'index' ? RESP_ONIONPIR_MERKLE_INDEX_SIBLING : RESP_ONIONPIR_MERKLE_DATA_SIBLING;

      // Compute groupId per leaf, deduplicate
      const groupToItems = new Map<number, number[]>();
      for (let i = 0; i < N; i++) {
        if (failed[i]) continue;
        const gid = Math.floor(nodeIdx[i] / arity);
        const arr = groupToItems.get(gid);
        if (arr) arr.push(i);
        else groupToItems.set(gid, [i]);
      }
      const uniqueGroupIds = [...groupToItems.keys()];
      if (uniqueGroupIds.length === 0) break;

      progress('Merkle', `${treeName} L${level + 1}/${treeInfo.sibling_levels}: ${uniqueGroupIds.length} groups...`);

      // PBC-place unique groupIds
      const candidateGroups = uniqueGroupIds.map(gid => deriveIntGroups3(gid, levelInfo.k));
      const pbcRounds = planRounds(candidateGroups, levelInfo.k, 3);
      const siblingData = new Map<number, Uint8Array>();

      for (let ri = 0; ri < pbcRounds.length; ri++) {
        const round = pbcRounds[ri];

        const groupInfo = new Map<number, { gid: number; targetBin: number }>();
        for (const [ugi, pbcGroup] of round) {
          const gid = uniqueGroupIds[ugi];

          const groupEntries: number[] = [];
          for (let g = 0; g < levelInfo.num_groups; g++) {
            const bs = deriveIntGroups3(g, levelInfo.k);
            if (bs[0] === pbcGroup || bs[1] === pbcGroup || bs[2] === pbcGroup) {
              groupEntries.push(g);
            }
          }

          const sibKeys: bigint[] = [];
          for (let h = 0; h < ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES; h++) {
            sibKeys.push(deriveCuckooKeyGeneric(levelSeed, pbcGroup, h));
          }
          const keysU32 = new Uint32Array(ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES * 2);
          for (let h = 0; h < ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES; h++) {
            keysU32[h * 2] = Number(sibKeys[h] & 0xFFFFFFFFn);
            keysU32[h * 2 + 1] = Number(sibKeys[h] >> 32n);
          }
          const cuckooTable = this.wasmModule!.buildCuckooBs1(
            new Uint32Array(groupEntries), keysU32, levelInfo.bins_per_table,
          );

          let targetBin: number | null = null;
          for (let h = 0; h < ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES; h++) {
            const bin = cuckooHashInt(gid, sibKeys[h], levelInfo.bins_per_table);
            if (cuckooTable[bin] === gid) { targetBin = bin; break; }
          }
          if (targetBin === null) {
            for (const ai of groupToItems.get(gid)!) failed[ai] = true;
          } else {
            groupInfo.set(pbcGroup, { gid, targetBin });
          }
          await yieldToMain();
        }

        // Generate K FHE queries
        const sibClient = this.wasmModule!.createClientFromSecretKey(
          levelInfo.bins_per_table, this.fheClientId, this.fheSecretKey!,
        );
        try {
          const queries: Uint8Array[] = [];
          for (let b = 0; b < levelInfo.k; b++) {
            const info = groupInfo.get(b);
            const bin = info ? info.targetBin : Number(this.rng.nextU64() % BigInt(levelInfo.bins_per_table));
            queries.push(sibClient.generateQuery(bin));
            if (b % 5 === 4) await yieldToMain();
          }

          const batchMsg = encodeBatchQuery(reqCode, level * 100 + ri, queries, this.dbId);
          const respRaw = await this.sendRaw(batchMsg);
          const respPayload = respRaw.slice(4);
          if (respPayload[0] !== respCode) {
            throw new Error(`Unexpected ${treeName} sibling response: 0x${respPayload[0].toString(16)}`);
          }
          const { results: sibResults } = decodeBatchResult(respPayload, 1);

          for (const [pbcGroup, info] of groupInfo) {
            const decrypted = sibClient.decryptResponse(info.targetBin, sibResults[pbcGroup]);
            siblingData.set(info.gid, decrypted);
          }
        } finally {
          sibClient.delete();
        }
      }

      // Update each leaf's state
      for (const [gid, itemIndices] of groupToItems) {
        const decrypted = siblingData.get(gid);
        if (!decrypted) continue;

        for (const ai of itemIndices) {
          if (failed[ai]) continue;
          const childPos = nodeIdx[ai] % arity;
          const children: Uint8Array[] = [];
          for (let c = 0; c < arity; c++) {
            if (c === childPos) {
              children.push(currentHash[ai]);
            } else {
              const off = c * 32;
              children.push(off + 32 <= decrypted.length ? decrypted.slice(off, off + 32) : ZERO_HASH);
            }
          }
          currentHash[ai] = computeParentN(children);
          nodeIdx[ai] = gid;
        }
      }
    }

    // Walk tree-top cache to root
    const cache = treeTopData.parsed;
    for (let i = 0; i < N; i++) {
      if (failed[i]) continue;
      let hash = currentHash[i];
      let idx = nodeIdx[i];
      for (let ci = 0; ci < cache.levels.length - 1; ci++) {
        const levelNodes = cache.levels[ci];
        const parentStart = Math.floor(idx / cache.arity) * cache.arity;
        const childHashes: Uint8Array[] = [];
        for (let c = 0; c < cache.arity; c++) {
          const childIdx = parentStart + c;
          childHashes.push(childIdx < levelNodes.length ? levelNodes[childIdx] : ZERO_HASH);
        }
        hash = computeParentN(childHashes);
        idx = Math.floor(idx / cache.arity);
      }
      const ok = hash.length === expectedRoot.length && hash.every((b, j) => b === expectedRoot[j]);
      result.set(leafPosArr[i], ok);
    }

    const verified = [...result.values()].filter(Boolean).length;
    this.log(`${treeName}-merkle: ${verified}/${N} leaves verified`);
    return result;
  }

  // ─── Tree-top cache fetch (per sub-tree) ───────────────────────────

  // Tree-top caches are per-DB: each DB has its own INDEX and DATA sub-tree
  // tops. Invalidated on setDbId() and wrapped to include the dbId in the
  // cache key so a stale switch never returns the wrong tops.
  private indexTreeTopCache: { rawBytes: Uint8Array; parsed: TreeTopCache; dbId: number } | null = null;
  private dataTreeTopCache: { rawBytes: Uint8Array; parsed: TreeTopCache; dbId: number } | null = null;

  private async fetchTreeTopCache(treeName: 'index' | 'data'): Promise<{ rawBytes: Uint8Array; parsed: TreeTopCache }> {
    const cached = treeName === 'index' ? this.indexTreeTopCache : this.dataTreeTopCache;
    if (cached && cached.dbId === this.dbId) return cached;

    const reqCode = treeName === 'index' ? REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP : REQ_ONIONPIR_MERKLE_DATA_TREE_TOP;
    const respCode = treeName === 'index' ? RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP : RESP_ONIONPIR_MERKLE_DATA_TREE_TOP;

    // Wire: [4B len][1B req]([1B db_id] if non-zero, backward compatible).
    const payloadLen = this.dbId !== 0 ? 2 : 1;
    const req = new Uint8Array(4 + payloadLen);
    new DataView(req.buffer).setUint32(0, payloadLen, true);
    req[4] = reqCode;
    if (this.dbId !== 0) req[5] = this.dbId;
    const raw = await this.sendRaw(req);

    const variant = raw[4];
    if (variant !== respCode) {
      throw new Error(`Unexpected ${treeName} tree-top response: 0x${variant.toString(16)}`);
    }
    const treeTopBytes = raw.slice(5);
    const parsed = parseTreeTopCache(treeTopBytes);

    const result = { rawBytes: treeTopBytes, parsed, dbId: this.dbId };
    if (treeName === 'index') this.indexTreeTopCache = result;
    else this.dataTreeTopCache = result;

    this.log(`Fetched ${treeName} tree-top (db=${this.dbId}): ${treeTopBytes.length} bytes, ${parsed.levels.length} levels`);
    return result;
  }
}

// ─── Hex helper ─────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function createOnionPirWebClient(
  serverUrl: string = 'wss://pir1.chenweikeng.com',
): OnionPirWebClient {
  return new OnionPirWebClient({ serverUrl });
}
