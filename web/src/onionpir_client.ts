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
} from './constants.js';

import {
  deriveBuckets, deriveCuckooKey, cuckooHash,
  deriveChunkBuckets,
  splitmix64, computeTag,
} from './hash.js';

import { cuckooPlace, planRounds } from './pbc.js';
import { readVarint, decodeUtxoData, DummyRng } from './codec.js';
import { findEntryInOnionPirIndexResult } from './scan.js';
import { ManagedWebSocket } from './ws.js';
import { fetchServerInfoJson } from './server-info.js';

import type { UtxoEntry, QueryResult, ConnectionState } from './client.js';

// ─── Constants for OnionPIR v2 layout ─────────────────────────────────────

const PACKED_ENTRY_SIZE = 3840;

/** Chunk cuckoo: 6 hash functions, bucket_size=1 */
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
    const buckets = deriveChunkBuckets(eid);
    for (const g of buckets) {
      index.get(g)!.push(eid);
    }
    // Yield periodically — 815K iterations with BigInt hashing
    if (eid % 50000 === 49999) {
      onProgress?.(`Building chunk reverse index: ${eid + 1}/${totalEntries}...`);
      await new Promise(r => setTimeout(r, 0));
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

function encodeRegisterKeys(galoisKeys: Uint8Array, gswKeys: Uint8Array): Uint8Array {
  const payloadLen = 1 + 4 + galoisKeys.length + 4 + gswKeys.length;
  const msg = new Uint8Array(4 + payloadLen);
  const dv = new DataView(msg.buffer);
  dv.setUint32(0, payloadLen, true);
  let pos = 4;
  msg[pos++] = REQ_REGISTER_KEYS;
  dv.setUint32(pos, galoisKeys.length, true); pos += 4;
  msg.set(galoisKeys, pos); pos += galoisKeys.length;
  dv.setUint32(pos, gswKeys.length, true); pos += 4;
  msg.set(gswKeys, pos);
  return msg;
}

function encodeBatchQuery(variant: number, roundId: number, queries: Uint8Array[]): Uint8Array {
  let payloadSize = 1 + 2 + 1; // variant + round_id + num_buckets
  for (const q of queries) payloadSize += 4 + q.length;
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
  return msg;
}

function decodeBatchResult(data: Uint8Array, pos: number): { roundId: number; results: Uint8Array[]; pos: number } {
  const dv = new DataView(data.buffer, data.byteOffset);
  const roundId = dv.getUint16(pos, true); pos += 2;
  const numBuckets = data[pos++];
  const results: Uint8Array[] = [];
  for (let i = 0; i < numBuckets; i++) {
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
  private indexK = 0;
  private chunkK = 0;
  private indexBins = 0;
  private chunkBins = 0;
  private tagSeed = 0n;
  private totalPacked = 0;
  private indexBucketSize = 0;
  private indexSlotSize = 0;

  // WASM module
  private wasmModule: OnionPirModule | null = null;

  constructor(config: OnionPirClientConfig) {
    this.config = config;
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

    if (info.onionpir) {
      // Use OnionPIR-specific parameters
      const opi = info.onionpir;
      this.indexK = opi.index_k;
      this.chunkK = opi.chunk_k;
      this.indexBins = opi.index_bins_per_table;
      this.chunkBins = opi.chunk_bins_per_table;
      this.tagSeed = opi.tag_seed;
      this.totalPacked = opi.total_packed_entries;
      this.indexBucketSize = opi.index_cuckoo_bucket_size;
      this.indexSlotSize = opi.index_slot_size;
    } else {
      // Fallback to top-level DPF params (server without OnionPIR data)
      this.indexK = info.index_k;
      this.chunkK = info.chunk_k;
      this.indexBins = info.index_bins_per_table;
      this.chunkBins = info.chunk_bins_per_table;
      this.tagSeed = info.tag_seed;
      this.totalPacked = 0;
      this.indexBucketSize = info.index_cuckoo_bucket_size;
      this.indexSlotSize = info.index_slot_size;
    }

    this.log(`Server (JSON): index K=${this.indexK} bins=${this.indexBins} bucket_size=${this.indexBucketSize}, chunk K=${this.chunkK} bins=${this.chunkBins}, total_packed=${this.totalPacked}`);
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
  ): Promise<(QueryResult | null)[]> {
    if (!this.isConnected()) throw new Error('Not connected');
    if (!this.wasmModule) throw new Error('WASM not loaded');

    const N = scriptHashes.length;
    const progress = onProgress || (() => {});
    this.log(`=== Batch query: ${N} script hashes ===`);

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

    const indexClient = this.wasmModule.createClientFromSecretKey(this.indexBins, clientId, secretKey);
    let chunkClient: WasmPirClient | null = null;

    try {
      // ── Register keys once (shared across all levels) ────────────
      progress('Setup', 'Registering keys...');
      this.log(`Keys: ${galoisKeys.length + gswKeys.length} bytes`);

      const regMsg = encodeRegisterKeys(galoisKeys, gswKeys);
      const ack = await this.sendRaw(regMsg);
      if (ack[4] !== RESP_KEYS_ACK) throw new Error('Key registration failed');
      this.log('Keys registered (single registration, shared secret key)');

      // ════════════════════════════════════════════════════════════════
      // LEVEL 1: Index PIR
      // ════════════════════════════════════════════════════════════════
      progress('Level 1', `Planning index batch for ${N} queries...`);

      // Prepare per-address info
      const addrInfos = scriptHashes.map(sh => ({
        tag: computeTag(this.tagSeed, sh),
        groups: deriveBuckets(sh),
      }));

      interface IndexResult {
        entryId: number;
        byteOffset: number;
        numEntries: number;
      }
      const indexResults: (IndexResult | null)[] = new Array(N).fill(null);
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
            await new Promise(r => setTimeout(r, 0));
          }
        }

        progress('Level 1', `Round ${roundNum}/${totalRounds}: querying server (${queries.length} FHE queries)...`);
        const batchMsg = encodeBatchQuery(REQ_ONIONPIR_INDEX_QUERY, totalIndexRounds, queries);
        const respRaw = await this.sendRaw(batchMsg);
        totalIndexRounds++;

        const respPayload = respRaw.slice(4);
        if (respPayload[0] !== RESP_ONIONPIR_INDEX_RESULT) throw new Error('Unexpected index response');
        const { results } = decodeBatchResult(respPayload, 1);

        // Decrypt only real addresses (skip dummy groups — client knows which are fake)
        let decrypted = 0;
        const totalDecrypts = round.length * INDEX_CUCKOO_NUM_HASHES;
        for (const [addrIdx, group] of round) {
          for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
            const qi = group * 2 + h;
            const bin = queryBins[qi];
            const entryBytes = indexClient.decryptResponse(bin, results[qi]);
            decrypted++;
            const found = findEntryInOnionPirIndexResult(entryBytes, addrInfos[addrIdx].tag, this.indexBucketSize, this.indexSlotSize);
            if (found) {
              indexResults[addrIdx] = found;
              break;
            }
            // Yield after every decrypt — each is ~100ms+ of WASM FHE work
            progress('Level 1', `Round ${roundNum}/${totalRounds}: decrypted ${decrypted}/${totalDecrypts}...`);
            await new Promise(r => setTimeout(r, 0));
          }
        }
      }

      const foundCount = indexResults.filter(r => r !== null).length;
      this.log(`Level 1 complete: ${foundCount}/${N} found in ${totalIndexRounds} rounds`);
      for (let i = 0; i < N; i++) {
        const ir = indexResults[i];
        if (ir) {
          this.log(`  [${i}] entryId=${ir.entryId} byteOffset=${ir.byteOffset} numEntries=${ir.numEntries}`);
        }
      }

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
      let chunkRoundsCount = 0;

      if (uniqueEntryIds.length > 0) {
        // Create chunk client from same secret key (no extra registration needed)
        progress('Level 2', 'Setting up chunk phase...');
        await new Promise(r => setTimeout(r, 0));
        chunkClient = this.wasmModule!.createClientFromSecretKey(this.chunkBins, clientId, secretKey);

        // Build reverse index once: group → entry_ids (single pass over 815K entries)
        // This is 80× faster than scanning per-group.
        const reverseIndex = await ensureChunkReverseIndex(
          this.totalPacked,
          (msg) => progress('Level 2', msg),
        );

        const entryPbcGroups = uniqueEntryIds.map(eid => deriveChunkBuckets(eid));
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
              const t0 = performance.now();
              cuckooCache.set(group, buildChunkCuckooForGroup(this.wasmModule!, group, reverseIndex, this.chunkBins));
              tablesBuilt++;
              this.log(`  Cuckoo table for group ${group}: ${(performance.now() - t0).toFixed(0)}ms`);
              progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: built ${tablesBuilt} cuckoo tables...`);
              await new Promise(r => setTimeout(r, 0));
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
              await new Promise(r => setTimeout(r, 0));
            }
          }

          progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: querying server...`);
          const batchMsg = encodeBatchQuery(REQ_ONIONPIR_CHUNK_QUERY, ri, queries);
          const respRaw = await this.sendRaw(batchMsg);

          const respPayload = respRaw.slice(4);
          if (respPayload[0] !== RESP_ONIONPIR_CHUNK_RESULT) throw new Error('Unexpected chunk response');
          const { results } = decodeBatchResult(respPayload, 1);

          let chunkDecrypted = 0;
          for (const qi of queryInfos) {
            this.log(`  chunk query: entryId=${qi.entryId} group=${qi.group} bin=${qi.bin}`);
            const entryBytes = chunkClient!.decryptResponse(qi.bin, results[qi.group]);
            // Log first 16 bytes of the raw decrypted entry (before byteOffset slicing)
            const rawPreview = Array.from(entryBytes.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
            this.log(`  raw decrypted[0..16]: ${rawPreview} (total ${entryBytes.length} bytes)`);
            decryptedEntries.set(qi.entryId, entryBytes.slice(0, PACKED_ENTRY_SIZE));
            chunkDecrypted++;
            progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length}: decrypted ${chunkDecrypted}/${queryInfos.length}...`);
            await new Promise(r => setTimeout(r, 0));
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
        if (!ir) continue;

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

        this.log(`  [${qi}] assembled ${totalLen} bytes from ${parts.length} entries (byteOffset=${ir.byteOffset})`);
        // Log first few bytes for debugging
        const preview = Array.from(fullData.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        this.log(`  [${qi}] data preview: ${preview}`);

        const { entries, totalSats } = this.decodeUtxoData(fullData);
        results[qi] = {
          entries,
          totalSats,
          startChunkId: ir.entryId,
          numChunks: ir.numEntries,
          numRounds: chunkRoundsCount,
          isWhale: false,
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
}

export function createOnionPirWebClient(
  serverUrl: string = 'wss://pir1.chenweikeng.com',
): OnionPirWebClient {
  return new OnionPirWebClient({ serverUrl });
}
