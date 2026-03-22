/**
 * OnionPIR v2 WebSocket client for browser.
 *
 * Single-server FHE-based PIR using OnionPIRv2 WASM module.
 * Two-level query: index PIR → chunk PIR → decode UTXO data.
 * Multi-address batching via PBC cuckoo placement.
 */

import {
  K, K_CHUNK, NUM_HASHES, INDEX_CUCKOO_NUM_HASHES,
  FLAG_WHALE, CHUNK_MASTER_SEED,
} from './constants.js';

import {
  deriveBuckets, deriveCuckooKey, cuckooHash,
  deriveChunkBuckets,
  splitmix64, computeTag,
} from './hash.js';

import type { UtxoEntry, QueryResult, ConnectionState } from './client.js';

// ─── Constants for OnionPIR v2 layout ─────────────────────────────────────

const PACKED_ENTRY_SIZE = 3840;

/** Chunk cuckoo: 6 hash functions, bucket_size=1 */
const CHUNK_CUCKOO_NUM_HASHES = 6;
const CHUNK_CUCKOO_MAX_KICKS = 10000;
const EMPTY = 0xFFFFFFFF;

const MASK64 = 0xFFFFFFFFFFFFFFFFn;

// ─── OnionPIR wire protocol constants ─────────────────────────────────────

const REQ_PING    = 0x00;
const REQ_GET_INFO = 0x01;
const RESP_INFO   = 0x01;
const RESP_PONG   = 0x00;

const REQ_REGISTER_KEYS         = 0x30;
const REQ_ONIONPIR_INDEX_QUERY  = 0x31;
const REQ_ONIONPIR_CHUNK_QUERY  = 0x32;

const RESP_KEYS_ACK             = 0x30;
const RESP_ONIONPIR_INDEX_RESULT  = 0x31;
const RESP_ONIONPIR_CHUNK_RESULT  = 0x32;

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

/**
 * Build the chunk cuckoo table for a specific group (deterministic).
 * Uses fast U64 arithmetic for the 815K entry scan, WASM for cuckoo insertion.
 */
function buildChunkCuckooForGroup(
  wasmModule: OnionPirModule,
  groupId: number,
  totalEntries: number,
  binsPerTable: number,
): Uint32Array {
  // Collect all entries assigned to this group
  const entries: number[] = [];
  for (let eid = 0; eid < totalEntries; eid++) {
    const buckets = deriveChunkBuckets(eid);
    if (buckets.includes(groupId)) {
      entries.push(eid);
    }
  }
  // entries are already sorted since we iterate eid in order

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

// ─── PBC batch placement ──────────────────────────────────────────────────

function planPbcRounds(
  candidateGroups: number[][],
  k: number,
): [number, number][][] {
  let remaining = candidateGroups.map((_, i) => i);
  const rounds: [number, number][][] = [];

  while (remaining.length > 0) {
    const roundCands = remaining.map(i => candidateGroups[i]);
    const buckets: (number | null)[] = new Array(k).fill(null);
    const placedLocal: number[] = [];

    for (let li = 0; li < roundCands.length; li++) {
      if (placedLocal.length >= k) break;
      const saved = [...buckets];
      if (pbcCuckooPlace(roundCands, buckets, li, 500)) {
        placedLocal.push(li);
      } else {
        for (let b = 0; b < k; b++) buckets[b] = saved[b];
      }
    }

    const round: [number, number][] = [];
    for (let g = 0; g < k; g++) {
      if (buckets[g] !== null) {
        round.push([remaining[buckets[g]!], g]);
      }
    }

    if (round.length === 0) break;

    const placedSet = new Set(placedLocal.map(li => remaining[li]));
    remaining = remaining.filter(i => !placedSet.has(i));
    rounds.push(round);
  }

  return rounds;
}

function pbcCuckooPlace(
  cands: number[][],
  buckets: (number | null)[],
  qi: number,
  maxKicks: number,
): boolean {
  for (const c of cands[qi]) {
    if (buckets[c] === null) {
      buckets[c] = qi;
      return true;
    }
  }

  let currentQi = qi;
  let currentBucket = cands[qi][0];

  for (let kick = 0; kick < maxKicks; kick++) {
    const evictedQi = buckets[currentBucket]!;
    buckets[currentBucket] = currentQi;

    for (let offset = 0; offset < NUM_HASHES; offset++) {
      const c = cands[evictedQi][(kick + offset) % NUM_HASHES];
      if (c === currentBucket) continue;
      if (buckets[c] === null) {
        buckets[c] = evictedQi;
        return true;
      }
    }

    let nextBucket = cands[evictedQi][0];
    for (let offset = 0; offset < NUM_HASHES; offset++) {
      const c = cands[evictedQi][(kick + offset) % NUM_HASHES];
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

// ─── PRNG for dummy queries ───────────────────────────────────────────────

class DummyRng {
  private state: bigint;
  constructor() { this.state = splitmix64(BigInt(Date.now())); }
  nextU64(): bigint {
    this.state = (this.state + 0x9e3779b97f4a7c15n) & MASK64;
    return splitmix64(this.state);
  }
}

// ─── Varint decoder ───────────────────────────────────────────────────────

function readVarint(data: Uint8Array, offset: number): { value: bigint; bytesRead: number } {
  let result = 0n;
  let shift = 0;
  let bytesRead = 0;
  while (true) {
    if (offset + bytesRead >= data.length) throw new Error('Unexpected end of varint');
    const byte = data[offset + bytesRead];
    bytesRead++;
    result |= BigInt(byte & 0x7F) << BigInt(shift);
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift >= 64) throw new Error('Varint too large');
  }
  return { value: result, bytesRead };
}

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
  private ws: WebSocket | null = null;
  private config: OnionPirClientConfig;
  private connectionState: ConnectionState = 'disconnected';
  private rng = new DummyRng();
  private pending: Array<(data: Uint8Array) => void> = [];
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  // Server info
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
  isConnected(): boolean { return this.ws !== null && this.ws.readyState === WebSocket.OPEN; }

  // ─── Connection ───────────────────────────────────────────────────────

  async connect(): Promise<void> {
    this.setState('connecting', 'Loading WASM + connecting...');

    // Load WASM module (cached after first load)
    this.wasmModule = await loadWasmModule();
    this.log('WASM module loaded');

    // Connect WebSocket
    const url = this.config.serverUrl;
    this.log(`Connecting to ${url}`);

    await new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
      ws.onopen = () => {
        this.ws = ws;
        this.pending = [];
        resolve();
      };
      ws.onerror = () => reject(new Error(`Failed to connect to ${url}`));
      ws.onmessage = (event) => {
        const data = new Uint8Array(event.data as ArrayBuffer);
        // Skip pong responses
        if (data.length >= 5) {
          const len = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
          if (len === 1 && data[4] === RESP_PONG) return;
        }
        const cb = this.pending.shift();
        if (cb) cb(data);
      };
      ws.onclose = () => {
        this.ws = null;
        this.stopHeartbeat();
        this.setState('disconnected');
      };
    });

    this.setState('connected', 'Connected');
    this.log('Connected to server', 'success');

    // Fetch server info
    await this.fetchServerInfo();

    // Start heartbeat
    this.heartbeatTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        const ping = new Uint8Array(5);
        new DataView(ping.buffer).setUint32(0, 1, true);
        ping[4] = REQ_PING;
        this.ws.send(ping);
      }
    }, 30000);
  }

  disconnect(): void {
    this.stopHeartbeat();
    this.ws?.close();
    this.ws = null;
    this.pending = [];
    this.setState('disconnected', 'Disconnected');
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) { clearInterval(this.heartbeatTimer); this.heartbeatTimer = null; }
  }

  // ─── Raw send/receive ─────────────────────────────────────────────────

  private sendRaw(msg: Uint8Array): Promise<Uint8Array> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('Not connected');
    }
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        const idx = this.pending.indexOf(cb);
        if (idx !== -1) this.pending.splice(idx, 1);
        reject(new Error('Request timed out'));
      }, 120000);
      const cb = (data: Uint8Array) => { clearTimeout(timeout); resolve(data); };
      this.pending.push(cb);
      this.ws!.send(msg);
    });
  }

  // ─── Server info ──────────────────────────────────────────────────────

  private async fetchServerInfo(): Promise<void> {
    const req = new Uint8Array(5);
    new DataView(req.buffer).setUint32(0, 1, true);
    req[4] = REQ_GET_INFO;
    const raw = await this.sendRaw(req);
    const payload = raw.slice(4); // skip length prefix
    if (payload[0] !== RESP_INFO) throw new Error('Expected Info response');
    const body = payload.slice(1);
    const dv = new DataView(body.buffer, body.byteOffset, body.length);

    this.indexK = body[0];
    this.chunkK = body[1];
    this.indexBins = dv.getUint32(2, true);
    this.chunkBins = dv.getUint32(6, true);
    this.tagSeed = dv.getBigUint64(10, true);
    this.totalPacked = dv.getUint32(18, true);
    this.indexBucketSize = dv.getUint16(22, true);
    this.indexSlotSize = body[24];

    this.log(`Server: index K=${this.indexK} bins=${this.indexBins} bucket_size=${this.indexBucketSize}, chunk K=${this.chunkK} bins=${this.chunkBins}, total_packed=${this.totalPacked}`);
  }

  // ─── Index bin scanning ───────────────────────────────────────────────

  private scanIndexBin(
    entryBytes: Uint8Array,
    tag: bigint,
  ): { entryId: number; byteOffset: number; numEntries: number } | null {
    const dv = new DataView(entryBytes.buffer, entryBytes.byteOffset, entryBytes.length);
    for (let slot = 0; slot < this.indexBucketSize; slot++) {
      const off = slot * this.indexSlotSize;
      if (off + this.indexSlotSize > entryBytes.length) break;
      const slotTag = dv.getBigUint64(off, true);
      if (slotTag === tag && slotTag !== 0n) {
        return {
          entryId: dv.getUint32(off + 8, true),
          byteOffset: dv.getUint16(off + 12, true),
          numEntries: entryBytes[off + 14],
        };
      }
    }
    return null;
  }

  // ─── UTXO decoder ─────────────────────────────────────────────────────

  private decodeUtxoData(fullData: Uint8Array): { entries: UtxoEntry[]; totalSats: bigint } {
    let pos = 0;
    const { value: numEntries, bytesRead: countBytes } = readVarint(fullData, pos);
    pos += countBytes;
    const entries: UtxoEntry[] = [];
    let totalSats = 0n;
    for (let i = 0; i < Number(numEntries); i++) {
      if (pos + 32 > fullData.length) break;
      const txid = fullData.slice(pos, pos + 32);
      pos += 32;
      const { value: vout, bytesRead: vr } = readVarint(fullData, pos);
      pos += vr;
      const { value: amount, bytesRead: ar } = readVarint(fullData, pos);
      pos += ar;
      totalSats += amount;
      entries.push({ txid: new Uint8Array(txid), vout: Number(vout), amount });
    }
    return { entries, totalSats };
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
    // Keys are independent of num_entries. We generate once, export the
    // secret key, then create per-level clients with correct num_entries.
    progress('Setup', 'Creating PIR client...');
    const keygenClient = new this.wasmModule.OnionPirClient(0);
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

      // Each round: 2 queries per group (hash0 + hash1 bins), matching DPF approach
      for (const round of indexRounds) {
        progress('Level 1', `Index round ${totalIndexRounds + 1}/${indexRounds.length}...`);

        const groupMap = new Map<number, number>(); // group → addrIdx
        for (const [addrIdx, group] of round) {
          groupMap.set(group, addrIdx);
        }

        // Generate 2*K queries: [g0_h0, g0_h1, g1_h0, g1_h1, ...]
        const queries: Uint8Array[] = [];
        const queryBins: number[] = [];
        for (let g = 0; g < this.indexK; g++) {
          for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
            let bin: number;
            const addrIdx = groupMap.get(g);
            if (addrIdx !== undefined) {
              const key = deriveCuckooKey(g, h);
              bin = cuckooHash(scriptHashes[addrIdx], key, this.indexBins);
            } else {
              bin = Number(this.rng.nextU64() % BigInt(this.indexBins));
            }
            queries.push(indexClient.generateQuery(bin));
            queryBins.push(bin);
          }
        }

        const batchMsg = encodeBatchQuery(REQ_ONIONPIR_INDEX_QUERY, totalIndexRounds, queries);
        const respRaw = await this.sendRaw(batchMsg);
        totalIndexRounds++;

        const respPayload = respRaw.slice(4);
        if (respPayload[0] !== RESP_ONIONPIR_INDEX_RESULT) throw new Error('Unexpected index response');
        const { results } = decodeBatchResult(respPayload, 1);

        // Decrypt both hash results and scan for tag
        for (const [addrIdx, group] of round) {
          for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
            const qi = group * 2 + h;
            const bin = queryBins[qi];
            const entryBytes = indexClient.decryptResponse(bin, results[qi]);
            const found = this.scanIndexBin(entryBytes, addrInfos[addrIdx].tag);
            if (found) {
              indexResults[addrIdx] = found;
              break;
            }
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
        if (ir.numEntries === FLAG_WHALE) { whaleQueries.add(i); continue; }
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
        chunkClient = this.wasmModule!.createClientFromSecretKey(this.chunkBins, clientId, secretKey);

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

          for (const [ei, group] of round) {
            const eid = uniqueEntryIds[ei];
            if (!cuckooCache.has(group)) {
              const t0 = performance.now();
              cuckooCache.set(group, buildChunkCuckooForGroup(this.wasmModule!, group, this.totalPacked, this.chunkBins));
              this.log(`  Cuckoo table for group ${group}: ${(performance.now() - t0).toFixed(0)}ms`);
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

          progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length} (querying)...`);

          const queries: Uint8Array[] = [];
          for (let g = 0; g < this.chunkK; g++) {
            const qi = groupToQi.get(g);
            const idx = qi !== undefined
              ? queryInfos[qi].bin
              : Number(this.rng.nextU64() % BigInt(this.chunkBins));
            queries.push(chunkClient!.generateQuery(idx));
          }

          const batchMsg = encodeBatchQuery(REQ_ONIONPIR_CHUNK_QUERY, ri, queries);
          const respRaw = await this.sendRaw(batchMsg);

          const respPayload = respRaw.slice(4);
          if (respPayload[0] !== RESP_ONIONPIR_CHUNK_RESULT) throw new Error('Unexpected chunk response');
          const { results } = decodeBatchResult(respPayload, 1);

          for (const qi of queryInfos) {
            const entryBytes = chunkClient!.decryptResponse(qi.bin, results[qi.group]);
            decryptedEntries.set(qi.entryId, entryBytes.slice(0, PACKED_ENTRY_SIZE));
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
  serverUrl: string = 'wss://onionpirv2.chenweikeng.com',
): OnionPirWebClient {
  return new OnionPirWebClient({ serverUrl });
}
