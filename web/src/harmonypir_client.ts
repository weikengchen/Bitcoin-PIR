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
  REQ_HARMONY_GET_INFO, REQ_HARMONY_HINTS, REQ_HARMONY_QUERY,
  RESP_HARMONY_INFO, RESP_HARMONY_HINTS, RESP_HARMONY_QUERY, RESP_ERROR,
} from './constants.js';

import {
  deriveBuckets, deriveCuckooKey, cuckooHash, computeTag,
  deriveChunkBuckets, deriveChunkCuckooKey, cuckooHashInt,
  scriptHash as computeScriptHash, addressToScriptPubKey,
  hexToBytes, bytesToHex,
} from './hash.js';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface HarmonyPirClientConfig {
  hintServerUrl: string;
  queryServerUrl: string;
  onProgress?: (msg: string) => void;
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
  };
  compute_balanced_t(n: number): number;
  verify_protocol(n: number, w: number): boolean;
}

interface HarmonyBucketWasm {
  load_hints(hintsData: Uint8Array): void;
  build_request(q: number): HarmonyRequestWasm;
  process_response(response: Uint8Array): Uint8Array;
  queries_remaining(): number;
  queries_used(): number;
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

  // Per-bucket WASM state
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

  /** Load the HarmonyPIR WASM module. */
  async loadWasm(): Promise<void> {
    if (this.wasm) return;
    // The WASM module is expected at /wasm/harmonypir/harmonypir_wasm.js
    const init = (globalThis as any).harmonypir_wasm_init;
    if (!init) {
      throw new Error('HarmonyPIR WASM not loaded. Include harmonypir_wasm.js before using.');
    }
    this.wasm = await init();
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

  /** Initialize WASM bucket instances for all PBC groups. */
  initBuckets(): void {
    if (!this.wasm) throw new Error('WASM not loaded');

    for (let b = 0; b < K; b++) {
      const bucket = new this.wasm.HarmonyBucket(
        this.indexBinsPerTable, HARMONY_INDEX_W, 0, this.prpKey, b
      );
      this.indexBuckets.set(b, bucket);
    }

    for (let b = 0; b < K_CHUNK; b++) {
      const bucket = new this.wasm.HarmonyBucket(
        this.chunkBinsPerTable, HARMONY_CHUNK_W, 0, this.prpKey, K + b
      );
      this.chunkBuckets.set(b, bucket);
    }

    this.log(`Initialized ${K} index + ${K_CHUNK} chunk HarmonyPIR buckets`);
  }

  /**
   * Fetch hints from the Hint Server for all buckets.
   * This is the offline phase — typically done once per session.
   */
  async fetchHints(): Promise<void> {
    this.log('Fetching hints from Hint Server...');

    // Connect to Hint Server.
    const hintWs = await this.connectHintServer();

    // Request index hints.
    await this.requestHints(hintWs, 0, K, this.indexBuckets, HARMONY_INDEX_W);
    this.log('Index hints loaded');

    // Request chunk hints.
    await this.requestHints(hintWs, 1, K_CHUNK, this.chunkBuckets, HARMONY_CHUNK_W);
    this.log('Chunk hints loaded');

    hintWs.close();
    this.log('Hints complete (~' + this.estimateHintSize() + ' MB)');
  }

  /**
   * Query a single Bitcoin address via HarmonyPIR.
   * Returns UTXO data.
   */
  async query(address: string): Promise<HarmonyQueryResult> {
    const scriptPubKey = addressToScriptPubKey(address);
    if (!scriptPubKey) throw new Error(`Invalid address: ${address}`);
    const sh = computeScriptHash(hexToBytes(scriptPubKey));
    const shHex = bytesToHex(sh);

    // Level 1: Index query — find which chunks hold this address's UTXOs.
    const candidateBuckets = deriveBuckets(sh);
    let indexEntry: { startChunkId: number; numChunks: number } | null = null;

    for (const bucketId of candidateBuckets) {
      if (indexEntry) break;
      const bucket = this.indexBuckets.get(bucketId);
      if (!bucket || bucket.queries_remaining() === 0) continue;

      // Try each cuckoo hash position.
      for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
        if (indexEntry) break;
        const cuckooKey = deriveCuckooKey(bucketId, h);
        const binIndex = cuckooHash(sh, cuckooKey, this.indexBinsPerTable);

        // Query this bin via HarmonyPIR.
        const binData = await this.queryBucket(bucket, binIndex, 0, bucketId);

        // Scan all slots in the bin for a matching tag.
        indexEntry = this.findTagInBin(binData, sh, HARMONY_INDEX_W);
      }
    }

    if (!indexEntry) {
      return { address, scriptHash: shHex, utxos: [], whale: false };
    }

    const whale = indexEntry.numChunks === 0;
    if (whale) {
      return { address, scriptHash: shHex, utxos: [], whale: true };
    }

    // Level 2: Chunk queries — fetch actual UTXO data.
    const chunks: Uint8Array[] = [];
    for (let ci = 0; ci < indexEntry.numChunks; ci++) {
      const chunkId = indexEntry.startChunkId + ci;
      const chunkData = await this.fetchChunk(chunkId);
      if (chunkData) chunks.push(chunkData);
    }

    // Decode UTXOs from chunk data.
    const utxos = this.decodeUtxos(chunks);

    return { address, scriptHash: shHex, utxos, whale: false };
  }

  // ─── Private helpers ────────────────────────────────────────────────────

  /** Query a single bin from a HarmonyBucket and get the response via Query Server. */
  private async queryBucket(
    bucket: HarmonyBucketWasm,
    binIndex: number,
    level: number,
    bucketId: number,
  ): Promise<Uint8Array> {
    // Build request in WASM — returns only sorted non-empty indices (no EMPTY, no dummy).
    const req = bucket.build_request(binIndex);
    const requestBytes = req.request;
    req.free();

    // Encode wire message: [1B variant][1B level][1B bucket_id][2B round_id][4B count][indices]
    const count = requestBytes.length / 4;
    const msg = new Uint8Array(1 + 1 + 1 + 2 + 4 + requestBytes.length);
    const view = new DataView(msg.buffer);
    msg[0] = REQ_HARMONY_QUERY;
    msg[1] = level;
    msg[2] = bucketId;
    view.setUint16(3, 0, true); // round_id
    view.setUint32(5, count, true); // count (only non-empty entries)
    msg.set(requestBytes, 9);

    // Send to Query Server and wait for response.
    const respData = await this.sendQueryRequest(msg);

    // Parse response: skip [1B variant][1B bucket_id][2B round_id], rest is count × w bytes.
    const responseEntries = respData.slice(4);

    // Process response in WASM (compute answer + relocation).
    const answer = bucket.process_response(responseEntries);
    return answer;
  }

  /** Fetch a single chunk by chunk_id via HarmonyPIR. */
  private async fetchChunk(chunkId: number): Promise<Uint8Array | null> {
    const candidateBuckets = deriveChunkBuckets(chunkId);

    for (const bucketId of candidateBuckets) {
      const bucket = this.chunkBuckets.get(bucketId);
      if (!bucket || bucket.queries_remaining() === 0) continue;

      for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
        const cuckooKey = deriveChunkCuckooKey(bucketId, h);
        const binIndex = cuckooHashInt(chunkId, cuckooKey, this.chunkBinsPerTable);

        const binData = await this.queryBucket(bucket, binIndex, 1, bucketId);

        // Scan slots for matching chunk_id.
        const chunkData = this.findChunkInBin(binData, chunkId);
        if (chunkData) return chunkData;
      }
    }

    return null;
  }

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

  /** Decode UTXOs from chunk data. Simple varint-encoded format. */
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

    // Decode: each UTXO is [32B txid][4B vout LE][8B value LE] = 44 bytes
    // But the actual format depends on the build pipeline encoding.
    // For now, return raw data as a single entry.
    const utxos: UtxoEntry[] = [];
    let offset = 0;
    while (offset + 44 <= data.length) {
      const view = new DataView(data.buffer, data.byteOffset + offset);
      const txidBytes = data.slice(offset, offset + 32);
      // Check if all zeros (padding).
      if (txidBytes.every(b => b === 0)) break;
      const txid = bytesToHex(new Uint8Array([...txidBytes].reverse()));
      const vout = view.getUint32(32, true);
      const value = Number(view.getBigUint64(36, true));
      utxos.push({ txid, vout, value });
      offset += 44;
    }

    return utxos;
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

  /** Request hints from the Hint Server for a set of buckets at one level. */
  private async requestHints(
    ws: WebSocket,
    level: number,
    numBuckets: number,
    buckets: Map<number, HarmonyBucketWasm>,
    w: number,
  ): Promise<void> {
    // Build hint request.
    const bucketIds = Array.from({ length: numBuckets }, (_, i) => i);
    const msg = new Uint8Array(1 + 16 + 1 + 1 + numBuckets);
    msg[0] = REQ_HARMONY_HINTS;
    msg.set(this.prpKey, 1);
    msg[17] = level;
    msg[18] = numBuckets;
    for (let i = 0; i < numBuckets; i++) {
      msg[19 + i] = bucketIds[i];
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
          const view = new DataView(payload.buffer, payload.byteOffset);
          const n = view.getUint32(2, true);
          const t = view.getUint32(6, true);
          const m = view.getUint32(10, true);
          const hintsData = payload.slice(14);

          const bucket = buckets.get(bucketId);
          if (bucket) {
            bucket.load_hints(hintsData);
          }

          received++;
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

  private estimateHintSize(): string {
    let total = 0;
    for (const [_, bucket] of this.indexBuckets) {
      total += bucket.m() * bucket.w();
    }
    for (const [_, bucket] of this.chunkBuckets) {
      total += bucket.m() * bucket.w();
    }
    return (total / (1024 * 1024)).toFixed(1);
  }

  /** Disconnect and free resources. */
  disconnect(): void {
    this.queryWs?.close();
    this.hintWs?.close();
    for (const [_, b] of this.indexBuckets) b.free();
    for (const [_, b] of this.chunkBuckets) b.free();
    this.indexBuckets.clear();
    this.chunkBuckets.clear();
  }
}

/** Factory function to create a HarmonyPIR client. */
export function createHarmonyPirClient(config: HarmonyPirClientConfig): HarmonyPirClient {
  return new HarmonyPirClient(config);
}
