/**
 * Two-level Batch PIR WebSocket client.
 *
 * Supports true batching: multiple script hashes are packed into a single
 * batch of K=75 index groups (Level 1) and K_CHUNK=80 chunk groups
 * (Level 2) using cuckoo placement, minimizing round-trips.
 */

import {
  K, K_CHUNK, NUM_HASHES,
  CHUNKS_PER_UNIT, UNIT_DATA_SIZE,
  INDEX_CUCKOO_NUM_HASHES,
  CHUNK_CUCKOO_NUM_HASHES,
} from './constants.js';

import {
  deriveGroups, deriveCuckooKey, cuckooHash,
  deriveChunkGroups, deriveChunkCuckooKey, cuckooHashInt,
  computeTag,
} from './hash.js';

import { genDpfKeys, genChunkDpfKeys, genDpfKeysN } from './dpf.js';

import {
  encodeRequest, decodeResponse,
  type Request, type Response, type BatchQuery, type BatchResult, type ServerInfo,
} from './protocol.js';

import { cuckooPlace, planRounds } from './pbc.js';
import { readVarint, decodeUtxoData, DummyRng } from './codec.js';
import { findEntryInIndexResult, findChunkInResult } from './scan.js';
import { ManagedWebSocket } from './ws.js';
import { fetchServerInfoJson, fetchDatabaseCatalog, type ServerInfoJson, type DatabaseCatalog, type DatabaseCatalogEntry } from './server-info.js';
import { verifyBucketMerkleBatchDpf, type BucketMerkleItem } from './merkle-verify-bucket.js';

// ─── Types ─────────────────────────────────────────────────────────────────

export interface UtxoEntry {
  txid: Uint8Array;    // 32-byte raw TXID (internal byte order)
  vout: number;
  amount: bigint;      // satoshis
}

export interface QueryResult {
  entries: UtxoEntry[];
  totalSats: bigint;
  startChunkId: number;
  numChunks: number;
  numRounds: number;
  /** True if this address was excluded from the database due to too many UTXOs */
  isWhale: boolean;
  /** Merkle verification result (undefined if not verified yet) */
  merkleVerified?: boolean;
  /** Merkle root hash hex (from server, for display) */
  merkleRootHex?: string;
  /** Raw chunk data (kept for Merkle verification) */
  rawChunkData?: Uint8Array;
  /** Script hash used for this query */
  scriptHash?: Uint8Array;
  // ── Per-bucket bin Merkle ─────────────────────────────────────────
  /** PBC group index for the INDEX query */
  indexPbcGroup?: number;
  /** Cuckoo bin index within the INDEX group */
  indexBinIndex?: number;
  /** Raw INDEX bin content (slotsPerBin × slotSize bytes) */
  indexBinContent?: Uint8Array;
  /** PBC group indices for each CHUNK query */
  chunkPbcGroups?: number[];
  /** Cuckoo bin indices for each CHUNK query */
  chunkBinIndices?: number[];
  /** Raw CHUNK bin contents */
  chunkBinContents?: Uint8Array[];
  // ── Per-bin Merkle (OnionPIR) ─────────────────────────────────────
  /** INDEX-MERKLE root hex (OnionPIR per-bin) */
  merkleIndexRoot?: string;
  /** DATA-MERKLE root hex (OnionPIR per-bin) */
  merkleDataRoot?: string;
  /** SHA256 of the decrypted INDEX bin (per-bin Merkle leaf) */
  indexBinHash?: Uint8Array;
  /** Leaf position in INDEX-MERKLE tree */
  indexLeafPos?: number;
  /** SHA256 of each decrypted DATA bin (per-bin Merkle leaves) */
  dataBinHashes?: Uint8Array[];
  /** Leaf positions in DATA-MERKLE tree */
  dataLeafPositions?: number[];
}

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting';

export interface BatchPirClientConfig {
  server0Url: string;
  server1Url: string;
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  onLog?: (message: string, level: 'info' | 'success' | 'error') => void;
}

// ─── Client ────────────────────────────────────────────────────────────────

export class BatchPirClient {
  private ws0: ManagedWebSocket | null = null;
  private ws1: ManagedWebSocket | null = null;
  private config: BatchPirClientConfig;
  private connectionState: ConnectionState = 'disconnected';
  private rng = new DummyRng();

  // Server info (fetched on connect via JSON)
  private serverInfo: ServerInfoJson | null = null;
  private indexBins = 0;
  private chunkBins = 0;
  private tagSeed = 0n;
  private catalog: DatabaseCatalog | null = null;

  constructor(config: BatchPirClientConfig) {
    this.config = config;
  }

  private log(message: string, level: 'info' | 'success' | 'error' = 'info'): void {
    if (this.config.onLog) {
      this.config.onLog(message, level);
    }
    console.log(`[BatchPIR] ${message}`);
  }

  private setConnectionState(state: ConnectionState, message?: string): void {
    this.connectionState = state;
    this.config.onConnectionStateChange?.(state, message);
  }

  getConnectionState(): ConnectionState {
    return this.connectionState;
  }

  isConnected(): boolean {
    return (this.ws0?.isOpen() ?? false) && (this.ws1?.isOpen() ?? false);
  }

  /** Return all open WebSocket connections (for diagnostics like residency check). */
  getConnectedSockets(): { label: string; ws: ManagedWebSocket }[] {
    const out: { label: string; ws: ManagedWebSocket }[] = [];
    if (this.ws0?.isOpen()) out.push({ label: 'DPF Server 0', ws: this.ws0 });
    if (this.ws1?.isOpen()) out.push({ label: 'DPF Server 1', ws: this.ws1 });
    return out;
  }

  // ─── Connection (delegates to shared ws.ts) ────────────────────────────

  async connect(): Promise<void> {
    this.setConnectionState('connecting', 'Connecting to servers...');

    try {
      this.ws0 = new ManagedWebSocket({
        url: this.config.server0Url,
        label: 'server0',
        onLog: (msg, level) => this.log(msg, level),
        onClose: () => {
          this.ws0 = null;
          this.setConnectionState('disconnected', 'Server 0 closed');
        },
      });
      this.ws1 = new ManagedWebSocket({
        url: this.config.server1Url,
        label: 'server1',
        onLog: (msg, level) => this.log(msg, level),
        onClose: () => {
          this.ws1 = null;
          this.setConnectionState('disconnected', 'Server 1 closed');
        },
      });

      await Promise.all([this.ws0.connect(), this.ws1.connect()]);

      this.setConnectionState('connected', 'Connected to both servers');
      this.log('Connected to both servers', 'success');

      // Fetch server info
      await this.fetchServerInfo();
    } catch (error) {
      this.setConnectionState('disconnected', `Connection failed: ${error}`);
      throw error;
    }
  }

  disconnect(): void {
    this.ws0?.disconnect();
    this.ws1?.disconnect();
    this.ws0 = null;
    this.ws1 = null;
    this.setConnectionState('disconnected', 'Disconnected');
  }

  // ─── Raw WebSocket send/receive ────────────────────────────────────────

  private sendRaw(serverNum: 0 | 1, encoded: Uint8Array): Promise<Uint8Array> {
    const ws = serverNum === 0 ? this.ws0 : this.ws1;
    if (!ws) throw new Error(`Not connected to server ${serverNum}`);
    return ws.sendRaw(encoded);
  }

  private async sendRequest(serverNum: 0 | 1, request: Request): Promise<Response> {
    const encoded = encodeRequest(request);
    const raw = await this.sendRaw(serverNum, encoded);
    return decodeResponse(raw.slice(4));
  }

  private async sendBoth(
    encoded0: Uint8Array,
    encoded1: Uint8Array,
  ): Promise<[Uint8Array, Uint8Array]> {
    const [raw0, raw1] = await Promise.all([
      this.sendRaw(0, encoded0),
      this.sendRaw(1, encoded1),
    ]);
    return [raw0, raw1];
  }

  // ─── Server info ───────────────────────────────────────────────────────

  private async fetchServerInfo(): Promise<void> {
    const info = await fetchServerInfoJson(this.ws0!);
    this.serverInfo = info;
    this.indexBins = info.index_bins_per_table;
    this.chunkBins = info.chunk_bins_per_table;
    this.tagSeed = info.tag_seed;
    this.log(`Server info (JSON): index_bins=${this.indexBins}, chunk_bins=${this.chunkBins}, index_K=${info.index_k}, chunk_K=${info.chunk_k}, tag_seed=0x${this.tagSeed.toString(16)}`);

    // Fetch database catalog
    try {
      this.catalog = await fetchDatabaseCatalog(this.ws0!);
      if (this.catalog.databases.length > 1) {
        this.log(`Database catalog: ${this.catalog.databases.length} databases available`);
        for (const db of this.catalog.databases) {
          this.log(`  [${db.dbId}] ${db.name} (height=${db.height}, index_bins=${db.indexBinsPerTable}, chunk_bins=${db.chunkBinsPerTable}, dpf_n=${db.dpfNIndex}/${db.dpfNChunk})`);
        }
      }
    } catch {
      this.log('Database catalog not available (older server)', 'info');
    }

    // Also fetch from server 1 to keep connection in sync
    await fetchServerInfoJson(this.ws1!);
  }

  getServerInfo(): { indexBins: number; chunkBins: number } {
    return { indexBins: this.indexBins, chunkBins: this.chunkBins };
  }

  /** Return the database catalog (fetched on connect). */
  getCatalog(): DatabaseCatalog | null {
    return this.catalog;
  }

  /** Find a catalog entry by db_id. */
  getCatalogEntry(dbId: number): DatabaseCatalogEntry | undefined {
    return this.catalog?.databases.find(d => d.dbId === dbId);
  }

  // ─── XOR utility ──────────────────────────────────────────────────────

  private xorBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(Math.max(a.length, b.length));
    for (let i = 0; i < result.length; i++) {
      result[i] = (a[i] || 0) ^ (b[i] || 0);
    }
    return result;
  }

  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  // ─── Index result parsing ─────────────────────────────────────────────

  // ─── Index/chunk result parsing (delegates to shared scan.ts) ──────────

  // ─── Cuckoo placement and round planning (delegates to shared pbc.ts) ──

  // ─── Decode UTXO data (delegates to shared codec.ts) ──────────────────

  // ─── Single-query method (for backward compat) ────────────────────────

  async query(
    scriptHashBytes: Uint8Array,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<QueryResult | null> {
    const results = await this.queryBatch([scriptHashBytes], onProgress);
    return results[0];
  }

  /**
   * Query the delta database for multiple script hashes.
   * Returns raw chunk data which should be decoded with decodeDeltaData().
   */
  async queryDelta(
    scriptHashes: Uint8Array[],
    dbId: number = 1,
    onProgress?: (step: string, detail: string) => void,
  ): Promise<(QueryResult | null)[]> {
    const entry = this.getCatalogEntry(dbId);
    if (!entry) throw new Error(`Delta database dbId=${dbId} not available`);
    return this.queryBatch(scriptHashes, onProgress, dbId);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // TRUE BATCH QUERY — multiple script hashes in one batch
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Query multiple script hashes in true batched mode.
   *
   * Level 1: Packs multiple queries into K=75 index groups using
   *   cuckoo placement. If >K queries, uses multiple index rounds.
   * Level 2: Collects ALL chunk IDs across all queries and fetches
   *   them in batched chunk rounds (K_CHUNK=80 per round).
   *
   * Returns an array parallel to the input, with results or null.
   */
  async queryBatch(
    scriptHashes: Uint8Array[],
    onProgress?: (step: string, detail: string) => void,
    dbId: number = 0,
  ): Promise<(QueryResult | null)[]> {
    if (!this.isConnected()) throw new Error('Not connected');
    if (this.indexBins === 0) throw new Error('Server info not loaded');

    // Resolve database parameters: use catalog entry for non-zero dbId
    let indexBins = this.indexBins;
    let chunkBins = this.chunkBins;
    let tagSeed = this.tagSeed;
    let indexDpfN = this.serverInfo!.index_dpf_n;
    let chunkDpfN = this.serverInfo!.chunk_dpf_n;
    if (dbId !== 0) {
      const entry = this.getCatalogEntry(dbId);
      if (!entry) throw new Error(`Unknown database dbId=${dbId}`);
      indexBins = entry.indexBinsPerTable;
      chunkBins = entry.chunkBinsPerTable;
      tagSeed = entry.tagSeed;
      indexDpfN = entry.dpfNIndex;
      chunkDpfN = entry.dpfNChunk;
    }

    const N = scriptHashes.length;
    const progress = onProgress || (() => {});

    this.log(`=== Batch query: ${N} script hashes ===`);

    // ════════════════════════════════════════════════════════════════════
    // LEVEL 1: Index PIR (batched)
    // ════════════════════════════════════════════════════════════════════
    progress('Level 1', `Planning index batch for ${N} queries...`);

    // Compute candidate index groups for each query
    const indexCandGroups = scriptHashes.map(sh => deriveGroups(sh));

    // Plan index rounds using cuckoo placement
    const indexRounds = planRounds(indexCandGroups, K, NUM_HASHES, (msg) => this.log(msg, 'error'));
    this.log(`Level 1: ${N} queries → ${indexRounds.length} index round(s)`);

    // Per-query results from Level 1
    const indexResults: Map<number, { startChunkId: number; numChunks: number; pbcGroup: number; binIndex: number; binContent: Uint8Array }> = new Map();

    for (let ir = 0; ir < indexRounds.length; ir++) {
      const round = indexRounds[ir];
      progress('Level 1', `Index round ${ir + 1}/${indexRounds.length} (${round.length} queries)...`);
      this.log(`  Index round ${ir + 1}: ${round.length} queries in ${K} groups`);

      // Build group → query mapping: which query goes in which group
      const groupToQuery: Map<number, number> = new Map();
      for (const [queryIdx, groupId] of round) {
        groupToQuery.set(groupId, queryIdx);
      }

      // Generate DPF keys for all K groups (INDEX_CUCKOO_NUM_HASHES keys per group)
      progress('Level 1', `Round ${ir + 1}: generating DPF keys...`);
      const s0Keys: Uint8Array[][] = [];
      const s1Keys: Uint8Array[][] = [];

      for (let b = 0; b < K; b++) {
        const qi = groupToQuery.get(b);
        const s0Group: Uint8Array[] = [];
        const s1Group: Uint8Array[] = [];

        for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
          let alpha: number;
          if (qi !== undefined) {
            const sh = scriptHashes[qi];
            const ck = deriveCuckooKey(b, h);
            alpha = cuckooHash(sh, ck, indexBins);
          } else {
            alpha = Number(this.rng.nextU64() % BigInt(indexBins));
          }
          const keys = await genDpfKeysN(alpha, indexDpfN);
          s0Group.push(keys.key0);
          s1Group.push(keys.key1);
        }

        s0Keys.push(s0Group);
        s1Keys.push(s1Group);
      }

      // Send to both servers
      progress('Level 1', `Round ${ir + 1}: querying servers...`);
      const req0 = encodeRequest({ type: 'IndexBatch', query: { level: 0, roundId: ir, keys: s0Keys, dbId } });
      const req1 = encodeRequest({ type: 'IndexBatch', query: { level: 0, roundId: ir, keys: s1Keys, dbId } });

      const [raw0, raw1] = await this.sendBoth(req0, req1);
      const resp0 = decodeResponse(raw0.slice(4));
      const resp1 = decodeResponse(raw1.slice(4));

      if (resp0.type !== 'IndexBatch' || resp1.type !== 'IndexBatch') {
        throw new Error(`Unexpected index response: ${resp0.type}, ${resp1.type}`);
      }

      // XOR and extract results for each real query group
      for (const [queryIdx, groupId] of round) {
        const r0 = resp0.result.results[groupId];
        const r1 = resp1.result.results[groupId];

        let found: { startChunkId: number; numChunks: number } | null = null;
        let matchedBinContent: Uint8Array | undefined;
        let matchedBinIndex = 0;
        const expectedTag = computeTag(tagSeed, scriptHashes[queryIdx]);
        for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
          const result = this.xorBuffers(r0[h], r1[h]);
          found = findEntryInIndexResult(result, expectedTag, this.serverInfo!.index_slots_per_bin, this.serverInfo!.index_slot_size);
          if (found) {
            matchedBinContent = result;
            // The bin index is the cuckoo hash of the script hash into this group's table
            const ck = deriveCuckooKey(groupId, h);
            matchedBinIndex = cuckooHash(scriptHashes[queryIdx], ck, indexBins);
            break;
          }
        }

        if (found) {
          indexResults.set(queryIdx, {
            ...found,
            pbcGroup: groupId,
            binIndex: matchedBinIndex,
            binContent: matchedBinContent!,
          });
        } else {
          this.log(`  Query ${queryIdx}: not found in index`, 'error');
        }
      }
    }

    this.log(`Level 1 complete: ${indexResults.size}/${N} found`);

    // ════════════════════════════════════════════════════════════════════
    // LEVEL 2: Chunk PIR (batched across ALL queries)
    // ════════════════════════════════════════════════════════════════════
    progress('Level 2', 'Collecting chunk IDs...');

    // Build a global list of unique chunk IDs needed, and track which
    // query needs which chunks
    const queryChunkInfo: Map<number, { startChunk: number; numUnits: number; startChunkId: number; numChunks: number }> = new Map();
    const allChunkIdsSet = new Set<number>();

    // Track whale-excluded queries separately
    const whaleQueries = new Set<number>();

    for (const [qi, info] of indexResults) {
      // Detect whale: num_chunks == 0
      if (info.numChunks === 0) {
        whaleQueries.add(qi);
        this.log(`  Query ${qi}: whale address (excluded, too many UTXOs)`);
        continue;
      }

      const startChunk = info.startChunkId;
      const numUnits = Math.ceil(info.numChunks / CHUNKS_PER_UNIT);
      const chunkIds: number[] = [];
      for (let u = 0; u < numUnits; u++) {
        const cid = startChunk + u * CHUNKS_PER_UNIT;
        chunkIds.push(cid);
        allChunkIdsSet.add(cid);
      }
      queryChunkInfo.set(qi, { startChunk, numUnits, startChunkId: info.startChunkId, numChunks: info.numChunks });
    }

    const allChunkIds = Array.from(allChunkIdsSet).sort((a, b) => a - b);
    this.log(`Level 2: ${allChunkIds.length} unique chunks to fetch across ${indexResults.size} queries`);

    // Plan chunk rounds collectively
    const chunkCandGroups = allChunkIds.map(cid => deriveChunkGroups(cid));
    const chunkRounds = planRounds(
      chunkCandGroups,
      K_CHUNK,
      NUM_HASHES,
      (msg) => this.log(msg, 'error'),
    );
    // chunkRounds[r][i] = [chunkListIndex, groupId]
    this.log(`  ${allChunkIds.length} chunks → ${chunkRounds.length} chunk round(s)`);

    // Execute chunk rounds
    const recoveredChunks = new Map<number, Uint8Array>();
    // Track per-chunk Merkle info: chunkId → { pbcGroup, binIndex, binContent }
    const chunkMerkleInfo = new Map<number, { pbcGroup: number; binIndex: number; binContent: Uint8Array }>();

    for (let ri = 0; ri < chunkRounds.length; ri++) {
      const roundPlan = chunkRounds[ri];
      progress('Level 2', `Chunk round ${ri + 1}/${chunkRounds.length} (${roundPlan.length} chunks)...`);

      // Always send CHUNK_CUCKOO_NUM_HASHES (2) DPF keys per group (uniform, no placement optimization)
      const groupTargets: Map<number, number[]> = new Map();
      for (const [chunkListIdx, groupId] of roundPlan) {
        const chunkId = allChunkIds[chunkListIdx];
        const locs: number[] = [];
        for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
          const ck = deriveChunkCuckooKey(groupId, h);
          locs.push(cuckooHashInt(chunkId, ck, chunkBins));
        }
        groupTargets.set(groupId, locs);
      }

      // Generate DPF keys
      const s0Keys: Uint8Array[][] = [];
      const s1Keys: Uint8Array[][] = [];

      for (let b = 0; b < K_CHUNK; b++) {
        const target = groupTargets.get(b);
        const s0Group: Uint8Array[] = [];
        const s1Group: Uint8Array[] = [];

        for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
          const alpha = target
            ? target[h]
            : Number(this.rng.nextU64() % BigInt(chunkBins));
          const keys = await genDpfKeysN(alpha, chunkDpfN);
          s0Group.push(keys.key0);
          s1Group.push(keys.key1);
        }

        s0Keys.push(s0Group);
        s1Keys.push(s1Group);
      }

      // Send
      const cReq0 = encodeRequest({ type: 'ChunkBatch', query: { level: 1, roundId: ri, keys: s0Keys, dbId } });
      const cReq1 = encodeRequest({ type: 'ChunkBatch', query: { level: 1, roundId: ri, keys: s1Keys, dbId } });

      const [craw0, craw1] = await this.sendBoth(cReq0, cReq1);
      const cresp0 = decodeResponse(craw0.slice(4));
      const cresp1 = decodeResponse(craw1.slice(4));

      if (cresp0.type !== 'ChunkBatch' || cresp1.type !== 'ChunkBatch') {
        throw new Error(`Unexpected chunk response: ${cresp0.type}, ${cresp1.type}`);
      }

      // XOR and extract
      for (const [chunkListIdx, groupId] of roundPlan) {
        const chunkId = allChunkIds[chunkListIdx];
        const cr0 = cresp0.result.results[groupId];
        const cr1 = cresp1.result.results[groupId];

        let data: Uint8Array | null = null;
        const numResults = cr0.length;
        for (let h = 0; h < numResults; h++) {
          const result = this.xorBuffers(cr0[h], cr1[h]);
          data = findChunkInResult(result, chunkId, this.serverInfo!.chunk_slots_per_bin, this.serverInfo!.chunk_slot_size);
          if (data) {
            // Save bin content + bin index for bucket Merkle verification
            const ck = deriveChunkCuckooKey(groupId, h);
            const binIndex = cuckooHashInt(chunkId, ck, chunkBins);
            chunkMerkleInfo.set(chunkId, { pbcGroup: groupId, binIndex, binContent: result });
            break;
          }
        }

        if (data) {
          recoveredChunks.set(chunkId, data);
        } else {
          this.log(`  WARNING: chunk ${chunkId} not found in round ${ri} group ${groupId}`, 'error');
        }
      }
    }

    this.log(`Level 2 complete: recovered ${recoveredChunks.size}/${allChunkIds.length} chunks`);

    // ════════════════════════════════════════════════════════════════════
    // Reassemble per-query results
    // ════════════════════════════════════════════════════════════════════
    progress('Decode', 'Reassembling UTXO data...');

    const totalChunkRounds = chunkRounds.length;
    const results: (QueryResult | null)[] = new Array(N).fill(null);

    for (let qi = 0; qi < N; qi++) {
      // Return a whale result if this address was excluded
      if (whaleQueries.has(qi)) {
        results[qi] = {
          entries: [],
          totalSats: 0n,
          startChunkId: 0,
          numChunks: 0,
          numRounds: 0,
          isWhale: true,
        };
        continue;
      }

      const info = queryChunkInfo.get(qi);
      if (!info) {
        // Not found in index
        continue;
      }

      const { startChunk, numUnits, startChunkId, numChunks } = info;
      const fullData = new Uint8Array(numUnits * UNIT_DATA_SIZE);
      let missing = 0;

      for (let u = 0; u < numUnits; u++) {
        const cid = startChunk + u * CHUNKS_PER_UNIT;
        const d = recoveredChunks.get(cid);
        if (d) {
          fullData.set(d, u * UNIT_DATA_SIZE);
        } else {
          missing++;
        }
      }

      if (missing > 0) {
        this.log(`Query ${qi}: ${missing} chunks missing`, 'error');
      }

      const { entries, totalSats } = decodeUtxoData(fullData, (msg) => this.log(msg, 'error'));

      // Collect chunk-level Merkle info for this query
      const qChunkPbcGroups: number[] = [];
      const qChunkBinIndices: number[] = [];
      const qChunkBinContents: Uint8Array[] = [];
      for (let u = 0; u < numUnits; u++) {
        const cid = startChunk + u * CHUNKS_PER_UNIT;
        const cmi = chunkMerkleInfo.get(cid);
        if (cmi) {
          qChunkPbcGroups.push(cmi.pbcGroup);
          qChunkBinIndices.push(cmi.binIndex);
          qChunkBinContents.push(cmi.binContent);
        }
      }

      // Get INDEX-level Merkle info
      const idxInfo = indexResults.get(qi);

      results[qi] = {
        entries,
        totalSats,
        startChunkId,
        numChunks,
        numRounds: totalChunkRounds,
        isWhale: false,
        merkleRootHex: this.serverInfo?.merkle_bucket?.super_root ?? this.serverInfo?.merkle?.root,
        rawChunkData: fullData,
        scriptHash: scriptHashes[qi],
        indexPbcGroup: idxInfo?.pbcGroup,
        indexBinIndex: idxInfo?.binIndex,
        indexBinContent: idxInfo?.binContent,
        chunkPbcGroups: qChunkPbcGroups,
        chunkBinIndices: qChunkBinIndices,
        chunkBinContents: qChunkBinContents,
      };
    }

    const found = results.filter(r => r !== null).length;
    this.log(`=== Batch complete: ${found}/${N} queries returned results ===`, 'success');

    return results;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // MERKLE VERIFICATION — separate from query (user-triggered)
  // ═══════════════════════════════════════════════════════════════════════

  /** Check if server supports Merkle verification */
  hasMerkle(): boolean {
    return !!(this.serverInfo?.merkle_bucket && this.serverInfo.merkle_bucket.index_levels.length > 0);
  }

  /** Get the Merkle root hash hex (for display) */
  getMerkleRootHex(): string | undefined {
    return this.serverInfo?.merkle_bucket?.super_root ?? this.serverInfo?.merkle?.root;
  }

  /**
   * Batch-verify per-bucket bin Merkle proofs for multiple query results.
   * Uses DPF sibling queries against flat per-group sibling tables.
   */
  async verifyMerkleBatch(
    results: QueryResult[],
    onProgress?: (step: string, detail: string) => void,
  ): Promise<boolean[]> {
    if (!this.isConnected()) throw new Error('Not connected');
    const merkle = this.serverInfo?.merkle_bucket;
    if (!merkle) throw new Error('Server does not support bucket Merkle');

    // Build BucketMerkleItem[] from verifiable results
    const items: BucketMerkleItem[] = [];
    const itemToResult: number[] = [];
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r.isWhale || r.indexPbcGroup === undefined || !r.indexBinContent) continue;
      items.push({
        indexPbcGroup: r.indexPbcGroup,
        indexBinIndex: r.indexBinIndex!,
        indexBinContent: r.indexBinContent,
        chunkPbcGroups: r.chunkPbcGroups ?? [],
        chunkBinIndices: r.chunkBinIndices ?? [],
        chunkBinContents: r.chunkBinContents ?? [],
      });
      itemToResult.push(i);
    }

    if (items.length === 0) return results.map(() => false);

    const batchResults = await verifyBucketMerkleBatchDpf(
      this.ws0!, this.ws1!, merkle, items, onProgress,
      (msg) => this.log(msg),
    );

    const out: boolean[] = new Array(results.length).fill(false);
    for (let j = 0; j < batchResults.length; j++) {
      const ri = itemToResult[j];
      out[ri] = batchResults[j];
      results[ri].merkleVerified = batchResults[j];
    }
    return out;
  }
}

/**
 * Create a Batch PIR client
 */
export function createBatchPirClient(
  server0Url: string = 'wss://pir1.chenweikeng.com',
  server1Url: string = 'wss://pir2.chenweikeng.com',
): BatchPirClient {
  return new BatchPirClient({ server0Url, server1Url });
}
