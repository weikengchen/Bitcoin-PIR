/**
 * Shared server info fetching and parsing for all PIR backends.
 *
 * Sends REQ_GET_INFO_JSON (0x03) to the server and parses the JSON response.
 * All backends extract their parameters from the same JSON structure.
 */

import { REQ_GET_INFO_JSON, REQ_RESIDENCY, REQ_GET_DB_CATALOG } from './constants.js';
import type { ManagedWebSocket } from './ws.js';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface OnionPirInfoJson {
  total_packed_entries: number;
  index_bins_per_table: number;
  chunk_bins_per_table: number;
  tag_seed: bigint;
  /**
   * INDEX/CHUNK cuckoo master seeds (chain-derived for v2 DBs). `0n`
   * when the server doesn't emit them (pre-ext server) — the client
   * then keeps its legacy-constant default.
   */
  index_master_seed: bigint;
  chunk_master_seed: bigint;
  index_k: number;
  chunk_k: number;
  index_slots_per_bin: number;
  index_slot_size: number;
  chunk_slots_per_bin: number;
  chunk_slot_size: number;
}

export interface ServerInfoJson {
  index_bins_per_table: number;
  chunk_bins_per_table: number;
  index_k: number;
  chunk_k: number;
  tag_seed: bigint;
  index_dpf_n: number;
  chunk_dpf_n: number;
  index_slots_per_bin: number;
  index_slot_size: number;
  chunk_slots_per_bin: number;
  chunk_slot_size: number;
  role: 'primary' | 'secondary';
  onionpir?: OnionPirInfoJson;
  merkle?: MerkleInfoJson;
  merkle_bucket?: BucketMerkleInfoJson;
  onionpir_merkle?: OnionPirMerkleInfoJson;
  /** Per-database info (Merkle availability). Present when server has >1 DB or any DB has bucket Merkle. */
  databases?: PerDatabaseInfoJson[];
}

export interface PerDatabaseInfoJson {
  db_id: number;
  has_bucket_merkle: boolean;
  /** Whether the server has OnionPIR data loaded for this DB. */
  has_onionpir?: boolean;
  /** Whether the server has per-bin OnionPIR Merkle data for this DB. */
  has_onionpir_merkle?: boolean;
  merkle_bucket?: BucketMerkleInfoJson;
  /** Per-DB OnionPIR params. When non-zero DBs have different bins_per_table
   * from main, the client must switch BFV params by reading this field. */
  onionpir?: OnionPirInfoJson;
  /** Per-DB OnionPIR per-bin Merkle info. Same shape as the top-level field. */
  onionpir_merkle?: OnionPirMerkleInfoJson;
}

export interface MerkleLevelInfo {
  dpf_n: number;
  bins_per_table: number;
}

export interface MerkleInfoJson {
  arity: number;
  sibling_levels: number;
  sibling_k: number;
  sibling_slots_per_bin: number;
  sibling_slot_size: number;
  levels: MerkleLevelInfo[];
  root: string;             // hex (32 bytes)
  tree_top_hash: string;   // SHA256 of tree-top cache blob (hex, 32 bytes)
  tree_top_size: number;   // byte size of tree-top cache
}

// ─── Per-bucket bin Merkle info ──────────────────────────────────────────

export interface BucketMerkleLevelInfo {
  dpf_n: number;
  bins_per_table: number;
}

export interface BucketMerkleInfoJson {
  arity: number;
  index_levels: BucketMerkleLevelInfo[];
  chunk_levels: BucketMerkleLevelInfo[];
  index_roots: string[];   // 75 hex roots
  chunk_roots: string[];   // 80 hex roots
  super_root: string;      // hex super-root
  tree_tops_hash: string;  // SHA256 of tree-tops blob
  tree_tops_size: number;
}

/**
 * Per-kind sibling-DB parameters for the per-group OnionPIR Merkle
 * (Phase 3 per-group redesign). One independent arity-`arity` Merkle
 * tree per PBC group; `k` = number of PBC groups = number of per-group
 * trees = FHE queries in one sibling pass; `num_pt` = plaintexts in
 * each per-group sibling DB. Mirrors the Rust `OnionMerkleKindInfo`.
 */
export interface OnionPirMerkleKindInfo {
  k: number;
  num_pt: number;
}

/**
 * Per-group OnionPIR Merkle metadata for one DB (Phase 3 redesign).
 *
 * Replaces the old flat per-table trees: there is now one independent
 * Merkle tree per PBC group (75 INDEX + 80 DATA), anchored by a single
 * `super_root` = SHA256 of the 155 concatenated per-group roots. Mirrors
 * the server's `append_onionpir_merkle_json` output and the Rust
 * `OnionMerkleInfo`.
 */
export interface OnionPirMerkleInfoJson {
  /** Merkle arity (children per internal node) — same for every tree. */
  arity: number;
  /** SHA256 of the 155 concatenated per-group roots — the pinned anchor. */
  super_root: string;
  /** SHA256 of the whole 155-tree tree-top blob (belt-and-suspenders). */
  tree_tops_hash: string;
  /** Byte length of the tree-top blob, as declared in the JSON. */
  tree_tops_size: number;
  /** INDEX per-group sibling-DB parameters. */
  index: OnionPirMerkleKindInfo;
  /** DATA per-group sibling-DB parameters. */
  data: OnionPirMerkleKindInfo;
}

// ─── JSON request message ────────────────────────────────────────────────────

/** Pre-built request: [4B len=1 LE][1B variant=REQ_GET_INFO_JSON] */
const INFO_JSON_REQUEST = new Uint8Array([1, 0, 0, 0, REQ_GET_INFO_JSON]);

// ─── Parser ──────────────────────────────────────────────────────────────────

function parseBucketMerkleInfo(mb: any): BucketMerkleInfoJson {
  return {
    arity: mb.arity ?? 8,
    index_levels: mb.index_levels ?? [],
    chunk_levels: mb.chunk_levels ?? [],
    index_roots: mb.index_roots ?? [],
    chunk_roots: mb.chunk_roots ?? [],
    super_root: mb.super_root ?? '',
    tree_tops_hash: mb.tree_tops_hash ?? '',
    tree_tops_size: mb.tree_tops_size ?? 0,
  };
}

/**
 * Parse a JSON server info string into a typed object.
 * Handles bigint conversion for tag_seed fields (hex string → bigint).
 */
export function parseServerInfoJson(jsonStr: string): ServerInfoJson {
  const raw = JSON.parse(jsonStr);

  const info: ServerInfoJson = {
    index_bins_per_table: raw.index_bins_per_table,
    chunk_bins_per_table: raw.chunk_bins_per_table,
    index_k: raw.index_k,
    chunk_k: raw.chunk_k,
    tag_seed: BigInt(raw.tag_seed),
    index_dpf_n: raw.index_dpf_n,
    chunk_dpf_n: raw.chunk_dpf_n,
    index_slots_per_bin: raw.index_slots_per_bin,
    index_slot_size: raw.index_slot_size,
    chunk_slots_per_bin: raw.chunk_slots_per_bin,
    chunk_slot_size: raw.chunk_slot_size,
    role: raw.role,
  };

  // `onionpir` is defined below but we also want it in the top-level
  // `info.onionpir` assignment. The helper is hoisted via `const` below so
  // we reference a local inline copy here to avoid hoisting issues.
  if (raw.onionpir) {
    info.onionpir = {
      total_packed_entries: raw.onionpir.total_packed_entries,
      index_bins_per_table: raw.onionpir.index_bins_per_table,
      chunk_bins_per_table: raw.onionpir.chunk_bins_per_table,
      tag_seed: BigInt(raw.onionpir.tag_seed),
      index_master_seed: raw.onionpir.index_master_seed != null ? BigInt(raw.onionpir.index_master_seed) : 0n,
      chunk_master_seed: raw.onionpir.chunk_master_seed != null ? BigInt(raw.onionpir.chunk_master_seed) : 0n,
      index_k: raw.onionpir.index_k,
      chunk_k: raw.onionpir.chunk_k,
      index_slots_per_bin: raw.onionpir.index_slots_per_bin,
      index_slot_size: raw.onionpir.index_slot_size,
      chunk_slots_per_bin: raw.onionpir.chunk_slots_per_bin,
      chunk_slot_size: raw.onionpir.chunk_slot_size,
    };
  }

  const parseOnionPirMerkle = (om: any): OnionPirMerkleInfoJson => {
    const parseKind = (st: any): OnionPirMerkleKindInfo => ({
      k: st.k ?? 0,
      num_pt: st.num_pt ?? 0,
    });
    return {
      arity: om.arity ?? 0,
      super_root: om.super_root ?? '',
      tree_tops_hash: om.tree_tops_hash ?? '',
      tree_tops_size: om.tree_tops_size ?? 0,
      index: parseKind(om.index ?? {}),
      data: parseKind(om.data ?? {}),
    };
  };

  const parseOnionPir = (op: any): OnionPirInfoJson => ({
    total_packed_entries: op.total_packed_entries,
    index_bins_per_table: op.index_bins_per_table,
    chunk_bins_per_table: op.chunk_bins_per_table,
    tag_seed: BigInt(op.tag_seed),
    index_master_seed: op.index_master_seed != null ? BigInt(op.index_master_seed) : 0n,
    chunk_master_seed: op.chunk_master_seed != null ? BigInt(op.chunk_master_seed) : 0n,
    index_k: op.index_k,
    chunk_k: op.chunk_k,
    index_slots_per_bin: op.index_slots_per_bin,
    index_slot_size: op.index_slot_size,
    chunk_slots_per_bin: op.chunk_slots_per_bin,
    chunk_slot_size: op.chunk_slot_size,
  });

  if (raw.onionpir_merkle && typeof raw.onionpir_merkle === 'object') {
    info.onionpir_merkle = parseOnionPirMerkle(raw.onionpir_merkle);
  }

  if (raw.merkle && typeof raw.merkle === 'object') {
    info.merkle = {
      arity: raw.merkle.arity,
      sibling_levels: raw.merkle.sibling_levels,
      sibling_k: raw.merkle.sibling_k,
      sibling_slots_per_bin: raw.merkle.sibling_slots_per_bin,
      sibling_slot_size: raw.merkle.sibling_slot_size,
      levels: raw.merkle.levels,
      root: raw.merkle.root ?? '',
      tree_top_hash: raw.merkle.tree_top_hash ?? '',
      tree_top_size: raw.merkle.tree_top_size ?? 0,
    };
  }

  if (raw.merkle_bucket && typeof raw.merkle_bucket === 'object') {
    const mb = raw.merkle_bucket;
    info.merkle_bucket = parseBucketMerkleInfo(mb);
  }

  if (Array.isArray(raw.databases)) {
    info.databases = raw.databases.map((db: any) => {
      const entry: PerDatabaseInfoJson = {
        db_id: db.db_id,
        has_bucket_merkle: db.has_bucket_merkle ?? false,
        has_onionpir: db.has_onionpir ?? false,
        has_onionpir_merkle: db.has_onionpir_merkle ?? false,
      };
      if (db.merkle_bucket && typeof db.merkle_bucket === 'object') {
        entry.merkle_bucket = parseBucketMerkleInfo(db.merkle_bucket);
      }
      if (db.onionpir && typeof db.onionpir === 'object') {
        entry.onionpir = parseOnionPir(db.onionpir);
      }
      if (db.onionpir_merkle && typeof db.onionpir_merkle === 'object') {
        entry.onionpir_merkle = parseOnionPirMerkle(db.onionpir_merkle);
      }
      return entry;
    });
  }

  return info;
}

// ─── Fetch ───────────────────────────────────────────────────────────────────

/**
 * Fetch JSON server info from a connected ManagedWebSocket.
 *
 * Wire format:
 *   Request:  [4B len=1 LE][1B 0x03]
 *   Response: [4B len LE][1B 0x03][JSON bytes...]
 */
export async function fetchServerInfoJson(
  ws: ManagedWebSocket,
  onRoundtrip?: (requestBytes: number, responseBytes: number) => void,
): Promise<ServerInfoJson> {
  const raw = await ws.sendRaw(INFO_JSON_REQUEST);
  onRoundtrip?.(INFO_JSON_REQUEST.length, raw.length);

  // Response: [4B length LE][1B variant][JSON payload...]
  if (raw.length < 6) {
    throw new Error('Server info response too short');
  }

  const variant = raw[4];
  if (variant === 0xFF) {
    throw new Error('Server returned error for GetInfoJson');
  }

  const jsonBytes = raw.slice(5);
  const jsonStr = new TextDecoder().decode(jsonBytes);
  return parseServerInfoJson(jsonStr);
}

// ─── Residency ──────────────────────────────────────────────────────────────

export interface ResidencyRegion {
  name: string;
  size: number;
  resident: number;
  pct: number;
}

export interface ResidencyInfo {
  page_size: number;
  regions: ResidencyRegion[];
  total_size: number;
  total_resident: number;
  total_pct: number;
}

/** Pre-built request: [4B len=1 LE][1B variant=REQ_RESIDENCY] */
const RESIDENCY_REQUEST = new Uint8Array([1, 0, 0, 0, REQ_RESIDENCY]);

/**
 * Fetch mmap page residency from a connected server.
 *
 * Wire format:
 *   Request:  [4B len=1 LE][1B 0x04]
 *   Response: [4B len LE][1B 0x04][JSON bytes...]
 */
export async function fetchResidency(ws: ManagedWebSocket): Promise<ResidencyInfo> {
  const raw = await ws.sendRaw(RESIDENCY_REQUEST);
  if (raw.length < 6) {
    throw new Error('Residency response too short');
  }
  const variant = raw[4];
  if (variant === 0xFF) {
    throw new Error('Server returned error for residency request');
  }
  const jsonBytes = raw.slice(5);
  const jsonStr = new TextDecoder().decode(jsonBytes);
  return JSON.parse(jsonStr) as ResidencyInfo;
}

// ─── Database Catalog ──────────────────────────────────────────────────────

export interface DatabaseCatalogEntry {
  dbId: number;
  /** 0 = full UTXO snapshot, 1 = delta between two heights. */
  dbType: number;
  name: string;
  /** Base height (0 for full snapshots, start height for deltas). */
  baseHeight: number;
  /** Tip height (snapshot height for full, end height for deltas). */
  height: number;
  indexBinsPerTable: number;
  chunkBinsPerTable: number;
  indexK: number;
  chunkK: number;
  tagSeed: bigint;
  dpfNIndex: number;
  dpfNChunk: number;
  /** Whether this database has per-bucket bin Merkle verification data. */
  hasBucketMerkle: boolean;
  /**
   * INDEX/CHUNK cuckoo master seeds delivered by the server (chain-derived
   * for v2 DBs). 0n for a legacy server that doesn't emit the ext section.
   */
  indexMasterSeed: bigint;
  chunkMasterSeed: bigint;
  /** Chain-anchor kind: 0 = none (legacy), 1 = snapshot, 2 = delta. */
  anchorKind: number;
  /** Hex of the raw anchor bytes (36/72), or "" for legacy DBs. */
  anchorHex: string;
}

export interface DatabaseCatalog {
  databases: DatabaseCatalogEntry[];
}

/** Pre-built request: [4B len=1 LE][1B variant=REQ_GET_DB_CATALOG] */
const CATALOG_REQUEST = new Uint8Array([1, 0, 0, 0, REQ_GET_DB_CATALOG]);

/**
 * Decode a database catalog response.
 *
 * Wire format:
 *   [1B num_databases]
 *   Per database:
 *     [1B db_id][1B db_type][1B name_len][name bytes]
 *     [4B base_height LE][4B height LE]
 *     [4B index_bins LE][4B chunk_bins LE]
 *     [1B index_k][1B chunk_k][8B tag_seed LE]
 *     [1B dpf_n_index][1B dpf_n_chunk]
 */
export function decodeDatabaseCatalog(data: Uint8Array): DatabaseCatalog {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let pos = 0;
  const numDatabases = data[pos++];
  const databases: DatabaseCatalogEntry[] = [];

  for (let i = 0; i < numDatabases; i++) {
    const dbId = data[pos++];
    const dbType = data[pos++];
    const nameLen = data[pos++];
    const name = new TextDecoder().decode(data.slice(pos, pos + nameLen));
    pos += nameLen;
    const baseHeight = dv.getUint32(pos, true); pos += 4;
    const height = dv.getUint32(pos, true); pos += 4;
    const indexBinsPerTable = dv.getUint32(pos, true); pos += 4;
    const chunkBinsPerTable = dv.getUint32(pos, true); pos += 4;
    const indexK = data[pos++];
    const chunkK = data[pos++];
    const tagSeed = dv.getBigUint64(pos, true); pos += 8;
    const dpfNIndex = data[pos++];
    const dpfNChunk = data[pos++];
    // has_bucket_merkle: always present in current wire format (1 byte, 0 or 1)
    const hasBucketMerkle = pos < data.length ? data[pos++] !== 0 : false;

    databases.push({
      dbId, dbType, name, baseHeight, height,
      indexBinsPerTable, chunkBinsPerTable,
      indexK, chunkK, tagSeed,
      dpfNIndex, dpfNChunk, hasBucketMerkle,
      // Patched from the trailing ext section below; defaults for a
      // legacy server that doesn't emit it.
      indexMasterSeed: 0n, chunkMasterSeed: 0n, anchorKind: 0, anchorHex: "",
    });
  }

  // Trailing ext section (CATALOG_EXT_V1 = 0x01): per-entry master seeds
  // + chain anchor. Mirrors runtime::protocol::encode_db_catalog. A
  // pre-ext server stops after the entries above, leaving the defaults.
  const CATALOG_EXT_V1 = 0x01;
  if (pos < data.length && data[pos] === CATALOG_EXT_V1) {
    pos++;
    for (const db of databases) {
      if (pos + 17 > data.length) break; // truncated ext — keep defaults
      db.indexMasterSeed = dv.getBigUint64(pos, true); pos += 8;
      db.chunkMasterSeed = dv.getBigUint64(pos, true); pos += 8;
      const kind = data[pos++];
      db.anchorKind = kind;
      const n = kind === 1 ? 36 : kind === 2 ? 72 : 0;
      if (n > 0 && pos + n <= data.length) {
        const bytes = data.slice(pos, pos + n);
        db.anchorHex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
        pos += n;
      }
    }
  }

  return { databases };
}

/**
 * Fetch the database catalog from a connected server.
 *
 * Wire format:
 *   Request:  [4B len=1 LE][1B 0x02]
 *   Response: [4B len LE][1B 0x02][catalog bytes...]
 */
export async function fetchDatabaseCatalog(
  ws: ManagedWebSocket,
  onRoundtrip?: (requestBytes: number, responseBytes: number) => void,
): Promise<DatabaseCatalog> {
  const raw = await ws.sendRaw(CATALOG_REQUEST);
  onRoundtrip?.(CATALOG_REQUEST.length, raw.length);
  if (raw.length < 6) {
    throw new Error('Database catalog response too short');
  }
  const variant = raw[4];
  if (variant === 0xFF) {
    throw new Error('Server returned error for database catalog request');
  }
  return decodeDatabaseCatalog(raw.slice(5));
}
