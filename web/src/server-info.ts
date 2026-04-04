/**
 * Shared server info fetching and parsing for all PIR backends.
 *
 * Sends REQ_GET_INFO_JSON (0x03) to the server and parses the JSON response.
 * All backends extract their parameters from the same JSON structure.
 */

import { REQ_GET_INFO_JSON } from './constants.js';
import type { ManagedWebSocket } from './ws.js';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface OnionPirInfoJson {
  total_packed_entries: number;
  index_bins_per_table: number;
  chunk_bins_per_table: number;
  tag_seed: bigint;
  index_k: number;
  chunk_k: number;
  index_cuckoo_bucket_size: number;
  index_slot_size: number;
  chunk_cuckoo_bucket_size: number;
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
  index_cuckoo_bucket_size: number;
  index_slot_size: number;
  chunk_cuckoo_bucket_size: number;
  chunk_slot_size: number;
  role: 'primary' | 'secondary';
  onionpir?: OnionPirInfoJson;
  merkle?: MerkleInfoJson;
}

export interface MerkleLevelInfo {
  dpf_n: number;
  bins_per_table: number;
}

export interface MerkleInfoJson {
  arity: number;
  sibling_levels: number;
  sibling_k: number;
  sibling_bucket_size: number;
  sibling_slot_size: number;
  levels: MerkleLevelInfo[];
  root: string;             // hex (32 bytes)
  tree_top_hash: string;   // SHA256 of tree-top cache blob (hex, 32 bytes)
  tree_top_size: number;   // byte size of tree-top cache
}

// ─── JSON request message ────────────────────────────────────────────────────

/** Pre-built request: [4B len=1 LE][1B variant=REQ_GET_INFO_JSON] */
const INFO_JSON_REQUEST = new Uint8Array([1, 0, 0, 0, REQ_GET_INFO_JSON]);

// ─── Parser ──────────────────────────────────────────────────────────────────

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
    index_cuckoo_bucket_size: raw.index_cuckoo_bucket_size,
    index_slot_size: raw.index_slot_size,
    chunk_cuckoo_bucket_size: raw.chunk_cuckoo_bucket_size,
    chunk_slot_size: raw.chunk_slot_size,
    role: raw.role,
  };

  if (raw.onionpir) {
    info.onionpir = {
      total_packed_entries: raw.onionpir.total_packed_entries,
      index_bins_per_table: raw.onionpir.index_bins_per_table,
      chunk_bins_per_table: raw.onionpir.chunk_bins_per_table,
      tag_seed: BigInt(raw.onionpir.tag_seed),
      index_k: raw.onionpir.index_k,
      chunk_k: raw.onionpir.chunk_k,
      index_cuckoo_bucket_size: raw.onionpir.index_cuckoo_bucket_size,
      index_slot_size: raw.onionpir.index_slot_size,
      chunk_cuckoo_bucket_size: raw.onionpir.chunk_cuckoo_bucket_size,
      chunk_slot_size: raw.onionpir.chunk_slot_size,
    };
  }

  if (raw.merkle && typeof raw.merkle === 'object') {
    info.merkle = {
      arity: raw.merkle.arity,
      sibling_levels: raw.merkle.sibling_levels,
      sibling_k: raw.merkle.sibling_k,
      sibling_bucket_size: raw.merkle.sibling_bucket_size,
      sibling_slot_size: raw.merkle.sibling_slot_size,
      levels: raw.merkle.levels,
      root: raw.merkle.root ?? '',
      tree_top_hash: raw.merkle.tree_top_hash ?? '',
      tree_top_size: raw.merkle.tree_top_size ?? 0,
    };
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
export async function fetchServerInfoJson(ws: ManagedWebSocket): Promise<ServerInfoJson> {
  const raw = await ws.sendRaw(INFO_JSON_REQUEST);

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
