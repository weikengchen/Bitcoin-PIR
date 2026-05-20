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
} from './constants.js';

import {
  deriveGroups, deriveCuckooKey, cuckooHash,
  deriveChunkGroups,
  splitmix64, computeTag,
  sha256,
} from './hash.js';

import { cuckooPlace, planRounds } from './pbc.js';
import { decodeUtxoData, DummyRng } from './codec.js';
import { unpackOnionPlaintext } from './onion-unpack.js';
import { findEntryInOnionPirIndexResult } from './scan.js';
import { ManagedWebSocket } from './ws.js';
import { fetchServerInfoJson } from './server-info.js';
import { computeParentN, ZERO_HASH } from './merkle.js';

import type { UtxoEntry, QueryResult, ConnectionState } from './types.js';
import type {
  DatabaseCatalog,
  OnionPirMerkleInfoJson,
  ServerInfoJson,
} from './server-info.js';
import { fetchDatabaseCatalog } from './server-info.js';

import type { LeakageRecorder, RoundProfile } from './leakage.js';

// ─── Constants for OnionPIR v2 layout ─────────────────────────────────────

// Post-port (commit 7): the byte count per decrypted bin is no longer a
// hardcoded 3840 — it equals `params_info().entry_size` (3328 for
// CONFIG_N2048_K1, 19968 for CONFIG_N4096_K2_MP). The TS port of the
// Rust `pir-core::onion_unpack` helper at `./onion-unpack.ts` returns
// exactly `entry_size` bytes from `decryptResponse`. The legacy
// constant is kept as a defensive upper-bound fallback only; the
// runtime `params.entrySize` is the source of truth at each call site.
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
//
// Post-port surface (onionpir rev 2402b16, upstream's wasm/bindings.cpp +
// hand-written .d.ts at web/public/wasm/onionpir_client.d.ts). The
// onionpir_client.wasm in web/public/wasm/ is rebuilt from this rev:
//
//   * `OnionPirClient(numEntries)`, `createClientFromSecretKey(numEntries,
//     clientId, secretKey)` and `paramsInfo(numEntries)` each take the
//     per-database `numEntries` (un-padded entry count): the FHE query
//     hypercube is sized from it, so INDEX / CHUNK / Merkle-sibling
//     clients each pass their own database's size.
//     `createClientFromSecretKey` returns `OnionPirClient | null` (per
//     upstream Rust: `from_secret_key -> Option<Self>`).
//   * Method renames: `generateGaloisKeys` → `galoisKeys`,
//     `generateGswKeys` → `gswKey`, `decryptResponse(idx, resp)` →
//     `decryptResponse(resp)` (caller now bit-unpacks via
//     `unpackOnionPlaintext`).
//   * Cuckoo helper key encoding flipped from `Uint32Array` lo/hi pairs
//     to `Float64Array` treated as u64-bytes (see
//     `buildCuckooKeysFloat64Array` below).

interface OnionPirParamsInfo {
  numEntries:     number;
  entrySize:      number;
  numPlaintexts:  number;
  fstDimSz:       number;
  otherDimSz:     number;
  polyDegree:     number;
  rnsModCount:    number;
  coeffValCnt:    number;
  dbSizeMB:       number;
  physicalSizeMB: number;
}

interface OnionPirModule {
  OnionPirClient: { new(numEntries: number): WasmPirClient };
  createClientFromSecretKey(numEntries: number, clientId: number, secretKey: Uint8Array): WasmPirClient | null;
  paramsInfo(numEntries: number): OnionPirParamsInfo;
  splitmix64(x: number): number;
  cuckooHashInt(entryId: number, key: number, numBins: number): number;
  buildCuckooBs1(entries: Uint32Array, keys: Uint32Array, numBins: number): Uint32Array;
}

interface WasmPirClient {
  id(): number;
  exportSecretKey(): Uint8Array;
  galoisKeys(): Uint8Array;
  gswKey(): Uint8Array;
  generateQuery(entryIndex: number): Uint8Array;
  decryptResponse(response: Uint8Array): Uint8Array;
  delete(): void;
}

// ─── WASM module loader ───────────────────────────────────────────────────
//
// Post-port the upstream WASM is emitted as an ES module
// (`onionpir_client.mjs`) with a default-exported async factory. The
// pre-port `<script>` tag + `globalThis.createOnionPirModule` global
// is gone — the browser HTML no longer ships the script tag (see
// commit 7 of the onionpir-port branch). Node tests dynamically
// `await import(...)` the same path; see
// `web/src/__tests__/onion_leakage_diff.test.ts` for the test-side
// loader.
//
// `globalThis.__onionpirWasmFactory` is a test-time escape hatch: when
// running under Node / vitest, the test harness can pre-install the
// factory there (resolved off the local filesystem) to avoid the
// browser-only `/wasm/onionpir_client.mjs` URL resolution path.

type OnionPirFactory = (moduleArg?: object) => Promise<OnionPirModule>;

let wasmModulePromise: Promise<OnionPirModule> | null = null;

async function loadWasmModule(): Promise<OnionPirModule> {
  if (!wasmModulePromise) {
    wasmModulePromise = (async () => {
      const installed = (globalThis as { __onionpirWasmFactory?: OnionPirFactory }).__onionpirWasmFactory;
      let factory: OnionPirFactory;
      if (installed) {
        factory = installed;
      } else {
        // The path is built at runtime so `tsc --noEmit` doesn't try to
        // resolve the .mjs module under web/public/wasm/ at type-check
        // time. The browser fetches it from /wasm/onionpir_client.mjs
        // (Vite serves the public/ tree verbatim); node tests install
        // a factory via `globalThis.__onionpirWasmFactory`.
        const wasmModuleUrl = '/wasm/onionpir_client.mjs';
        const mod = await import(/* @vite-ignore */ /* webpackIgnore: true */ wasmModuleUrl);
        factory = (mod as { default: OnionPirFactory }).default;
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

  // onionpir 2402b16's `buildCuckooBs1` embind wrapper expects the cuckoo
  // keys as a `Uint32Array` of `numHashes * 2` consecutive (lo32, hi32)
  // pairs — see wasm/hash_utils.cpp `hash_build_cuckoo_bs1_embind`. (The
  // pre-2402b16 WASM took a `Float64Array` of u64 bit-patterns; the fork
  // switched the key ABI to avoid double-precision loss.)
  const keys: bigint[] = [];
  for (let h = 0; h < CHUNK_CUCKOO_NUM_HASHES; h++) {
    keys.push(chunkDeriveCuckooKey(groupId, h));
  }
  return wasmModule.buildCuckooBs1(
    new Uint32Array(entries),
    packCuckooKeysU32(keys),
    binsPerTable,
  );
}

/**
 * Pack u64 cuckoo-hash keys into the `Uint32Array` layout the onionpir
 * 2402b16 `buildCuckooBs1` embind wrapper expects: `keys.length * 2`
 * elements, each key as a consecutive (lo32, hi32) pair.
 */
function packCuckooKeysU32(keys: bigint[]): Uint32Array {
  const out = new Uint32Array(keys.length * 2);
  for (let i = 0; i < keys.length; i++) {
    out[i * 2] = Number(keys[i] & 0xFFFFFFFFn);
    out[i * 2 + 1] = Number((keys[i] >> 32n) & 0xFFFFFFFFn);
  }
  return out;
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

// DummyRng imported from codec.ts

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

// ─── Per-group OnionPIR Merkle: tree-top blob + trust anchor ──────────────
//
// SOUNDNESS-CRITICAL module section — the standalone-TS mirror of the Rust
// verifier `pir-sdk-client/src/onion_merkle.rs` (Phase 3d, commit 79e422b4).
//
// Since the Phase-3 per-group redesign (PLAN_MERKLE_CODING.md /
// MERKLE_COLOCATION_REVIEW.md §2-§6) OnionPIR has one independent
// arity-`arity` Merkle tree per PBC group — 75 INDEX trees + 80 DATA trees
// — anchored by a single `super_root` = SHA256 of the 155 concatenated
// per-group roots. The old flat per-table trees, and the gid-cuckoo +
// `planRounds`-over-gids sibling machinery they needed, are gone.
//
// The 155 per-group roots ride in the *untrusted*, server-supplied tree-top
// blob; `super_root` (from the trusted server-info JSON) is the pinned
// anchor. `checkTreeTopAnchor` binds the blob to that anchor — this is the
// load-bearing check. Skip or weaken it and a malicious server can
// fabricate a self-consistent blob + sibling responses, and every leaf
// "verifies" against forged roots.

/**
 * One parsed per-group Merkle tree-top. `levels[0]` is the first cached
 * level (the level-1 nodes — the leaf level is the single PIR sibling
 * level and is never cached); `levels[last]` is `[root]`. Mirrors the
 * Rust `OnionTreeTopCache`.
 */
interface OnionTreeTopCache {
  cacheFromLevel: number;
  arity: number;
  levels: Uint8Array[][];
}

/** The per-group root = the single hash in the last cached level. */
function onionTreeTopRoot(top: OnionTreeTopCache): Uint8Array | null {
  const last = top.levels[top.levels.length - 1];
  return last && last.length > 0 ? last[0] : null;
}

/** Constant-length byte-array equality. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Parse the consolidated 155-tree tree-top blob `merkle_onion_tree_tops.bin`.
 * Mirrors the Rust `parse_onion_tree_top_cache`.
 *
 * The whole blob is served on either TREE_TOP opcode (0x54 / 0x56); the
 * caller parses all 155 trees — 75 INDEX trees first, then 80 DATA trees
 * (the order `gen_4_build_merkle_onion` writes them).
 *
 * Wire format:
 * ```text
 * [4B num_trees LE]
 * per tree:
 *   [1B cache_from_level][4B total_nodes LE][2B arity LE][1B num_cached_levels]
 *   per cached level: [4B num_nodes LE][num_nodes × 32B hashes]
 * ```
 *
 * Throws on truncation / arity=0 — SOUNDNESS-CRITICAL: a malformed blob
 * must abort verification, never silently parse as garbage.
 */
function parseOnionTreeTopCache(data: Uint8Array): OnionTreeTopCache[] {
  if (data.length < 4) {
    throw new Error('onionpir tree-tops blob too short (need 4B num_trees)');
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const numTrees = dv.getUint32(0, true);
  let off = 4;
  const out: OnionTreeTopCache[] = [];

  for (let t = 0; t < numTrees; t++) {
    if (off + 8 > data.length) {
      throw new Error(`onionpir tree-tops: truncated header for tree ${t}`);
    }
    const cacheFromLevel = data[off]; off += 1;
    off += 4; // total_nodes — informational, ignored
    const arity = dv.getUint16(off, true); off += 2;
    const numLevels = data[off]; off += 1;
    if (arity === 0) {
      throw new Error(`onionpir tree-tops: tree ${t} has arity=0`);
    }

    const levels: Uint8Array[][] = [];
    for (let l = 0; l < numLevels; l++) {
      if (off + 4 > data.length) {
        throw new Error(
          `onionpir tree-tops: truncated level-${l} count for tree ${t}`,
        );
      }
      const n = dv.getUint32(off, true); off += 4;
      if (off + n * 32 > data.length) {
        throw new Error(
          `onionpir tree-tops: truncated hashes for tree ${t} level ${l}`,
        );
      }
      const nodes: Uint8Array[] = [];
      for (let i = 0; i < n; i++) {
        nodes.push(data.slice(off, off + 32));
        off += 32;
      }
      levels.push(nodes);
    }
    out.push({ cacheFromLevel, arity, levels });
  }
  return out;
}

/**
 * Bind the fetched 155-tree tree-top blob to the pinned `super_root`.
 *
 * **SOUNDNESS-CRITICAL** — mirrors the Rust `check_tree_top_anchor`. The
 * 155 per-group roots ride in the (untrusted, server-supplied) blob;
 * `info.super_root` is the pinned anchor. If this check is skipped or
 * weakened, a malicious server can fabricate a self-consistent tree-top
 * blob + sibling responses and every leaf "verifies" against forged roots.
 *
 * Returns true iff all four checks pass:
 *  1. the blob has exactly `index.k + data.k` trees;
 *  2. the blob length + SHA256 match the JSON-declared `tree_tops_size` /
 *     `tree_tops_hash` (integrity — clearer diagnostic on corruption);
 *  3. every per-tree arity matches the JSON `arity` (build/JSON drift);
 *  4. **SHA256(concat of the 155 per-group roots) == super_root** — the
 *     load-bearing cryptographic anchor check.
 */
function checkTreeTopAnchor(
  info: OnionPirMerkleInfoJson,
  blob: Uint8Array,
  allTops: OnionTreeTopCache[],
  logErr: (msg: string) => void,
): boolean {
  const expectedTrees = info.index.k + info.data.k;
  if (allTops.length !== expectedTrees) {
    logErr(
      `[PIR-AUDIT] OnionPIR Merkle: tree-top blob has ${allTops.length} ` +
      `trees, expected ${expectedTrees} (index_k=${info.index.k} + ` +
      `data_k=${info.data.k}) — REJECTING ALL LEAVES`,
    );
    return false;
  }

  // Integrity: blob size + hash vs the JSON-declared values.
  if (blob.length !== info.tree_tops_size) {
    logErr(
      `[PIR-AUDIT] OnionPIR Merkle: tree-top blob is ${blob.length} B, ` +
      `JSON declared tree_tops_size=${info.tree_tops_size} — ` +
      `REJECTING ALL LEAVES`,
    );
    return false;
  }
  if (!bytesEqual(sha256(blob), hexToBytes(info.tree_tops_hash))) {
    logErr(
      '[PIR-AUDIT] OnionPIR Merkle: tree-top blob hash != JSON ' +
      'tree_tops_hash — REJECTING ALL LEAVES (blob corrupt or server lied)',
    );
    return false;
  }

  // Per-tree arity must match the JSON arity (build/JSON drift guard).
  for (let t = 0; t < allTops.length; t++) {
    if (allTops[t].arity !== info.arity) {
      logErr(
        `[PIR-AUDIT] OnionPIR Merkle: tree ${t} arity ${allTops[t].arity} ` +
        `!= JSON arity ${info.arity} — REJECTING ALL LEAVES`,
      );
      return false;
    }
  }

  // SOUNDNESS-CRITICAL: the 155 per-group roots must hash to super_root.
  const preimage = new Uint8Array(allTops.length * 32);
  for (let t = 0; t < allTops.length; t++) {
    const r = onionTreeTopRoot(allTops[t]);
    if (!r) {
      logErr(
        `[PIR-AUDIT] OnionPIR Merkle: tree-top ${t} has no root level — ` +
        'REJECTING ALL LEAVES',
      );
      return false;
    }
    preimage.set(r, t * 32);
  }
  if (!bytesEqual(sha256(preimage), hexToBytes(info.super_root))) {
    logErr(
      `[PIR-AUDIT] OnionPIR Merkle: SUPER-ROOT MISMATCH — computed from ` +
      `${allTops.length} per-group roots != pinned anchor — ` +
      'REJECTING ALL LEAVES (blob corrupt or server lied)',
    );
    return false;
  }
  return true;
}

/**
 * Walk a per-group tree-top from a reconstructed level-1 node up to the
 * group root. Mirrors the Rust `walk_tree_top_to_root`.
 *
 * `startHash` is the hash of the level-1 node the FHE sibling pass
 * reconstructed; `startIdx` is its index within that level. At each step
 * the running hash replaces the child at `idx % arity` of its parent (the
 * rest read from the cached level), the parent is recomputed, and `idx`
 * advances. Returns the reconstructed root.
 */
function walkTreeTopToRoot(
  startHash: Uint8Array,
  startIdx: number,
  top: OnionTreeTopCache,
  arity: number,
): Uint8Array {
  let hash = startHash;
  let idx = startIdx;
  // Walk every cached level except the last (which IS the root).
  for (let ci = 0; ci < top.levels.length - 1; ci++) {
    const levelNodes = top.levels[ci];
    const parentStart = Math.floor(idx / arity) * arity;
    const childPos = idx % arity;
    const children: Uint8Array[] = [];
    for (let c = 0; c < arity; c++) {
      const nodeI = parentStart + c;
      if (c === childPos) children.push(hash);
      else if (nodeI < levelNodes.length) children.push(levelNodes[nodeI]);
      else children.push(ZERO_HASH);
    }
    hash = computeParentN(children);
    idx = Math.floor(idx / arity);
  }
  return hash;
}

// ─── Client config ────────────────────────────────────────────────────────

export interface OnionPirClientConfig {
  serverUrl: string;
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
  onLog?: (message: string, level: 'info' | 'success' | 'error') => void;
}

// ─── CHUNK Round-Presence Symmetry: per-slot classifier ───────────────────
//
// Mirrors the Rust helper `classify_chunk_slots` in
// `pir-sdk-client/src/onion.rs`. Pure (no side effects, no RNG, no DOM
// access) so it can be exercised by unit tests in node without
// instantiating the WASM module.
//
// CHUNK Round-Presence Symmetry (CLAUDE.md): every per-query slot
// produces exactly one action — `AppendReal` if the INDEX scan
// returned a non-whale match, `AppendDummy` otherwise (not-found or
// whale). The pre-fix bug skipped not-found / whale slots entirely,
// so CHUNK round count was a binary side channel for found vs
// not-found. The classifier captures the structural fix: the
// per-slot action list has length equal to the input list, with no
// "skip" branch.

/**
 * Per-slot input shape — projection of the relevant fields of the
 * IndexResult-like objects produced by the INDEX scan loop. Used by
 * the classifier; the OnionPirWebClient also emits this shape when
 * delegating to `classifyChunkSlots`.
 */
export interface ChunkSlotInput {
  entryId: number;
  numEntries: number;
}

/**
 * Per-slot action emitted by the classifier. The `queryBatch` chunk
 * loop dispatches on this discriminator: `append_real` adds
 * `numEntries` real entry_ids to the unique-fetch list,
 * `append_dummy` injects one uniformly random dummy entry_id (with
 * up to 32 dedup retries).
 */
export type ChunkSlotAction =
  | { kind: 'append_real'; entryId: number; numEntries: number }
  | { kind: 'append_dummy' };

/**
 * Classify each per-query slot for the OnionPIR CHUNK round.
 *
 * Postconditions (verified by the unit tests in
 * `web/src/__tests__/onion_chunk_slot_classifier.test.ts`):
 *
 * - **P1** (round-count uniformity) — `result.length === slots.length`.
 *   Combined with the call-site loop in `queryBatch`, this gives
 *   `uniqueEntryIds.length >= slots.length` (modulo dedup
 *   collisions on the dummy path, probabilistically negligible).
 * - **P2** (no-skip) — every slot maps to either `append_real` or
 *   `append_dummy`. There is no third "skip" branch — the pre-fix
 *   bug.
 *
 * Mirrors `classify_chunk_slots` in `pir-sdk-client/src/onion.rs`.
 * Cross-language consistency is enforced by the cross-language diff
 * test (`onion_leakage_diff.test.ts`) — same RoundProfile shape on
 * the wire requires same per-slot decisions here.
 */
export function classifyChunkSlots(slots: readonly ChunkSlotInput[]): ChunkSlotAction[] {
  return slots.map((s) => {
    if (s.numEntries > 0) {
      return { kind: 'append_real' as const, entryId: s.entryId, numEntries: s.numEntries };
    }
    return { kind: 'append_dummy' as const };
  });
}

/**
 * Pure version of the unique-fetch collection logic in `queryBatch`.
 *
 * Drives the same dedup loop the production code runs, but takes a
 * deterministic dummy generator (an iterator over u32) instead of
 * `crypto.getRandomValues`. The actual `queryBatch` path uses
 * `crypto.getRandomValues`, but the iteration logic and dedup
 * behaviour are otherwise identical — this helper is the
 * test-friendly analog.
 *
 * **Returns** `{ unique, dummiesAdded }` where `unique` is the
 * deduplicated entry_id list and `dummiesAdded` is the count of
 * successful dummy appends.
 *
 * **Property** verified by tests: when the dummy generator yields
 * fresh values (no dedup collisions), `unique.length === slots.length`
 * for any input — every slot contributes one entry, real or dummy.
 */
export function selectChunkUniqueFetches(
  slots: readonly ChunkSlotInput[],
  dummyGen: () => number,
): { unique: number[]; dummiesAdded: number } {
  const actions = classifyChunkSlots(slots);
  const unique: number[] = [];
  const seen = new Set<number>();
  let dummiesAdded = 0;

  for (const action of actions) {
    if (action.kind === 'append_real') {
      for (let i = 0; i < action.numEntries; i++) {
        const eid = action.entryId + i;
        if (!seen.has(eid)) {
          seen.add(eid);
          unique.push(eid);
        }
      }
    } else {
      // Up to 32 retries to dodge dedup collisions — same bound as
      // the production code.
      for (let attempt = 0; attempt < 32; attempt++) {
        const cand = dummyGen();
        if (!seen.has(cand)) {
          seen.add(cand);
          unique.push(cand);
          dummiesAdded++;
          break;
        }
      }
    }
  }

  return { unique, dummiesAdded };
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

  // Optional leakage recorder. When installed, every transport-level
  // roundtrip emits a structured `RoundProfile` matching what the Rust
  // `OnionClient` emits — Phase 2.3 of `PLAN_LEAKAGE_VERIFICATION.md`
  // diff-tests Rust against TS using these profiles. `null` = no
  // recording (zero overhead in the no-recorder case).
  private leakageRecorder: LeakageRecorder | null = null;

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

  /**
   * Install (or replace) a leakage recorder. Pass `null` to uninstall.
   * Mirrors `OnionClient::set_leakage_recorder` on the Rust side — same
   * trait shape, same `server_id = 0` (single-server) convention. Used
   * by the cross-language diff harness in Phase 2.3.
   */
  setLeakageRecorder(recorder: LeakageRecorder | null): void {
    this.leakageRecorder = recorder;
  }

  /** Internal: emit a `RoundProfile` to the installed recorder, if any. */
  private recordRound(round: RoundProfile): void {
    this.leakageRecorder?.recordRound('onion', round);
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
   * Whether this database has per-group OnionPIR Merkle data available.
   * Works for both the main DB (dbId=0) and delta DBs.
   *
   * Fail-safe: a missing / non-64-hex `super_root` (the pinned anchor)
   * makes this return `false` ⇒ no verification, rather than verifying
   * against a zero anchor. Mirrors the Rust `parse_onionpir_merkle`
   * "skip on bad super_root" contract.
   */
  hasMerkleForDb(dbId: number): boolean {
    const info = this.getOnionPirMerkleForDb(dbId);
    return !!(
      info &&
      info.arity > 0 &&
      /^[0-9a-f]{64}$/.test(info.super_root) &&
      info.index?.k > 0 &&
      info.data?.k > 0
    );
  }

  /** Merkle super-root hex for a specific DB (the pinned trust anchor). */
  getMerkleRootHexForDb(dbId: number): string | undefined {
    const info = this.getOnionPirMerkleForDb(dbId);
    return info && info.super_root ? info.super_root : undefined;
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
    const info = await fetchServerInfoJson(this.ws!, (req, resp) => {
      this.recordRound({
        kind: 'info',
        server_id: 0,
        db_id: null,
        request_bytes: req,
        response_bytes: resp,
        items: [],
      });
    });
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
      this.catalog = await fetchDatabaseCatalog(this.ws!, (req, resp) => {
        this.recordRound({
          kind: 'info',
          server_id: 0,
          db_id: null,
          request_bytes: req,
          response_bytes: resp,
          items: [],
        });
      });
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
    this.log(`[PIR-AUDIT] Query parameters: K=${this.indexK} index groups, K_CHUNK=${this.chunkK} chunk groups, INDEX_CUCKOO_NUM_HASHES=${INDEX_CUCKOO_NUM_HASHES}`);

    // ── Generate keys and create per-level clients ─────────────────────
    // `OnionPirClient` / `createClientFromSecretKey` / `paramsInfo` take the
    // per-database `numEntries` (un-padded entry count). INDEX, CHUNK and each
    // Merkle-sibling level are separate OnionPIR databases of different sizes,
    // and the FHE query hypercube dimensions are derived from `numEntries` —
    // so every client MUST be sized to the database it queries (mirrors the
    // native onion.rs::num_entries_for_level). The keygen client uses the
    // INDEX size; the secret key it exports is size-independent and re-seeds
    // per-level clients of any size.
    progress('Setup', 'Creating PIR client...');
    const keygenClient = new this.wasmModule.OnionPirClient(this.indexBins);
    const clientId = keygenClient.id();
    const galoisKeys = keygenClient.galoisKeys();
    const gswKeys = keygenClient.gswKey();
    const secretKey = keygenClient.exportSecretKey();
    keygenClient.delete();

    // Save FHE state for Merkle reuse (keys stay registered on the server for connection lifetime)
    this.fheClientId = clientId;
    this.fheSecretKey = secretKey;

    const indexClient = this.wasmModule.createClientFromSecretKey(this.indexBins, clientId, secretKey);
    if (!indexClient) {
      // Upstream's `from_secret_key` returns `Option<Self>` and the WASM
      // binding maps None → null. None can only fire on size/format
      // mismatch — for a freshly-exported secret key this should be
      // unreachable. Throw to surface the inconsistency.
      throw new Error(
        `OnionPIR createClientFromSecretKey returned null for freshly-exported sk ` +
        `(clientId=${clientId}, sk.len=${secretKey.length}). ` +
        `Likely cause: WASM module / .d.ts drift.`
      );
    }
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
        this.recordRound({
          kind: 'onion_key_register',
          server_id: 0,
          db_id: dbId,
          request_bytes: regMsg.length,
          response_bytes: ack.length,
          items: [],
        });
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
      // Per-group OnionPIR Merkle: SHA256 of the first probed INDEX bin
      // per address. Retained only as the UI's "this result is
      // Merkle-verifiable" marker (index.html filters on
      // `indexBinHash !== undefined`); the verifier itself walks
      // `allBinsChecked`, keyed by (pbcGroup, bin).
      const indexBinHashes: (Uint8Array | null)[] = new Array(N).fill(null);
      // Every probed INDEX cuckoo bin as a per-group Merkle leaf —
      // always INDEX_CUCKOO_NUM_HASHES per address (found / not-found /
      // whale alike, per the INDEX item-count symmetry invariant).
      // `pbcGroup` selects the per-group INDEX tree; `bin` is the leaf
      // index within that group's tree.
      const allBinsChecked: Map<number, { hash: Uint8Array; pbcGroup: number; bin: number }[]> = new Map();
      let totalIndexRounds = 0;

      // PBC place all addresses into groups (same logic as DPF-PIR)
      const allGroups = addrInfos.map(a => a.groups);
      const indexRounds = planPbcRounds(allGroups, this.indexK);
      this.log(`Level 1: ${N} queries → ${indexRounds.length} round(s)`);
      this.log(`[PIR-AUDIT] PADDING: Each index round sends exactly ${this.indexK} queries (real + empty groups for privacy)`);

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
        // Per-group item count: every group sends INDEX_CUCKOO_NUM_HASHES
        // FHE queries — matches the Rust shape (and DPF's INDEX shape).
        // The Merkle INDEX item-count symmetry invariant lives in this
        // uniform 2-per-group payload.
        this.recordRound({
          kind: 'index',
          server_id: 0,
          db_id: dbId,
          request_bytes: batchMsg.length,
          response_bytes: respRaw.length,
          items: new Array(this.indexK).fill(INDEX_CUCKOO_NUM_HASHES),
        });
        totalIndexRounds++;

        const respPayload = respRaw.slice(4);
        if (respPayload[0] !== RESP_ONIONPIR_INDEX_RESULT) throw new Error('Unexpected index response');
        const { results } = decodeBatchResult(respPayload, 1);

        // Decrypt all INDEX_CUCKOO_NUM_HASHES responses per address — even
        // after a match — so the Merkle item count is uniform across
        // found/not-found (closes the side channel where pass count leaks
        // presence). Cost: ~100ms of WASM FHE work per extra decrypt on
        // found@h=0 queries. See CLAUDE.md "Merkle INDEX item-count symmetry".
        let decrypted = 0;
        const totalDecrypts = round.length * INDEX_CUCKOO_NUM_HASHES;
        for (const [addrIdx, group] of round) {
          // Track ALL bins probed for this address as per-group leaves.
          const binsForAddr: { hash: Uint8Array; pbcGroup: number; bin: number }[] = [];
          let foundMatch = false;
          // Post-port (commit 7): query `paramsInfo()` once per
          // round; we need polyDegree + entrySize to unpack the
          // raw plaintext bytes.
          const wasmParams = this.wasmModule.paramsInfo(this.indexBins);
          for (let h = 0; h < INDEX_CUCKOO_NUM_HASHES; h++) {
            const qi = group * 2 + h;
            const bin = queryBins[qi];
            // Post-port: `decryptResponse(response)` returns the raw
            // plaintext as `[u32 N][u64 coeff_0]...`; the TS port of
            // pir-core::onion_unpack handles the inverse-bit-pack.
            const rawPt = indexClient.decryptResponse(results[qi]);
            const entryBytes = unpackOnionPlaintext(
              rawPt, wasmParams.polyDegree, wasmParams.entrySize,
            );
            if (!entryBytes) {
              throw new Error(
                `onion_unpack rejected INDEX plaintext (raw.len=${rawPt.length} ` +
                `N=${wasmParams.polyDegree} es=${wasmParams.entrySize})`
              );
            }
            decrypted++;
            // Hash the full unpacked bin (entry_size bytes). The
            // legacy `PACKED_ENTRY_SIZE = 3840` slice would overshoot
            // the new 3328-byte bin and read past the end; bound the
            // slice by the actual unpack length.
            const hashLen = Math.min(entryBytes.length, PACKED_ENTRY_SIZE);
            const binHash = sha256(entryBytes.slice(0, hashLen));
            // Per-group OnionPIR Merkle leaf key: `group` selects the
            // per-group INDEX tree, `bin` is the leaf index within it.
            binsForAddr.push({ hash: binHash, pbcGroup: group, bin });

            // Only capture the first match; later iterations still decrypt
            // and track their bin but don't overwrite the matched-bin record.
            if (!foundMatch) {
              const found = findEntryInOnionPirIndexResult(entryBytes, addrInfos[addrIdx].tag, this.indexSlotsPerBin, this.indexSlotSize);
              if (found) {
                indexResults[addrIdx] = found;
                indexBinHashes[addrIdx] = binHash;
                foundMatch = true;
              }
            }
            // Yield after every decrypt — each is ~100ms+ of WASM FHE work
            progress('Level 1', `Round ${roundNum}/${totalRounds}: decrypted ${decrypted}/${totalDecrypts}...`);
            await yieldToMain();
          }

          allBinsChecked.set(addrIdx, binsForAddr);
          if (!foundMatch) {
            // Not found: set the `indexBinHash` marker from the first
            // probed bin so the UI still treats this result as
            // Merkle-verifiable (the verifier walks `allBinsChecked`).
            const firstBin = binsForAddr[0];
            if (firstBin) {
              indexBinHashes[addrIdx] = firstBin.hash;
            }
            this.log(`[PIR-AUDIT] Query ${addrIdx}: NOT FOUND (checked ${binsForAddr.length} bins)`);
          } else {
            const ir = indexResults[addrIdx];
            this.log(`[PIR-AUDIT] Query ${addrIdx}: FOUND at entryId=${ir?.entryId}, numEntries=${ir?.numEntries} (tracking ${binsForAddr.length} bins for Merkle)`);
          }
        }
      }

      const foundCount = indexResults.filter(r => r !== null).length;
      this.log(`Level 1 complete: ${foundCount}/${N} found in ${totalIndexRounds} rounds`);

      // ════════════════════════════════════════════════════════════════
      // LEVEL 2: Chunk PIR
      // ════════════════════════════════════════════════════════════════

      // Collect each query's *real* chunk entry_ids. Phase 3 / WS-A
      // removed the M=16 chunk-Merkle padding (PLAN_MERKLE_CODING.md):
      // a query now fetches its real chunk count — found-with-N → N
      // reals, not-found / whale → 0. The newly-admitted leak (per-query
      // real chunk count is observable) is intended and tracked in the
      // leakage spec; ~99% of addresses have exactly 1 chunk. This
      // mirrors the Rust `OnionClient::query_chunk_level` (commit
      // `79e422b4`, which dropped `pad_chunk_ids_to_m`).
      //
      // Round-presence is preserved *separately* from M-padding:
      //   - CHUNK PIR round-presence — every non-empty batch issues ≥1
      //     K_CHUNK CHUNK PIR round even when all-not-found (the
      //     `chunkRounds` empty-round fallback below).
      //   - CHUNK-Merkle round-presence — the per-group verifier always
      //     issues ≥1 all-dummy DATA sibling pass (`verifySubTree`).
      // Together they keep found-vs-not-found hidden without M=16.
      const whaleQueries = new Set<number>();
      const chunkOwnedPerQuery: number[][] = new Array(N);
      const uniqueEntryIds: number[] = [];
      const seen = new Set<number>();

      for (let i = 0; i < N; i++) {
        const ir = indexResults[i];
        if (ir && ir.numEntries === 0) {
          whaleQueries.add(i);
        }
        const realChunks: number[] = [];
        if (ir && ir.numEntries > 0) {
          for (let j = 0; j < ir.numEntries; j++) {
            realChunks.push(ir.entryId + j);
          }
        }
        for (const eid of realChunks) {
          if (eid < this.totalPacked && !seen.has(eid)) {
            seen.add(eid);
            uniqueEntryIds.push(eid);
          }
        }
        chunkOwnedPerQuery[i] = realChunks;
      }

      if (whaleQueries.size > 0) {
        this.log(`${whaleQueries.size} whale address(es) excluded`);
      }

      this.log(
        `[PIR-AUDIT] CHUNK: ${N} queries, ${uniqueEntryIds.length} unique real chunk entry_ids`,
      );

      const decryptedEntries = new Map<number, Uint8Array>();
      // entry_id → per-group OnionPIR Merkle DATA leaf. `pbcGroup`
      // selects the per-group DATA tree; `bin` is the leaf index within
      // it. Mirrors the Rust `data_merkle: HashMap<u32,(Hash256,usize,u32)>`.
      const dataMerkle = new Map<number, { hash: Uint8Array; pbcGroup: number; bin: number }>();
      let chunkRoundsCount = 0;

      // 🔒 CHUNK Round-Presence Symmetry (CLAUDE.md / PLAN_MERKLE_CODING.md
      // cross-cutting invariant C.1). A genuinely empty batch (no
      // scripthashes, N === 0) has nothing to hide → no CHUNK round. But
      // a batch whose scripthashes are *all* not-found / whale
      // (`uniqueEntryIds` empty) MUST still issue exactly one all-dummy
      // K_CHUNK CHUNK PIR round — skipping it would leak found-vs-not-found
      // via CHUNK round absence. Mirrors the Rust `query_chunk_level`.
      if (N > 0) {
        // Create chunk client from same secret key (no extra registration needed).
        // Post-port (commit 7): no `numEntries` arg; null check on stale-key.
        progress('Level 2', 'Setting up chunk phase...');
        await yieldToMain();
        chunkClient = this.wasmModule!.createClientFromSecretKey(this.chunkBins, clientId, secretKey);
        if (!chunkClient) {
          throw new Error(
            `OnionPIR chunk createClientFromSecretKey returned null ` +
            `(clientId=${clientId}, sk.len=${secretKey.length})`
          );
        }

        // Plan PBC rounds over the real chunk entry_ids. An all-not-found
        // batch has `uniqueEntryIds` empty → substitute a single empty
        // round so exactly one all-dummy K_CHUNK CHUNK PIR round still
        // goes out (round-presence, above). The round body handles an
        // empty `round` natively — every group falls through to a random
        // dummy and no real cuckoo lookup runs.
        const chunkRounds: [number, number][][] = uniqueEntryIds.length === 0
          ? [[]]
          : planPbcRounds(uniqueEntryIds.map(eid => deriveChunkGroups(eid)), this.chunkK);
        chunkRoundsCount = chunkRounds.length;
        this.log(`Level 2: ${uniqueEntryIds.length} entries → ${chunkRounds.length} round(s)`);

        // The reverse index only locates *real* entries; an all-not-found
        // batch never indexes it, so skip the (total-entries-scale) build.
        const reverseIndex = uniqueEntryIds.length === 0
          ? null
          : await ensureChunkReverseIndex(
              this.totalPacked,
              (msg) => progress('Level 2', msg),
            );

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
              // A non-empty `round` implies `uniqueEntryIds.length > 0`,
              // so `reverseIndex` was built (non-null) above.
              cuckooCache.set(group, buildChunkCuckooForGroup(this.wasmModule!, group, reverseIndex!, this.chunkBins));
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
          // OnionPIR CHUNK shape: 1 FHE query per group, K_CHUNK groups.
          // Differs from DPF/Harmony CHUNK (which send 2 per group); the
          // Rust `OnionClient::query_chunk_level` pin matches this.
          this.recordRound({
            kind: 'chunk',
            server_id: 0,
            db_id: dbId,
            request_bytes: batchMsg.length,
            response_bytes: respRaw.length,
            items: new Array(this.chunkK).fill(1),
          });

          const respPayload = respRaw.slice(4);
          if (respPayload[0] !== RESP_ONIONPIR_CHUNK_RESULT) throw new Error('Unexpected chunk response');
          const { results } = decodeBatchResult(respPayload, 1);

          let chunkDecrypted = 0;
          // Post-port (commit 7): unpack the raw plaintext exactly as
          // in the INDEX block above.
          const chunkWasmParams = this.wasmModule!.paramsInfo(this.chunkBins);
          for (const qi of queryInfos) {
            const rawPt = chunkClient!.decryptResponse(results[qi.group]);
            const entryBytes = unpackOnionPlaintext(
              rawPt, chunkWasmParams.polyDegree, chunkWasmParams.entrySize,
            );
            if (!entryBytes) {
              throw new Error(
                `onion_unpack rejected CHUNK plaintext (raw.len=${rawPt.length} ` +
                `N=${chunkWasmParams.polyDegree} es=${chunkWasmParams.entrySize})`
              );
            }
            const hashLen = Math.min(entryBytes.length, PACKED_ENTRY_SIZE);
            decryptedEntries.set(qi.entryId, entryBytes.slice(0, hashLen));
            // Per-group OnionPIR Merkle DATA leaf — `qi.group` selects
            // the per-group DATA tree, `qi.bin` is the leaf index. The
            // leaf hash is OnionPIR's no-prefix SHA256(decrypted_bin).
            dataMerkle.set(qi.entryId, {
              hash: sha256(entryBytes.slice(0, hashLen)),
              pbcGroup: qi.group,
              bin: qi.bin,
            });
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

      // OnionPIR Merkle info for this DB — `super_root` (the pinned
      // anchor) is surfaced on each result for display.
      const merkleInfo = this.getOnionPirMerkleForDb(this.dbId);

      // Helper: collect the per-group DATA Merkle leaves owned by query
      // `qi` — one per real chunk entry_id (so 0 for not-found / whale).
      // Phase 3 / WS-A removed the M=16 pad, so the leaf count now varies
      // with UTXO count (an admitted, documented leak); CHUNK-Merkle
      // round-presence is kept by `verifySubTree`'s ≥1 all-dummy DATA
      // sibling pass, not by padding.
      const collectOwnedDataLeaves = (
        qi: number,
      ): { hash: Uint8Array; pbcGroup: number; bin: number }[] => {
        const leaves: { hash: Uint8Array; pbcGroup: number; bin: number }[] = [];
        for (const eid of chunkOwnedPerQuery[qi]) {
          const leaf = dataMerkle.get(eid);
          if (leaf) leaves.push(leaf);
        }
        return leaves;
      };

      for (let qi = 0; qi < N; qi++) {
        const ownedLeaves = collectOwnedDataLeaves(qi);

        if (whaleQueries.has(qi)) {
          // Whale: matched INDEX entry but `numEntries == 0` → 0 DATA
          // leaves. The whale's INDEX entry is committed to the per-group
          // INDEX Merkle root, so its probed INDEX bins still verify
          // (whale-exclusion is a verifiable property). DATA round-
          // presence is handled by `verifySubTree`'s all-dummy pass.
          results[qi] = {
            entries: [],
            totalSats: 0n,
            startChunkId: 0,
            numChunks: 0,
            numRounds: chunkRoundsCount,
            isWhale: true,
            merkleSuperRoot: merkleInfo?.super_root,
            indexBinHash: indexBinHashes[qi] ?? undefined,
            indexBinLeaves: allBinsChecked.get(qi),
            dataBinLeaves: ownedLeaves,
            scriptHash: scriptHashes[qi],
            rawChunkData: new Uint8Array(0),
          };
          continue;
        }

        const ir = indexResults[qi];
        if (!ir) {
          // Not-found in INDEX — every probed cuckoo bin is committed for
          // the absence proof. Post-M=16-removal a not-found query owns
          // 0 DATA leaves; found-vs-not-found stays hidden because
          // `verifySubTree` always issues ≥1 all-dummy DATA sibling pass
          // (CHUNK-Merkle round-presence).
          const binHash = indexBinHashes[qi];
          const allBins = allBinsChecked.get(qi);
          if (binHash) {
            results[qi] = {
              entries: [],
              totalSats: 0n,
              startChunkId: 0,
              numChunks: 0,
              numRounds: chunkRoundsCount,
              isWhale: false,
              merkleSuperRoot: merkleInfo?.super_root,
              indexBinHash: binHash,
              indexBinLeaves: allBins,
              dataBinLeaves: ownedLeaves,
              scriptHash: scriptHashes[qi],
              rawChunkData: new Uint8Array(0),
            };
          }
          continue;
        }

        // Found path — assemble UTXO data from this query's real entries.
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
          merkleSuperRoot: merkleInfo?.super_root,
          indexBinHash: indexBinHashes[qi] ?? undefined,
          // ALL probed cuckoo positions (always INDEX_CUCKOO_NUM_HASHES bins —
          // see CLAUDE.md "Merkle INDEX Item-Count Symmetry"); one per-group
          // INDEX Merkle leaf each.
          indexBinLeaves: allBinsChecked.get(qi),
          // One per-group DATA Merkle leaf per real chunk entry_id.
          dataBinLeaves: ownedLeaves,
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
   * Batch-verify per-group OnionPIR Merkle proofs for multiple query
   * results. SOUNDNESS-CRITICAL — the standalone-TS mirror of the Rust
   * `onion_merkle::verify_onion_merkle_batch` (Phase 3d).
   *
   * Two per-group forests: 75 INDEX trees + 80 DATA trees, anchored by
   * one pinned `super_root`. Each leaf carried on a `QueryResult`
   * (`indexBinLeaves` / `dataBinLeaves`) is keyed by `(pbcGroup, bin)`.
   * The verifier fetches + anchor-checks the 155-tree tree-top blob,
   * runs one FHE sibling pass per kind, and walks each per-group
   * tree-top to its group root.
   *
   * **Both** sub-trees are always verified, even when one has no leaves
   * — `verifySubTree` issues one all-dummy K-padded sibling pass for an
   * empty sub-tree so a not-found / whale batch (0 DATA leaves) is
   * wire-indistinguishable from a found batch (CHUNK-Merkle
   * round-presence).
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

    // One per-group Merkle leaf per probed bin. `tree` selects the
    // INDEX vs DATA per-group forest; `pbcGroup` selects the tree.
    interface LeafItem {
      tree: 'index' | 'data';
      pbcGroup: number;
      bin: number;
      hash: Uint8Array;
      resultIdx: number;
    }
    const leaves: LeafItem[] = [];
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      // INDEX leaves — always INDEX_CUCKOO_NUM_HASHES per query (found /
      // not-found / whale alike: the INDEX item-count symmetry invariant).
      if (r.indexBinLeaves) {
        for (const lf of r.indexBinLeaves) {
          leaves.push({ tree: 'index', pbcGroup: lf.pbcGroup, bin: lf.bin, hash: lf.hash, resultIdx: i });
        }
      }
      // DATA leaves — one per real chunk entry_id (0 for not-found /
      // whale). The variable count is the admitted UTXO-count leak;
      // found-vs-not-found stays hidden via DATA round-presence below.
      if (r.dataBinLeaves) {
        for (const lf of r.dataBinLeaves) {
          leaves.push({ tree: 'data', pbcGroup: lf.pbcGroup, bin: lf.bin, hash: lf.hash, resultIdx: i });
        }
      }
    }

    // Genuinely empty input — nothing to verify, no Merkle traffic.
    // Mirrors the Rust `run_merkle_verification` empty-leaves guard.
    if (leaves.length === 0) return out;

    // Verify BOTH sub-trees — ALWAYS, even when one has no leaves. An
    // all-not-found / whale batch contributes 0 DATA leaves, but
    // `verifySubTree` still issues one all-dummy K_CHUNK sibling pass,
    // so found-vs-not-found cannot be inferred from CHUNK-Merkle traffic
    // (CLAUDE.md "CHUNK Round-Presence Symmetry"). Mirrors the Rust
    // `verify_onion_merkle_batch`, which always verifies both sub-trees.
    const indexLeaves = leaves.filter(l => l.tree === 'index');
    const dataLeaves = leaves.filter(l => l.tree === 'data');

    const indexVerdicts = await this.verifySubTree('index', merkle, indexLeaves, progress);
    const dataVerdicts = await this.verifySubTree('data', merkle, dataLeaves, progress);

    // Aggregate: a result passes iff ALL of its leaves verified. A
    // failure on any leaf can never be overridden back to `true`.
    const perResultOk = new Map<number, boolean>();
    for (const lf of leaves) {
      const verdicts = lf.tree === 'index' ? indexVerdicts : dataVerdicts;
      const ok = verdicts.get(`${lf.pbcGroup}:${lf.bin}`) ?? false;
      if (!ok) {
        perResultOk.set(lf.resultIdx, false);
      } else if (!perResultOk.has(lf.resultIdx)) {
        perResultOk.set(lf.resultIdx, true);
      }
    }

    let verified = 0;
    for (const [ri, ok] of perResultOk) {
      out[ri] = ok;
      results[ri].merkleVerified = ok;
      if (ok) verified++;
    }

    const total = perResultOk.size;
    if (verified === total && total > 0) {
      this.log(`Merkle VERIFIED: all ${total} results valid (per-group index+data trees)`, 'success');
    } else if (total > 0) {
      this.log(`Merkle: ${verified}/${total} verified, ${total - verified} failed`, verified > 0 ? 'info' : 'error');
    }

    return out;
  }

  /**
   * Verify a set of per-group OnionPIR Merkle leaves against one
   * sub-tree (INDEX or DATA). Mirrors the Rust
   * `onion_merkle::verify_sub_tree`.
   *
   * Per-group walk: fetch + anchor-check the consolidated 155-tree
   * tree-top blob, then for each "pass" issue one K-padded FHE sibling
   * round (one query per PBC group — real row for a group with a leaf,
   * random-row dummy for the rest), fold the decrypted sibling row into
   * the leaf's running hash, and walk the cached per-group tree-top to
   * the group root.
   *
   * `max(1, maxItemsPerGroup)` passes run: ≥1 even for an empty
   * sub-tree (CHUNK-Merkle round-presence) and one extra per
   * within-group collision (e.g. the two INDEX cuckoo positions of a
   * not-found query landing in the same group).
   *
   * Returns map: `"<pbcGroup>:<bin>"` → verified boolean.
   *
   * On a protocol / parse error this throws (the verdict is "could not
   * verify"); on a super-root mismatch every probed leaf is recorded
   * `false` and the sibling rounds are skipped (they would prove
   * nothing against forged roots).
   */
  private async verifySubTree(
    treeName: 'index' | 'data',
    info: OnionPirMerkleInfoJson,
    leaves: { pbcGroup: number; bin: number; hash: Uint8Array }[],
    progress: (step: string, detail: string) => void,
  ): Promise<Map<string, boolean>> {
    const out = new Map<string, boolean>();
    const arity = info.arity;
    const kind = treeName === 'index' ? info.index : info.data;
    const k = kind.k;
    const numPt = kind.num_pt;

    const treeTopReq = treeName === 'index'
      ? REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP : REQ_ONIONPIR_MERKLE_DATA_TREE_TOP;
    const treeTopResp = treeName === 'index'
      ? RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP : RESP_ONIONPIR_MERKLE_DATA_TREE_TOP;
    const sibReq = treeName === 'index'
      ? REQ_ONIONPIR_MERKLE_INDEX_SIBLING : REQ_ONIONPIR_MERKLE_DATA_SIBLING;
    const sibResp = treeName === 'index'
      ? RESP_ONIONPIR_MERKLE_INDEX_SIBLING : RESP_ONIONPIR_MERKLE_DATA_SIBLING;

    // ── 1. Fetch the consolidated 155-tree tree-top blob ───────────────
    // The whole blob is served on either TREE_TOP opcode; fetching once
    // per sub-tree mirrors the Rust `verify_sub_tree` (and keeps the
    // `merkle_tree_tops` round count = 2 — one INDEX, one DATA).
    progress('Merkle', `Fetching ${treeName} tree-top blob...`);
    // Wire: [4B len][1B req]([1B db_id] if non-zero, backward compatible).
    const ttPayloadLen = this.dbId !== 0 ? 2 : 1;
    const ttReq = new Uint8Array(4 + ttPayloadLen);
    new DataView(ttReq.buffer).setUint32(0, ttPayloadLen, true);
    ttReq[4] = treeTopReq;
    if (this.dbId !== 0) ttReq[5] = this.dbId;
    const ttRaw = await this.sendRaw(ttReq);
    // Tree-top fetch is admitted to leak (public Merkle tops). Tagged
    // `merkle_tree_tops` — matches the Rust `RoundKind::MerkleTreeTops`.
    this.recordRound({
      kind: 'merkle_tree_tops',
      server_id: 0,
      db_id: this.dbId,
      request_bytes: ttReq.length,
      response_bytes: ttRaw.length,
      items: [],
    });
    if (ttRaw.length < 5 || ttRaw[4] !== treeTopResp) {
      throw new Error(
        `Unexpected ${treeName} tree-top response: 0x${(ttRaw[4] ?? 0).toString(16)}`,
      );
    }
    const blob = ttRaw.slice(5);
    const allTops = parseOnionTreeTopCache(blob);
    this.log(
      `[PIR-AUDIT] OnionPIR Merkle ${treeName} tree-top: ${allTops.length} ` +
      `trees parsed (arity=${arity})`,
    );

    // ── 2. Bind the blob to the pinned super-root (SOUNDNESS-CRITICAL) ──
    // A super-root mismatch means the server's whole Merkle commitment
    // is untrusted (malicious server, or a DB-version skew). Every
    // probed leaf fails; the sibling rounds would prove nothing against
    // forged roots, so skip them.
    if (!checkTreeTopAnchor(info, blob, allTops, (m) => this.log(m, 'error'))) {
      for (const lf of leaves) out.set(`${lf.pbcGroup}:${lf.bin}`, false);
      return out;
    }

    // ── 3. Deduplicate leaves by (pbcGroup, bin) ───────────────────────
    const uniqueMap = new Map<string, { pbcGroup: number; bin: number; hash: Uint8Array }>();
    for (const lf of leaves) {
      const key = `${lf.pbcGroup}:${lf.bin}`;
      if (!uniqueMap.has(key)) uniqueMap.set(key, lf);
    }
    const keys = [...uniqueMap.keys()];
    const n = keys.length;
    // Per-leaf running state.
    const currentHash: Uint8Array[] = keys.map(key => uniqueMap.get(key)!.hash);
    const nodeIdx: number[] = keys.map(key => uniqueMap.get(key)!.bin);
    const failed: boolean[] = new Array(n).fill(false);

    this.log(
      `[PIR-AUDIT] OnionPIR Merkle ${treeName}: verifying ${n} unique ` +
      `leaves (k=${k})`,
    );

    // ── 4. Group leaves by PBC group ───────────────────────────────────
    // Multiple leaves share a group only for the INDEX-not-found case
    // (both cuckoo positions) or batch collisions; each surplus leaf
    // becomes one extra pass, each pass itself fully K-padded.
    const itemsByGroup = new Map<number, number[]>();
    for (let i = 0; i < n; i++) {
      const g = uniqueMap.get(keys[i])!.pbcGroup;
      const arr = itemsByGroup.get(g);
      if (arr) arr.push(i);
      else itemsByGroup.set(g, [i]);
    }
    // ≥1: an empty sub-tree still issues one all-dummy pass (round-presence).
    let maxItemsPerGroup = 1;
    for (const arr of itemsByGroup.values()) {
      if (arr.length > maxItemsPerGroup) maxItemsPerGroup = arr.length;
    }

    // ── 5. FHE sibling client (one per sub-tree — fixed num_pt) ────────
    const sibClient = this.wasmModule!.createClientFromSecretKey(
      numPt, this.fheClientId, this.fheSecretKey!,
    );
    if (!sibClient) {
      throw new Error(
        `OnionPIR Merkle ${treeName}: sib createClientFromSecretKey ` +
        `returned null (clientId=${this.fheClientId}, num_pt=${numPt}, ` +
        `sk.len=${this.fheSecretKey!.length})`,
      );
    }
    try {
      const pinfo = this.wasmModule!.paramsInfo(numPt);
      if (pinfo.entrySize !== arity * 32) {
        throw new Error(
          `OnionPIR Merkle ${treeName}: sibling DB entry_size ` +
          `${pinfo.entrySize} != arity*32 (${arity * 32}) — onionpir ` +
          `rev / build-shape drift`,
        );
      }

      // ── 6. Sibling passes: one K-padded FHE round per pass ───────────
      // There is exactly ONE PIR sibling level (leaf → level-1). Each
      // pass handles at most one leaf per group, and every leaf is in
      // exactly one pass, so per-pass updates of nodeIdx / currentHash
      // never interfere.
      for (let pass = 0; pass < maxItemsPerGroup; pass++) {
        progress('Merkle', `${treeName} sibling pass ${pass + 1}/${maxItemsPerGroup}...`);

        // Which leaf (if any) each group contributes at this pass.
        const passGroupToItem = new Map<number, number>();
        for (const [g, arr] of itemsByGroup) {
          if (pass < arr.length) passGroupToItem.set(g, arr[pass]);
        }

        // K FHE queries — real row for a group with a pass-`pass` leaf,
        // random-row dummy for the rest. K-padding: the server sees K
        // indistinguishable FHE queries every pass, regardless of how
        // many leaves are real (CLAUDE.md "Query Padding").
        const queries: Uint8Array[] = [];
        for (let g = 0; g < k; g++) {
          const item = passGroupToItem.get(g);
          const row = item !== undefined
            ? Math.floor(nodeIdx[item] / arity)
            : Number(this.rng.nextU64() % BigInt(numPt));
          queries.push(sibClient.generateQuery(row));
          if (g % 5 === 4) await yieldToMain();
        }

        // round_id is vestigial under the per-group design — send 0.
        const batchMsg = encodeBatchQuery(sibReq, 0, queries, this.dbId);
        const respRaw = await this.sendRaw(batchMsg);
        // One PIR sibling level ⇒ level is always 0. K FHE queries, one
        // per PBC group — items[g] = 1 each. Matches the Rust
        // `verify_sub_tree`'s `Index/ChunkMerkleSiblings { level: 0 }`.
        this.recordRound({
          kind: treeName === 'index' ? 'index_merkle_siblings' : 'chunk_merkle_siblings',
          level: 0,
          server_id: 0,
          db_id: this.dbId,
          request_bytes: batchMsg.length,
          response_bytes: respRaw.length,
          items: new Array(k).fill(1),
        });
        const respPayload = respRaw.slice(4);
        if (respPayload[0] !== sibResp) {
          throw new Error(
            `Unexpected ${treeName} sibling response: 0x${respPayload[0].toString(16)}`,
          );
        }
        const { results: batch } = decodeBatchResult(respPayload, 1);

        // Fold each real group's decrypted sibling row into its leaf.
        for (const [g, item] of passGroupToItem) {
          if (failed[item]) continue;
          if (g >= batch.length) {
            this.log(
              `[PIR-AUDIT] OnionPIR Merkle ${treeName} pass ${pass}: result ` +
              `batch truncated at group ${g} (len ${batch.length})`,
              'error',
            );
            failed[item] = true;
            continue;
          }
          const rawPt = sibClient.decryptResponse(batch[g]);
          const row = unpackOnionPlaintext(rawPt, pinfo.polyDegree, pinfo.entrySize);
          if (!row) {
            throw new Error(
              `onion_unpack rejected ${treeName} sibling plaintext ` +
              `(raw.len=${rawPt.length} N=${pinfo.polyDegree} ` +
              `es=${pinfo.entrySize})`,
            );
          }
          // Recompute the level-1 parent of bin `nodeIdx[item]`: the
          // decrypted row holds that parent's `arity` leaf children;
          // replace the child at `bin % arity` with the leaf's own
          // committed hash, then hash the `arity` children. If the
          // server lied about any sibling, the parent — and hence the
          // root — will not match.
          const childPos = nodeIdx[item] % arity;
          const children: Uint8Array[] = [];
          for (let c = 0; c < arity; c++) {
            if (c === childPos) {
              children.push(currentHash[item]);
            } else {
              const off = c * 32;
              children.push(off + 32 <= row.length ? row.slice(off, off + 32) : ZERO_HASH);
            }
          }
          currentHash[item] = computeParentN(children);
          nodeIdx[item] = Math.floor(nodeIdx[item] / arity);
        }
      }
    } finally {
      sibClient.delete();
    }

    // ── 7. Walk each leaf's cached tree-top to its per-group root ──────
    for (let i = 0; i < n; i++) {
      const { pbcGroup, bin } = uniqueMap.get(keys[i])!;
      if (failed[i]) {
        out.set(keys[i], false);
        continue;
      }
      // 75 INDEX trees first, then 80 DATA trees.
      const topIdx = treeName === 'index' ? pbcGroup : info.index.k + pbcGroup;
      const top = allTops[topIdx];
      if (!top) {
        this.log(
          `[PIR-AUDIT] OnionPIR Merkle ${treeName}: no tree-top for group ` +
          `${pbcGroup} (leaf bin ${bin})`,
          'error',
        );
        out.set(keys[i], false);
        continue;
      }
      const walked = walkTreeTopToRoot(currentHash[i], nodeIdx[i], top, arity);
      // `onionTreeTopRoot` is non-null — `checkTreeTopAnchor` already
      // rejected any tree-top without a root level.
      const expected = onionTreeTopRoot(top);
      const ok = expected !== null && bytesEqual(walked, expected);
      if (!ok) {
        this.log(
          `[PIR-AUDIT] OnionPIR Merkle ${treeName} group ${pbcGroup} bin ` +
          `${bin}: root MISMATCH`,
          'error',
        );
      }
      out.set(keys[i], ok);
    }

    const verified = [...out.values()].filter(Boolean).length;
    this.log(`[PIR-AUDIT] OnionPIR Merkle ${treeName}: ${verified}/${n} leaves verified`);
    return out;
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
  serverUrl: string = 'wss://weikeng1.bitcoinpir.org',
): OnionPirWebClient {
  return new OnionPirWebClient({ serverUrl });
}
