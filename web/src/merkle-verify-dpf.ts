/**
 * Standalone DPF-based Merkle verification.
 *
 * Extracted so both BatchPirClient and HarmonyPirClient can verify
 * Merkle proofs using the 2-server DPF sibling query protocol.
 */

import {
  deriveIntBuckets3, deriveCuckooKeyGeneric, cuckooHashInt, sha256,
} from './hash.js';
import { genDpfKeysN } from './dpf.js';
import { encodeRequest, decodeResponse } from './protocol.js';
import { findGroupInSiblingResult } from './scan.js';
import { DummyRng } from './codec.js';
import {
  computeDataHash, computeLeafHash, computeParentN,
  parseTreeTopCache, ZERO_HASH,
  type TreeTopCache,
} from './merkle.js';
import { REQ_MERKLE_TREE_TOP, RESP_MERKLE_TREE_TOP } from './constants.js';
import type { ManagedWebSocket } from './ws.js';
import type { MerkleInfoJson } from './server-info.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function xorBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(Math.max(a.length, b.length));
  for (let i = 0; i < result.length; i++) {
    result[i] = (a[i] || 0) ^ (b[i] || 0);
  }
  return result;
}

// ─── Tree-top cache (shared across calls) ───────────────────────────────────

let cachedTreeTop: { rawBytes: Uint8Array; parsed: TreeTopCache } | null = null;

async function fetchTreeTopCache(
  ws: ManagedWebSocket,
): Promise<{ rawBytes: Uint8Array; parsed: TreeTopCache }> {
  if (cachedTreeTop) return cachedTreeTop;

  const req = new Uint8Array([1, 0, 0, 0, REQ_MERKLE_TREE_TOP]);
  const raw = await ws.sendRaw(req);

  const variant = raw[4];
  if (variant !== RESP_MERKLE_TREE_TOP) {
    throw new Error(`Unexpected tree-top response variant: 0x${variant.toString(16)}`);
  }
  const treeTopBytes = raw.slice(5);
  const parsed = parseTreeTopCache(treeTopBytes);

  cachedTreeTop = { rawBytes: treeTopBytes, parsed };
  return cachedTreeTop;
}

/** Clear the cached tree-top (call on disconnect). */
export function clearTreeTopCache(): void {
  cachedTreeTop = null;
}

// ─── Main verification function ─────────────────────────────────────────────

/**
 * Verify a Merkle proof using 2-server DPF sibling queries.
 *
 * @param ws0 - ManagedWebSocket to server 0 (primary)
 * @param ws1 - ManagedWebSocket to server 1 (secondary)
 * @param merkle - Merkle info from server JSON
 * @param scriptHash - 20-byte script hash
 * @param rawChunkData - Raw assembled chunk data
 * @param treeLoc - Leaf position in Merkle tree
 * @param onProgress - Optional progress callback
 * @param onLog - Optional log callback
 * @returns true if verified
 */
export async function verifyMerkleDpf(
  ws0: ManagedWebSocket,
  ws1: ManagedWebSocket,
  merkle: MerkleInfoJson,
  scriptHash: Uint8Array,
  rawChunkData: Uint8Array,
  treeLoc: number,
  onProgress?: (step: string, detail: string) => void,
  onLog?: (msg: string, level: 'info' | 'success' | 'error') => void,
): Promise<boolean> {
  const progress = onProgress || (() => {});
  const log = onLog || (() => {});
  const rng = new DummyRng();

  // ── Fetch tree-top cache ─────────────────────────────────────────
  progress('Merkle', 'Fetching tree-top cache...');
  const treeTop = await fetchTreeTopCache(ws0);
  const expectedRoot = hexToBytes(merkle.root);

  // Verify tree-top cache integrity
  const treeTopHash = sha256(treeTop.rawBytes);
  const expectedTopHash = hexToBytes(merkle.tree_top_hash);
  if (!treeTopHash.every((b, i) => b === expectedTopHash[i])) {
    log('Tree-top cache integrity check FAILED', 'error');
    return false;
  }
  log('Tree-top cache integrity: OK', 'success');

  // ── Compute leaf hash ────────────────────────────────────────────
  const dataHash = computeDataHash(rawChunkData);
  const leafHash = computeLeafHash(scriptHash, treeLoc, dataHash);
  let currentHash = leafHash;
  let nodeIdx = treeLoc;

  // ── Sibling PIR rounds (DPF) ─────────────────────────────────────
  for (let level = 0; level < merkle.sibling_levels; level++) {
    progress('Merkle', `Sibling level ${level + 1}/${merkle.sibling_levels}...`);
    const levelInfo = merkle.levels[level];
    const groupId = Math.floor(nodeIdx / merkle.arity);
    const levelSeed = BigInt('0xBA7C51B100000000') + BigInt(level);

    const myBuckets = deriveIntBuckets3(groupId, merkle.sibling_k);
    const assignedBucket = myBuckets[0];

    const myLocs: number[] = [];
    for (let h = 0; h < 2; h++) {
      const ck = deriveCuckooKeyGeneric(levelSeed, assignedBucket, h);
      myLocs.push(cuckooHashInt(groupId, ck, levelInfo.bins_per_table));
    }

    const s0Keys: Uint8Array[][] = [];
    const s1Keys: Uint8Array[][] = [];
    for (let b = 0; b < merkle.sibling_k; b++) {
      const s0B: Uint8Array[] = [];
      const s1B: Uint8Array[] = [];
      for (let h = 0; h < 2; h++) {
        const alpha = b === assignedBucket
          ? myLocs[h]
          : Number(rng.nextU64() % BigInt(levelInfo.bins_per_table));
        const keys = await genDpfKeysN(alpha, levelInfo.dpf_n);
        s0B.push(keys.key0);
        s1B.push(keys.key1);
      }
      s0Keys.push(s0B);
      s1Keys.push(s1B);
    }

    const mReq0 = encodeRequest({ type: 'MerkleSiblingBatch', query: { level: 2, roundId: level, keys: s0Keys } });
    const mReq1 = encodeRequest({ type: 'MerkleSiblingBatch', query: { level: 2, roundId: level, keys: s1Keys } });

    const [mraw0, mraw1] = await Promise.all([
      ws0.sendRaw(mReq0),
      ws1.sendRaw(mReq1),
    ]);
    const mresp0 = decodeResponse(mraw0.slice(4));
    const mresp1 = decodeResponse(mraw1.slice(4));

    if (mresp0.type !== 'MerkleSiblingBatch' || mresp1.type !== 'MerkleSiblingBatch') {
      log(`Merkle L${level}: unexpected response`, 'error');
      return false;
    }

    const mr0 = mresp0.result.results[assignedBucket];
    const mr1 = mresp1.result.results[assignedBucket];
    let children: Uint8Array[] | null = null;
    for (let h = 0; h < 2; h++) {
      const xored = xorBuffers(mr0[h], mr1[h]);
      children = findGroupInSiblingResult(xored, groupId, merkle.arity, merkle.sibling_bucket_size, merkle.sibling_slot_size);
      if (children) break;
    }

    if (!children) {
      log(`Merkle L${level}: group ${groupId} not found`, 'error');
      return false;
    }

    currentHash = computeParentN(children);
    nodeIdx = groupId;
  }

  // ── Walk tree-top cache to root ──────────────────────────────────
  progress('Merkle', 'Walking tree-top cache to root...');
  const cache = treeTop.parsed;
  for (let ci = 0; ci < cache.levels.length - 1; ci++) {
    const levelNodes = cache.levels[ci];
    const parentStart = Math.floor(nodeIdx / merkle.arity) * merkle.arity;
    const childHashes: Uint8Array[] = [];
    for (let c = 0; c < merkle.arity; c++) {
      const idx = parentStart + c;
      childHashes.push(idx < levelNodes.length ? levelNodes[idx] : ZERO_HASH);
    }
    currentHash = computeParentN(childHashes);
    nodeIdx = Math.floor(nodeIdx / merkle.arity);
  }

  // ── Check root ───────────────────────────────────────────────────
  const verified = currentHash.length === expectedRoot.length &&
    currentHash.every((b, i) => b === expectedRoot[i]);

  if (verified) {
    log(`Merkle VERIFIED: proof valid to root ${merkle.root.substring(0, 16)}...`, 'success');
  } else {
    log('Merkle FAILED: root mismatch', 'error');
  }

  return verified;
}
