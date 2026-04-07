/**
 * Client-side Merkle tree verification for PIR responses.
 *
 * Uses SHA-256 from hash.js (same as the rest of the web client).
 * Implements the same N-ary Merkle tree logic as pir-core/src/merkle.rs.
 */

import { sha256 } from './hash.js';

/** 32-byte zero hash (padding for incomplete groups). */
export const ZERO_HASH = new Uint8Array(32);

/**
 * Compute a leaf hash: SHA256(scriptHash || treeLoc_u32_LE || dataHash).
 */
export function computeLeafHash(
  scriptHash: Uint8Array,
  treeLoc: number,
  dataHash: Uint8Array,
): Uint8Array {
  const preimage = new Uint8Array(20 + 4 + 32);
  preimage.set(scriptHash, 0);
  new DataView(preimage.buffer).setUint32(20, treeLoc, true);
  preimage.set(dataHash, 24);
  return sha256(preimage);
}

/**
 * Compute data hash: SHA256(chunkData).
 */
export function computeDataHash(chunkData: Uint8Array): Uint8Array {
  return sha256(chunkData);
}

/**
 * Per-bucket bin Merkle: leaf = SHA256(binIndex_u32_LE || binContent).
 *
 * Each leaf in a per-PBC-group Merkle tree commits to the bin index and
 * all slot data at that bin.
 */
export function computeBinLeafHash(binIndex: number, binContent: Uint8Array): Uint8Array {
  const preimage = new Uint8Array(4 + binContent.length);
  new DataView(preimage.buffer).setUint32(0, binIndex, true);
  preimage.set(binContent, 4);
  return sha256(preimage);
}

/**
 * Compute an N-ary parent hash: SHA256(child_0 || child_1 || ... || child_{N-1}).
 *
 * @param children - Array of 32-byte child hashes (length = arity)
 */
export function computeParentN(children: Uint8Array[]): Uint8Array {
  const preimage = new Uint8Array(children.length * 32);
  for (let i = 0; i < children.length; i++) {
    preimage.set(children[i], i * 32);
  }
  return sha256(preimage);
}

/**
 * Parse the tree-top cache from a hex string (as provided by the server JSON info).
 *
 * Header: [1B cache_from_level][4B total_nodes LE][2B arity LE][1B num_cached_levels]
 * Per-level: [4B num_nodes LE] then [num_nodes x 32B hashes]
 */
export interface TreeTopCache {
  cacheFromLevel: number;
  arity: number;
  levels: Uint8Array[][]; // levels[0] = first cached level, levels[last] = [root]
}

export function parseTreeTopCache(data: Uint8Array): TreeTopCache {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const cacheFromLevel = data[0];
  // skip total_nodes at [1..5]
  const arity = dv.getUint16(5, true);
  const numCachedLevels = data[7];

  let offset = 8;
  const levels: Uint8Array[][] = [];
  for (let i = 0; i < numCachedLevels; i++) {
    const numNodes = dv.getUint32(offset, true);
    offset += 4;
    const level: Uint8Array[] = [];
    for (let j = 0; j < numNodes; j++) {
      level.push(data.slice(offset, offset + 32));
      offset += 32;
    }
    levels.push(level);
  }

  return { cacheFromLevel, arity, levels };
}

/**
 * Verify a full Merkle proof given sibling groups and tree-top cache.
 *
 * @param scriptHash  - 20-byte script hash
 * @param treeLoc     - Leaf position in the Merkle tree
 * @param dataHash    - SHA256 of the raw chunk data
 * @param siblingGroups - Array of sibling groups per level (each is arity child hashes)
 * @param treeTopCache - Parsed tree-top cache
 * @param expectedRoot - 32-byte expected root hash
 * @returns true if the proof is valid
 */
export function verifyMerkleProof(
  scriptHash: Uint8Array,
  treeLoc: number,
  dataHash: Uint8Array,
  siblingGroups: Uint8Array[][],
  treeTopCache: TreeTopCache,
  expectedRoot: Uint8Array,
): boolean {
  const arity = treeTopCache.arity;
  const leafHash = computeLeafHash(scriptHash, treeLoc, dataHash);
  let currentHash = leafHash;
  let nodeIdx = treeLoc;

  // Walk sibling levels (from PIR queries)
  for (const children of siblingGroups) {
    currentHash = computeParentN(children);
    nodeIdx = Math.floor(nodeIdx / arity);
  }

  // Walk tree-top cache levels (excluding the last which is the root)
  for (let i = 0; i < treeTopCache.levels.length - 1; i++) {
    const levelNodes = treeTopCache.levels[i];
    const parentStart = Math.floor(nodeIdx / arity) * arity;
    const children: Uint8Array[] = [];
    for (let c = 0; c < arity; c++) {
      const childIdx = parentStart + c;
      if (childIdx < levelNodes.length) {
        children.push(levelNodes[childIdx]);
      } else {
        children.push(ZERO_HASH);
      }
    }
    currentHash = computeParentN(children);
    nodeIdx = Math.floor(nodeIdx / arity);
  }

  // Compare to expected root
  if (currentHash.length !== expectedRoot.length) return false;
  for (let i = 0; i < currentHash.length; i++) {
    if (currentHash[i] !== expectedRoot[i]) return false;
  }
  return true;
}
