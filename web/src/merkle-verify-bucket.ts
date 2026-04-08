/**
 * Per-bucket bin Merkle verification for DPF clients.
 *
 * Each PBC group (75 for INDEX, 80 for CHUNK) has its own arity-8 Merkle
 * tree over the cuckoo bins. Sibling tables are flat (row = 8 × 32B child
 * hashes), indexed directly by group_id.
 *
 * Verification flow:
 *   1. Compute leaf = SHA256(binIndex_u32_LE || binContent)
 *   2. For each sibling level: batch DPF queries across K groups
 *   3. Walk tree-top cache to per-group root
 *   4. Verify per-group root matches server-reported root
 */

import {
  K, K_CHUNK,
  BUCKET_MERKLE_ARITY,
  BUCKET_MERKLE_SIB_ROW_SIZE,
  REQ_BUCKET_MERKLE_TREE_TOPS,
  RESP_BUCKET_MERKLE_TREE_TOPS,
} from './constants.js';

import { computeBinLeafHash, computeParentN, ZERO_HASH } from './merkle.js';
import { sha256 } from './hash.js';
import { genDpfKeysN } from './dpf.js';
import { encodeRequest, decodeResponse, type BatchQuery } from './protocol.js';
import type { ManagedWebSocket } from './ws.js';
import type { BucketMerkleInfoJson, BucketMerkleLevelInfo } from './server-info.js';
import { DummyRng } from './codec.js';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface BucketMerkleItem {
  /** PBC group this address was placed in (INDEX level) */
  indexPbcGroup: number;
  /** Cuckoo bin index within that group (INDEX level) */
  indexBinIndex: number;
  /** Raw bin content from PIR (INDEX level, slotsPerBin × slotSize bytes) */
  indexBinContent: Uint8Array;
  /** PBC group for each chunk bin (CHUNK level) */
  chunkPbcGroups: number[];
  /** Cuckoo bin index for each chunk bin */
  chunkBinIndices: number[];
  /** Raw bin content for each chunk bin */
  chunkBinContents: Uint8Array[];
}

type LogFn = (msg: string) => void;
type ProgressFn = (step: string, detail: string) => void;

// ─── Tree-top cache parsing ─────────────────────────────────────────────

interface ParsedTreeTops {
  /** Per-group tree-top. Indexed by sequential order: [0..K-1] = index, [K..K+K_CHUNK-1] = chunk */
  tops: { cacheFromLevel: number; levels: Uint8Array[][] }[];
}

function parseTreeTops(data: Uint8Array): ParsedTreeTops {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const numTrees = dv.getUint32(0, true);
  let off = 4;

  const tops: ParsedTreeTops['tops'] = [];
  for (let t = 0; t < numTrees; t++) {
    const cacheFromLevel = data[off]; off += 1;
    const _totalNodes = dv.getUint32(off, true); off += 4;
    const _arity = dv.getUint16(off, true); off += 2;
    const numCachedLevels = data[off]; off += 1;

    const levels: Uint8Array[][] = [];
    for (let l = 0; l < numCachedLevels; l++) {
      const numNodes = dv.getUint32(off, true); off += 4;
      const nodes: Uint8Array[] = [];
      for (let n = 0; n < numNodes; n++) {
        nodes.push(data.slice(off, off + 32));
        off += 32;
      }
      levels.push(nodes);
    }
    tops.push({ cacheFromLevel, levels });
  }

  return { tops };
}

// ─── Main verification function ─────────────────────────────────────────

/**
 * Batch-verify per-bucket bin Merkle proofs via DPF.
 *
 * @param ws0 - WebSocket to server 0 (primary)
 * @param ws1 - WebSocket to server 1 (secondary)
 * @param info - BucketMerkleInfoJson from server
 * @param items - One per queried address
 * @param onProgress - Optional progress callback
 * @param log - Optional log function
 * @param dbId - Optional database ID (0=main, 1+=delta). Defaults to 0.
 * @returns boolean[] — one per item
 */
export async function verifyBucketMerkleBatchDpf(
  ws0: ManagedWebSocket,
  ws1: ManagedWebSocket,
  info: BucketMerkleInfoJson,
  items: BucketMerkleItem[],
  onProgress?: ProgressFn,
  log?: LogFn,
  dbId: number = 0,
): Promise<boolean[]> {
  const A = BUCKET_MERKLE_ARITY; // 8
  const rng = new DummyRng();

  // ── Step 1: Fetch tree-top caches ──────────────────────────────────
  log?.('Fetching bucket Merkle tree-tops...');
  onProgress?.('Merkle', 'Fetching tree-top caches...');

  const topsLen = dbId !== 0 ? 2 : 1;
  const topsReq = new Uint8Array(4 + topsLen);
  new DataView(topsReq.buffer).setUint32(0, topsLen, true);
  topsReq[4] = REQ_BUCKET_MERKLE_TREE_TOPS;
  if (dbId !== 0) {
    topsReq[5] = dbId;
  }

  const topsRaw = await ws0.sendRaw(topsReq);
  // Response: [4B len][1B variant][tree_tops_bytes...]
  if (topsRaw.length < 6 || topsRaw[4] !== RESP_BUCKET_MERKLE_TREE_TOPS) {
    log?.('Failed to fetch bucket Merkle tree-tops');
    return items.map(() => false);
  }
  const topsData = topsRaw.slice(5);

  // Verify tree-tops integrity
  const topsHash = sha256(topsData);
  const expectedHash = hexToBytes(info.tree_tops_hash);
  if (!bytesEqual(topsHash, expectedHash)) {
    log?.('Tree-tops integrity check FAILED');
    return items.map(() => false);
  }
  log?.('Tree-top cache integrity: OK');

  const parsedTops = parseTreeTops(topsData);

  // ── Step 2: Verify INDEX bins ──────────────────────────────────────
  log?.('Verifying INDEX bins...');
  onProgress?.('Merkle', 'Verifying INDEX Merkle...');

  const indexVerified = await verifySiblingLevels(
    ws0, ws1, rng, items.map(it => ({
      pbcGroup: it.indexPbcGroup,
      binIndex: it.indexBinIndex,
      binContent: it.indexBinContent,
    })),
    info.index_levels,
    info.index_roots,
    parsedTops.tops.slice(0, K),
    K,
    0, // table_type = 0 for INDEX
    log,
    dbId,
  );

  // ── Step 3: Verify CHUNK bins ──────────────────────────────────────
  // For each address, we need to verify all its chunk bins.
  // Flatten chunk bins across all addresses, then re-map results.
  log?.('Verifying CHUNK bins...');
  onProgress?.('Merkle', 'Verifying CHUNK Merkle...');

  const chunkItems: { pbcGroup: number; binIndex: number; binContent: Uint8Array }[] = [];
  const chunkItemMap: { addrIdx: number; chunkIdx: number }[] = [];

  for (let i = 0; i < items.length; i++) {
    for (let c = 0; c < items[i].chunkPbcGroups.length; c++) {
      chunkItems.push({
        pbcGroup: items[i].chunkPbcGroups[c],
        binIndex: items[i].chunkBinIndices[c],
        binContent: items[i].chunkBinContents[c],
      });
      chunkItemMap.push({ addrIdx: i, chunkIdx: c });
    }
  }

  const chunkVerified = chunkItems.length > 0 ? await verifySiblingLevels(
    ws0, ws1, rng, chunkItems,
    info.chunk_levels,
    info.chunk_roots,
    parsedTops.tops.slice(K, K + K_CHUNK),
    K_CHUNK,
    1, // table_type = 1 for CHUNK
    log,
    dbId,
  ) : [];

  // ── Step 4: Combine results ────────────────────────────────────────
  const results: boolean[] = new Array(items.length).fill(true);

  // INDEX check
  for (let i = 0; i < items.length; i++) {
    if (!indexVerified[i]) results[i] = false;
  }

  // CHUNK check: all chunk bins for an address must verify
  for (let j = 0; j < chunkItemMap.length; j++) {
    if (!chunkVerified[j]) {
      results[chunkItemMap[j].addrIdx] = false;
    }
  }

  const passed = results.filter(v => v).length;
  const failed = results.length - passed;
  log?.(`Merkle: ${passed}/${results.length} verified, ${failed} failed`);

  return results;
}

// ─── Core: verify one table type (INDEX or CHUNK) ───────────────────────

async function verifySiblingLevels(
  ws0: ManagedWebSocket,
  ws1: ManagedWebSocket,
  rng: DummyRng,
  items: { pbcGroup: number; binIndex: number; binContent: Uint8Array }[],
  levelInfos: BucketMerkleLevelInfo[],
  rootsHex: string[],
  treeTops: { cacheFromLevel: number; levels: Uint8Array[][] }[],
  tableK: number,
  tableType: number,
  log?: LogFn,
  dbId: number = 0,
): Promise<boolean[]> {
  const A = BUCKET_MERKLE_ARITY;
  const N = items.length;

  // Per-item state
  const currentHash: Uint8Array[] = new Array(N);
  const nodeIdx: number[] = new Array(N);

  // Compute leaf hashes
  for (let i = 0; i < N; i++) {
    currentHash[i] = computeBinLeafHash(items[i].binIndex, items[i].binContent);
    nodeIdx[i] = items[i].binIndex;
  }

  // For each sibling level, query all K groups via DPF
  for (let level = 0; level < levelInfos.length; level++) {
    const levelInfo = levelInfos[level];

    // Determine which group_id each item needs at this level
    // group_id = floor(nodeIdx / arity)
    const itemGroupIds: number[] = items.map((_, i) => Math.floor(nodeIdx[i] / A));

    // Build batch: one DPF key-pair per PBC group (tableK groups total)
    // For each PBC group, at most one item is "real" (the rest are dummy)
    const groupToItem = new Map<number, number>(); // pbcGroup → item index
    for (let i = 0; i < N; i++) {
      groupToItem.set(items[i].pbcGroup, i); // last one wins for multi-address
    }

    // Generate DPF keys for all K groups
    const s0Keys: Uint8Array[][] = [];
    const s1Keys: Uint8Array[][] = [];

    for (let g = 0; g < tableK; g++) {
      let alpha: number;
      const itemIdx = groupToItem.get(g);
      if (itemIdx !== undefined) {
        // Real: target the group_id in the flat table
        alpha = itemGroupIds[itemIdx];
      } else {
        // Dummy: random target
        alpha = Number(rng.nextU64() % BigInt(levelInfo.bins_per_table));
      }

      const pair = await genDpfKeysN(alpha, levelInfo.dpf_n);
      s0Keys.push([pair.key0]);
      s1Keys.push([pair.key1]);
    }

    // Encode and send batch to both servers using shared protocol
    const roundId = tableType * 100 + level;
    const query0: BatchQuery = { level: 2, roundId, keys: s0Keys, dbId: dbId || undefined };
    const query1: BatchQuery = { level: 2, roundId, keys: s1Keys, dbId: dbId || undefined };
    const req0Bytes = encodeRequest({ type: 'BucketMerkleSibBatch', query: query0 });
    const req1Bytes = encodeRequest({ type: 'BucketMerkleSibBatch', query: query1 });

    const [resp0Raw, resp1Raw] = await Promise.all([
      ws0.sendRaw(req0Bytes),
      ws1.sendRaw(req1Bytes),
    ]);

    // Decode responses using shared protocol decoder
    const resp0 = decodeResponse(resp0Raw.slice(4)); // strip 4-byte length prefix
    const resp1 = decodeResponse(resp1Raw.slice(4));

    if (resp0.type !== 'BucketMerkleSibBatch' || resp1.type !== 'BucketMerkleSibBatch') {
      log?.(`Merkle L${level}: failed to get sibling responses (${resp0.type}, ${resp1.type})`);
      return items.map(() => false);
    }

    const r0Results = resp0.result.results;
    const r1Results = resp1.result.results;

    // For each real item, XOR the two server responses to get the sibling row
    for (let i = 0; i < N; i++) {
      const g = items[i].pbcGroup;
      if (g >= r0Results.length || g >= r1Results.length) {
        log?.(`Merkle L${level}: group ${g} out of range (have ${r0Results.length})`);
        currentHash[i] = ZERO_HASH;
        continue;
      }

      // XOR the single hash-function result (flat table = 1 key per group)
      const r0 = r0Results[g][0];
      const r1 = r1Results[g][0];
      const row = xorBuffers(r0, r1);

      if (row.length < BUCKET_MERKLE_SIB_ROW_SIZE) {
        log?.(`Merkle L${level}: row too short for group ${g}`);
        currentHash[i] = ZERO_HASH;
        continue;
      }

      // Extract arity children from the row
      const childPos = nodeIdx[i] % A;
      const children: Uint8Array[] = [];
      for (let c = 0; c < A; c++) {
        if (c === childPos) {
          children.push(currentHash[i]);
        } else {
          children.push(row.slice(c * 32, (c + 1) * 32));
        }
      }
      currentHash[i] = computeParentN(children);
      nodeIdx[i] = Math.floor(nodeIdx[i] / A);
    }
  }

  // Walk tree-top cache to root for each item
  const verified: boolean[] = new Array(N);
  for (let i = 0; i < N; i++) {
    const g = items[i].pbcGroup;
    const top = treeTops[g];
    if (!top) {
      verified[i] = false;
      continue;
    }

    let hash = currentHash[i];
    let idx = nodeIdx[i];

    for (let cl = 0; cl < top.levels.length - 1; cl++) {
      const levelNodes = top.levels[cl];
      const parentStart = Math.floor(idx / A) * A;
      const childPos = idx % A;
      const children: Uint8Array[] = [];
      for (let c = 0; c < A; c++) {
        const nodeI = parentStart + c;
        if (c === childPos) {
          children.push(hash);
        } else if (nodeI < levelNodes.length) {
          children.push(levelNodes[nodeI]);
        } else {
          children.push(ZERO_HASH);
        }
      }
      hash = computeParentN(children);
      idx = Math.floor(idx / A);
    }

    // Compare to expected root
    const expectedRoot = hexToBytes(rootsHex[g]);
    verified[i] = bytesEqual(hash, expectedRoot);

    if (!verified[i]) {
      log?.(`Merkle: group ${g} root mismatch`);
    }
  }

  return verified;
}

// ─── Wire format helpers (using shared protocol.ts) ─────────────────────
// Encoding/decoding is handled by encodeRequest/decodeResponse from protocol.ts.

// ─── Utility ────────────────────────────────────────────────────────────

function xorBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ (b[i] ?? 0);
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
