/**
 * Apply a delta query result on top of a full snapshot query result.
 *
 * Used by the multi-database sync flow: after a fresh sync against a full
 * checkpoint, subsequent delta databases are applied to bring the snapshot
 * up to a more recent height. The merge is per-scripthash:
 *
 *   1. Start from the snapshot's `entries` (a UtxoEntry[])
 *   2. Remove entries listed in `delta.spent` (match by txid+vout)
 *   3. Append entries from `delta.newUtxos`
 *
 * Both inputs are typed as `QueryResult` (from client.ts) since both come
 * from `BatchPirClient.queryBatch` / `queryDelta`. The delta's `rawChunkData`
 * is delta-encoded bytes (not standard UTXO data), so we decode it here with
 * `decodeDeltaData` from codec.ts.
 */

import type { QueryResult, UtxoEntry } from './client.js';
import { decodeDeltaData, type DeltaData, type SpentRef } from './codec.js';

// ─── Single-result merge ─────────────────────────────────────────────────────

/**
 * Merge a delta query result into a snapshot query result for a single
 * scripthash. Returns a new `QueryResult` (does not mutate either input).
 *
 * The returned result preserves the snapshot's metadata (chunk ids, scripthash)
 * but uses the merged entry list and recomputed `totalSats`.
 */
export function mergeDeltaIntoSnapshot(
  snapshot: QueryResult | null,
  deltaResult: QueryResult | null,
  onError?: (msg: string) => void,
): QueryResult | null {
  // No snapshot → nothing to merge into. Caller decides what to do.
  if (!snapshot) return null;

  // Whale snapshot → cannot apply a delta meaningfully.
  if (snapshot.isWhale) return snapshot;

  // No delta result for this scripthash → nothing changed.
  if (!deltaResult || deltaResult.isWhale) return snapshot;

  // Decode the delta payload from rawChunkData. If absent or empty, no change.
  const rawDelta = deltaResult.rawChunkData;
  if (!rawDelta || rawDelta.length === 0) return snapshot;

  let delta: DeltaData;
  try {
    delta = decodeDeltaData(rawDelta, onError);
  } catch (e) {
    onError?.(`mergeDeltaIntoSnapshot: failed to decode delta: ${e}`);
    return snapshot;
  }

  return applyDeltaData(snapshot, delta);
}

/**
 * Apply an already-decoded `DeltaData` to a snapshot. Pure function on the
 * entries array; useful for tests and for callers that already decoded.
 */
export function applyDeltaData(
  snapshot: QueryResult,
  delta: DeltaData,
): QueryResult {
  // Build a key set of spent (txid_hex, vout) for O(1) removal lookup.
  const spentKeys = new Set<string>();
  for (const s of delta.spent) {
    spentKeys.add(makeOutpointKey(s.txid, s.vout));
  }

  // Filter out spent entries from the snapshot.
  const remaining: UtxoEntry[] = [];
  for (const e of snapshot.entries) {
    if (!spentKeys.has(makeOutpointKey(e.txid, e.vout))) {
      remaining.push(e);
    }
  }

  // Append new UTXOs from the delta.
  const merged: UtxoEntry[] = remaining.slice();
  for (const u of delta.newUtxos) {
    merged.push({
      txid: u.txid,
      vout: u.vout,
      amount: u.amount,
    });
  }

  // Recompute totalSats from the merged set.
  let totalSats = 0n;
  for (const e of merged) totalSats += e.amount;

  return {
    ...snapshot,
    entries: merged,
    totalSats,
  };
}

// ─── Batch merge (one delta over many snapshots, parallel arrays) ────────────

/**
 * Merge a batch of delta results into a batch of snapshot results, in the
 * same order. Both arrays must have the same length and the same per-index
 * scripthash. Each pair is processed independently with `mergeDeltaIntoSnapshot`.
 */
export function mergeDeltaBatch(
  snapshots: (QueryResult | null)[],
  deltas: (QueryResult | null)[],
  onError?: (msg: string) => void,
): (QueryResult | null)[] {
  if (snapshots.length !== deltas.length) {
    throw new Error(
      `mergeDeltaBatch: length mismatch: snapshots=${snapshots.length}, deltas=${deltas.length}`,
    );
  }
  const out: (QueryResult | null)[] = new Array(snapshots.length);
  for (let i = 0; i < snapshots.length; i++) {
    out[i] = mergeDeltaIntoSnapshot(snapshots[i], deltas[i], onError);
  }
  return out;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Build a stable string key for an outpoint (txid + vout). Used to dedupe
 * "spent" entries against snapshot entries. Hex-encodes the txid bytes.
 */
function makeOutpointKey(txid: Uint8Array, vout: number): string {
  // Hex-encode the 32-byte txid in a single pass. This matches both
  // SpentRef.txid and UtxoEntry.txid since both are raw 32-byte arrays.
  let s = '';
  for (let i = 0; i < txid.length; i++) {
    const b = txid[i];
    s += (b < 16 ? '0' : '') + b.toString(16);
  }
  return `${s}:${vout}`;
}

// Re-export DeltaData/SpentRef for convenience.
export type { DeltaData, SpentRef };
