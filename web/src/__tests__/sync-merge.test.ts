import { describe, it, expect, vi } from 'vitest';
import {
  mergeDeltaIntoSnapshot,
  applyDeltaData,
  mergeDeltaBatch,
} from '../sync-merge.js';
import type { QueryResult, UtxoEntry } from '../client.js';
import type { DeltaData } from '../codec.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Encode a unsigned integer as LEB128 varint. */
function encodeVarint(n: bigint): Uint8Array {
  const bytes: number[] = [];
  let v = n;
  while (v > 0x7Fn) {
    bytes.push(Number(v & 0x7Fn) | 0x80);
    v >>= 7n;
  }
  bytes.push(Number(v));
  return new Uint8Array(bytes);
}

/** Build a deterministic 32-byte txid from a numeric seed. */
function fakeTxid(seed: number): Uint8Array {
  const txid = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    txid[i] = (seed * 31 + i * 17) & 0xFF;
  }
  return txid;
}

/** Build a UtxoEntry with the given fields. */
function utxo(seed: number, vout: number, amount: bigint): UtxoEntry {
  return { txid: fakeTxid(seed), vout, amount };
}

/** Build a minimal QueryResult snapshot from a list of entries. */
function snapshot(entries: UtxoEntry[]): QueryResult {
  let totalSats = 0n;
  for (const e of entries) totalSats += e.amount;
  return {
    entries,
    totalSats,
    startChunkId: 100,
    numChunks: 5,
    numRounds: 1,
    isWhale: false,
    scriptHash: new Uint8Array([1, 2, 3, 4]),
  };
}

/** Encode delta data in the wire format consumed by decodeDeltaData. */
function encodeDelta(
  spent: { txid: Uint8Array; vout: number }[],
  newUtxos: { txid: Uint8Array; vout: number; amount: bigint }[],
): Uint8Array {
  const parts: Uint8Array[] = [];

  parts.push(encodeVarint(BigInt(spent.length)));
  for (const s of spent) {
    parts.push(s.txid);
    parts.push(encodeVarint(BigInt(s.vout)));
  }

  parts.push(encodeVarint(BigInt(newUtxos.length)));
  for (const u of newUtxos) {
    parts.push(u.txid);
    parts.push(encodeVarint(BigInt(u.vout)));
    parts.push(encodeVarint(u.amount));
  }

  const totalLen = parts.reduce((s, p) => s + p.length, 0);
  const buf = new Uint8Array(totalLen);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return buf;
}

/** Build a QueryResult holding raw delta-encoded bytes (as queryDelta returns). */
function deltaResult(deltaBytes: Uint8Array): QueryResult {
  return {
    entries: [],
    totalSats: 0n,
    startChunkId: 200,
    numChunks: 1,
    numRounds: 1,
    isWhale: false,
    rawChunkData: deltaBytes,
  };
}

// ─── applyDeltaData ──────────────────────────────────────────────────────────

describe('applyDeltaData', () => {
  it('removes spent entries by txid+vout', () => {
    const snap = snapshot([
      utxo(1, 0, 1000n),
      utxo(2, 1, 2000n),
      utxo(3, 0, 3000n),
    ]);

    const delta: DeltaData = {
      spent: [{ txid: fakeTxid(2), vout: 1 }],
      newUtxos: [],
    };

    const merged = applyDeltaData(snap, delta);

    expect(merged.entries).toHaveLength(2);
    expect(merged.entries[0].vout).toBe(0);
    expect(merged.entries[0].amount).toBe(1000n);
    expect(merged.entries[1].vout).toBe(0);
    expect(merged.entries[1].amount).toBe(3000n);
    expect(merged.totalSats).toBe(4000n);
  });

  it('appends new entries', () => {
    const snap = snapshot([utxo(1, 0, 1000n)]);

    const delta: DeltaData = {
      spent: [],
      newUtxos: [
        { txid: fakeTxid(10), vout: 0, amount: 5000n },
        { txid: fakeTxid(11), vout: 2, amount: 7000n },
      ],
    };

    const merged = applyDeltaData(snap, delta);

    expect(merged.entries).toHaveLength(3);
    expect(merged.totalSats).toBe(13000n);
    expect(merged.entries[1].amount).toBe(5000n);
    expect(merged.entries[2].amount).toBe(7000n);
  });

  it('combines spent + new in one delta', () => {
    const snap = snapshot([
      utxo(1, 0, 1000n),
      utxo(2, 0, 2000n),
      utxo(3, 0, 3000n),
    ]);

    const delta: DeltaData = {
      spent: [
        { txid: fakeTxid(1), vout: 0 },
        { txid: fakeTxid(3), vout: 0 },
      ],
      newUtxos: [{ txid: fakeTxid(99), vout: 5, amount: 10000n }],
    };

    const merged = applyDeltaData(snap, delta);

    expect(merged.entries).toHaveLength(2);
    expect(merged.entries[0].amount).toBe(2000n); // utxo(2)
    expect(merged.entries[1].amount).toBe(10000n); // new
    expect(merged.totalSats).toBe(12000n);
  });

  it('vout discrimination: same txid different vouts are independent', () => {
    const snap = snapshot([
      utxo(1, 0, 1000n),
      utxo(1, 1, 2000n),
      utxo(1, 2, 3000n),
    ]);

    const delta: DeltaData = {
      spent: [{ txid: fakeTxid(1), vout: 1 }],
      newUtxos: [],
    };

    const merged = applyDeltaData(snap, delta);

    // Only vout=1 removed, vout=0 and vout=2 should remain.
    expect(merged.entries).toHaveLength(2);
    expect(merged.entries[0].vout).toBe(0);
    expect(merged.entries[1].vout).toBe(2);
    expect(merged.totalSats).toBe(4000n);
  });

  it('preserves snapshot metadata', () => {
    const snap = snapshot([utxo(1, 0, 1000n)]);
    const delta: DeltaData = {
      spent: [{ txid: fakeTxid(1), vout: 0 }],
      newUtxos: [{ txid: fakeTxid(99), vout: 0, amount: 500n }],
    };

    const merged = applyDeltaData(snap, delta);

    expect(merged.startChunkId).toBe(snap.startChunkId);
    expect(merged.numChunks).toBe(snap.numChunks);
    expect(merged.numRounds).toBe(snap.numRounds);
    expect(merged.isWhale).toBe(false);
    expect(merged.scriptHash).toBe(snap.scriptHash);
  });

  it('does not mutate the snapshot input', () => {
    const snap = snapshot([utxo(1, 0, 1000n), utxo(2, 0, 2000n)]);
    const before = snap.entries.slice();
    const beforeTotal = snap.totalSats;

    const delta: DeltaData = {
      spent: [{ txid: fakeTxid(1), vout: 0 }],
      newUtxos: [],
    };

    applyDeltaData(snap, delta);

    expect(snap.entries).toEqual(before);
    expect(snap.totalSats).toBe(beforeTotal);
  });

  it('empty delta returns equivalent snapshot', () => {
    const snap = snapshot([utxo(1, 0, 1000n), utxo(2, 0, 2000n)]);
    const delta: DeltaData = { spent: [], newUtxos: [] };

    const merged = applyDeltaData(snap, delta);

    expect(merged.entries).toHaveLength(2);
    expect(merged.totalSats).toBe(3000n);
  });
});

// ─── mergeDeltaIntoSnapshot ──────────────────────────────────────────────────

describe('mergeDeltaIntoSnapshot', () => {
  it('decodes delta from rawChunkData and merges', () => {
    const snap = snapshot([utxo(1, 0, 1000n), utxo(2, 0, 2000n)]);

    const deltaBytes = encodeDelta(
      [{ txid: fakeTxid(1), vout: 0 }],
      [{ txid: fakeTxid(99), vout: 0, amount: 500n }],
    );
    const dr = deltaResult(deltaBytes);

    const merged = mergeDeltaIntoSnapshot(snap, dr);

    expect(merged).not.toBeNull();
    expect(merged!.entries).toHaveLength(2);
    expect(merged!.entries[0].amount).toBe(2000n);
    expect(merged!.entries[1].amount).toBe(500n);
    expect(merged!.totalSats).toBe(2500n);
  });

  it('returns null when snapshot is null', () => {
    const dr = deltaResult(encodeDelta([], []));
    expect(mergeDeltaIntoSnapshot(null, dr)).toBeNull();
  });

  it('returns snapshot unchanged when delta result is null', () => {
    const snap = snapshot([utxo(1, 0, 1000n)]);
    const merged = mergeDeltaIntoSnapshot(snap, null);
    expect(merged).toBe(snap);
  });

  it('returns snapshot unchanged when delta has no rawChunkData', () => {
    const snap = snapshot([utxo(1, 0, 1000n)]);
    const drNoRaw: QueryResult = {
      entries: [],
      totalSats: 0n,
      startChunkId: 0,
      numChunks: 0,
      numRounds: 0,
      isWhale: false,
    };
    const merged = mergeDeltaIntoSnapshot(snap, drNoRaw);
    expect(merged).toBe(snap);
  });

  it('returns snapshot unchanged when snapshot is whale', () => {
    const whaleSnap: QueryResult = {
      entries: [],
      totalSats: 0n,
      startChunkId: 0,
      numChunks: 0,
      numRounds: 0,
      isWhale: true,
    };
    const dr = deltaResult(encodeDelta([{ txid: fakeTxid(1), vout: 0 }], []));
    const merged = mergeDeltaIntoSnapshot(whaleSnap, dr);
    expect(merged).toBe(whaleSnap);
  });

  it('multiple deltas applied sequentially', () => {
    // Snapshot at h0: 3 UTXOs
    let merged: QueryResult | null = snapshot([
      utxo(1, 0, 1000n),
      utxo(2, 0, 2000n),
      utxo(3, 0, 3000n),
    ]);

    // Delta 1 (h0→h1): spend utxo(1), add utxo(10)=4000
    const d1 = deltaResult(encodeDelta(
      [{ txid: fakeTxid(1), vout: 0 }],
      [{ txid: fakeTxid(10), vout: 0, amount: 4000n }],
    ));
    merged = mergeDeltaIntoSnapshot(merged, d1);
    expect(merged!.entries).toHaveLength(3);
    expect(merged!.totalSats).toBe(9000n);

    // Delta 2 (h1→h2): spend utxo(10) just added, add utxo(20)=500
    const d2 = deltaResult(encodeDelta(
      [{ txid: fakeTxid(10), vout: 0 }],
      [{ txid: fakeTxid(20), vout: 0, amount: 500n }],
    ));
    merged = mergeDeltaIntoSnapshot(merged, d2);
    expect(merged!.entries).toHaveLength(3);
    expect(merged!.totalSats).toBe(5500n);

    // Verify exact entries: utxo(2), utxo(3), utxo(20)
    const amounts = merged!.entries.map(e => e.amount).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    expect(amounts).toEqual([500n, 2000n, 3000n]);
  });

  it('calls onError if delta decode fails', () => {
    const snap = snapshot([utxo(1, 0, 1000n)]);
    // Truncated bytes — claims 1 spent but no txid follows.
    const bad = new Uint8Array([0x01]);
    const dr = deltaResult(bad);
    const onError = vi.fn();
    const merged = mergeDeltaIntoSnapshot(snap, dr, onError);
    expect(onError).toHaveBeenCalled();
    // On decode failure, returns the snapshot unchanged.
    expect(merged).toBe(snap);
  });
});

// ─── mergeDeltaBatch ─────────────────────────────────────────────────────────

describe('mergeDeltaBatch', () => {
  it('merges per-index across parallel arrays', () => {
    const snapA = snapshot([utxo(1, 0, 1000n)]);
    const snapB = snapshot([utxo(2, 0, 2000n), utxo(3, 0, 3000n)]);

    const deltaA = deltaResult(encodeDelta(
      [],
      [{ txid: fakeTxid(11), vout: 0, amount: 100n }],
    ));
    const deltaB = deltaResult(encodeDelta(
      [{ txid: fakeTxid(2), vout: 0 }],
      [],
    ));

    const out = mergeDeltaBatch([snapA, snapB], [deltaA, deltaB]);

    expect(out).toHaveLength(2);
    expect(out[0]!.entries).toHaveLength(2);
    expect(out[0]!.totalSats).toBe(1100n);
    expect(out[1]!.entries).toHaveLength(1);
    expect(out[1]!.totalSats).toBe(3000n);
  });

  it('handles nulls in either array', () => {
    const snapA = snapshot([utxo(1, 0, 1000n)]);
    const out = mergeDeltaBatch([snapA, null], [null, null]);
    expect(out).toHaveLength(2);
    expect(out[0]).toBe(snapA);
    expect(out[1]).toBeNull();
  });

  it('throws on length mismatch', () => {
    expect(() => mergeDeltaBatch([snapshot([])], [])).toThrow('length mismatch');
  });
});
