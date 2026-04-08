import { describe, it, expect, vi } from 'vitest';
import { decodeDeltaData, decodeUtxoData, readVarint } from '../codec.js';

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

/** Build a random-looking 32-byte txid from a seed. */
function fakeTxid(seed: number): Uint8Array {
  const txid = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    txid[i] = (seed * 31 + i * 17) & 0xFF;
  }
  return txid;
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

// ─── readVarint ──────────────────────────────────────────────────────────────

describe('readVarint', () => {
  it('reads single-byte varint', () => {
    const data = new Uint8Array([42]);
    const { value, bytesRead } = readVarint(data, 0);
    expect(value).toBe(42n);
    expect(bytesRead).toBe(1);
  });

  it('reads multi-byte varint', () => {
    // 300 = 0b100101100 → LEB128: [0xAC, 0x02]
    const data = new Uint8Array([0xAC, 0x02]);
    const { value, bytesRead } = readVarint(data, 0);
    expect(value).toBe(300n);
    expect(bytesRead).toBe(2);
  });

  it('reads varint at non-zero offset', () => {
    const data = new Uint8Array([0xFF, 0xFF, 7]); // skip first 2 bytes
    const { value, bytesRead } = readVarint(data, 2);
    expect(value).toBe(7n);
    expect(bytesRead).toBe(1);
  });
});

// ─── decodeDeltaData ─────────────────────────────────────────────────────────

describe('decodeDeltaData', () => {
  it('decodes basic delta with 2 spent and 1 new', () => {
    const txid1 = fakeTxid(1);
    const txid2 = fakeTxid(2);
    const txid3 = fakeTxid(3);

    const data = encodeDelta(
      [
        { txid: txid1, vout: 0 },
        { txid: txid2, vout: 3 },
      ],
      [
        { txid: txid3, vout: 1, amount: 50000n },
      ],
    );

    const result = decodeDeltaData(data);

    expect(result.spent).toHaveLength(2);
    expect(result.spent[0].vout).toBe(0);
    expect(result.spent[1].vout).toBe(3);
    expect(new Uint8Array(result.spent[0].txid)).toEqual(txid1);
    expect(new Uint8Array(result.spent[1].txid)).toEqual(txid2);

    expect(result.newUtxos).toHaveLength(1);
    expect(result.newUtxos[0].vout).toBe(1);
    expect(result.newUtxos[0].amount).toBe(50000n);
    expect(new Uint8Array(result.newUtxos[0].txid)).toEqual(txid3);
  });

  it('decodes empty delta (0 spent, 0 new)', () => {
    const data = encodeDelta([], []);
    const result = decodeDeltaData(data);
    expect(result.spent).toHaveLength(0);
    expect(result.newUtxos).toHaveLength(0);
  });

  it('handles large varint values (multi-byte vout and amount)', () => {
    const txidS = fakeTxid(10);
    const txidN = fakeTxid(20);
    const largeAmount = 2100000000000000n; // 21M BTC in sats

    const data = encodeDelta(
      [{ txid: txidS, vout: 300 }],          // vout=300 needs 2-byte varint
      [{ txid: txidN, vout: 65535, amount: largeAmount }],
    );

    const result = decodeDeltaData(data);

    expect(result.spent).toHaveLength(1);
    expect(result.spent[0].vout).toBe(300);

    expect(result.newUtxos).toHaveLength(1);
    expect(result.newUtxos[0].vout).toBe(65535);
    expect(result.newUtxos[0].amount).toBe(largeAmount);
  });

  it('calls onError and returns partial results on truncated txid data', () => {
    const txid1 = fakeTxid(1);
    // Encode 2 spent: first is complete, second has a partial txid (only 10 bytes)
    const parts: Uint8Array[] = [
      encodeVarint(2n),         // num_spent = 2
      txid1,                    // first txid (32B)
      encodeVarint(0n),         // first vout
      txid1.slice(0, 10),       // second txid truncated to 10 bytes (needs 32)
    ];
    const totalLen = parts.reduce((s, p) => s + p.length, 0);
    const data = new Uint8Array(totalLen);
    let off = 0;
    for (const p of parts) { data.set(p, off); off += p.length; }

    const onError = vi.fn();
    const result = decodeDeltaData(data, onError);

    expect(onError).toHaveBeenCalled();
    // Should have decoded the first spent entry before truncation
    expect(result.spent).toHaveLength(1);
    expect(result.spent[0].vout).toBe(0);
  });

  it('throws on truncated varint', () => {
    // Buffer with num_spent varint that claims 1 entry but data ends abruptly
    // before the varint for vout can be read
    const txid1 = fakeTxid(1);
    const parts: Uint8Array[] = [
      encodeVarint(1n),     // num_spent = 1
      txid1,                // txid (32B)
      new Uint8Array([0x80]), // incomplete varint (continuation bit set, no follow-up)
    ];
    const totalLen = parts.reduce((s, p) => s + p.length, 0);
    const data = new Uint8Array(totalLen);
    let off = 0;
    for (const p of parts) { data.set(p, off); off += p.length; }

    expect(() => decodeDeltaData(data)).toThrow('Unexpected end of data');
  });

  it('decodes delta with only spent (no new UTXOs)', () => {
    const txid = fakeTxid(42);
    const data = encodeDelta(
      [{ txid, vout: 7 }],
      [],
    );
    const result = decodeDeltaData(data);
    expect(result.spent).toHaveLength(1);
    expect(result.newUtxos).toHaveLength(0);
  });

  it('decodes delta with only new UTXOs (no spent)', () => {
    const txid = fakeTxid(99);
    const data = encodeDelta(
      [],
      [{ txid, vout: 0, amount: 1000n }],
    );
    const result = decodeDeltaData(data);
    expect(result.spent).toHaveLength(0);
    expect(result.newUtxos).toHaveLength(1);
    expect(result.newUtxos[0].amount).toBe(1000n);
  });
});

// ─── decodeUtxoData ──────────────────────────────────────────────────────────

describe('decodeUtxoData', () => {
  it('decodes UTXO data with 2 entries', () => {
    const txid1 = fakeTxid(1);
    const txid2 = fakeTxid(2);

    const parts: Uint8Array[] = [
      encodeVarint(2n),           // numEntries
      txid1,                      // 32B txid
      encodeVarint(0n),           // vout
      encodeVarint(100000n),      // amount
      txid2,
      encodeVarint(1n),
      encodeVarint(200000n),
    ];
    const totalLen = parts.reduce((s, p) => s + p.length, 0);
    const data = new Uint8Array(totalLen);
    let off = 0;
    for (const p of parts) { data.set(p, off); off += p.length; }

    const { entries, totalSats } = decodeUtxoData(data);

    expect(entries).toHaveLength(2);
    expect(entries[0].vout).toBe(0);
    expect(entries[0].amount).toBe(100000n);
    expect(entries[1].vout).toBe(1);
    expect(entries[1].amount).toBe(200000n);
    expect(totalSats).toBe(300000n);
  });

  it('decodes empty UTXO data', () => {
    const data = encodeVarint(0n);
    const { entries, totalSats } = decodeUtxoData(data);
    expect(entries).toHaveLength(0);
    expect(totalSats).toBe(0n);
  });
});
