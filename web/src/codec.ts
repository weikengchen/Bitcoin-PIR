/**
 * Shared wire-format utilities for PIR clients.
 *
 * Provides varint decoding, UTXO data parsing, and a deterministic PRNG
 * for dummy queries. Used by all three PIR protocol clients.
 */

import { splitmix64 } from './hash.js';

// ─── Types ───────────────────────────────────────────────────────────────────

/** Canonical raw UTXO entry (binary txid, bigint amount). */
export interface UtxoEntryRaw {
  txid: Uint8Array;   // 32-byte raw TXID (internal byte order)
  vout: number;
  amount: bigint;     // satoshis
}

// ─── Varint decoder ──────────────────────────────────────────────────────────

/** Read a LEB128 unsigned varint from `data` at `offset`. */
export function readVarint(data: Uint8Array, offset: number): { value: bigint; bytesRead: number } {
  let result = 0n;
  let shift = 0;
  let bytesRead = 0;

  while (true) {
    if (offset + bytesRead >= data.length) {
      throw new Error('Unexpected end of data while reading varint');
    }
    const byte = data[offset + bytesRead];
    bytesRead++;
    result |= BigInt(byte & 0x7F) << BigInt(shift);
    if ((byte & 0x80) === 0) break;
    shift += 7;
    if (shift >= 64) throw new Error('VarInt too large');
  }

  return { value: result, bytesRead };
}

// ─── UTXO data decoder ──────────────────────────────────────────────────────

/**
 * Decode UTXO data from concatenated chunk bytes.
 *
 * Format: [varint numEntries][per entry: 32B txid, varint vout, varint amount]
 */
export function decodeUtxoData(
  fullData: Uint8Array,
  onError?: (msg: string) => void,
): { entries: UtxoEntryRaw[]; totalSats: bigint } {
  let pos = 0;
  const { value: numEntries, bytesRead: countBytes } = readVarint(fullData, pos);
  pos += countBytes;

  const entries: UtxoEntryRaw[] = [];
  let totalSats = 0n;

  for (let i = 0; i < Number(numEntries); i++) {
    if (pos + 32 > fullData.length) {
      onError?.(`Data truncated at entry ${i}`);
      break;
    }

    const txid = fullData.slice(pos, pos + 32);
    pos += 32;

    const { value: vout, bytesRead: vr } = readVarint(fullData, pos);
    pos += vr;

    const { value: amount, bytesRead: ar } = readVarint(fullData, pos);
    pos += ar;

    totalSats += amount;
    entries.push({
      txid: new Uint8Array(txid),
      vout: Number(vout),
      amount,
    });
  }

  return { entries, totalSats };
}

// ─── PRNG for dummy queries ──────────────────────────────────────────────────

/** Splitmix64-based PRNG for generating deterministic dummy query data. */
export class DummyRng {
  private state: bigint;

  constructor() {
    this.state = splitmix64(BigInt(Date.now()));
  }

  nextU64(): bigint {
    this.state = (this.state + 0x9e3779b97f4a7c15n) & 0xFFFFFFFFFFFFFFFFn;
    return splitmix64(this.state);
  }
}
