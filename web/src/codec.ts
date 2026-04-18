/**
 * Shared wire-format utilities for PIR clients.
 *
 * Provides varint decoding, UTXO data parsing, and a deterministic PRNG
 * for dummy queries. Used by all three PIR protocol clients.
 */

import { splitmix64 } from './hash.js';
import { sdkDecodeDeltaData, sdkDecodeUtxoData } from './sdk-bridge.js';

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
 *
 * WASM-first dispatch: when `pir-sdk-wasm` is loaded the Rust-native decoder
 * (`pir_core::codec::parse_utxo_data`) runs; the pure-TS implementation below
 * is the fallback. The WASM path cannot invoke `onError` on mid-stream
 * truncation — the underlying Rust function silently stops — so callers that
 * depend on that diagnostic only see it when the WASM module failed to load.
 * Truncation is extremely rare in practice because the build pipeline
 * zero-pads on `BLOCK_SIZE` boundaries.
 */
export function decodeUtxoData(
  fullData: Uint8Array,
  onError?: (msg: string) => void,
): { entries: UtxoEntryRaw[]; totalSats: bigint } {
  // Try WASM first; on any failure (module not loaded, malformed payload),
  // fall back to the pure-TS implementation so the diagnostic `onError`
  // callback still fires on truncation.
  const viaSdk = sdkDecodeUtxoData(fullData);
  if (viaSdk !== undefined) return viaSdk;

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

// ─── Delta data types ──────────────────────────────────────────────────────

/** A spent UTXO reference in a delta (no amount needed). */
export interface SpentRef {
  txid: Uint8Array;   // 32-byte raw TXID (internal byte order)
  vout: number;
}

/** Decoded delta data for a single scripthash. */
export interface DeltaData {
  spent: SpentRef[];
  newUtxos: UtxoEntryRaw[];
}

// ─── Delta data decoder ────────────────────────────────────────────────────

/**
 * Decode delta data from concatenated chunk bytes.
 *
 * Format:
 *   [varint num_spent]
 *     per spent: [32B txid][varint vout]
 *   [varint num_new]
 *     per new:   [32B txid][varint vout][varint amount]
 *
 * WASM-first dispatch: when `pir-sdk-wasm` is loaded the Rust-native decoder
 * (`pir_sdk::decode_delta_data`) runs; the pure-TS implementation below is
 * the fallback. The WASM path cannot invoke `onError` on mid-stream
 * truncation — `pir_sdk::decode_delta_data` returns a typed `PirError` on
 * truncation / varint overflow, which the WASM binding wraps in a `JsError`
 * that `sdkDecodeDeltaData` catches and converts to `undefined`, triggering
 * fall-through to the TS path (which then throws on the same malformed
 * input via `readVarint`). Callers that rely on the `onError` diagnostic
 * string only see it when the WASM module failed to load.
 */
export function decodeDeltaData(
  fullData: Uint8Array,
  onError?: (msg: string) => void,
): DeltaData {
  // Try WASM first; on any failure (module not loaded, malformed payload),
  // fall back to the pure-TS implementation so the `onError` callback can
  // still fire on mid-stream truncation for diagnostic purposes.
  const viaSdk = sdkDecodeDeltaData(fullData);
  if (viaSdk !== undefined) return viaSdk;

  let pos = 0;

  // Spent UTXOs
  const { value: numSpent, bytesRead: spentCountBytes } = readVarint(fullData, pos);
  pos += spentCountBytes;

  const spent: SpentRef[] = [];
  for (let i = 0; i < Number(numSpent); i++) {
    if (pos + 32 > fullData.length) {
      onError?.(`Delta data truncated at spent entry ${i}`);
      break;
    }
    const txid = fullData.slice(pos, pos + 32);
    pos += 32;
    const { value: vout, bytesRead: vr } = readVarint(fullData, pos);
    pos += vr;
    spent.push({ txid: new Uint8Array(txid), vout: Number(vout) });
  }

  // New UTXOs
  const { value: numNew, bytesRead: newCountBytes } = readVarint(fullData, pos);
  pos += newCountBytes;

  const newUtxos: UtxoEntryRaw[] = [];
  for (let i = 0; i < Number(numNew); i++) {
    if (pos + 32 > fullData.length) {
      onError?.(`Delta data truncated at new entry ${i}`);
      break;
    }
    const txid = fullData.slice(pos, pos + 32);
    pos += 32;
    const { value: vout, bytesRead: vr } = readVarint(fullData, pos);
    pos += vr;
    const { value: amount, bytesRead: ar } = readVarint(fullData, pos);
    pos += ar;
    newUtxos.push({ txid: new Uint8Array(txid), vout: Number(vout), amount });
  }

  return { spent, newUtxos };
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
