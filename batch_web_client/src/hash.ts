/**
 * Hash functions for the Batch PIR system.
 *
 * Ports the splitmix64-based functions from build_batchdb/src/common.rs.
 * All 64-bit arithmetic uses BigInt to match the Rust implementation exactly.
 */

import {
  K, K_CHUNK, NUM_HASHES,
  MASTER_SEED, CHUNK_MASTER_SEED,
  SCRIPT_HASH_SIZE,
} from './constants.js';

const MASK64 = 0xFFFFFFFFFFFFFFFFn;

// ─── Core functions ────────────────────────────────────────────────────────

/** splitmix64 finalizer (matches Rust exactly) */
export function splitmix64(x: bigint): bigint {
  x = (x ^ (x >> 30n)) & MASK64;
  x = (x * 0xbf58476d1ce4e5b9n) & MASK64;
  x = (x ^ (x >> 27n)) & MASK64;
  x = (x * 0x94d049bb133111ebn) & MASK64;
  x = (x ^ (x >> 31n)) & MASK64;
  return x;
}

/** Read first 8 bytes of a script_hash as u64 LE */
function shA(data: Uint8Array): bigint {
  const dv = new DataView(data.buffer, data.byteOffset, 8);
  return dv.getBigUint64(0, true);
}

/** Read bytes 8..16 of a script_hash as u64 LE */
function shB(data: Uint8Array): bigint {
  const dv = new DataView(data.buffer, data.byteOffset + 8, 8);
  return dv.getBigUint64(0, true);
}

/** Read bytes 16..20 of a script_hash as u32 LE, zero-extended to u64 */
function shC(data: Uint8Array): bigint {
  const dv = new DataView(data.buffer, data.byteOffset + 16, 4);
  return BigInt(dv.getUint32(0, true));
}

// ─── Index-level bucket assignment ─────────────────────────────────────────

/** Hash script_hash with a nonce for bucket assignment */
function hashForBucket(scriptHash: Uint8Array, nonce: bigint): bigint {
  let h = (shA(scriptHash) + ((nonce * 0x9e3779b97f4a7c15n) & MASK64)) & MASK64;
  h = (h ^ shB(scriptHash)) & MASK64;
  h = splitmix64((h ^ shC(scriptHash)) & MASK64);
  return h;
}

/** Derive NUM_HASHES (3) distinct bucket indices for a script_hash */
export function deriveBuckets(scriptHash: Uint8Array): number[] {
  const buckets: number[] = [];
  let nonce = 0n;

  while (buckets.length < NUM_HASHES) {
    const h = hashForBucket(scriptHash, nonce);
    const bucket = Number(h % BigInt(K));
    nonce += 1n;

    if (!buckets.includes(bucket)) {
      buckets.push(bucket);
    }
  }

  return buckets;
}

// ─── Index-level cuckoo hashing ────────────────────────────────────────────

/** Derive a cuckoo hash function key for (bucket_id, hash_fn) */
export function deriveCuckooKey(bucketId: number, hashFn: number): bigint {
  return splitmix64(
    (MASTER_SEED
      + ((BigInt(bucketId) * 0x9e3779b97f4a7c15n) & MASK64)
      + ((BigInt(hashFn) * 0x517cc1b727220a95n) & MASK64)
    ) & MASK64
  );
}

/** Cuckoo hash: hash a script_hash with a derived key, return a bin index */
export function cuckooHash(scriptHash: Uint8Array, key: bigint, numBins: number): number {
  let h = (shA(scriptHash) ^ key) & MASK64;
  h = (h ^ shB(scriptHash)) & MASK64;
  h = splitmix64((h ^ shC(scriptHash)) & MASK64);
  return Number(h % BigInt(numBins));
}

// ─── Chunk-level bucket assignment ─────────────────────────────────────────

/** Hash a chunk_id with a nonce for chunk-level bucket assignment */
function hashChunkForBucket(chunkId: number, nonce: bigint): bigint {
  return splitmix64(
    (BigInt(chunkId) + ((nonce * 0x9e3779b97f4a7c15n) & MASK64)) & MASK64
  );
}

/** Derive 3 distinct chunk-level bucket indices for a chunk_id */
export function deriveChunkBuckets(chunkId: number): number[] {
  const buckets: number[] = [];
  let nonce = 0n;

  while (buckets.length < NUM_HASHES) {
    const h = hashChunkForBucket(chunkId, nonce);
    const bucket = Number(h % BigInt(K_CHUNK));
    nonce += 1n;

    if (!buckets.includes(bucket)) {
      buckets.push(bucket);
    }
  }

  return buckets;
}

// ─── Chunk-level cuckoo hashing ────────────────────────────────────────────

/** Derive a cuckoo hash function key for chunk-level (bucket_id, hash_fn) */
export function deriveChunkCuckooKey(bucketId: number, hashFn: number): bigint {
  return splitmix64(
    (CHUNK_MASTER_SEED
      + ((BigInt(bucketId) * 0x9e3779b97f4a7c15n) & MASK64)
      + ((BigInt(hashFn) * 0x517cc1b727220a95n) & MASK64)
    ) & MASK64
  );
}

/** Cuckoo hash for chunk_ids: map a chunk_id to a bin index using a derived key */
export function cuckooHashInt(chunkId: number, key: bigint, numBins: number): number {
  return Number(splitmix64((BigInt(chunkId) ^ key) & MASK64) % BigInt(numBins));
}

// ─── Script hash computation ───────────────────────────────────────────────

// @ts-ignore
import * as hashJs from 'hash.js';

/** Compute SHA256 hash */
export function sha256(data: Uint8Array): Uint8Array {
  const lib = (hashJs as any).default || hashJs;
  return new Uint8Array(lib.sha256().update(data).digest());
}

/** Compute RIPEMD160 hash */
export function ripemd160(data: Uint8Array): Uint8Array {
  const lib = (hashJs as any).default || hashJs;
  return new Uint8Array(lib.ripemd160().update(data).digest());
}

/** Compute HASH160 = RIPEMD160(SHA256(script)) */
export function scriptHash(scriptPubkey: Uint8Array): Uint8Array {
  return ripemd160(sha256(scriptPubkey));
}

// ─── Bitcoin address encoding ─────────────────────────────────────────────

/** Bech32 character set */
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >>> i) & 1) chk ^= GEN[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (const c of hrp) ret.push(c.charCodeAt(0) >> 5);
  ret.push(0);
  for (const c of hrp) ret.push(c.charCodeAt(0) & 31);
  return ret;
}

function bech32CreateChecksum(hrp: string, data: number[], encoding: number): number[] {
  const values = [...bech32HrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const polymod = bech32Polymod(values) ^ encoding;
  const ret: number[] = [];
  for (let i = 0; i < 6; i++) ret.push((polymod >>> (5 * (5 - i))) & 31);
  return ret;
}

function bech32Encode(hrp: string, data: number[], encoding: number): string {
  const checksum = bech32CreateChecksum(hrp, data, encoding);
  const combined = [...data, ...checksum];
  return hrp + '1' + combined.map(d => BECH32_CHARSET[d]).join('');
}

/** Convert 8-bit bytes to 5-bit groups for bech32 */
function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const b of data) {
    acc = (acc << fromBits) | b;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) {
    ret.push((acc << (toBits - bits)) & maxv);
  }
  return ret;
}

/** Base58 alphabet */
const BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(data: Uint8Array): string {
  // Count leading zeros
  let leadingZeros = 0;
  for (const b of data) { if (b === 0) leadingZeros++; else break; }

  // Convert to bigint and encode
  let num = 0n;
  for (const b of data) num = num * 256n + BigInt(b);

  const chars: string[] = [];
  while (num > 0n) {
    chars.push(BASE58_CHARS[Number(num % 58n)]);
    num = num / 58n;
  }
  chars.reverse();

  return '1'.repeat(leadingZeros) + chars.join('');
}

/** Base58Check encode: data with 4-byte double-SHA256 checksum */
function base58check(payload: Uint8Array): string {
  const hash1 = sha256(payload);
  const hash2 = sha256(hash1);
  const withChecksum = new Uint8Array(payload.length + 4);
  withChecksum.set(payload);
  withChecksum.set(hash2.slice(0, 4), payload.length);
  return base58Encode(withChecksum);
}

/**
 * Convert a scriptPubKey hex to a Bitcoin address.
 * Returns the address string, or null if the script type is not recognized.
 */
export function scriptPubKeyToAddress(spkHex: string): string | null {
  const len = spkHex.length;

  // P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
  if (len === 50 && spkHex.startsWith('76a914') && spkHex.endsWith('88ac')) {
    const hash = hexToBytes(spkHex.slice(6, 46));
    const payload = new Uint8Array(21);
    payload[0] = 0x00; // mainnet P2PKH
    payload.set(hash, 1);
    return base58check(payload);
  }

  // P2SH: OP_HASH160 <20> <hash> OP_EQUAL
  if (len === 46 && spkHex.startsWith('a914') && spkHex.endsWith('87')) {
    const hash = hexToBytes(spkHex.slice(4, 44));
    const payload = new Uint8Array(21);
    payload[0] = 0x05; // mainnet P2SH
    payload.set(hash, 1);
    return base58check(payload);
  }

  // P2WPKH: OP_0 <20> <hash>
  if (len === 44 && spkHex.startsWith('0014')) {
    const hash = hexToBytes(spkHex.slice(4));
    const data5 = convertBits(hash, 8, 5, true);
    return bech32Encode('bc', [0, ...data5], 1); // bech32
  }

  // P2WSH: OP_0 <32> <hash>
  if (len === 68 && spkHex.startsWith('0020')) {
    const hash = hexToBytes(spkHex.slice(4));
    const data5 = convertBits(hash, 8, 5, true);
    return bech32Encode('bc', [0, ...data5], 1); // bech32
  }

  // P2TR: OP_1 <32> <key>
  if (len === 68 && spkHex.startsWith('5120')) {
    const key = hexToBytes(spkHex.slice(4));
    const data5 = convertBits(key, 8, 5, true);
    return bech32Encode('bc', [1, ...data5], 0x2bc830a3); // bech32m
  }

  return null;
}

// ─── Byte utilities ────────────────────────────────────────────────────────

/** Reverse byte array (for Bitcoin TXID display) */
export function reverseBytes(data: Uint8Array): Uint8Array {
  const reversed = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    reversed[i] = data[data.length - 1 - i];
  }
  return reversed;
}

/** Convert hex string to Uint8Array */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/** Convert Uint8Array to hex string */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
