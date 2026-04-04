/**
 * Hash functions for the Batch PIR system.
 *
 * Ports the splitmix64-based functions from build/src/common.rs.
 * All 64-bit arithmetic uses BigInt to match the Rust implementation exactly.
 */

import {
  K, K_CHUNK, NUM_HASHES,
  MASTER_SEED, CHUNK_MASTER_SEED,
  SCRIPT_HASH_SIZE,
} from './constants.js';

import {
  wasmSplitmix64,
  wasmComputeTag,
  wasmDeriveBuckets,
  wasmDeriveCuckooKey,
  wasmCuckooHash,
  wasmDeriveChunkBuckets,
  wasmDeriveChunkCuckooKey,
  wasmCuckooHashInt,
} from './wasm-bridge.js';

const MASK64 = 0xFFFFFFFFFFFFFFFFn;

// ─── Core functions ────────────────────────────────────────────────────────

/** splitmix64 finalizer (matches Rust exactly) */
export function splitmix64(x: bigint): bigint {
  const w = wasmSplitmix64(x);
  if (w !== undefined) return w;
  // Pure-TS fallback
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

// ─── Fingerprint tag computation ────────────────────────────────────────────

/** Compute an 8-byte fingerprint tag for a script_hash using a keyed hash */
export function computeTag(tagSeed: bigint, scriptHash: Uint8Array): bigint {
  const w = wasmComputeTag(tagSeed, scriptHash);
  if (w !== undefined) return w;
  // Pure-TS fallback
  let h = (shA(scriptHash) ^ tagSeed) & MASK64;
  h = (h ^ shB(scriptHash)) & MASK64;
  h = splitmix64((h ^ shC(scriptHash)) & MASK64);
  return h;
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
  const w = wasmDeriveBuckets(scriptHash, K);
  if (w !== undefined) return w;
  // Pure-TS fallback
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
  const w = wasmDeriveCuckooKey(MASTER_SEED, bucketId, hashFn);
  if (w !== undefined) return w;
  // Pure-TS fallback
  return splitmix64(
    (MASTER_SEED
      + ((BigInt(bucketId) * 0x9e3779b97f4a7c15n) & MASK64)
      + ((BigInt(hashFn) * 0x517cc1b727220a95n) & MASK64)
    ) & MASK64
  );
}

/** Cuckoo hash: hash a script_hash with a derived key, return a bin index */
export function cuckooHash(scriptHash: Uint8Array, key: bigint, numBins: number): number {
  const w = wasmCuckooHash(scriptHash, key, numBins);
  if (w !== undefined) return w;
  // Pure-TS fallback
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
  const w = wasmDeriveChunkBuckets(chunkId, K_CHUNK);
  if (w !== undefined) return w;
  // Pure-TS fallback
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
  const w = wasmDeriveChunkCuckooKey(CHUNK_MASTER_SEED, bucketId, hashFn);
  if (w !== undefined) return w;
  // Pure-TS fallback
  return splitmix64(
    (CHUNK_MASTER_SEED
      + ((BigInt(bucketId) * 0x9e3779b97f4a7c15n) & MASK64)
      + ((BigInt(hashFn) * 0x517cc1b727220a95n) & MASK64)
    ) & MASK64
  );
}

/** Cuckoo hash for chunk_ids: map a chunk_id to a bin index using a derived key */
export function cuckooHashInt(chunkId: number, key: bigint, numBins: number): number {
  const w = wasmCuckooHashInt(chunkId, key, numBins);
  if (w !== undefined) return w;
  // Pure-TS fallback
  return Number(splitmix64((BigInt(chunkId) ^ key) & MASK64) % BigInt(numBins));
}

// ─── Merkle sibling integer-keyed hashing ─────────────────────────────────

/** Derive 3 distinct bucket indices for an integer ID (generic K). */
export function deriveIntBuckets3(id: number, k: number): [number, number, number] {
  const buckets: number[] = [];
  let nonce = 0n;
  while (buckets.length < 3) {
    const h = hashChunkForBucket(id, nonce);
    const bucket = Number(h % BigInt(k));
    nonce += 1n;
    if (!buckets.includes(bucket)) {
      buckets.push(bucket);
    }
  }
  return buckets as [number, number, number];
}

/** Derive a cuckoo hash function key for a given (masterSeed, bucketId, hashFn). */
export function deriveCuckooKeyGeneric(masterSeed: bigint, bucketId: number, hashFn: number): bigint {
  return splitmix64(
    (masterSeed
      + ((BigInt(bucketId) * 0x9e3779b97f4a7c15n) & MASK64)
      + ((BigInt(hashFn) * 0x517cc1b727220a95n) & MASK64)
    ) & MASK64
  );
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

// ─── Bitcoin address decoding (address → scriptPubKey) ────────────────────

/** Base58 decode (returns raw bytes including version + checksum) */
function base58Decode(str: string): Uint8Array {
  let num = 0n;
  for (const c of str) {
    const idx = BASE58_CHARS.indexOf(c);
    if (idx === -1) throw new Error(`Invalid Base58 character: ${c}`);
    num = num * 58n + BigInt(idx);
  }
  // Count leading '1' chars → leading zero bytes
  let leadingZeros = 0;
  for (const c of str) { if (c === '1') leadingZeros++; else break; }

  // Convert bigint to bytes
  const hexStr = num === 0n ? '' : num.toString(16).padStart(
    num.toString(16).length + (num.toString(16).length % 2), '0');
  const rawBytes = hexToBytes(hexStr);
  const result = new Uint8Array(leadingZeros + rawBytes.length);
  result.set(rawBytes, leadingZeros);
  return result;
}

/** Base58Check decode: verify checksum, return payload (version + data) */
function base58checkDecode(str: string): Uint8Array {
  const raw = base58Decode(str);
  if (raw.length < 5) throw new Error('Base58Check: too short');
  const payload = raw.slice(0, raw.length - 4);
  const checksum = raw.slice(raw.length - 4);
  const hash1 = sha256(payload);
  const hash2 = sha256(hash1);
  for (let i = 0; i < 4; i++) {
    if (hash2[i] !== checksum[i]) throw new Error('Base58Check: invalid checksum');
  }
  return payload;
}

/** Bech32/Bech32m decode: returns { hrp, witnessVersion, program } */
function bech32Decode(str: string): { hrp: string; witnessVersion: number; program: Uint8Array } | null {
  const lower = str.toLowerCase();
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) return null;

  const hrp = lower.slice(0, pos);
  const dataChars = lower.slice(pos + 1);

  // Decode 5-bit values
  const data5: number[] = [];
  for (const c of dataChars) {
    const idx = BECH32_CHARSET.indexOf(c);
    if (idx === -1) return null;
    data5.push(idx);
  }

  // Verify checksum (try bech32 encoding=1, bech32m encoding=0x2bc830a3)
  const values = [...bech32HrpExpand(hrp), ...data5];
  const polymod = bech32Polymod(values);
  let encoding: number;
  if (polymod === 1) encoding = 1;               // bech32
  else if (polymod === 0x2bc830a3) encoding = 2;  // bech32m
  else return null;

  // Strip checksum (last 6 chars)
  const payload5 = data5.slice(0, data5.length - 6);
  if (payload5.length < 1) return null;

  const witnessVersion = payload5[0];
  // Convert remaining 5-bit groups back to 8-bit
  const programBits = payload5.slice(1);
  const program = convertBitsNoPad(programBits, 5, 8);
  if (!program) return null;

  // Validate: bech32 for v0, bech32m for v1+
  if (witnessVersion === 0 && encoding !== 1) return null;
  if (witnessVersion >= 1 && encoding !== 2) return null;

  return { hrp, witnessVersion, program: new Uint8Array(program) };
}

/** Convert bits without padding (for bech32 decode) */
function convertBitsNoPad(data: number[], fromBits: number, toBits: number): number[] | null {
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
  if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) return null;
  return ret;
}

/**
 * Convert a Bitcoin address to its scriptPubKey hex.
 * Supports P2PKH (1...), P2SH (3...), P2WPKH/P2WSH (bc1q...), P2TR (bc1p...).
 * Returns null if the address is not recognized.
 */
export function addressToScriptPubKey(address: string): string | null {
  const trimmed = address.trim();
  if (!trimmed) return null;

  // Try bech32/bech32m first (bc1...)
  if (trimmed.toLowerCase().startsWith('bc1')) {
    const decoded = bech32Decode(trimmed);
    if (!decoded || decoded.hrp !== 'bc') return null;

    const progHex = bytesToHex(decoded.program);
    if (decoded.witnessVersion === 0 && decoded.program.length === 20) {
      return '0014' + progHex;  // P2WPKH
    }
    if (decoded.witnessVersion === 0 && decoded.program.length === 32) {
      return '0020' + progHex;  // P2WSH
    }
    if (decoded.witnessVersion === 1 && decoded.program.length === 32) {
      return '5120' + progHex;  // P2TR
    }
    return null;
  }

  // Try base58check (1... or 3...)
  try {
    const payload = base58checkDecode(trimmed);
    if (payload.length === 21) {
      const version = payload[0];
      const hashHex = bytesToHex(payload.slice(1));
      if (version === 0x00) return '76a914' + hashHex + '88ac';  // P2PKH
      if (version === 0x05) return 'a914' + hashHex + '87';       // P2SH
    }
  } catch {
    // Not valid base58check
  }

  return null;
}

// ─── Script decompiler ────────────────────────────────────────────────────

/** Bitcoin opcode names (common ones) */
const OPCODES: Record<number, string> = {
  0x00: 'OP_0', 0x4c: 'OP_PUSHDATA1', 0x4d: 'OP_PUSHDATA2', 0x4e: 'OP_PUSHDATA4',
  0x4f: 'OP_1NEGATE',
  0x51: 'OP_1', 0x52: 'OP_2', 0x53: 'OP_3', 0x54: 'OP_4', 0x55: 'OP_5',
  0x56: 'OP_6', 0x57: 'OP_7', 0x58: 'OP_8', 0x59: 'OP_9', 0x5a: 'OP_10',
  0x5b: 'OP_11', 0x5c: 'OP_12', 0x5d: 'OP_13', 0x5e: 'OP_14', 0x5f: 'OP_15',
  0x60: 'OP_16',
  0x69: 'OP_VERIFY', 0x6a: 'OP_RETURN',
  0x76: 'OP_DUP', 0x87: 'OP_EQUAL', 0x88: 'OP_EQUALVERIFY',
  0xa6: 'OP_RIPEMD160', 0xa7: 'OP_SHA1', 0xa8: 'OP_SHA256',
  0xa9: 'OP_HASH160', 0xaa: 'OP_HASH256',
  0xab: 'OP_CODESEPARATOR', 0xac: 'OP_CHECKSIG', 0xad: 'OP_CHECKSIGVERIFY',
  0xae: 'OP_CHECKMULTISIG', 0xaf: 'OP_CHECKMULTISIGVERIFY',
  0xb1: 'OP_CLTV', 0xb2: 'OP_CSV',
};

/** Small number opcode → number (OP_0=0, OP_1..OP_16 = 1..16) */
function smallNum(op: number): number | null {
  if (op === 0x00) return 0;
  if (op >= 0x51 && op <= 0x60) return op - 0x50;
  return null;
}

export interface DecompiledOp {
  type: 'opcode' | 'data';
  text: string;       // opcode name or full hex
  dataLen?: number;    // byte length of pushed data
}

/**
 * Decompile a scriptPubKey hex into structured ops.
 * Returns an array of opcodes and data pushes (full, untruncated).
 */
export function decompileScript(spkHex: string): DecompiledOp[] {
  const bytes = hexToBytes(spkHex);
  const result: DecompiledOp[] = [];

  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i++];
    if (op >= 0x01 && op <= 0x4b) {
      const data = bytes.slice(i, i + op);
      i += op;
      result.push({ type: 'data', text: bytesToHex(data), dataLen: data.length });
    } else if (op === 0x4c && i < bytes.length) {
      const len = bytes[i++];
      const data = bytes.slice(i, i + len);
      i += len;
      result.push({ type: 'data', text: bytesToHex(data), dataLen: data.length });
    } else if (op === 0x4d && i + 1 < bytes.length) {
      const len = bytes[i] | (bytes[i + 1] << 8);
      i += 2;
      const data = bytes.slice(i, i + len);
      i += len;
      result.push({ type: 'data', text: bytesToHex(data), dataLen: data.length });
    } else {
      result.push({ type: 'opcode', text: OPCODES[op] || `0x${op.toString(16).padStart(2, '0')}` });
    }
  }

  return result;
}

/**
 * Render decompiled ops to a plain-text one-liner (for tooltips, etc.).
 */
export function decompileScriptText(spkHex: string, maxLen = 120): string {
  const ops = decompileScript(spkHex);
  const parts = ops.map(o => o.type === 'data'
    ? (o.text.length <= 16 ? `<${o.text}>` : `<${o.text.substring(0, 8)}…${o.text.substring(o.text.length - 8)}>`)
    : o.text);
  const result = parts.join(' ');
  if (result.length <= maxLen) return result;
  return result.substring(0, maxLen - 1) + '…';
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
