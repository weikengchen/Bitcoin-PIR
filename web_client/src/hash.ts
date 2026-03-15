/**
 * Hash functions for the Bitcoin PIR system
 * 
 * Implements cuckoo hash functions and RIPEMD160 for script hashes
 */

import {
  DEFAULT_HASH1_SEED,
  DEFAULT_HASH1_PRIME,
  DEFAULT_HASH2_SEED,
  DEFAULT_HASH2_PRIME,
  KEY_SIZE,
} from './constants.js';

/**
 * Cuckoo hash function 1
 * Uses FNV-1a style mixing over the key bytes
 * Uses BigInt for 64-bit arithmetic to match Rust implementation
 */
export function cuckooHash1(key: Uint8Array, numBuckets: number): number {
  let h: bigint = DEFAULT_HASH1_SEED;
  const prime: bigint = DEFAULT_HASH1_PRIME;
  
  for (const byte of key) {
    h ^= BigInt(byte);
    h = h * prime;  // Wrapping multiplication (handled by BigInt naturally for low 64 bits)
    h = h & 0xFFFFFFFFFFFFFFFFn;  // Keep only 64 bits
  }
  
  // Extra mixing (matching Rust implementation)
  h ^= h >> 33n;
  h = (h * 0xff51afd7ed558ccdn) & 0xFFFFFFFFFFFFFFFFn;
  h ^= h >> 33n;
  
  return Number(h % BigInt(numBuckets));
}

/**
 * Cuckoo hash function 2
 * Different seed/constants from hash1
 * Uses BigInt for 64-bit arithmetic to match Rust implementation
 */
export function cuckooHash2(key: Uint8Array, numBuckets: number): number {
  let h: bigint = DEFAULT_HASH2_SEED;
  const prime: bigint = DEFAULT_HASH2_PRIME;
  
  for (const byte of key) {
    h ^= BigInt(byte);
    h = h * prime;  // Wrapping multiplication
    h = h & 0xFFFFFFFFFFFFFFFFn;  // Keep only 64 bits
  }
  
  // Mixing (matching Rust implementation)
  h ^= h >> 32n;
  h = (h * 0xbf58476d1ce4e5b9n) & 0xFFFFFFFFFFFFFFFFn;
  h ^= h >> 32n;
  
  return Number(h % BigInt(numBuckets));
}

/**
 * Compute both cuckoo hash locations for a key
 * Returns [location1, location2] tuple
 */
export function cuckooLocations(key: Uint8Array, numBuckets: number): [number, number] {
  return [cuckooHash1(key, numBuckets), cuckooHash2(key, numBuckets)];
}

/**
 * Custom hash function for TXID mapping (hash 1)
 * murmurhash3-style finalizer
 * 
 * Matches Rust implementation exactly:
 * - Uses wrapping multiplication
 * - Converts to u64 before modulo to ensure unsigned behavior
 */
export function txidMappingHash1(key: Uint8Array, numBuckets: number): number {
  // Interpret key as u32 (little-endian) - matches Rust's u32::from_le_bytes
  let h = (key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24)) >>> 0;
  
  // murmurhash3-style finalizer (matches Rust exactly)
  h ^= h >>> 16;
  h = (Math.imul(h, 0x45d9f3b) >>> 0);  // wrapping_mul as u32
  h ^= h >>> 16;
  
  // Use BigInt for the modulo to match Rust's "as u64 as usize % num_buckets"
  // This ensures we get the correct positive result
  return Number(BigInt(h >>> 0) % BigInt(numBuckets));
}

/**
 * Custom hash function for TXID mapping (hash 2)
 * Different mixing constants
 * 
 * Matches Rust implementation exactly:
 * - Uses wrapping multiplication
 * - Converts to u64 before modulo to ensure unsigned behavior
 */
export function txidMappingHash2(key: Uint8Array, numBuckets: number): number {
  // Interpret key as u32 (little-endian) - matches Rust's u32::from_le_bytes
  let h = (key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24)) >>> 0;
  
  // Different mixing constants (matches Rust exactly)
  h ^= h >>> 15;
  h = (Math.imul(h, 0x735a2d97) >>> 0);  // wrapping_mul as u32
  h ^= h >>> 15;
  h = (Math.imul(h, 0x0bef6c35) >>> 0);  // wrapping_mul as u32
  h ^= h >>> 16;
  
  // Use BigInt for the modulo to match Rust's "as u64 as usize % num_buckets"
  // This ensures we get the correct positive result
  return Number(BigInt(h >>> 0) % BigInt(numBuckets));
}

/**
 * Compute TXID mapping cuckoo locations
 */
export function txidMappingLocations(key: Uint8Array, numBuckets: number): [number, number] {
  return [txidMappingHash1(key, numBuckets), txidMappingHash2(key, numBuckets)];
}

/**
 * Compute RIPEMD160 hash of data
 * Uses hash.js library for a well-tested implementation
 */
// @ts-ignore
import * as hashJs from 'hash.js';

export function ripemd160(data: Uint8Array): Uint8Array {
  // hash.js uses CommonJS, need to handle both ESM and CJS
  const lib = (hashJs as any).default || hashJs;
  const hash = lib.ripemd160().update(data).digest();
  return new Uint8Array(hash);
}

/**
 * Compute script hash from Bitcoin scriptPubkey
 */
export function scriptHash(scriptPubkey: Uint8Array): Uint8Array {
  return ripemd160(scriptPubkey);
}

/**
 * Reverse byte array (for Bitcoin TXID handling)
 */
export function reverseBytes(data: Uint8Array): Uint8Array {
  const reversed = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    reversed[i] = data[data.length - 1 - i];
  }
  return reversed;
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}
