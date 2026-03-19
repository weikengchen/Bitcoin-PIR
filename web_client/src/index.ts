/**
 * Bitcoin PIR Web Client
 *
 * Main entry point for the Bitcoin PIR web client library
 */

// Polyfill Buffer for browser environment
import { Buffer } from 'buffer';
if (typeof window !== 'undefined') {
  (window as any).Buffer = Buffer;

  // Polyfill crypto.randomBytes for browser environment
  // This is needed by libdpf for random key generation
  if (!(window as any).crypto) {
    (window as any).crypto = {};
  }
  if (!(window as any).crypto.randomBytes) {
    (window as any).crypto.randomBytes = (size: number) => {
      const bytes = new Uint8Array(size);
      // Use Web Crypto API if available
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(bytes);
      } else {
        // Fallback to Math.random (not cryptographically secure)
        for (let i = 0; i < size; i++) {
          bytes[i] = Math.floor(Math.random() * 256);
        }
      }
      return Buffer.from(bytes);
    };
  }
}

export { Bincode, type DatabaseInfo, encodeRequest, decodeRequest, encodeResponse, decodeResponse } from './sbp.js';
export {
  createDpf,
  DpfWrapper,
  type DpfKeyPair,
} from './dpf.js';
export {
  cuckooHash1,
  cuckooHash2,
  cuckooLocations,
  sha256,
  ripemd160,
  scriptHash,
  reverseBytes,
  hexToBytes,
  bytesToHex,
} from './hash.js';
export {
  createPirClient,
  PirClient,
  type PirClientConfig,
  type ReconnectConfig,
  type ConnectionState,
  type Request,
  type Response,
} from './client.js';

export {
  CUCKOO_DB_ID,
  CHUNKS_DB_ID,
  CUCKOO_NUM_BUCKETS,
  CUCKOO_BUCKET_SIZE,
  CUCKOO_ENTRY_SIZE,
  CHUNKS_NUM_ENTRIES,
  CHUNK_SIZE,
  DEFAULT_HASH1_SEED,
  DEFAULT_HASH1_PRIME,
  DEFAULT_HASH2_SEED,
  DEFAULT_HASH2_PRIME,
  KEY_SIZE,
  SERVER1_PORT,
  SERVER2_PORT,
  WS_SERVER1_PORT,
  WS_SERVER2_PORT,
} from './constants.js';
