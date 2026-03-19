/**
 * Bitcoin Batch PIR Web Client
 *
 * Main entry point for the two-level Batch PIR web client library.
 */

// Polyfill Buffer for browser environment
import { Buffer } from 'buffer';
if (typeof window !== 'undefined') {
  (window as any).Buffer = Buffer;

  if (!(window as any).crypto) {
    (window as any).crypto = {};
  }
  if (!(window as any).crypto.randomBytes) {
    (window as any).crypto.randomBytes = (size: number) => {
      const bytes = new Uint8Array(size);
      if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(bytes);
      } else {
        for (let i = 0; i < size; i++) {
          bytes[i] = Math.floor(Math.random() * 256);
        }
      }
      return Buffer.from(bytes);
    };
  }
}

export {
  BatchPirClient,
  createBatchPirClient,
  type BatchPirClientConfig,
  type ConnectionState,
  type UtxoEntry,
  type QueryResult,
} from './client.js';

export {
  encodeRequest,
  decodeResponse,
  type Request,
  type Response,
  type BatchQuery,
  type BatchResult,
  type ServerInfo,
} from './protocol.js';

export {
  genDpfKeys,
  type DpfKeyPair,
} from './dpf.js';

export {
  splitmix64,
  deriveBuckets,
  deriveCuckooKey,
  cuckooHash,
  deriveChunkBuckets,
  deriveChunkCuckooKey,
  cuckooHashInt,
  sha256,
  ripemd160,
  scriptHash,
  scriptPubKeyToAddress,
  decompileScript,
  decompileScriptText,
  type DecompiledOp,
  reverseBytes,
  hexToBytes,
  bytesToHex,
} from './hash.js';

export {
  K, K_CHUNK, NUM_HASHES,
  SCRIPT_HASH_SIZE, INDEX_ENTRY_SIZE,
  CHUNK_SIZE, CHUNKS_PER_UNIT, UNIT_DATA_SIZE,
  CUCKOO_BUCKET_SIZE,
  DPF_N,
  DEFAULT_SERVER0_URL,
  DEFAULT_SERVER1_URL,
} from './constants.js';
