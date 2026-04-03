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
        throw new Error('crypto.getRandomValues is required but not available in this browser');
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
  genChunkDpfKeys,
  type DpfKeyPair,
} from './dpf.js';

export {
  splitmix64,
  computeTag,
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
  addressToScriptPubKey,
  decompileScript,
  decompileScriptText,
  type DecompiledOp,
  reverseBytes,
  hexToBytes,
  bytesToHex,
} from './hash.js';

export {
  K, K_CHUNK, NUM_HASHES,
  SCRIPT_HASH_SIZE, TAG_SIZE, INDEX_ENTRY_SIZE,
  CHUNK_SIZE, CHUNKS_PER_UNIT, UNIT_DATA_SIZE,
  CUCKOO_BUCKET_SIZE, INDEX_CUCKOO_NUM_HASHES,
  CHUNK_CUCKOO_BUCKET_SIZE, CHUNK_CUCKOO_NUM_HASHES,
  DPF_N, CHUNK_DPF_N,
  HARMONY_INDEX_W, HARMONY_CHUNK_W, HARMONY_EMPTY,
  DEFAULT_SERVER0_URL,
  DEFAULT_SERVER1_URL,
} from './constants.js';

export {
  OnionPirWebClient,
  createOnionPirWebClient,
  type OnionPirClientConfig,
} from './onionpir_client.js';

export {
  HarmonyPirClient,
  createHarmonyPirClient,
  type HarmonyPirClientConfig,
  type HarmonyQueryResult,
  type HarmonyUtxoEntry,
} from './harmonypir_client.js';

export {
  initWasm,
  isWasmReady,
} from './wasm-bridge.js';

export {
  cuckooPlace,
  planRounds,
} from './pbc.js';

export {
  readVarint,
  decodeUtxoData,
  DummyRng,
  type UtxoEntryRaw,
} from './codec.js';
