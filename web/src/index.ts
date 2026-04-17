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
  BatchPirClientAdapter,
  type BatchPirClientConfig,
} from './dpf-adapter.js';

export type {
  ConnectionState,
  UtxoEntry,
  QueryResult,
} from './types.js';

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
  genDpfKeysN,
  type DpfKeyPair,
} from './dpf.js';

export {
  splitmix64,
  computeTag,
  deriveGroups,
  deriveCuckooKey,
  cuckooHash,
  deriveChunkGroups,
  deriveChunkCuckooKey,
  cuckooHashInt,
  deriveIntGroups3,
  deriveCuckooKeyGeneric,
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
  SCRIPT_HASH_SIZE, TAG_SIZE, INDEX_SLOT_SIZE,
  CHUNK_SIZE, CHUNKS_PER_UNIT, UNIT_DATA_SIZE,
  INDEX_SLOTS_PER_BIN, INDEX_CUCKOO_NUM_HASHES,
  CHUNK_SLOTS_PER_BIN, CHUNK_CUCKOO_NUM_HASHES,
  DPF_N, CHUNK_DPF_N,
  HARMONY_INDEX_W, HARMONY_CHUNK_W, HARMONY_EMPTY,
  DEFAULT_SERVER0_URL,
  DEFAULT_SERVER1_URL,
  BUCKET_MERKLE_ARITY, BUCKET_MERKLE_SIB_ROW_SIZE,
  REQ_BUCKET_MERKLE_SIB_BATCH, RESP_BUCKET_MERKLE_SIB_BATCH,
  REQ_BUCKET_MERKLE_TREE_TOPS, RESP_BUCKET_MERKLE_TREE_TOPS,
} from './constants.js';

export {
  computeLeafHash,
  computeDataHash,
  computeParentN,
  computeBinLeafHash,
  parseTreeTopCache,
  verifyMerkleProof,
  type TreeTopCache,
} from './merkle.js';

export {
  OnionPirWebClient,
  createOnionPirWebClient,
  type OnionPirClientConfig,
} from './onionpir_client.js';

export {
  HarmonyPirClientAdapter,
  createHarmonyPirClientAdapter,
  type HarmonyPirClientConfig,
} from './harmonypir-adapter.js';

export type {
  HarmonyQueryResult,
  HarmonyUtxoEntry,
  QueryInspectorData,
  RoundTimingData,
} from './harmony-types.js';

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
  decodeDeltaData,
  DummyRng,
  type UtxoEntryRaw,
  type DeltaData,
  type SpentRef,
} from './codec.js';

export {
  fetchDatabaseCatalog,
  decodeDatabaseCatalog,
  type DatabaseCatalog,
  type DatabaseCatalogEntry,
  type PerDatabaseInfoJson,
} from './server-info.js';

export {
  computeSyncPlan,
  type SyncPlan,
  type SyncStep,
} from './sync.js';

export {
  mergeDeltaIntoSnapshot,
  applyDeltaData,
  mergeDeltaBatch,
  mergeDeltaIntoHarmonySnapshot,
  mergeDeltaHarmonyBatch,
} from './sync-merge.js';

export {
  SyncController,
  describeStep,
  type SyncableResult,
  type SyncExecuteHooks,
  type SyncExecuteOutput,
  type SyncControllerConfig,
} from './sync-controller.js';

// SDK WASM bridge (optional - use pir-sdk-wasm for Rust-backed implementations)
export {
  initSdkWasm,
  isSdkWasmReady,
  computeSyncPlanSdk,
  sdkSplitmix64,
  sdkComputeTag,
  sdkDeriveGroups,
  sdkDeriveCuckooKey,
  sdkCuckooHash,
  sdkDeriveChunkGroups,
  sdkCuckooHashInt,
} from './sdk-bridge.js';
