/**
 * Binary protocol encoder/decoder for the Batch PIR system.
 *
 * Matches runtime/src/protocol.rs exactly:
 *   Messages are length-prefixed: [4B total_len][1B variant][payload...]
 *   Batch queries/results: [2B round_id][1B count][1B keys_per_bucket][per-bucket: [2B len][key]...]
 */

import {
  REQ_PING, REQ_GET_INFO, REQ_INDEX_BATCH, REQ_CHUNK_BATCH,
  RESP_PONG, RESP_INFO, RESP_INDEX_BATCH, RESP_CHUNK_BATCH, RESP_ERROR,
} from './constants.js';

// ─── Types ─────────────────────────────────────────────────────────────────

export interface BatchQuery {
  level: number;
  roundId: number;
  /** Per-bucket: list of DPF keys (2 for index, 3 for chunks) */
  keys: Uint8Array[][];
}

export interface ServerInfo {
  indexBinsPerTable: number;
  chunkBinsPerTable: number;
  indexK: number;
  chunkK: number;
  tagSeed: bigint;
}

export interface BatchResult {
  level: number;
  roundId: number;
  /** Per-bucket: list of results (2 for index, 3 for chunks) */
  results: Uint8Array[][];
}

export type Request =
  | { type: 'Ping' }
  | { type: 'GetInfo' }
  | { type: 'IndexBatch'; query: BatchQuery }
  | { type: 'ChunkBatch'; query: BatchQuery };

export type Response =
  | { type: 'Pong' }
  | { type: 'Info'; info: ServerInfo }
  | { type: 'IndexBatch'; result: BatchResult }
  | { type: 'ChunkBatch'; result: BatchResult }
  | { type: 'Error'; message: string };

// ─── Encoding ──────────────────────────────────────────────────────────────

function encodeBatchQuery(buf: number[], q: BatchQuery): void {
  // round_id: u16 LE
  buf.push(q.roundId & 0xFF, (q.roundId >> 8) & 0xFF);
  // count: u8
  buf.push(q.keys.length & 0xFF);
  // keys_per_bucket: u8
  const keysPerBucket = q.keys.length > 0 ? q.keys[0].length : 0;
  buf.push(keysPerBucket & 0xFF);
  for (const bucketKeys of q.keys) {
    for (const k of bucketKeys) {
      buf.push(k.length & 0xFF, (k.length >> 8) & 0xFF);
      for (let i = 0; i < k.length; i++) buf.push(k[i]);
    }
  }
}

/** Encode a request to a length-prefixed binary message */
export function encodeRequest(request: Request): Uint8Array {
  const payload: number[] = [];

  switch (request.type) {
    case 'Ping':
      payload.push(REQ_PING);
      break;
    case 'GetInfo':
      payload.push(REQ_GET_INFO);
      break;
    case 'IndexBatch':
      payload.push(REQ_INDEX_BATCH);
      encodeBatchQuery(payload, request.query);
      break;
    case 'ChunkBatch':
      payload.push(REQ_CHUNK_BATCH);
      encodeBatchQuery(payload, request.query);
      break;
  }

  // Length-prefix the payload
  const msg = new Uint8Array(4 + payload.length);
  const dv = new DataView(msg.buffer);
  dv.setUint32(0, payload.length, true);
  msg.set(payload, 4);
  return msg;
}

// ─── Decoding ──────────────────────────────────────────────────────────────

function decodeBatchResult(data: Uint8Array, pos: number): { result: BatchResult; pos: number } {
  const roundId = data[pos] | (data[pos + 1] << 8);
  pos += 2;
  const count = data[pos];
  pos += 1;
  const resultsPerBucket = data[pos];
  pos += 1;

  const results: Uint8Array[][] = [];
  for (let i = 0; i < count; i++) {
    const bucketResults: Uint8Array[] = [];
    for (let j = 0; j < resultsPerBucket; j++) {
      const len = data[pos] | (data[pos + 1] << 8);
      pos += 2;
      const r = data.slice(pos, pos + len);
      pos += len;
      bucketResults.push(r);
    }
    results.push(bucketResults);
  }

  return {
    result: { level: 0, roundId, results },
    pos,
  };
}

/**
 * Decode a response from the payload bytes (after stripping the 4-byte length prefix).
 */
export function decodeResponse(data: Uint8Array): Response {
  if (data.length === 0) throw new Error('Empty response');

  const variant = data[0];

  switch (variant) {
    case RESP_PONG:
      return { type: 'Pong' };

    case RESP_INFO: {
      if (data.length < 19) throw new Error('Info response too short');
      const dv = new DataView(data.buffer, data.byteOffset, data.length);
      return {
        type: 'Info',
        info: {
          indexBinsPerTable: dv.getUint32(1, true),
          chunkBinsPerTable: dv.getUint32(5, true),
          indexK: data[9],
          chunkK: data[10],
          tagSeed: dv.getBigUint64(11, true),
        },
      };
    }

    case RESP_INDEX_BATCH: {
      const { result } = decodeBatchResult(data, 1);
      return { type: 'IndexBatch', result };
    }

    case RESP_CHUNK_BATCH: {
      const { result } = decodeBatchResult(data, 1);
      return { type: 'ChunkBatch', result };
    }

    case RESP_ERROR: {
      const dv = new DataView(data.buffer, data.byteOffset, data.length);
      const len = dv.getUint32(1, true);
      const message = new TextDecoder().decode(data.slice(5, 5 + len));
      return { type: 'Error', message };
    }

    default:
      throw new Error(`Unknown response variant: 0x${variant.toString(16)}`);
  }
}
