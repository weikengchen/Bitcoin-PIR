/**
 * Binary protocol encoder/decoder for the Batch PIR system.
 *
 * Matches batch_pir/src/protocol.rs exactly:
 *   Messages are length-prefixed: [4B total_len][1B variant][payload...]
 *   Batch queries/results: [2B round_id][1B count][per-bucket: [2B len][key]...]
 */

import {
  REQ_PING, REQ_GET_INFO, REQ_INDEX_BATCH, REQ_CHUNK_BATCH,
  RESP_PONG, RESP_INFO, RESP_INDEX_BATCH, RESP_CHUNK_BATCH, RESP_ERROR,
} from './constants.js';

// ─── Types ─────────────────────────────────────────────────────────────────

export interface BatchQuery {
  level: number;
  roundId: number;
  /** Per-bucket: [dpf_key_q0, dpf_key_q1] */
  keys: [Uint8Array, Uint8Array][];
}

export interface ServerInfo {
  indexBinsPerTable: number;
  chunkBinsPerTable: number;
  indexK: number;
  chunkK: number;
}

export interface BatchResult {
  level: number;
  roundId: number;
  /** Per-bucket: [result_q0, result_q1] */
  results: [Uint8Array, Uint8Array][];
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
  for (const [k0, k1] of q.keys) {
    // key0 length: u16 LE
    buf.push(k0.length & 0xFF, (k0.length >> 8) & 0xFF);
    for (let i = 0; i < k0.length; i++) buf.push(k0[i]);
    // key1 length: u16 LE
    buf.push(k1.length & 0xFF, (k1.length >> 8) & 0xFF);
    for (let i = 0; i < k1.length; i++) buf.push(k1[i]);
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

  const results: [Uint8Array, Uint8Array][] = [];
  for (let i = 0; i < count; i++) {
    const len0 = data[pos] | (data[pos + 1] << 8);
    pos += 2;
    const r0 = data.slice(pos, pos + len0);
    pos += len0;

    const len1 = data[pos] | (data[pos + 1] << 8);
    pos += 2;
    const r1 = data.slice(pos, pos + len1);
    pos += len1;

    results.push([r0, r1]);
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
      if (data.length < 11) throw new Error('Info response too short');
      const dv = new DataView(data.buffer, data.byteOffset, data.length);
      return {
        type: 'Info',
        info: {
          indexBinsPerTable: dv.getUint32(1, true),
          chunkBinsPerTable: dv.getUint32(5, true),
          indexK: data[9],
          chunkK: data[10],
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
