import { describe, it, expect } from 'vitest';
import { encodeRequest, decodeResponse } from '../protocol.js';
import { REQ_INDEX_BATCH, REQ_CHUNK_BATCH } from '../constants.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Make a minimal DPF key (just enough bytes to be non-empty). */
function fakeKey(len: number = 4): Uint8Array {
  const key = new Uint8Array(len);
  for (let i = 0; i < len; i++) key[i] = i + 1;
  return key;
}

// ─── BatchQuery dbId encoding ────────────────────────────────────────────────

describe('BatchQuery dbId wire format', () => {
  it('omits trailing db_id byte when dbId=0', () => {
    const msg = encodeRequest({
      type: 'IndexBatch',
      query: {
        level: 0,
        roundId: 0,
        keys: [[fakeKey()]],  // 1 group, 1 key
        dbId: 0,
      },
    });

    // msg layout: [4B len][1B REQ_INDEX_BATCH][2B roundId][1B count][1B keysPerGroup][2B keyLen][4B key]
    // = 4 + 1 + 2 + 1 + 1 + 2 + 4 = 15 bytes total
    const expectedLen = 4 + 1 + 2 + 1 + 1 + 2 + 4;
    expect(msg.length).toBe(expectedLen);

    // The last byte should be the last byte of the key, NOT a db_id
    expect(msg[msg.length - 1]).toBe(4); // last key byte
  });

  it('appends trailing db_id byte when dbId=1', () => {
    const msgWithDb = encodeRequest({
      type: 'IndexBatch',
      query: {
        level: 0,
        roundId: 0,
        keys: [[fakeKey()]],
        dbId: 1,
      },
    });

    const msgWithoutDb = encodeRequest({
      type: 'IndexBatch',
      query: {
        level: 0,
        roundId: 0,
        keys: [[fakeKey()]],
        dbId: 0,
      },
    });

    // With dbId=1 should be exactly 1 byte longer
    expect(msgWithDb.length).toBe(msgWithoutDb.length + 1);

    // The trailing byte should be 0x01
    expect(msgWithDb[msgWithDb.length - 1]).toBe(1);
  });

  it('treats undefined dbId same as dbId=0', () => {
    const msgUndefined = encodeRequest({
      type: 'IndexBatch',
      query: {
        level: 0,
        roundId: 0,
        keys: [[fakeKey()]],
      },
    });

    const msgZero = encodeRequest({
      type: 'IndexBatch',
      query: {
        level: 0,
        roundId: 0,
        keys: [[fakeKey()]],
        dbId: 0,
      },
    });

    expect(msgUndefined.length).toBe(msgZero.length);
    expect(msgUndefined).toEqual(msgZero);
  });

  it('works for ChunkBatch too', () => {
    const msg = encodeRequest({
      type: 'ChunkBatch',
      query: {
        level: 1,
        roundId: 5,
        keys: [[fakeKey(), fakeKey()]],  // 1 group, 2 keys
        dbId: 2,
      },
    });

    // Trailing byte should be db_id=2
    expect(msg[msg.length - 1]).toBe(2);

    // Verify the request variant byte
    expect(msg[4]).toBe(REQ_CHUNK_BATCH);
  });

  it('preserves roundId in encoding', () => {
    const msg = encodeRequest({
      type: 'IndexBatch',
      query: {
        level: 0,
        roundId: 0x1234,
        keys: [[fakeKey()]],
        dbId: 0,
      },
    });

    // roundId is at offset 5 (after 4B length + 1B variant), u16 LE
    expect(msg[5]).toBe(0x34);
    expect(msg[6]).toBe(0x12);
  });
});

// ─── Response decoding ───────────────────────────────────────────────────────

describe('decodeResponse', () => {
  it('decodes error response', () => {
    // Error: [1B 0xFF][4B len LE][message bytes]
    const errorMsg = 'unknown db_id 5';
    const msgBytes = new TextEncoder().encode(errorMsg);
    const data = new Uint8Array(1 + 4 + msgBytes.length);
    data[0] = 0xFF;
    const dv = new DataView(data.buffer);
    dv.setUint32(1, msgBytes.length, true);
    data.set(msgBytes, 5);

    const resp = decodeResponse(data);
    expect(resp.type).toBe('Error');
    if (resp.type === 'Error') {
      expect(resp.message).toBe('unknown db_id 5');
    }
  });
});
