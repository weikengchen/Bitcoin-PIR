/**
 * Example tests for Bitcoin PIR Web Client
 * 
 * These tests demonstrate the basic functionality of the library
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  hexToBytes,
  bytesToHex,
  cuckooHash1,
  cuckooHash2,
  cuckooLocations,
  CUCKOO_NUM_BUCKETS,
  reverseBytes,
  createPirClient,
  PirClient,
  CHUNK_SIZE,
} from '../index.js';

describe('Hash Functions', () => {
  it('should convert hex to bytes correctly', () => {
    const bytes = hexToBytes('deadbeef');
    assert.strictEqual(bytes.length, 4);
    assert.strictEqual(bytes[0], 0xde);
    assert.strictEqual(bytes[1], 0xad);
    assert.strictEqual(bytes[2], 0xbe);
    assert.strictEqual(bytes[3], 0xef);
  });

  it('should convert bytes to hex correctly', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const hex = bytesToHex(bytes);
    assert.strictEqual(hex, 'deadbeef');
  });

  it('should produce different cuckoo hash values', () => {
    const key = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const h1 = cuckooHash1(key, 1000);
    const h2 = cuckooHash2(key, 1000);
    assert.notStrictEqual(h1, h2);
  });

  it('should produce hash values within bucket range', () => {
    const key = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const h1 = cuckooHash1(key, CUCKOO_NUM_BUCKETS);
    const h2 = cuckooHash2(key, CUCKOO_NUM_BUCKETS);
    assert.ok(h1 >= 0 && h1 < CUCKOO_NUM_BUCKETS);
    assert.ok(h2 >= 0 && h2 < CUCKOO_NUM_BUCKETS);
  });

  it('should compute both cuckoo locations', () => {
    const key = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const [loc1, loc2] = cuckooLocations(key, CUCKOO_NUM_BUCKETS);
    assert.ok(loc1 >= 0 && loc1 < CUCKOO_NUM_BUCKETS);
    assert.ok(loc2 >= 0 && loc2 < CUCKOO_NUM_BUCKETS);
    assert.notStrictEqual(loc1, loc2);
  });

  it('should reverse bytes correctly', () => {
    const bytes = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const reversed = reverseBytes(bytes);
    assert.strictEqual(reversed[0], 0x04);
    assert.strictEqual(reversed[1], 0x03);
    assert.strictEqual(reversed[2], 0x02);
    assert.strictEqual(reversed[3], 0x01);
  });
});

describe('Hex Round-trip', () => {
  it('should maintain data integrity through hex conversion', () => {
    const original = new Uint8Array([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
      0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    ]);
    const hex = bytesToHex(original);
    const restored = hexToBytes(hex);
    assert.deepStrictEqual(restored, original);
  });
});

describe('Varint Reader', () => {
  it('should read single-byte varints correctly', () => {
    const client = createPirClient();
    
    // Test values 0-127 (single byte)
    for (let i = 0; i < 128; i++) {
      const data = new Uint8Array([i]);
      const result = client.readVarint(data, 0);
      assert.strictEqual(result.value, BigInt(i));
      assert.strictEqual(result.bytesConsumed, 1);
    }
  });

  it('should read multi-byte varints correctly', () => {
    const client = createPirClient();
    
    // Test 128 (0x80 0x01 in LEB128)
    const data128 = new Uint8Array([0x80, 0x01]);
    const result128 = client.readVarint(data128, 0);
    assert.strictEqual(result128.value, 128n);
    assert.strictEqual(result128.bytesConsumed, 2);

    // Test 300 (0xAC 0x02 in LEB128)
    const data300 = new Uint8Array([0xAC, 0x02]);
    const result300 = client.readVarint(data300, 0);
    assert.strictEqual(result300.value, 300n);
    assert.strictEqual(result300.bytesConsumed, 2);

    // Test 16383 (max 2-byte varint)
    const data16383 = new Uint8Array([0xFF, 0x7F]);
    const result16383 = client.readVarint(data16383, 0);
    assert.strictEqual(result16383.value, 16383n);
    assert.strictEqual(result16383.bytesConsumed, 2);
  });

  it('should read large varints correctly', () => {
    const client = createPirClient();
    
    // Test 65535 (max 3-byte varint is 2097151, but 65535 fits in 3)
    const data65535 = new Uint8Array([0xFF, 0xFF, 0x03]);
    const result65535 = client.readVarint(data65535, 0);
    assert.strictEqual(result65535.value, 65535n);
    assert.strictEqual(result65535.bytesConsumed, 3);

    // Test 1000000 in LEB128 encoding
    // 1000000 = 0xF4240 in hex
    // LEB128 encoding: split into 7-bit groups from LSB
    // 1000000 & 0x7F = 64, first byte = 64 | 0x80 = 0xC0 (continuation)
    // 1000000 >> 7 = 7812
    // 7812 & 0x7F = 4, second byte = 4 | 0x80 = 0x84 (continuation)
    // 7812 >> 7 = 61, third byte = 61 = 0x3D (no continuation)
    const data1M = new Uint8Array([0xC0, 0x84, 0x3D]);
    const result1M = client.readVarint(data1M, 0);
    assert.strictEqual(result1M.value, 1000000n);
    assert.strictEqual(result1M.bytesConsumed, 3);
  });

  it('should read varint at offset', () => {
    const client = createPirClient();
    
    // Data with some prefix bytes
    const data = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF, 0xAC, 0x02]);
    const result = client.readVarint(data, 4);
    assert.strictEqual(result.value, 300n);
    assert.strictEqual(result.bytesConsumed, 2);
  });
});

describe('PIR Client', () => {
  it('should create a PIR client with default configuration', () => {
    const client = createPirClient();
    assert.ok(client instanceof PirClient);
    assert.ok(!client.isConnected());
  });

  it('should create a PIR client with custom configuration', () => {
    const client = createPirClient('ws://localhost:9001', 'ws://localhost:9002');
    assert.ok(client instanceof PirClient);
  });
});

describe('Constants', () => {
  it('should have correct chunk size', () => {
    assert.strictEqual(CHUNK_SIZE, 32 * 1024); // 32KB
  });
});
