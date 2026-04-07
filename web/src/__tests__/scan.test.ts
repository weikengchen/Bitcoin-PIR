import { describe, it, expect } from 'vitest';
import {
  findEntryInIndexResult,
  findEntryInOnionPirIndexResult,
  findChunkInResult,
} from '../scan.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Write a u64 LE into a buffer at the given offset. */
function writeU64LE(buf: Uint8Array, offset: number, val: bigint): void {
  const dv = new DataView(buf.buffer, buf.byteOffset);
  dv.setBigUint64(offset, val, true);
}

/** Write a u32 LE into a buffer at the given offset. */
function writeU32LE(buf: Uint8Array, offset: number, val: number): void {
  const dv = new DataView(buf.buffer, buf.byteOffset);
  dv.setUint32(offset, val, true);
}

/** Write a u16 LE into a buffer at the given offset. */
function writeU16LE(buf: Uint8Array, offset: number, val: number): void {
  const dv = new DataView(buf.buffer, buf.byteOffset);
  dv.setUint16(offset, val, true);
}

// ─── findEntryInIndexResult (DPF / HarmonyPIR layout) ────────────────────────

describe('findEntryInIndexResult', () => {
  // DPF layout: 4 slots * 13 bytes = 52 bytes per bin
  const SLOTS_PER_BIN = 4;
  const SLOT_SIZE = 13; // 8B tag + 4B startChunkId + 1B numChunks

  it('finds matching tag in first slot', () => {
    const data = new Uint8Array(SLOTS_PER_BIN * SLOT_SIZE);
    const tag = 0xDEADBEEFCAFEBABEn;
    writeU64LE(data, 0, tag);       // tag in slot 0
    writeU32LE(data, 8, 42);        // startChunkId = 42
    data[12] = 5;                   // numChunks = 5

    const result = findEntryInIndexResult(data, tag, SLOTS_PER_BIN, SLOT_SIZE);
    expect(result).toEqual({ startChunkId: 42, numChunks: 5 });
  });

  it('finds matching tag in third slot', () => {
    const data = new Uint8Array(SLOTS_PER_BIN * SLOT_SIZE);
    const tag = 0x1234567890ABCDEFn;
    // Write to slot 2 (offset = 2 * 13 = 26)
    writeU64LE(data, 26, tag);
    writeU32LE(data, 34, 1000);
    data[38] = 3;

    const result = findEntryInIndexResult(data, tag, SLOTS_PER_BIN, SLOT_SIZE);
    expect(result).toEqual({ startChunkId: 1000, numChunks: 3 });
  });

  it('returns null when tag not found', () => {
    const data = new Uint8Array(SLOTS_PER_BIN * SLOT_SIZE);
    // Fill with some other tags
    writeU64LE(data, 0, 0x1111111111111111n);
    writeU64LE(data, 13, 0x2222222222222222n);

    const result = findEntryInIndexResult(data, 0x9999999999999999n, SLOTS_PER_BIN, SLOT_SIZE);
    expect(result).toBeNull();
  });

  it('returns null on empty (all-zero) bin', () => {
    const data = new Uint8Array(SLOTS_PER_BIN * SLOT_SIZE);
    const result = findEntryInIndexResult(data, 0xDEADn, SLOTS_PER_BIN, SLOT_SIZE);
    expect(result).toBeNull();
  });

  it('works with different bin sizes (HarmonyPIR-style)', () => {
    // HarmonyPIR: HARMONY_INDEX_W = 52, so slotsPerBin = 52 / 13 = 4
    // Same as DPF in this case, but let's test with a different size
    const slotsPerBin = 2;
    const data = new Uint8Array(slotsPerBin * SLOT_SIZE);
    const tag = 0xABCDEF0123456789n;
    writeU64LE(data, SLOT_SIZE, tag); // slot 1
    writeU32LE(data, SLOT_SIZE + 8, 777);
    data[SLOT_SIZE + 12] = 10;

    const result = findEntryInIndexResult(data, tag, slotsPerBin, SLOT_SIZE);
    expect(result).toEqual({ startChunkId: 777, numChunks: 10 });
  });
});

// ─── findEntryInOnionPirIndexResult ──────────────────────────────────────────

describe('findEntryInOnionPirIndexResult', () => {
  // OnionPIR layout: 8B tag + 4B entryId + 2B byteOffset + 1B numEntries = 15 bytes
  const SLOT_SIZE = 15;
  const BUCKET_SIZE = 256;

  it('finds matching tag and extracts entryId, byteOffset, numEntries', () => {
    // Use small bin for test
    const testBucketSize = 4;
    const data = new Uint8Array(testBucketSize * SLOT_SIZE);
    const tag = 0xFEDCBA9876543210n;

    // Write to slot 1
    const off = SLOT_SIZE;
    writeU64LE(data, off, tag);
    writeU32LE(data, off + 8, 12345);  // entryId
    writeU16LE(data, off + 12, 320);   // byteOffset
    data[off + 14] = 7;               // numEntries

    const result = findEntryInOnionPirIndexResult(data, tag, testBucketSize, SLOT_SIZE);
    expect(result).toEqual({ entryId: 12345, byteOffset: 320, numEntries: 7 });
  });

  it('skips zero tags', () => {
    const testBucketSize = 2;
    const data = new Uint8Array(testBucketSize * SLOT_SIZE);
    // Slot 0: tag = 0 (should be skipped even if searching for 0)
    // All zeros

    const result = findEntryInOnionPirIndexResult(data, 0n, testBucketSize, SLOT_SIZE);
    expect(result).toBeNull();
  });

  it('returns null when tag not present', () => {
    const testBucketSize = 3;
    const data = new Uint8Array(testBucketSize * SLOT_SIZE);
    writeU64LE(data, 0, 0x1111n);
    writeU64LE(data, SLOT_SIZE, 0x2222n);

    const result = findEntryInOnionPirIndexResult(data, 0x9999n, testBucketSize, SLOT_SIZE);
    expect(result).toBeNull();
  });
});

// ─── findChunkInResult ───────────────────────────────────────────────────────

describe('findChunkInResult', () => {
  // DPF: 3 slots * 44 bytes (4B chunkId + 40B data) = 132 bytes
  const CHUNK_BUCKET_SIZE = 3;
  const CHUNK_SLOT_SIZE = 44;
  const CHUNK_SIZE = 40;

  it('finds chunk by ID and returns data', () => {
    const data = new Uint8Array(CHUNK_BUCKET_SIZE * CHUNK_SLOT_SIZE);
    const targetId = 42;

    // Write to slot 1
    const off = CHUNK_SLOT_SIZE;
    writeU32LE(data, off, targetId);
    // Fill data bytes with recognizable pattern
    for (let i = 0; i < CHUNK_SIZE; i++) {
      data[off + 4 + i] = i + 1;
    }

    const result = findChunkInResult(data, targetId, CHUNK_BUCKET_SIZE, CHUNK_SLOT_SIZE);
    expect(result).not.toBeNull();
    expect(result!.length).toBe(CHUNK_SIZE);
    expect(result![0]).toBe(1);
    expect(result![39]).toBe(40);
  });

  it('returns null when chunk ID not found', () => {
    const data = new Uint8Array(CHUNK_BUCKET_SIZE * CHUNK_SLOT_SIZE);
    writeU32LE(data, 0, 100);
    writeU32LE(data, CHUNK_SLOT_SIZE, 200);
    writeU32LE(data, 2 * CHUNK_SLOT_SIZE, 300);

    const result = findChunkInResult(data, 999, CHUNK_BUCKET_SIZE, CHUNK_SLOT_SIZE);
    expect(result).toBeNull();
  });

  it('works with different slot sizes (HarmonyPIR chunk)', () => {
    // HarmonyPIR: CHUNK_SLOT_SIZE = 44, CHUNK_SLOTS_PER_BIN = 3
    // HARMONY_CHUNK_W = 132 = 3 * 44
    const data = new Uint8Array(3 * 44);
    writeU32LE(data, 2 * 44, 555); // slot 2
    for (let i = 0; i < 40; i++) {
      data[2 * 44 + 4 + i] = 0xAB;
    }

    const result = findChunkInResult(data, 555, 3, 44);
    expect(result).not.toBeNull();
    expect(result!.every(b => b === 0xAB)).toBe(true);
  });

  it('returns a copy (slice), not a view', () => {
    const data = new Uint8Array(CHUNK_BUCKET_SIZE * CHUNK_SLOT_SIZE);
    writeU32LE(data, 0, 1);
    data[4] = 0xFF;

    const result = findChunkInResult(data, 1, CHUNK_BUCKET_SIZE, CHUNK_SLOT_SIZE);
    expect(result).not.toBeNull();

    // Modify original, result should be unaffected
    data[4] = 0x00;
    expect(result![0]).toBe(0xFF);
  });
});
