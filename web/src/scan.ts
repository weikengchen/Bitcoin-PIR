/**
 * Shared result scanning functions for all PIR backends.
 *
 * These functions scan cuckoo-hash bins returned by PIR queries to find
 * matching entries by tag (index level) or chunk ID (chunk level).
 * They are parameterized by slot/bucket sizes so they work with DPF,
 * OnionPIR, and HarmonyPIR backends despite different table layouts.
 */

// ─── Index scanning (DPF / HarmonyPIR) ──────────────────────────────────────

/**
 * Scan an index result (cuckoo bin) for a matching tag.
 *
 * Slot layout: [8B tag LE][4B startChunkId LE][1B numChunks][4B treeLoc LE]
 * Used by DPF (XOR'd result from 2 servers) and HarmonyPIR (reconstructed bin).
 *
 * @param data       - Raw bin bytes (bucketSize * slotSize bytes)
 * @param expectedTag - 8-byte tag as bigint to match against
 * @param bucketSize  - Number of slots in the bin (e.g. 4 for DPF index)
 * @param slotSize    - Bytes per slot (e.g. 17 for DPF/HarmonyPIR index)
 */
export function findEntryInIndexResult(
  data: Uint8Array,
  expectedTag: bigint,
  bucketSize: number,
  slotSize: number,
): { startChunkId: number; numChunks: number; treeLoc: number } | null {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  for (let slot = 0; slot < bucketSize; slot++) {
    const off = slot * slotSize;
    if (off + slotSize > data.length) break;
    const slotTag = dv.getBigUint64(off, true);
    if (slotTag === expectedTag) {
      const startChunkId = dv.getUint32(off + 8, true);
      const numChunks = data[off + 12];
      const treeLoc = (off + 17 <= data.length) ? dv.getUint32(off + 13, true) : 0;
      return { startChunkId, numChunks, treeLoc };
    }
  }
  return null;
}

// ─── Index scanning (OnionPIR) ───────────────────────────────────────────────

/**
 * Scan an OnionPIR index result for a matching tag.
 *
 * OnionPIR slot layout: [8B tag LE][4B entryId LE][2B byteOffset LE][1B numEntries][4B treeLoc LE]
 * This is a DIFFERENT layout from DPF/HarmonyPIR (19 bytes vs 17 bytes).
 *
 * @param data       - Raw bin bytes
 * @param expectedTag - 8-byte tag as bigint
 * @param bucketSize  - Number of slots (e.g. 202 for OnionPIR index)
 * @param slotSize    - Bytes per slot (e.g. 19 for OnionPIR)
 */
export function findEntryInOnionPirIndexResult(
  data: Uint8Array,
  expectedTag: bigint,
  bucketSize: number,
  slotSize: number,
): { entryId: number; byteOffset: number; numEntries: number; treeLoc: number } | null {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  for (let slot = 0; slot < bucketSize; slot++) {
    const off = slot * slotSize;
    if (off + slotSize > data.length) break;
    const slotTag = dv.getBigUint64(off, true);
    if (slotTag === expectedTag && slotTag !== 0n) {
      return {
        entryId: dv.getUint32(off + 8, true),
        byteOffset: dv.getUint16(off + 12, true),
        numEntries: data[off + 14],
        treeLoc: (off + 19 <= data.length) ? dv.getUint32(off + 15, true) : 0,
      };
    }
  }
  return null;
}

// ─── Chunk scanning ──────────────────────────────────────────────────────────

/**
 * Scan a chunk result (cuckoo bin) for a matching chunk ID.
 *
 * Slot layout: [4B chunkId LE][chunkData...]
 * Used by DPF (XOR'd result) and HarmonyPIR (reconstructed bin).
 *
 * @param data           - Raw bin bytes
 * @param targetChunkId  - Chunk ID to search for
 * @param chunkBucketSize - Number of slots (e.g. 3 for DPF chunks)
 * @param chunkSlotSize   - Bytes per slot (e.g. 44 = 4B id + 40B data)
 */
export function findChunkInResult(
  data: Uint8Array,
  targetChunkId: number,
  chunkBucketSize: number,
  chunkSlotSize: number,
): Uint8Array | null {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  for (let slot = 0; slot < chunkBucketSize; slot++) {
    const off = slot * chunkSlotSize;
    if (off + chunkSlotSize > data.length) break;
    const chunkId = dv.getUint32(off, true);
    if (chunkId === targetChunkId) {
      return data.slice(off + 4, off + chunkSlotSize);
    }
  }
  return null;
}

// ─── Merkle sibling group scanning ──────────────────────────────────────────

/**
 * Scan a Merkle sibling result (cuckoo bin) for a matching group ID.
 *
 * Slot layout: [4B groupId LE][arity × 32B child hashes]
 *
 * @param data       - Raw bin bytes (bucketSize × slotSize)
 * @param groupId    - Group ID to find
 * @param arity      - Number of children per group (e.g. 8)
 * @param bucketSize - Number of slots in the bin (e.g. 4)
 * @param slotSize   - Bytes per slot (e.g. 260 = 4 + 8×32)
 * @returns Array of arity child hashes (each 32 bytes), or null if not found
 */
export function findGroupInSiblingResult(
  data: Uint8Array,
  groupId: number,
  arity: number,
  bucketSize: number,
  slotSize: number,
): Uint8Array[] | null {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  for (let slot = 0; slot < bucketSize; slot++) {
    const off = slot * slotSize;
    if (off + slotSize > data.length) break;
    const storedId = dv.getUint32(off, true);
    if (storedId === groupId) {
      const children: Uint8Array[] = [];
      for (let c = 0; c < arity; c++) {
        children.push(data.slice(off + 4 + c * 32, off + 4 + (c + 1) * 32));
      }
      return children;
    }
  }
  return null;
}
