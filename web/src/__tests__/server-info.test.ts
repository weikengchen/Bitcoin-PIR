import { describe, it, expect } from 'vitest';
import { parseServerInfoJson, decodeDatabaseCatalog } from '../server-info.js';

describe('parseServerInfoJson', () => {
  const MINIMAL_JSON = JSON.stringify({
    index_bins_per_table: 1048576,
    chunk_bins_per_table: 2097152,
    index_k: 75,
    chunk_k: 80,
    tag_seed: '0x71a2ef38b4c90d15',
    index_dpf_n: 20,
    chunk_dpf_n: 21,
    index_slots_per_bin: 4,
    index_slot_size: 13,
    chunk_slots_per_bin: 3,
    chunk_slot_size: 44,
    role: 'primary',
  });

  it('parses minimal JSON (no onionpir, no merkle)', () => {
    const info = parseServerInfoJson(MINIMAL_JSON);
    expect(info.index_bins_per_table).toBe(1048576);
    expect(info.chunk_bins_per_table).toBe(2097152);
    expect(info.index_k).toBe(75);
    expect(info.chunk_k).toBe(80);
    expect(info.tag_seed).toBe(0x71a2ef38b4c90d15n);
    expect(info.index_dpf_n).toBe(20);
    expect(info.chunk_dpf_n).toBe(21);
    expect(info.index_slots_per_bin).toBe(4);
    expect(info.index_slot_size).toBe(13);
    expect(info.chunk_slots_per_bin).toBe(3);
    expect(info.chunk_slot_size).toBe(44);
    expect(info.role).toBe('primary');
    expect(info.onionpir).toBeUndefined();
    expect(info.merkle).toBeUndefined();
  });

  it('parses tag_seed as bigint from hex string', () => {
    const info = parseServerInfoJson(MINIMAL_JSON);
    expect(typeof info.tag_seed).toBe('bigint');
    expect(info.tag_seed).toBe(0x71a2ef38b4c90d15n);
  });

  it('parses full JSON with onionpir section', () => {
    const full = JSON.stringify({
      index_bins_per_table: 1048576,
      chunk_bins_per_table: 2097152,
      index_k: 75,
      chunk_k: 80,
      tag_seed: '0x71a2ef38b4c90d15',
      index_dpf_n: 20,
      chunk_dpf_n: 21,
      index_slots_per_bin: 4,
      index_slot_size: 13,
      chunk_slots_per_bin: 3,
      chunk_slot_size: 44,
      role: 'primary',
      onionpir: {
        total_packed_entries: 262144,
        index_bins_per_table: 8839,
        chunk_bins_per_table: 32562,
        tag_seed: '0xd4e5f6a7b8c91023',
        index_k: 75,
        chunk_k: 80,
        index_slots_per_bin: 256,
        index_slot_size: 15,
        chunk_slots_per_bin: 1,
        chunk_slot_size: 3840,
      },
      merkle: {
        arity: 8,
        sibling_levels: 4,
        sibling_k: 75,
        sibling_slots_per_bin: 4,
        sibling_slot_size: 260,
        levels: [
          { dpf_n: 18, bins_per_table: 200000 },
        ],
        root: 'abcd1234',
        tree_top_hash: 'ef567890',
        tree_top_size: 1024,
      },
    });

    const info = parseServerInfoJson(full);
    expect(info.onionpir).toBeDefined();
    expect(info.onionpir!.total_packed_entries).toBe(262144);
    expect(info.onionpir!.index_bins_per_table).toBe(8839);
    expect(info.onionpir!.chunk_bins_per_table).toBe(32562);
    expect(info.onionpir!.tag_seed).toBe(0xd4e5f6a7b8c91023n);
    expect(typeof info.onionpir!.tag_seed).toBe('bigint');
    expect(info.onionpir!.index_k).toBe(75);
    expect(info.onionpir!.chunk_k).toBe(80);
    expect(info.onionpir!.index_slots_per_bin).toBe(256);
    expect(info.onionpir!.index_slot_size).toBe(15);
    expect(info.onionpir!.chunk_slots_per_bin).toBe(1);
    expect(info.onionpir!.chunk_slot_size).toBe(3840);
    expect(info.merkle).toBeDefined();
    expect(info.merkle!.arity).toBe(8);
    expect(info.merkle!.root).toBe('abcd1234');
  });

  it('parses secondary role', () => {
    const json = MINIMAL_JSON.replace('"primary"', '"secondary"');
    const info = parseServerInfoJson(json);
    expect(info.role).toBe('secondary');
  });

  it('handles different tag_seed values', () => {
    const json = MINIMAL_JSON.replace('0x71a2ef38b4c90d15', '0x0000000000000001');
    const info = parseServerInfoJson(json);
    expect(info.tag_seed).toBe(1n);
  });
});

// ─── decodeDatabaseCatalog ──────────────────────────────────────────────────

describe('decodeDatabaseCatalog', () => {
  /** Helper: build a catalog binary buffer. */
  function buildCatalogEntry(opts: {
    dbId: number; dbType: number; name: string;
    baseHeight: number; height: number;
    indexBins: number; chunkBins: number;
    indexK: number; chunkK: number;
    tagSeed: bigint; dpfNIndex: number; dpfNChunk: number;
    hasBucketMerkle?: boolean;
  }): Uint8Array {
    const nameBytes = new TextEncoder().encode(opts.name);
    const buf = new Uint8Array(3 + nameBytes.length + 4 + 4 + 4 + 4 + 1 + 1 + 8 + 1 + 1 + 1);
    const dv = new DataView(buf.buffer);
    let pos = 0;
    buf[pos++] = opts.dbId;
    buf[pos++] = opts.dbType;
    buf[pos++] = nameBytes.length;
    buf.set(nameBytes, pos); pos += nameBytes.length;
    dv.setUint32(pos, opts.baseHeight, true); pos += 4;
    dv.setUint32(pos, opts.height, true); pos += 4;
    dv.setUint32(pos, opts.indexBins, true); pos += 4;
    dv.setUint32(pos, opts.chunkBins, true); pos += 4;
    buf[pos++] = opts.indexK;
    buf[pos++] = opts.chunkK;
    dv.setBigUint64(pos, opts.tagSeed, true); pos += 8;
    buf[pos++] = opts.dpfNIndex;
    buf[pos++] = opts.dpfNChunk;
    buf[pos++] = opts.hasBucketMerkle ? 1 : 0;
    return buf;
  }

  it('decodes catalog with 1 full + 1 delta database', () => {
    const entry0 = buildCatalogEntry({
      dbId: 0, dbType: 0, name: 'main',
      baseHeight: 0, height: 940611,
      indexBins: 1048576, chunkBins: 2097152,
      indexK: 75, chunkK: 80,
      tagSeed: 0x71a2ef38b4c90d15n,
      dpfNIndex: 20, dpfNChunk: 21,
    });
    const entry1 = buildCatalogEntry({
      dbId: 1, dbType: 1, name: 'delta_940611_944000',
      baseHeight: 940611, height: 944000,
      indexBins: 4096, chunkBins: 8192,
      indexK: 75, chunkK: 80,
      tagSeed: 0xaabbccdd11223344n,
      dpfNIndex: 12, dpfNChunk: 13,
    });

    const data = new Uint8Array(1 + entry0.length + entry1.length);
    data[0] = 2; // num_databases
    data.set(entry0, 1);
    data.set(entry1, 1 + entry0.length);

    const catalog = decodeDatabaseCatalog(data);

    expect(catalog.databases).toHaveLength(2);

    const db0 = catalog.databases[0];
    expect(db0.dbId).toBe(0);
    expect(db0.dbType).toBe(0);
    expect(db0.name).toBe('main');
    expect(db0.baseHeight).toBe(0);
    expect(db0.height).toBe(940611);
    expect(db0.indexBinsPerTable).toBe(1048576);
    expect(db0.chunkBinsPerTable).toBe(2097152);
    expect(db0.tagSeed).toBe(0x71a2ef38b4c90d15n);
    expect(db0.dpfNIndex).toBe(20);
    expect(db0.dpfNChunk).toBe(21);
    expect(db0.hasBucketMerkle).toBe(false);

    const db1 = catalog.databases[1];
    expect(db1.dbId).toBe(1);
    expect(db1.dbType).toBe(1);
    expect(db1.name).toBe('delta_940611_944000');
    expect(db1.baseHeight).toBe(940611);
    expect(db1.height).toBe(944000);
    expect(db1.indexBinsPerTable).toBe(4096);
    expect(db1.chunkBinsPerTable).toBe(8192);
    expect(db1.tagSeed).toBe(0xaabbccdd11223344n);
    expect(db1.dpfNIndex).toBe(12);
    expect(db1.dpfNChunk).toBe(13);
    expect(db1.hasBucketMerkle).toBe(false);
  });

  it('decodes catalog with hasBucketMerkle flag', () => {
    const entry0 = buildCatalogEntry({
      dbId: 0, dbType: 0, name: 'main',
      baseHeight: 0, height: 940611,
      indexBins: 1048576, chunkBins: 2097152,
      indexK: 75, chunkK: 80,
      tagSeed: 0x71a2ef38b4c90d15n,
      dpfNIndex: 20, dpfNChunk: 21,
      hasBucketMerkle: true,
    });

    const data = new Uint8Array(1 + entry0.length);
    data[0] = 1;
    data.set(entry0, 1);

    const catalog = decodeDatabaseCatalog(data);
    expect(catalog.databases[0].hasBucketMerkle).toBe(true);
  });

  it('decodes empty catalog', () => {
    const data = new Uint8Array([0]); // num_databases = 0
    const catalog = decodeDatabaseCatalog(data);
    expect(catalog.databases).toHaveLength(0);
  });
});
