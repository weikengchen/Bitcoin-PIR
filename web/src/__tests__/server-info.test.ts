import { describe, it, expect } from 'vitest';
import { parseServerInfoJson } from '../server-info.js';

describe('parseServerInfoJson', () => {
  const MINIMAL_JSON = JSON.stringify({
    index_bins_per_table: 1048576,
    chunk_bins_per_table: 2097152,
    index_k: 75,
    chunk_k: 80,
    tag_seed: '0x71a2ef38b4c90d15',
    index_dpf_n: 20,
    chunk_dpf_n: 21,
    index_cuckoo_bucket_size: 4,
    index_slot_size: 13,
    chunk_cuckoo_bucket_size: 3,
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
    expect(info.index_cuckoo_bucket_size).toBe(4);
    expect(info.index_slot_size).toBe(13);
    expect(info.chunk_cuckoo_bucket_size).toBe(3);
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
      index_cuckoo_bucket_size: 4,
      index_slot_size: 13,
      chunk_cuckoo_bucket_size: 3,
      chunk_slot_size: 44,
      role: 'primary',
      onionpir: {
        total_packed_entries: 262144,
        index_bins_per_table: 8839,
        chunk_bins_per_table: 32562,
        tag_seed: '0xd4e5f6a7b8c91023',
        index_k: 75,
        chunk_k: 80,
        index_cuckoo_bucket_size: 256,
        index_slot_size: 15,
        chunk_cuckoo_bucket_size: 1,
        chunk_slot_size: 3840,
      },
      merkle: {
        arity: 8,
        sibling_levels: 4,
        sibling_k: 75,
        sibling_bucket_size: 4,
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
    expect(info.onionpir!.index_cuckoo_bucket_size).toBe(256);
    expect(info.onionpir!.index_slot_size).toBe(15);
    expect(info.onionpir!.chunk_cuckoo_bucket_size).toBe(1);
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
