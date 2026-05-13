/**
 * `padChunkIdsToM` — TypeScript port of the Rust Kani-verified helper
 * `crate::dpf::pad_chunk_ids_to_m`.
 *
 * The properties asserted below mirror the four Rust Kani harnesses
 * (`pad_chunk_ids_to_m_emits_exactly_m_when_padding_needed`,
 * `pad_chunk_ids_to_m_real_chunks_in_prefix`,
 * `pad_chunk_ids_to_m_synthetics_disjoint_from_real`,
 * `pad_chunk_ids_to_m_zero_m_is_identity`). Cross-language consistency
 * with the Rust reference is what makes the
 * `chunk_max_items_per_group_per_level` axis closure observably
 * equivalent across `OnionClient` (Rust) and `OnionPirWebClient`
 * (this file's home).
 *
 * Post-commit-`08d4725a`: synthetic chunk_ids are SHA-256-derived
 * (scripthash-seeded), not the legacy `0..M`-skipping deterministic
 * fill. Property assertions (shape, prefix-preservation, disjointness,
 * identity) survive; specific synthetic *values* depend on SHA-256
 * output and are not pinned by literal expectations here. The live
 * cross-language diff test (`onion_leakage_diff.test.ts`) catches any
 * drift between this TS port and the Rust reference.
 */

import { describe, it, expect } from 'vitest';
import {
  padChunkIdsToM,
  deriveChunkPadSeed,
  deriveSyntheticChunkIds,
  CHUNK_MERKLE_ITEMS_PER_QUERY,
} from '../onionpir_client.js';

// Fixed test seed matching the Rust Kani harnesses, which use
// `let seed = [0u8; 32]`. Reusing all-zeros keeps the TS unit tests
// trivially comparable to the Rust reasoning even when the specific
// SHA-256 output is computed by the helper itself.
const ZERO_SEED = new Uint8Array(32);

// Production-typical `num_chunks` upper bound. Any value much larger
// than M is fine — the production constraint is `num_chunks >> M`.
const NUM_CHUNKS = 1000;

describe('padChunkIdsToM (chunk_max axis closure helper)', () => {
  it('exposes M = 16 matching the Rust constant', () => {
    expect(CHUNK_MERKLE_ITEMS_PER_QUERY).toBe(16);
  });

  // ── Mirror: pad_chunk_ids_to_m_emits_exactly_m_when_padding_needed ──
  it('emits exactly m ids when padding needed (empty real-chunks)', () => {
    const padded = padChunkIdsToM([], 4, ZERO_SEED, NUM_CHUNKS);
    expect(padded.length).toBe(4);
  });

  it('emits exactly m ids when padding needed (one real chunk)', () => {
    const padded = padChunkIdsToM([42], 4, ZERO_SEED, NUM_CHUNKS);
    expect(padded.length).toBe(4);
    expect(padded[0]).toBe(42);
  });

  // ── Mirror: pad_chunk_ids_to_m_real_chunks_in_prefix ──
  it('preserves real chunks in the prefix verbatim', () => {
    const padded = padChunkIdsToM([100, 200], 4, ZERO_SEED, NUM_CHUNKS);
    expect(padded[0]).toBe(100);
    expect(padded[1]).toBe(200);
    expect(padded.length).toBe(4);
  });

  // ── Mirror: pad_chunk_ids_to_m_synthetics_disjoint_from_real ──
  it('synthetics never collide with real-chunk list (worst-case [0, 1])', () => {
    const padded = padChunkIdsToM([0, 1], 4, ZERO_SEED, NUM_CHUNKS);
    expect(padded.length).toBe(4);
    // Each synthetic must be disjoint from real_chunks = {0, 1} ...
    expect(padded[2]).not.toBe(0);
    expect(padded[2]).not.toBe(1);
    expect(padded[3]).not.toBe(0);
    expect(padded[3]).not.toBe(1);
    // ... and pairwise distinct.
    expect(padded[2]).not.toBe(padded[3]);
  });

  // ── Mirror: pad_chunk_ids_to_m_zero_m_is_identity ──
  it('is identity when m <= realChunks.length (m=0 case)', () => {
    const padded = padChunkIdsToM([10, 20, 30], 0, ZERO_SEED, NUM_CHUNKS);
    expect(padded).toEqual([10, 20, 30]);
  });

  it('is identity when m <= realChunks.length (m=N case)', () => {
    const padded = padChunkIdsToM([10, 20, 30], 3, ZERO_SEED, NUM_CHUNKS);
    expect(padded).toEqual([10, 20, 30]);
  });

  it('is identity when m < realChunks.length (defensive shrink path)', () => {
    // Production callers always pass `m === CHUNK_MERKLE_ITEMS_PER_QUERY = 16`,
    // but the helper must remain total for any (real_chunks, m) pair —
    // including the surprising case `m < real_chunks.length`. Returns
    // the input verbatim (no truncation) so the caller's downstream
    // length-check fires cleanly.
    const padded = padChunkIdsToM([10, 20, 30, 40, 50], 2, ZERO_SEED, NUM_CHUNKS);
    expect(padded).toEqual([10, 20, 30, 40, 50]);
  });

  it('production M=16 case with N=1 real produces M-length output', () => {
    // The realistic shape every found query produces: one or two real
    // entry_ids + 14-15 deterministic synthetics. Pin shape + prefix +
    // disjointness; specific synthetic values are SHA-256-derived.
    const padded = padChunkIdsToM([100], CHUNK_MERKLE_ITEMS_PER_QUERY, ZERO_SEED, NUM_CHUNKS);
    expect(padded.length).toBe(16);
    expect(padded[0]).toBe(100);
    const synth = padded.slice(1);
    // None of the synthetics collide with the real.
    for (const s of synth) expect(s).not.toBe(100);
    // All synthetics pairwise distinct.
    expect(new Set(synth).size).toBe(synth.length);
    // All synthetics in [0, NUM_CHUNKS).
    for (const s of synth) {
      expect(s).toBeGreaterThanOrEqual(0);
      expect(s).toBeLessThan(NUM_CHUNKS);
    }
  });

  it('not-found / whale path: M=16 owned ids are all synthetic', () => {
    const padded = padChunkIdsToM([], CHUNK_MERKLE_ITEMS_PER_QUERY, ZERO_SEED, NUM_CHUNKS);
    expect(padded.length).toBe(16);
    // All entries pairwise distinct and in range.
    expect(new Set(padded).size).toBe(padded.length);
    for (const s of padded) {
      expect(s).toBeGreaterThanOrEqual(0);
      expect(s).toBeLessThan(NUM_CHUNKS);
    }
  });

  it('synthetic suffix avoids real ids that overlap the search space', () => {
    // Worst-case overlap: every real id is in the synthetic search space.
    // The helper must skip all of them.
    const realChunks = [0, 5, 10];
    const padded = padChunkIdsToM(realChunks, 8, ZERO_SEED, NUM_CHUNKS);
    expect(padded.length).toBe(8);
    expect(padded.slice(0, 3)).toEqual([0, 5, 10]);
    const synth = padded.slice(3);
    // Synthetics disjoint from reals.
    for (const s of synth) {
      expect(realChunks).not.toContain(s);
    }
    // Synthetics pairwise distinct.
    expect(new Set(synth).size).toBe(synth.length);
  });

  it('is deterministic in (realChunks, m, seed, numChunks)', () => {
    // Same inputs → same output, every call. (Rust kani harnesses
    // assume this implicitly; pin it explicitly here so a regression
    // that introduces RNG into the synthetic path fires loudly.)
    const a = padChunkIdsToM([7, 11], 6, ZERO_SEED, NUM_CHUNKS);
    const b = padChunkIdsToM([7, 11], 6, ZERO_SEED, NUM_CHUNKS);
    expect(a).toEqual(b);
  });

  it('different seeds produce (typically) different synthetic suffixes', () => {
    const seed1 = new Uint8Array(32);
    const seed2 = new Uint8Array(32);
    seed2[0] = 1; // single-bit difference
    const a = padChunkIdsToM([], 8, seed1, NUM_CHUNKS);
    const b = padChunkIdsToM([], 8, seed2, NUM_CHUNKS);
    // With overwhelming probability the two SHA-256 outputs differ
    // in the leading bytes, so the synthetic sets differ. This is a
    // weak property (could in theory fail for a colliding seed, but
    // SHA-256 makes that infeasible) — main point is that the seed
    // is actually wired through and not silently ignored.
    expect(a).not.toEqual(b);
  });
});

describe('deriveChunkPadSeed (per-query seed derivation)', () => {
  it('is deterministic in (scripthash, queryIndex)', () => {
    const sh = new Uint8Array(20);
    for (let i = 0; i < 20; i++) sh[i] = i;
    const a = deriveChunkPadSeed(sh, 0);
    const b = deriveChunkPadSeed(sh, 0);
    expect(a).toEqual(b);
    expect(a.length).toBe(32);
  });

  it('different scripthashes produce different seeds', () => {
    const sh1 = new Uint8Array(20);
    const sh2 = new Uint8Array(20);
    sh2[0] = 1;
    expect(deriveChunkPadSeed(sh1, 0)).not.toEqual(deriveChunkPadSeed(sh2, 0));
  });

  it('different query indices produce different seeds (same scripthash)', () => {
    const sh = new Uint8Array(20);
    expect(deriveChunkPadSeed(sh, 0)).not.toEqual(deriveChunkPadSeed(sh, 1));
  });

  it('matches the documented format: SHA-256("BPIR-CHUNK-PAD" || sh || idx_le)', async () => {
    // Independent re-derivation using Web Crypto SubtleCrypto — pins
    // the exact pre-image format against the helper's implementation.
    // (Node's crypto.subtle is available via globalThis.crypto in
    // Node 18+ and is standards-compliant.)
    const sh = new Uint8Array(20);
    for (let i = 0; i < 20; i++) sh[i] = i * 13;
    const queryIndex = 0x12345678;

    const label = new TextEncoder().encode('BPIR-CHUNK-PAD');
    const idxLe = new Uint8Array([
      queryIndex & 0xff,
      (queryIndex >>> 8) & 0xff,
      (queryIndex >>> 16) & 0xff,
      (queryIndex >>> 24) & 0xff,
    ]);
    const input = new Uint8Array(label.length + sh.length + 4);
    input.set(label, 0);
    input.set(sh, label.length);
    input.set(idxLe, label.length + sh.length);

    const expectedBuffer = await crypto.subtle.digest('SHA-256', input);
    const expected = new Uint8Array(expectedBuffer);

    const actual = deriveChunkPadSeed(sh, queryIndex);
    expect(actual).toEqual(expected);
  });
});

describe('deriveSyntheticChunkIds (counter-mode SHA-256 stream)', () => {
  it('returns empty when m === 0', () => {
    expect(deriveSyntheticChunkIds(ZERO_SEED, 0, NUM_CHUNKS, [])).toEqual([]);
  });

  it('returns empty when numChunks === 0', () => {
    expect(deriveSyntheticChunkIds(ZERO_SEED, 4, 0, [])).toEqual([]);
  });

  it('caps result length at numChunks - real_count', () => {
    // available = numChunks - real_count = 5 - 3 = 2; m = 4 → expect 2.
    const result = deriveSyntheticChunkIds(ZERO_SEED, 4, 5, [0, 1, 2]);
    expect(result.length).toBe(2);
    for (const s of result) {
      expect([0, 1, 2]).not.toContain(s);
      expect(s).toBeGreaterThanOrEqual(0);
      expect(s).toBeLessThan(5);
    }
  });

  it('produces pairwise distinct entries', () => {
    const result = deriveSyntheticChunkIds(ZERO_SEED, 16, NUM_CHUNKS, []);
    expect(result.length).toBe(16);
    expect(new Set(result).size).toBe(16);
  });

  it('produces entries disjoint from realChunks', () => {
    const reals = [10, 20, 30, 40, 50];
    const result = deriveSyntheticChunkIds(ZERO_SEED, 8, NUM_CHUNKS, reals);
    expect(result.length).toBe(8);
    for (const s of result) {
      expect(reals).not.toContain(s);
    }
  });

  it('is deterministic', () => {
    const a = deriveSyntheticChunkIds(ZERO_SEED, 8, NUM_CHUNKS, [3, 7]);
    const b = deriveSyntheticChunkIds(ZERO_SEED, 8, NUM_CHUNKS, [3, 7]);
    expect(a).toEqual(b);
  });
});
