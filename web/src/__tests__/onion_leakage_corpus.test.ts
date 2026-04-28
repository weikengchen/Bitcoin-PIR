/**
 * Phase 2.3 step C: corpus shape verification.
 *
 * Loads the JSON fixture produced by the Rust `onion_leakage_dump`
 * example (`pir-sdk-client/examples/onion_leakage_dump.rs`) and
 * confirms it parses cleanly into the TypeScript `LeakageProfile`
 * shape. Catches schema regressions: if the Rust serde output drifts
 * (kind tag rename, field reorder, missing field), this test fails
 * before the live cross-language diff in step D ever runs.
 *
 * Step D — running a real OnionPIR query through the TS
 * `OnionPirWebClient` and diffing the result against this fixture —
 * needs WASM + WebSocket + FHE state in vitest, which is significant
 * infrastructure. This step C check is the cheap precondition that
 * pins the JSON contract.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  itemsUniform,
  type LeakageProfile,
  type RoundKind,
  type RoundProfile,
} from '../leakage.js';

interface CorpusFile {
  server_url: string;
  queries: Array<{
    script_hash_hex: string;
    profile: LeakageProfile;
  }>;
}

const FIXTURE_PATH = resolve(__dirname, '../../test/fixtures/onion_corpus.json');

function loadCorpus(): CorpusFile {
  const raw = readFileSync(FIXTURE_PATH, 'utf-8');
  return JSON.parse(raw) as CorpusFile;
}

describe('OnionPIR corpus fixture (Phase 2.3 step C)', () => {
  it('loads as a well-formed CorpusFile', () => {
    const corpus = loadCorpus();
    expect(typeof corpus.server_url).toBe('string');
    expect(Array.isArray(corpus.queries)).toBe(true);
    expect(corpus.queries.length).toBeGreaterThanOrEqual(2);
  });

  it('every query has a parseable LeakageProfile', () => {
    const corpus = loadCorpus();
    for (const q of corpus.queries) {
      expect(q.script_hash_hex).toMatch(/^[0-9a-f]{40}$/);
      expect(q.profile.backend).toBe('onion');
      expect(Array.isArray(q.profile.rounds)).toBe(true);
      expect(q.profile.rounds.length).toBeGreaterThan(0);
    }
  });

  it('every round has the structural fields the TS port expects', () => {
    const corpus = loadCorpus();
    const validKinds: ReadonlySet<RoundKind['kind']> = new Set([
      'index',
      'chunk',
      'index_merkle_siblings',
      'chunk_merkle_siblings',
      'harmony_hint_refresh',
      'onion_key_register',
      'info',
      'merkle_tree_tops',
    ]);
    for (const q of corpus.queries) {
      for (const r of q.profile.rounds as RoundProfile[]) {
        expect(validKinds.has(r.kind)).toBe(true);
        expect(typeof r.server_id).toBe('number');
        // db_id is `null` (catalog rounds) or a small unsigned int.
        if (r.db_id !== null) expect(typeof r.db_id).toBe('number');
        expect(typeof r.request_bytes).toBe('number');
        expect(typeof r.response_bytes).toBe('number');
        expect(Array.isArray(r.items)).toBe(true);
        // Parametric variants must carry `level`.
        if (r.kind === 'index_merkle_siblings' || r.kind === 'chunk_merkle_siblings') {
          expect(typeof r.level).toBe('number');
        }
      }
    }
  });

  /**
   * The simulator property: two not-found queries with the same
   * admitted leakage must produce structurally equivalent (in fact
   * byte-identical) transcripts. The Rust dumper already verifies
   * this empirically; re-verifying here in TS catches any schema
   * drift that would mask a real divergence.
   */
  it('two not-found queries produce byte-identical profiles', () => {
    const corpus = loadCorpus();
    expect(corpus.queries.length).toBeGreaterThanOrEqual(2);
    const a = corpus.queries[0].profile;
    const b = corpus.queries[1].profile;
    expect(a.rounds.length).toBe(b.rounds.length);
    for (let i = 0; i < a.rounds.length; i++) {
      // Stringify ensures field-order-independent equality, then
      // compare as JSON canonical form.
      const ja = JSON.stringify(a.rounds[i], Object.keys(a.rounds[i]).sort());
      const jb = JSON.stringify(b.rounds[i], Object.keys(b.rounds[i]).sort());
      expect(ja).toBe(jb);
    }
  });

  /**
   * Per-message invariant pin against the OnionPIR shape. If the
   * Rust client ever emits a different per-group count for INDEX
   * (it's been INDEX_CUCKOO_NUM_HASHES = 2 since CLAUDE.md "Merkle
   * INDEX Item-Count Symmetry" landed) this test fires.
   */
  it('every Index round has uniform items[g] = 2 (INDEX_CUCKOO_NUM_HASHES)', () => {
    const corpus = loadCorpus();
    for (const q of corpus.queries) {
      const indexRounds = q.profile.rounds.filter(
        (r): r is RoundProfile => r.kind === 'index',
      );
      expect(indexRounds.length).toBeGreaterThan(0);
      for (const r of indexRounds) {
        expect(itemsUniform(r, r.items.length, 2)).toBe(true);
      }
    }
  });

  /**
   * Every IndexMerkleSiblings round emits exactly one FHE query per
   * group — items[g] = 1 — matching the Rust pin in
   * `pir-sdk-client/src/onion_merkle.rs`.
   */
  it('every IndexMerkleSiblings round has uniform items[g] = 1', () => {
    const corpus = loadCorpus();
    for (const q of corpus.queries) {
      const merkleRounds = q.profile.rounds.filter(
        (r): r is RoundProfile => r.kind === 'index_merkle_siblings',
      );
      for (const r of merkleRounds) {
        expect(itemsUniform(r, r.items.length, 1)).toBe(true);
      }
    }
  });
});
