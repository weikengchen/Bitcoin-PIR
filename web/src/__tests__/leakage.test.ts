import { describe, it, expect } from 'vitest';
import {
  BufferingLeakageRecorder,
  countOfKind,
  itemsUniform,
  kindMatches,
  leakageProfilesEqual,
  roundProfilesEqual,
  roundsOfKind,
  type LeakageProfile,
  type RoundProfile,
} from '../leakage.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function indexRound(serverId: number, dbId: number, k: number, perGroup: number): RoundProfile {
  return {
    kind: 'index',
    server_id: serverId,
    db_id: dbId,
    request_bytes: 0,
    response_bytes: 0,
    items: Array(k).fill(perGroup),
  };
}

function indexMerkleRound(level: number, k: number, perGroup: number): RoundProfile {
  return {
    kind: 'index_merkle_siblings',
    level,
    server_id: 0,
    db_id: 0,
    request_bytes: 0,
    response_bytes: 0,
    items: Array(k).fill(perGroup),
  };
}

// ─── BufferingLeakageRecorder ────────────────────────────────────────────────

describe('BufferingLeakageRecorder', () => {
  it('starts empty', () => {
    const r = new BufferingLeakageRecorder();
    expect(r.isEmpty).toBe(true);
    expect(r.length).toBe(0);
    expect(r.snapshot()).toEqual([]);
  });

  it('appends rounds in emission order', () => {
    const r = new BufferingLeakageRecorder();
    r.recordRound('onion', indexRound(0, 0, 75, 2));
    r.recordRound('onion', indexMerkleRound(0, 75, 1));
    r.recordRound('onion', indexMerkleRound(1, 75, 1));

    expect(r.length).toBe(3);
    const snap = r.snapshot();
    expect(snap[0].kind).toBe('index');
    expect(snap[1].kind).toBe('index_merkle_siblings');
    expect(snap[1].level).toBe(0);
    expect(snap[2].level).toBe(1);
  });

  it('takeProfile drains the buffer', () => {
    const r = new BufferingLeakageRecorder();
    r.recordRound('onion', indexRound(0, 0, 75, 2));
    r.recordRound('onion', indexRound(0, 0, 75, 2));

    const p = r.takeProfile('onion');
    expect(p.backend).toBe('onion');
    expect(p.rounds.length).toBe(2);
    expect(r.isEmpty).toBe(true);
  });

  it('clear drops without producing a profile', () => {
    const r = new BufferingLeakageRecorder();
    r.recordRound('onion', indexRound(0, 0, 75, 2));
    r.clear();
    expect(r.isEmpty).toBe(true);
  });
});

// ─── Helper functions ────────────────────────────────────────────────────────

describe('itemsUniform', () => {
  it('returns true when length and value match', () => {
    expect(itemsUniform(indexRound(0, 0, 75, 2), 75, 2)).toBe(true);
  });

  it('rejects wrong length', () => {
    expect(itemsUniform(indexRound(0, 0, 75, 2), 74, 2)).toBe(false);
  });

  it('rejects wrong value', () => {
    expect(itemsUniform(indexRound(0, 0, 75, 2), 75, 1)).toBe(false);
  });

  it('rejects one outlier', () => {
    const r = indexRound(0, 0, 75, 2);
    r.items[40] = 1;
    expect(itemsUniform(r, 75, 2)).toBe(false);
  });

  it('treats empty items as length-0 only', () => {
    const r: RoundProfile = {
      kind: 'info',
      server_id: 0,
      db_id: null,
      request_bytes: 0,
      response_bytes: 0,
      items: [],
    };
    expect(itemsUniform(r, 0, 99)).toBe(true);
    expect(itemsUniform(r, 1, 0)).toBe(false);
  });
});

describe('kindMatches / roundsOfKind / countOfKind', () => {
  it('matches by kind discriminator regardless of level', () => {
    const a = indexMerkleRound(0, 1, 2);
    const b = indexMerkleRound(7, 1, 2);
    expect(kindMatches(a, 'index_merkle_siblings')).toBe(true);
    expect(kindMatches(b, 'index_merkle_siblings')).toBe(true);
    expect(kindMatches(a, 'chunk_merkle_siblings')).toBe(false);
    expect(kindMatches(a, 'index')).toBe(false);
  });

  it('roundsOfKind filters across levels', () => {
    const profile: LeakageProfile = {
      backend: 'onion',
      rounds: [
        indexRound(0, 0, 75, 2),
        indexMerkleRound(0, 75, 1),
        indexMerkleRound(1, 75, 1),
        indexMerkleRound(2, 75, 1),
      ],
    };
    expect(roundsOfKind(profile, 'index_merkle_siblings').length).toBe(3);
    expect(countOfKind(profile, 'index_merkle_siblings')).toBe(3);
    expect(countOfKind(profile, 'index')).toBe(1);
    expect(countOfKind(profile, 'chunk')).toBe(0);
    expect(countOfKind(profile, 'onion_key_register')).toBe(0);
  });
});

// ─── Cross-language equality ─────────────────────────────────────────────────

describe('roundProfilesEqual / leakageProfilesEqual', () => {
  it('two identical not-found profiles compare equal', () => {
    const a: LeakageProfile = {
      backend: 'onion',
      rounds: [indexRound(0, 0, 75, 2), indexMerkleRound(0, 75, 1)],
    };
    const b: LeakageProfile = {
      backend: 'onion',
      rounds: [indexRound(0, 0, 75, 2), indexMerkleRound(0, 75, 1)],
    };
    expect(leakageProfilesEqual(a, b)).toBe(true);
  });

  it('an INDEX-Merkle item-count drift makes profiles unequal', () => {
    const good = indexMerkleRound(0, 1, 2);
    const bad = indexMerkleRound(0, 1, 1);
    expect(roundProfilesEqual(good, bad)).toBe(false);
  });

  it('different round counts make profiles unequal', () => {
    const a: LeakageProfile = { backend: 'onion', rounds: [indexRound(0, 0, 75, 2)] };
    const b: LeakageProfile = {
      backend: 'onion',
      rounds: [indexRound(0, 0, 75, 2), indexMerkleRound(0, 75, 1)],
    };
    expect(leakageProfilesEqual(a, b)).toBe(false);
  });

  it('different server_id makes rounds unequal', () => {
    const a = indexRound(0, 0, 75, 2);
    const b = indexRound(1, 0, 75, 2);
    expect(roundProfilesEqual(a, b)).toBe(false);
  });

  it('different level on same merkle kind makes rounds unequal', () => {
    const a = indexMerkleRound(0, 1, 2);
    const b = indexMerkleRound(1, 1, 2);
    expect(roundProfilesEqual(a, b)).toBe(false);
  });

  it('different backend tag makes profiles unequal', () => {
    const a: LeakageProfile = { backend: 'onion', rounds: [] };
    const b: LeakageProfile = { backend: 'dpf', rounds: [] };
    expect(leakageProfilesEqual(a, b)).toBe(false);
  });
});

// ─── JSON-shape pin ──────────────────────────────────────────────────────────

/**
 * The Rust pin test (`leakage_profile_json_shape_is_pinned` in
 * `pir-sdk/src/leakage.rs`) asserts the exact wire JSON the Rust side
 * produces. This test pins the same shape from the TS side. If the
 * Rust shape changes, both pins must change together — that's the
 * cross-language contract.
 */
describe('JSON-shape compatibility with Rust serde', () => {
  it('non-parametric variant: kind tag is flat at top level', () => {
    const r: RoundProfile = {
      kind: 'index',
      server_id: 0,
      db_id: 3,
      request_bytes: 1024,
      response_bytes: 4096,
      items: [2, 2],
    };
    expect(JSON.stringify(r)).toBe(
      '{"kind":"index","server_id":0,"db_id":3,"request_bytes":1024,"response_bytes":4096,"items":[2,2]}',
    );
  });

  it('parametric variant: level sits next to kind, not nested', () => {
    const r: RoundProfile = {
      kind: 'index_merkle_siblings',
      level: 7,
      server_id: 0,
      db_id: 3,
      request_bytes: 100,
      response_bytes: 200,
      items: [1, 1],
    };
    expect(JSON.stringify(r)).toBe(
      '{"kind":"index_merkle_siblings","level":7,"server_id":0,"db_id":3,"request_bytes":100,"response_bytes":200,"items":[1,1]}',
    );
  });

  it('null db_id serialises as null (matches Rust Option::None)', () => {
    const r: RoundProfile = {
      kind: 'info',
      server_id: 0,
      db_id: null,
      request_bytes: 5,
      response_bytes: 23,
      items: [],
    };
    expect(JSON.stringify(r)).toBe(
      '{"kind":"info","server_id":0,"db_id":null,"request_bytes":5,"response_bytes":23,"items":[]}',
    );
  });
});
