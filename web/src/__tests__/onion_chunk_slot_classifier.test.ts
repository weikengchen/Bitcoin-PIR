/**
 * CHUNK Round-Presence Symmetry — TypeScript helper tests.
 *
 * Verifies the two pure helpers extracted from `OnionPirWebClient.queryBatch`:
 *
 * - `classifyChunkSlots` — per-slot classifier: for every input slot,
 *   returns either `append_real` (real entry_ids to fetch) or
 *   `append_dummy` (one dummy entry_id needed). No "skip" branch.
 *
 * - `selectChunkUniqueFetches` — wraps the classifier with the dedup
 *   loop the production `queryBatch` runs. Takes a deterministic
 *   dummy generator so tests can pin the expected behaviour without
 *   `crypto.getRandomValues` non-determinism.
 *
 * The properties tested below are the TypeScript analog of the Rust
 * Kani harnesses in `pir-sdk-client/src/onion.rs::kani_harnesses`:
 *
 *   P1 (round-count uniformity) — every slot contributes ≥1 entry_id
 *       to the unique-fetch list.
 *   P2 (no-skip)               — classifier output length equals input
 *       length; every entry is `append_real` xor `append_dummy`.
 *
 * Cross-language equivalence with the Rust client is enforced by
 * `onion_leakage_diff.test.ts` — same RoundProfile shape on the wire
 * requires same per-slot decisions here.
 */

import { describe, it, expect } from 'vitest';
import {
  classifyChunkSlots,
  selectChunkUniqueFetches,
  type ChunkSlotInput,
  type ChunkSlotAction,
} from '../onionpir_client.js';

// ─── classifyChunkSlots: P1 + P2 ───────────────────────────────────────────

describe('classifyChunkSlots: per-slot decision tree', () => {
  it('P1: result.length === slots.length for any input', () => {
    const cases: ChunkSlotInput[][] = [
      [],
      [{ entryId: 100, numEntries: 3 }],
      [
        { entryId: 0, numEntries: 0 },                     // not-found
        { entryId: 42, numEntries: 0 },                    // whale
        { entryId: 1234, numEntries: 1 },                  // small-found
        { entryId: 5000, numEntries: 17 },                 // generic-found
      ],
      [
        { entryId: 0, numEntries: 0 },
        { entryId: 0, numEntries: 0 },
        { entryId: 0, numEntries: 0 },
      ],
    ];
    for (const slots of cases) {
      expect(classifyChunkSlots(slots)).toHaveLength(slots.length);
    }
  });

  it('P2: action is append_real iff numEntries > 0; append_dummy iff === 0', () => {
    const slots: ChunkSlotInput[] = [
      { entryId: 0, numEntries: 0 },        // not-found sentinel → dummy
      { entryId: 7, numEntries: 0 },        // whale (entryId is irrelevant) → dummy
      { entryId: 99, numEntries: 1 },       // small-found → real
      { entryId: 200, numEntries: 250 },    // multi-found → real
    ];
    const actions = classifyChunkSlots(slots);
    expect(actions[0]).toEqual({ kind: 'append_dummy' });
    expect(actions[1]).toEqual({ kind: 'append_dummy' });
    expect(actions[2]).toEqual({ kind: 'append_real', entryId: 99, numEntries: 1 });
    expect(actions[3]).toEqual({ kind: 'append_real', entryId: 200, numEntries: 250 });
  });

  it('P2 corollary: AppendReal preserves entryId and numEntries faithfully', () => {
    // Hammer the field-preservation invariant across a wide range to
    // catch a hypothetical regression that truncates u32→u16 or
    // swaps the field order.
    for (let entryId = 0; entryId < 1_000_000; entryId += 50_001) {
      for (const numEntries of [1, 2, 7, 64, 200, 255]) {
        const [a] = classifyChunkSlots([{ entryId, numEntries }]);
        expect(a).toEqual({ kind: 'append_real', entryId, numEntries });
      }
    }
  });

  it('P2 corollary: numEntries === 0 produces dummy regardless of entryId', () => {
    for (const entryId of [0, 1, 1024, 0x7fff_ffff, 0xffff_ffff]) {
      const [a] = classifyChunkSlots([{ entryId, numEntries: 0 }]);
      expect(a).toEqual({ kind: 'append_dummy' });
    }
  });

  it('preserves slot order — actions[i] always corresponds to slots[i]', () => {
    const slots: ChunkSlotInput[] = [
      { entryId: 11, numEntries: 1 },
      { entryId: 0, numEntries: 0 },
      { entryId: 22, numEntries: 5 },
      { entryId: 33, numEntries: 0 },
      { entryId: 44, numEntries: 3 },
    ];
    const actions = classifyChunkSlots(slots);
    expect((actions[0] as { entryId: number }).entryId).toBe(11);
    expect(actions[1].kind).toBe('append_dummy');
    expect((actions[2] as { entryId: number }).entryId).toBe(22);
    expect(actions[3].kind).toBe('append_dummy');
    expect((actions[4] as { entryId: number }).entryId).toBe(44);
  });
});

// ─── selectChunkUniqueFetches: P1 lifts to wire-level fetch count ──────────

describe('selectChunkUniqueFetches: dedup-aware fetch list', () => {
  /** Deterministic dummy generator — yields a strictly increasing
   *  sequence starting at `start`. Used to pin the "no collisions"
   *  scenario where every dummy ends up in the unique list. */
  function freshDummies(start: number): () => number {
    let n = start;
    return () => n++;
  }

  it('all-not-found batch: unique.length === slots.length', () => {
    const slots: ChunkSlotInput[] = Array(8).fill({ entryId: 0, numEntries: 0 });
    const dummies = freshDummies(1000);
    const { unique, dummiesAdded } = selectChunkUniqueFetches(slots, dummies);
    expect(unique).toHaveLength(8);
    expect(dummiesAdded).toBe(8);
    // Every entry is a fresh dummy from the generator.
    expect(unique).toEqual([1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007]);
  });

  it('all-whale batch (numEntries === 0, entryId !== 0): unique.length === slots.length', () => {
    const slots: ChunkSlotInput[] = [
      { entryId: 100, numEntries: 0 },
      { entryId: 200, numEntries: 0 },
      { entryId: 300, numEntries: 0 },
    ];
    const dummies = freshDummies(7000);
    const { unique, dummiesAdded } = selectChunkUniqueFetches(slots, dummies);
    expect(unique).toHaveLength(3);
    expect(dummiesAdded).toBe(3);
    // Whale `entryId`s are NOT used — dummies replace them entirely.
    expect(unique).toEqual([7000, 7001, 7002]);
  });

  it('mixed batch: real fetches first, then dummies', () => {
    const slots: ChunkSlotInput[] = [
      { entryId: 50, numEntries: 2 },                 // real (50, 51)
      { entryId: 0, numEntries: 0 },                  // dummy
      { entryId: 100, numEntries: 1 },                // real (100)
      { entryId: 0, numEntries: 0 },                  // dummy
    ];
    const dummies = freshDummies(9000);
    const { unique, dummiesAdded } = selectChunkUniqueFetches(slots, dummies);
    expect(unique).toEqual([50, 51, 9000, 100, 9001]);
    expect(dummiesAdded).toBe(2);
  });

  it('dedup: real entries that overlap collapse into a single unique entry', () => {
    const slots: ChunkSlotInput[] = [
      { entryId: 7, numEntries: 3 },                  // 7, 8, 9
      { entryId: 8, numEntries: 2 },                  // 8 dedup, 9 dedup → only adds nothing new... wait, 8 and 9 already in
    ];
    const dummies = freshDummies(0); // not exercised on real path
    const { unique } = selectChunkUniqueFetches(slots, dummies);
    expect(unique).toEqual([7, 8, 9]);
  });

  it('dedup: dummy that collides with a real entry retries until fresh', () => {
    const slots: ChunkSlotInput[] = [
      { entryId: 100, numEntries: 1 }, // real → 100
      { entryId: 0, numEntries: 0 },   // dummy: generator hits 100, then 101
    ];
    const collidingDummies = (() => {
      const seq = [100, 101]; // 100 collides with the real entry
      let i = 0;
      return () => seq[Math.min(i++, seq.length - 1)];
    })();
    const { unique, dummiesAdded } = selectChunkUniqueFetches(slots, collidingDummies);
    expect(unique).toEqual([100, 101]);
    expect(dummiesAdded).toBe(1);
  });

  it('P1: empty batch → empty fetch list (the only way to get a length-0 result)', () => {
    const { unique, dummiesAdded } = selectChunkUniqueFetches([], freshDummies(0));
    expect(unique).toHaveLength(0);
    expect(dummiesAdded).toBe(0);
  });

  it('round-count uniformity: not-found and small-found batches of equal size produce equal-size fetch lists', () => {
    const N = 5;
    const allNotFound: ChunkSlotInput[] = Array(N).fill({ entryId: 0, numEntries: 0 });
    const allFound: ChunkSlotInput[] = Array(N).fill(0).map((_, i) => ({
      entryId: 1000 + i, numEntries: 1,
    }));

    const nfFetches = selectChunkUniqueFetches(allNotFound, freshDummies(20_000)).unique;
    const fFetches = selectChunkUniqueFetches(allFound, freshDummies(20_000)).unique;

    // The structural witness for CHUNK Round-Presence Symmetry P1:
    // not-found and found batches of the same size produce equal-size
    // unique-fetch lists, so the CHUNK PIR round count on the wire is
    // proportional to batch size, not to how many queries matched.
    expect(nfFetches.length).toBe(fFetches.length);
    expect(nfFetches.length).toBe(N);
  });

  it('regression guard: pre-fix behaviour (skip on numEntries === 0) is rejected', () => {
    // The bug being closed: pre-fix, not-found / whale slots
    // produced no unique entries. Two batches of equal size would
    // therefore produce *different* unique-list lengths if one had
    // matches and the other didn't — a binary side channel.
    //
    // This test pins the post-fix invariant: a not-found batch and a
    // small-found batch of equal size must produce equal-length
    // unique lists. If `selectChunkUniqueFetches` ever regresses to
    // skipping not-found slots, this test fires.
    const N = 4;
    const notFound = Array(N).fill({ entryId: 0, numEntries: 0 });
    const found = Array(N).fill(0).map((_, i) => ({ entryId: 50 + i, numEntries: 1 }));
    const a = selectChunkUniqueFetches(notFound, freshDummies(60_000));
    const b = selectChunkUniqueFetches(found, freshDummies(70_000));
    expect(a.unique.length).toBe(b.unique.length);
    // Pre-fix this would have been `a.unique.length === 0` and
    // `b.unique.length === N` — the leak.
    expect(a.unique.length).toBe(N);
  });
});
