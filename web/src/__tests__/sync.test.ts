import { describe, it, expect } from 'vitest';
import { computeSyncPlan } from '../sync.js';
import type { DatabaseCatalog, DatabaseCatalogEntry } from '../server-info.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Build a minimal catalog entry. */
function entry(opts: {
  dbId: number; dbType: 0 | 1; name: string;
  baseHeight: number; height: number;
}): DatabaseCatalogEntry {
  return {
    dbId: opts.dbId,
    dbType: opts.dbType,
    name: opts.name,
    baseHeight: opts.baseHeight,
    height: opts.height,
    indexBinsPerTable: 1024,
    chunkBinsPerTable: 2048,
    indexK: 75,
    chunkK: 80,
    tagSeed: 0n,
    dpfNIndex: 10,
    dpfNChunk: 11,
    hasBucketMerkle: false,
  };
}

function catalog(...entries: DatabaseCatalogEntry[]): DatabaseCatalog {
  return { databases: entries };
}

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('computeSyncPlan', () => {
  it('fresh sync picks the highest full database', () => {
    const cat = catalog(
      entry({ dbId: 0, dbType: 0, name: 'old', baseHeight: 0, height: 900000 }),
      entry({ dbId: 1, dbType: 0, name: 'main', baseHeight: 0, height: 940611 }),
    );

    const plan = computeSyncPlan(cat);
    expect(plan.isFreshSync).toBe(true);
    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0].dbId).toBe(1);
    expect(plan.steps[0].dbType).toBe('full');
    expect(plan.steps[0].tipHeight).toBe(940611);
    expect(plan.targetHeight).toBe(940611);
  });

  it('fresh sync with lastSyncedHeight=0', () => {
    const cat = catalog(
      entry({ dbId: 0, dbType: 0, name: 'main', baseHeight: 0, height: 940611 }),
    );

    const plan = computeSyncPlan(cat, 0);
    expect(plan.isFreshSync).toBe(true);
    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0].tipHeight).toBe(940611);
  });

  it('single delta incremental sync', () => {
    const cat = catalog(
      entry({ dbId: 0, dbType: 0, name: 'main', baseHeight: 0, height: 940611 }),
      entry({ dbId: 1, dbType: 1, name: 'delta1', baseHeight: 940611, height: 944000 }),
    );

    const plan = computeSyncPlan(cat, 940611);
    expect(plan.isFreshSync).toBe(false);
    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0].dbId).toBe(1);
    expect(plan.steps[0].dbType).toBe('delta');
    expect(plan.steps[0].baseHeight).toBe(940611);
    expect(plan.steps[0].tipHeight).toBe(944000);
    expect(plan.targetHeight).toBe(944000);
  });

  it('chain of 2 deltas', () => {
    const cat = catalog(
      entry({ dbId: 0, dbType: 0, name: 'main', baseHeight: 0, height: 940611 }),
      entry({ dbId: 1, dbType: 1, name: 'd1', baseHeight: 940611, height: 942000 }),
      entry({ dbId: 2, dbType: 1, name: 'd2', baseHeight: 942000, height: 944000 }),
    );

    const plan = computeSyncPlan(cat, 940611);
    expect(plan.isFreshSync).toBe(false);
    expect(plan.steps).toHaveLength(2);
    expect(plan.steps[0].name).toBe('d1');
    expect(plan.steps[0].tipHeight).toBe(942000);
    expect(plan.steps[1].name).toBe('d2');
    expect(plan.steps[1].tipHeight).toBe(944000);
    expect(plan.targetHeight).toBe(944000);
  });

  it('no matching delta chain falls back to full', () => {
    const cat = catalog(
      entry({ dbId: 0, dbType: 0, name: 'main', baseHeight: 0, height: 944000 }),
      entry({ dbId: 1, dbType: 1, name: 'd1', baseHeight: 940611, height: 942000 }),
      // Gap: no delta from 942000 to 944000 — chain is broken
    );

    const plan = computeSyncPlan(cat, 940611);
    expect(plan.isFreshSync).toBe(false);
    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0].dbType).toBe('full');
    expect(plan.steps[0].tipHeight).toBe(944000);
  });

  it('too many deltas (>5) falls back to full', () => {
    const entries: DatabaseCatalogEntry[] = [
      entry({ dbId: 0, dbType: 0, name: 'main', baseHeight: 0, height: 946000 }),
    ];
    // Create a chain of 6 deltas: 940000 -> 941000 -> ... -> 946000
    for (let i = 0; i < 6; i++) {
      entries.push(entry({
        dbId: i + 1,
        dbType: 1,
        name: `d${i}`,
        baseHeight: 940000 + i * 1000,
        height: 940000 + (i + 1) * 1000,
      }));
    }

    const plan = computeSyncPlan(catalog(...entries), 940000);
    // Should fall back to full because chain length (6) > MAX (5)
    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0].dbType).toBe('full');
  });

  it('already at tip returns empty plan', () => {
    const cat = catalog(
      entry({ dbId: 0, dbType: 0, name: 'main', baseHeight: 0, height: 940611 }),
    );

    const plan = computeSyncPlan(cat, 940611);
    expect(plan.isFreshSync).toBe(false);
    expect(plan.steps).toHaveLength(0);
    expect(plan.targetHeight).toBe(940611);
  });

  it('already past tip returns empty plan', () => {
    const cat = catalog(
      entry({ dbId: 0, dbType: 0, name: 'main', baseHeight: 0, height: 940611 }),
    );

    const plan = computeSyncPlan(cat, 950000);
    expect(plan.steps).toHaveLength(0);
  });

  it('throws on empty catalog', () => {
    expect(() => computeSyncPlan(catalog())).toThrow('Empty catalog');
  });

  it('throws on fresh sync with no full DB', () => {
    const cat = catalog(
      entry({ dbId: 0, dbType: 1, name: 'delta_only', baseHeight: 940611, height: 944000 }),
    );
    expect(() => computeSyncPlan(cat)).toThrow('No full checkpoint');
  });
});
