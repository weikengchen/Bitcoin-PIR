/**
 * Generic multi-database sync orchestration shared across all three PIR
 * backends (DPF, OnionPIR, HarmonyPIR).
 *
 * Owns:
 *   - The in-memory snapshot cache keyed by scripthash hex
 *   - lastSyncedHeight persistence in localStorage (per-backend namespace)
 *   - Plan computation, with a page-refresh safety rule
 *   - Plan execution loop (full vs delta step, merge)
 *   - Reset logic
 *
 * Backend-agnostic: takes callbacks for the actual per-step query and per-step
 * merge. The caller provides the client-specific bits; this module owns the
 * orchestration so all three tabs share a single, audited flow.
 *
 * No DOM access — all UI updates happen via progress/error callbacks provided
 * by the caller.
 */
import { computeSyncPlan, type SyncPlan, type SyncStep } from './sync.js';
import { bytesToHex } from './hash.js';
import type { DatabaseCatalog } from './server-info.js';

// ─── Types ───────────────────────────────────────────────────────────────────

/**
 * Minimal interface a backend's per-query result must satisfy to flow through
 * the sync controller. The controller does not inspect the fields itself —
 * the caller-supplied `mergeStep` does — but this type exists to keep the
 * generic parameter constrained and document the contract.
 */
export interface SyncableResult {
  rawChunkData?: Uint8Array;
  isWhale?: boolean;
}

export interface SyncExecuteHooks<T extends SyncableResult> {
  /** Script hashes queried by this sync run, in the same order as the caller's view. */
  scriptHashes: Uint8Array[];
  /** Run one step of the plan against the backend and return per-scripthash results. */
  queryStep: (step: SyncStep, stepIdx: number) => Promise<(T | null)[]>;
  /** Merge a delta step's result onto the current snapshot for one scripthash. */
  mergeStep: (snapshot: T | null, delta: T | null) => T | null;
  /** Optional hook run before each step (e.g. HarmonyPIR hint switch / re-download). */
  beforeStep?: (step: SyncStep, stepIdx: number) => Promise<void>;
  /** Progress callback. `pct` is 0–100 for the whole sync, `detail` is free-form. */
  onStepProgress?: (stepIdx: number, label: string, pct: number, detail: string) => void;
  /** Error logging callback (non-fatal messages from merge, etc). */
  onError?: (msg: string) => void;
}

export interface SyncExecuteOutput<T extends SyncableResult> {
  /** Final merged snapshot per scripthash, after all plan steps. */
  merged: (T | null)[];
  /**
   * Per-step results as returned by `queryStep`, in plan order. Callers use
   * these (not the merged view) for per-step Merkle verification because
   * Merkle verifies the bin content of the specific DB each step ran against.
   */
  verifiableSteps: { step: SyncStep; stepResults: (T | null)[] }[];
  /** Height the client is at after this sync run. */
  targetHeight: number;
}

// ─── Controller ──────────────────────────────────────────────────────────────

export interface SyncControllerConfig {
  /**
   * Closure returning the localStorage key for this backend's sync state.
   * Evaluated on every load/save so server URL changes produce new namespaces.
   * Example: () => `bitcoinpir.dpf.lastSync:${s0}|${s1}`.
   */
  storageKey: () => string;
}

/**
 * Backend-generic sync orchestrator. One instance per tab.
 *
 * Instances are cheap; create one per tab and reuse across sync runs. State is
 * purely in-memory + localStorage.
 */
export class SyncController<T extends SyncableResult> {
  private cache = new Map<string, T>();
  private readonly storageKey: () => string;

  constructor(config: SyncControllerConfig) {
    this.storageKey = config.storageKey;
  }

  // ── Persistence (localStorage) ─────────────────────────────────────────

  loadLastSyncedHeight(): number {
    try {
      const raw = localStorage.getItem(this.storageKey());
      if (!raw) return 0;
      const n = parseInt(raw, 10);
      return Number.isFinite(n) && n > 0 ? n : 0;
    } catch {
      return 0;
    }
  }

  saveLastSyncedHeight(height: number): void {
    try {
      localStorage.setItem(this.storageKey(), String(height));
    } catch {
      /* ignore quota errors */
    }
  }

  clearLastSyncedHeight(): void {
    try {
      localStorage.removeItem(this.storageKey());
    } catch {
      /* ignore */
    }
  }

  // ── Snapshot cache ─────────────────────────────────────────────────────

  hasSnapshotFor(scriptHash: Uint8Array): boolean {
    return this.cache.has(bytesToHex(scriptHash));
  }

  getSnapshot(scriptHash: Uint8Array): T | undefined {
    return this.cache.get(bytesToHex(scriptHash));
  }

  // ── Plan computation ───────────────────────────────────────────────────

  /**
   * Compute the sync plan for the given scripthashes, applying a page-refresh
   * safety rule: if `lastSyncedHeight > 0` but the in-memory cache does not
   * contain snapshots for every scripthash being synced, treat this as a fresh
   * sync. This prevents a delta-only plan from silently merging onto `null`
   * after a page reload (the cache is in-memory only).
   */
  computePlan(catalog: DatabaseCatalog, scriptHashes: Uint8Array[]): SyncPlan {
    const persisted = this.loadLastSyncedHeight();
    const cacheComplete =
      scriptHashes.length > 0 &&
      scriptHashes.every(sh => this.cache.has(bytesToHex(sh)));
    const effective = persisted > 0 && !cacheComplete ? 0 : persisted;
    return computeSyncPlan(catalog, effective || undefined);
  }

  // ── Execution ──────────────────────────────────────────────────────────

  /**
   * Execute a plan's steps sequentially, merging deltas onto the cached
   * snapshot. On full success, commits the merged results to the cache and
   * persists the new height. On failure, throws without updating state.
   */
  async execute(
    plan: SyncPlan,
    hooks: SyncExecuteHooks<T>,
  ): Promise<SyncExecuteOutput<T>> {
    const N = hooks.scriptHashes.length;
    // Seed merged state from the in-memory cache so a delta-only plan in the
    // same session can apply on top of a previous full sync.
    const merged: (T | null)[] = hooks.scriptHashes.map(
      sh => this.cache.get(bytesToHex(sh)) ?? null,
    );
    const verifiableSteps: SyncExecuteOutput<T>['verifiableSteps'] = [];

    for (let si = 0; si < plan.steps.length; si++) {
      const step = plan.steps[si];
      const label = describeStep(step, si + 1, plan.steps.length);
      hooks.onStepProgress?.(si, label, 5, 'starting');

      if (hooks.beforeStep) {
        await hooks.beforeStep(step, si);
      }

      const stepResults = await hooks.queryStep(step, si);

      if (step.dbType === 'full') {
        // Full snapshot replaces merged state entirely.
        for (let qi = 0; qi < N; qi++) merged[qi] = stepResults[qi];
      } else {
        // Delta step: merge onto each per-query snapshot.
        for (let qi = 0; qi < N; qi++) {
          merged[qi] = hooks.mergeStep(merged[qi], stepResults[qi]);
        }
      }

      verifiableSteps.push({ step, stepResults });
    }

    // Commit to cache + persisted height only on full success.
    for (let qi = 0; qi < N; qi++) {
      const r = merged[qi];
      if (r) this.cache.set(bytesToHex(hooks.scriptHashes[qi]), r);
    }
    this.saveLastSyncedHeight(plan.targetHeight);

    return { merged, verifiableSteps, targetHeight: plan.targetHeight };
  }

  // ── Reset ──────────────────────────────────────────────────────────────

  /** Clear in-memory snapshot cache AND persisted last-synced height. */
  reset(): void {
    this.cache.clear();
    this.clearLastSyncedHeight();
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Human-readable description of one sync step. Mirrors the `describeStep`
 * helper previously inlined in `web/index.html` so all tabs show identical
 * plan text.
 */
export function describeStep(s: SyncStep, idx?: number, total?: number): string {
  const prefix = idx !== undefined && total !== undefined
    ? `Step ${idx}/${total}: `
    : '';
  if (s.dbType === 'full') {
    return `${prefix}[full ${s.name} @ ${s.tipHeight.toLocaleString()}]`;
  }
  return `${prefix}[delta ${s.name}: ${s.baseHeight.toLocaleString()} \u2192 ${s.tipHeight.toLocaleString()}]`;
}
