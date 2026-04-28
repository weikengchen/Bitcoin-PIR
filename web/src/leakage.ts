/**
 * Leakage profile capture — TypeScript port of `pir-sdk/src/leakage.rs`.
 *
 * The cross-language diff (Phase 2.3 of `PLAN_LEAKAGE_VERIFICATION.md`)
 * compares profiles emitted by the Rust `OnionClient` against profiles
 * emitted by the standalone TypeScript `OnionPirWebClient` (the only
 * client without a Rust-shared WASM core, since SEAL doesn't compile to
 * `wasm32-unknown-unknown`). Identical profiles for the same query
 * corpus = the two implementations leak the same shape on the wire.
 *
 * The JSON shape pinned by the Rust `leakage_profile_json_shape_is_pinned`
 * test is what this module produces / consumes:
 *
 * ```json
 * { "kind": "index", "server_id": 0, "db_id": 3, "request_bytes": 1024,
 *   "response_bytes": 4096, "items": [2, 2] }
 *
 * { "kind": "index_merkle_siblings", "level": 7, "server_id": 0,
 *   "db_id": 3, "request_bytes": 100, "response_bytes": 200, "items": [1] }
 *
 * { "kind": "info", "server_id": 0, "db_id": null, "request_bytes": 5,
 *   "response_bytes": 23, "items": [] }
 * ```
 *
 * If the Rust pin test changes, this file's `RoundKind` union and the
 * fixture in `onion_leakage.test.ts` must change with it.
 */

// ─── Round kind ─────────────────────────────────────────────────────────────

/**
 * Categorisation of one logical round in the PIR protocol. Matches the
 * Rust `RoundKind` enum, serialised with `#[serde(tag = "kind")]` and
 * `rename_all = "snake_case"`. Parametric variants
 * (`index_merkle_siblings`, `chunk_merkle_siblings`) carry a `level`
 * sibling key; non-parametric variants have no extra fields.
 */
export type RoundKind =
  | { kind: 'index' }
  | { kind: 'chunk' }
  | { kind: 'index_merkle_siblings'; level: number }
  | { kind: 'chunk_merkle_siblings'; level: number }
  | { kind: 'harmony_hint_refresh' }
  | { kind: 'onion_key_register' }
  | { kind: 'info' }
  | { kind: 'merkle_tree_tops' };

// ─── RoundProfile ───────────────────────────────────────────────────────────

/**
 * Wire-observable shape of a single (logical round × server) pair —
 * structural mirror of Rust's `RoundProfile`. Each pair of cross-language
 * profiles is compared field-by-field; if anything diverges, the
 * implementations leak different shapes for the same query.
 *
 * Note the field layout: `kind`, then any kind-specific keys (`level`),
 * then `server_id`, `db_id`, `request_bytes`, `response_bytes`, `items`.
 * The Rust serde `#[serde(flatten)]` on `RoundProfile.kind` produces
 * this exact key order; matching the order is purely cosmetic for
 * structural equality but useful when reading dumped JSON by eye.
 */
export interface RoundProfile {
  /** Round category. See [`RoundKind`]. */
  kind: RoundKind['kind'];
  /** Merkle level for `*_merkle_siblings`; absent otherwise. */
  level?: number;
  /**
   * Server identifier within the backend.
   * - Single-server backends (Onion): always 0.
   * - DPF: 0 = server0, 1 = server1.
   * - HarmonyPIR: 0 = query server, 1 = hint server.
   */
  server_id: number;
  /** Database identifier the round targets, or `null` for catalog-only rounds. */
  db_id: number | null;
  /** Wire-payload size of the request, in bytes (length-prefixed framing included). */
  request_bytes: number;
  /** Wire-payload size of the response, in bytes (length-prefixed framing included). */
  response_bytes: number;
  /**
   * Item counts at the round's natural granularity. Semantics depend on
   * `kind` — see the Rust doc on `pir_sdk::leakage::RoundProfile::items`.
   */
  items: number[];
}

// ─── LeakageProfile ─────────────────────────────────────────────────────────

/**
 * Ordered sequence of `RoundProfile`s — the wire transcript shape for
 * a complete query. Cross-language equivalence is decided by deep
 * equality of this object after JSON roundtrip.
 */
export interface LeakageProfile {
  /** Backend tag — `"dpf"`, `"harmony"`, or `"onion"`. */
  backend: string;
  /** Rounds in emission order. */
  rounds: RoundProfile[];
}

// ─── Recorder interface ─────────────────────────────────────────────────────

/**
 * Mirror of Rust's `LeakageRecorder` trait. Default implementations
 * are silent — installing none costs nothing. Tests install a
 * [`BufferingLeakageRecorder`] and inspect the captured rounds.
 */
export interface LeakageRecorder {
  /**
   * Fired once per (logical round × server) — i.e. per transport-level
   * roundtrip — with the round's wire-observable shape.
   *
   * `backend` is the same `"dpf" | "harmony" | "onion"` tag used on the
   * Rust side so a single test fixture can demultiplex.
   */
  recordRound(backend: string, round: RoundProfile): void;
}

// ─── BufferingLeakageRecorder ───────────────────────────────────────────────

/**
 * Recorder that buffers every emitted `RoundProfile` in memory.
 * Designed for tests: install one, run a query, call
 * [`takeProfile`](BufferingLeakageRecorder.takeProfile) (or
 * [`snapshot`](BufferingLeakageRecorder.snapshot)) to inspect.
 */
export class BufferingLeakageRecorder implements LeakageRecorder {
  private rounds: RoundProfile[] = [];

  recordRound(_backend: string, round: RoundProfile): void {
    this.rounds.push(round);
  }

  /** Shallow copy of the current buffer. The recorder retains state. */
  snapshot(): RoundProfile[] {
    return this.rounds.slice();
  }

  /**
   * Drain the buffer into a [`LeakageProfile`] tagged with the given
   * backend. After this call the recorder is empty — useful when
   * comparing per-query profiles across multiple queries through one
   * recorder.
   */
  takeProfile(backend: string): LeakageProfile {
    const rounds = this.rounds;
    this.rounds = [];
    return { backend, rounds };
  }

  /** Drop every buffered round without producing a profile. */
  clear(): void {
    this.rounds = [];
  }

  /** Number of rounds currently buffered. */
  get length(): number {
    return this.rounds.length;
  }

  /** True iff no rounds have been recorded since the last drain. */
  get isEmpty(): boolean {
    return this.rounds.length === 0;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * True if `items` has exactly `expectedLen` entries, all equal to
 * `expectedValue`. Mirror of Rust's `RoundProfile::items_uniform`.
 */
export function itemsUniform(
  round: RoundProfile,
  expectedLen: number,
  expectedValue: number,
): boolean {
  if (round.items.length !== expectedLen) return false;
  for (const v of round.items) {
    if (v !== expectedValue) return false;
  }
  return true;
}

/**
 * True if two rounds match on their `kind` discriminator, ignoring the
 * `level` for parametric variants. Mirror of
 * `RoundProfile::kind_matches`.
 */
export function kindMatches(round: RoundProfile, kind: RoundKind['kind']): boolean {
  return round.kind === kind;
}

/**
 * Filter a profile's rounds by `kind` (ignoring `level`). Mirror of
 * Rust's `LeakageProfile::rounds_of_kind`.
 */
export function roundsOfKind(
  profile: LeakageProfile,
  kind: RoundKind['kind'],
): RoundProfile[] {
  return profile.rounds.filter((r) => r.kind === kind);
}

/** Number of rounds matching the given `kind` (ignoring `level`). */
export function countOfKind(
  profile: LeakageProfile,
  kind: RoundKind['kind'],
): number {
  let n = 0;
  for (const r of profile.rounds) if (r.kind === kind) n += 1;
  return n;
}

// ─── Cross-language equality ────────────────────────────────────────────────

/**
 * Deep structural equality between two [`RoundProfile`]s. Used by the
 * cross-language diff harness — if this returns `false` the two
 * implementations diverge on a wire-observable axis. Field order is
 * not checked; only field values.
 */
export function roundProfilesEqual(a: RoundProfile, b: RoundProfile): boolean {
  if (a.kind !== b.kind) return false;
  // `level` is `undefined` on non-parametric variants; strict equality
  // handles undefined === undefined correctly.
  if (a.level !== b.level) return false;
  if (a.server_id !== b.server_id) return false;
  if (a.db_id !== b.db_id) return false;
  if (a.request_bytes !== b.request_bytes) return false;
  if (a.response_bytes !== b.response_bytes) return false;
  if (a.items.length !== b.items.length) return false;
  for (let i = 0; i < a.items.length; i++) {
    if (a.items[i] !== b.items[i]) return false;
  }
  return true;
}

/** Deep structural equality between two [`LeakageProfile`]s. */
export function leakageProfilesEqual(a: LeakageProfile, b: LeakageProfile): boolean {
  if (a.backend !== b.backend) return false;
  if (a.rounds.length !== b.rounds.length) return false;
  for (let i = 0; i < a.rounds.length; i++) {
    if (!roundProfilesEqual(a.rounds[i], b.rounds[i])) return false;
  }
  return true;
}
