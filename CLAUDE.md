# BitcoinPIR Project Memory

## Project Overview
Bitcoin Private Information Retrieval (PIR) system with three backends: DPF-PIR, OnionPIR, HarmonyPIR. Supports full snapshots and delta synchronization for incremental updates.

---

## CRITICAL SECURITY REQUIREMENTS

### Query Padding (MANDATORY for Privacy)

**NEVER OPTIMIZE AWAY PADDING. The padding is INTENTIONAL and REQUIRED for privacy.**

Within each PIR round, queries are padded to FIXED counts:
- **INDEX queries**: Always K=75 groups (regardless of how many real queries)
- **CHUNK queries**: Always K_CHUNK=80 groups (regardless of how many real chunks)
- **MERKLE queries**: Always 25 sibling queries (regardless of proof depth)

**Why:** If the server sees varying numbers of queries, it can infer information about which groups contain real queries vs padding. By always sending exactly K queries, the server cannot distinguish real queries from dummy queries.

**How padding works:**
1. Real queries are placed in their computed cuckoo positions
2. Remaining empty groups get random DPF keys (dummy queries)
3. Server processes ALL groups identically, cannot tell which are real

### Cuckoo Hashing and "Not Found" Verification

Each scripthash maps to INDEX_CUCKOO_NUM_HASHES=2 possible cuckoo positions. To prove a scripthash is "not found", ALL positions must be checked and verified:
- Client checks position h=0, then h=1
- If neither contains the scripthash, it's definitively not in the database
- Merkle verification must cover ALL checked bins to prove "not found"

### Merkle INDEX Item-Count Symmetry (MANDATORY for Privacy)

**All five clients (TS DPF/Onion/Harmony, Rust DPF/Harmony) MUST emit exactly
`INDEX_CUCKOO_NUM_HASHES = 2` Merkle items per INDEX query, regardless of
query outcome (found at h=0, found at h=1, not-found, or whale).**

The per-level sibling **pass count** (`max_items_per_group`) is directly
observable on the wire. If a found query emits 1 INDEX Merkle item and a
not-found query emits 2, the server can infer found-vs-not-found from
the batched sibling request size for every INDEX Merkle level. That
defeats the "chunk rounds reveal found/not-found" trade-off at the INDEX
level and leaks cuckoo-position (h=0 vs h=1) as well.

**Invariants clients must preserve:**
1. Both cuckoo positions are probed for every INDEX query — no early exit
   on match. (In DPF and Onion the extra probe is tracking-only since
   both bins are XOR'd from the same batch response; in Harmony it costs
   one extra wire round per found@h=0 query.)
2. The Merkle item builder iterates the full `all_index_bins` list
   unconditionally, emitting one `BucketMerkleItem` per probed bin.
3. Whales emit INDEX Merkle items from their probed bins too — the
   whale's INDEX entry (`num_chunks=0`) is committed to the INDEX Merkle
   root, so whale-exclusion is a verifiable property.
4. Chunk-level Merkle items attach only to the matched INDEX bin.
   CHUNK Merkle item counts still vary with UTXO count — that is a
   separate, documented trade-off (see "What the Server Learns" below).

### What the Server Learns (Documented Trade-offs)

The server **cannot** learn:
- Which specific groups contain real queries (due to padding)
- Which specific scripthash was queried
- Whether a query was found or not-found at the INDEX Merkle level
  (closed by the item-count symmetry invariant above)
- Which cuckoo position (h=0 vs h=1) a found query matched at

The server **can** observe (known trade-offs):
- Whether CHUNK rounds occur (reveals found vs not-found for non-whale
  queries — chunk rounds are skipped entirely when no INDEX match)
- Whether CHUNK Merkle rounds occur, and how many CHUNK Merkle items
  (reveals approximate UTXO count for found queries)
- Timing patterns across rounds

To fully hide found/not-found, the client would need to send dummy chunk
and chunk-Merkle rounds even when no results were found. This is a
documented privacy/efficiency trade-off that is distinct from — and
strictly weaker than — the INDEX-Merkle leak closed above.

---

## Recent Work: PIR SDK Implementation

### Completed
1. **pir-sdk/** - Core SDK crate with:
   - Database catalog types and sync planning (BFS delta chain, max 5 steps)
   - Delta merging logic
   - Hash function wrappers (splitmix64, cuckooHash, etc.)

2. **pir-sdk-wasm/** - WASM bindings for browser use:
   - `WasmDatabaseCatalog`, `WasmSyncPlan`, `WasmQueryResult` classes
   - `computeSyncPlan()`, `mergeDelta()`, `decodeDeltaData()` functions
   - Hash functions exposed to JS
   - Built with `wasm-pack build --target web`

3. **pir-sdk-client/** - Native Rust client. All three backends are fully
   implemented:
   - `DpfClient` — per-bucket Merkle verification via `merkle_verify.rs`
     (see item 8 below).
   - `HarmonyClient` — per-bucket Merkle verification via the shared
     `BucketMerkleSiblingQuerier` trait (see item 8 below).
   - `OnionClient` — per-bin Merkle verification via a separate module
     `onion_merkle.rs` (INDEX + DATA flat trees, FHE sibling queries;
     see item 10 below). Feature-gated behind `onion`.

4. **pir-sdk-server/** - Server-side SDK placeholder

5. **Web SDK Integration**:
   - `web/src/sdk-bridge.ts` - Bridge with automatic fallback to TypeScript
   - `web/src/sync-controller.ts` - Now uses `computeSyncPlanSdk` from SDK
   - `web/index.html` - Calls `initSdkWasm()` at startup
   - `web/package.json` - Added `pir-sdk-wasm` dependency

6. **Merkle Verification for "Not Found" Results** (web TS clients, commit `60fe19c`):
   - All three **web TypeScript** PIR clients (DPF, OnionPIR, HarmonyPIR)
     track ALL bins checked.
   - For "not found", verifies ALL INDEX_CUCKOO_NUM_HASHES=2 positions.
   - Proves scripthash is truly absent from the database.
   - Enables Merkle verification of delta databases even when no activity.

7. **Human-Verifiable Audit Logging** (commit `9a693c5`):
   - `[PIR-AUDIT]` prefixed logs in web TS clients (DPF, OnionPIR, HarmonyPIR)
     and in the native Rust `DpfClient` (see item 8).
   - Logs show: query parameters, padding reminders, per-query FOUND/NOT FOUND
     status, bin indices, chunk IDs, Merkle verification details.
   - Enables humans to verify PIR operations are correct.

8. **Native Rust per-bucket Merkle verification (DPF + Harmony)**:
   - Module [`pir-sdk-client/src/merkle_verify.rs`](pir-sdk-client/src/merkle_verify.rs)
     implements the shared verifier: bin-leaf hash, K-padded sibling batches,
     tree-top parsing, full walk-to-root. 12 unit tests cover good proofs,
     tampered content, wrong bin index, encoding/decoding round-trips, and
     partial-cache walks against `pir-core::merkle`.
   - Backend-agnostic driver: a `BucketMerkleSiblingQuerier` trait abstracts
     one K-padded sibling-query round, with `DpfSiblingQuerier`
     (two-server DPF, `REQ_BUCKET_MERKLE_SIB_BATCH = 0x33`) and
     `HarmonySiblingQuerier` (single-server Harmony query,
     `REQ_HARMONY_BATCH_QUERY = 0x43` with `level = 10+L` INDEX or `20+L`
     CHUNK) both implementing it. `verify_bucket_merkle_batch_generic`
     drives the shared walk.
   - [`DpfClient`](pir-sdk-client/src/dpf.rs) and
     [`HarmonyClient`](pir-sdk-client/src/harmony.rs) now track every INDEX
     cuckoo bin they inspect (both `INDEX_CUCKOO_NUM_HASHES=2` positions for
     not-found, the matching position for found) and every CHUNK bin that
     returned a UTXO, then batch-verify them against the per-group root
     from the tree-top blob. Queries whose Merkle proof fails are coerced
     to `None`.
   - HarmonyPIR sibling groups and hints are lazily initialised per
     `(db_id, merkle_level)` — sibling-group count is derived from the
     server-supplied tree-tops (`cache_from_level`), and the sibling
     group's `derived_key` offset matches the server's
     `compute_hints_for_group` layout:
     * INDEX sib L, group g → `(k_index + k_chunk) + L*k_index + g`
     * CHUNK sib L, group g →
       `(k_index + k_chunk) + index_sib_levels*k_index + L*k_chunk + g`
   - Gated on `DatabaseInfo::has_bucket_merkle`. Padding (K=75 INDEX,
     K_CHUNK=80 CHUNK, 25 MERKLE) is preserved — see CLAUDE.md "Query Padding"
     section above.
   - Whales **are** Merkle-verified on their INDEX bin (so the client can
     prove the address really is whale-excluded). Whales have no chunk
     chain, so chunk-level Merkle info is empty by construction.
   - `OnionClient` Merkle verification is wired via a **separate**
     module [`pir-sdk-client/src/onion_merkle.rs`](pir-sdk-client/src/onion_merkle.rs)
     — see item 10 below. (OnionPIR uses its own two flat trees +
     FHE sibling queries, so the per-bucket `merkle_verify.rs` machinery
     doesn't apply.)

10. **Native Rust OnionPIR per-bin Merkle verification**:
    - Module [`pir-sdk-client/src/onion_merkle.rs`](pir-sdk-client/src/onion_merkle.rs)
      implements the OnionPIR Merkle subsystem, which is **distinct**
      from per-bucket Merkle:
      * Two flat trees (INDEX + DATA), not per-PBC-bucket trees.
      * Leaf hash: `SHA256(decrypted_bin_bytes)` (no bin-index prefix).
      * Sibling cuckoo: 6 hash functions, 1 slot per bin, per-level
        master seed `SEED_BASE + level`
        (`INDEX_SIBLING_SEED_BASE = 0xBA7C_51B1_FEED_0100`,
         `DATA_SIBLING_SEED_BASE  = 0xBA7C_51B1_FEED_0200`).
      * Sibling queries are FHE-encrypted: `0x53` INDEX, `0x55` DATA.
        Tree-top fetches: `0x54` INDEX, `0x56` DATA.
    - `OnionClient::query_index_level` now tracks every probed INDEX
      cuckoo bin (both `INDEX_CUCKOO_NUM_HASHES = 2` positions, matched
      or not, whale or found, see invariant #9) and emits a
      `(pbc_group * index_bins + bin, SHA256(bin))` trace per bin.
    - `OnionClient::query_chunk_level` emits a DATA trace per decrypted
      entry_id: `(pbc_group * chunk_bins + bin, SHA256(packed))`.
    - `run_merkle_verification` aggregates traces into
      `Vec<OnionMerkleLeaf>`, calls `verify_onion_merkle_batch`, and
      coerces failed queries to `None` (same "untrusted ⇒ absent"
      pattern as DpfClient/HarmonyClient). A local `SibSendClient`
      newtype makes `onionpir::Client` `Send` across `.await` for the
      sibling roundtrips.
    - Gated behind the `onion` cargo feature (same as `OnionClient`'s
      query path). Padding is preserved (K per sibling round, dummy
      FHE queries fill empty groups).
    - JSON parsing: `parse_onion_merkle_per_db` handles top-level
      `onionpir_merkle` (db_id=0) and per-entry `onionpir_merkle` inside
      `databases[]` — symmetric with `parse_onion_params_per_db`. The
      subtree parser tolerates whitespace after `"root":` and
      `"levels":` so pretty-printed JSON works.
    - 46 unit tests cover tree-top parsing, sibling cuckoo
      (INDEX + DATA, 6-hash roundtrip), seed-base invariants, wire
      encoder/decoder, and JSON parse shapes.

9. **Merkle INDEX item-count symmetry (all five clients)**:
   - All five clients — TS DPF (`web/src/client.ts`), TS OnionPIR
     (`web/src/onionpir_client.ts`), TS HarmonyPIR
     (`web/src/harmonypir_client.ts`), Rust DPF
     (`pir-sdk-client/src/dpf.rs`), Rust Harmony
     (`pir-sdk-client/src/harmony.rs`) — now probe BOTH cuckoo positions
     unconditionally and emit `INDEX_CUCKOO_NUM_HASHES = 2` Merkle items
     per INDEX query regardless of outcome.
   - Closes the side channel where `max_items_per_group` (per-level
     sibling pass count) leaked found-vs-not-found and cuckoo h-position.
   - Costs: DPF and Onion free (both bins already XOR'd from the same
     batch response). Rust Harmony adds one wire round per found@h=0
     query. TS Onion adds one FHE decrypt (~100ms) per found@h=0 query.
   - Whales participate in INDEX Merkle verification via a new
     `whaleIndexInfo`/trace bin-info path in each client.
   - CHUNK Merkle item count still varies with UTXO count — documented
     trade-off, separate from INDEX symmetry. See "Merkle INDEX
     Item-Count Symmetry" under CRITICAL SECURITY REQUIREMENTS.

---

## SDK Roadmap

The full SDK work plan lives in [SDK_ROADMAP.md](SDK_ROADMAP.md) — P0
through P4 priorities, with in-progress items tracked at the bottom.
Consult it before starting new SDK work so nothing gets duplicated or
forgotten. Padding/privacy invariants (🔒 items in the roadmap) must
not be optimized away — see "Query Padding" above.

Short-term active work:
- **TS retirement plan is complete.** All six sessions have landed —
  see "TS retirement Session 6 — Harmony web-side cutover" in
  Completed milestones below for the final landing note. The web
  client's DPF and Harmony halves now run through thin adapter
  shims over `WasmDpfClient` / `WasmHarmonyClient`; ~1880 LOC of
  hand-rolled Harmony TS was retired in Session 6 (on top of the
  ~1300 LOC retired across Sessions 1-3). `web/src/onionpir_client.ts`
  stays indefinitely — the upstream `onionpir` crate requires C++
  SEAL which doesn't compile to wasm32, so there's no
  `WasmOnionClient` to replace it.

- **Error taxonomy refinement is complete.** `PirError` now exposes
  a categorical `ErrorKind` classifier (`TransientNetwork` /
  `SessionEvicted` / `ProtocolSkew` / `MerkleVerificationFailed` /
  `ServerError` / `ClientError` / `DataError` / `Other`) plus four
  new variants (`Transient { origin, context }`, `ProtocolSkew {
  expected, actual }`, `SessionEvicted(String)`,
  `MerkleVerificationFailed(String)`) and four new retry/inspection
  helpers (`is_transient_network`, `is_session_lost`,
  `is_verification_failure`, `is_protocol_skew`). Three concrete
  call-site migrations landed: OnionPIR's retry-exhausted eviction
  now raises `SessionEvicted` instead of `ServerError`;
  `merkle_verify::decode_sibling_batch` now raises
  `MerkleVerificationFailed` on mid-round `RESP_ERROR`; and
  `fetch_tree_tops` + the tree-top count check now raise
  `ProtocolSkew` when the catalog and server disagree on
  `has_bucket_merkle` or K_INDEX+K_CHUNK. See the "Error taxonomy
  refinement" entry in Completed milestones below for the full
  breakdown.

- **Observability Phase 1 is complete.** `tracing` is now an
  additive dep of `pir-sdk-client` (with the `log` feature so the
  existing `[PIR-AUDIT]` `log::info!` trail continues to flow
  through any installed subscriber). `DpfClient`, `HarmonyClient`,
  `OnionClient`, and `WsConnection` public methods carry
  `#[tracing::instrument]` spans with a consistent `backend =
  "dpf"/"harmony"/"onion"` field, level tiers (`info` for top-level
  ops, `debug` for sub-ops, `trace` for per-query inner loops), and
  `skip_all` to keep binary payloads / secrets out of spans. A
  smoke test per client captures the formatted span output through
  a `MakeWriter` buffer so an accidental `#[tracing::instrument]`
  removal or `backend` field rename fails at test time. See the
  "Native Rust tracing instrumentation (P2 observability Phase 1)"
  entry in Completed milestones below for the full breakdown.

- **Observability Phase 2 is complete.** `pir-sdk` now ships a
  `PirMetrics` observer trait with six defaulted callbacks
  (`on_query_start` / `on_query_end` / `on_bytes_sent` /
  `on_bytes_received` / `on_connect` / `on_disconnect`) plus two
  concrete recorders (`NoopMetrics`, `AtomicMetrics` with lock-free
  `AtomicU64` counters + a `Copy` `Snapshot`). `PirTransport` gained
  `set_metrics_recorder(recorder, backend)` with a default no-op
  body; `WsConnection`, `MockTransport`, and `WasmWebSocketTransport`
  override to fire per-frame byte callbacks (`send` counts after
  confirmed-OK result, `recv` counts full raw frame including
  length prefix). `DpfClient`, `HarmonyClient`, `OnionClient` each
  expose a client-layer `set_metrics_recorder` that stores the
  handle, propagates it to every owned transport (DPF: 2, Harmony:
  2, Onion: 1) with the matching `&'static str` backend label, and
  fires `on_connect` per-transport + `on_disconnect` once per
  client + `on_query_start` / `on_query_end` around `query_batch`.
  Pre-connect and post-connect installation both work. See the
  "Native Rust metrics observer (P2 observability Phase 2)" entry
  in Completed milestones below for the full breakdown.

- **Observability Phase 2+ `WasmAtomicMetrics` bridge is
  complete.** `pir-sdk-wasm` now ships a `#[wasm_bindgen]`
  `WasmAtomicMetrics` class wrapping `Arc<pir_sdk::AtomicMetrics>`
  (lock-free atomic counters shared with any client that holds
  an `Arc` clone). JS surface: `new()`, `snapshot()` returning
  a plain object with nine `bigint` fields (`queriesStarted` /
  `queriesCompleted` / `queryErrors` / `bytesSent` /
  `bytesReceived` / `framesSent` / `framesReceived` / `connects`
  / `disconnects`). `WasmDpfClient` and `WasmHarmonyClient` each
  picked up `setMetricsRecorder(metrics) / clearMetricsRecorder()`
  — the native client then propagates the handle to every owned
  transport (DPF: 2, Harmony: 2) with the matching
  `&'static str` backend label, so all pre-existing Phase 2
  byte / frame / connect / disconnect / query-lifecycle
  callbacks start firing on the shared counters. Pre-connect
  and post-connect install both work. `web/src/sdk-bridge.ts`
  exposes `sdkCreateAtomicMetrics()` helper + typed
  `WasmAtomicMetrics` / `AtomicMetricsSnapshot` interfaces with
  `setMetricsRecorder` / `clearMetricsRecorder` typed on both
  client interfaces. See the "Native Rust `WasmAtomicMetrics`
  bridge (P2 observability Phase 2+ tail, first item)" entry
  in Completed milestones below for the full breakdown.

- **Observability Phase 2+ `tracing-wasm` subscriber is
  complete.** `pir-sdk-wasm` now ships a new `tracing_bridge`
  module with a `#[wasm_bindgen]` `initTracingSubscriber()`
  function that installs `tracing-wasm::set_as_global_default`
  as the browser's global `tracing` subscriber. Guarded by
  `std::sync::Once` so repeat calls from multiple init paths
  are no-ops (without the guard, `tracing-wasm` panics on the
  second call because `tracing` allows one global subscriber
  per process). All Phase 1 `#[tracing::instrument]` spans on
  `DpfClient` / `HarmonyClient` / `OnionClient` / `WsConnection`
  / `WasmWebSocketTransport` now surface in the browser DevTools
  console with the consistent `backend="dpf"/"harmony"/"onion"`
  field. `web/src/sdk-bridge.ts` exposes an `initSdkTracing()`
  helper that follows the `sdkCreateAtomicMetrics()` pattern —
  throws if `initSdkWasm()` hasn't resolved. Bundle cost:
  +35 kB uncompressed / +14 kB gzipped for the
  `tracing-subscriber` + `tracing-wasm` + `sharded-slab`
  transitive deps. See the "Native Rust `tracing-wasm`
  subscriber bridge (P2 observability Phase 2+ tail, second
  item)" entry in Completed milestones below for the full
  breakdown.

- **Observability Phase 2+ per-client latency histograms is
  complete.** `pir-sdk` now depends on `web-time = "1.1"`
  (drop-in `Instant` / `Duration` replacement that uses
  `performance.now()` on `wasm32-unknown-unknown` and
  `std::time` on native), re-exporting `Instant` / `Duration`
  from the crate root alongside `PirMetrics` / `AtomicMetrics`.
  `PirMetrics::on_query_end` gained a sixth parameter
  `duration: Duration`; `AtomicMetrics` gained three new
  lock-free `AtomicU64` counters (`total_query_latency_micros`
  / `min_query_latency_micros` / `max_query_latency_micros`)
  with `min` initialised to a `MIN_LATENCY_SENTINEL =
  u64::MAX` so `fetch_min(observed)` always wins on the first
  measurement (no first-value-special-cased CAS loop needed).
  The three native clients (`DpfClient`, `HarmonyClient`,
  `OnionClient`) all switched their `fire_query_start` /
  `fire_query_end` helpers to an `Option<Instant>`-threading
  pattern: `fire_query_start` returns `Some(Instant::now())`
  only when a recorder is installed (zero overhead — and zero
  `performance.now()` JS↔WASM boundary calls — when none is),
  `fire_query_end` consumes the `Option<Instant>` and surfaces
  `t.elapsed()` (or `Duration::ZERO` if the recorder was
  installed mid-query) on the per-recorder
  `on_query_end(duration)` callback.
  `WasmAtomicMetrics.snapshot()` grew from 9 to 12 `bigint`
  fields — new fields `totalQueryLatencyMicros` /
  `minQueryLatencyMicros` / `maxQueryLatencyMicros` join the
  pre-existing nine. The TS bridge documents the
  min-sentinel detection contract (`0xFFFF_FFFF_FFFF_FFFFn`
  meaning "no measurements yet"). 🔒 Padding invariants
  preserved — the latency layer is strictly observational
  and cannot influence padding queries. See the "Native Rust
  per-client latency histograms (P2 observability Phase 2+
  tail, third item)" entry in Completed milestones below for
  the full breakdown.

- Other unblocked P2 items:
  * **Observability Phase 2+ tail (remaining stretch)** —
    per-frame round-trip latency tracking via
    `WsConnection::send` / `recv` / `roundtrip`. Would
    require capturing an `Instant` inside the
    transport-level `roundtrip` future and surfacing it
    through a new `PirMetrics::on_roundtrip_end` callback
    — meaningful API extension, separate design decision
    from the per-query-end latency that already landed.
    The `WasmAtomicMetrics` bridge, `tracing-wasm`
    subscriber, and per-client latency histograms items
    from the original Phase 2+ tail list have all
    landed — see above.
  * **Post-Session-6 worker-pool measurement follow-up** — revisit
    if real-world p95 query latency exceeds the ~200ms budget
    that Session 5's main-thread decision was predicated on.

### Completed milestones
- PIR SDK + WASM bindings + web integration (commit `19cbf5f`).
- Merkle verification for "not found" results in the web clients
  (commit `60fe19c`).
- `[PIR-AUDIT]` logging in web clients (commit `9a693c5`).
- Native Rust `HarmonyClient` + `OnionClient` un-stub (commit `f37db8f`).
- Native Rust `DpfClient` per-bucket Merkle verification (commit `8bd4b7b`).
- Native Rust `HarmonyClient` per-bucket Merkle verification via
  shared `BucketMerkleSiblingQuerier` trait (commit `6aee562`).
- Merkle INDEX item-count symmetry across all five clients + whale
  INDEX Merkle verification (closes found-vs-not-found / h-position
  side channel at the INDEX Merkle level).
- Native Rust `OnionClient` per-bin Merkle verification via
  feature-gated `onion_merkle.rs` module (P0 #1 — see item 10 above).
- INDEX PBC placement verified (P0 #1 closed — not a bug): server
  replicates each scripthash into all 3 candidate groups at build time
  (`build/src/build_cuckoo_generic.rs:87-90`), so `my_groups[0]` in
  single-query paths is correct and matches the reference Rust binary
  (`runtime/src/bin/client.rs:246`) and every web TS / Python client.
  Explanatory comments added at `DpfClient::query_index_level` and
  `HarmonyClient::query_single` to prevent future re-flagging.
- **`merkle_verified: bool` on `QueryResult`** (last P0): a failed
  per-bucket Merkle proof is now surfaced as
  `Some(QueryResult::merkle_failed())` — `merkle_verified = false`,
  empty entries, `is_whale = false` — instead of being coerced to
  `None`. `None` in `SyncResult::results` is now purely "not found"
  (verified absent when the DB publishes Merkle, via the symmetric
  INDEX bin probes). All three native Rust clients (`DpfClient`,
  `HarmonyClient`, `OnionClient`) and the WASM bindings propagate the
  flag. `merge_delta_batch` ANDs snapshot × delta so a single untrusted
  input taints the merge. New unit tests in `pir-sdk/src/sync.rs`
  cover AND semantics, `(None, Some(del))` propagation, and the
  `merkle_failed()` / default-verified state.
- **CI integration tests against live public PIR servers** (first P1):
  `pir-sdk-client/tests/integration_test.rs` now defaults to the
  public deployment (`wss://pir1.chenweikeng.com` /
  `wss://pir2.chenweikeng.com`) with per-URL env var overrides, and
  `.github/workflows/pir-sdk-integration.yml` runs all 12 ignored tests
  on every push/PR plus a daily canary. Surfaced and fixed three
  protocol mismatches that were blocking live-server runs: (1) the
  DPF batch wire format (`encode_batch_query` had a spurious leading
  `level` byte, wrongly-positioned `db_id`, and per-group `num_keys`
  counts instead of a single top-level `keys_per_group`), (2) catalog
  `num_dbs` was decoded as u16 instead of u8 — single-entry catalogs
  looked corrupted because the `db_id` byte was being read as the
  high byte of the count, (3) `wss://` support needed `rustls` with
  an explicit `ring` crypto provider (lazy-installed via `OnceLock`)
  plus bumping the WebSocket max-frame-size to 256 MiB so fresh-sync
  chunk batches (~32 MiB) fit in a single frame. OnionPIR integration
  tests now exist too, gated behind `--features onion`. See
  [SDK_ROADMAP.md](SDK_ROADMAP.md) Completed section for details.
- **OnionPIR CI job** (follow-up to the CI milestone): the
  `integration-onion` job in
  `.github/workflows/pir-sdk-integration.yml` builds `pir-sdk-client`
  with `--features onion` (which compiles SEAL + libonionpir from
  source via CMake + GCC) and runs the new `onion_tests::` module
  against `wss://pir1.chenweikeng.com`. It's a separate job from the
  DPF/Harmony integration job because the C++ build is slow
  (~5–10 min cold); PRs that only touch DPF/Harmony code still get
  fast feedback. Two things the runner needs that plain
  ubuntu-latest doesn't give for free: `CARGO_NET_GIT_FETCH_WITH_CLI=true`
  + a `url.https://github.com/.insteadOf git@github.com:` git config
  rewrite so Cargo can fetch the SEAL submodule (its `.gitmodules`
  uses an SSH URL which the runner has no credentials for).
- **HarmonyClient `REQ_GET_DB_CATALOG` with legacy fallback** (P1):
  Previously `HarmonyClient::fetch_catalog` always called the legacy
  `REQ_HARMONY_GET_INFO = 0x40`, whose `ServerInfo` wire shape predates
  `DatabaseCatalog` and carries no `height` / `has_bucket_merkle`
  fields. As a result `SyncResult::synced_height` was pinned to `0`
  for every Harmony deployment and cache-by-height was broken.
  `fetch_catalog` now tries `REQ_GET_DB_CATALOG = 0x02` first via a
  new `try_fetch_db_catalog`, returning `Ok(None)` on empty reply /
  `RESP_ERROR` / unknown-variant so `fetch_legacy_info` can still
  serve older servers. Both Harmony unified_server roles (hint pir2,
  query pir1) already answer `REQ_GET_DB_CATALOG` — the match arm in
  `unified_server.rs::REQ_GET_DB_CATALOG` runs before any role check —
  so sending it over `hint_conn` works for both. Integration test
  `test_harmony_client_sync_single` now asserts `synced_height > 0`
  end-to-end against the public servers (was previously relaxed with
  a NOTE comment). Also deduplicated the three copies of
  `encode_request` / `decode_catalog` that the DPF, Harmony, and
  OnionPIR clients each maintained into a single shared
  [`pir-sdk-client/src/protocol.rs`](pir-sdk-client/src/protocol.rs)
  module (4 new unit tests for wire-format and catalog decoding) —
  future catalog-format changes now live in one place instead of
  three.
- **Connection resilience: per-request deadlines + reconnect with
  exponential backoff** (P1):
  [`pir-sdk-client/src/connection.rs`](pir-sdk-client/src/connection.rs)
  now wraps every `send` / `recv` / `roundtrip` on `WsConnection` in
  `tokio::time::timeout` (default `DEFAULT_REQUEST_TIMEOUT = 90s`,
  overridable via `with_request_timeout`), and wraps the initial
  TLS/WebSocket handshake in a separate `connect_timeout` (default
  `DEFAULT_CONNECT_TIMEOUT = 30s`). A wedged server no longer hangs a
  query indefinitely — the caller gets `PirError::Timeout` in bounded
  time and can decide what to do next. `WsConnection::connect` now
  internally calls `connect_with_backoff(url, RetryPolicy::default())`;
  the default policy retries up to
  `DEFAULT_MAX_CONNECT_ATTEMPTS = 5` times with
  `DEFAULT_INITIAL_BACKOFF_DELAY = 250ms`→`DEFAULT_MAX_BACKOFF_DELAY
  = 5s` exponential backoff. `reconnect(&mut self)` re-handshakes to
  the same URL using the stored retry policy and replaces the
  sink/stream in place — higher-level clients can use it as an escape
  hatch, but must remember that server-side session state (Harmony
  hints, Onion FHE keys, in-flight round IDs) is gone after a
  reconnect and needs to be re-negotiated. Seven new unit tests cover
  retry-policy shape, backoff doubling + clamping, u32-overflow
  safety, and DNS-fail / route-unreachable timeout paths; a new
  live-server integration test `test_wsconnection_reconnect_roundtrip`
  proves the transport works post-reconnect. `RetryPolicy` and the
  `DEFAULT_*` constants are re-exported from the crate root so
  downstream callers can dial custom policies.
- **OnionPIR LRU-eviction retry in INDEX/CHUNK query rounds** (P1):
  The OnionPIR server's SEAL `KeyStore` evicts registered clients FIFO
  at a 100-client cap; any `answer_query` for an evicted client panics
  inside SEAL and the server's `catch_unwind` surfaces the failure as
  an all-empty batch response (every slot `Vec::new()`). Both query
  rounds in [`pir-sdk-client/src/onion.rs`](pir-sdk-client/src/onion.rs)
  now send through a single chokepoint `onionpir_batch_rpc` that
  (a) detects the eviction signal via a free-standing `batch_looks_evicted`
  helper (≥1-slot batch where every slot is empty — legit FHE responses
  can never match because all slots share one `client_id`), (b) drops
  the `registered[db_id]` flag so `register_keys` actually re-registers,
  (c) replays Galois + GSW keys via `register_keys(db_id)`, and
  (d) retries the exact same encoded query once. A second all-empty
  response surfaces as `PirError::ServerError` instead of looping —
  that case indicates FHE param drift, unreachable DB, or similar. The
  Merkle sibling path in `onion_merkle.rs` is intentionally left
  uncovered; its failure mode ("Merkle proof fails ⇒ result coerced to
  `merkle_failed()`") is already conservative, so post-eviction Merkle
  failures surface as untrusted-⇒-absent rather than stale cache.
  Three new unit tests lock the `batch_looks_evicted` contract
  (all-empty triggers, mixed/full don't, zero-length doesn't either so
  decode bugs can't masquerade as eviction); the helper is `pub(crate)`
  free-standing so it's testable on non-`onion` builds.
- **Thread-safety audit for `unsafe impl Sync for SendClient`** (P1,
  final P1 item): Walked the full public API of `onionpir::Client`
  @ rev `946550a` and confirmed only `id(&self) -> u64` and
  `export_secret_key(&self) -> Vec<u8>` take `&self`; everything else
  is `&mut self`. Cross-checked the C++ side
  (`rust/onionpir-fork/src/ffi.cpp` + `ffi_c.cpp`): both read-only
  entry points accept `const OnionPirClient&` and delegate to
  `client.inner.get_client_id()` (pure integer read) and
  `SecretKey::save(stringstream)` (SEAL const member; uses the default
  thread-safe `MemoryPool`). No `mutable` fields, no globals, no
  thread-locals, no OpenMP parallel regions in those paths. The Sync
  impl is sound, and in practice the SDK never actually shares
  `&SendClient` across threads — `FheState.level_clients` is reached
  only via `&mut OnionClient`, so the Sync impl exists purely to
  satisfy the `PirClient: Send + Sync` trait bound. Recorded the
  audit in a long-form safety comment in
  [`pir-sdk-client/src/onion.rs`](pir-sdk-client/src/onion.rs) and
  locked in compile-time assertions via `const _: fn() = || {
  assert_send_sync::<OnionClient>(); ... }` probes that fail at the
  declaration site if someone adds an `Rc<>` / `RefCell<>` / raw
  pointer to `FheState` or `SendClient`. Added a feature-gated
  concurrency smoke test `test_send_client_sync_smoke` that spawns 8
  threads sharing `Arc<SendClient>` and hammers `id` +
  `export_secret_key` from each (runs in the `integration-onion` CI
  job; plain `cargo test -p pir-sdk-client` doesn't need the C++
  toolchain). `onion_merkle.rs::SibSendClient` picked up a matching
  `assert_send` probe and a cross-reference to the audit.
- **`pir-sdk-wasm` per-bucket Merkle verifier (P2 #2)**: new module
  [`pir-sdk-wasm/src/merkle_verify.rs`](pir-sdk-wasm/src/merkle_verify.rs)
  ships the pure-crypto half of the verifier as `wasm_bindgen` bindings
  — `WasmBucketMerkleTreeTops.fromBytes` parses the
  `REQ_BUCKET_MERKLE_TREE_TOPS` (0x34) blob (same wire format as
  `pir-sdk-client::merkle_verify::parse_tree_tops` and
  `web/src/merkle-verify-bucket.ts::parseTreeTops`), and
  `verifyBucketMerkleItem(bin_index, content, pbc_group,
  sibling_rows_flat, tree_tops)` walks one proof from leaf to cached
  root given pre-fetched XOR'd sibling rows. Supporting primitives:
  `bucketMerkleLeafHash`, `bucketMerkleParentN`, `bucketMerkleSha256`,
  `xorBuffers`. Thirteen unit tests cover parsing (empty/truncated),
  primitive agreement with `pir_core::merkle`, happy-path walks (fully
  cached + one-sibling-level), tamper rejection (bin content, bin
  index, group index, tampered sibling row), and malformed-input
  graceful failure — wasm-pack build succeeds and the new bindings
  show up in `pkg/pir_sdk_wasm.d.ts`. **Deliberate scope limit**:
  the *network* half (K-padded sibling batches over DPF, XOR fold
  across servers, multi-pass for items sharing a PBC group) stays in
  JS. `pir-sdk-client`'s transport layer (tokio-tungstenite, rustls,
  multi-threaded tokio) doesn't compile to `wasm32-unknown-unknown`,
  so a WASM-side transport requires pulling `send`/`recv`/`roundtrip`
  out of `WsConnection` into a `PirTransport` trait (tracked as
  roadmap P2 #1a, must land before `Wasm{Dpf,Harmony,Onion}Client`
  wrappers are possible). Shipping the pure-crypto half first still
  wins: it's the ~400-LOC TS verifier's bulk and the part most likely
  to drift out of spec. `web/src/sdk-bridge.ts` now declares the new
  `PirSdkWasm` surface; retiring
  [`web/src/merkle-verify-bucket.ts`](web/src/merkle-verify-bucket.ts)
  in favour of the WASM bindings is a follow-up that can land
  independently.
- **`pir-sdk-client` transport abstraction (P2 #1a, fully landed)**:
  delivered in three checkpoints.

  *Checkpoint 1 — trait + `WsConnection` impl + Merkle-verifier
  plumbing.* New module
  [`pir-sdk-client/src/transport.rs`](pir-sdk-client/src/transport.rs)
  defines a `PirTransport: Send + Sync` trait (`send` / `recv` /
  `roundtrip` / `close` / `url`) via `async_trait`, with a blanket
  `impl<T: PirTransport + ?Sized> PirTransport for Box<T>` so
  `&mut Box<dyn PirTransport>` coerces to `&mut dyn PirTransport` at
  call sites. `WsConnection` picked up a delegating impl (zero
  behaviour change — the inherent methods stay primary because they
  own connect / reconnect / retry / backoff, which don't generalize).
  An in-memory `MockTransport` (test-only,
  `#[cfg(test)] pub(crate) mod mock`) enqueues canned responses and
  records every `send`/`roundtrip` payload, letting state-machine
  tests run without a WebSocket or tokio runtime. The Merkle-verifier
  helpers (`fetch_tree_tops`, `DpfSiblingQuerier`,
  `verify_bucket_merkle_batch_dpf`, `HarmonySiblingQuerier.query_conn`,
  OnionPIR's `verify_onion_merkle_batch` + `verify_sub_tree`) now take
  `&mut dyn PirTransport` instead of `&mut WsConnection`.

  *Checkpoint 2 — client struct refactor.* The three clients
  (`DpfClient.conn0`/`conn1`, `HarmonyClient.hint_conn`/`query_conn`,
  `OnionClient.conn`) now hold `Option<Box<dyn PirTransport>>`
  instead of `Option<WsConnection>`. Each picked up a
  `connect_with_transport(...)` escape hatch for injecting arbitrary
  `Box<dyn PirTransport>` values (`MockTransport` in tests,
  `WasmWebSocketTransport` on wasm32, etc.), and `connect()` now
  cfg-branches on `target_arch = "wasm32"` — native uses
  `tokio::try_join!` with `WsConnection::connect`, wasm32 uses
  `futures::future::try_join` with `WasmWebSocketTransport::connect`.
  New `connect_with_transport_marks_connected` unit tests in each
  client's `mod tests` prove the injection path.

  *Checkpoint 3 — WASM transport impl.* New module
  [`pir-sdk-client/src/wasm_transport.rs`](pir-sdk-client/src/wasm_transport.rs)
  (`#![cfg(target_arch = "wasm32")]`) implements a
  `web-sys::WebSocket`-backed `PirTransport`. The callback-driven
  DOM API is bridged to async via `futures::channel::mpsc` for
  ongoing binary frames + `futures::channel::oneshot` for the
  open/error race during handshake. `web_sys::WebSocket`,
  `Closure<_>`, and `Rc<RefCell<_>>` are all `!Send + !Sync`, but
  `#[async_trait]` demands `Send` futures and the trait requires
  `Send + Sync`; resolved by wrapping those fields in
  `send_wrapper::SendWrapper<T>` (unsafely impls `Send + Sync`,
  panics on cross-thread access — sound on wasm32 since that target
  is single-threaded). `connect` is split into a synchronous
  `build_transport` helper that constructs all `!Send` locals before
  any `.await` to keep the generated future `Send`. 🔒 Padding
  invariants preserved: the WASM transport is padding-agnostic, it
  just shuttles opaque byte frames; K / K_CHUNK / 25-MERKLE padding
  stays in the client structs above it.

  Features deliberately omitted from the WASM transport (follow-ups):
  per-request deadlines (`setTimeout` + cancellation), reconnect with
  backoff, and anything requiring a tokio reactor. The browser's
  `WebSocket` handles ping/pong control frames invisibly, so nothing
  is needed there. Close/error events still propagate as
  `PirError::ConnectionClosed` / `PirError::ConnectionFailed` so a
  wedged peer can't hang a caller indefinitely.

  `Cargo.toml` split into `[target.'cfg(not(target_arch =
  "wasm32"))'.dependencies]` (tokio, tokio-tungstenite, rustls) and
  `[target.'cfg(target_arch = "wasm32")'.dependencies]`
  (wasm-bindgen, wasm-bindgen-futures, js-sys, web-sys with
  `WebSocket`/`MessageEvent`/`CloseEvent`/etc. features, futures,
  futures-channel, send_wrapper). `cargo test -p pir-sdk-client`
  = 50/50 passing (native); `cargo build --target
  wasm32-unknown-unknown -p pir-sdk-client` succeeds; `cargo check
  --features onion` (C++/SEAL) passes. P2 #1b
  (`Wasm{Dpf,Harmony,Onion}Client` wrappers in `pir-sdk-wasm`) is
  now unblocked.
- **`Wasm{Dpf,Harmony}Client` wrappers in `pir-sdk-wasm` (P2 #1b)**:
  new module
  [`pir-sdk-wasm/src/client.rs`](pir-sdk-wasm/src/client.rs) exposes
  two `wasm-bindgen` classes — `WasmDpfClient` and `WasmHarmonyClient`
  — that wrap the native `DpfClient` / `HarmonyClient` from
  `pir-sdk-client`. JS-facing API per class: `constructor(url, url)`,
  async `connect()` / `disconnect()` / `fetchCatalog(): Promise<WasmDatabaseCatalog>`,
  async `sync(Uint8Array, last_height?): Promise<WasmSyncResult>`,
  async `queryBatch(Uint8Array, db_id): Promise<any>`, and a
  `isConnected` getter. `WasmHarmonyClient` additionally has
  `setMasterKey(Uint8Array[16])` + `setPrpBackend(u8)`, and the PRP
  backend constants are exposed as `PRP_HMR12()` / `PRP_FASTPRP()` /
  `PRP_ALF()` free functions. A new `WasmSyncResult` class wraps
  `pir_sdk::SyncResult`: `resultCount` / `syncedHeight` /
  `wasFreshSync` getters, `getResult(i) → WasmQueryResult | null`,
  and `toJson()`. Script hashes cross the JS boundary as a packed
  `Uint8Array` of length `20 * N` (HASH160 = 20 bytes per scripthash);
  `unpack_script_hashes` validates length-is-multiple-of-20 and
  errors loudly on mismatch. `WasmDatabaseCatalog` picked up a
  `pub(crate) fn from_native` so the wrappers return catalogs without
  a JSON round-trip. `Cargo.toml` added `pir-sdk-client` and
  `wasm-bindgen-futures` as cross-target deps (needed so native
  `cargo test -p pir-sdk-wasm` still builds; the Promise bridging
  only activates on wasm32). Under the hood, `WasmDpfClient::connect`
  uses `WasmWebSocketTransport::connect` on wasm32 (via the
  cfg-branch added in P2 #1a) and `WsConnection::connect` on native —
  the wrapper itself is transport-agnostic. 🔒 Padding invariants
  stay in the native `DpfClient`/`HarmonyClient` (K=75 INDEX,
  K_CHUNK=80 CHUNK, 25-MERKLE); the wrapper is a thin translation
  layer and cannot bypass them. Implementation detail to watch out
  for: the validation helpers (`unpack_script_hashes`,
  `validate_prp_backend`, `validate_master_key_len`,
  `sync_result_to_json`) return `Result<_, String>` rather than
  `Result<_, JsError>` so native unit tests can call them —
  `JsError::new` is a wasm-bindgen import and panics on non-wasm
  targets. The `#[wasm_bindgen]` methods convert at the boundary via
  `.map_err(|e| JsError::new(&e))`. 10 new unit tests cover unpack
  round-trip + error paths, both validators, both client
  constructors, PRP constant distinctness, and `SyncResult → JSON`
  shape (including `merkleVerified = false` round-trip for
  `QueryResult::merkle_failed()`). Build: `cargo test -p pir-sdk-wasm
  --lib` = 23/23 passing; `cargo build --target
  wasm32-unknown-unknown -p pir-sdk-wasm` succeeds; `wasm-pack build
  --target web` generates `pkg/pir_sdk_wasm.d.ts` with
  `export class WasmDpfClient { sync(script_hashes: Uint8Array,
  last_height?: number | null): Promise<WasmSyncResult>; ... }` and
  the `WasmHarmonyClient` / `WasmSyncResult` counterparts. **No
  `WasmOnionClient`**: the upstream `onionpir` crate depends on a
  C++ SEAL build which does not compile to wasm32, so OnionPIR in
  the browser continues to use `web/src/onionpir_client.ts` for the
  foreseeable future.
- **TS retirement Session 2 — DPF surface extensions** (see
  [SDK_ROADMAP.md](SDK_ROADMAP.md) Completed section for the full
  breakdown). Landed in three layers: (a) a new `BucketRef` struct
  + three optional inspector fields (`index_bins`, `chunk_bins`,
  `matched_index_idx`) on `pir_sdk::QueryResult`, with
  `#[serde(default)]` so pre-Session-2 JSON round-trips stay
  byte-identical; (b) `DpfClient::query_batch_with_inspector` /
  `verify_merkle_batch_for_results` split-verify pair that lets
  callers run PIR now and Merkle-verify later (or against
  rehydrated persisted results), plus a new `ConnectionState` +
  `StateListener` trait fired from `connect` / `disconnect`, a
  `server_urls()` accessor, and a `sync_with_progress` variant
  that drives the pre-existing `SyncProgress` trait; (c) WASM
  bindings wiring all of the above to JS — new
  `WasmDpfClient.{serverUrls, queryBatchRaw, verifyMerkleBatch,
  syncWithProgress, onStateChange}`, `WasmQueryResult.{indexBins,
  chunkBins, matchedIndexIdx}` accessors, `WasmDatabaseCatalog.
  {getEntry, hasBucketMerkle}` accessors, with the wasm32-only
  `syncWithProgress` / `onStateChange` using
  `SendWrapper<js_sys::Function>` to bridge `!Send` JS callbacks
  across the `SyncProgress` / `StateListener` trait bounds.
  16 new unit tests: 5 in `pir-sdk-client/src/dpf.rs` (state
  listener recorder, server URLs, state-string contract), 11 in
  `pir-sdk-wasm/src/lib.rs` (bucket-ref round-trip, query-result
  JSON with/without inspector fields, catalog `getEntry`
  by-db_id vs positional).
  Test totals now: `pir-sdk` 14/14, `pir-sdk-client` 55/55,
  `pir-sdk-wasm` 34/34. 🔒 Padding invariants preserved — new
  surfaces route through the same native `DpfClient` that owns
  K / K_CHUNK / 25-MERKLE padding. `WasmHarmonyClient` untouched
  (Session 5 scope); `WasmOnionClient` doesn't exist
  (C++/SEAL wasm32 incompatibility). **Unblocks Session 3** (DPF
  cutover of `BatchPirClient` → `WasmDpfClient` adapter in
  `web/index.html`, plus deletion of `web/src/client.ts` and
  `web/src/merkle-verify-bucket.ts`).
- **TS retirement Session 3 — DPF cutover** (see
  [SDK_ROADMAP.md](SDK_ROADMAP.md) Completed section for the full
  breakdown). The DPF half of the web client is now a thin adapter
  over `WasmDpfClient`. Three artefacts landed:
  * *New adapter shim* `web/src/dpf-adapter.ts` (~400 LOC) —
    `BatchPirClientAdapter` exposes the same public surface as the
    old `BatchPirClient` (`connect` / `disconnect` / `isConnected` /
    `getConnectedSockets` / `getCatalog` / `getCatalogEntry` /
    `hasMerkle` / `hasMerkleForDb` / `getMerkleRootHex` /
    `getMerkleRootHexForDb` / `queryBatch` / `queryDelta` /
    `verifyMerkleBatch` + `onConnectionStateChange` / `onLog` /
    `onSyncProgress` config hooks). Internally owns two
    `ManagedWebSocket` side-channels (for diagnostic frames:
    `REQ_GET_INFO_JSON` / `REQ_GET_DB_CATALOG` / `REQ_RESIDENCY`)
    plus a single `WasmDpfClient` for PIR query + Merkle verify.
    A `WeakMap<QueryResult, WasmQueryResult>` stash lets verify-time
    JSON round-trips reuse the original `WasmQueryResult` handle;
    externally-sourced results fall through a `queryResultToJson`
    helper. A `translateWasmResult` helper converts
    `WasmQueryResult` → legacy `QueryResult` (hex-decode `txid` /
    `binContent`, lift `matchedIdx` to the UI's primary-bin
    convention, derive `allIndexBins` / `chunkPbcGroups` /
    `chunkBinIndices` / `chunkBinContents` from inspector fields).
  * *WASM raw-chunk-byte round-trip* — `parse_query_result_json` in
    `pir-sdk-wasm/src/lib.rs` picked up hex-decode of
    `rawChunkData` (symmetric with `WasmQueryResult.toJson`'s
    hex-encode of `raw_chunk_data`), so persisted results survive
    `fromJson` → `verifyMerkleBatch` byte-exact. New unit test
    `parse_query_result_json_round_trips_raw_chunk_data` locks in
    the positive round-trip; the invalid-hex error path is not
    unit-tested because `JsError::new(...)` panics on non-wasm32
    targets (same pattern already guards the `txid` hex field).
  * *File deletions + re-exports* — `web/src/client.ts`
    (35,391 bytes) and `web/src/merkle-verify-bucket.ts`
    (16,411 bytes) are gone. `web/index.html` swapped `new
    BatchPirClient({ ... })` → `new BatchPirClientAdapter({ ... })`
    (config shape unchanged). `web/src/index.ts` dropped
    `BatchPirClient` / `createBatchPirClient` / `BatchPirClientConfig`
    from `./client.js` and added `BatchPirClientAdapter` /
    `BatchPirClientConfig` from `./dpf-adapter.js` plus direct
    re-exports of `ConnectionState` / `UtxoEntry` / `QueryResult`
    from `./types.js`. `web/src/__tests__/sync-merge.test.ts`
    migrated its type imports from `../client.js` to `../types.js`.
  *Accepted regressions (documented in SDK_ROADMAP.md):*
  (1) `[PIR-AUDIT]` logs from native `DpfClient` go to
  `console.info` rather than the web UI's log panel (no `onLog`
  hook on `WasmDpfClient`);
  (2) `queryBatch` per-batch progress is coarse (begin/end) because
  `queryBatchRaw` is a single `Promise` without inner progress
  ticks; (3) `getConnectedSockets()` returns only the two side-channel
  `ManagedWebSocket`s because the WASM transport's internal
  sockets are hidden behind the `wasm-bindgen` boundary —
  functionally equivalent for residency purposes since both hit
  the same origin.
  Verification: `npx tsc --noEmit` → no new TS errors (same three
  pre-existing ones); `npx vite build` → clean
  (`✓ built in ~270ms`, 5 assets); `npx vitest run` → 88/88 passing
  across 7 test files; `cargo test -p pir-sdk-wasm --lib` →
  35/35 passing; `cargo test -p pir-sdk-client --lib` → 55/55;
  `cargo test -p pir-sdk --lib` → 14/14.
  🔒 Padding invariants preserved — PIR rounds still run through
  native `DpfClient` (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE),
  INDEX-Merkle item-count symmetry invariant lives in the same
  native code path. The adapter is a translation shim; it cannot
  bypass the padding.
  LOC impact: -883 (`client.ts`) -420 (`merkle-verify-bucket.ts`)
  +~400 (`dpf-adapter.ts`) +~30 (`sdk-bridge.ts` interface
  extensions) +~15 (`lib.rs` WASM plumbing). Net: ~900 LOC of
  hand-rolled TS retired.
  **Unblocks Sessions 4-6 for the Harmony retirement path.** Session
  4 (native `HarmonyClient` hint persistence) is Rust-side only and
  independent; Session 5 (Harmony WASM surface extensions) wraps
  Session 4; Session 6 (web-side Harmony cutover) mirrors Session
  3's pattern. OnionPIR stays on TS indefinitely — SEAL doesn't
  compile to wasm32.
- **TS retirement Session 4 — native HarmonyClient hint persistence**
  (see [SDK_ROADMAP.md](SDK_ROADMAP.md) Completed section for the
  full breakdown). Closes the first-query-latency gap for HarmonyPIR:
  every `ensure_*_groups_ready` that previously downloaded dozens of
  MiB of hint parities now short-circuits on a cache hit, and any
  `persist_hints_to_cache` after a sync preserves
  `HarmonyGroup::query_count` + the relocation log so a restarted
  client resumes mid-session instead of starting fresh. Three
  artefacts landed:
  * *New module* [`pir-sdk-client/src/hint_cache.rs`](pir-sdk-client/src/hint_cache.rs)
    (~640 LOC). Self-describing binary format: magic bytes `PSH1`,
    a `u16` format version, a 32-byte SHA-256 of a private
    `SCHEMA_STRING` constant (mismatched schemas re-fetch cleanly),
    a 16-byte `CacheKey::fingerprint` that folds
    `(master_prp_key, prp_backend, db_id, height, index_bins,
    chunk_bins, tag_seed, index_k, chunk_k)` through
    `pir_core::merkle::sha256`. Main + sibling `HarmonyGroup` blobs
    follow in length-prefixed records with sorted group IDs
    (deterministic encode output locked in by unit test). Keyed on
    fingerprint only — the master PRP key itself never hits disk as
    cleartext, not even in the filename. `decode_hints` takes an
    optional `expected_fingerprint` cross-check so a stale cache
    with the wrong key/shape fails `PirError::InvalidState` instead
    of returning zeros. `resolve_default_cache_dir` follows XDG
    (`$XDG_CACHE_HOME/pir-sdk/hints/` with `~/.cache/pir-sdk/hints/`
    fallback); `write_cache_file` uses `<path>.tmp` + rename for
    POSIX-atomic writes. 21 unit tests cover round-trip, encode
    determinism, cross-check mismatch, schema/magic/version/length
    tampering rejection, XDG + home-dir fallback logic.
  * *`HarmonyClient` persistence surface* (~430 new LOC in
    [`pir-sdk-client/src/harmony.rs`](pir-sdk-client/src/harmony.rs)).
    New field `hint_cache_dir: Option<PathBuf>` + 8 new public
    methods: `with_hint_cache_dir` / `set_hint_cache_dir` /
    `hint_cache_dir` accessor, `save_hints_bytes() ->
    PirResult<Option<Vec<u8>>>` (in-memory export for the browser's
    IndexedDB bridge, `None` when no groups are loaded),
    `load_hints_bytes(&mut self, bytes, &DatabaseInfo)` (importer
    with fingerprint cross-check), `persist_hints_to_cache` +
    `restore_hints_from_cache` (filesystem-backed pair; no-op on
    wasm32). The group-ID layout baked into encode/decode follows
    the documented per-group key offsets: main INDEX = `g`, main
    CHUNK = `k_index + g`, INDEX sib L = `(k_index + k_chunk) +
    L*k_index + g`, CHUNK sib L = `(k_index + k_chunk) +
    index_sib_levels*k_index + L*k_chunk + g`.
  * *`ensure_*_groups_ready` integration.* Both `ensure_groups_ready`
    (main) and `ensure_sibling_groups_ready` (per-level Merkle
    siblings) now try `restore_hints_from_cache` before the network
    fetch, then persist after a successful fetch (errors logged and
    ignored so a read-only cache dir can't brick the client). The
    sibling variant tightened its early-return check from
    "not empty" to `index_sib_groups.len() == index_sib_levels *
    k_index` (plus chunk counterpart) — closes a latent bug where a
    stale cache with fewer levels would serve stale proofs.
    12 new `harmony::tests` unit tests cover each surface.
  Verification: `cargo test -p pir-sdk-client --lib` = 89/89
  passing (native); `cargo build --target wasm32-unknown-unknown -p
  pir-sdk-client` succeeds; `cargo check -p pir-sdk-client
  --features onion` passes. 🔒 Padding invariants preserved — the
  hint cache just shuttles `HarmonyGroup::serialize()` bytes, it
  cannot bypass the K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE
  padding which lives in the query path above it. **Unblocks
  Session 5** (`WasmHarmonyClient.saveHints` / `loadHints` wrapping
  these byte-level APIs, plus inspector + Merkle-verify parity with
  DPF reusing Session 2's machinery).
- **TS retirement Session 5 — Harmony WASM surface extensions**
  (see [SDK_ROADMAP.md](SDK_ROADMAP.md) Completed section for the
  full breakdown). Extends the native `HarmonyClient` with the
  full DPF-parity surface and bridges it through
  `WasmHarmonyClient`, unblocking Session 6 (the Harmony web-side
  cutover). Three artefacts landed:
  * *Native `HarmonyClient` surface parity with DPF (Session 2)*
    in [`pir-sdk-client/src/harmony.rs`](pir-sdk-client/src/harmony.rs).
    Six new translator helpers convert Harmony's `QueryTraces`
    into SDK-level `BucketMerkleItem` / `BucketRef` values.
    Existing `run_merkle_verification` refactored to delegate to
    a new `verify_merkle_items` shared backend (tree-top fetch +
    sibling-group ensure + `HarmonySiblingQuerier`-driven
    `verify_bucket_merkle_batch_generic` with the existing
    `std::mem::take` borrow-split) — same behaviour, now reusable
    from the new split-verify path. New public methods:
    `server_urls(&self) -> (&str, &str)`,
    `set_state_listener(Option<Arc<dyn StateListener>>)` +
    private `notify_state(ConnectionState)` fired in `connect` /
    `connect_with_transport` / `disconnect`,
    `query_batch_with_inspector(...)` (front-loads
    `ensure_groups_ready`, translates traces to inspector fields,
    synthesises empty `QueryResult` for not-found),
    `verify_merkle_batch_for_results(...)` (no-op when
    `!has_bucket_merkle`, otherwise runs the shared backend),
    `sync_with_progress(...)` (drives `SyncProgress` observer
    through plan steps), `db_id(&self)` / `set_db_id(u8)` /
    `min_queries_remaining(&self)` / `estimate_hint_size_bytes(&self)` /
    `cache_fingerprint(&DatabaseInfo) -> [u8; 16]` (the
    DB-switch + hint-stats API new to this session). Nine new
    unit tests.
  * *`WasmHarmonyClient` bindings* in
    [`pir-sdk-wasm/src/client.rs`](pir-sdk-wasm/src/client.rs).
    New JS-visible methods: `serverUrls()`, `queryBatchRaw()`,
    `verifyMerkleBatch()`, `dbId()`, `setDbId()`,
    `minQueriesRemaining()`, `estimateHintSizeBytes()`,
    `fingerprint(catalog, db_id)`,
    `saveHints() -> Uint8Array | null`,
    `loadHints(bytes, catalog, db_id)`, plus wasm32-only
    `syncWithProgress(...)` and `onStateChange(...)` bridges
    (same `SendWrapper<js_sys::Function>` pattern as
    `WasmDpfClient`). A new `pub(crate) fn inner()` on
    `WasmDatabaseCatalog` lets the Harmony wrapper look up
    `DatabaseInfo` by `db_id` for the cache-key-derivation paths.
    Four new native-safe unit tests (`Uint8Array`-returning
    methods can't be native-tested because the wasm-bindgen
    import panics outside wasm32).
  * *Worker-pool strategy decision: main thread.* Deferred to a
    post-Session-6 follow-up if real-world p95 measurements
    exceed the ~200ms budget. Rationale: native `HarmonyClient`
    bulk-processes groups inside one Rust call without TS↔WASM
    boundary crossings, so per-round CPU budget drops well below
    what the TS worker pool's amortized cost covered. Exposing
    sub-group lifecycle to JS would break `HarmonyClient`'s
    encapsulation of padding-critical state transitions.
  Verification: `cargo test -p pir-sdk` = 14/14,
  `cargo test -p pir-sdk-client --lib` = 98/98 (9 new Session 5
  tests), `cargo test -p pir-sdk-wasm --lib` = 39/39 (5 new
  Session 5 tests), `cargo build --target wasm32-unknown-unknown
  -p pir-sdk-wasm` succeeds, `wasm-pack build --target web`
  emits `pkg/pir_sdk_wasm.d.ts` with the full Session 5 Harmony
  surface visible. 🔒 Padding invariants preserved — all new
  inspector/verify paths delegate to the same native
  `HarmonyClient` query code that owns K=75 INDEX / K_CHUNK=80
  CHUNK / 25-MERKLE and the INDEX-Merkle item-count symmetry
  invariant. **Unblocks Session 6** — the WASM surface this
  session exposes is the exact set a `HarmonyPirClientAdapter`
  needs to drop in over `harmonypir_client.ts`.
- **Error taxonomy refinement in `PirError` (P2 follow-up after
  TS retirement)**: landed a categorical
  [`ErrorKind`](pir-sdk/src/error.rs) enum that lets callers
  dispatch on cause without matching every variant. Three layers:
  * *New variants* on `PirError`:
    - `Transient { origin: &'static str, context: String }` —
      general transient-blip path for retry-layer code (field
      named `origin`, not `source`, so `thiserror` doesn't
      coerce it into a `std::error::Error` source chain; the
      `&'static str` type would otherwise fail the
      `AsDynError` trait bound with a cryptic
      "`as_dyn_error` exists but trait bounds not satisfied"
      compile error).
    - `ProtocolSkew { expected: String, actual: String }` —
      version/feature mismatch that a caller can't recover from
      without an upgrade. Distinct from `Protocol` (malformed
      wire data *within* the agreed protocol).
    - `SessionEvicted(String)` — server lost our session
      (OnionPIR LRU eviction after in-session retry failed;
      future: stale Harmony hint session). Dedicated variant so
      reconnect-then-retry loops can target this cause
      specifically instead of lumping with generic
      `ServerError`.
    - `MerkleVerificationFailed(String)` — pipeline-level Merkle
      failure. Explicitly distinct from the per-query
      `QueryResult::merkle_failed()` coercion, which stays in
      place (per-query failures don't abort the batch; pipeline
      failures do). The legacy `VerificationFailed(String)`
      variant still exists and classifies the same way, for
      back-compat with anyone who matches on it directly.
  * *Classification API*: `PirError::kind() -> ErrorKind`
    returns one of eight categorical kinds
    (`TransientNetwork` / `SessionEvicted` / `ProtocolSkew` /
    `MerkleVerificationFailed` / `ServerError` / `ClientError`
    / `DataError` / `Other`). Callers can match on the enum
    instead of the many specific variants. Four new helpers
    (`is_transient_network`, `is_session_lost`,
    `is_verification_failure`, `is_protocol_skew`) wrap the
    common patterns. `is_retryable` broadened from the old
    `Timeout | ConnectionClosed` match to
    `TransientNetwork | SessionEvicted`, and
    `is_connection_error` / `is_protocol_error` picked up the
    new `Transient` / `ProtocolSkew` variants respectively —
    the existing retry loop in
    `pir-sdk-client/src/connection.rs::connect_with_backoff`
    uses `is_connection_error` as its "retry this attempt"
    predicate and continues to work.
  * *Three concrete call-site migrations*:
    - `pir-sdk-client/src/onion.rs::onionpir_batch_rpc` now
      returns `PirError::SessionEvicted` when the all-empty
      eviction signal (`batch_looks_evicted`) fires twice in a
      row — once initially, once after re-registering keys.
      Previously this produced a generic `ServerError` that
      naive retry loops could spin on; the new variant gives
      callers a clean signal to reconnect.
    - `pir-sdk-client/src/merkle_verify.rs::decode_sibling_batch`
      now returns `PirError::MerkleVerificationFailed` when the
      server sends `RESP_ERROR = 0xFF` mid-Merkle-round. By
      that point tree-tops are already fetched, so a mid-round
      error means the server can't produce the evidence needed
      to verify. Unit test
      `test_decode_sibling_batch_error_variant` updated to
      assert the new variant + `kind() ==
      ErrorKind::MerkleVerificationFailed`.
    - `pir-sdk-client/src/merkle_verify.rs::fetch_tree_tops`
      now returns `PirError::ProtocolSkew` when the server
      rejects the tree-tops request despite the catalog
      advertising `has_bucket_merkle = true`. The tree-tops
      count check in `verify_bucket_merkle_batch_dpf` also
      raises `ProtocolSkew` when the server's blob has fewer
      entries than the declared `K_INDEX + K_CHUNK` — client
      and server disagree on PBC group count, which is a
      version/feature gap rather than a transient corruption.
  * *Docs*: module-level docs in `pir-sdk/src/error.rs` include
    a cause-to-action mapping table, and per-variant docs
    cross-link to preferred more-specific variants (e.g.
    `ServerError` notes LRU eviction should use
    `SessionEvicted` instead; `VerificationFailed` is marked as
    legacy in favour of `MerkleVerificationFailed`). `ErrorKind`
    is re-exported from `pir_sdk` crate root alongside
    `PirError` / `PirResult`.

  Verification: `cargo test -p pir-sdk --lib` = 31/31 passing
  (was 14/14; 17 new error-taxonomy tests cover every
  `ErrorKind` classification, all four new retry helpers, both
  new variants' `Display` format, and `is_connection_error` /
  `is_protocol_error` back-compat). `cargo test -p
  pir-sdk-client --lib` = 98/98 passing. `cargo test -p
  pir-sdk-wasm --lib` = 39/39 passing. `cargo build --target
  wasm32-unknown-unknown -p pir-sdk-client` and `-p
  pir-sdk-wasm` both succeed; `cargo check -p pir-sdk-client
  --features onion` (C++/SEAL) succeeds. Web suites unchanged:
  `npx vitest run` = 88/88 across 7 files, `npx vite build`
  clean in ~300ms. 🔒 Padding invariants preserved — the
  taxonomy sits above the query code that owns K=75 INDEX /
  K_CHUNK=80 CHUNK / 25-MERKLE padding, and the three
  migrations are error-raising-only changes (no wire-format or
  query-logic shifts).
- **Native Rust tracing instrumentation (P2 observability Phase
  1)**: added `tracing = "0.1"` (with the `log` feature so every
  existing `log::info!`/`log::warn!`/`log::debug!` call
  automatically bridges into any installed subscriber) as an
  additive dep on `pir-sdk-client`. Every public inherent + trait
  method on `DpfClient` / `HarmonyClient` / `OnionClient` now
  carries a `#[tracing::instrument(level = …, skip_all, fields(…))]`
  attribute; `WsConnection::{connect, connect_once,
  connect_with_backoff, reconnect}` likewise. Consistent shape
  across all three backends:
  * Every span has `backend = "dpf" | "harmony" | "onion"` as a
    recorded field so a downstream subscriber can filter to a
    single backend with one clause. The three
    `tracing_instrument_emits_backend_field_for_<backend>` smoke
    tests lock this in — they install a scoped
    `tracing_subscriber::fmt` backed by an in-memory
    `MakeWriter` buffer, drive an instrumented method via the
    `MockTransport` injection path, then assert the captured
    output contains both the span name and the `backend="…"`
    field string. An accidental `#[tracing::instrument]` removal
    or `backend` rename therefore fails at `cargo test` time, not
    in a production log search.
  * Three-tier level hierarchy:
    - `info` for top-level user operations (`connect`,
      `disconnect`, `sync`, `reconnect`).
    - `debug` for sub-operations (`connect_with_transport`,
      `connect_with_backoff`, `execute_step`, `fetch_catalog`,
      `sync_with_plan`, `query_batch`, `query_batch_with_inspector`,
      `verify_merkle_batch_for_results`, `sync_with_progress`,
      `run_merkle_verification`, `ensure_groups_ready`,
      `ensure_sibling_groups_ready`, `verify_merkle_items`).
    - `trace` for per-query inner loops (`query_index_level`,
      `query_chunk_level`, Harmony's `query_single`).
  * `skip_all` on every instrument attribute guards against
    accidental injection of binary payloads (script-hash slices,
    hint blobs, `Arc<…>` trait objects, `Box<dyn PirTransport>`)
    as span fields. Only scalars / display-string URLs / DB ids
    / query counts / heights / step names / flags are recorded.
    Display formatting goes through `%` (for `Display`) or `?`
    (for `Debug`); no `Serialize` bounds are imposed on recorded
    types.
  * DPF-specific fields recorded: `server0` / `server1` URLs on
    `connect`, `db_id` / `step` / `height` / `num_queries` on
    `execute_step`, `db_id` on the two per-level query helpers.
  * Harmony-specific fields recorded: `hint` / `query` URLs on
    `connect`, `num_items` on `verify_merkle_items`, same
    step/db/height/query-count triplet as DPF on `execute_step`.
  * Onion-specific fields recorded: `server` URL on `connect`,
    same step/db/height/query-count triplet on `execute_step`,
    `db_id` on the INDEX / CHUNK level helpers. The Onion spans
    fire from both the `cfg(feature = "onion")` and the
    placeholder-fallback `cfg(not(feature = "onion"))` `execute_step`
    so a disabled-feature trace still surfaces the attempt.
  * `WsConnection` spans: `url` + `max_attempts` on
    `connect_with_backoff`, `url` on `connect` / `connect_once`,
    `url` on `reconnect` (pulled from `self.url` since reconnect
    re-handshakes the same endpoint). Chosen scope: lifecycle
    only — `send` / `recv` / `roundtrip` are per-frame and too
    noisy to span without sampling, which is Phase 2+ work.

  **Phase 2+ (deferred):** per-client metrics trait + recorder
  (query count / bytes-in / bytes-out / round-trip-latency
  histograms), WASM bindings for tracing (`pir-sdk-wasm` needs a
  `tracing` feature + a web-compatible subscriber adapter, since
  `tracing-subscriber::fmt` writes to `io::Write` which doesn't
  exist on `wasm32-unknown-unknown`), per-transport byte counters
  surfaced through `PirTransport`.

  Verification: `cargo build -p pir-sdk-client` clean (only the
  two pre-existing `INDEX_RESULT_SIZE` / `CHUNK_RESULT_SIZE`
  dead-code warnings). `cargo build --target
  wasm32-unknown-unknown -p pir-sdk-client` clean (`tracing` core
  compiles to wasm32; only the subscriber side is gated). `cargo
  check -p pir-sdk-client --features onion` clean (the
  feature-gated `query_index_level` / `query_chunk_level` /
  `execute_step` / `run_merkle_verification` instruments compile
  under the C++/SEAL path too). `cargo test -p pir-sdk-client
  --lib` = 101/101 passing (up from 98/98; three new
  tracing-capture smoke tests). `tracing-subscriber` is a
  dev-dep only — no subscriber is forced on downstream callers.
  No-op unless an application installs one. 🔒 Padding invariants
  preserved — tracing sits above the query code that owns K=75
  INDEX / K_CHUNK=80 CHUNK / 25-MERKLE padding and the
  INDEX-Merkle item-count symmetry invariant; every
  instrumentation change is a pure attribute addition with zero
  behavioural impact, and `skip_all` explicitly keeps binary
  payloads out of the span fields.

- **Native Rust metrics observer (P2 observability Phase 2)**:
  structured counters that sit alongside the tracing spans. Four
  layers landed:

  *Layer 1 — trait and recorders in `pir-sdk`.* New module
  [`pir-sdk/src/metrics.rs`](pir-sdk/src/metrics.rs) (~280 LOC)
  defines a `PirMetrics: Send + Sync + 'static` observer trait
  with six callbacks, all defaulted to empty-body no-ops so a
  transport or client doesn't *have* to implement them if it
  prefers to be silent on a given event. The six are
  `on_query_start(backend: &'static str, batch_size: usize,
  db_id: u8)`, `on_query_end(backend, batch_size, db_id,
  success)`, `on_bytes_sent(backend, bytes)`, `on_bytes_received(
  backend, bytes)`, `on_connect(backend)`, `on_disconnect(
  backend)`. Backend labels are `&'static str` (`"dpf"`,
  `"harmony"`, `"onion"`) so per-callback allocations are zero.
  Two concrete impls: `NoopMetrics` (explicit ZST that simply
  inherits the trait defaults — useful as an
  `Arc<dyn PirMetrics>` placeholder in tests) and `AtomicMetrics`
  (nine `AtomicU64` counters: `query_starts` / `query_ends` /
  `query_successes` / `query_failures` / `bytes_sent` /
  `bytes_received` / `frames_sent` / `frames_received` /
  `connects` / `disconnects`). `AtomicMetrics::snapshot()` returns
  a `Copy` `AtomicMetricsSnapshot` struct with `Ordering::Relaxed`
  loads — correct since each counter is independently atomic with
  no cross-counter invariant (a snapshot is a momentary fuzzy
  read, not a transaction). The trait + `PirMetrics` /
  `NoopMetrics` / `AtomicMetrics` / `AtomicMetricsSnapshot` are
  re-exported from `pir_sdk` crate root. 8 unit tests cover
  defaulted callbacks (installing a bare trait impl still
  compiles), atomic counter agreement across 16 threads hammering
  a shared `Arc<AtomicMetrics>`, snapshot determinism when the
  world is quiet, `NoopMetrics` producing no writes, `Copy`
  semantics on the snapshot struct, backend label preservation
  through `on_query_start`, and crate-root re-export existence.
  Plus 1 doc-test demonstrating the canonical
  `Arc::new(AtomicMetrics::new())` install pattern.

  *Layer 2 — `PirTransport` extension + transport impls.* The
  trait picked up `fn set_metrics_recorder(&mut self, recorder:
  Option<Arc<dyn PirMetrics>>, backend: &'static str)` with a
  default empty body so existing impls compile unchanged. The
  `Box<T: PirTransport + ?Sized>` blanket impl forwards via
  `(**self).set_metrics_recorder(recorder, backend)`. `WsConnection`
  gained an *inherent* `set_metrics_recorder` method (the trait
  impl delegates to it via UFCS — having both the trait and the
  inherent method would normally bind to the trait and recurse,
  but the inherent method wins at the name lookup level when both
  exist with the same signature, which is the pattern that
  closes the recursion). Inherent helpers `fire_bytes_sent` /
  `fire_bytes_received` null-check the `Option<Arc<dyn PirMetrics>>`
  on every frame (hot path; one branch is cheap). `send` fires
  the byte callback only *after* the send future resolves with
  `Ok(())` — a timeout or wire error produces no byte callback,
  so the counters reflect bytes that actually hit the wire.
  `recv` counts the full raw frame including the 4-byte length
  prefix on a successful decode. `roundtrip` is the tricky one:
  `self.sink` / `self.stream` are mutably borrowed during the
  inner async block, so `self.metrics_recorder` can't be read
  inside it — instead we capture `bytes_out: usize`,
  `bytes_in: Option<usize>`, and `send_succeeded: bool` in locals
  inside the async block, then fire the byte callbacks after the
  future resolves and the `sink`/`stream` borrows drop.
  `MockTransport` picked up an `Option<(Arc<dyn PirMetrics>,
  &'static str)>` field + `fire_bytes_sent` / `fire_bytes_received`
  helpers; `send` / `recv` / `roundtrip` fire them.
  `WasmWebSocketTransport` got the same treatment — the recorder
  field sits alongside the existing `SendWrapper`-guarded DOM
  handles, but `Arc<dyn PirMetrics>: Send + Sync` so it doesn't
  need `SendWrapper`. `send` fires after the successful
  `ws.send_with_u8_array`; `recv` fires on the `IncomingFrame::Binary`
  branch. 3 new `transport::tests` unit tests
  (`mock_transport_fires_byte_callbacks`,
  `mock_transport_roundtrip_fires_both_callbacks`,
  `mock_transport_uninstall_recorder_silences_callbacks`) lock in
  the install-fires / roundtrip-fires-both / uninstall-silences
  contract.

  *Layer 3 — client wiring.* `DpfClient`, `HarmonyClient`,
  `OnionClient` each gained `metrics_recorder: Option<Arc<dyn
  PirMetrics>>` + public `set_metrics_recorder`. The client's
  setter stores the handle, then propagates to every owned
  transport (DpfClient: `conn0` / `conn1`, HarmonyClient:
  `hint_conn` / `query_conn`, OnionClient: `conn`) with the
  backend label `"dpf"` / `"harmony"` / `"onion"` respectively.
  Install-before-connect: the handle is stored, then pushed to
  each transport slot in `connect_with_transport` and `connect`
  after the slot is populated. Install-after-connect: the setter
  pushes immediately to any already-populated transport slot.
  Each client has `fire_query_start` / `fire_query_end` /
  `fire_connect` / `fire_disconnect` inherent helpers. Semantics:
  * `on_connect` fires per transport — so DPF and Harmony each
    tick `connects` by 2 per successful `connect`, Onion by 1.
  * `on_disconnect` fires once per client — the semantic signal
    is "the client left the connected state", which happens once
    regardless of how many transports it owns.
  * `on_query_start` and `on_query_end` fire at `query_batch`
    entry and exit, passing `batch_size`, `db_id`, and (for
    `on_query_end`) a `success` flag.
  The query-round internals don't fire per-round metrics (INDEX
  / CHUNK / Merkle sub-rounds) — that's intentional for now;
  sub-round instrumentation is in the Phase 2+ tail. 12 new
  client-layer tests (4 per client × 3 clients): pre-connect
  install via `connect_with_transport` +
  `connects == N_transports` assertion, post-connect
  `set_metrics_recorder(None)` silences all subsequent callbacks,
  post-connect install propagates the handle (exercised by driving
  a raw `send` through the underlying transport and asserting
  `bytes_sent > 0`), and explicit `disconnect` fires
  `on_disconnect` once.

  *Layer 4 — documentation and invariant preservation.*
  The metrics layer is strictly observational: callbacks receive
  scalar counters and `&'static str` labels only, never query
  payloads, hint blobs, secret keys, or padding-critical state.
  It sits *above* the query code that owns K=75 INDEX / K_CHUNK=80
  CHUNK / 25-MERKLE padding and the INDEX-Merkle item-count
  symmetry invariant, and there is no code path by which a
  recorder can influence the number or content of padding queries
  sent. Installing no recorder (the default) means the
  `Option<Arc<dyn PirMetrics>>` is `None` everywhere and every
  `fire_*` helper is a single null-check with no allocation.

  **Phase 2+ tail (deferred):** per-client latency histograms
  (need a `performance.now()`-backed substitute for wasm32's lack
  of `std::time::Instant`), WASM bindings for `tracing`
  (`pir-sdk-wasm` needs a `tracing` feature + a web-compatible
  subscriber adapter since `tracing-subscriber::fmt` writes to
  `io::Write` which doesn't exist on `wasm32-unknown-unknown`),
  round-trip latency tracking (capture `Instant` at
  `on_query_start`, diff at `on_query_end`), and
  `WasmAtomicMetrics` bridge so a browser tools panel can read
  the counters through `wasm-bindgen`.

  Verification: `cargo test -p pir-sdk --lib` = 39/39 passing
  (up from 31/31; 8 new metrics tests). `cargo test -p
  pir-sdk-client --lib` = 116/116 passing (up from 101/101; 15
  new tests — 3 `MockTransport`, 4 DpfClient, 4 HarmonyClient, 4
  OnionClient). `cargo test -p pir-sdk-client --features onion
  --lib` = 138/138 passing. `cargo test -p pir-sdk-wasm --lib`
  = 39/39 (unchanged — WASM client wrappers don't expose
  metrics yet; that's Phase 2+). `cargo build --target
  wasm32-unknown-unknown -p pir-sdk-client` clean (the 3
  pre-existing warnings — `INDEX_RESULT_SIZE` / `CHUNK_RESULT_SIZE`
  / `Path` unused on wasm32 — are unchanged from pre-session
  baseline). `cargo check -p pir-sdk-client --features onion`
  clean. 🔒 Padding invariants preserved — see Layer 4 above.

- **Native Rust `WasmAtomicMetrics` bridge (P2 observability
  Phase 2+ tail, first item)**: exposes the native
  `pir_sdk::AtomicMetrics` lock-free counter recorder to
  JavaScript via `wasm-bindgen` so a browser tools panel /
  dashboard can poll live PIR query + transport counters
  without leaving the Rust-native metrics path. Three layers
  landed:

  *Layer 1 — `WasmAtomicMetrics` class in `pir-sdk-wasm`.*
  New module [`pir-sdk-wasm/src/metrics.rs`](pir-sdk-wasm/src/metrics.rs)
  (~275 LOC) defines a `#[wasm_bindgen]`-annotated
  `WasmAtomicMetrics` struct wrapping `Arc<AtomicMetrics>`. JS
  surface is intentionally minimal: a zero-arg `new()`
  constructor (every counter starts at zero) and a `snapshot()`
  method that returns a plain JS object with nine `bigint`
  fields (`queriesStarted` / `queriesCompleted` / `queryErrors`
  / `bytesSent` / `bytesReceived` / `framesSent` /
  `framesReceived` / `connects` / `disconnects`). The object is
  built manually via `js_sys::Object::new() + Reflect::set`
  rather than `serde_wasm_bindgen::to_value` so the `u64 →
  BigInt` conversion is explicit and avoids any serializer
  ambiguity; `js_sys::BigInt::from(u64)` lands on a real JS
  `BigInt` via the `bigint_from_big!(i64 u64 i128 u128)` macro
  expansion in js-sys 0.3.91. Using `bigint` rather than JS
  `Number` is required because byte counters in a long-running
  session could exceed 2^53 (the `Number.MAX_SAFE_INTEGER`
  ceiling, ~9 PB). Callers can wrap with `Number(snap.bytesSent)`
  if they prefer `Number` arithmetic and the value is known to
  fit. Crate-visible `recorder_handle(&self) -> Arc<dyn
  PirMetrics>` clones the inner `Arc` and returns it as a trait
  object so it satisfies `DpfClient::set_metrics_recorder`'s
  `Option<Arc<dyn PirMetrics>>` signature without the caller
  having to know the concrete recorder type. `#[cfg(test)]
  snapshot_raw() -> AtomicMetricsSnapshot` returns the native
  snapshot type so unit tests can bypass the wasm-bindgen JS
  layer — `js_sys::Object::new()` panics on native targets, so
  the `snapshot()` wasm-bindgen method isn't directly
  unit-testable. `Default` for `WasmAtomicMetrics` delegates to
  `new()` for `Default::default()` convenience.

  *Layer 2 — client wiring in `pir-sdk-wasm/src/client.rs`.*
  `WasmDpfClient` and `WasmHarmonyClient` each gained two new
  JS-visible methods: `setMetricsRecorder(metrics:
  &WasmAtomicMetrics)` and `clearMetricsRecorder()`. Both
  delegate to `self.inner.set_metrics_recorder(Some(metrics.
  recorder_handle()))` or `...(None)` on the native `DpfClient`
  / `HarmonyClient`. The native client then propagates the
  handle to every owned transport (DPF: `conn0` + `conn1` with
  backend label `"dpf"`; Harmony: `hint_conn` + `query_conn`
  with backend label `"harmony"`), so all pre-existing Phase 2
  byte / frame / connect / disconnect / query-lifecycle
  callbacks start firing on the shared counters. Two methods
  rather than a single nullable setter because
  `Option<&WasmAtomicMetrics>` isn't supported as a
  `wasm-bindgen` parameter type. Pre-connect install (store the
  handle, propagate at `connect`) and post-connect install
  (propagate immediately to already-populated transport slots)
  both work — this is the native-client behaviour documented
  in the Phase 2 entry above, inherited unchanged. Dropping the
  JS-side `WasmAtomicMetrics` handle does NOT detach the
  recorder from installed clients, because each client holds
  its own `Arc` clone; callers that want to stop recording must
  call `clearMetricsRecorder()` on the client (tested via
  `uninstall_preserves_js_handle`).

  *Layer 3 — TypeScript surface in `web/src/sdk-bridge.ts`.*
  `WasmAtomicMetrics` class added to the `PirSdkWasm` interface;
  a dedicated `WasmAtomicMetrics` interface (with `free()` +
  `snapshot(): AtomicMetricsSnapshot`) documents the handle,
  and an `AtomicMetricsSnapshot` interface carries nine
  `readonly bigint` fields matching the native snapshot shape.
  `setMetricsRecorder(metrics: WasmAtomicMetrics): void` and
  `clearMetricsRecorder(): void` added to both `WasmDpfClient`
  and `WasmHarmonyClient` interfaces. Public helper
  `sdkCreateAtomicMetrics(): WasmAtomicMetrics` follows the
  pattern of `sdkParseBucketMerkleTreeTops` — throws if
  `initSdkWasm()` hasn't resolved yet, since the metrics bridge
  has no TS fallback (and none is wanted — counters without
  native client backing would silently be zero). Both
  `WasmAtomicMetrics` and `AtomicMetricsSnapshot` types are
  re-exported so downstream TS code gets IntelliSense without
  reaching into the generated `pkg/pir_sdk_wasm.d.ts` directly.

  Unit tests (7 new, all in `metrics::tests` in
  `pir-sdk-wasm`): `new_starts_at_zero` (constructor baseline),
  `recorder_handle_is_shared_arc` (fire events through the
  `Arc<dyn PirMetrics>` trait object and observe them on the
  JS-side handle — proves the Arc clone is aliased, not zeroed),
  `recorder_handle_installs_on_dpf_client` and
  `recorder_handle_installs_on_harmony_client` (install +
  compile + no panic — end-to-end wire-level behaviour is
  covered by the `MockTransport` tests in Phase 2),
  `multiple_clients_share_one_recorder` (one
  `WasmAtomicMetrics` installed on both a DpfClient and a
  HarmonyClient aggregates bytes across them), `default_equals_new`
  (convenience `Default::default` produces equal zeroed state
  with distinct Arc identities), `uninstall_preserves_js_handle`
  (`client.set_metrics_recorder(None)` drops the client's Arc
  reference but the JS-side handle keeps reading the
  last-observed counters — this is the contract that lets a
  dashboard survive a mid-session client reconnect).

  Verification: `cargo test -p pir-sdk-wasm --lib` = 46/46
  passing (up from 39/39; 7 new metrics tests). `cargo build
  --target wasm32-unknown-unknown -p pir-sdk-wasm` clean (3
  pre-existing warnings unchanged). `wasm-pack build --target
  web --out-dir pkg` in `pir-sdk-wasm/` emits the new surface
  in `pir_sdk_wasm.d.ts`: `WasmAtomicMetrics` class at line
  170, `snapshot(): any` at line 201,
  `setMetricsRecorder(metrics: WasmAtomicMetrics): void` on
  `WasmDpfClient` at line 446 and on `WasmHarmonyClient` at
  line 672, `clearMetricsRecorder(): void` at lines 343 and
  528. Raw wasm imports at lines 1099-1143 (`wasmdpfclient_
  setMetricsRecorder`, `wasmatomicmetrics_snapshot`, etc.)
  confirm the wasm-bindgen binding table is wired through. Web
  suite: `npx tsc --noEmit` shows only the two pre-existing
  errors unchanged (`ws.test.ts` SharedArrayBuffer type,
  `onionpir_client.ts` null/undefined); `npx vitest run` =
  88/88 passing across 7 files; `npx vite build` clean in
  ~300ms (WASM bundle `pir_sdk_wasm_bg-Fgpy-jiq.wasm` =
  973.94 kB, gzip 327.26 kB; JS wrapper `pir_sdk_wasm-
  BfXewFv4.js` = 30.02 kB, gzip 7.51 kB). 🔒 Padding
  invariants preserved — the metrics bridge is a pure JS↔Rust
  marshalling layer over the already-landed Phase 2 observer,
  which is itself strictly observational. It sits above the
  native-client query code that owns K=75 INDEX / K_CHUNK=80
  CHUNK / 25-MERKLE padding and the INDEX-Merkle item-count
  symmetry invariant; there is no code path by which a
  recorder can influence the number or content of padding
  queries sent. Installing no recorder (the default) means the
  `Option<Arc<dyn PirMetrics>>` on every client is `None` and
  every `fire_*` helper is a single null-check.

  Remaining Phase 2+ tail (still deferred): per-client latency
  histograms (need a `performance.now()`-backed `Duration`
  substitute for wasm32's missing `std::time::Instant`, likely
  behind a cfg-branch in a new `pir-sdk::timing` module), and
  WASM bindings for `tracing` (`pir-sdk-wasm` needs a
  web-compatible subscriber adapter since `tracing-subscriber::
  fmt` writes to `io::Write` which doesn't exist on
  `wasm32-unknown-unknown`).

- **Native Rust `tracing-wasm` subscriber bridge (P2
  observability Phase 2+ tail, second item)**: installs a
  browser-compatible `tracing::Subscriber` so the Phase 1
  `#[tracing::instrument]` spans on the native
  `DpfClient` / `HarmonyClient` / `OnionClient` / `WsConnection`
  / `WasmWebSocketTransport` actually surface in the browser's
  DevTools console (Phase 1 added the span attributes but the
  spans were invisible on wasm32 because `tracing-subscriber::
  fmt::fmt()` writes to `io::Write`, and the only working
  `io::Write` on `wasm32-unknown-unknown` is the tokio-io
  shim from pir-sdk-client's native-only deps). Three layers
  landed:

  *Layer 1 — `tracing_bridge` module in `pir-sdk-wasm`.* New
  module [`pir-sdk-wasm/src/tracing_bridge.rs`](pir-sdk-wasm/src/tracing_bridge.rs)
  (~130 LOC, mostly docs) exposes a single `#[wasm_bindgen]`
  function `initTracingSubscriber()` that calls
  `tracing_wasm::set_as_global_default()` inside a
  `std::sync::Once::call_once(|| { ... })`. The `Once` guard
  is essential — `tracing-wasm 0.2.1`'s
  `set_as_global_default` internally `.expect()`s the
  `tracing::subscriber::set_global_default` result, and the
  second call returns `Err` (the global default is already
  set) which unwraps to a panic. Wrapping in `Once` means
  init-from-multiple-paths is safe, which matters because a
  web app may initialize observability from both the main
  thread's startup and a potential worker-pool reinit
  (Session 6 main-thread decision notwithstanding).
  The inner body is `#[cfg(target_arch = "wasm32")]`-gated
  so `cargo test -p pir-sdk-wasm` on native compiles it as
  an empty `Once`-guarded block (no-op). Module docstring
  documents the "install both" relationship with
  `WasmAtomicMetrics` — they answer different questions
  ("what is happening now" vs. "how many of each thing has
  happened") and are independent opt-ins.

  *Layer 2 — `Cargo.toml` dep.* Added
  `tracing-wasm = "0.2"` under
  `[target.'cfg(target_arch = "wasm32")'.dependencies]`,
  alongside the existing `send_wrapper` entry. Gated on
  wasm32 because `tracing-wasm` transitively depends on
  `web-sys::console` which doesn't link on native. Not
  gated behind a cargo feature — the first cut always
  links the dep on wasm32, paying ~35 KB uncompressed /
  ~14 KB gzipped for callers who don't install the
  subscriber. If bundle size becomes a concern, gating
  behind `features = ["tracing-subscriber"]` is a
  follow-up. New transitive deps pulled in for wasm32-only
  builds: `tracing-wasm 0.2.1`, `tracing-subscriber 0.3.23`,
  `sharded-slab 0.1.7`.

  *Layer 3 — TypeScript surface in
  `web/src/sdk-bridge.ts`.* Added
  `initTracingSubscriber(): void` to the `PirSdkWasm`
  interface and a public `initSdkTracing(): void` helper
  that wraps `requireSdkWasm().initTracingSubscriber()`.
  The helper follows the `sdkCreateAtomicMetrics()` pattern
  — throws `Error("WASM module required...")` if
  `initSdkWasm()` hasn't resolved yet, since the bridge
  has no TS fallback (the native `PIR-AUDIT` log-bridge
  already surfaces some info via `log::info!`, but Phase 1
  span structure is invisible without the subscriber).

  Unit tests (3 new, all in `tracing_bridge::tests` in
  `pir-sdk-wasm`): `init_tracing_subscriber_no_panic_on_native`
  (fn is callable without panic — important because native
  test suites exercise the same surface as wasm32),
  `init_tracing_subscriber_idempotent` (three consecutive
  calls complete without panic — proves the `Once` guard
  holds; without it, tracing-wasm would panic on the second
  call), `init_state_is_a_module_static_once` (compile-time
  + runtime assertion that `INIT` remains a
  `std::sync::Once`, catching any future refactor that
  swaps in a different sync primitive with different
  idempotency semantics).

  Verification: `cargo test -p pir-sdk-wasm --lib` = **49/49**
  passing (up from 46/46; 3 new `tracing_bridge` tests).
  `cargo build --target wasm32-unknown-unknown -p pir-sdk-wasm`
  clean (the 3 pre-existing warnings — `INDEX_RESULT_SIZE` /
  `CHUNK_RESULT_SIZE` / `Path` unused on wasm32 — unchanged).
  `wasm-pack build --target web --out-dir pkg` in
  `pir-sdk-wasm/` emits `initTracingSubscriber(): void` at
  line 996 of `pir_sdk_wasm.d.ts` with the full doc comment
  preserved, and the raw wasm import table at line 1119
  (`readonly initTracingSubscriber: () => void`) confirms
  the wasm-bindgen binding is wired. Raw wasm bundle:
  973.94 KB → 986 KB (**+12 KB**); vite-compiled output:
  973.94 KB → 1009.23 KB uncompressed (**+35 KB**), gzip
  327.26 KB → 341.50 KB (**+14 KB**). Web suite: `npx
  tsc --noEmit` shows only the two pre-existing errors
  unchanged; `npx vitest run` = 88/88 passing across 7
  files; `npx vite build` clean in ~298ms. 🔒 Padding
  invariants preserved — the tracing subscriber is strictly
  observational. Span fields are filtered by
  `#[tracing::instrument(skip_all, ...)]` attributes on the
  native side, so only whitelisted scalars / URLs /
  `&'static str` labels reach the subscriber — never
  binary payloads, hint blobs, or secret keys. It sits
  above the query code that owns K=75 INDEX / K_CHUNK=80
  CHUNK / 25-MERKLE padding, with no code path by which a
  subscriber can influence the number or content of
  padding queries sent.

  Remaining Phase 2+ tail at the time of this landing —
  per-client latency histograms — has since landed (see
  the next entry below). The remaining stretch follow-up
  is per-frame round-trip latency tracking through
  `WsConnection::{send,recv,roundtrip}`, which would need
  a new `PirMetrics::on_roundtrip_end` callback and is a
  separate API extension.

- **Native Rust per-client latency histograms (P2
  observability Phase 2+ tail, third item)**: closes the
  last remaining Phase 2+ item by extending
  `PirMetrics::on_query_end` with a `duration: Duration`
  parameter and threading captured `Instant` values from
  query start through to query end across all three
  native clients. Before this landing, `AtomicMetrics`
  could count completed queries but the time those
  queries took was invisible — operators had no signal on
  whether p50 or p95 was creeping up under load. Five
  layers landed:

  *Layer 1 — `web-time` dep + `Instant` / `Duration`
  re-exports.* Added `web-time = "1.1"` as a `pir-sdk`
  dep (cross-target, no cfg gating) — the crate provides
  drop-in `Instant` / `Duration` types that delegate to
  `std::time` on native and to `performance.now()` via
  `web_sys::Performance` on `wasm32-unknown-unknown`.
  This unblocks shipping a single timing-aware metrics
  surface that compiles for both targets without
  per-callsite cfg-branches. `pir-sdk/src/metrics.rs`
  re-exports `web_time::{Instant, Duration}` at module
  scope; the `pir-sdk` crate root then re-exports both
  alongside `PirMetrics` / `AtomicMetrics` /
  `AtomicMetricsSnapshot` / `NoopMetrics` so callers
  don't need a direct `web-time` dep. (This re-export
  was the source of an early `unresolved import
  pir_sdk::Instant` E0432 during client wiring that
  took one round to chase down.)

  *Layer 2 — trait + recorder shape changes in
  `pir-sdk`.* The `PirMetrics` trait's `on_query_end`
  callback gained a sixth parameter — `duration: Duration`
  — that all implementations now receive. The signature
  change is source-breaking but additive in spirit (the
  parameter has a meaningful default of `Duration::ZERO`
  for best-effort observation, see Layer 3).
  `AtomicMetrics` picked up three new lock-free counters:
  `total_query_latency_micros: AtomicU64`,
  `min_query_latency_micros: AtomicU64`,
  `max_query_latency_micros: AtomicU64`. The min counter
  is initialised to a `MIN_LATENCY_SENTINEL = u64::MAX`
  constant — `fetch_min(observed)` always wins on the
  first measurement (any observed value <= `u64::MAX`),
  which sidesteps the alternative
  "first-value-special-cased via CAS loop" pattern that
  would have needed a separate observed-anything-yet
  flag. `Default` is hand-written for both
  `AtomicMetrics` and `AtomicMetricsSnapshot` to set
  `min_query_latency_micros` to the sentinel rather than
  to `0`; the autoderived `Default` would have zeroed
  the field, which would then cause the very first
  observation to miscompute as min=0. Both
  `AtomicMetrics::on_query_end` and the snapshot's
  atomic loads use `Ordering::Relaxed` (each counter is
  independently atomic with no cross-counter invariant
  — a snapshot is a momentary fuzzy read, not a
  transaction). Snapshot consumers detect "no
  measurements yet" by checking
  `min_query_latency_micros == u64::MAX`; the JS-side
  bridge (Layer 4) documents this with the literal
  `0xFFFF_FFFF_FFFF_FFFFn` BigInt sentinel. 7 new
  `metrics::tests` unit tests cover the latency surface
  end-to-end: zero-state assertion, single-observation
  agreement, multi-observation aggregation
  (total / min / max), 16-thread concurrent
  `Arc<AtomicMetrics>` hammer test, snapshot
  determinism, `Default` correctness for the sentinel,
  and `Copy` semantics on the snapshot struct.

  *Layer 3 — `Option<Instant>` threading in client
  helpers.* All three native clients (`DpfClient`,
  `HarmonyClient`, `OnionClient`) replaced their
  pre-existing `fire_query_start` / `fire_query_end`
  inherent helpers with an `Option<Instant>`-threading
  pair:
  ```rust
  fn fire_query_start(&self, db_id: u8, num_queries: usize)
      -> Option<Instant> {
      if let Some(rec) = &self.metrics_recorder {
          rec.on_query_start("dpf", db_id, num_queries);
          Some(Instant::now())
      } else {
          None
      }
  }
  fn fire_query_end(&self, db_id: u8, num_queries: usize,
                    success: bool,
                    started_at: Option<Instant>) {
      if let Some(rec) = &self.metrics_recorder {
          let duration = started_at.map(|t| t.elapsed())
              .unwrap_or_default();
          rec.on_query_end("dpf", db_id, num_queries,
                           success, duration);
      }
  }
  ```
  Three properties this design preserves: (a) **zero
  overhead when no recorder is installed** —
  `fire_query_start` returns `None` immediately without
  touching the clock, so `Instant::now()` (which on
  wasm32 hits `performance.now()`, a non-trivial
  JS↔WASM boundary call) is skipped entirely; (b)
  **best-effort observation when recorder installed
  mid-query** — `fire_query_end` receiving
  `started_at = None` (recorder absent at start) still
  surfaces an `on_query_end` callback with
  `duration = Duration::ZERO` rather than swallowing the
  event silently, which keeps the `query_starts` /
  `query_ends` counter pair consistent for callers that
  compute "in-flight queries" via subtraction; (c) **no
  allocation in the hot path** — `Option<Instant>` is
  `Copy`, the clock value is captured once and consumed
  via `.elapsed()`, no `Box` / `Arc` / heap interaction.
  Each client's existing `query_batch` call site changed
  from a single `self.fire_query_start(...)` to
  `let started_at = self.fire_query_start(...);`
  followed by `self.fire_query_end(..., started_at);` at
  the return path. 9 new client-level tests landed (3
  per client × 3 clients):
  `fire_query_start_returns_instant_only_when_recorder_installed`
  (proves `None` baseline + `Some(_)` post-install),
  `fire_query_end_records_non_zero_duration_with_recorder`
  (5 ms `tokio::time::sleep` between start + end,
  asserts `min_query_latency_micros >= 1_000`),
  `fire_query_end_with_none_start_records_zero_duration`
  (locks in the best-effort `Duration::ZERO` semantics).
  The Onion variants get `_onion` suffixes for parallel
  test discovery in IDEs.

  *Layer 4 — `WasmAtomicMetrics` snapshot bridge.*
  `pir-sdk-wasm/src/metrics.rs::snapshot_to_js` now sets
  three additional `bigint` fields on the returned JS
  object: `totalQueryLatencyMicros`,
  `minQueryLatencyMicros`, `maxQueryLatencyMicros`. The
  field count on the snapshot grew from 9 to 12; the
  module docstring's example moved from a 9-field
  read-out to a 12-field one, with a new explanatory
  paragraph on min-sentinel detection (JS side reads
  `0xFFFF_FFFF_FFFF_FFFFn` to mean "no measurements
  yet" and should display "—" rather than misleadingly
  rendering the sentinel as a real measurement). The
  existing `new_starts_at_zero` test was extended to
  assert all three latency fields land at their
  expected zero-state (`0`, `u64::MAX`, `0`); two new
  tests landed:
  `latency_through_recorder_handle_lands_in_snapshot`
  (3 simulated query completions with synthetic
  durations 20 ms / 50 ms / 80 ms; asserts
  `total = 150_000`, `min = 20_000`, `max = 80_000`)
  and `multiple_clients_aggregate_latency` (one
  `WasmAtomicMetrics` installed on both a
  `WasmDpfClient` and a `WasmHarmonyClient`, 4
  simulated completions spread across both clients;
  asserts the snapshot reflects the union — proves
  the `Arc` clone aliases share state across client
  backends). `WasmAtomicMetrics` test count: 49/49 →
  51/51 passing.

  *Layer 5 — TypeScript surface in
  `web/src/sdk-bridge.ts`.* The `AtomicMetricsSnapshot`
  interface gained three new `readonly bigint` fields
  (`totalQueryLatencyMicros`, `minQueryLatencyMicros`,
  `maxQueryLatencyMicros`) with TSDoc comments
  documenting the latency-snapshot semantics: total =
  sum of all completed query durations in microseconds;
  min initialised to `0xFFFF_FFFF_FFFF_FFFFn`
  (`u64::MAX`) sentinel meaning "no measurements yet";
  max monotonically grows. The `snapshot()` doc comment
  moved from "nine `bigint` counters" to "twelve
  `bigint` counters". No new TS-side helpers needed —
  the pre-existing `sdkCreateAtomicMetrics()` factory
  returns the same `WasmAtomicMetrics` handle, just
  with three more fields available on its `snapshot()`
  output.

  Verification: `cargo test -p pir-sdk --lib` =
  **48/48** passing (up from 41/41; 7 new
  `metrics::tests` including a thread-safety stress
  test). `cargo test -p pir-sdk-client --lib` =
  **125/125** passing (up from 116/116; 9 new
  client-level tests, 3 per client). `cargo test -p
  pir-sdk-client --features onion --lib` = **147/147**
  passing. `cargo test -p pir-sdk-wasm --lib` =
  **51/51** passing (up from 49/49; 2 new
  `metrics::tests`). `cargo test -p pir-core --lib` =
  25/25 (unchanged). `cargo build --target
  wasm32-unknown-unknown -p pir-sdk-client` clean (3
  pre-existing warnings unchanged); `cargo build
  --target wasm32-unknown-unknown -p pir-sdk-wasm`
  clean. `cargo check -p pir-sdk-client --features
  onion` (C++/SEAL) clean. `wasm-pack build --target
  web --out-dir pkg` in `pir-sdk-wasm/` succeeds; the
  three new latency fields are visible in
  `pir_sdk_wasm.d.ts` at lines 193-195 (interface) and
  205-210 (snapshot return shape). Web suite:
  `npx tsc --noEmit` shows only the two pre-existing
  errors unchanged; `npx vitest run` = 88/88 passing
  across 7 files; `npx vite build` clean in ~300ms
  with bundle 1010.26 kB / 341.95 kB gzipped (the
  +1 kB uncompressed / +0.5 kB gzip delta vs. the
  `tracing-wasm` baseline reflects the small added
  `web-time` integration).
  🔒 Padding invariants preserved — the latency layer
  is strictly observational. The new `Duration`
  parameter on `on_query_end` is computed from
  `Instant::now()` deltas, never from query payload
  shape; `Option<Instant>` threading guarantees zero
  overhead when no recorder is installed; the
  per-client metrics handle is propagated to all
  owned transports but never reaches the query encoder
  / decoder paths that own K=75 INDEX / K_CHUNK=80
  CHUNK / 25-MERKLE padding and the INDEX-Merkle
  item-count symmetry invariant. There is no code path
  by which an installed recorder can influence the
  number or content of padding queries sent.

  All three Phase 2+ tail items have now landed
  (`WasmAtomicMetrics` bridge ✅, `tracing-wasm`
  subscriber bridge ✅, per-client latency histograms
  ✅). The single remaining stretch follow-up
  (per-frame round-trip latency tracking via
  `WsConnection::send` / `recv` / `roundtrip`) stays
  deferred — it would require capturing an `Instant`
  inside the transport-level `roundtrip` future and
  surfacing it through a new
  `PirMetrics::on_roundtrip_end` callback, a
  meaningful API extension separate from the
  per-query-end latency this entry closes.

- **P3 sweep: rustdoc + dead-code + clippy polish.** Three
  [SDK_ROADMAP.md](SDK_ROADMAP.md) P3 items landed together
  as a pre-publish polish pass:
  * *Rustdoc examples per client.* `DpfClient`,
    `HarmonyClient`, and `OnionClient` each now carry a
    struct-level rustdoc block with a runnable-looking
    `ignore`'d `#[tokio::main]` example plus intra-doc
    links into the methods that matter. `DpfClient`'s doc
    covers the two-server DPF XOR basis and shows both a
    basic `query_batch` call and a `sync` call driven by a
    catalog. `HarmonyClient`'s doc covers the hint + query
    two-server architecture, PRP backend selection (HMR12
    default; `fastprp`/`alf` feature-gated), and
    demonstrates the hint-cache-resume pattern via
    [`with_hint_cache_dir`] + [`load_hints_bytes`] /
    [`save_hints_bytes`]. `OnionClient`'s doc covers the
    Microsoft SEAL BFV basis, Galois + GSW key lifecycle,
    server LRU eviction and the
    [`PirError::SessionEvicted`] retry surface (via
    `onion_merkle.rs::onionpir_batch_rpc`), and the `onion`
    cargo feature gating (native-only; SEAL doesn't compile
    to wasm32). All three examples use `ignore` since they
    require a live PIR server; they serve as shape /
    signature documentation rather than doctests.
  * *Dead code sweep.* Five removals + two feature-gated
    allows: (1) unused `INDEX_RESULT_SIZE` /
    `CHUNK_RESULT_SIZE` constants in
    `pir-sdk-client/src/dpf.rs` replaced with NOTE comments
    pointing to `runtime/src/eval.rs` for the canonical
    values; (2) `use std::path::{Path, PathBuf}` in
    `pir-sdk-client/src/hint_cache.rs` split so `Path` is
    `#[cfg(not(target_arch = "wasm32"))]`-gated (only the
    native filesystem helpers use it; `PathBuf` stays
    unconditional for the XDG resolver which runs on both
    targets); (3) dead `derived_key: [u8; 16]` and
    `group_id: u32` fields on `HarmonyGroup` in
    `harmonypir-wasm/src/lib.rs` removed — deserialize
    takes them as args and re-derives the per-group RNG
    seed, so storing them in the struct was a leftover
    from an earlier factoring. Both construction sites
    (`new_with_backend` and `deserialize`) now `let _ =
    key; let _ = group_id;` before the `Ok(HarmonyGroup {
    ... })` so the arguments are deliberately consumed;
    (4) non-root `[profile.release]` stanzas in
    `pir-sdk-wasm/Cargo.toml` and `harmonypir-wasm/Cargo
    .toml` removed (Cargo ignores profile stanzas in
    non-root packages, so these were misleading
    documentation at best) and replaced with a
    cross-reference comment block recommending the
    canonical workspace-level `wasm-release` profile
    pattern; (5) two onion-feature dead-code warnings
    gated: `OnionTreeTopCache.cache_from_level` (parse-only
    metadata — kept to preserve schema symmetry with the
    per-bucket `merkle_verify.rs` version, which DOES
    consume it, in case a future walker needs absolute
    level indices) and `onion_leaf_hash` (public API
    surface for external consumers of the `onion` feature
    to reproduce leaf hashing without reaching into
    `pir_core::merkle`; exercised by
    `test_onion_leaf_hash_matches_sha256`), both with
    `#[allow(dead_code)]` + multi-line justification
    comments.
  * *`pir-core` clippy cleanup.* All 5 pre-existing
    warnings cleared so `-D warnings` can now safely go
    into CI for the whole workspace. Three
    `needless_range_loop` refactors:
    (a) `pir-core/src/hash.rs`'s `derive_groups_3` and
    `derive_int_groups_3` dup-rejection inner loops
    collapsed to `groups.iter().take(count).any(|&g| g ==
    group)`; (b) `pir-core/src/pbc.rs::pbc_plan_rounds`
    refactored to `for (g, owner) in group_owner.iter().
    enumerate().take(num_groups) { ... }` so `g` continues
    to serve as both the `group_owner` index and the
    pushed group ID (the canonical fix for this lint —
    an explicit comment now explains why enumerate is the
    right shape); (c) `pir-core/src/cuckoo.rs::build_int_
    keyed_table` refactored to `for (i, id) in ids.iter().
    enumerate() { ... }` since the panic message's
    `ids[i]` lookup is satisfied by the `id` iter value.
    Plus one `manual_div_ceil` fix:
    `pir-core/src/merkle.rs::compute_tree_top_cache` at
    line 301 changed from `(prev.len() + arity - 1) /
    arity` to the stable (Rust 1.73+)
    `prev.len().div_ceil(arity)`.

  Verification: `cargo test -p pir-core --lib` = 25/25,
  `cargo test -p pir-sdk --lib` = 41/41, `cargo test -p
  pir-sdk-client --lib` = 116/116, `cargo test -p
  pir-sdk-wasm --lib` = 49/49; `cargo build --target
  wasm32-unknown-unknown -p pir-sdk-client` / `-p
  pir-sdk-wasm` / `-p harmonypir-wasm` all clean; `cargo
  check -p pir-sdk-client --features onion` (C++/SEAL)
  clean. 🔒 Padding invariants unaffected — the sweep
  is pure polish. Rustdoc additions are
  documentation-only; dead-code removals never touched
  the query path; clippy refactors are semantically
  equivalent per-loop restructurings. None of the three
  layers can influence K=75 INDEX / K_CHUNK=80 CHUNK /
  25-MERKLE padding or the INDEX-Merkle item-count
  symmetry invariant.

  [`with_hint_cache_dir`]: pir-sdk-client/src/harmony.rs
  [`load_hints_bytes`]: pir-sdk-client/src/harmony.rs
  [`save_hints_bytes`]: pir-sdk-client/src/harmony.rs
  [`PirError::SessionEvicted`]: pir-sdk/src/error.rs

- **Publishing prep landed (P3 #2 + #3 in
  [SDK_ROADMAP.md](SDK_ROADMAP.md)).** Five publishable crates
  (`pir-core`, `pir-sdk`, `pir-sdk-client`, `pir-sdk-server`,
  `pir-sdk-wasm`) now ship with full crates.io / npm metadata,
  dual-license blocks, READMEs, Keep-a-Changelog v1.1.0
  CHANGELOGs, plus workspace-level `FEATURES.md` (per-crate
  feature × default × compat × description matrix + platform
  compatibility matrix) and `PUBLISHING.md` (readiness matrix
  with 🟢/🟡/🔴 tags, two documented blockers each with two
  suggested fixes, publish order, per-crate checklist, npm
  workflow, version-bump procedure, unpublishing notes, and a
  PIR invariant preservation gate). Landed in four logical
  commits on `main`:
  * `5d4e8da chore(publishing): add LICENSE files and align
    Cargo.toml metadata for crates.io` — workspace-root
    LICENSE-MIT + LICENSE-APACHE + per-crate symlinks +
    Cargo.toml metadata fill-in (description / license /
    repository / homepage / documentation / readme / keywords
    / categories / authors / rust-version) + explicit `version
    = "0.1.0"` on every cross-publishable path dep + `publish
    = false` on `block_reader` / `build` / `runtime` /
    `harmonypir-wasm`.
  * `c5bf8cd docs(publishing): write per-crate READMEs for
    crates.io` — per-crate README.md files that render on
    crates.io and docs.rs, each pointing readers at the right
    level of the stack.
  * `4f5dee2 docs(publishing): add per-crate CHANGELOGs +
    FEATURES.md + PUBLISHING.md` — five Keep-a-Changelog
    files, the workspace `FEATURES.md`, the workspace
    `PUBLISHING.md`. The `pir-sdk` and `pir-sdk-client`
    CHANGELOGs each carry an explicit Security section
    re-stating the K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE
    padding invariant and the INDEX-Merkle item-count
    symmetry rule.
  * `bb41ab0 chore(publishing): add pir-sdk-wasm npm-publish
    helper script` — `scripts/prepare-wasm-publish.sh`
    (executable). wasm-pack copies only `name` / `version` /
    `description` / `license` from Cargo.toml; the script
    uses `jq --arg` (strings) + `--argjson` (keywords array)
    to add `repository` / `homepage` / `bugs` / `keywords` /
    `author`, and appends `CHANGELOG.md` + `LICENSE-MIT` +
    `LICENSE-APACHE` to the `files` array via `unique` (npm
    auto-includes `LICENSE`/`LICENCE` but not the hyphenated
    variants, and never auto-includes `CHANGELOG.md`).
    Cross-checks the version in `pir-sdk-wasm/Cargo.toml`
    against `pkg/package.json` to prevent publishing a stale
    pkg/. Exit codes: 0 success, 1 pkg missing, 2 version
    mismatch, 3 jq missing.

  The actual `cargo publish` / `npm publish` invocations are
  deliberately not run pending blocker resolution (unpinned
  `libdpf` git dep, pinned-rev `harmonypir` git dep,
  `runtime`/`build` path deps inside `pir-sdk-server`); see
  [PUBLISHING.md](PUBLISHING.md) for the documented fix paths.
  Verification: full test surface stayed green throughout —
  `cargo test -p pir-core --lib` 25/25, `pir-sdk --lib`
  48/48, `pir-sdk-client --lib` 125/125 (147/147 with
  `--features onion`), `pir-sdk-wasm --lib` 51/51. `cargo
  build --target wasm32-unknown-unknown -p pir-sdk-client`
  and `-p pir-sdk-wasm` both clean. `wasm-pack build --target
  web --out-dir pkg` succeeds. 🔒 Padding invariants
  unaffected — the entire prep series is metadata + docs +
  tooling, no query path was touched. The "Security" sections
  in the pir-sdk and pir-sdk-client CHANGELOGs and the
  invariant-preservation gate in PUBLISHING.md re-state
  (don't relax) the padding + INDEX-Merkle symmetry rules
  from this file's CRITICAL SECURITY REQUIREMENTS section.

---

## Key Files
- `pir-sdk/src/lib.rs` - SDK entry point
- `pir-sdk/src/error.rs` - `PirError` + `ErrorKind` taxonomy + classification helpers
- `pir-sdk/src/metrics.rs` - `PirMetrics` observer trait + `NoopMetrics` / `AtomicMetrics` (Phase 2 observability)
- `pir-sdk-wasm/src/lib.rs` - WASM bindings
- `pir-sdk-wasm/src/merkle_verify.rs` - WASM per-bucket Merkle verifier
- `pir-sdk-wasm/src/client.rs` - `WasmDpfClient` + `WasmHarmonyClient` wrappers
- `pir-sdk-wasm/src/metrics.rs` - `WasmAtomicMetrics` JS bridge (Phase 2+ observability)
- `pir-sdk-wasm/src/tracing_bridge.rs` - `initTracingSubscriber()` for browser-console spans (Phase 2+ observability)
- `pir-sdk-client/src/transport.rs` - `PirTransport` trait (+ `MockTransport`)
- `pir-sdk-client/src/connection.rs` - `WsConnection` (native `PirTransport` impl)
- `pir-sdk-client/src/wasm_transport.rs` - `WasmWebSocketTransport` (wasm32 `PirTransport` impl)
- `pir-sdk-client/src/hint_cache.rs` - HarmonyPIR hint cache format + fingerprint (Session 4)
- `web/src/sdk-bridge.ts` - JS/TS bridge to WASM
- `web/src/dpf-adapter.ts` - `BatchPirClientAdapter` over `WasmDpfClient` (Session 3)
- `web/src/types.ts` - Neutral `ConnectionState` / `UtxoEntry` / `QueryResult` types (Session 1)
- `web/src/sync-controller.ts` - Uses SDK for sync planning

## Build Commands
```bash
# Build SDK WASM
cd pir-sdk-wasm && wasm-pack build --target web --out-dir pkg

# Run web dev server
cd web && npm run dev

# Test SDK
cd pir-sdk && cargo test
```
