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

- Other unblocked P2 items:
  * **Observability** — `tracing` spans + per-client metrics +
    progress callbacks for long syncs.
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
  backend constants are exposed as `PRP_HOANG()` / `PRP_FASTPRP()` /
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

---

## Key Files
- `pir-sdk/src/lib.rs` - SDK entry point
- `pir-sdk/src/error.rs` - `PirError` + `ErrorKind` taxonomy + classification helpers
- `pir-sdk-wasm/src/lib.rs` - WASM bindings
- `pir-sdk-wasm/src/merkle_verify.rs` - WASM per-bucket Merkle verifier
- `pir-sdk-wasm/src/client.rs` - `WasmDpfClient` + `WasmHarmonyClient` wrappers
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
