# PIR SDK Roadmap

Status snapshot: the native Rust SDK has three real clients (`DpfClient`,
`HarmonyClient`, `OnionClient`) and per-bin Merkle verification wired
into all three. This document tracks what's left before the SDK is
production-ready.

Items marked 🔒 touch the padding/privacy invariants in CLAUDE.md
("Query Padding", "Cuckoo Hashing and Not-Found Verification"). Any
change near them needs extra care — do not optimize away padding.

## Completed

- `DpfClient` — real implementation with `[PIR-AUDIT]` logging.
- `HarmonyClient` — real implementation via `harmonypir-wasm` rlib.
- `OnionClient` — real implementation, feature-gated behind `onion`.
- Per-bucket Merkle verification for `DpfClient`
  (`pir-sdk-client/src/merkle_verify.rs` + `run_merkle_verification`).
- Per-bucket Merkle verification for `HarmonyClient` via a shared
  `BucketMerkleSiblingQuerier` trait — DPF and Harmony backends drive the
  same walk/top logic, with Harmony-specific sibling queries routed through
  `REQ_HARMONY_BATCH_QUERY` (levels `10+L` INDEX, `20+L` CHUNK).
  Commit `6aee562`.
- Web TypeScript client parity for all three protocols including Merkle
  verification and IndexedDB-cached Harmony hints.
- 🔒 **Merkle INDEX item-count symmetry across all five clients.** All
  five clients (TS DPF/Onion/Harmony, Rust DPF/Harmony) now probe both
  cuckoo positions unconditionally and emit `INDEX_CUCKOO_NUM_HASHES=2`
  Merkle items per INDEX query regardless of outcome. Closes the side
  channel where per-level sibling `max_items_per_group` leaked
  found-vs-not-found and cuckoo h-position. Whales also emit their
  INDEX Merkle item so whale-exclusion is verifiable. See CLAUDE.md
  "Merkle INDEX Item-Count Symmetry" for the full invariant.
- 🔒 **Merkle verification for native Rust `OnionClient`.** New
  module `pir-sdk-client/src/onion_merkle.rs` implements the OnionPIR
  per-bin Merkle subsystem (INDEX + DATA flat trees, 6-hash sibling
  cuckoo with 1 slot per bin, FHE sibling queries `0x53`/`0x55`,
  tree-top fetches `0x54`/`0x56`). `OnionClient` tracks per-bin INDEX
  hashes (both probed cuckoo positions, regardless of match) plus DATA
  bin hashes for every fetched chunk, then batch-verifies via
  `verify_onion_merkle_batch`. Failed proofs coerce results to `None`
  (matches DpfClient/HarmonyClient behavior). Gated behind the `onion`
  feature so consumers without a C++ toolchain are unaffected.
- 🔒 **INDEX PBC placement verified.** `DpfClient::query_index_level`
  and `HarmonyClient::query_single` use `my_groups[0]` (first of 3 PBC
  candidates). Confirmed correct: the server REPLICATES every
  scripthash into all 3 candidate groups at build time
  (`build/src/build_cuckoo_generic.rs:87-90`,
  `build/src/gen_4_build_merkle.rs:236-239`), so any one group is
  sufficient for retrieval. Matches the reference Rust binary
  (`runtime/src/bin/client.rs:246`: "single query, just use first") and
  every web TS / Python client (all reduce to `candGroups[0]` at N=1 via
  `planRounds`). `OnionClient::query_index_level` uses `pbc_plan_rounds`
  because it genuinely batches multiple scripthashes into one FHE query
  set — that is the N>1 generalization, not a different placement
  rule. Explanatory comments added at both single-query sites to
  prevent future re-flagging.
- **`merkle_verified: bool` on `QueryResult`.** Verification failures
  used to be silently coerced to `None`, indistinguishable from "not
  found". Now a failed proof surfaces as
  `Some(QueryResult::merkle_failed())` — `merkle_verified = false`,
  `entries = []`, `is_whale = false`. Successful verification (or a
  database without Merkle commitments) yields `merkle_verified = true`.
  `merge_delta_batch` ANDs the flag from snapshot × delta so a single
  untrusted input taints the merge. WASM exposes `merkleVerified` as a
  getter and in `toJson()`. New unit tests cover AND semantics,
  `(None, Some(del))` propagation, and `merkle_failed()` state.
- **CI integration tests against live public PIR servers.** The 12
  `#[ignore = "requires running PIR servers"]` tests in
  `pir-sdk-client/tests/integration_test.rs` now default to
  `wss://pir1.chenweikeng.com` / `wss://pir2.chenweikeng.com` (the same
  servers the web client uses) and are driven by
  `.github/workflows/pir-sdk-integration.yml` on every push/PR plus a
  daily canary cron. Configurable per-URL via env vars
  (`PIR_DPF_SERVER0_URL`, `PIR_DPF_SERVER1_URL`, `PIR_HARMONY_HINT_URL`,
  `PIR_HARMONY_QUERY_URL`, `PIR_ONION_URL`) for local runs against
  `unified_server`. Includes a new `onion_tests` module for OnionPIR
  (gated behind `--features onion`), plus three protocol fixes that
  were blocking live-server runs:
  1. **Batch wire format** — `pir-sdk-client/src/dpf.rs` was sending an
     extra leading `level` byte, putting `db_id` before the keys
     instead of as an optional trailing byte, and emitting a per-group
     `num_keys` counter. Now matches
     `runtime/src/protocol.rs::encode_batch_query` exactly:
     `[round_id u16][num_groups u8][keys_per_group u8][keys...][db_id u8]?`.
  2. **Catalog `num_dbs` size** — was decoded as u16, but the server
     encodes as u8; a single-entry catalog's `db_id=0` byte was being
     read as the high byte of `num_dbs`, pushing every subsequent
     field off by one.
  3. **TLS + frame-size** — added `rustls` with the `ring` crypto
     provider (installed lazily via `OnceLock`) plus
     `tokio-tungstenite`'s `rustls-tls-webpki-roots` feature for
     `wss://` support. Bumped the WebSocket max-message / max-frame
     size from 16 MiB to 256 MiB to accommodate fresh-sync chunk
     batches (~32 MiB against the main UTXO database).
  All 12 ignored tests now pass against the public servers in ~3m on a
  laptop.
- **HarmonyClient uses `REQ_GET_DB_CATALOG` (0x02) with legacy
  fallback.** Previously it always called the legacy
  `REQ_HARMONY_GET_INFO` (0x40), whose `ServerInfo` wire shape predates
  `DatabaseCatalog` and has no `height` or `has_bucket_merkle` fields —
  `SyncResult::synced_height` was therefore hard-wired to `0` for every
  Harmony deployment, and cache-by-height was broken. Both Harmony
  unified_server roles (hint + query) already respond to
  `REQ_GET_DB_CATALOG` (the match arm runs before the role check), so
  `HarmonyClient::fetch_catalog` now sends it over `hint_conn` first via
  the new `try_fetch_db_catalog`, returning `Ok(None)` on empty reply /
  `RESP_ERROR` / unknown variant so the legacy `fetch_legacy_info` path
  can still serve older servers. The integration test
  `test_harmony_client_sync_single` now asserts `synced_height > 0`
  against live public servers. Also deduplicated the three copies of
  `encode_request` / `decode_catalog` into a new shared
  `pir-sdk-client/src/protocol.rs` module (with 4 unit tests covering
  the wire format) — future catalog-format changes now live in one
  place instead of three.

## P0 — Blockers for "production-ready"

_(none — all P0 items closed.)_

## P1 — Correctness & robustness

- [ ] **OnionPIR LRU-eviction retry.** Server evicts clients at 100
      connections. Current `ensure_keys_registered` uses `HashSet<u8>`
      but doesn't catch mid-session eviction. Parse specific
      "client not found" server response codes and re-register.
- [ ] **Connection resilience.** WebSocket disconnects, server restarts,
      request timeouts. `WsConnection` is best-effort today; add
      auto-reconnect with backoff and per-request deadlines.
- [ ] **Thread-safety audit for `unsafe impl Sync for SendClient`.**
      Documented as safe because only `&mut self` FFI calls mutate, but
      this assumes OpenMP/SEAL static state is also safe under
      concurrent read. Worth a second pair of eyes from OnionPIR
      maintainers.

## P2 — API completeness

- [ ] **`pir-sdk-wasm`: full client wrappers.** `WasmDpfClient`,
      `WasmHarmonyClient`, `WasmOnionClient`. Currently only helpers
      (catalog, sync plan, hash funcs) are exposed; the web app still
      maintains its own TS clients. Unifying would remove a lot of
      code duplication.
- [ ] **`pir-sdk-wasm`: Merkle verification exposed to JS.**
      `verify_bucket_merkle_batch_dpf` should get a `wasm_bindgen`
      wrapper so web clients share the Rust verifier instead of
      maintaining the TS one.
- [ ] **HarmonyClient hint persistence (native).** Web client caches
      sibling hints in IndexedDB (commit `e00ecb7`). Native Rust has
      no equivalent — hints re-fetch every session. Add a file-backed
      cache keyed by db_id/height.
- [ ] **Error taxonomy.** `PirError` variants don't distinguish
      (a) Merkle verify failure, (b) server protocol version skew,
      (c) server LRU eviction, (d) transient network error. Callers
      that want to retry only on (c)/(d) can't today.
- [ ] **Observability beyond `[PIR-AUDIT]`.** Add `tracing` spans,
      per-client metrics (query count, bytes in/out, round-trip
      latency), progress callbacks for long syncs.

## P3 — Polish & ship

- [ ] **rustdoc examples per client.** `DpfClient` has a good rustdoc
      example; `HarmonyClient` and `OnionClient` don't.
- [ ] **Publishing story.** Decide if/how this ships to crates.io
      (`pir-sdk`, `pir-sdk-client`, `pir-sdk-server`) and npm
      (`pir-sdk-wasm`). Pin versioning scheme, write `CHANGELOG.md`.
- [ ] **Feature flag doc page.** `fastprp`, `alf`, `onion` — what
      each enables, what each costs (build-time, link-time),
      compatibility matrix.
- [ ] **Delta sync chain optimizations.** `compute_sync_plan`
      BFS-to-5-steps is conservative. Benchmark against realistic
      delta graphs; consider caching chain computations.
- [ ] **Clean up pre-existing `pir-core` clippy warnings**
      (`needless_range_loop`, `manual_div_ceil`) so `-D warnings`
      can go into CI for the whole workspace.
- [ ] **Dead code sweep.** `INDEX_RESULT_SIZE` and `CHUNK_RESULT_SIZE`
      in `pir-sdk-client/src/dpf.rs` are unused. Probably more
      elsewhere.

## P4 — Nice-to-have / research

- [ ] **OnionPIR large-key streaming.** Galois + GSW keys are several
      MB each; currently sent as a single WebSocket frame. Chunking
      would help on flaky links.
- [ ] **HarmonyPIR hint delta sync** (incremental hint updates across
      deltas, instead of re-fetching full hints on each height).
- [ ] **FHE params tuning benchmarks** for OnionPIR (trade query time
      vs response size across DB sizes).
- [ ] **Rate limiting / DoS protection** in `pir-sdk-server`.

## Notes

Whenever work starts on a new item, move it to "In progress" below and
link the branch / commit.

### In progress

_(none — P0 is empty. P1's `REQ_GET_DB_CATALOG` item is now closed
too, so `SyncResult::synced_height` works for Harmony. Next candidate
is **Connection resilience** (auto-reconnect / per-request deadlines
in `WsConnection`) or **OnionPIR LRU-eviction retry** depending on
whether production robustness or OnionPIR mid-session stability is
the more pressing need.)_
