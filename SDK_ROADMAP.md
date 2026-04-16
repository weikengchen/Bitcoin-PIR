# PIR SDK Roadmap

Status snapshot: the native Rust SDK has three real clients (`DpfClient`,
`HarmonyClient`, `OnionClient`) and per-bucket Merkle verification
wired into `DpfClient` only. This document tracks what's left before the
SDK is production-ready.

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

## P0 — Blockers for "production-ready"

- [ ] **🔒 Merkle verification for `OnionClient`.** Same as above.
      OnionPIR already records both cuckoo positions in its trace
      state; wiring is mechanical. Reference: web client's
      `web/src/onion-client.ts`.
- [ ] **🔒 Verify INDEX PBC placement.** `DpfClient::query_index_level`
      uses `my_groups[0]` (first of 3 PBC candidates) — the Merkle
      subagent flagged this as possibly wrong. Confirm against server
      behavior. If wrong, fan out to all 3 groups with padding
      preserved.
- [ ] **Expose `merkle_verified: bool` on `QueryResult`.** Currently
      `run_merkle_verification` silently coerces failed proofs to
      `None`, making verification failure indistinguishable from
      absence. Callers need a separate signal to audit.

## P1 — Correctness & robustness

- [ ] **OnionPIR LRU-eviction retry.** Server evicts clients at 100
      connections. Current `ensure_keys_registered` uses `HashSet<u8>`
      but doesn't catch mid-session eviction. Parse specific
      "client not found" server response codes and re-register.
- [ ] **Connection resilience.** WebSocket disconnects, server restarts,
      request timeouts. `WsConnection` is best-effort today; add
      auto-reconnect with backoff and per-request deadlines.
- [ ] **Run ignored integration tests in CI.** All 8
      `#[ignore = "requires running PIR servers"]` tests never execute.
      Spin up a fixture server in a GitHub Actions job (or
      `testcontainers`) and drop the `ignore` where safe.
- [ ] **Thread-safety audit for `unsafe impl Sync for SendClient`.**
      Documented as safe because only `&mut self` FFI calls mutate, but
      this assumes OpenMP/SEAL static state is also safe under
      concurrent read. Worth a second pair of eyes from OnionPIR
      maintainers.
- [ ] **Test HarmonyClient end-to-end against a live two-server
      deployment.** Integration tests exist but are ignored.

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

_(none — P0 #1 moved to Completed.)_
