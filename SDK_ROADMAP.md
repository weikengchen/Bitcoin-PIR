# PIR SDK Roadmap

Status snapshot: the native Rust SDK has three real clients (`DpfClient`,
`HarmonyClient`, `OnionClient`) and per-bin Merkle verification wired
into all three. This document tracks what's left before the SDK is
production-ready.

Items marked 🔒 touch the padding/privacy invariants in CLAUDE.md
("Query Padding", "Cuckoo Hashing and Not-Found Verification"). Any
change near them needs extra care — do not optimize away padding.

## Completed

- **P3 sweep: rustdoc + dead-code + clippy.** Three P3 items landed
  together as a polish pass:
  * *Rustdoc examples per client.* `DpfClient`, `HarmonyClient`, and
    `OnionClient` each now carry a struct-level rustdoc block with a
    runnable-looking `ignore`'d `#[tokio::main]` example plus
    intra-doc links into the methods that matter. `DpfClient`'s doc
    covers the two-server DPF XOR basis and shows both a basic
    `query_batch` call and a `sync` call driven by a catalog.
    `HarmonyClient`'s doc covers the hint + query two-server
    architecture, PRP backend selection (Hoang default;
    `fastprp`/`alf` feature-gated), and demonstrates the
    hint-cache-resume pattern via `with_hint_cache_dir` +
    `load_hints_bytes` / `save_hints_bytes`. `OnionClient`'s doc
    covers the Microsoft SEAL BFV basis, Galois + GSW key
    lifecycle, server LRU eviction and the `SessionEvicted` retry
    surface (via `onion_merkle.rs::onionpir_batch_rpc`), and the
    `onion` cargo feature gating (native-only; SEAL doesn't
    compile to wasm32). All three examples use `ignore` since they
    require a live PIR server; they serve as shape/signature
    documentation rather than doctests.
  * *Dead code sweep.* Five removals + two feature-gated allows:
    (1) unused `INDEX_RESULT_SIZE` / `CHUNK_RESULT_SIZE` constants
    in `pir-sdk-client/src/dpf.rs` replaced with NOTE comments
    pointing to `runtime/src/eval.rs` for the canonical values;
    (2) `use std::path::{Path, PathBuf}` in
    `pir-sdk-client/src/hint_cache.rs` split so `Path` is
    `#[cfg(not(target_arch = "wasm32"))]`-gated (only the native
    filesystem helpers use it; `PathBuf` stays unconditional for
    the XDG resolver which runs on both targets);
    (3) dead `derived_key: [u8; 16]` and `group_id: u32` fields on
    `HarmonyGroup` in `harmonypir-wasm/src/lib.rs` removed —
    deserialize takes them as args and re-derives the per-group
    RNG seed, so storing them in the struct was a leftover from an
    earlier factoring. Both construction sites (`new_with_backend`
    and `deserialize`) now `let _ = key; let _ = group_id;` before
    the `Ok(HarmonyGroup { ... })` so the arguments are
    deliberately consumed; (4) non-root `[profile.release]`
    stanzas in `pir-sdk-wasm/Cargo.toml` and
    `harmonypir-wasm/Cargo.toml` removed (Cargo ignores profile
    stanzas in non-root packages, so these were misleading
    documentation at best) and replaced with a cross-reference
    comment block recommending the canonical workspace-level
    `wasm-release` profile pattern; (5) two onion-feature
    dead-code warnings gated: `OnionTreeTopCache.cache_from_level`
    (parse-only metadata — kept to preserve schema symmetry with
    the per-bucket `merkle_verify.rs` version, which DOES consume
    it, in case a future walker needs absolute level indices) and
    `onion_leaf_hash` (public API surface for external consumers
    of the `onion` feature to reproduce leaf hashing without
    reaching into `pir_core::merkle`; exercised by
    `test_onion_leaf_hash_matches_sha256`), both with `#[allow(
    dead_code)]` + multi-line justification comments.
  * *`pir-core` clippy cleanup.* All 5 pre-existing warnings
    cleared so `-D warnings` can now safely go into CI for the
    whole workspace. Three `needless_range_loop` refactors:
    (a) `pir-core/src/hash.rs`'s `derive_groups_3` and
    `derive_int_groups_3` dup-rejection inner loops collapsed to
    `groups.iter().take(count).any(|&g| g == group)`;
    (b) `pir-core/src/pbc.rs::pbc_plan_rounds` refactored to
    `for (g, owner) in group_owner.iter().enumerate().take(num_groups) { ... }`
    so `g` continues to serve as both the `group_owner` index and
    the pushed group ID (the canonical fix for this lint — an
    explicit comment now explains why enumerate is the right
    shape); (c) `pir-core/src/cuckoo.rs::build_int_keyed_table`
    refactored to `for (i, id) in ids.iter().enumerate() { ... }`
    since the panic message's `ids[i]` lookup is satisfied by the
    `id` iter value. Plus one `manual_div_ceil` fix:
    `pir-core/src/merkle.rs::compute_tree_top_cache` at line 301
    changed from `(prev.len() + arity - 1) / arity` to the stable
    (Rust 1.73+) `prev.len().div_ceil(arity)`.

  Verification: `cargo test -p pir-core --lib` = 25/25,
  `cargo test -p pir-sdk --lib` = 41/41, `cargo test -p
  pir-sdk-client --lib` = 116/116, `cargo test -p pir-sdk-wasm
  --lib` = 49/49; `cargo build --target wasm32-unknown-unknown
  -p pir-sdk-client` / `-p pir-sdk-wasm` / `-p harmonypir-wasm`
  all clean; `cargo check -p pir-sdk-client --features onion`
  (C++/SEAL) clean. 🔒 Padding invariants unaffected — the
  sweep is pure polish. Rustdoc additions are documentation-only;
  dead-code removals never touched the query path; clippy
  refactors are semantically equivalent per-loop restructurings.
  None of the three layers can influence K=75 INDEX / K_CHUNK=80
  CHUNK / 25-MERKLE padding or the INDEX-Merkle item-count
  symmetry invariant.

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
- **Connection resilience: per-request deadlines + reconnect-with-
  backoff.** `WsConnection` now wraps every `send` / `recv` /
  `roundtrip` in `tokio::time::timeout` (default 90s, configurable via
  `with_request_timeout`), and wraps the initial TLS/WebSocket
  handshake in a separate `connect_timeout` (default 30s). A wedged
  server no longer hangs a query indefinitely; the caller gets
  `PirError::Timeout` in bounded time and can decide what to do.
  `connect_with_backoff(url, RetryPolicy)` replaces the single-shot
  `connect` internally — the default policy is 5 attempts with
  250ms→5s exponential backoff, which rides out brief server restarts
  without punishing an actually-down server. `reconnect(&mut self)`
  re-handshakes to the same URL using the stored retry policy and
  replaces the underlying sink/stream in place, giving higher-level
  clients a clean escape hatch when server-side state is lost (Harmony
  hints / Onion FHE keys must be re-negotiated after, since a fresh
  server session has no record of them). Seven new unit tests cover
  retry-policy shape, backoff doubling + clamping, overflow safety,
  and DNS-fail / route-unreachable timeout paths; a new live-server
  integration test `test_wsconnection_reconnect_roundtrip` proves
  the transport actually works post-`reconnect`. `RetryPolicy` and
  the default constants are re-exported from the crate root so
  downstream users can dial a custom policy.
- **OnionPIR LRU-eviction retry in query rounds.** The SEAL
  `KeyStore` on the OnionPIR server evicts registered clients FIFO at
  the 100-client cap; any subsequent `answer_query` for an evicted
  client panics inside SEAL and the server's `catch_unwind` surfaces
  it as an all-empty batch response. `OnionClient::query_index_level`
  and `query_chunk_level` now route their batch sends through a
  single chokepoint `onionpir_batch_rpc` that detects this signal
  (`batch_looks_evicted` — every slot in a ≥1-slot batch is empty,
  which can never happen to a legitimate FHE response because all
  queries in a batch share one `client_id`), drops the
  `registered[db_id]` flag, calls `register_keys(db_id)` to replay
  our Galois + GSW keys, and retries the exact same query once.
  Falling back to `PirError::ServerError` after a second all-empty
  response avoids a retry loop when the real failure is something
  other than eviction (FHE param drift, unreachable DB, etc.). The
  Merkle sibling path in `onion_merkle.rs` is intentionally left
  uncovered — its failure mode ("Merkle proof fails → coerce query
  result to `merkle_failed()`") is already conservative, so silent
  post-eviction Merkle failures surface as untrusted-⇒-absent rather
  than stale cache. Three new unit tests lock the `batch_looks_evicted`
  contract (all-empty / mixed / zero-length); the function is kept
  as a free-standing `pub(crate)` so it can be tested on non-`onion`
  builds.
- **Thread-safety audit for `unsafe impl Sync for SendClient`.**
  Walked the entire public API of `onionpir::Client` @ rev `946550a`
  (pinned in our `Cargo.toml`): only two methods take `&self` —
  `id(&self) -> u64` and `export_secret_key(&self) -> Vec<u8>`.
  Everything else (query generation, key generation, response
  decryption) is `&mut self`. Audited the C++ side too: both
  read-only FFI entry points accept `const OnionPirClient&` and
  delegate to `client.inner.get_client_id()` (pure integer read) and
  `SecretKey::save(stream)` into a local `stringstream` (SEAL const
  member; uses the default thread-safe `MemoryPool`). The Sync impl
  is therefore sound, but the audit also noted that the SDK's code
  paths never actually share `&SendClient` across threads today —
  `FheState.level_clients` is only reached via `&mut OnionClient`, so
  the Sync impl exists purely to satisfy the `PirClient: Send + Sync`
  trait bound. The long-form safety comment in
  `pir-sdk-client/src/onion.rs` now records this audit explicitly.
  Added compile-time `assert_send_sync::<OnionClient>` / `<SendClient>`
  / `<FheState>` probes so regressions (e.g. adding an `Rc<>` field)
  fail at the declaration site instead of at a distant `PirClient`
  trait-usage site. Added a feature-gated concurrency smoke test
  (`test_send_client_sync_smoke`) that spawns 8 threads sharing
  `Arc<SendClient>` and hammers `id` + `export_secret_key` from each;
  the test runs in the `integration-onion` CI job (plain
  `cargo test -p pir-sdk-client` doesn't need the C++ toolchain).
  `onion_merkle.rs::SibSendClient` also picked up a compile-time
  `assert_send` probe and a cross-reference to this audit.
- 🔒 **`pir-sdk-wasm`: per-bucket bin-Merkle verifier exposed to JS**
  (P2 #2). The pure-crypto half of the verifier moved into a new
  `pir-sdk-wasm/src/merkle_verify.rs` module. What's exposed:
  * `WasmBucketMerkleTreeTops.fromBytes(blob)` parses the server's
    `REQ_BUCKET_MERKLE_TREE_TOPS` (0x34) payload — same wire format
    as the native Rust parser (`pir-sdk-client::merkle_verify::parse_tree_tops`)
    and the TS parser in `web/src/merkle-verify-bucket.ts`, so
    switching callers over is a drop-in.
  * `bucketMerkleLeafHash(bin_index, content)`,
    `bucketMerkleParentN(children_flat)`, and `bucketMerkleSha256(data)`
    are thin wrappers over `pir_core::merkle::{compute_bin_leaf_hash,
    compute_parent_n, sha256}`. Leaf hashes and arity-N parent hashes
    are the primitives the TS verifier rolls by hand today.
  * `xorBuffers(a, b)` folds the two DPF shard responses —
    length-mismatched inputs return an empty array rather than
    throwing, so callers get a normal "verification failed" path.
  * `verifyBucketMerkleItem(bin_index, content, pbc_group,
    sibling_rows_flat, tree_tops)` walks one proof from leaf to the
    cached root. `sibling_rows_flat` is `cache_from_level × 256B` of
    pre-fetched, already-XOR'd sibling rows (bottom-up), so JS keeps
    full ownership of the K-padded sibling-batch network dance and
    the Rust side only owns the pure SHA-256 walk. Failures return
    `false` instead of throwing — matches the
    "untrusted-⇒-merkle_failed" convention used by the native
    clients.

  The **network** half — K-padded DPF sibling batches, per-level
  multi-pass for items sharing a PBC group, tree-top fetch — stays in
  JS. This is a deliberate trade-off: `pir-sdk-client`'s transport
  layer (`tokio-tungstenite`, multi-threaded tokio, `rustls` with the
  `ring` provider) does not compile to `wasm32-unknown-unknown`, so a
  WASM-side transport has no host to sit on until the transport layer
  is pulled out into a trait (tracked as P2 #1a). Shipping the
  pure-crypto part first is the highest-leverage incremental win:
  it's the bulk of the cryptographic duplication (the TS verifier is
  ~400 LOC), it's the part most prone to subtle bugs, and it lets the
  web client drop the leaf/parent/sha256/tree-top code without
  waiting on the transport refactor.

  Thirteen native unit tests cover tree-top parsing (empty / truncated
  / well-formed), hash-primitive agreement with `pir_core::merkle`,
  end-to-end walk acceptance (fully-cached tree and one-sibling-level
  tree), tamper rejection (wrong bin content, wrong bin index,
  out-of-range PBC group, tampered sibling row), and malformed-input
  graceful failure (short sibling rows, odd-length parent-N input,
  length-mismatched XOR). Verified via `cargo test -p pir-sdk-wasm`
  and the full `wasm-pack build --target web` run — the package
  builds cleanly and the new bindings show up in the generated
  `pir_sdk_wasm.d.ts`. `web/src/sdk-bridge.ts` now declares the new
  `PirSdkWasm` surface so the TS compiler sees them; rewiring the
  web client's `merkle-verify-bucket.ts` to call into them is a
  follow-up that can land independently.
- 🔒 **`pir-sdk-client`: transport abstraction — first checkpoints of
  P2 #1a.** New `pir-sdk-client/src/transport.rs` module defines a
  `PirTransport` trait (`send` / `recv` / `roundtrip` / `close` /
  `url`) via `async_trait`, so the verifier + sibling helpers can
  plug against any transport. The trait is dyn-compatible on purpose:
  a compile-time assertion (`fn assert_send<T: Send>()`) locks in
  `Box<dyn PirTransport>: Send` so a client that holds a boxed
  transport can cross `tokio::spawn`. `WsConnection` picks up a
  delegating impl (zero behaviour change — the inherent methods stay
  the primary API surface because they own connect / reconnect /
  retry / backoff, which don't generalize to a WASM `WebSocket`
  without first pulling those out separately).

  An in-memory `MockTransport` (test-only) enqueues canned responses
  and records every `send`/`roundtrip` payload — state-machine tests
  for the three clients can now run without a WebSocket or a tokio
  runtime, which is the main reason the trait exists in the first
  place. 8 new unit tests cover: trait dyn-compat + Send bound,
  `roundtrip` 4-byte length-prefix strip, `send`/`recv` prefix-keep
  asymmetry (matching `WsConnection`'s contract), `close`
  invalidating subsequent ops, URL round-trip, short-frame rejection,
  empty-queue error path, and the trait-object roundtrip path.

  Helper functions now take `&mut dyn PirTransport` instead of
  `&mut WsConnection`: `fetch_tree_tops` (per-bucket tree-top fetch),
  `DpfSiblingQuerier` (+ `new` ctor) and
  `verify_bucket_merkle_batch_dpf` (DPF sibling-batch path),
  `HarmonySiblingQuerier.query_conn` field (Harmony sibling-batch
  path), and OnionPIR's `verify_onion_merkle_batch` +
  `verify_sub_tree`. Production call sites pass `&mut WsConnection`
  and rely on Rust's unsized coercion — no caller-side code changes
  needed. `cargo check --features onion` (including the C++/SEAL
  compile of the OnionPIR crate) passes, the full 47-test
  pir-sdk-client suite passes, and the 🔒 padding invariants are
  preserved verbatim (the trait is padding-agnostic; it only moves
  opaque byte frames — the K=75 / K_CHUNK=80 / 25-MERKLE padding
  requirements are a client-side concern, not a transport one).

  What's **left** for P2 #1a (tracked as unchecked sub-items in
  P2 #1a above): (a) making the three client structs themselves
  (`DpfClient.conn0`/`conn1`, `HarmonyClient.hint_conn`/`query_conn`,
  `OnionClient.conn`) generic over `T: PirTransport` or holding
  `Option<Box<dyn PirTransport>>` — currently they still own
  concrete `WsConnection`s; and (b) the actual
  `web-sys::WebSocket`-backed WASM transport impl plus the
  cfg-gated `tokio::try_join!` → `futures::join!` swap. Both can
  land independently — (a) is pure Rust-side plumbing, (b) is an
  additive alternative transport that doesn't touch existing code.
- **TS retirement Session 1 — crypto retirement in
  `merkle-verify-bucket.ts` + neutral `web/src/types.ts`.** First of
  the six TS-retirement sessions (see "TS retirement: phased plan"
  below). Two deliverables, both landed in the web tree only (no Rust
  side touched):

  1. *Per-bucket Merkle verifier, crypto half.*
     [`web/src/merkle-verify-bucket.ts`](web/src/merkle-verify-bucket.ts)
     no longer owns any hash code. Its previous inline
     `parseTreeTops`, `ParsedTreeTops` interface, local `xorBuffers`,
     and calls to `computeBinLeafHash` / `computeParentN` /
     `ZERO_HASH` / `sha256` from the web's own `merkle.ts`/`hash.ts`
     are all gone; the verifier now drives the walk through
     six wrappers added to
     [`web/src/sdk-bridge.ts`](web/src/sdk-bridge.ts):
     `sdkBucketMerkleSha256`, `sdkBucketMerkleLeafHash`,
     `sdkBucketMerkleParentN`, `sdkXorBuffers`,
     `sdkParseBucketMerkleTreeTops` (returns the opaque
     `WasmBucketMerkleTreeTops` handle, which the caller `.free()`s
     in a `finally`), and `sdkVerifyBucketMerkleItem`. The wire loop
     — K-padded DPF sibling batches over `ManagedWebSocket`,
     per-level `maxItemsPerGroup` multi-pass for items that share a
     PBC group — stays in TS as planned. 🔒 Padding invariants
     (K=75 INDEX, K_CHUNK=80 CHUNK, 25 MERKLE) are untouched by the
     rewrite; the refactor only moves hash code from `.ts` files to
     WASM bindings, not the sibling-batch loop that owns the
     padding. Also dropped: the old rootsHex comparison against
     `info.index_roots[g]` / `info.chunk_roots[g]` — the WASM
     verifier checks internally against `top.root()` from the
     tree-tops blob, which is the same thing the native Rust path
     (`pir-sdk-client::merkle_verify`) does; the blob's
     `tree_tops_hash` integrity field binds the roots
     cryptographically, so the external-rootsHex compare was
     redundant. CHUNK trees live at global tree-top indices
     `[K..K+K_CHUNK)`, so `verifySiblingLevels` picked up a
     `groupOffset: number` parameter (0 for INDEX, `K` for CHUNK)
     that's added to `pbcGroup` before the WASM call looks up the
     right global tree. Xor length-mismatch graceful-failure path
     is preserved — `sdkXorBuffers` returns an empty array on
     length mismatch (WASM behaviour), and the pre-existing
     `row.length < BUCKET_MERKLE_SIB_ROW_SIZE` guard catches both
     that and legitimate short-response cases, setting
     per-item `failed[itemIdx] = true`.

     The file stays present for now (the wire half is the other
     ~half of its body and depends on Session 2's
     `WasmDpfClient.verifyMerkleBatch` landing before it can move
     behind WASM too); full retirement is scheduled for Session 3.

  2. *Neutral types module.* `UtxoEntry`, `QueryResult`, and
     `ConnectionState` moved out of `web/src/client.ts` into a new
     `web/src/types.ts` module (118 LOC, no runtime code, heavily
     commented). `client.ts` re-exports them so every existing
     `import { QueryResult } from './client.js'` call site keeps
     working unchanged; `web/src/sync-merge.ts` and
     `web/src/onionpir_client.ts` were moved off the `client.ts`
     import and onto `./types.js` directly, breaking the circular
     import hazard that previously forced a non-DPF consumer
     (OnionPIR) to transitively pull `BatchPirClient`. This also
     un-blocks Session 3's eventual `client.ts` deletion — the
     types outlive the client.

  Verification: `npx tsc --noEmit` shows zero new TS errors (the
  three pre-existing ones — `ws.test.ts:38` `ArrayBuffer`
  variance, `harmonypir_worker.ts:108` missing `HarmonyBucket`
  type, `onionpir_client.ts:884` `null` vs `undefined` — match the
  baseline on `HEAD~`); `npx vitest run` passes 88/88 across 7
  test files (including `sync-merge.test.ts`'s 28 tests, which
  exercise both the DPF `QueryResult` and the Harmony one against
  the new import paths); `npx vite build` produces the same
  307 KB main bundle + 500 KB `pir_sdk_wasm` split. LOC impact:
  `client.ts` -54, `sdk-bridge.ts` +102 (six new wrappers +
  `requireSdkForMerkle` helper + one re-exported type),
  `types.ts` +118 (new), `merkle-verify-bucket.ts` ±3 (fully
  rewritten internals, close to the same total size because
  documentation grew to explain the dropped rootsHex compare +
  the groupOffset contract; the crypto code is gone but the wire
  loop and its comments stay). Sessions 2 and 4 remain unblocked
  and can start in either order.
- **TS retirement Session 2 — DPF surface extensions.** Second of
  the six TS-retirement sessions. The WASM DPF surface now matches
  everything the web TS `BatchPirClient` exposes, so Session 3 (DPF
  cutover) is unblocked. Deliverables:

  1. *Native inspector state on `QueryResult`.*
     `pir-sdk/src/types.rs` picked up a new `BucketRef { pbc_group,
     bin_index, bin_content }` struct plus three optional fields on
     `QueryResult` — `index_bins: Vec<BucketRef>`, `chunk_bins:
     Vec<BucketRef>`, and `matched_index_idx: Option<usize>`. The
     fields default to empty / `None` so every existing
     `QueryResult` construction site keeps working; inspector state
     is populated only by the new `query_batch_with_inspector`
     path. Fields are serde-gated via the same
     `#[cfg_attr(feature = "serde", serde(default))]` pattern the
     other optional-state fields use, so JSON round-trips of
     pre-Session-2 shapes are still byte-identical.

  2. *Split verify on native `DpfClient`.*
     `pir-sdk-client/src/dpf.rs` gained two new methods:
     `query_batch_with_inspector(&[ScriptHash], db_id) ->
     Vec<Option<QueryResult>>` runs the full PIR + trace-collection
     path but **skips** inline Merkle verification — callers get
     `Some(QueryResult)` for every slot (not-found is synthesised
     as `QueryResult::empty()` plus inspector bins so the absence
     proof survives); and `verify_merkle_batch_for_results(&[...],
     db_id) -> Vec<bool>` consumes inspector-populated results
     (fresh or rehydrated from persisted storage) and runs the
     shared bucket-Merkle verifier to produce one `bool` per query.
     Databases without a bucket-Merkle commitment short-circuit to
     `vec![true; n]` (nothing to verify, not a failure).
     `run_merkle_verification` was refactored into four small
     helpers (`items_from_trace`, `collect_merkle_items_from_traces`,
     `items_from_inspector_result`,
     `collect_merkle_items_from_results`, `verify_merkle_items`)
     that the inline and split paths both drive. 🔒 Padding
     invariants (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) stay
     untouched — both paths go through the same padded sibling
     batches.

  3. *Observability surface on native `DpfClient`.*
     `pir-sdk/src/client.rs` added a `ConnectionState {Connecting,
     Connected, Disconnected}` enum (with stable `as_str()` labels
     — `"connecting"` / `"connected"` / `"disconnected"` — for the
     JS `onStateChange` contract) plus a `StateListener: Send +
     Sync` trait. `DpfClient` grew `set_state_listener(Option<Arc<dyn
     StateListener>>)` and now fires `Connecting → Connected` on
     handshake success (with `Disconnected` rollback on failure),
     `Connected` from `connect_with_transport`, and `Disconnected`
     from `disconnect`. Also added `server_urls() -> (&str,
     &str)` for display-only "connected to …" surfaces, and
     `sync_with_progress(&[sh], last_height, &dyn SyncProgress)`
     which reuses the pre-existing `SyncProgress` trait
     (`on_step_start` / `on_step_progress` / `on_step_complete` /
     `on_complete` / `on_error`) — progress is emitted at
     step-transition granularity (single coarse `on_step_progress`
     tick per step because `execute_step`'s inner loop is
     K-bounded and driven synchronously).

  4. *WASM wrappers (`pir-sdk-wasm/src/client.rs`).* New methods on
     `WasmDpfClient`:
     * `serverUrls(): [string, string]` — echoes the constructor
       arguments, no network I/O.
     * `queryBatchRaw(Uint8Array, db_id): Promise<WasmQueryResult[]>`
       — wraps `DpfClient::query_batch_with_inspector`; returns
       opaque `WasmQueryResult` handles whose
       `indexBins()/chunkBins()/matchedIndexIdx()` accessors are
       populated and whose inline Merkle check has been skipped.
     * `verifyMerkleBatch(results_json, db_id): Promise<bool[]>`
       — parses a JS array of `QueryResult` JSON objects (same
       shape `WasmQueryResult.toJson()` emits, including optional
       inspector fields) and runs the standalone Merkle verifier.
       Accepts round-tripped persisted results so callers can
       cache raw results and verify later.
     * `syncWithProgress(Uint8Array, last_height, progress:
       Function): Promise<WasmSyncResult>` — wasm32-only;
       installs a `JsSyncProgress` bridge that serialises each
       `SyncProgress` event as `{type: "step_start" |
       "step_progress" | "step_complete" | "complete" | "error",
       ...}` and invokes the JS function.
     * `onStateChange(cb: Function)` — wasm32-only; installs a
       `JsStateListener` that calls the JS function with the
       `ConnectionState::as_str` string on every transition.

     Both wasm32-only methods wrap the JS `Function` in a
     `SendWrapper<js_sys::Function>` so the resulting
     `StateListener` / `SyncProgress` object can cross the
     `Send + Sync` trait bounds; the wrapper panics on
     cross-thread access which is sound on wasm32's single JS
     event loop. `WasmQueryResult` picked up three new
     `#[wasm_bindgen]` getters — `indexBins()` / `chunkBins()`
     (JS arrays of `{pbcGroup, binIndex, binContent: hex}` objects)
     and `matchedIndexIdx()` (returns `undefined` for inspector-free
     results). Its `fromJson` / `toJson` round-trip the new
     inspector fields, emitting them only when non-empty so
     pre-Session-2 JSON callers see byte-identical output.
     `WasmDatabaseCatalog` picked up `getEntry(dbId)` (by-`db_id`
     lookup — returns `null` if absent, complementing the existing
     positional `getDatabase(i)`) and `hasBucketMerkle(dbId)`
     (safe `false` fallback for absent entries).

  5. *Tests.* 16 new unit tests across three files —
     `pir-sdk-client/src/dpf.rs` (5: state listener recorder
     fires / replaces / silences, server-URL echo, `ConnectionState`
     string contract); `pir-sdk-wasm/src/lib.rs` (11: `parse_bucket_refs`
     / `bucket_refs_to_json` round-trips including empty and
     legacy-field cases, `parse_query_result_json` minimal / full /
     legacy-`amount` forms, `database_info_to_json` surface,
     `WasmDatabaseCatalog.has_bucket_merkle` positional-vs-by-ID
     regression). Test counts: `pir-sdk` 14/14, `pir-sdk-client`
     55/55, `pir-sdk-wasm` 34/34 — full suite green. `cargo build
     --target wasm32-unknown-unknown -p pir-sdk-wasm` clean;
     `wasm-pack build --target web` emits
     `pkg/pir_sdk_wasm.d.ts` with all the new TypeScript
     declarations (`serverUrls`, `queryBatchRaw`,
     `verifyMerkleBatch`, `syncWithProgress`, `onStateChange`,
     catalog accessors, `QueryResult` inspector getters).

     🔒 Padding invariants preserved — all new surfaces route
     through the native `DpfClient`, which owns the K / K_CHUNK /
     25-MERKLE padding. The wrappers are thin translation layers
     and cannot bypass them.

     *Scope discipline.* DPF-only as planned. `WasmHarmonyClient`
     is unchanged (Session 5); `WasmOnionClient` does not exist
     (SEAL doesn't compile to wasm32). The `BucketRef` inspector
     fields exist on every `QueryResult` regardless of backend,
     but `HarmonyClient::query_batch_with_inspector` and
     `OnionClient::query_batch_with_inspector` are not yet wired
     — Harmony path is a Session 5 deliverable, Onion stays on
     TS.
- **TS retirement Session 3 — DPF cutover.** Third of the six
  TS-retirement sessions. `BatchPirClient` (883 LOC) and
  `merkle-verify-bucket.ts` (420 LOC) — 51 KB / ~1300 LOC of
  hand-rolled DPF + Merkle verifier TypeScript — have been removed
  from the web client in favour of a thin adapter over
  `WasmDpfClient`. What landed:

  1. *Adapter shim.* New
     [`web/src/dpf-adapter.ts`](web/src/dpf-adapter.ts) (~400 LOC)
     exports `BatchPirClientAdapter` with the same public surface as
     the deleted `BatchPirClient`: `connect` / `disconnect` /
     `isConnected` / `getConnectedSockets` / `getCatalog` /
     `getCatalogEntry(dbId)` / `hasMerkle` / `hasMerkleForDb(dbId)` /
     `getMerkleRootHex` / `getMerkleRootHexForDb(dbId)` / `queryBatch` /
     `queryDelta` / `verifyMerkleBatch`, plus `onConnectionStateChange`
     / `onLog` / `onSyncProgress` configuration hooks. Internally it
     owns two `ManagedWebSocket` side-channels (for
     `REQ_GET_INFO_JSON` + `REQ_GET_DB_CATALOG` + `REQ_RESIDENCY` —
     diagnostic wire traffic the WASM client doesn't expose) and a
     single `WasmDpfClient` (for the PIR query + Merkle verify rounds).
     A `WeakMap<QueryResult, WasmQueryResult>` stash lets the adapter
     pass fresh query handles straight back to `verifyMerkleBatch`
     without a JSON round-trip; externally-sourced results (e.g.
     rehydrated from persisted storage) fall through a
     `queryResultToJson` helper that reconstructs the WASM-compatible
     JSON shape. A `translateWasmResult` helper converts
     `WasmQueryResult` → legacy `QueryResult` (hex-decode `txid` /
     `binContent`, lift `matchedIdx` to the primary-bin convention
     the UI expects, derive `allIndexBins` / `chunkPbcGroups` /
     `chunkBinIndices` / `chunkBinContents` from the inspector
     fields).

  2. *WASM plumbing: raw chunk bytes round-trip.*
     [`pir-sdk-wasm/src/lib.rs`](pir-sdk-wasm/src/lib.rs)
     `parse_query_result_json` grew a hex-decode branch for the
     optional `rawChunkData` field (symmetric with
     `WasmQueryResult.toJson()`'s existing hex-encode of
     `raw_chunk_data`). This is the last byte-exact field the
     adapter's verify-time JSON round-trip needs so persisted results
     survive `fromJson` → `verifyMerkleBatch` without losing the raw
     chunk payload. A new unit test
     `parse_query_result_json_round_trips_raw_chunk_data` locks in
     the positive round-trip (`hex_encode(bytes)` → parse →
     `raw_chunk_data == bytes`); the invalid-hex error path is
     intentionally not asserted in unit tests because
     `JsError::new(...)` panics on non-wasm32 targets — the same
     pattern already guards the `txid` field, so the error surface
     is covered by existing invariants.

  3. *Call-site rewire.* `web/index.html` swapped the ctor: `new
     BatchPirClient({ ... })` → `new BatchPirClientAdapter({ ... })`,
     same config shape. Every `queryBatch` / `queryDelta` /
     `verifyMerkleBatch` / `getCatalog` / `hasMerkle` /
     `getConnectedSockets` call site kept working without further
     edits — the adapter preserves the signatures verbatim. The
     `ManagedWebSocket` side-channels still feed the residency /
     server-info diagnostic panels.

  4. *File deletions.* `web/src/client.ts` (35,391 bytes — the old
     `BatchPirClient` plus `ConnectionState` / `UtxoEntry` /
     `QueryResult` type aliases, which Session 1 already duplicated
     into `web/src/types.ts`) and `web/src/merkle-verify-bucket.ts`
     (16,411 bytes — the pre-WASM DPF sibling-batch wire loop + the
     crypto half Session 1 already routed through
     `sdk-bridge.ts`) are gone. `web/src/__tests__/sync-merge.test.ts`
     migrated from `import type { QueryResult, UtxoEntry } from
     '../client.js'` to `from '../types.js'`;
     `web/src/index.ts`'s public re-export list dropped
     `BatchPirClient` / `createBatchPirClient` /
     `BatchPirClientConfig` (from `./client.js`) and added
     `BatchPirClientAdapter` (from `./dpf-adapter.js`) plus direct
     re-exports of `ConnectionState` / `UtxoEntry` / `QueryResult`
     from `./types.js`.

  5. *Accepted regressions (documented).* The adapter is a
     translation layer; three UI-surface features don't survive the
     cutover 1:1 and are deliberately left as shallow / absent:
     * *`[PIR-AUDIT]` log routing.* Native Rust `DpfClient` emits
       `[PIR-AUDIT]` lines via `log::info!`, which on wasm32 goes to
       `console.info`. There is no `onLog` hook on `WasmDpfClient` to
       thread those lines into the web UI's "Log" panel — users
       wanting audit visibility open the browser console.
     * *`queryBatch` per-batch progress.* The WASM surface exposes
       `queryBatchRaw` as a single `Promise<WasmQueryResult[]>`
       without per-batch progress ticks. The adapter's `onProgress`
       callback fires at coarser granularity (begin / end) than the
       pre-cutover per-round reports.
     * *`getConnectedSockets()`.* The WASM client's internal
       `PirTransport` sockets are hidden behind the `wasm-bindgen`
       boundary; the adapter returns only the two side-channel
       `ManagedWebSocket`s. The residency-check panel still works
       but reports diagnostic sockets rather than the actual PIR
       query sockets — functionally equivalent for residency
       purposes because both hit the same origin.

  Verification (on top of the pre-Session-3 baseline):
  `npx tsc --noEmit` = no new TypeScript errors (same three
  pre-existing ones: `ws.test.ts` `ArrayBuffer` variance,
  `harmonypir_worker.ts` missing `HarmonyBucket`,
  `onionpir_client.ts` null/undefined). `npx vite build` clean
  (`✓ built in ~270ms`, 5 assets). `npx vitest run` = 88/88 passing
  across 7 test files. `cargo test -p pir-sdk-wasm --lib` =
  35/35 passing (the Session 3 `parse_query_result_json_round_trips_raw_chunk_data`
  test is the +1 over Session 2's 34).
  `cargo test -p pir-sdk-client --lib` = 55/55 passing,
  `cargo test -p pir-sdk --lib` = 14/14 passing (both unchanged).

  🔒 Padding invariants preserved — PIR rounds still run through
  `DpfClient` → native K / K_CHUNK / 25-MERKLE padding, and the
  INDEX-Merkle item-count symmetry invariant lives in the same native
  code path. The adapter is a translation shim; it cannot bypass
  the padding.

  LOC impact: `web/src/client.ts` -883 (deleted),
  `web/src/merkle-verify-bucket.ts` -420 (deleted),
  `web/src/dpf-adapter.ts` +~400 (new),
  `web/index.html` ±2 (import + ctor swap),
  `web/src/index.ts` ±5 (re-export list shuffle),
  `web/src/__tests__/sync-merge.test.ts` ±1 (import path),
  `web/src/sdk-bridge.ts` +~30 (new `WasmDpfClient` /
  `WasmQueryResult` interface declarations + `requireSdkWasm` +
  type re-exports),
  `pir-sdk-wasm/src/lib.rs` +~15 (hex-round-trip +
  one unit test). Net: ~900 LOC of hand-rolled TS
  retired in exchange for ~450 LOC of adapter / interface /
  plumbing.

  **Sessions 4 and 5 newly unblocked for the Harmony side of the
  retirement.** Session 4 is pure Rust-side (native `HarmonyClient`
  hint persistence) — independent of the web cutover but slated as
  the precursor to Session 5 because the WASM Harmony surface needs
  byte-level cache I/O to bridge IndexedDB. Session 6 is the web
  cutover that mirrors this session's pattern for
  `HarmonyPirClient`. OnionPIR remains on TS indefinitely (SEAL
  doesn't compile to wasm32, so there is no `WasmOnionClient`
  equivalent).
- **TS retirement Session 4 — native HarmonyClient hint persistence.**
  Fourth of the six TS-retirement sessions. Closes the long-running
  "first-query latency" gap for HarmonyPIR: every `ensure_*_ready` that
  previously downloaded dozens of MiB of hint parities now short-circuits
  on a cache hit, and any `persist_hints_to_cache` call after a sync
  preserves `HarmonyGroup::query_count` + the relocation log so a
  restarted client resumes mid-session instead of starting fresh. What
  landed:

  1. *New module
     [`pir-sdk-client/src/hint_cache.rs`](pir-sdk-client/src/hint_cache.rs).*
     Self-describing binary format prefixed with the magic bytes
     `PSH1`, a `u16` format version, a 32-byte SHA-256 of the module's
     `SCHEMA_STRING` constant, and a 16-byte
     [`CacheKey::fingerprint`] that folds
     `(master_prp_key, prp_backend, db_id, height, index_bins,
     chunk_bins, tag_seed, index_k, chunk_k)` through `pir_core::merkle::sha256`.
     Main + sibling `HarmonyGroup` blobs follow in length-prefixed
     records (`(group_id u8, len u32, bytes)` for main,
     `(level u8, group_id u8, len u32, bytes)` for siblings). Keyed
     on the fingerprint only — the master PRP key itself never hits
     disk, so even someone who can `ls` the cache directory can't
     extract it. Exposed functions: `encode_hints`, `decode_hints`
     (with optional `expected_fingerprint`
     cross-check), `CacheKey::from_db_info`, `CacheKey::filename`
     (hex-of-fingerprint + `.hints`), `HintBundle::{new,
     has_siblings, total_hint_bytes}`, `resolve_default_cache_dir`
     (`$PIR_SDK_HINT_CACHE_DIR` → `$XDG_CACHE_HOME/pir-sdk/hints`
     → `$HOME/.cache/pir-sdk/hints`, returns `None` on wasm32),
     `read_cache_file` (returns `Ok(None)` on `NotFound` — cold
     cache is not an error), `write_cache_file` (atomic rename via
     `<path>.hints.tmp` → `<path>.hints`). 21 unit tests cover
     fingerprint determinism + every varying field
     (master_key, backend, height, shape, db_id), encode/decode
     round-trip (empty bundle + groups + siblings), deterministic
     sort order (HashMap insertion order doesn't leak into the
     encoded bytes), all four reject paths (bad magic / bad format
     version / bad schema hash / wrong fingerprint), truncated
     buffers, tiny-buffer short-circuit, filename stability, and
     the pure-function env-var resolver's four decision branches.

  2. *`HarmonyClient` persistence surface.*
     [`pir-sdk-client/src/harmony.rs`](pir-sdk-client/src/harmony.rs)
     picked up a new `hint_cache_dir: Option<PathBuf>` field plus
     eight public methods. Builder-style
     `with_hint_cache_dir<P: Into<PathBuf>>(self, dir) -> Self`
     and mutable-reference `set_hint_cache_dir(Option<PathBuf>)`
     configure the cache; `hint_cache_dir()` reads it back.
     `save_hints_bytes()` walks `loaded_db_id` + catalog to
     serialise all four group maps
     (`index_groups` / `chunk_groups` / `index_sib_groups` /
     `chunk_sib_groups`) into one `encode_hints` blob, returning
     `Ok(None)` when nothing's loaded.
     `load_hints_bytes(&[u8], &DatabaseInfo)` fingerprint-checks
     the blob against the caller's master key + `DatabaseInfo`,
     then rehydrates every group via
     `HarmonyGroup::deserialize(bytes, &master_prp_key, group_id)`
     with the same `group_id` layout used by
     `ensure_*_groups_ready` — main INDEX = g,
     main CHUNK = k_index + g, INDEX sib L g = (k_index + k_chunk)
     + L*k_index + g, CHUNK sib L g = (k_index + k_chunk)
     + index_sib_levels*k_index + L*k_chunk + g.
     `persist_hints_to_cache` / `restore_hints_from_cache` wrap
     the byte-level pair with filesystem I/O and
     `log::info!("[PIR-AUDIT] …")` tracing. Private helpers
     `cache_path_for` + `load_bundle_into_groups` keep path /
     deserialise logic separate from the public surface.

  3. *`ensure_*_groups_ready` integration.*
     `ensure_groups_ready` now consults `restore_hints_from_cache`
     before the `HarmonyGroup::new_with_backend` + network fetch
     path — on cache hit it returns immediately, skipping two
     `REQ_HARMONY_HINTS` roundtrips. Cache miss / reject falls
     through to the existing fetch, then writes the fresh blob
     back with `persist_hints_to_cache` (warning-logged on
     failure so a read-only cache dir doesn't wedge live queries).
     `ensure_sibling_groups_ready` tightened its early-return
     check from "any siblings loaded" to "group counts match the
     server-advertised `index_sib_levels * k_index` +
     `chunk_sib_levels * k_chunk`" — a latent correctness bug
     where a cache restored from an older snapshot with fewer
     levels would serve stale proofs. After fetching fresh
     sibling hints it re-persists the combined main+sibling blob
     so a warm restart gets everything via one `read_cache_file`.

  4. *Unit tests.* 12 new tests in `harmony::tests` cover the
     client-level surface: `with_hint_cache_dir_sets_and_reads`,
     `set_hint_cache_dir_mutates_and_clears`,
     `save_hints_bytes_returns_none_when_nothing_loaded`,
     `save_hints_bytes_errors_when_catalog_missing`,
     `save_and_load_hints_bytes_round_trips_main_groups`
     (populates groups via a local `populate_main_groups` helper
     that mirrors `ensure_groups_ready` minus the network fetch),
     `load_hints_bytes_rejects_master_key_mismatch`,
     `load_hints_bytes_rejects_shape_mismatch` (different
     `index_bins` → fingerprint mismatch),
     `persist_and_restore_hints_to_cache_round_trips` (full
     filesystem path + different-master-key cold-cache assertion),
     `restore_hints_from_cache_returns_false_when_dir_unset`,
     `restore_hints_from_cache_returns_false_when_file_missing`,
     `persist_hints_to_cache_is_noop_when_nothing_loaded`,
     `cache_path_for_is_none_when_dir_unset`,
     `cache_path_for_uses_fingerprint_filename` (verifies
     `parent/<32-hex>.hints` shape).

  Verification:
  `cargo test -p pir-sdk-client --lib` = **89/89 passing** (76
  pre-Session-4 + 13 new: 12 `harmony::tests` + 1 `hint_cache::tests`
  filesystem round-trip). `cargo build --target wasm32-unknown-unknown
  -p pir-sdk-client` = clean (3 pre-existing warnings, none from
  Session 4). `cargo check -p pir-sdk-client --features onion` =
  clean (4 pre-existing warnings). `cargo test -p pir-sdk --lib` =
  14/14, `cargo test -p pir-sdk-wasm --lib` = 35/35, both unchanged.

  🔒 Padding invariants preserved — `save_hints_bytes` /
  `load_hints_bytes` only shuttle the already-computed
  `HarmonyGroup` state; K / K_CHUNK / 25-MERKLE padding plus the
  INDEX-Merkle item-count symmetry invariant live in the
  unchanged `query_single` + `ensure_*_groups_ready` code paths.
  The cache fingerprint includes `master_prp_key`, so cross-client
  cache reuse is impossible — a stolen cache file on a different
  machine (with a different key) fails the fingerprint check and
  falls through to a fresh network fetch. The atomic `.hints.tmp`
  rename means a crash mid-write leaves the prior cache file
  intact rather than corrupted.

  LOC impact: `pir-sdk-client/src/hint_cache.rs` +~640 (new
  module, ~180 LOC of code + 21 unit tests). `pir-sdk-client/src/harmony.rs`
  +~430 (~330 LOC of public methods + helpers + 12 unit tests).
  `pir-sdk-client/src/lib.rs` ±1 (module registration). No net
  LOC reduction yet — Sessions 5 and 6 deliver the TS-deletion
  payoff (Session 5 adds `WasmHarmonyClient.saveHints /
  loadHints` on top of this module; Session 6 deletes
  `web/src/harmonypir_client.ts` 2151 LOC).

  **Session 5 is now unblocked.** The byte-level API
  `save_hints_bytes` / `load_hints_bytes` is exactly what Session
  5's `WasmHarmonyClient.saveHints(): Uint8Array` + `loadHints(bytes,
  db_info): void` bindings will wrap — the wasm32 target
  short-circuits all filesystem calls (the new
  `cfg(not(target_arch = "wasm32"))` gates on
  `read_cache_file` / `write_cache_file` / `persist_hints_to_cache` /
  `restore_hints_from_cache`'s body), so Session 5's bindings
  route through the bytes API directly and IndexedDB plumbing
  stays in the web client. Session 6 (web Harmony cutover) then
  mirrors Session 3's pattern.
- **TS retirement Session 5 — Harmony WASM surface extensions.**
  Fifth of the six TS-retirement sessions. Extends the native
  `HarmonyClient` with the Session-2-parity surface (observer hooks,
  inspector split-verify, DB-switch + hint-stats API) and bridges
  the full surface through `WasmHarmonyClient` so Session 6 can
  drop an adapter over it and delete `harmonypir_client.ts`. What
  landed:

  1. *Native `HarmonyClient` surface parity with DPF (Session 2).*
     New imports in
     [`pir-sdk-client/src/harmony.rs`](pir-sdk-client/src/harmony.rs)
     for `BucketRef`, `ConnectionState`, `StateListener`,
     `SyncProgress`, and `Arc`. Six new **translator helpers**
     convert Harmony's `QueryTraces` (the PIR-round inspector
     state) into SDK-level `BucketMerkleItem` (the verification
     layer's currency) and `BucketRef` (the JSON-ready inspector
     currency): `items_from_trace`,
     `collect_merkle_items_from_traces`,
     `items_from_inspector_result`,
     `collect_merkle_items_from_results`,
     `index_trace_to_bucket_ref`, `chunk_trace_to_bucket_ref`.
     Existing `run_merkle_verification` refactored to delegate
     to a new **`verify_merkle_items` shared backend**
     (tree-top fetch, sibling-group ensure, `HarmonySiblingQuerier`
     driven by `verify_bucket_merkle_batch_generic` with
     `std::mem::take` to disjoint-borrow sibling maps and
     `query_conn`, verdict aggregation) — same behaviour, now
     reusable from split-verify. New public surface (all
     mirroring DPF signatures so the WASM wrapper can share the
     same JS-facing contract):

     * `server_urls(&self) -> (&str, &str)` — returns
       `(hint_url, query_url)` in constructor order. Safe any
       time; no connection state required.
     * `set_state_listener(&mut self, Option<Arc<dyn StateListener>>)`
       + private `notify_state(ConnectionState)` fired in
       `connect_with_transport` (Connected), `connect`
       (Connecting → Connected on success, Disconnected on
       dial error), `disconnect` (Disconnected).
     * `query_batch_with_inspector(...) -> Vec<Option<QueryResult>>`
       — front-loads `ensure_groups_ready` (hint-fetch errors
       surface upfront, mirroring DPF), runs `query_single` per
       scripthash, translates traces into
       `QueryResult.{index_bins, chunk_bins, matched_index_idx}`
       inspector fields, synthesises empty `QueryResult` for
       not-found (so the absence-proof bins are preserved for
       verification). 🔒 Padding preserved — delegates to the
       same native round code that enforces K=75 INDEX / K_CHUNK=80
       CHUNK / 25-MERKLE.
     * `verify_merkle_batch_for_results(...) -> Vec<bool>` —
       no-op when `!has_bucket_merkle` (returns all `true`);
       otherwise `collect_merkle_items_from_results` +
       `verify_merkle_items`, maps `Option<bool>` to `bool` via
       `.unwrap_or(true)` (None ⇒ nothing to verify ⇒ pass).
     * `sync_with_progress(&mut self, &[ScriptHash],
       Option<u32>, &dyn SyncProgress) -> SyncResult` — drives
       the plan through `on_step_start` / `on_step_progress` /
       `on_step_complete` / `on_complete` / `on_error`.
     * **DB-switch + hint-stats API** (new surface, no DPF
       counterpart): `db_id(&self) -> Option<u8>` mirrors
       `loaded_db_id`; `set_db_id(u8)` is idempotent when the
       id matches, otherwise `invalidate_groups()` (clears main
       AND sibling groups — different db has different tree
       tops, so stale siblings would fail verification);
       `min_queries_remaining() -> Option<u32>` folds the min
       across all four group maps (index / chunk / index-sib /
       chunk-sib); `estimate_hint_size_bytes() -> usize` calls
       `save_hints_bytes` and returns the length (0 on error);
       `cache_fingerprint(&DatabaseInfo) -> [u8; 16]` is a pure
       function of `(master_prp_key, prp_backend, db_info)`
       returning the exact same 16-byte prefix embedded in
       `save_hints_bytes` blob headers and used as the on-disk
       `.hints` filename stem. Nine new unit tests:
       `RecordingListener` + three `state_listener_*` tests
       (fire-on-connect, None silences, replace swaps cleanly),
       `server_urls_returns_configured_urls`,
       `db_id_roundtrip_with_same_id_is_noop`,
       `set_db_id_different_invalidates_all_groups`,
       `min_queries_remaining_aggregates_across_group_maps`,
       `estimate_hint_size_bytes_matches_save_hints_length`,
       `cache_fingerprint_is_stable_and_matches_blob_header`.

  2. *`WasmHarmonyClient` bindings* in
     [`pir-sdk-wasm/src/client.rs`](pir-sdk-wasm/src/client.rs).
     New JS-visible methods wrapping the native surface:
     `serverUrls(): [string, string]`,
     `queryBatchRaw(Uint8Array, db_id): Promise<WasmQueryResult[]>`,
     `verifyMerkleBatch(results_json, db_id): Promise<bool[]>`,
     `dbId(): number | null`,
     `setDbId(number)`,
     `minQueriesRemaining(): number | null`,
     `estimateHintSizeBytes(): number`,
     `fingerprint(WasmDatabaseCatalog, db_id): Uint8Array`
     (rejects `JsError` when db_id missing from catalog),
     `saveHints(): Uint8Array | null`,
     `loadHints(bytes, WasmDatabaseCatalog, db_id): void`
     (rejects `JsError` on fingerprint mismatch or missing db_id).
     A new wasm32-only `impl WasmHarmonyClient` block adds
     `syncWithProgress(script_hashes, last_height, progress_fn): Promise<WasmSyncResult>`
     (bridges `js_sys::Function` via the shared `JsSyncProgress`
     adapter with `SendWrapper<js_sys::Function>`) and
     `onStateChange(cb: Function): void` (same pattern via
     `JsStateListener`, callback gets `"connecting"` /
     `"connected"` / `"disconnected"` strings). A new
     `pub(crate) fn inner() -> &DatabaseCatalog` on
     `WasmDatabaseCatalog` (in `pir-sdk-wasm/src/lib.rs`) lets
     the Harmony wrapper look up `DatabaseInfo` by `db_id`
     without a JSON round-trip. Four new native-safe unit tests
     in `pir-sdk-wasm::client::tests`:
     `wasm_harmony_db_id_defaults_to_none`,
     `wasm_harmony_min_queries_remaining_none_when_empty`,
     `wasm_harmony_estimate_hint_size_zero_when_empty`,
     `wasm_harmony_inner_server_urls_match_constructor`.
     (`Uint8Array`-returning methods can't be native-tested
     because the `wasm-bindgen` import panics outside wasm32 —
     same pattern guarding `fingerprint` / `saveHints` in this
     session and `JsError::new` / `txid` hex-parse in Sessions 2-3.)

  3. *Worker-pool strategy decision (empirical).* The roadmap
     framed this as "main thread if p95 round time stays under
     ~200ms, otherwise replace `harmonypir_worker_pool.ts`".
     **Decision: start on the main thread**, defer worker-pool
     work to a post-Session-6 follow-up if measurements show
     actual p95 breach. Rationale: the original TS worker pool
     (`web/src/harmonypir_worker_pool.ts` 462 LOC +
     `harmonypir_worker.ts` 180 LOC) parallelized
     `build_request` / `process_response` by owning one
     `HarmonyGroup` WASM instance per worker — the cost it was
     hiding was per-group `Group::build_request` serialized on
     a single thread across TS <-> WASM boundary crossings.
     The native `HarmonyClient` bulk-processes all groups
     inside one Rust call (no boundary crossings, aggressive
     inlining of the cryptographic primitives), so the
     per-round CPU budget is dramatically smaller than the TS
     pool's amortized cost. Exposing the sub-group lifecycle
     to JS for parallel main-thread dispatch would break
     `HarmonyClient`'s encapsulation of state transitions
     (`ensure_groups_ready` → `build_batch` →
     `process_response` → `relocate_log`) that the padding
     invariants rely on. Session 6 will measure real-world p95
     once the adapter lands; a worker-pool replacement is a
     ~200-LOC deliverable postponable until (and if) those
     numbers actually exceed the budget.

  Verification: `cargo test -p pir-sdk` = 14/14,
  `cargo test -p pir-sdk-client --lib` = 98/98 (9 new Session
  5 tests added to 89 pre-existing),
  `cargo test -p pir-sdk-wasm --lib` = 39/39 (5 new Session 5
  tests added to 34 pre-existing — one wasm-client constructor
  test was pre-existing, and four new native-safe tests land in
  this session),
  `cargo build --target wasm32-unknown-unknown -p pir-sdk-wasm`
  succeeds, `wasm-pack build --target web --out-dir pkg`
  generates `pkg/pir_sdk_wasm.d.ts` with the full Session 5
  Harmony surface visible (`saveHints`, `loadHints`,
  `fingerprint`, `setDbId`, `dbId`, `minQueriesRemaining`,
  `estimateHintSizeBytes`, `serverUrls`, `queryBatchRaw`,
  `verifyMerkleBatch`, `syncWithProgress`, `onStateChange`).

  🔒 Padding invariants preserved — all new inspector / verify
  paths delegate to the same native `HarmonyClient` query code
  that owns K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE and the
  INDEX-Merkle item-count symmetry invariant. The wrappers are
  translation shims and cannot bypass them.

  LOC impact: `pir-sdk-client/src/harmony.rs` +~760 (translator
  helpers + verify_merkle_items + inspector/verify/db-switch
  surface + 9 unit tests), `pir-sdk-wasm/src/client.rs` +~300
  (`WasmHarmonyClient` Session 5 surface + wasm32-only
  progress/state-change block + 4 unit tests),
  `pir-sdk-wasm/src/lib.rs` +8 (`inner()` accessor on
  `WasmDatabaseCatalog`).

  **Session 6 is now unblocked.** The WASM surface this session
  exposes is the exact set of methods a
  `HarmonyPirClientAdapter` over `WasmHarmonyClient` needs to
  become a drop-in replacement for `harmonypir_client.ts` —
  mirroring the Session 3 DPF cutover pattern. An IndexedDB
  bridge for `saveHints` / `loadHints` is the only non-trivial
  new TS code (~200 LOC); everything else is translation layer.

- **TS retirement Session 6 — Harmony web-side cutover.** The
  Harmony half of the web client is now a thin adapter over
  `WasmHarmonyClient`. Five artefacts landed:

  * *New neutral types module*
    [`web/src/harmony-types.ts`](web/src/harmony-types.ts) (~100
    LOC). Hosts `HarmonyQueryResult`, `HarmonyUtxoEntry`,
    `QueryInspectorData`, `RoundTimingData` — shapes previously
    embedded in `harmonypir_client.ts`. Consumers (`sync-merge.ts`
    + `__tests__/sync-merge.test.ts`) switched their
    `type` imports over, so the shapes keep working even after
    `harmonypir_client.ts` is deleted.

  * *Rewritten IndexedDB bridge*
    [`web/src/harmonypir_hint_db.ts`](web/src/harmonypir_hint_db.ts)
    (v2 schema). Replaces the old per-group
    `Map<number, Uint8Array>` layout with a single opaque
    `bytes: Uint8Array` blob produced by
    `WasmHarmonyClient.saveHints()`, plus a `masterKey: Uint8Array`
    (16-byte random PRP key generated at adapter construction),
    plus `fingerprintHex: string` (from
    `WasmHarmonyClient.fingerprint()` for debugging/logging —
    authoritative cross-check runs inside WASM on `loadHints`).
    Keyed on `(serverUrl, dbId, prpBackend)`. `onupgradeneeded`
    drops the v1 store and re-creates it so pre-Session-6
    entries are discarded cleanly; users re-download hints once.

  * *New adapter shim*
    [`web/src/harmonypir-adapter.ts`](web/src/harmonypir-adapter.ts)
    (~830 LOC — larger than the DPF adapter because HarmonyPIR's
    public surface is wider and the IndexedDB bridge lives
    here). `HarmonyPirClientAdapter` exposes the same
    constructor config + method set as the legacy
    `HarmonyPirClient` (`loadWasm` / `connectQueryServer` /
    `fetchServerInfo` / `initGroups` / `fetchHints` /
    `restoreHintsFromCache` / `saveHintsToCache` / `setDbId` /
    `getDbId` / `getCatalog` / `getCatalogEntry` / `queryBatch` /
    `verifyMerkleBatch` / `hasMerkle` / `hasMerkleForDb` /
    `getMerkleRootHex` / `estimateHintSize` /
    `getMinQueriesRemaining` / `getConnectedSockets` /
    `reconnectQueryServer` / `disconnectQueryServer` /
    `onQueryServerClose` / `disconnect` / `terminatePool` /
    `updatePrpBackend` / `refreshHints` / `hasPersistedHints` /
    `setScriptHashOverrideForNextQuery` + field
    `lastInspectorData`). Internally owns one `ManagedWebSocket`
    side-channel (for `REQ_GET_INFO_JSON` / `REQ_GET_DB_CATALOG` /
    `REQ_RESIDENCY`) plus a single `WasmHarmonyClient` for PIR
    query + Merkle verify. A `WeakMap<HarmonyQueryResult,
    WasmQueryResult>` stash lets verify-time JSON round-trips
    reuse the original `WasmQueryResult` handle; externally-sourced
    results fall through a `harmonyResultToJson` helper that
    undoes the txid display-order reversal applied in
    `translateWasmResult`. The adapter generates a 16-byte
    master PRP key once per instance via `crypto.getRandomValues`
    and mirrors it into the WASM client via `setMasterKey` so
    `saveHints` → reload → `setMasterKey` → `loadHints`
    round-trips byte-exact.

  * *`sdk-bridge.ts` interface extension* — added a
    `WasmHarmonyClient` interface + `WasmHarmonyClient` /
    `PRP_HOANG` / `PRP_FASTPRP` / `PRP_ALF` entries on the
    `PirSdkWasm` contract (mirrors the `WasmDpfClient` pattern).
    The adapter reads the type via the same `requireSdkWasm()`
    accessor used elsewhere.

  * *Call-site swap + export migration* —
    `web/index.html` swapped
    `new HarmonyPirClient({ ... })` →
    `new HarmonyPirClientAdapter({ ... })` (config shape
    unchanged, but the progress-string regex was updated because
    the legacy "Hints: N/155" streaming text no longer exists;
    the adapter emits discrete "Hints: downloading…" and
    "Hints: ready" messages instead). `web/src/index.ts`
    dropped `HarmonyPirClient` / `createHarmonyPirClient` /
    `HarmonyQueryResult` / `HarmonyUtxoEntry` from
    `./harmonypir_client.js` and added
    `HarmonyPirClientAdapter` / `createHarmonyPirClientAdapter` /
    `HarmonyPirClientConfig` from `./harmonypir-adapter.js`
    plus type re-exports of `HarmonyQueryResult` /
    `HarmonyUtxoEntry` / `QueryInspectorData` /
    `RoundTimingData` from `./harmony-types.js`.

  *File deletions:* `web/src/harmonypir_client.ts` (2151 LOC),
  `web/src/harmonypir_worker.ts` (180 LOC),
  `web/src/harmonypir_worker_pool.ts` (462 LOC). Worker-pool
  strategy was decided in Session 5 as main-thread, so both
  worker files disappear entirely.

  *Accepted regressions (documented inline):*
  (1) `[PIR-AUDIT]` logs from native `HarmonyClient` go to
  `console.info` rather than the web UI's log panel (no
  `onLog` hook on `WasmHarmonyClient`); (2) hint-download
  progress is coarse (no incremental "N/155 groups" updates —
  native `HarmonyClient` bulk-fetches), so the UI's offline
  progress bar flips 0% → 100% around the `fetchHints()`
  roundtrip; (3) the Query Inspector panel only populates PBC
  bin / whale / chunk-count fields from the WASM inspector
  surface — placement-round details (`indexPlacementRound`,
  `indexSegment` / `indexPosition` / `indexSegmentSize`,
  per-chunk segment+position, per-round `roundTimings`) are no
  longer surfaced because the native `HarmonyClient` doesn't
  expose those internals across the WASM boundary; (4) the
  legacy `setScriptHashOverrideForNextQuery` test hook is now
  a no-op stub since the native client has no matching override
  path (production UI never called it).

  Verification: `npx tsc --noEmit` → no new TS errors (same two
  pre-existing errors in `ws.test.ts` and `onionpir_client.ts`);
  `npx vite build` → clean (`✓ built in ~260ms`, 7 assets);
  `npx vitest run` → 88/88 passing across 7 test files;
  `cargo test -p pir-sdk-wasm --lib` → 39/39 passing;
  `cargo test -p pir-sdk-client --lib` → 98/98;
  `cargo test -p pir-sdk --lib` → 14/14.

  🔒 Padding invariants preserved — PIR rounds still run through
  native `HarmonyClient` (K=75 INDEX / K_CHUNK=80 CHUNK /
  25-MERKLE), INDEX-Merkle item-count symmetry lives in the
  same native code path. The adapter is a translation shim;
  it cannot bypass the padding.

  LOC impact: -2151 (`harmonypir_client.ts`) -642
  (`harmonypir_worker{,_pool}.ts`) +~830 (`harmonypir-adapter.ts`)
  +~100 (`harmony-types.ts`) +~130 (`harmonypir_hint_db.ts`
  rewrite, net -0 LOC since the old version was ~120) +~60
  (`sdk-bridge.ts` interface extensions). Net: ~1880 LOC of
  hand-rolled TS retired.

  **This closes the TS retirement plan** for everything
  practical on wasm32. The three remaining web-side TS PIR
  files after Session 6:
  * `web/src/onionpir_client.ts` — stays indefinitely; the
    upstream `onionpir` crate requires C++ SEAL which doesn't
    compile to wasm32. No `WasmOnionClient` to replace it.
  * `web/src/dpf-adapter.ts` + `web/src/harmonypir-adapter.ts`
    — Session 3 + Session 6 adapter shims; these are the
    adapters themselves.
  * `web/src/sync-controller.ts`, `web/src/sync.ts`,
    `web/src/sync-merge.ts` — cross-backend orchestration,
    independent of which backend is wasm-backed.
- **Error taxonomy refinement in `PirError` (P2 #3 — follow-up
  after TS retirement).** Added a categorical `ErrorKind` enum
  (`TransientNetwork` / `SessionEvicted` / `ProtocolSkew` /
  `MerkleVerificationFailed` / `ServerError` / `ClientError` /
  `DataError` / `Other`) plus a `kind()` classifier on
  `PirError`, so retry logic and UI can dispatch on cause
  without matching every variant. Four new variants landed:
  * `Transient { origin: &'static str, context: String }` — a
    general "transient blip" path for retry-layer code that
    doesn't want to overload `ConnectionClosed` / `Timeout`.
    Field named `origin` (not `source`) so that
    `#[derive(thiserror::Error)]` doesn't try to coerce it into
    a `std::error::Error` source chain — `&'static str` doesn't
    implement `Error`, and picking the wrong name produces a
    hard-to-diagnose `as_dyn_error` trait-bound failure.
  * `ProtocolSkew { expected: String, actual: String }` —
    distinct from `Protocol` (which is for malformed wire data
    *within* the agreed protocol); skew specifically means the
    caller needs a software upgrade.
  * `SessionEvicted(String)` — server lost our session (OnionPIR
    LRU eviction after in-session retry failed, stale Harmony
    hint session, etc.). A dedicated variant (instead of
    lumping with `ServerError`) lets reconnect-then-retry loops
    target this specific cause.
  * `MerkleVerificationFailed(String)` — pipeline-level Merkle
    failure (server refuses to serve tree-tops despite
    advertising `has_bucket_merkle=true`, mid-round
    `RESP_ERROR`). Explicitly distinct from the per-query
    `QueryResult::merkle_failed()` coercion, which stays in
    place — per-query failures don't need to abort the batch.

  Four new retry/inspection helpers:
  * `is_transient_network()` — `matches!(kind(),
    TransientNetwork)`; retry with exponential backoff.
  * `is_session_lost()` — `TransientNetwork | SessionEvicted`;
    reconnect-then-retry.
  * `is_verification_failure()` — `MerkleVerificationFailed`
    (both the new variant and the legacy `VerificationFailed`
    alias classify the same way).
  * `is_protocol_skew()` — `ProtocolSkew | UnexpectedResponse`;
    not retryable.

  The existing `is_retryable()` was broadened from the old
  `Timeout | ConnectionClosed` match to cover both
  `TransientNetwork` and `SessionEvicted` kinds (no callers
  existed that depended on the narrower semantics — grep
  confirmed `is_retryable` was only defined, never called).
  `is_connection_error` and `is_protocol_error` both grew to
  cover the new variants (`Transient` and `ProtocolSkew`
  respectively) while retaining every case they already
  matched. The connection-retry loop in
  `pir-sdk-client/src/connection.rs`
  (`connect_with_backoff` + `reconnect`) uses
  `is_connection_error` for its "retry this attempt" check;
  that keeps working and now also covers `Transient`.

  Three concrete call-site migrations landed alongside the new
  taxonomy:
  * `pir-sdk-client/src/onion.rs::onionpir_batch_rpc` now
    returns `PirError::SessionEvicted` when the all-empty
    eviction signal (`batch_looks_evicted`) fires twice in a
    row (once initially, once after re-registering keys).
    Previously this produced a generic `ServerError` that
    naive retry loops could spin on; the new variant gives
    callers a specific signal to reconnect cleanly.
  * `pir-sdk-client/src/merkle_verify.rs::decode_sibling_batch`
    now returns `PirError::MerkleVerificationFailed` when the
    server sends `RESP_ERROR = 0xFF` mid-Merkle-round. By that
    point the tree-tops are already fetched, so a mid-round
    error means the server can't produce the evidence needed
    to verify. The unit test `test_decode_sibling_batch_error_variant`
    was updated to assert the new variant and `kind() ==
    ErrorKind::MerkleVerificationFailed`.
  * `pir-sdk-client/src/merkle_verify.rs::fetch_tree_tops` now
    returns `PirError::ProtocolSkew` when the server rejects
    the tree-tops request despite the catalog advertising
    `has_bucket_merkle = true`. Similarly
    `verify_bucket_merkle_batch_dpf` raises `ProtocolSkew` when
    the server's tree-tops blob has fewer entries than the
    declared `K_INDEX + K_CHUNK` — client and server disagree
    on the PBC group count, which is a version/feature gap
    rather than a transient wire corruption.

  `ErrorKind` re-exported from `pir_sdk` crate root alongside
  `PirError` / `PirResult`. Module-level docs in
  `pir-sdk/src/error.rs` now include a cause-to-action mapping
  table, and per-variant doc comments cross-link to the
  preferred more-specific variant (e.g. `ServerError` notes
  that LRU eviction should use `SessionEvicted` instead;
  `Protocol` notes that version/feature gaps should use
  `ProtocolSkew`; `VerificationFailed` is marked as legacy in
  favour of `MerkleVerificationFailed`).

  Verification: `cargo test -p pir-sdk --lib` = 31/31 passing
  (was 14/14; 17 new error-taxonomy tests). `cargo test -p
  pir-sdk-client --lib` = 98/98 passing (the
  `test_decode_sibling_batch_error_variant` update is the
  only behaviour change — all other tests unchanged).
  `cargo test -p pir-sdk-wasm --lib` = 39/39 passing (no
  change). `cargo build --target wasm32-unknown-unknown -p
  pir-sdk-client` succeeds; `cargo build --target
  wasm32-unknown-unknown -p pir-sdk-wasm` succeeds;
  `cargo check -p pir-sdk-client --features onion` succeeds
  (C++/SEAL onion path still compiles). Web suites unchanged:
  `npx vitest run` = 88/88 across 7 files, `npx vite build`
  clean in ~300ms. 🔒 Padding invariants preserved — the
  taxonomy sits above the query code that owns K=75 INDEX /
  K_CHUNK=80 CHUNK / 25-MERKLE padding, and the migrations are
  error-raising changes only (no wire-format or logic shifts).

- **Observability beyond `[PIR-AUDIT]` — Phases 1 & 2 landed.**
  Phase 1 (commit `e34d93e`): `tracing` is an additive dep on
  `pir-sdk-client` (with the `log` feature so existing
  `[PIR-AUDIT]` `log::info!` calls keep flowing through any
  installed subscriber). Every public method on `DpfClient`,
  `HarmonyClient`, `OnionClient`, and `WsConnection::{connect,
  connect_once, connect_with_backoff, reconnect}` carries
  `#[tracing::instrument(level = …, skip_all, fields(backend =
  "dpf"/"harmony"/"onion", …))]`. Three-tier level scheme:
  `info` for top-level ops (`sync` / `connect` / `disconnect` /
  `reconnect`), `debug` for sub-ops (step execution, catalog
  fetch, inspector/verify paths), `trace` for per-query inner
  loops. One smoke test per client captures formatted span
  output through a `MakeWriter` so rename/removal fails at test
  time. `pir-sdk-client` 98 → 101 tests.
  Phase 2 (commit `3ad01b3`): `pir-sdk` ships a `PirMetrics`
  observer trait with six defaulted callbacks (`on_query_start`
  / `on_query_end` / `on_bytes_sent` / `on_bytes_received` /
  `on_connect` / `on_disconnect`) plus `NoopMetrics` +
  `AtomicMetrics` (lock-free `AtomicU64` counters, `Copy`
  `Snapshot`). `PirTransport` gained
  `set_metrics_recorder(recorder, backend)`; `WsConnection` /
  `MockTransport` / `WasmWebSocketTransport` fire per-frame byte
  callbacks (send counts after confirmed-OK result, recv counts
  full raw frame with length prefix). `DpfClient`,
  `HarmonyClient`, `OnionClient` each propagate the recorder to
  every owned transport with `&'static str` backend label, and
  fire `on_connect` per-transport + `on_disconnect` once per
  client + `on_query_start` / `on_query_end` around every
  `query_batch`. Pre- and post-connect install both work.
  `pir-sdk` 31 → 39, `pir-sdk-client` 101 → 116,
  `--features onion` 138/138, `pir-sdk-wasm` 39/39 unchanged.
  wasm32 + onion builds clean. 🔒 Padding invariants preserved
  — metrics are strictly observational, sit above the K=75
  INDEX / K_CHUNK=80 CHUNK / 25-MERKLE padding invariants, and
  callbacks receive scalars / static labels only. Phase 2+ tail
  (latency histograms with wasm32-compatible `Instant`
  substitute, WASM `tracing` subscriber bindings,
  `WasmAtomicMetrics` bridge for browser tools panels) deferred.
- **Native Rust `WasmAtomicMetrics` bridge (P2 observability
  Phase 2+ tail, first item)**: exposes the native
  `pir_sdk::AtomicMetrics` lock-free counter recorder to
  JavaScript via `wasm-bindgen` so a browser tools panel /
  dashboard can poll live PIR query + transport counters
  without leaving the Rust-native metrics path. Three artefacts
  landed:

  *Layer 1 — `WasmAtomicMetrics` class in `pir-sdk-wasm`.* New
  module [`pir-sdk-wasm/src/metrics.rs`](pir-sdk-wasm/src/metrics.rs)
  (~275 LOC) defines a `#[wasm_bindgen]`-annotated
  `WasmAtomicMetrics` struct wrapping `Arc<AtomicMetrics>`. JS
  surface: `new()` constructor (counters start at zero),
  `snapshot()` method returning a plain JS object with nine
  `bigint` fields (`queriesStarted` / `queriesCompleted` /
  `queryErrors` / `bytesSent` / `bytesReceived` / `framesSent`
  / `framesReceived` / `connects` / `disconnects`). The object
  is built manually via `js_sys::Object::new() + Reflect::set`
  rather than `serde_wasm_bindgen::to_value` so the `u64 →
  BigInt` conversion is explicit and avoids any serializer
  ambiguity; `js_sys::BigInt::from(u64)` lands on a real JS
  `BigInt` via the `bigint_from_big!(i64 u64 i128 u128)` macro
  expansion in js-sys 0.3.91. Using `bigint` rather than JS
  `Number` is required because byte counters in a long-running
  session could exceed 2^53 (the `Number.MAX_SAFE_INTEGER`
  ceiling, ~9 PB). Callers can wrap with `Number(snap.bytesSent)`
  if they prefer `Number` arithmetic and the value fits.
  Crate-visible `recorder_handle() -> Arc<dyn PirMetrics>` clones
  the inner `Arc` for client-side install (returned as a trait
  object so it satisfies `DpfClient::set_metrics_recorder`'s
  `Option<Arc<dyn PirMetrics>>` signature without the caller
  having to know the concrete recorder type). `#[cfg(test)]
  snapshot_raw() -> AtomicMetricsSnapshot` returns the native
  snapshot type for unit tests, bypassing the wasm-bindgen JS
  layer whose `js_sys::Object::new()` panics on native targets.
  `Default` impl for `WasmAtomicMetrics` delegates to `new()`.

  *Layer 2 — client wiring.* `WasmDpfClient` and
  `WasmHarmonyClient` in
  [`pir-sdk-wasm/src/client.rs`](pir-sdk-wasm/src/client.rs)
  each picked up two new JS-visible methods:
  `setMetricsRecorder(metrics: &WasmAtomicMetrics)` and
  `clearMetricsRecorder()`. Both delegate to
  `self.inner.set_metrics_recorder(Some|None)` on the native
  `DpfClient` / `HarmonyClient`. The native client then
  propagates the handle to every owned transport (DPF: `conn0` +
  `conn1` with backend label `"dpf"`; Harmony: `hint_conn` +
  `query_conn` with backend label `"harmony"`), so all
  pre-existing Phase 2 byte / frame / connect / disconnect /
  query-lifecycle callbacks start firing on the shared counters.
  Two methods rather than a single nullable setter because
  `Option<&WasmAtomicMetrics>` isn't supported as a
  `wasm-bindgen` parameter type. Pre-connect install (store the
  handle, it'll propagate at `connect`) and post-connect install
  (propagate immediately to already-populated transport slots)
  both work — this follows the native-client behaviour documented
  in the Phase 2 entry above. Dropping the JS-side
  `WasmAtomicMetrics` handle does NOT detach the recorder from
  installed clients, because each client holds its own `Arc`
  clone; callers that want to stop recording must call
  `clearMetricsRecorder()` on the client (tested via
  `uninstall_preserves_js_handle`).

  *Layer 3 — TypeScript surface in `web/src/sdk-bridge.ts`.*
  Added `WasmAtomicMetrics` class declaration to the `PirSdkWasm`
  interface, a `WasmAtomicMetrics` interface (with `free()` +
  `snapshot(): AtomicMetricsSnapshot`), an
  `AtomicMetricsSnapshot` interface with nine `readonly bigint`
  fields matching the native snapshot shape, and
  `setMetricsRecorder(metrics: WasmAtomicMetrics): void` /
  `clearMetricsRecorder(): void` methods on both `WasmDpfClient`
  and `WasmHarmonyClient` interfaces. Public helper
  `sdkCreateAtomicMetrics(): WasmAtomicMetrics` follows the
  pattern of `sdkParseBucketMerkleTreeTops` — throws if
  `initSdkWasm()` hasn't resolved yet, since the metrics bridge
  has no TS fallback. Both `WasmAtomicMetrics` and
  `AtomicMetricsSnapshot` types are re-exported so downstream
  TS code gets full IntelliSense without reaching into the
  generated `pkg/pir_sdk_wasm.d.ts` directly.

  Verification: `cargo test -p pir-sdk-wasm --lib` = 46/46
  passing (up from 39/39; 7 new metrics-module tests —
  `new_starts_at_zero`, `recorder_handle_is_shared_arc`,
  `recorder_handle_installs_on_dpf_client`,
  `recorder_handle_installs_on_harmony_client`,
  `multiple_clients_share_one_recorder`, `default_equals_new`,
  `uninstall_preserves_js_handle`). `cargo build --target
  wasm32-unknown-unknown -p pir-sdk-wasm` clean (only the 3
  pre-existing warnings unchanged from pre-session baseline).
  `wasm-pack build --target web --out-dir pkg` in
  `pir-sdk-wasm/` emits the new `WasmAtomicMetrics` class + the
  two new client methods in `pir_sdk_wasm.d.ts` (verified at
  lines 170, 201, 446, 528, 672; raw wasm imports at lines
  1099-1143 confirm the wasm-bindgen exports). `npx tsc
  --noEmit` shows only the two pre-existing errors (unchanged);
  `npx vitest run` = 88/88 passing across 7 files; `npx vite
  build` clean in ~300ms (WASM bundle 973.94 kB, gzip 327.26
  kB). 🔒 Padding invariants preserved — the metrics bridge is
  a pure JS↔Rust marshalling layer over the already-landed
  Phase 2 observer, which is itself strictly observational.
  It sits above the native-client query code that owns K=75
  INDEX / K_CHUNK=80 CHUNK / 25-MERKLE padding and the
  INDEX-Merkle item-count symmetry invariant; there is no code
  path by which a recorder can influence the number or content
  of padding queries sent. Remaining Phase 2+ tail items
  (latency histograms needing a `performance.now()`-backed
  `Duration` substitute for wasm32's missing `Instant`, WASM
  `tracing` subscriber bindings) remain deferred.
- **Native Rust `tracing-wasm` subscriber bridge (P2
  observability Phase 2+ tail, second item)**: installs a
  browser-compatible `tracing::Subscriber` so the Phase 1
  `#[tracing::instrument]` spans on the native
  `DpfClient` / `HarmonyClient` / `OnionClient` /
  `WsConnection` / `WasmWebSocketTransport` surface in the
  browser's DevTools console. Before this landing, Phase 1
  added the span attributes but they were invisible on
  wasm32 — `tracing-subscriber::fmt::fmt()` writes to
  `io::Write`, which has no working backend on
  `wasm32-unknown-unknown`. Three layers:

  *Layer 1 — `tracing_bridge` module in `pir-sdk-wasm`.* New
  module [`pir-sdk-wasm/src/tracing_bridge.rs`](pir-sdk-wasm/src/tracing_bridge.rs)
  (~130 LOC, mostly docs) exposes
  `#[wasm_bindgen] fn init_tracing_subscriber(js_name =
  "initTracingSubscriber")` that calls
  `tracing_wasm::set_as_global_default()` inside a
  `std::sync::Once::call_once(|| { ... })`. The `Once` guard
  is essential: `tracing-wasm 0.2.1`'s
  `set_as_global_default` internally `.expect()`s the
  `tracing::subscriber::set_global_default` result, which
  returns `Err` on the second call (global default already
  set) and unwraps to a panic. Wrapping in `Once` makes
  init-from-multiple-paths safe. Inner body is
  `#[cfg(target_arch = "wasm32")]`-gated, so native tests
  see an empty `Once`-guarded block (no-op). Module
  docstring documents the "install both" relationship with
  `WasmAtomicMetrics` — they answer different questions
  ("what is happening now" vs. "how many of each thing has
  happened"), are independent opt-ins.

  *Layer 2 — `Cargo.toml` dep.* Added
  `tracing-wasm = "0.2"` under
  `[target.'cfg(target_arch = "wasm32")'.dependencies]`
  alongside the existing `send_wrapper` entry. Gated on
  wasm32 because the dep transitively requires
  `web-sys::console` which doesn't link on native. Not
  behind a cargo feature — first cut always links the dep
  on wasm32, paying ~35 KB uncompressed / ~14 KB gzipped
  for callers who don't install the subscriber. Gating
  behind `features = ["tracing-subscriber"]` is a follow-up
  if bundle size becomes a concern. Transitive deps pulled
  in for wasm32-only builds: `tracing-wasm 0.2.1`,
  `tracing-subscriber 0.3.23`, `sharded-slab 0.1.7`.

  *Layer 3 — TypeScript surface in
  `web/src/sdk-bridge.ts`.* Added
  `initTracingSubscriber(): void` to the `PirSdkWasm`
  interface, and a public `initSdkTracing(): void` helper
  that follows the `sdkCreateAtomicMetrics()` pattern —
  throws if `initSdkWasm()` hasn't resolved yet (no TS
  fallback, the point of the bridge is to surface
  Rust-side span events).

  Tests: 3 new unit tests in `tracing_bridge::tests` in
  `pir-sdk-wasm` — `init_tracing_subscriber_no_panic_on_native`
  (fn is callable without panic on native builds),
  `init_tracing_subscriber_idempotent` (three consecutive
  calls complete without panic — proves the `Once` guard
  holds), `init_state_is_a_module_static_once` (compile-
  and runtime assertion that `INIT` remains a
  `std::sync::Once`, catching any future refactor that
  swaps in a different sync primitive with different
  idempotency semantics).

  Verification: `cargo test -p pir-sdk-wasm --lib` = 49/49
  passing (up from 46/46; 3 new `tracing_bridge` tests).
  `cargo build --target wasm32-unknown-unknown -p pir-sdk-wasm`
  clean. `wasm-pack build --target web --out-dir pkg` emits
  `initTracingSubscriber(): void` at line 996 of
  `pir_sdk_wasm.d.ts` with the full doc comment preserved;
  raw wasm import table at line 1119 confirms the
  wasm-bindgen binding is wired. Raw wasm bundle:
  973.94 KB → 986 KB (+12 KB); vite-compiled:
  973.94 KB → 1009.23 KB uncompressed (+35 KB), gzip
  327.26 KB → 341.50 KB (+14 KB). Web suite:
  `npx tsc --noEmit` shows only the two pre-existing errors
  unchanged; `npx vitest run` = 88/88 passing across 7
  files; `npx vite build` clean in ~298ms. 🔒 Padding
  invariants preserved — the tracing subscriber is strictly
  observational. Span fields are filtered by
  `#[tracing::instrument(skip_all, ...)]` on the native
  side, so only whitelisted scalars / URLs / `&'static str`
  labels reach the subscriber — never binary payloads,
  hint blobs, or secret keys. It sits above the query code
  that owns K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE
  padding; no code path by which a subscriber can
  influence the number or content of padding queries sent.

  Remaining Phase 2+ tail: a stretch follow-up for
  per-frame round-trip latency tracking via
  `WsConnection::send` / `recv` / `roundtrip` — the
  per-client query-end latency item has now landed
  (see "Native Rust per-client latency histograms"
  entry in Completed milestones below).

- **Native Rust per-client latency histograms (P2
  observability Phase 2+ tail, third item)**: closes the
  last remaining Phase 2+ item by extending
  `PirMetrics::on_query_end` with a `duration: Duration`
  parameter and threading captured `Instant` values from
  query start through to query end across all three native
  clients. Before this landing, `AtomicMetrics` could
  count completed queries but the time those queries took
  was invisible — operators had no signal on whether p50
  or p95 was creeping up under load. Four layers landed:

  *Layer 1 — `web-time` dep + `Instant` / `Duration`
  re-exports.* Added `web-time = "1.1"` as a `pir-sdk` dep
  (cross-target, no cfg gating) — the crate provides
  drop-in `Instant` / `Duration` types that delegate to
  `std::time` on native and to `performance.now()` via
  `web_sys::Performance` on `wasm32-unknown-unknown`. This
  unblocks shipping a single timing-aware metrics surface
  that compiles for both targets without per-callsite
  cfg-branches. `pir-sdk/src/metrics.rs` re-exports
  `web_time::{Instant, Duration}` at module scope; the
  `pir-sdk` crate root then re-exports both alongside
  `PirMetrics` / `AtomicMetrics` / `AtomicMetricsSnapshot`
  / `NoopMetrics` so callers don't need a direct
  `web-time` dep. (This re-export was the source of an
  early `unresolved import pir_sdk::Instant` (E0432)
  during client wiring that took one round to chase down.)

  *Layer 2 — trait + recorder shape changes in `pir-sdk`.*
  The `PirMetrics` trait's `on_query_end` callback gained
  a sixth parameter — `duration: Duration` — that all
  implementations now receive. The signature change is
  source-breaking but additive in spirit (the parameter
  has a meaningful default of `Duration::ZERO` for
  best-effort observation, see Layer 3). `AtomicMetrics`
  picked up three new lock-free counters:
  `total_query_latency_micros: AtomicU64`,
  `min_query_latency_micros: AtomicU64`,
  `max_query_latency_micros: AtomicU64`. The min counter
  is initialised to a `MIN_LATENCY_SENTINEL = u64::MAX`
  constant — `fetch_min(observed)` always wins on the
  first measurement (any observed value <= `u64::MAX`),
  which sidesteps the alternative "first-value-special-cased
  via CAS loop" pattern that would have needed a separate
  observed-anything-yet flag. `Default` is hand-written
  for both `AtomicMetrics` and `AtomicMetricsSnapshot` to
  set `min_query_latency_micros` to the sentinel rather
  than to `0`; the autoderived `Default` would have
  zeroed the field, which would then cause the very first
  observation to miscompute as min=0. Both `AtomicMetrics::
  on_query_end` and the snapshot's atomic loads use
  `Ordering::Relaxed` (each counter is independently
  atomic with no cross-counter invariant — a snapshot is
  a momentary fuzzy read, not a transaction). Snapshot
  consumers detect "no measurements yet" by checking
  `min_query_latency_micros == u64::MAX`; the JS-side
  bridge (Layer 4) documents this with the literal
  `0xFFFF_FFFF_FFFF_FFFFn` BigInt sentinel. 7 new
  `metrics::tests` unit tests cover the latency surface
  end-to-end: zero-state assertion, single-observation
  agreement, multi-observation aggregation
  (total / min / max), 16-thread concurrent
  `Arc<AtomicMetrics>` hammer test, snapshot determinism,
  `Default` correctness for the sentinel, and `Copy`
  semantics on the snapshot struct.

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
                    success: bool, started_at: Option<Instant>) {
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
  touching the clock, so `Instant::now()` (which on wasm32
  hits `performance.now()`, a non-trivial JS↔WASM
  boundary call) is skipped entirely; (b) **best-effort
  observation when recorder installed mid-query** —
  `fire_query_end` receiving `started_at = None`
  (recorder absent at start) still surfaces an
  `on_query_end` callback with `duration = Duration::ZERO`
  rather than swallowing the event silently, which keeps
  the `query_starts` / `query_ends` counter pair
  consistent for callers that compute "in-flight queries"
  via subtraction; (c) **no allocation in the hot path**
  — `Option<Instant>` is `Copy`, the clock value is
  captured once and consumed via `.elapsed()`, no `Box` /
  `Arc` / heap interaction. Each client's existing
  `query_batch` call site changed from a single
  `self.fire_query_start(...)` to
  `let started_at = self.fire_query_start(...);` followed
  by `self.fire_query_end(..., started_at);` at the
  return path. 9 new client-level tests landed (3 per
  client × 3 clients): `fire_query_start_returns_instant_only_when_recorder_installed`
  (proves `None` baseline + `Some(_)` post-install),
  `fire_query_end_records_non_zero_duration_with_recorder`
  (5 ms `tokio::time::sleep` between start + end, asserts
  `min_query_latency_micros >= 1_000`),
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
  `0xFFFF_FFFF_FFFF_FFFFn` to mean "no measurements yet"
  and should display "—" rather than misleadingly
  rendering the sentinel as a real measurement). The
  existing `new_starts_at_zero` test was extended to
  assert all three latency fields land at their expected
  zero-state (`0`, `u64::MAX`, `0`); two new tests
  landed: `latency_through_recorder_handle_lands_in_snapshot`
  (3 simulated query completions with synthetic durations
  20 ms / 50 ms / 80 ms; asserts `total = 150_000`,
  `min = 20_000`, `max = 80_000`) and
  `multiple_clients_aggregate_latency` (one
  `WasmAtomicMetrics` installed on both a `WasmDpfClient`
  and a `WasmHarmonyClient`, 4 simulated completions
  spread across both clients; asserts the snapshot
  reflects the union — proves the `Arc` clone aliases
  share state across client backends). `WasmAtomicMetrics`
  test count: 49/49 → 51/51 passing.

  *Layer 5 — TypeScript surface in
  `web/src/sdk-bridge.ts`.* The `AtomicMetricsSnapshot`
  interface gained three new `readonly bigint` fields
  (`totalQueryLatencyMicros`, `minQueryLatencyMicros`,
  `maxQueryLatencyMicros`) with TSDoc comments
  documenting the latency-snapshot semantics: total = sum
  of all completed query durations in microseconds; min
  initialised to `0xFFFF_FFFF_FFFF_FFFFn` (`u64::MAX`)
  sentinel meaning "no measurements yet"; max
  monotonically grows. The `snapshot()` doc comment moved
  from "nine `bigint` counters" to "twelve `bigint`
  counters". No new TS-side helpers needed — the
  pre-existing `sdkCreateAtomicMetrics()` factory returns
  the same `WasmAtomicMetrics` handle, just with three
  more fields available on its `snapshot()` output.

  Verification: `cargo test -p pir-sdk --lib` = **48/48**
  passing (up from 41/41; 7 new `metrics::tests`
  including a thread-safety stress test). `cargo test -p
  pir-sdk-client --lib` = **125/125** passing (up from
  116/116; 9 new client-level tests, 3 per client).
  `cargo test -p pir-sdk-client --features onion --lib`
  = **147/147** passing. `cargo test -p pir-sdk-wasm
  --lib` = **51/51** passing (up from 49/49; 2 new
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
  across 7 files; `npx vite build` clean in ~300ms with
  bundle 1010.26 kB / 341.95 kB gzipped (the +1 kB
  uncompressed / +0.5 kB gzip delta vs. the
  `tracing-wasm` baseline reflects the small added
  `web-time` integration).
  🔒 Padding invariants preserved — the latency layer
  is strictly observational. The new `Duration`
  parameter on `on_query_end` is computed from
  `Instant::now()` deltas, never from query payload
  shape; `Option<Instant>` threading guarantees zero
  overhead when no recorder is installed; the per-client
  metrics handle is propagated to all owned transports
  but never reaches the query encoder / decoder paths
  that own K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE
  padding and the INDEX-Merkle item-count symmetry
  invariant. There is no code path by which an installed
  recorder can influence the number or content of
  padding queries sent.

  All three Phase 2+ tail items have now landed
  (`WasmAtomicMetrics` bridge ✅, `tracing-wasm`
  subscriber bridge ✅, per-client latency histograms
  ✅). The single remaining stretch follow-up
  (per-frame round-trip latency tracking via
  `WsConnection::send` / `recv` / `roundtrip`) stays
  deferred — it would require capturing an `Instant`
  inside the transport-level `roundtrip` future and
  surfacing it through a new `PirMetrics::on_roundtrip_end`
  callback, which is a meaningful API extension and a
  separate design decision from the per-query latency
  this entry closes.

## P0 — Blockers for "production-ready"

_(none — all P0 items closed.)_

## P1 — Correctness & robustness

_(none — all P1 items closed.)_

## P2 — API completeness

- [~] **`pir-sdk-wasm`: full client wrappers.** `WasmDpfClient` and
      `WasmHarmonyClient` landed (P2 #1b below); `WasmOnionClient` is
      skipped because the upstream `onionpir` crate requires C++ SEAL
      which is not compatible with `wasm32-unknown-unknown`. Both
      sub-items below are done; the remaining work is the TS
      retirement that the wrappers unblock.
    - [x] **P2 #1a — Transport abstraction in `pir-sdk-client`.** All
          four sub-checkpoints below have landed: the trait surface,
          helper-function port, client struct refactor, and the
          `web-sys::WebSocket`-backed WASM transport. `pir-sdk-client`
          now compiles cleanly to `wasm32-unknown-unknown` (verified
          with `cargo check --target wasm32-unknown-unknown`); the
          `connect()` method on all three clients uses
          `tokio::try_join!` on native and `futures::future::try_join`
          on WASM via `cfg(target_arch = "wasm32")`. OnionPIR's
          C++/SEAL dep is native-only by nature, so the WASM build
          treats the `onion` feature as unavailable — see the
          `WasmOnionClient` note under P2 #1b.
        - [x] **Trait surface landed.** New
              `pir-sdk-client/src/transport.rs` defines `PirTransport`
              (`send` / `recv` / `roundtrip` / `close` / `url`) via
              `async_trait` so it's dyn-compatible. `WsConnection` has a
              delegating impl (zero behaviour change). An in-memory
              `MockTransport` for tests enqueues canned responses and
              records sent payloads — lets client state-machine tests
              run without a WebSocket or tokio runtime. 8 new unit
              tests cover trait dyn-compat, `roundtrip` prefix-strip,
              `send`/`recv` prefix-keep asymmetry (matching
              `WsConnection`), `close` invalidation, URL round-trip,
              short-frame rejection, and empty-queue handling.
        - [x] **Helper functions ported to `&mut dyn PirTransport`.**
              `fetch_tree_tops`, `DpfSiblingQuerier` (+ `new` ctor),
              `verify_bucket_merkle_batch_dpf`, `HarmonySiblingQuerier`
              field, `verify_onion_merkle_batch`, and `verify_sub_tree`
              all take trait objects now. Production call sites pass
              `&mut WsConnection` and rely on unsized coercion — no
              caller-side changes needed. `cargo check --features
              onion` (including the C++/SEAL compile) passes, the full
              47-test pir-sdk-client suite passes, and the 🔒 padding
              invariants are preserved (the trait is padding-agnostic;
              it only moves opaque byte frames).
        - [x] **Client struct refactor.** `DpfClient.conn0`/`conn1`,
              `HarmonyClient.hint_conn`/`query_conn`, and
              `OnionClient.conn` are now all
              `Option<Box<dyn PirTransport>>` instead of
              `Option<WsConnection>`. Each client also grew a
              `connect_with_transport(...)` inherent method (an
              escape hatch that accepts a pre-built
              `Box<dyn PirTransport>`) — this is what lets unit tests
              inject a `MockTransport` and drive client state without
              a wire connection. Making the coercion
              `&mut Box<dyn PirTransport>` → `&mut dyn PirTransport`
              work at the helper call sites required a blanket
              `impl<T: PirTransport + ?Sized> PirTransport for Box<T>`
              in `transport.rs` and adding a `Sync` bound to
              `PirTransport` (so `Box<dyn PirTransport>: Send + Sync`,
              satisfying `PirClient: Send + Sync`). Three new
              `connect_with_transport_marks_connected` tests (one per
              client) demonstrate the escape hatch works end-to-end;
              total native test count is now 50/50 passing.
        - [x] **WASM transport impl.** New
              `pir-sdk-client/src/wasm_transport.rs` (cfg-gated on
              `target_arch = "wasm32"`) ships
              `WasmWebSocketTransport` — a `PirTransport` backed by
              `web_sys::WebSocket`. The DOM's callback-driven API is
              bridged to async via a `futures::channel::mpsc`
              receiver: `on_message` pushes `Binary(Vec<u8>)`
              frames, `on_error` pushes `Error(String)`, `on_close`
              pushes `Closed(String)`, and `recv().await` pops the
              next item. The handshake uses a `oneshot::channel` so
              `connect(url)` resolves when `on_open` fires (or
              errors if `on_error`/`on_close` beat it to the punch).
              Send / Sync story: `web_sys::WebSocket`, `Closure<_>`,
              and `Rc<RefCell<_>>` are all `!Send + !Sync`, but the
              trait requires `Send + Sync` (so
              `Box<dyn PirTransport>` satisfies
              `DpfClient: PirClient: Send + Sync` and so
              `#[async_trait]` futures are `Send`). Fix: every
              `!Send` field is wrapped in
              `send_wrapper::SendWrapper<T>`, which unsafely impls
              `Send + Sync` for any `T` and panics on access from a
              thread other than the one that constructed it — sound
              on wasm32 where there's only one thread. The three
              clients' `connect()` methods now cfg-branch on
              `target_arch = "wasm32"`: native uses
              `tokio::try_join!(WsConnection::connect(...))`, WASM
              uses
              `futures::future::try_join(WasmWebSocketTransport::connect(...))`.
              `Cargo.toml` split: `tokio` / `tokio-tungstenite` /
              `rustls` moved to
              `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]`;
              `wasm-bindgen` / `wasm-bindgen-futures` /
              `web-sys` (WebSocket + MessageEvent + BinaryType +
              Blob + ErrorEvent + CloseEvent + FileReader +
              ProgressEvent + Event features) / `js-sys` /
              `futures` / `futures-channel` / `send_wrapper` are in
              `[target.'cfg(target_arch = "wasm32")'.dependencies]`.
              `cargo check --target wasm32-unknown-unknown` passes;
              native `cargo test -p pir-sdk-client --lib` is still
              50/50 passing; `cargo check --features onion` (SEAL
              + native only) still passes. 🔒 Padding invariants
              preserved — the WASM transport is padding-agnostic
              just like the native one.
    - [x] **P2 #1b — `Wasm{Dpf,Harmony}Client` wrappers landed;
          TS retirement is the remaining follow-up.** New module
          `pir-sdk-wasm/src/client.rs` exposes two `wasm-bindgen` classes
          wrapping the native `DpfClient` / `HarmonyClient` from
          `pir-sdk-client`: `WasmDpfClient` and `WasmHarmonyClient`,
          each with `connect()` / `disconnect()` / `fetchCatalog()` /
          `sync(Uint8Array, last_height?)` / `queryBatch(Uint8Array, db_id)`
          async methods that return `Promise<...>` on the JS side via
          `wasm-bindgen-futures`. Plus a `WasmSyncResult` class with
          `resultCount` / `syncedHeight` / `wasFreshSync` getters,
          `getResult(i)` → `WasmQueryResult | null`, and `toJson()` for
          the whole blob. PRP-backend selection is exposed as
          `PRP_HOANG()` / `PRP_FASTPRP()` / `PRP_ALF()` free functions
          plus `setPrpBackend(u8)` / `setMasterKey(Uint8Array)` on
          `WasmHarmonyClient`. Internals: `pir-sdk-client` and
          `wasm-bindgen-futures` added as cross-target deps of
          `pir-sdk-wasm`; `WasmDatabaseCatalog` picked up a
          `pub(crate) fn from_native` for zero-copy wrapping of a
          catalog returned by the underlying client (no JSON
          round-trip); helpers that don't touch JS (`unpack_script_hashes`,
          `validate_prp_backend`, `validate_master_key_len`,
          `sync_result_to_json`) return `Result<_, String>` rather than
          `Result<_, JsError>` so native unit tests can exercise them
          (`JsError::new` is a wasm-bindgen import that panics on native).
          10 new unit tests cover script-hash unpacking (empty, happy
          path, non-multiple-of-20 error), validator rejection paths,
          both client constructors, PRP constant uniqueness, and
          `SyncResult → JSON` shape (including `merkleVerified=false`
          for `QueryResult::merkle_failed()`). Build: `cargo test -p
          pir-sdk-wasm --lib` = 23/23 passing; `cargo build --target
          wasm32-unknown-unknown -p pir-sdk-wasm` succeeds; `wasm-pack
          build --target web` emits `pkg/pir_sdk_wasm.d.ts` with
          `export class WasmDpfClient { sync(...): Promise<WasmSyncResult>;
          ... }` and friends. 🔒 Padding invariants preserved — the
          wrapper is a thin translation layer; K / K_CHUNK / 25-MERKLE
          padding stays in the native `DpfClient` / `HarmonyClient`
          structs. **`WasmOnionClient` deliberately skipped**: the
          upstream `onionpir` crate pulls in a C++ SEAL build which
          does not compile to `wasm32-unknown-unknown`. Browsers that
          need OnionPIR must stay on the existing
          `web/src/onionpir_client.ts` until a WASM-compatible FHE
          backend exists. **TS retirement is the remaining sub-item**
          — `web/src/{client,harmonypir_client}.ts` + the DPF half of
          `sdk-bridge.ts` can be swapped for the new `WasmDpfClient` /
          `WasmHarmonyClient`, and `web/src/sync-controller.ts` cut
          over to the unified surface. Tracked separately below.
- [x] **`pir-sdk-wasm`: Merkle verification exposed to JS.** Pure-crypto
      half of the per-bucket bin-Merkle verifier landed in
      `pir-sdk-wasm/src/merkle_verify.rs`: tree-top blob parser
      (`WasmBucketMerkleTreeTops.fromBytes`), leaf / parent / sha256
      primitives (`bucketMerkleLeafHash`, `bucketMerkleParentN`,
      `bucketMerkleSha256`), DPF shard-XOR helper (`xorBuffers`), and a
      per-item walker (`verifyBucketMerkleItem`) that consumes
      pre-fetched XOR'd sibling rows and walks the cached tree-top to
      root. 13 unit tests cover tree-top parsing, the happy-path walk
      (fully cached + one-sibling-level), tamper rejection (bin
      content, bin index, out-of-range group), and malformed-input
      graceful failure (short rows, odd-length children, zero-length
      XOR). The **network** half (K-padded sibling batches over DPF)
      stays in JS because the transport layer is not WASM-compat; see
      P2 #1a. `sdk-bridge.ts` carries the updated `PirSdkWasm`
      interface so callers can consume the new bindings. Switching the
      web client's `merkle-verify-bucket.ts` over to these bindings is
      a follow-up that can land independently.
- [x] **HarmonyClient hint persistence (native).** Landed via
      `pir-sdk-client/src/hint_cache.rs` (TS-retirement Session 4) —
      XDG-backed file cache keyed by a 16-byte fingerprint of
      `(master_prp_key, prp_backend, db_id, height, bins, seed, k)`.
      Both filesystem-backed (`persist_hints_to_cache` /
      `restore_hints_from_cache`) and byte-blob (`save_hints_bytes` /
      `load_hints_bytes`) variants are exposed; the byte-blob variant
      is what the browser's IndexedDB mirror (Session 6 `hint_db.ts`)
      relies on. See the Session 4 entry in the Completed section
      above for the full breakdown.
- [x] **Error taxonomy.** `PirError` now exposes a categorical
      [`ErrorKind`] classifier (`TransientNetwork` / `SessionEvicted`
      / `ProtocolSkew` / `MerkleVerificationFailed` / `ServerError` /
      `ClientError` / `DataError` / `Other`) plus four new variants
      (`Transient { origin, context }`, `ProtocolSkew { expected,
      actual }`, `SessionEvicted(String)`, `MerkleVerificationFailed
      (String)`). Retry helpers `is_transient_network`,
      `is_session_lost`, `is_verification_failure`, `is_protocol_skew`,
      and a broadened `is_retryable` (covers both `TransientNetwork`
      and `SessionEvicted`) let callers dispatch on cause without
      matching every variant. Three concrete migrations landed
      alongside: (a) OnionPIR's `onionpir_batch_rpc` now returns
      `SessionEvicted` when the all-empty eviction signal fires twice
      (was `ServerError`), so a reconnect-and-retry loop can target
      eviction specifically; (b) `merkle_verify::decode_sibling_batch`
      now returns `MerkleVerificationFailed` on `RESP_ERROR` mid-round
      (was `ServerError`) so callers distinguish untrusted data from
      generic server failures; (c) `fetch_tree_tops` + the tree-top
      length check now raise `ProtocolSkew` when the catalog
      advertises `has_bucket_merkle=true` but the server rejects the
      tree-tops request or returns fewer entries than the declared
      K_INDEX+K_CHUNK (was `ServerError` / `Protocol`). Seventeen new
      unit tests in `pir-sdk/src/error.rs` cover the full
      classification matrix, retry helpers, legacy `VerificationFailed`
      alias, `UnexpectedResponse` being classified as skew, and
      `is_connection_error` / `is_protocol_error` back-compat. One
      test in `pir-sdk-client/src/merkle_verify.rs` updated for the
      `RESP_ERROR` mid-round migration. All 31/31 + 98/98 + 39/39
      SDK crate tests pass; `wasm32-unknown-unknown` builds clean;
      `--features onion` checks clean. 🔒 Padding invariants
      preserved — error taxonomy sits above the query code that owns
      K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE padding.
- [~] **Observability beyond `[PIR-AUDIT]`.** Phase 1 (tracing
      spans) and Phase 2 (per-client metrics + per-transport byte
      counters) landed; Phase 2+ tail (WASM tracing subscriber
      bindings, latency histograms, timing callbacks) deferred.
      * Phase 1 ✅ — `tracing` is an additive dep on `pir-sdk-client`
        (with the `log` feature so existing `log::info!` calls still
        surface through any installed subscriber). Every public
        inherent + trait method on `DpfClient`, `HarmonyClient`, and
        `OnionClient` is now annotated with
        `#[tracing::instrument(level = …, skip_all, fields(backend =
        "dpf"/"harmony"/"onion", …))]`. `WsConnection::{connect,
        connect_once, connect_with_backoff, reconnect}` carry
        equivalent lifecycle spans. Span levels follow a three-tier
        scheme: `info` for top-level user ops (`sync` / `connect` /
        `disconnect` / `reconnect`), `debug` for sub-operations
        (step execution, catalog fetch, inspector/verify paths),
        `trace` for per-query inner loops (`query_index_level` /
        `query_chunk_level` / `query_single`). Recorded fields skip
        binary payloads, `Arc`s, and secrets; they carry only
        scalars / URLs / display-string identifiers. `skip_all`
        guards against accidental injection of large values. One
        `tracing_instrument_emits_backend_field_for_<backend>` smoke
        test per client captures the formatted span output through
        an in-memory `MakeWriter` and asserts the span name +
        `backend=` field are present, so future renames /
        accidental `#[tracing::instrument]` removal fail at test
        time. Test totals: `pir-sdk-client` lib tests 98 → 101.
        `tracing-subscriber` is a dev-dep only — no subscriber is
        forced on downstream callers. No-op unless an application
        installs one.
      * Phase 2 ✅ — `pir-sdk` now ships a `PirMetrics` observer
        trait with six defaulted callbacks (`on_query_start` /
        `on_query_end` / `on_bytes_sent` / `on_bytes_received` /
        `on_connect` / `on_disconnect`) plus two concrete
        recorder implementations: `NoopMetrics` (the trait-default
        base case — installing no recorder is still zero-overhead)
        and `AtomicMetrics` (lock-free `AtomicU64` counters with a
        `Copy` `Snapshot` struct for read-out, using
        `Ordering::Relaxed` since each counter is independently
        atomic and there's no cross-counter invariant). The
        `PirTransport` trait gained `set_metrics_recorder(recorder,
        backend)` (`&'static str` backend label — no per-callback
        allocation) with a default no-op body so existing transport
        impls keep compiling; `WsConnection`, `MockTransport`, and
        `WasmWebSocketTransport` all override to store the handle
        and fire per-frame byte callbacks. Wire-frame semantics:
        `send` counts request-payload bytes *after* the confirmed-OK
        result (a timed-out send produces no byte callback); `recv`
        counts the full raw frame bytes (length prefix included) on
        successful decode. `DpfClient`, `HarmonyClient`, and
        `OnionClient` each expose `set_metrics_recorder` at the
        client layer: the handle is stored, propagated to every
        owned transport (DPF: 2, Harmony: 2, Onion: 1) with the
        matching backend label, and the clients themselves fire
        `on_connect` per-transport, `on_disconnect` once per client
        (one semantic "left connected state" signal regardless of
        transport count), and `on_query_start` / `on_query_end`
        around every `query_batch` call. Recorder install works
        pre- or post-connect — pre-install is stored then pushed to
        transports at connect time; post-install pushes immediately
        to currently-connected transports. Test totals:
        `pir-sdk` lib tests 31 → 39 (8 new tests for trait defaults,
        atomic counter agreement across threads, snapshot semantics,
        backend label preservation); `pir-sdk-client` lib tests 101
        → 116 (3 new `MockTransport` tests for byte-callback wiring,
        4 new DpfClient tests, 4 new HarmonyClient tests, 4 new
        OnionClient tests covering pre-connect install / disconnect
        fire / post-connect propagation / uninstall-silences-all).
        `--features onion`: 138/138. `wasm32-unknown-unknown`
        builds clean for `pir-sdk-client` + `pir-sdk-wasm` (the 3
        pre-existing warnings — `INDEX_RESULT_SIZE` /
        `CHUNK_RESULT_SIZE` / `Path` unused on wasm32 — are
        unchanged). 🔒 Padding invariants preserved — the metrics
        layer is strictly observational: callbacks receive scalar
        counters only, no access to query payloads or padding
        state, and it sits above the K=75 INDEX / K_CHUNK=80 CHUNK
        / 25-MERKLE padding which stays in the client query code.
      * Phase 2+ tail — three of four sub-items have landed; only
        a stretch follow-up remains:
        * `WasmAtomicMetrics` bridge ✅ — `pir-sdk-wasm` ships a
          `#[wasm_bindgen]` `WasmAtomicMetrics` class wrapping
          `Arc<pir_sdk::AtomicMetrics>`; `WasmDpfClient` /
          `WasmHarmonyClient` picked up `setMetricsRecorder` /
          `clearMetricsRecorder` so a browser tools panel can read
          live counters without leaving the Rust-native metrics
          path. See the "Native Rust `WasmAtomicMetrics` bridge"
          entry in Completed milestones for the full breakdown.
        * `tracing-wasm` subscriber bridge ✅ — `pir-sdk-wasm` ships
          a `tracing_bridge` module with `initTracingSubscriber()`
          that installs `tracing-wasm::set_as_global_default` as
          the browser's global `tracing` subscriber, so the Phase
          1 spans surface in DevTools console. See the "Native
          Rust `tracing-wasm` subscriber bridge" entry in
          Completed milestones.
        * Per-client latency histograms ✅ — `PirMetrics::on_query_end`
          now carries a `Duration` measured between matching
          `on_query_start` and `on_query_end` calls. The clock
          source is `web_time::Instant` (a drop-in
          `std::time::Instant` substitute that uses
          `performance.now()` on wasm32). `AtomicMetrics` aggregates
          via three new lock-free counters
          (`total_query_latency_micros`, lock-free `fetch_min`-backed
          `min_query_latency_micros` with `u64::MAX` sentinel, and
          `fetch_max`-backed `max_query_latency_micros`).
          `WasmAtomicMetrics.snapshot()` exposes them as three more
          `bigint` fields. Mean = total / (queries_completed +
          query_errors); the `mean_query_latency_micros()` helper
          on the snapshot returns `Option<u64>`. Per-bucket
          percentile estimation is left to a custom `PirMetrics`
          impl maintaining a histogram (e.g. via the `hdrhistogram`
          crate). See the "Native Rust per-client latency
          histograms" entry in Completed milestones.
        * Stretch follow-up (deferred): round-trip latency
          tracking via per-frame `Instant` capture in
          `WsConnection::send` / `recv` / `roundtrip` — the trait
          surface to attach `Duration` to per-frame byte callbacks
          would need new `on_bytes_sent_with_latency` /
          `on_bytes_received_with_latency` methods (or generalize
          existing ones to optionally carry a `Duration`). Lower
          priority than the now-landed query-end latency since
          frame-level timing duplicates what the query-end
          callback already captures.

## P3 — Polish & ship

- [x] **rustdoc examples per client.** `DpfClient`, `HarmonyClient`,
      and `OnionClient` all now ship struct-level rustdoc with a
      runnable-looking (`ignore`'d) example plus intra-doc links
      into the relevant methods (`with_hint_cache_dir` /
      `set_prp_backend` for Harmony; `PirError::SessionEvicted` for
      Onion). See "P3 sweep: rustdoc + dead-code + clippy" in
      Completed milestones below.
- [ ] **Publishing story.** Decide if/how this ships to crates.io
      (`pir-sdk`, `pir-sdk-client`, `pir-sdk-server`) and npm
      (`pir-sdk-wasm`). Pin versioning scheme, write `CHANGELOG.md`.
- [ ] **Feature flag doc page.** `fastprp`, `alf`, `onion` — what
      each enables, what each costs (build-time, link-time),
      compatibility matrix.
- [ ] **Delta sync chain optimizations.** `compute_sync_plan`
      BFS-to-5-steps is conservative. Benchmark against realistic
      delta graphs; consider caching chain computations.
- [x] **Clean up pre-existing `pir-core` clippy warnings**
      (`needless_range_loop`, `manual_div_ceil`) so `-D warnings`
      can go into CI for the whole workspace. All 5 warnings
      cleared — see "P3 sweep" entry for the per-file breakdown.
- [x] **Dead code sweep.** Removed `INDEX_RESULT_SIZE` /
      `CHUNK_RESULT_SIZE` (pir-sdk-client/src/dpf.rs), cfg-gated
      the `Path` import (pir-sdk-client/src/hint_cache.rs),
      dropped the never-read `derived_key` / `group_id` fields on
      `HarmonyGroup` (harmonypir-wasm/src/lib.rs), stripped
      non-root `[profile.release]` stanzas from pir-sdk-wasm /
      harmonypir-wasm Cargo.toml, and gated the two onion-feature
      dead-code warnings (`cache_from_level`, `onion_leaf_hash`)
      with `#[allow(dead_code)]` + justification comments. See
      the "P3 sweep" entry for details.

## P4 — Nice-to-have / research

- [ ] **OnionPIR large-key streaming.** Galois + GSW keys are several
      MB each; currently sent as a single WebSocket frame. Chunking
      would help on flaky links.
- [ ] **HarmonyPIR hint delta sync** (incremental hint updates across
      deltas, instead of re-fetching full hints on each height).
- [ ] **FHE params tuning benchmarks** for OnionPIR (trade query time
      vs response size across DB sizes).
- [ ] **Rate limiting / DoS protection** in `pir-sdk-server`.

## TS retirement: phased plan

The TS retirement aspiration under P2 #1b ("~1000 LOC of duplicated
TypeScript can come out") is real, but a scope survey against
`web/index.html` and `web/src/sync-merge.ts` shows the web clients
have grown features the current `WasmDpfClient` / `WasmHarmonyClient`
wrappers don't expose. The gap must be closed in the WASM crate
first; after that the TS files can actually be deleted. Ordered
sessions below, each self-contained and green on its own.

### Surface gaps surveyed

**DPF (`web/src/client.ts`, 883 LOC):**

1. Progress callbacks (`onConnectionStateChange`, `onLog`,
   `queryBatch(..., onProgress)`).
2. Synchronous catalog accessor (`getCatalog()` / `getCatalogEntry(dbId)`).
3. Separate user-triggered Merkle-verify API
   (`verifyMerkleBatch(results, onProgress, dbId)`) — `WasmDpfClient.sync()`
   only supports inline Merkle; the UI's "Verify Merkle" button can't
   run against it.
4. Per-query Merkle inspector state (`indexBinContent`, `allIndexBins`,
   `chunkPbcGroups/BinIndices/BinContents`) surfaced to the UI.
5. `hasMerkle()` / `hasMerkleForDb(dbId)` / `getMerkleRootHex()` /
   `getMerkleRootHexForDb(dbId)` for UI gating.
6. `getConnectedSockets()` — residency-check diagnostic.

**Harmony (`web/src/harmonypir_client.ts`, 2151 LOC + 759 LOC of
worker/hint-db support):**

On top of every DPF gap:

7. Hint persistence: `saveHintsToCache` / `restoreHintsFromCache(prp)` /
   `getMinQueriesRemaining` / `estimateHintSize`. Requires (a) Rust
   file-backed cache (the unchecked P2 item), (b) `Uint8Array` I/O on
   `WasmHarmonyClient` so the browser can keep using IndexedDB.
8. Explicit DB switching: `setDbId(newDbId)` invalidates groups and
   triggers hint re-fetch. `getDbId()` getter.
9. Worker pool: heavy Harmony crypto (`process_response` over K+K_CHUNK
   groups) today runs in Web Workers — the main-thread default of
   wasm-bindgen may or may not be fast enough now that the hot loop is
   already in Rust/WASM. Measure before replacing.
10. Inspector data (`lastInspectorData` — per-round build/net timings).

**Shared:**

11. `sync-merge.ts` and `onionpir_client.ts` import `QueryResult` /
    `UtxoEntry` types from `client.ts`. Retiring `client.ts` requires
    moving those types to a neutral module (or declaring equivalents
    from `pir-sdk-wasm`'s JS surface).

**Merkle verifier (`web/src/merkle-verify-bucket.ts`, 420 LOC):**

The crypto half (tree-top parse, leaf / parent hash, SHA-256, XOR,
per-item walk) is fully duplicated by WASM primitives already
re-exported through `sdk-bridge.ts`. The wire half (DPF sibling
batches over `ManagedWebSocket`) has to stay TS — the crypto-only
WASM surface has no transport. ~150–200 LOC deletable today without
any Rust-side work; the remainder goes when Session 3 lands the
WASM-side `verifyMerkleBatch`.

### Sessions

**Session 1 — plan + low-risk wins.**

- Land this plan in `SDK_ROADMAP.md`.
- Retire the crypto half of `web/src/merkle-verify-bucket.ts`: rewrite
  internals to call `bucketMerkleLeafHash` / `bucketMerkleParentN` /
  `bucketMerkleSha256` / `xorBuffers` / `WasmBucketMerkleTreeTops` /
  `verifyBucketMerkleItem` from `sdk-bridge.ts`. Wire loop stays
  (~150–200 LOC deleted, 0 risk).
- Move `UtxoEntry` + `QueryResult` + `ConnectionState` type aliases
  out of `client.ts` into `web/src/types.ts`. Re-export from `client.ts`
  for backcompat. `sync-merge.ts` + `onionpir_client.ts` switch to
  the neutral import.

**Session 2 — DPF surface extensions.**

Work in `pir-sdk-wasm/src/client.rs` plus targeted additions to
`pir-sdk/src/types.rs` and `pir-sdk-client/src/dpf.rs`:

- Extend `QueryResult` (native) with optional Merkle-inspector
  fields: `index_bins: Vec<BucketRef>`, `chunk_bins: Vec<BucketRef>`
  where `BucketRef = { pbc_group: u32, bin_index: u32, bin_content: Vec<u8> }`.
  Populated only when `DpfClient::query_batch_with_inspector(...)` is
  called; the sync path stays lean.
- Expose via `WasmQueryResult.indexBins()` / `chunkBins()` JS
  getters (`any` JSON).
- Add `WasmDpfClient.queryBatchRaw(script_hashes, db_id):
  WasmQueryResult[]` — runs PIR, skips inline Merkle, returns the
  inspector state. UI renders then defers Merkle.
- Add `WasmDpfClient.verifyMerkleBatch(results_json, db_id):
  bool[]` — consumes inspector state and runs the network Merkle
  verifier standalone.
- Catalog accessors on `WasmDatabaseCatalog`: `getEntry(dbId)`,
  `hasBucketMerkle(dbId)`, `merkleRootHex(dbId)`.
- `WasmDpfClient.serverUrls(): [string, string]` for the
  residency-check UI.
- `ProgressListener`-backed progress callback:
  `sync(sh, last_height?, progress?: (ev: any) => void)` where `ev`
  is a plain JSON event
  (`{type, step_index, total_steps, description, progress}`).
- Connection-state push: `onStateChange(cb: (state: string) => void)`.
  State transitions originate in the native client; the wasm wrapper
  forwards them through a JS callback held behind
  `SendWrapper<Rc<_>>`.
- New unit tests for catalog accessors, inspector plumbing, progress
  event shapes, raw-query path.

**Session 3 — DPF cutover.**

- In `web/index.html`, replace `new BatchPirClient({ ... })` with
  a ~100-LOC TS adapter that binds the existing
  `onConnectionStateChange` / `onLog` hooks to
  `WasmDpfClient.onStateChange` + a log callback.
- Rewire `queryBatch` / `queryDelta` / `verifyMerkleBatch` /
  `getCatalog` / `hasMerkle...` / `getConnectedSockets` call sites.
- Delete `web/src/client.ts` (types already moved in Session 1).
- Delete `web/src/merkle-verify-bucket.ts` (the WASM surface now
  owns the wire half via session-2 `verifyMerkleBatch`).
- Update `web/src/index.ts` exports.

**Session 4 — HarmonyClient hint persistence (native).**

(= the unchecked P2 roadmap item; blocks Session 6.)

- File-backed cache in `pir-sdk-client/src/harmony.rs` keyed by
  `(db_id, height, prp_backend, master_key_fingerprint)`.
- Default path: `$XDG_CACHE_HOME/pir-sdk/hints/` with fallback to
  `~/.cache/pir-sdk/hints/`. Configurable via
  `HarmonyClient::with_hint_cache_dir(...)`.
- Serialized format version byte + schema hash so mismatched schemas
  get re-fetched rather than silently mis-used.
- Expose `save_hints_bytes()` / `load_hints_bytes(...)` on
  `HarmonyClient` — the browser needs byte-level I/O to bridge to
  IndexedDB.

**Session 5 — Harmony surface extensions. ✅ Landed** — see
Completed section above for the full breakdown. Summary of what's
in place:

- ✅ `WasmHarmonyClient.saveHints(): Uint8Array | null` /
  `loadHints(bytes, catalog, db_id): void` — byte-level cache
  export/import wrapping Session 4's native APIs.
- ✅ `WasmHarmonyClient.fingerprint(catalog, db_id): Uint8Array` —
  same 16-byte fingerprint the native cache keys on, so the
  browser's IndexedDB bridge can key entries identically.
- ✅ `WasmHarmonyClient.setDbId(u8)` / `dbId(): number | null` —
  group invalidation + lazy hint refetch.
- ✅ `WasmHarmonyClient.minQueriesRemaining(): number | null` /
  `estimateHintSizeBytes(): number`.
- ✅ Merkle inspector state + verify parity with DPF — new
  `queryBatchRaw` and `verifyMerkleBatch` on `WasmHarmonyClient`,
  backed by new `query_batch_with_inspector` /
  `verify_merkle_batch_for_results` on the native
  `HarmonyClient` that reuse Session 2's `verify_merkle_items`
  shared backend.
- ✅ Also landed: `serverUrls()`, `syncWithProgress()`,
  `onStateChange()` (wasm32-only) — mirrors `WasmDpfClient`.
- ✅ **Worker-pool strategy decision: main thread.** Defer
  worker-pool work to a post-Session-6 follow-up if real-world
  p95 measurements exceed the ~200ms budget. Rationale (see
  Completed section above): native `HarmonyClient` bulk-processes
  groups inside one Rust call without TS↔WASM boundary crossings,
  so the per-round CPU budget is dramatically smaller than the
  TS worker pool's amortized cost. Exposing sub-group lifecycle
  to JS would break `HarmonyClient`'s padding invariants
  (K=75 / K_CHUNK=80 / 25-MERKLE owned in the native query path).
- ✅ Unit tests: 9 new Rust-side + 4 new WASM-side (native-safe).
  `cargo test -p pir-sdk-client --lib` = 98/98,
  `cargo test -p pir-sdk-wasm --lib` = 39/39,
  `wasm-pack build --target web` emits `WasmHarmonyClient` with
  the full Session 5 surface visible in `.d.ts`.

**Session 6 — Harmony cutover. ✅ Landed** — see Completed section
above for the full breakdown. Summary of what's in place:

- ✅ `HarmonyPirClientAdapter` in
  [`web/src/harmonypir-adapter.ts`](web/src/harmonypir-adapter.ts)
  (~830 LOC) — drop-in replacement for `HarmonyPirClient`
  wrapping `WasmHarmonyClient`.
- ✅ Neutral types module
  [`web/src/harmony-types.ts`](web/src/harmony-types.ts) for
  `HarmonyQueryResult` / `HarmonyUtxoEntry` /
  `QueryInspectorData` / `RoundTimingData` — consumed by
  `sync-merge.ts` + tests.
- ✅ Rewritten IndexedDB bridge
  [`web/src/harmonypir_hint_db.ts`](web/src/harmonypir_hint_db.ts)
  (v2 schema: single `bytes` blob + `masterKey`, drops per-group
  map).
- ✅ `web/index.html` swapped
  `new HarmonyPirClient({ ... })` →
  `new HarmonyPirClientAdapter({ ... })` plus hint-progress regex
  updated for the coarser "Hints: downloading…" / "Hints: ready"
  messages.
- ✅ `web/src/index.ts` re-exports updated; deleted files:
  `harmonypir_client.ts` (2151 LOC),
  `harmonypir_worker.ts` (180 LOC),
  `harmonypir_worker_pool.ts` (462 LOC).
- ✅ Verification: `npx tsc --noEmit` clean (pre-existing errors
  only), `npx vite build` clean, `npx vitest run` 88/88,
  `cargo test -p pir-sdk-wasm --lib` 39/39, `cargo test -p
  pir-sdk-client --lib` 98/98, `cargo test -p pir-sdk --lib`
  14/14.
- 🔒 Padding invariants preserved (K=75 INDEX / K_CHUNK=80 CHUNK
  / 25-MERKLE, INDEX-Merkle item-count symmetry) — all live in
  native `HarmonyClient` underneath the adapter.

**TS retirement plan complete.** Only `onionpir_client.ts` remains
in the web client as a hand-rolled PIR client, and it stays
indefinitely because SEAL doesn't compile to wasm32.

### Dependencies

```
Session 1 ──────┐
Session 2 ──► Session 3 (DPF cutover)
Session 4 ──┐
Session 5 ──┴► Session 6 (Harmony cutover)
```

Sessions 1, 2, and 4 have no predecessors and can start in any
order. Session 5 depends on session 4 (for the native cache API it
wraps). Session 3 and session 6 are pure web-side cutovers that
delete the duplicate TS.

### Estimated deletions

| File                                      |   LOC |
|-------------------------------------------|------:|
| `web/src/client.ts`                       |   883 |
| `web/src/harmonypir_client.ts`            |  2151 |
| `web/src/merkle-verify-bucket.ts`         |   420 |
| `web/src/harmonypir_worker{,_pool}.ts` *  |   642 |
| **Total deletable**                       | ~4100 |

*if session 5 lands the main-thread path; stays if workers are kept.

Replaced by roughly ~300 LOC of WASM-adapter TS in `web/index.html`
+ `web/src/types.ts` + extensions to `web/src/sdk-bridge.ts`.

### What ships incrementally

Even if later sessions stall:

- After Session 1: `merkle-verify-bucket.ts` is no longer duplicate
  crypto; `QueryResult` types live in a neutral module.
- After Session 2: the WASM DPF surface matches the web TS client's
  feature set — independent consumers (Node.js, other web apps) can
  adopt it without going through `BatchPirClient`.
- After Session 3: DPF side fully retired; Harmony side still on TS.
- After Session 4: native `HarmonyClient` gains hint persistence
  regardless of the browser cutover.

## Notes

Whenever work starts on a new item, move it to "In progress" below and
link the branch / commit.

### In progress

_(The TS retirement plan and the error taxonomy refinement have both
landed. See the Completed section above for per-session and
per-milestone breakdowns. `web/src/onionpir_client.ts` remains in
the web client indefinitely because SEAL does not compile to
wasm32.)_

Other tractable P2 items that are unblocked:
Observability Phase 2+ tail — the `WasmAtomicMetrics` bridge
landed (see the "Native Rust `WasmAtomicMetrics` bridge" entry
in Completed milestones above); still deferred are latency
histograms (need a `performance.now()`-backed substitute for
wasm32's lack of `std::time::Instant`) and WASM subscriber
bindings for `tracing` (need a web-compatible writer adapter
since `tracing-subscriber::fmt` targets `io::Write`). Phase 1
(`tracing` spans) and Phase 2 (metrics trait + per-transport
byte counters + per-batch callbacks) both landed — see the
`[~]` entry above. Independent of the (now complete) TS
retirement and error taxonomy.
