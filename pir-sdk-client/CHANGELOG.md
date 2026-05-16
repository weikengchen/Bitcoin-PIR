# Changelog

All notable changes to `pir-sdk-client` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — initial release

### Added

- **Three backend clients**:
  - `DpfClient` — two-server DPF (XOR of two shares).
  - `HarmonyClient` — two-server PBC-code hint + query architecture
    with PRP-based hint server. PRP backend selectable
    (`PRP_HMR12` / `PRP_FASTPRP` / `PRP_ALF`) via the `fastprp` /
    `alf` cargo features.
  - `OnionClient` — single-server FHE (Microsoft SEAL BFV) via the
    `onion` cargo feature. Native-only; SEAL does not compile to
    `wasm32-unknown-unknown`.
  - All three implement `pir_sdk::PirClient` for interchangeable
    call sites.
- **`PirTransport` trait** (new module `transport.rs`):
  - `Send + Sync` trait with `send` / `recv` / `roundtrip` / `close`
    / `url`.
  - Blanket `impl<T: PirTransport + ?Sized> PirTransport for Box<T>`
    so `&mut Box<dyn PirTransport>` coerces to
    `&mut dyn PirTransport`.
  - `WsConnection` delegating impl on native
    (tokio-tungstenite + rustls).
  - `WasmWebSocketTransport` on wasm32 (bridges the callback-driven
    `web-sys::WebSocket` DOM API to `async_trait`-compatible
    `Send` futures via `send_wrapper::SendWrapper`).
  - Test-only `MockTransport` enqueues canned responses.
- **Connection resilience**:
  - Per-request deadlines: `DEFAULT_REQUEST_TIMEOUT = 90s`.
  - `RetryPolicy::default()` — 5 attempts, 250ms → 5s exponential
    backoff.
  - Connect-with-backoff via `WsConnection::connect`; public
    `reconnect(&mut self)` escape hatch (session state not
    preserved — caller re-negotiates hints / FHE keys / in-flight
    round IDs).
- **Per-bucket Merkle verification** (DPF + Harmony):
  - New module `merkle_verify.rs` — bin-leaf hash, K-padded sibling
    batches, tree-top parsing, full walk-to-root.
  - Backend-agnostic `BucketMerkleSiblingQuerier` trait with
    `DpfSiblingQuerier` and `HarmonySiblingQuerier` impls.
  - Gated on `DatabaseInfo::has_bucket_merkle`. Padding (K=75
    INDEX, K_CHUNK=80 CHUNK, 25 MERKLE) preserved.
  - Failed proofs surface as `Some(QueryResult::merkle_failed())`
    rather than being coerced to `None`.
  - `query_batch_with_inspector` / `verify_merkle_batch_for_results`
    split-verify pair for "run PIR now, verify later" workflows.
- **OnionPIR per-bin Merkle verification**:
  - New module `onion_merkle.rs` (feature-gated on `onion`).
  - Two flat trees (INDEX + DATA), SHA256 leaf hash (no bin-index
    prefix), 6-way sibling cuckoo with per-level master seed
    (`INDEX_SIBLING_SEED_BASE = 0xBA7C_51B1_FEED_0100`,
    `DATA_SIBLING_SEED_BASE = 0xBA7C_51B1_FEED_0200`).
  - FHE-encrypted sibling queries (0x53 INDEX, 0x55 DATA).
  - `SibSendClient` newtype makes `onionpir::Client` `Send` across
    `.await`; thread-safety audit recorded in a long-form comment
    + compile-time `assert_send_sync` probes.
- **OnionPIR LRU-eviction retry**:
  - `onionpir_batch_rpc` chokepoint detects the all-empty
    eviction signal via `batch_looks_evicted`, drops the
    `registered[db_id]` flag, replays Galois + GSW keys, and
    retries once. Second all-empty raises
    `PirError::SessionEvicted`.
- **Hint cache** (Harmony; new module `hint_cache.rs`):
  - Self-describing binary format (magic `PSH1`, u16 version,
    32-byte schema SHA-256, 16-byte `CacheKey::fingerprint`).
  - Cache key folds
    `(master_prp_key, prp_backend, db_id, height, index_bins,
    chunk_bins, tag_seed, index_k, chunk_k)` through
    `pir_core::merkle::sha256` — master PRP key never hits disk
    as cleartext.
  - XDG-backed default (`$XDG_CACHE_HOME/pir-sdk/hints/` with
    `~/.cache/pir-sdk/hints/` fallback).
  - Byte-blob surface (`save_hints_bytes` /
    `load_hints_bytes`) for browser IndexedDB bridges.
  - Mismatched fingerprint fails fast with
    `PirError::InvalidState` rather than silently mis-using stale
    hints.
- **Shared protocol helpers** (`protocol.rs`): deduplicated
  `encode_request` / `decode_catalog` — previously each of the
  three clients maintained its own copy.
- **Observability Phase 1 — `tracing` spans**:
  - `#[tracing::instrument]` on every public method of
    `DpfClient` / `HarmonyClient` / `OnionClient` / `WsConnection`.
  - Consistent `backend = "dpf" | "harmony" | "onion"` field.
  - Three-tier level hierarchy: `info` (top-level ops) / `debug`
    (sub-ops) / `trace` (per-query inner loops).
  - `skip_all` keeps binary payloads / secrets out of span fields.
  - `tracing` dep with `log` feature so existing
    `log::info!` / `log::warn!` / `log::debug!` calls bridge to
    any installed subscriber.
- **Observability Phase 2 — `PirMetrics` wiring**:
  - `set_metrics_recorder(&mut self, Option<Arc<dyn PirMetrics>>)`
    on all three clients.
  - Handle propagates to every owned transport (DPF: 2,
    Harmony: 2, Onion: 1) with `&'static str` backend label.
  - Per-frame byte callbacks from `WsConnection` / `MockTransport`
    / `WasmWebSocketTransport`: `send` counts after confirmed-OK
    result; `recv` counts full raw frame including length prefix.
  - `on_connect` fires per-transport; `on_disconnect` fires once
    per client; `on_query_start` / `on_query_end(duration)`
    around `query_batch`.
  - `Option<Instant>`-threading pattern: `fire_query_start`
    returns `Some(Instant::now())` only when a recorder is
    installed (zero overhead — and zero `performance.now()`
    JS↔WASM boundary calls — when none is).
- **Integration test suite against live public PIR servers**:
  - Defaults to `wss://weikeng1.bitcoinpir.org` /
    `wss://weikeng2.bitcoinpir.org` with per-URL env var overrides.
  - Surfaced three protocol fixes: DPF batch wire format
    (spurious leading `level` byte + wrong `db_id` position +
    per-group `num_keys` → single top-level `keys_per_group`),
    catalog `num_dbs` decoded as u16 vs u8, and `wss://` support
    (rustls `ring` provider lazy-installed via `OnceLock` +
    256 MiB max-frame-size for ~32 MiB fresh-sync chunks).
- **`REQ_GET_DB_CATALOG` with legacy fallback** (Harmony):
  `fetch_catalog` tries the modern request first, falls back to
  `REQ_HARMONY_GET_INFO = 0x40` on empty / `RESP_ERROR` /
  unknown-variant. Unlocks `synced_height > 0` and
  cache-by-height for Harmony deployments.

### Fixed

- `is_connection_error` / `is_protocol_error` updated to match the
  new `PirError` variants from the taxonomy refinement.
- `decode_sibling_batch` now raises
  `PirError::MerkleVerificationFailed` on mid-round `RESP_ERROR`
  (tree-tops already fetched by that point — the server can't
  produce the verification evidence).
- `fetch_tree_tops` + the tree-top count check raise
  `PirError::ProtocolSkew` when the catalog and server disagree on
  `has_bucket_merkle` or `K_INDEX + K_CHUNK`.
- `ensure_sibling_groups_ready` tightened from
  "groups not empty" to `groups.len() == levels * k_index`
  (chunk counterpart likewise) — closes a latent bug where a
  stale cache with fewer levels would serve stale proofs.

### Security

- All three clients preserve the **Merkle INDEX item-count
  symmetry** invariant: every INDEX query emits exactly
  `INDEX_CUCKOO_NUM_HASHES = 2` Merkle items regardless of outcome
  (found at h=0, h=1, not-found, or whale).
- Whales participate in INDEX Merkle verification via their
  probed bins.
- Padding invariants (K=75 INDEX, K_CHUNK=80 CHUNK, 25 MERKLE) are
  enforced in the query path; the `merkle_verify` and
  `onion_merkle` modules preserve them.

[Unreleased]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/releases/tag/v0.1.0
