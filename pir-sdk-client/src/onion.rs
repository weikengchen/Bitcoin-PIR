//! OnionPIR client implementation.
//!
//! OnionPIR is a single-server PIR protocol based on fully homomorphic
//! encryption (BFV, Microsoft SEAL). The client encrypts its query under
//! its own secret key; the server operates on the ciphertexts and returns
//! an encrypted response that only the client can decrypt.
//!
//! ## Feature gating
//!
//! The real implementation is gated behind the `onion` cargo feature because
//! the upstream [`onionpir`](https://github.com/Bitcoin-PIR/OnionPIRv2-fork)
//! crate has a heavy native build: CMake + the Microsoft SEAL C++ library
//! (pulled in as a submodule) and Homebrew GCC on macOS. Most SDK consumers
//! don't need OnionPIR and shouldn't pay that cost.
//!
//! ```toml
//! [dependencies]
//! pir-sdk-client = { version = "0.1", features = ["onion"] }
//! ```
//!
//! Without the feature, `OnionClient` compiles but every query logs a
//! warning and returns `None` — so the rest of the SDK (DPF, HarmonyPIR)
//! stays usable on systems without a C++ toolchain.
//!
//! ## Protocol flow
//!
//! 1. Fetch JSON server info (`0x03`) — gives per-database OnionPIR params
//!    (index_bins, chunk_bins, index_k, chunk_k, tag_seed, total_packed,
//!    index_slots_per_bin, index_slot_size).
//! 2. Create a per-client `onionpir::Client`, generate Galois + GSW keys,
//!    export the secret key.
//! 3. Send `REQ_REGISTER_KEYS (0x50)` once per database — await
//!    `RESP_KEYS_ACK (0x50)`.
//! 4. For each INDEX round: send `REQ_ONIONPIR_INDEX_QUERY (0x51)` with K
//!    encrypted queries (2 × K because INDEX uses 2-hash cuckoo — one query
//!    per hash position per group). Decrypt, scan the 256-slot × 15-byte
//!    bin for a matching tag.
//! 5. For each CHUNK round: build a 6-hash cuckoo table client-side to find
//!    each entry's exact bin, send `REQ_ONIONPIR_CHUNK_QUERY (0x52)` with
//!    K_CHUNK encrypted queries. Decrypt PACKED_ENTRY_SIZE=3840 bytes per
//!    entry.
//! 6. Assemble entries into raw UTXO bytes and decode with varint.
//!
//! ## Privacy-critical padding
//!
//! Every INDEX round sends **exactly K queries** (padded with random-bin
//! dummies), every CHUNK round sends **exactly K_CHUNK queries**. This is
//! mandatory per `CLAUDE.md` and is implemented identically to the DPF
//! client — never "optimize" it away.

#[cfg(not(target_arch = "wasm32"))]
use crate::connection::WsConnection;
use crate::protocol::{decode_catalog, encode_request, REQ_GET_DB_CATALOG, RESP_DB_CATALOG};
use crate::transport::PirTransport;
use async_trait::async_trait;
use pir_sdk::{
    compute_sync_plan, merge_delta_batch, DatabaseCatalog, DatabaseInfo, DatabaseKind,
    PirBackendType, PirClient, PirError, PirResult, QueryResult, ScriptHash, SyncPlan, SyncResult,
    SyncStep,
};

// `UtxoEntry` is only constructed by the feature-gated decode path.
#[cfg(feature = "onion")]
use pir_sdk::UtxoEntry;

#[cfg(feature = "onion")]
use crate::onion_merkle::{
    parse_onionpir_merkle, verify_onion_merkle_batch, OnionMerkleInfo, OnionMerkleLeaf,
    OnionTreeKind,
};

#[cfg(feature = "onion")]
use pir_core::merkle::Hash256;

#[cfg(feature = "onion")]
use std::collections::{HashMap, HashSet};

// ─── Protocol wire codes ────────────────────────────────────────────────────

/// Request: fetch server info as JSON.
const REQ_GET_INFO_JSON: u8 = 0x03;
/// Response: JSON server info payload.
const RESP_GET_INFO_JSON: u8 = 0x03;
// `REQ_GET_DB_CATALOG` / `RESP_DB_CATALOG` come from `crate::protocol`.

/// Request: register FHE keys for a client.
#[cfg(feature = "onion")]
const REQ_REGISTER_KEYS: u8 = 0x50;
/// Response: FHE keys acknowledged.
#[cfg(feature = "onion")]
const RESP_KEYS_ACK: u8 = 0x50;
/// Request: batched encrypted INDEX queries.
#[cfg(feature = "onion")]
const REQ_ONIONPIR_INDEX_QUERY: u8 = 0x51;
/// Response: batched encrypted INDEX results.
#[cfg(feature = "onion")]
const RESP_ONIONPIR_INDEX_RESULT: u8 = 0x51;
/// Request: batched encrypted CHUNK queries.
#[cfg(feature = "onion")]
const REQ_ONIONPIR_CHUNK_QUERY: u8 = 0x52;
/// Response: batched encrypted CHUNK results.
#[cfg(feature = "onion")]
const RESP_ONIONPIR_CHUNK_RESULT: u8 = 0x52;

// ─── Layout constants ───────────────────────────────────────────────────────

/// Number of PBC hash functions (group assignment).
#[cfg(feature = "onion")]
const NUM_HASHES: usize = 3;

/// INDEX cuckoo hash functions (per-bin placement).
#[cfg(feature = "onion")]
const INDEX_CUCKOO_NUM_HASHES: usize = 2;

/// CHUNK cuckoo hash functions.
#[cfg(feature = "onion")]
const CHUNK_CUCKOO_NUM_HASHES: usize = 6;

/// Max kicks before declaring a cuckoo-build failure.
#[cfg(feature = "onion")]
const CHUNK_CUCKOO_MAX_KICKS: usize = 10000;

/// Master seed for CHUNK cuckoo derivation (must match server).
#[cfg(feature = "onion")]
const CHUNK_CUCKOO_SEED: u64 = 0xa3f7c2d918e4b065;

/// Sentinel for empty cuckoo slots.
#[cfg(feature = "onion")]
const EMPTY: u32 = u32::MAX;

/// Size of one packed entry bin in the CHUNK table.
#[cfg(feature = "onion")]
const PACKED_ENTRY_SIZE: usize = 3840;

// ─── Per-DB OnionPIR parameters ─────────────────────────────────────────────

/// OnionPIR-specific parameters that aren't captured by [`DatabaseInfo`].
///
/// These come from the JSON `onionpir` sub-object in the server info
/// response. The SDK keeps a per-`db_id` table so the right numbers flow
/// into query generation when the client talks to deltas as well as the
/// main database.
///
/// The struct is always present (its values are parsed + stored regardless
/// of feature gate), but the fields are only *read* when the `onion` feature
/// is on. The `allow(dead_code)` silences the warning on default builds.
#[derive(Clone, Debug)]
#[cfg_attr(not(feature = "onion"), allow(dead_code))]
struct OnionDbParams {
    /// Total number of packed entries in the DB (for CHUNK reverse index).
    total_packed: usize,
    /// Number of slots in each decrypted INDEX bin (typically 256).
    index_slots_per_bin: usize,
    /// Byte size of each INDEX slot (typically 15).
    index_slot_size: usize,
}

// ─── Send + Sync wrapper around onionpir::Client ────────────────────────────
//
// `onionpir::Client` wraps an opaque C++ pointer via FFI and is `!Send + !Sync`
// by default. We need both marker traits because `OnionClient` has to satisfy
// `PirClient: Send + Sync` (see `pir-sdk/src/client.rs`), and `OnionClient`'s
// `FheState` transitively holds `HashMap<_, SendClient>`.
//
// ─── Audit: what Rust methods `SendClient` exposes ──────────────────────────
//
// The full public API of `onionpir::Client` (upstream
// `rust/onionpir/src/lib.rs` @ rev `946550a`, pinned in our Cargo.toml) is:
//
//     new(num_entries: u64) -> Self                                 [ctor]
//     new_from_secret_key(num_entries, client_id, sk) -> Self       [ctor]
//     export_secret_key(&self) -> Vec<u8>                           [&self]
//     id(&self) -> u64                                              [&self]
//     generate_galois_keys(&mut self) -> Vec<u8>                    [&mut]
//     generate_gsw_keys(&mut self) -> Vec<u8>                       [&mut]
//     generate_query(&mut self, entry_index: u64) -> Vec<u8>        [&mut]
//     decrypt_response(&mut self, entry_index, response) -> Vec<u8> [&mut]
//     Drop::drop(&mut self)                                         [&mut]
//
// Only two methods take `&self`: `id` and `export_secret_key`. Everything
// else (including all query generation and decryption) requires `&mut self`.
//
// ─── Send safety ────────────────────────────────────────────────────────────
//
// `Send` is safe because:
// 1. `onionpir::Client` owns a unique C++ object via `ClientHandle`; no
//    internal sharing with other `onionpir::Client` instances.
// 2. All mutating entry points take `&mut self`, so an owned move across
//    threads cannot race with a concurrent `&mut` on the origin thread.
// 3. `Drop` takes `&mut self` and calls `onion_client_free`, a standard
//    per-instance `delete`.
//
// ─── Sync safety ────────────────────────────────────────────────────────────
//
// `Sync` means `&SendClient` is shareable across threads. Because the Rust
// borrow checker will only let a shared `&SendClient` invoke `&self` methods,
// the Sync safety argument only needs to cover `id` and `export_secret_key`.
//
// I audited the C++ side (upstream `src/ffi.cpp` + `src/ffi_c.cpp`) and
// confirmed:
// * `client_get_id(const OnionPirClient& client)` just reads an integer
//   field (`client.inner.get_client_id()`). No allocation, no mutation.
// * `client_export_secret_key(const OnionPirClient& client)` calls
//   SEAL's `SecretKey::save(stream)` into a *local* `stringstream`. SEAL's
//   `save` is a const member that only reads the secret-key polynomial.
//   Any SEAL-internal allocation goes through SEAL's default `MemoryPool`,
//   which is thread-safe by SEAL's contract.
//
// Neither function touches shared mutable state, global state, thread-local
// state, or OpenMP parallel regions — those all live on `Server::*`, which
// is explicitly documented as `!Send + !Sync` upstream and is not used here.
//
// ─── Practical note: `&self` paths are unused by the SDK ────────────────────
//
// In practice the OnionPIR SDK never actually invokes `&SendClient` methods
// concurrently. `FheState.level_clients` is only accessed via
// `get_level_client(&mut self, ...)` which takes `&mut self` on the
// `OnionClient`, and the per-query callers hold `&mut OnionClient`. So the
// Sync impl exists purely to satisfy the `PirClient: Send + Sync` trait
// bound — it is never exercised in parallel at runtime today.
//
// Keeping the Sync impl (instead of wrapping `SendClient` in a `Mutex`) is
// intentional: a `Mutex` would add lock overhead to every `get_level_client`
// call on the hot query path, and the guarantee it provides is no stronger
// than what the audit above already gives us.

#[cfg(feature = "onion")]
struct SendClient(onionpir::Client);

#[cfg(feature = "onion")]
// Safety: see the "Send + Sync wrapper around onionpir::Client" block above.
// Short version: `onionpir::Client` owns a unique C++ object via an opaque
// handle; all mutation is `&mut self`; there is no internal sharing.
unsafe impl Send for SendClient {}

#[cfg(feature = "onion")]
// Safety: see the "Send + Sync wrapper around onionpir::Client" block above.
// Short version: the only `&self` methods are `id` (integer read) and
// `export_secret_key` (const serialization into a local stringstream).
// Neither touches shared mutable state. No code path in the SDK actually
// shares `&SendClient` across threads today — the impl exists only to
// satisfy the `PirClient: Send + Sync` bound.
unsafe impl Sync for SendClient {}

// Compile-time assertion that `OnionClient` genuinely is `Send + Sync`. If
// somebody adds a new field that is `!Send` or `!Sync` (e.g. an `Rc`, a
// `RefCell`, or a raw pointer) without also wrapping it, this fails to
// compile rather than breaking the `PirClient` trait contract at a distant
// call site.
#[cfg(feature = "onion")]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SendClient>();
    assert_send_sync::<FheState>();
    assert_send_sync::<OnionClient>();
};
// Same assertion for the stub (non-`onion`) build: `OnionClient` there is a
// no-op but still has to meet `PirClient: Send + Sync`.
#[cfg(not(feature = "onion"))]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OnionClient>();
};

// ─── FHE state (only when the `onion` feature is on) ────────────────────────

#[cfg(feature = "onion")]
struct FheState {
    /// Deterministic client ID (overridden from C++'s `rand()` default).
    client_id: u64,
    /// Exported secret key bytes; used to spawn per-level clients.
    secret_key: Vec<u8>,
    /// Serialized Galois key bytes; re-sent on server LRU eviction.
    galois_keys: Vec<u8>,
    /// Serialized GSW key bytes; re-sent on server LRU eviction.
    gsw_keys: Vec<u8>,
    /// Per-level clients, keyed by `(db_id, level)` where level 0=index, 1=chunk.
    ///
    /// Lazily populated on first query to each `(db_id, level)` combination.
    /// Keys are long-lived; per-level clients just adjust `num_entries` for
    /// query generation and response decryption.
    level_clients: HashMap<(u8, u8), SendClient>,
    /// Database IDs for which we've already registered keys on the server.
    registered: HashSet<u8>,
}

// ─── OnionClient ────────────────────────────────────────────────────────────

/// OnionPIR client for single-server FHE-based PIR queries.
///
/// Requires the `onion` cargo feature to perform real queries. Without the
/// feature, queries succeed as no-ops returning `None` — useful for builds
/// on systems without a C++ toolchain.
pub struct OnionClient {
    server_url: String,
    conn: Option<Box<dyn PirTransport>>,
    catalog: Option<DatabaseCatalog>,
    /// Per-DB OnionPIR-specific parameters. Keyed by db_id.
    onion_params: std::collections::HashMap<u8, OnionDbParams>,
    /// Per-DB OnionPIR per-bin Merkle info, populated during `fetch_server_info`
    /// when the server exposes an `onionpir_merkle` section. Absent entries
    /// mean the server has no Merkle commitment for that DB and queries run
    /// unverified (matching DpfClient's `has_bucket_merkle=false` path).
    #[cfg(feature = "onion")]
    onion_merkle: std::collections::HashMap<u8, OnionMerkleInfo>,
    /// Cached raw JSON info (so we can re-parse per-DB params on demand).
    info_json: Option<String>,
    #[cfg(feature = "onion")]
    fhe: Option<FheState>,
}

impl OnionClient {
    /// Create a new OnionPIR client.
    pub fn new(server_url: &str) -> Self {
        Self {
            server_url: server_url.to_string(),
            conn: None,
            catalog: None,
            onion_params: std::collections::HashMap::new(),
            #[cfg(feature = "onion")]
            onion_merkle: std::collections::HashMap::new(),
            info_json: None,
            #[cfg(feature = "onion")]
            fhe: None,
        }
    }

    /// Install a pre-built transport directly, bypassing the URL-based
    /// [`PirClient::connect`] path.
    ///
    /// This is the test-injection escape hatch the `PirTransport` trait was
    /// designed around: state-machine tests can hand in a
    /// [`MockTransport`](crate::transport::MockTransport) (or any other
    /// impl) and drive the client without opening a real WebSocket.
    /// `PirClient::is_connected` returns `true` after this call.
    ///
    /// Note: with the `onion` feature, real queries also require FHE state
    /// (Galois + GSW keys) which is populated during
    /// [`PirClient::fetch_catalog`]. Tests that want to bypass the wire
    /// entirely should drive query primitives directly, not through
    /// `sync_with_plan`.
    pub fn connect_with_transport(&mut self, conn: Box<dyn PirTransport>) {
        self.conn = Some(conn);
    }

    /// Fetch the JSON server info and (best-effort) the DPF-format catalog,
    /// merging into a unified [`DatabaseCatalog`] plus per-DB OnionPIR params.
    async fn fetch_server_info(&mut self) -> PirResult<()> {
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;

        // Request JSON info.
        let req = encode_request(REQ_GET_INFO_JSON, &[]);
        let response = conn.roundtrip(&req).await?;

        if response.is_empty() || response[0] != RESP_GET_INFO_JSON {
            return Err(PirError::Protocol(
                "expected 0x03 JSON info response".into(),
            ));
        }
        let json_bytes = &response[1..];
        let json = std::str::from_utf8(json_bytes)
            .map_err(|e| PirError::Protocol(format!("info JSON not UTF-8: {}", e)))?
            .to_string();

        self.onion_params = parse_onion_params_per_db(&json);
        if self.onion_params.is_empty() {
            return Err(PirError::Protocol(
                "server has no OnionPIR data — is this an OnionPIR-enabled server?".into(),
            ));
        }

        // Parse onionpir_merkle (optional). Populated per-DB so queries
        // against the main DB, deltas, and secondary DBs each pick up the
        // right root + sibling-level layout.
        #[cfg(feature = "onion")]
        {
            self.onion_merkle = parse_onion_merkle_per_db(&json);
        }

        // Best-effort DPF catalog fetch for heights/names. If the server
        // doesn't support it, synthesize a single-DB catalog from JSON.
        let dpf_catalog = self.try_fetch_dpf_catalog().await.ok();

        let catalog = build_catalog(&json, &self.onion_params, dpf_catalog.as_ref());
        self.catalog = Some(catalog);
        self.info_json = Some(json);
        Ok(())
    }

    async fn try_fetch_dpf_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let req = encode_request(REQ_GET_DB_CATALOG, &[]);
        let response = conn.roundtrip(&req).await?;
        if response.is_empty() || response[0] != RESP_DB_CATALOG {
            return Err(PirError::Protocol("no DPF catalog available".into()));
        }
        decode_catalog(&response[1..])
    }

    /// Execute a single sync step for a batch of script hashes.
    #[cfg(feature = "onion")]
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        let params = self
            .onion_params
            .get(&db_info.db_id)
            .cloned()
            .ok_or_else(|| {
                PirError::InvalidState(format!(
                    "no OnionPIR params for db_id={}",
                    db_info.db_id
                ))
            })?;

        self.ensure_fhe_initialised()?;
        self.ensure_keys_registered(db_info).await?;

        log::info!(
            "[PIR-AUDIT] OnionPIR execute_step db_id={} ({}), {} scripthashes, K={}, K_CHUNK={}",
            db_info.db_id,
            db_info.name,
            script_hashes.len(),
            db_info.index_k,
            db_info.chunk_k
        );
        log::info!(
            "[PIR-AUDIT] OnionPIR padding: INDEX rounds send exactly K={} queries \
             (2*K cuckoo positions), CHUNK rounds send exactly K_CHUNK={} queries — \
             dummies fill empty groups.",
            db_info.index_k,
            db_info.chunk_k,
        );

        let (index_results, index_traces) = self
            .query_index_level(script_hashes, db_info, &params)
            .await?;

        let (chunk_data, data_merkle) = self
            .query_chunk_level(script_hashes, &index_results, db_info, &params)
            .await?;

        // Decode per-scripthash UTXOs from assembled raw bytes.
        let mut results = Vec::with_capacity(script_hashes.len());
        for (idx, ir) in index_results.iter().enumerate() {
            let qr = match ir {
                None => {
                    log::info!(
                        "[PIR-AUDIT] OnionPIR scripthash {}: NOT FOUND",
                        hex_short(&script_hashes[idx])
                    );
                    None
                }
                Some(ir) if ir.num_entries == 0 => {
                    log::info!(
                        "[PIR-AUDIT] OnionPIR scripthash {}: WHALE (excluded)",
                        hex_short(&script_hashes[idx])
                    );
                    Some(QueryResult {
                        entries: Vec::new(),
                        is_whale: true,
                        // Optimistic default — `run_merkle_verification`
                        // flips this to `false` if the INDEX proof fails.
                        merkle_verified: true,
                        raw_chunk_data: None,
                        // OnionPIR inspector state isn't part of Session 2
                        // scope (DPF-only). Kept empty so the struct shape
                        // matches across backends; OnionPIR's per-bin
                        // Merkle trace lives inside `index_traces` /
                        // `data_merkle` which are consumed by
                        // `run_merkle_verification` directly.
                        index_bins: Vec::new(),
                        chunk_bins: Vec::new(),
                        matched_index_idx: None,
                    })
                }
                Some(ir) => {
                    let raw = assemble_entry_bytes(ir, &chunk_data, db_info.db_id)?;
                    let entries = decode_utxo_entries(&raw);
                    log::info!(
                        "[PIR-AUDIT] OnionPIR scripthash {}: FOUND {} UTXOs \
                         (entry_id={}, num_entries={}, byte_offset={})",
                        hex_short(&script_hashes[idx]),
                        entries.len(),
                        ir.entry_id,
                        ir.num_entries,
                        ir.byte_offset,
                    );
                    Some(QueryResult {
                        entries,
                        is_whale: false,
                        // Optimistic default — `run_merkle_verification`
                        // flips this to `false` (and empties `entries`) if
                        // INDEX or DATA proofs fail for this query.
                        merkle_verified: true,
                        raw_chunk_data: if db_info.kind.is_delta() {
                            Some(raw)
                        } else {
                            None
                        },
                        // See whale-case comment above — OnionPIR inspector
                        // state is out of scope for Session 2.
                        index_bins: Vec::new(),
                        chunk_bins: Vec::new(),
                        matched_index_idx: None,
                    })
                }
            };
            results.push(qr);
        }

        // Per-bin Merkle verification — same semantics as DpfClient: on any
        // leaf failing verification the corresponding result is coerced to
        // None so callers can't distinguish server lies from genuine absence.
        //
        // Only runs if the server exposed an `onionpir_merkle` section for
        // this DB (otherwise it's a silent skip, matching
        // `has_bucket_merkle=false` for DPF/Harmony).
        if self.onion_merkle.contains_key(&db_info.db_id) {
            self.run_merkle_verification(
                &mut results,
                &index_traces,
                &index_results,
                &data_merkle,
                db_info,
            )
            .await?;
        } else {
            log::info!(
                "[PIR-AUDIT] OnionPIR Merkle verification SKIPPED \
                 (db_id={} has no onionpir_merkle section)",
                db_info.db_id
            );
        }

        Ok(results)
    }

    /// Run OnionPIR per-bin Merkle verification on the traces collected
    /// during `query_index_level` / `query_chunk_level`.
    ///
    /// A query passes iff ALL of its INDEX leaves and (if found) DATA leaves
    /// verify to the respective sub-tree roots. On any failure, that query's
    /// result is set to `None` so untrusted data never reaches the caller.
    #[cfg(feature = "onion")]
    async fn run_merkle_verification(
        &mut self,
        results: &mut [Option<QueryResult>],
        index_traces: &[IndexBinMerkle],
        index_results: &[Option<IndexResult>],
        data_merkle: &HashMap<u32, (Hash256, usize)>,
        db_info: &DatabaseInfo,
    ) -> PirResult<()> {
        let info = match self.onion_merkle.get(&db_info.db_id).cloned() {
            Some(m) => m,
            None => return Ok(()),
        };

        // Build the flat leaf list (both INDEX and DATA).
        let mut leaves: Vec<OnionMerkleLeaf> =
            Vec::with_capacity(index_traces.len() + data_merkle.len());

        for it in index_traces {
            leaves.push(OnionMerkleLeaf {
                tree: OnionTreeKind::Index,
                leaf_pos: it.leaf_pos,
                hash: it.bin_hash,
                result_idx: it.sh_idx,
            });
        }

        // DATA leaves map back to which scripthash they belong to via
        // entry_id range [entry_id, entry_id + num_entries). A single entry_id
        // may back multiple scripthashes (shared chunks are rare but possible
        // across batches) — we track all owners so any failure fails them all.
        let mut entry_id_to_result: HashMap<u32, Vec<usize>> = HashMap::new();
        for (idx, ir) in index_results.iter().enumerate() {
            if let Some(ir) = ir {
                if ir.num_entries == 0 {
                    continue; // whale has no DATA leaves
                }
                for i in 0..ir.num_entries as u32 {
                    let eid = ir.entry_id + i;
                    entry_id_to_result.entry(eid).or_default().push(idx);
                }
            }
        }

        for (eid, &(hash, leaf_pos)) in data_merkle {
            let owners = match entry_id_to_result.get(eid) {
                Some(o) => o,
                None => continue, // entry fetched but no owning query — shouldn't happen
            };
            for &owner in owners {
                leaves.push(OnionMerkleLeaf {
                    tree: OnionTreeKind::Data,
                    leaf_pos,
                    hash,
                    result_idx: owner,
                });
            }
        }

        if leaves.is_empty() {
            log::info!(
                "[PIR-AUDIT] OnionPIR Merkle: no leaves to verify for db_id={}",
                db_info.db_id
            );
            return Ok(());
        }

        log::info!(
            "[PIR-AUDIT] OnionPIR Merkle: verifying db_id={} ({} INDEX + {} DATA leaves across {} queries)",
            db_info.db_id,
            index_traces.len(),
            data_merkle.len(),
            results.len(),
        );

        let (client_id, secret_key) = {
            let fhe = self
                .fhe
                .as_ref()
                .ok_or_else(|| PirError::InvalidState("FHE not initialised".into()))?;
            (fhe.client_id, fhe.secret_key.clone())
        };
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let verdicts =
            verify_onion_merkle_batch(conn, &info, &leaves, client_id, &secret_key, db_info.db_id)
                .await?;

        // Aggregate: a result passes iff ALL of its leaves' verdicts are true.
        let mut per_query_ok = vec![true; results.len()];
        let mut per_query_touched = vec![false; results.len()];
        for leaf in &leaves {
            per_query_touched[leaf.result_idx] = true;
            let ok = verdicts
                .get(&(leaf.tree, leaf.leaf_pos))
                .copied()
                .unwrap_or(false);
            if !ok {
                per_query_ok[leaf.result_idx] = false;
            }
        }

        for qi in 0..results.len() {
            if !per_query_touched[qi] {
                continue;
            }
            if per_query_ok[qi] {
                log::info!("[PIR-AUDIT] OnionPIR Merkle PASSED for query #{}", qi);
                // merkle_verified is already true by construction above.
            } else {
                log::warn!(
                    "[PIR-AUDIT] OnionPIR Merkle FAILED for query #{}: \
                     emitting QueryResult {{ merkle_verified: false, entries: [] }} (untrusted)",
                    qi
                );
                // Surface the failure as a distinct signal from "not found"
                // (the old behaviour collapsed both to `None`). Entries are
                // wiped so downstream callers cannot accidentally trust
                // unverified data even if they ignore `merkle_verified`.
                results[qi] = Some(QueryResult::merkle_failed());
            }
        }

        Ok(())
    }

    /// Placeholder fallback when the `onion` feature is disabled.
    #[cfg(not(feature = "onion"))]
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        _db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        log::warn!(
            "OnionPIR query attempted without the `onion` cargo feature — \
             returning empty results for {} script hash(es). Enable the feature \
             (requires a C++ toolchain + cmake + SEAL) to run real OnionPIR queries.",
            script_hashes.len()
        );
        Ok(vec![None; script_hashes.len()])
    }

    // ─── FHE helpers (onion feature only) ───────────────────────────────────

    #[cfg(feature = "onion")]
    fn ensure_fhe_initialised(&mut self) -> PirResult<()> {
        if self.fhe.is_some() {
            return Ok(());
        }
        // Pick an arbitrary DB for key generation — keys are independent of
        // num_entries, so we just need something to instantiate the client.
        let any_db_id = *self
            .onion_params
            .keys()
            .next()
            .ok_or_else(|| PirError::InvalidState("no OnionPIR databases known".into()))?;
        let num_entries = self.num_entries_for_level(any_db_id, /* chunk */ false);

        // Override client_id with a cryptographic-quality random u64 — the
        // C++ default uses rand() which is non-crypto and can collide.
        let client_id: u64 = rand::random();

        // Allocate a temporary `Client` just for keygen + secret-key export,
        // then drop it. Per-level clients are created lazily from the exported
        // secret key as queries come in.
        let mut keygen = onionpir::Client::new_from_secret_key(
            num_entries as u64,
            client_id,
            &onionpir::Client::new(num_entries as u64).export_secret_key(),
        );
        // The above pattern (new + export + new_from_sk) is what the reference
        // onionpir_client does to decouple key ownership from num_entries.
        // We create one keygen client with our client_id bound to the newly
        // generated secret key, then pull keys + sk out of it.
        let galois_keys = keygen.generate_galois_keys();
        let gsw_keys = keygen.generate_gsw_keys();
        let secret_key = keygen.export_secret_key();

        self.fhe = Some(FheState {
            client_id,
            secret_key,
            galois_keys,
            gsw_keys,
            level_clients: HashMap::new(),
            registered: HashSet::new(),
        });
        log::info!("[PIR-AUDIT] OnionPIR generated FHE keys (client_id=0x{:016x})", client_id);
        Ok(())
    }

    /// Register keys for a given database if we haven't already. Server
    /// LRU-evicts at 100 clients, so this is also called lazily to retry.
    #[cfg(feature = "onion")]
    async fn ensure_keys_registered(&mut self, db_info: &DatabaseInfo) -> PirResult<()> {
        let already = self
            .fhe
            .as_ref()
            .map(|f| f.registered.contains(&db_info.db_id))
            .unwrap_or(false);
        if already {
            return Ok(());
        }
        self.register_keys(db_info.db_id).await
    }

    #[cfg(feature = "onion")]
    async fn register_keys(&mut self, db_id: u8) -> PirResult<()> {
        let (galois_keys, gsw_keys) = {
            let fhe = self
                .fhe
                .as_ref()
                .ok_or_else(|| PirError::InvalidState("FHE not initialised".into()))?;
            (fhe.galois_keys.clone(), fhe.gsw_keys.clone())
        };

        let payload = encode_register_keys(&galois_keys, &gsw_keys, db_id);
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn.roundtrip(&payload).await?;

        if response.is_empty() || response[0] != RESP_KEYS_ACK {
            return Err(PirError::Protocol(
                "expected RESP_KEYS_ACK (0x50)".into(),
            ));
        }

        self.fhe
            .as_mut()
            .expect("fhe present")
            .registered
            .insert(db_id);
        log::info!(
            "[PIR-AUDIT] OnionPIR registered keys for db_id={}",
            db_id
        );
        Ok(())
    }

    /// Number of packed entries in a DB at a particular level (false=index, true=chunk).
    #[cfg(feature = "onion")]
    fn num_entries_for_level(&self, db_id: u8, chunk: bool) -> usize {
        let db = self.catalog.as_ref().and_then(|c| c.get(db_id));
        match db {
            Some(d) if chunk => d.chunk_bins as usize,
            Some(d) => d.index_bins as usize,
            None => 1,
        }
    }

    /// Send an OnionPIR `[REQ_ONIONPIR_INDEX_QUERY | REQ_ONIONPIR_CHUNK_QUERY]`
    /// batch, parse the response, and transparently handle server-side
    /// LRU eviction of our registered keys.
    ///
    /// If the server returns an all-empty batch (see
    /// [`batch_looks_evicted`]), we treat it as eviction: mark
    /// `db_id` as un-registered, call `register_keys(db_id)`, and retry
    /// the exact same query once. A second all-empty response is
    /// surfaced as a [`PirError::SessionEvicted`] — classified as
    /// [`ErrorKind::SessionEvicted`], distinct from a generic
    /// [`ErrorKind::ServerError`], so a caller can reconnect and
    /// retry specifically on this cause without retrying on every
    /// server error. A second straight eviction after re-registering
    /// keys usually means FHE param drift or DB misconfig; the
    /// reconnect logic should cap retries at that point rather than
    /// spin.
    ///
    /// [`ErrorKind::SessionEvicted`]: pir_sdk::ErrorKind::SessionEvicted
    /// [`ErrorKind::ServerError`]: pir_sdk::ErrorKind::ServerError
    ///
    /// This is the single chokepoint for both `query_index_level` and
    /// `query_chunk_level`; keeping it in one place means the Merkle
    /// verification path (which uses its own sibling-query path in
    /// `onion_merkle.rs`) is the only OnionPIR code path still
    /// vulnerable to silent LRU eviction. That path's failure mode is
    /// "Merkle proof fails → result coerced to `Some(merkle_failed())`"
    /// which is already conservative, so it's acceptable to leave it
    /// uncovered here.
    #[cfg(feature = "onion")]
    async fn onionpir_batch_rpc(
        &mut self,
        msg: &[u8],
        expected_variant: u8,
        db_id: u8,
        variant_name: &'static str,
    ) -> PirResult<Vec<Vec<u8>>> {
        let batch = self
            .onionpir_batch_rpc_once(msg, expected_variant, variant_name)
            .await?;
        if !batch_looks_evicted(&batch) {
            return Ok(batch);
        }
        log::warn!(
            "[PIR-AUDIT] OnionPIR: all-empty {} for db_id={} — assuming \
             server LRU-evicted our keys. Re-registering and retrying once.",
            variant_name,
            db_id,
        );
        // Drop the "already registered" flag so `register_keys` will
        // actually re-register (otherwise a caller that calls
        // `ensure_keys_registered` before this would be a no-op).
        if let Some(fhe) = self.fhe.as_mut() {
            fhe.registered.remove(&db_id);
        }
        self.register_keys(db_id).await?;
        let batch = self
            .onionpir_batch_rpc_once(msg, expected_variant, variant_name)
            .await?;
        if batch_looks_evicted(&batch) {
            // Two consecutive empty batches ⇒ eviction signal even
            // after re-registering. Classified as
            // `ErrorKind::SessionEvicted` so a calling retry loop can
            // reconnect + re-register and try again, distinct from a
            // generic `ServerError` that a retry loop should NOT spin on.
            return Err(PirError::SessionEvicted(format!(
                "OnionPIR {} returned all-empty batch for db_id={} \
                 even after re-registering keys — server may be \
                 overloaded, or FHE params may have drifted",
                variant_name, db_id,
            )));
        }
        Ok(batch)
    }

    /// One-shot sender for `onionpir_batch_rpc`: single roundtrip, no retry.
    #[cfg(feature = "onion")]
    async fn onionpir_batch_rpc_once(
        &mut self,
        msg: &[u8],
        expected_variant: u8,
        variant_name: &'static str,
    ) -> PirResult<Vec<Vec<u8>>> {
        let conn = self.conn.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn.roundtrip(msg).await?;
        if response.is_empty() || response[0] != expected_variant {
            return Err(PirError::Protocol(format!(
                "expected {} (0x{:02x})",
                variant_name, expected_variant,
            )));
        }
        decode_onionpir_batch_result(&response[1..])
    }

    /// Get or create a per-level `onionpir::Client` for (db_id, level).
    #[cfg(feature = "onion")]
    fn get_level_client(&mut self, db_id: u8, chunk: bool) -> PirResult<&mut onionpir::Client> {
        let key = (db_id, if chunk { 1u8 } else { 0u8 });
        let num_entries = self.num_entries_for_level(db_id, chunk) as u64;
        let fhe = self
            .fhe
            .as_mut()
            .ok_or_else(|| PirError::InvalidState("FHE not initialised".into()))?;

        if !fhe.level_clients.contains_key(&key) {
            let client = onionpir::Client::new_from_secret_key(
                num_entries,
                fhe.client_id,
                &fhe.secret_key,
            );
            fhe.level_clients.insert(key, SendClient(client));
        }
        Ok(&mut fhe.level_clients.get_mut(&key).unwrap().0)
    }

    #[cfg(feature = "onion")]
    async fn query_index_level(
        &mut self,
        script_hashes: &[ScriptHash],
        db_info: &DatabaseInfo,
        params: &OnionDbParams,
    ) -> PirResult<(Vec<Option<IndexResult>>, Vec<IndexBinMerkle>)> {
        let k = db_info.index_k as usize;
        let bins = db_info.index_bins as usize;
        let tag_seed = db_info.tag_seed;
        let master_seed = pir_core::params::INDEX_PARAMS.master_seed;

        // Plan PBC rounds.
        let groups_per_sh: Vec<[usize; NUM_HASHES]> = script_hashes
            .iter()
            .map(|sh| pir_core::hash::derive_groups_3(sh, k))
            .collect();
        let rounds = pir_core::pbc::pbc_plan_rounds(&groups_per_sh, k, NUM_HASHES, 500);

        let mut results: Vec<Option<IndexResult>> =
            (0..script_hashes.len()).map(|_| None).collect();
        // INDEX Merkle traces: always `INDEX_CUCKOO_NUM_HASHES = 2` entries
        // per scripthash so Merkle item-count is uniform across found /
        // not-found / whale (CLAUDE.md: "Merkle INDEX Item-Count Symmetry").
        let mut index_traces: Vec<IndexBinMerkle> =
            Vec::with_capacity(script_hashes.len() * INDEX_CUCKOO_NUM_HASHES);
        let mut rng = SimpleRng::new();

        for (round_id, round) in rounds.iter().enumerate() {
            let mut group_to_sh: HashMap<usize, usize> = HashMap::new();
            for &(sh_idx, group) in round {
                group_to_sh.insert(group, sh_idx);
            }

            // Generate 2*K queries: [g0_h0, g0_h1, g1_h0, g1_h1, ...]
            let mut query_bins: Vec<u64> = Vec::with_capacity(2 * k);
            for g in 0..k {
                for h in 0..INDEX_CUCKOO_NUM_HASHES {
                    let bin = if let Some(&sh_idx) = group_to_sh.get(&g) {
                        let key = pir_core::hash::derive_cuckoo_key(master_seed, g, h);
                        pir_core::hash::cuckoo_hash(&script_hashes[sh_idx], key, bins) as u64
                    } else {
                        rng.next_u64() % bins as u64
                    };
                    query_bins.push(bin);
                }
            }

            // Encrypt queries.
            let index_client = self.get_level_client(db_info.db_id, false)?;
            let mut queries = Vec::with_capacity(2 * k);
            for &bin in &query_bins {
                queries.push(index_client.generate_query(bin));
            }

            // Send and receive. `onionpir_batch_rpc` transparently
            // re-registers keys + retries once if the server LRU-evicted
            // us mid-session (the 100-client cap in SEAL's KeyStore).
            let msg = encode_onionpir_batch_query(
                REQ_ONIONPIR_INDEX_QUERY,
                round_id as u16,
                &queries,
                db_info.db_id,
            );
            let batch = self
                .onionpir_batch_rpc(
                    &msg,
                    RESP_ONIONPIR_INDEX_RESULT,
                    db_info.db_id,
                    "RESP_ONIONPIR_INDEX_RESULT",
                )
                .await?;

            // Decrypt both cuckoo positions for every real scripthash in this
            // round. We DO NOT early-exit on match — both bins must be tracked
            // so the INDEX Merkle leaf count is 2 per query regardless of
            // outcome (see CLAUDE.md "Merkle INDEX Item-Count Symmetry"). The
            // second decrypt costs ~100ms FHE but closes the side channel
            // where sibling-round pass counts would otherwise leak
            // found-vs-not-found and h-position.
            let index_client = self.get_level_client(db_info.db_id, false)?;
            for &(sh_idx, group) in round {
                let tag = pir_core::hash::compute_tag(tag_seed, &script_hashes[sh_idx]);
                for h in 0..INDEX_CUCKOO_NUM_HASHES {
                    let qi = group * INDEX_CUCKOO_NUM_HASHES + h;
                    if qi >= batch.len() {
                        return Err(PirError::Protocol(format!(
                            "result batch truncated: qi={} len={}",
                            qi,
                            batch.len()
                        )));
                    }
                    let bin = query_bins[qi];
                    let entry = index_client.decrypt_response(bin, &batch[qi]);

                    // Emit a Merkle trace for EVERY probed bin (not just the
                    // matching one). Leaf position matches the server's
                    // flat-table ordering: `pbc_group * bins + bin`.
                    let entry_for_hash = if entry.len() >= PACKED_ENTRY_SIZE {
                        &entry[..PACKED_ENTRY_SIZE]
                    } else {
                        &entry[..]
                    };
                    index_traces.push(IndexBinMerkle {
                        sh_idx,
                        leaf_pos: group * bins + bin as usize,
                        bin_hash: pir_core::merkle::sha256(entry_for_hash),
                    });

                    // Only record the first matching index result — the
                    // second probe is tracking-only for Merkle symmetry.
                    if results[sh_idx].is_none() {
                        if let Some(ir) = scan_index_bin(
                            &entry,
                            tag,
                            params.index_slots_per_bin,
                            params.index_slot_size,
                        ) {
                            results[sh_idx] = Some(ir);
                        }
                    }
                }
            }
        }

        Ok((results, index_traces))
    }

    #[cfg(feature = "onion")]
    async fn query_chunk_level(
        &mut self,
        _script_hashes: &[ScriptHash],
        index_results: &[Option<IndexResult>],
        db_info: &DatabaseInfo,
        params: &OnionDbParams,
    ) -> PirResult<(HashMap<u32, Vec<u8>>, HashMap<u32, (Hash256, usize)>)> {
        // Collect unique entry_ids to fetch.
        let mut unique: Vec<u32> = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();
        for ir in index_results.iter().flatten() {
            if ir.num_entries == 0 {
                continue;
            }
            for i in 0..ir.num_entries as u32 {
                let eid = ir.entry_id + i;
                if seen.insert(eid) {
                    unique.push(eid);
                }
            }
        }

        let mut decrypted: HashMap<u32, Vec<u8>> = HashMap::new();
        // entry_id → (SHA256(decrypted_bin), pbc_group * chunk_bins + bin)
        // Populated per DATA bin fetched — later fed to the OnionPIR per-bin
        // Merkle verifier.
        let mut data_merkle: HashMap<u32, (Hash256, usize)> = HashMap::new();
        if unique.is_empty() {
            return Ok((decrypted, data_merkle));
        }

        let chunk_k = db_info.chunk_k as usize;
        let chunk_bins = db_info.chunk_bins as usize;

        // Build per-group reverse index once — scales with total entries.
        let reverse_index = build_chunk_reverse_index(params.total_packed, chunk_k);

        // Plan PBC rounds.
        let entry_groups: Vec<[usize; NUM_HASHES]> = unique
            .iter()
            .map(|&eid| pir_core::hash::derive_int_groups_3(eid, chunk_k))
            .collect();
        let rounds = pir_core::pbc::pbc_plan_rounds(&entry_groups, chunk_k, NUM_HASHES, 500);

        let mut cuckoo_cache: HashMap<usize, Vec<u32>> = HashMap::new();
        let mut rng = SimpleRng::new();

        for (round_id, round) in rounds.iter().enumerate() {
            struct Q {
                entry_id: u32,
                group: usize,
                bin: usize,
            }
            let mut round_queries: Vec<Q> = Vec::new();
            let mut group_bin: HashMap<usize, usize> = HashMap::new();

            for &(ei, group) in round {
                let eid = unique[ei];
                cuckoo_cache
                    .entry(group)
                    .or_insert_with(|| {
                        build_chunk_cuckoo_for_group(group, &reverse_index, chunk_bins)
                    });

                let keys = chunk_derive_keys(group);
                let bin = find_in_chunk_cuckoo(
                    cuckoo_cache.get(&group).unwrap(),
                    eid,
                    &keys,
                    chunk_bins,
                )
                .ok_or_else(|| {
                    PirError::InvalidState(format!(
                        "entry_id {} not in chunk cuckoo for group {}",
                        eid, group
                    ))
                })?;

                round_queries.push(Q {
                    entry_id: eid,
                    group,
                    bin,
                });
                group_bin.insert(group, bin);
            }

            // Generate K_CHUNK queries with dummies in empty groups.
            let chunk_client = self.get_level_client(db_info.db_id, true)?;
            let mut queries = Vec::with_capacity(chunk_k);
            for g in 0..chunk_k {
                let bin = if let Some(&b) = group_bin.get(&g) {
                    b as u64
                } else {
                    rng.next_u64() % chunk_bins as u64
                };
                queries.push(chunk_client.generate_query(bin));
            }

            // Same eviction-retry path as the INDEX round — see
            // `onionpir_batch_rpc` for the reasoning.
            let msg = encode_onionpir_batch_query(
                REQ_ONIONPIR_CHUNK_QUERY,
                round_id as u16,
                &queries,
                db_info.db_id,
            );
            let batch = self
                .onionpir_batch_rpc(
                    &msg,
                    RESP_ONIONPIR_CHUNK_RESULT,
                    db_info.db_id,
                    "RESP_ONIONPIR_CHUNK_RESULT",
                )
                .await?;

            let chunk_client = self.get_level_client(db_info.db_id, true)?;
            for q in &round_queries {
                if q.group >= batch.len() {
                    return Err(PirError::Protocol(format!(
                        "chunk result truncated: group={} len={}",
                        q.group,
                        batch.len()
                    )));
                }
                let bytes = chunk_client.decrypt_response(q.bin as u64, &batch[q.group]);
                if bytes.len() < PACKED_ENTRY_SIZE {
                    return Err(PirError::Protocol(format!(
                        "decrypted chunk shorter than PACKED_ENTRY_SIZE: {} < {}",
                        bytes.len(),
                        PACKED_ENTRY_SIZE
                    )));
                }
                let packed = &bytes[..PACKED_ENTRY_SIZE];
                decrypted.insert(q.entry_id, packed.to_vec());
                // DATA Merkle trace: one leaf per fetched entry_id. Leaf
                // position matches server's flat-table layout
                // (`pbc_group * chunk_bins + bin`).
                data_merkle.insert(
                    q.entry_id,
                    (
                        pir_core::merkle::sha256(packed),
                        q.group * chunk_bins + q.bin,
                    ),
                );
            }
        }

        Ok((decrypted, data_merkle))
    }
}

// ─── PirClient trait impl ───────────────────────────────────────────────────

#[async_trait]
impl PirClient for OnionClient {
    fn backend_type(&self) -> PirBackendType {
        PirBackendType::Onion
    }

    async fn connect(&mut self) -> PirResult<()> {
        log::info!("Connecting to OnionPIR server: {}", self.server_url);

        // Native → tokio-tungstenite; WASM → web-sys WebSocket. OnionPIR
        // has a single server so no try_join is needed.
        #[cfg(not(target_arch = "wasm32"))]
        let conn: Box<dyn PirTransport> = {
            Box::new(WsConnection::connect(&self.server_url).await?)
        };
        #[cfg(target_arch = "wasm32")]
        let conn: Box<dyn PirTransport> = {
            use crate::wasm_transport::WasmWebSocketTransport;
            Box::new(WasmWebSocketTransport::connect(&self.server_url).await?)
        };

        self.conn = Some(conn);
        #[cfg(not(feature = "onion"))]
        log::warn!(
            "OnionPIR client connected without the `onion` cargo feature — \
             queries will return empty results."
        );
        Ok(())
    }

    async fn disconnect(&mut self) -> PirResult<()> {
        if let Some(ref mut conn) = self.conn {
            let _ = conn.close().await;
        }
        self.conn = None;
        self.catalog = None;
        self.onion_params.clear();
        self.info_json = None;
        #[cfg(feature = "onion")]
        {
            self.fhe = None;
            self.onion_merkle.clear();
        }
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.conn.is_some()
    }

    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        self.fetch_server_info().await?;
        Ok(self
            .catalog
            .clone()
            .expect("fetch_server_info populates catalog"))
    }

    fn cached_catalog(&self) -> Option<&DatabaseCatalog> {
        self.catalog.as_ref()
    }

    fn compute_sync_plan(
        &self,
        catalog: &DatabaseCatalog,
        last_height: Option<u32>,
    ) -> PirResult<SyncPlan> {
        compute_sync_plan(catalog, last_height)
    }

    async fn sync(
        &mut self,
        script_hashes: &[ScriptHash],
        last_height: Option<u32>,
    ) -> PirResult<SyncResult> {
        if !self.is_connected() {
            self.connect().await?;
        }
        let catalog = match &self.catalog {
            Some(c) => c.clone(),
            None => self.fetch_catalog().await?,
        };
        let plan = self.compute_sync_plan(&catalog, last_height)?;
        self.sync_with_plan(script_hashes, &plan, None).await
    }

    async fn sync_with_plan(
        &mut self,
        script_hashes: &[ScriptHash],
        plan: &SyncPlan,
        cached_results: Option<&[Option<QueryResult>]>,
    ) -> PirResult<SyncResult> {
        if plan.is_empty() {
            return Ok(SyncResult {
                results: cached_results
                    .map(|r| r.to_vec())
                    .unwrap_or_else(|| vec![None; script_hashes.len()]),
                synced_height: plan.target_height,
                was_fresh_sync: false,
            });
        }

        let catalog = self
            .catalog
            .clone()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;
        let mut merged: Vec<Option<QueryResult>> = cached_results
            .map(|r| r.to_vec())
            .unwrap_or_else(|| vec![None; script_hashes.len()]);

        for (step_idx, step) in plan.steps.iter().enumerate() {
            log::info!(
                "[{}/{}] OnionPIR querying {} (db_id={}, height={})",
                step_idx + 1,
                plan.steps.len(),
                step.name,
                step.db_id,
                step.tip_height
            );

            let db_info = catalog
                .get(step.db_id)
                .ok_or(PirError::DatabaseNotFound(step.db_id))?
                .clone();

            let step_results = self.execute_step(script_hashes, step, &db_info).await?;

            if step.is_full() {
                merged = step_results;
            } else {
                merged = merge_delta_batch(&merged, &step_results)?;
            }
        }

        Ok(SyncResult {
            results: merged,
            synced_height: plan.target_height,
            was_fresh_sync: plan.is_fresh_sync,
        })
    }

    async fn query_batch(
        &mut self,
        script_hashes: &[ScriptHash],
        db_id: u8,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        let catalog = self
            .catalog
            .clone()
            .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;
        let db_info = catalog
            .get(db_id)
            .ok_or(PirError::DatabaseNotFound(db_id))?
            .clone();
        let step = SyncStep::from_db_info(&db_info);
        self.execute_step(script_hashes, &step, &db_info).await
    }
}

// ─── INDEX-level scan result ────────────────────────────────────────────────

#[cfg(feature = "onion")]
#[derive(Clone, Debug)]
struct IndexResult {
    entry_id: u32,
    byte_offset: u16,
    num_entries: u8,
}

/// Per-bin Merkle trace entry from the INDEX or DATA level.
///
/// Emitted for **every** probed cuckoo bin so the INDEX leaf count is uniform
/// across found / not-found / whale — see CLAUDE.md's
/// "Merkle INDEX Item-Count Symmetry" invariant. One of these is pushed per
/// bin we inspect (INDEX) or per entry_id we fetch (DATA).
#[cfg(feature = "onion")]
#[derive(Clone, Debug)]
struct IndexBinMerkle {
    /// Back-reference to which scripthash (query index) this bin belongs to.
    sh_idx: usize,
    /// `pbc_group * index_bins + bin` — leaf position in the flat INDEX tree.
    leaf_pos: usize,
    /// `SHA256(decrypted_bin[..PACKED_ENTRY_SIZE])`.
    bin_hash: Hash256,
}

/// Scan a decrypted INDEX bin (slots_per_bin × slot_size bytes) for a tag.
/// OnionPIR slot layout: `tag(8) | entry_id(4) | byte_offset(2) | num_entries(1)`.
#[cfg(feature = "onion")]
fn scan_index_bin(
    entry_bytes: &[u8],
    tag: u64,
    slots_per_bin: usize,
    slot_size: usize,
) -> Option<IndexResult> {
    for slot in 0..slots_per_bin {
        let off = slot * slot_size;
        if off + slot_size > entry_bytes.len() {
            break;
        }
        let slot_tag = u64::from_le_bytes(entry_bytes[off..off + 8].try_into().ok()?);
        if slot_tag == tag && slot_tag != 0 {
            let entry_id =
                u32::from_le_bytes(entry_bytes[off + 8..off + 12].try_into().ok()?);
            let byte_offset =
                u16::from_le_bytes(entry_bytes[off + 12..off + 14].try_into().ok()?);
            let num_entries = entry_bytes[off + 14];
            return Some(IndexResult {
                entry_id,
                byte_offset,
                num_entries,
            });
        }
    }
    None
}

/// Stitch raw entry bytes into a single UTXO data blob starting at byte_offset.
#[cfg(feature = "onion")]
fn assemble_entry_bytes(
    ir: &IndexResult,
    chunk_data: &HashMap<u32, Vec<u8>>,
    db_id: u8,
) -> PirResult<Vec<u8>> {
    let mut out = Vec::with_capacity(ir.num_entries as usize * PACKED_ENTRY_SIZE);
    for i in 0..ir.num_entries as u32 {
        let eid = ir.entry_id + i;
        let entry = chunk_data.get(&eid).ok_or_else(|| {
            PirError::InvalidState(format!(
                "missing decrypted entry_id {} (db_id={})",
                eid, db_id
            ))
        })?;
        if i == 0 {
            let start = ir.byte_offset as usize;
            if start > entry.len() {
                return Err(PirError::Protocol(format!(
                    "byte_offset {} exceeds entry size {}",
                    start,
                    entry.len()
                )));
            }
            out.extend_from_slice(&entry[start..]);
        } else {
            out.extend_from_slice(entry);
        }
    }
    Ok(out)
}

/// Decode UTXO entries from assembled entry bytes (varint-encoded).
///
/// Layout: `varint(num_utxos) | [txid(32) | varint(vout) | varint(amount)] * N`.
#[cfg(feature = "onion")]
fn decode_utxo_entries(data: &[u8]) -> Vec<UtxoEntry> {
    let mut entries = Vec::new();
    if data.is_empty() {
        return entries;
    }
    let mut pos = 0;
    let (num_utxos, vr) = pir_core::codec::read_varint(&data[pos..]);
    pos += vr;

    for _ in 0..num_utxos {
        if pos + 32 > data.len() {
            break;
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        if pos >= data.len() {
            break;
        }
        let (vout, vr) = pir_core::codec::read_varint(&data[pos..]);
        pos += vr;
        if pos >= data.len() {
            break;
        }
        let (amount, ar) = pir_core::codec::read_varint(&data[pos..]);
        pos += ar;

        entries.push(UtxoEntry {
            txid,
            vout: vout as u32,
            amount_sats: amount,
        });
    }

    entries
}

// ─── Client-side CHUNK cuckoo (6-hash, slots_per_bin=1) ─────────────────────

#[cfg(feature = "onion")]
fn chunk_derive_keys(group_id: usize) -> [u64; CHUNK_CUCKOO_NUM_HASHES] {
    let mut keys = [0u64; CHUNK_CUCKOO_NUM_HASHES];
    for (h, k) in keys.iter_mut().enumerate() {
        *k = pir_core::hash::splitmix64(
            CHUNK_CUCKOO_SEED
                .wrapping_add((group_id as u64).wrapping_mul(pir_core::hash::GOLDEN_RATIO))
                .wrapping_add((h as u64).wrapping_mul(pir_core::hash::CUCKOO_KEY_MIX)),
        );
    }
    keys
}

#[cfg(feature = "onion")]
#[inline]
fn chunk_cuckoo_hash(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (pir_core::hash::splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

#[cfg(feature = "onion")]
fn build_chunk_reverse_index(total_entries: usize, k_chunk: usize) -> Vec<Vec<u32>> {
    let mut index: Vec<Vec<u32>> = (0..k_chunk).map(|_| Vec::new()).collect();
    for eid in 0..total_entries as u32 {
        let groups = pir_core::hash::derive_int_groups_3(eid, k_chunk);
        for &g in &groups {
            index[g].push(eid);
        }
    }
    index
}

#[cfg(feature = "onion")]
fn build_chunk_cuckoo_for_group(
    group_id: usize,
    reverse_index: &[Vec<u32>],
    bins_per_table: usize,
) -> Vec<u32> {
    let entries = &reverse_index[group_id];
    let keys = chunk_derive_keys(group_id);
    let mut table = vec![EMPTY; bins_per_table];

    for &entry_id in entries {
        // Try primary placements.
        let mut placed = false;
        for &key in keys.iter() {
            let bin = chunk_cuckoo_hash(entry_id, key, bins_per_table);
            if table[bin] == EMPTY {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if placed {
            continue;
        }

        // Kick loop — mirrors reference implementation exactly so bin
        // assignments match the server.
        let mut current_id = entry_id;
        let mut current_hash_fn = 0;
        let mut current_bin = chunk_cuckoo_hash(entry_id, keys[0], bins_per_table);
        let mut success = false;

        for kick in 0..CHUNK_CUCKOO_MAX_KICKS {
            let evicted = table[current_bin];
            table[current_bin] = current_id;

            for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                let try_h = (current_hash_fn + 1 + h) % CHUNK_CUCKOO_NUM_HASHES;
                let bin = chunk_cuckoo_hash(evicted, keys[try_h], bins_per_table);
                if bin == current_bin {
                    continue;
                }
                if table[bin] == EMPTY {
                    table[bin] = evicted;
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }

            let alt_h =
                (current_hash_fn + 1 + kick % (CHUNK_CUCKOO_NUM_HASHES - 1)) % CHUNK_CUCKOO_NUM_HASHES;
            let alt_bin = chunk_cuckoo_hash(evicted, keys[alt_h], bins_per_table);
            let final_bin = if alt_bin == current_bin {
                let h2 = (alt_h + 1) % CHUNK_CUCKOO_NUM_HASHES;
                chunk_cuckoo_hash(evicted, keys[h2], bins_per_table)
            } else {
                alt_bin
            };

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        if !success {
            // Don't panic — let the caller surface this as a protocol error.
            log::error!(
                "OnionPIR client-side cuckoo failed for entry_id={} group={}",
                entry_id,
                group_id
            );
        }
    }

    table
}

#[cfg(feature = "onion")]
fn find_in_chunk_cuckoo(
    table: &[u32],
    entry_id: u32,
    keys: &[u64; CHUNK_CUCKOO_NUM_HASHES],
    bins_per_table: usize,
) -> Option<usize> {
    for &key in keys.iter() {
        let bin = chunk_cuckoo_hash(entry_id, key, bins_per_table);
        if table[bin] == entry_id {
            return Some(bin);
        }
    }
    None
}

// ─── Wire encoding / decoding ──────────────────────────────────────────────

/// Encode a `RegisterKeysMsg`.
#[cfg(feature = "onion")]
fn encode_register_keys(galois: &[u8], gsw: &[u8], db_id: u8) -> Vec<u8> {
    let trailing = if db_id != 0 { 1 } else { 0 };
    let payload_len = 1 + 4 + galois.len() + 4 + gsw.len() + trailing;
    let mut buf = Vec::with_capacity(4 + payload_len);
    buf.extend_from_slice(&(payload_len as u32).to_le_bytes());
    buf.push(REQ_REGISTER_KEYS);
    buf.extend_from_slice(&(galois.len() as u32).to_le_bytes());
    buf.extend_from_slice(galois);
    buf.extend_from_slice(&(gsw.len() as u32).to_le_bytes());
    buf.extend_from_slice(gsw);
    if db_id != 0 {
        buf.push(db_id);
    }
    buf
}

/// Encode an `OnionPirBatchQuery` for INDEX (0x51) or CHUNK (0x52) variants.
#[cfg(feature = "onion")]
fn encode_onionpir_batch_query(
    variant: u8,
    round_id: u16,
    queries: &[Vec<u8>],
    db_id: u8,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(variant);
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.push(queries.len() as u8);
    for q in queries {
        payload.extend_from_slice(&(q.len() as u32).to_le_bytes());
        payload.extend_from_slice(q);
    }
    if db_id != 0 {
        payload.push(db_id);
    }
    let mut msg = Vec::with_capacity(4 + payload.len());
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(&payload);
    msg
}

/// Detect whether an OnionPIR batch response signals that the server
/// has lost our keys.
///
/// The server-side `unified_server` loop wraps each `answer_query`
/// call in `catch_unwind` and returns `Vec::new()` on panic. When the
/// SEAL `KeyStore` has evicted our `client_id` (after 100 concurrent
/// clients, FIFO), every `answer_query` for us throws inside SEAL →
/// panics → returns empty. Since all queries in one batch share a
/// `client_id`, either every slot is empty (we've been evicted) or
/// every slot carries a real ciphertext. An all-empty batch with ≥1
/// slot is therefore an unambiguous eviction signal; an empty-length
/// batch is not (it would indicate a decode error in the outer frame,
/// which is handled elsewhere).
///
/// Kept as a free-standing function (rather than `impl OnionClient`)
/// so it can be unit-tested without the `onion` cargo feature.
/// The function itself has no FHE dependencies; the `#[allow(dead_code)]`
/// attribute below silences the spurious "never used" warning on
/// non-onion builds, where the only call sites are cfg-gated out.
#[cfg_attr(not(feature = "onion"), allow(dead_code))]
pub(crate) fn batch_looks_evicted(batch: &[Vec<u8>]) -> bool {
    !batch.is_empty() && batch.iter().all(|r| r.is_empty())
}

/// Decode an `OnionPirBatchResult` payload (after the variant byte).
///
/// Wire format: `[2B round_id][1B num_groups]({ [4B len][bytes] })*`.
#[cfg(feature = "onion")]
fn decode_onionpir_batch_result(data: &[u8]) -> PirResult<Vec<Vec<u8>>> {
    if data.len() < 3 {
        return Err(PirError::Decode("result batch too short".into()));
    }
    let mut pos = 2; // skip round_id
    let num_groups = data[pos] as usize;
    pos += 1;
    let mut results = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        if pos + 4 > data.len() {
            return Err(PirError::Decode("truncated result len".into()));
        }
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + len > data.len() {
            return Err(PirError::Decode("truncated result bytes".into()));
        }
        results.push(data[pos..pos + len].to_vec());
        pos += len;
    }
    Ok(results)
}

// ─── JSON parsing (minimal, no serde) ───────────────────────────────────────

/// Parse `"key":<number>` or `"key":"0xHEX"` out of a JSON string.
fn json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)?;
    let start = pos + needle.len();
    let rest = json[start..].trim_start();
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        let hex = &rest[..end];
        u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    }
}

/// Find a JSON sub-object `"key":{ ... }` and return its inner slice.
fn extract_json_object<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)?;
    let brace = json[start..].find('{')? + start;
    let mut depth = 0;
    let mut end = brace;
    for (i, c) in json[brace..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = brace + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    Some(&json[brace..end])
}

/// Parse per-DB OnionPIR params from the JSON info response.
///
/// Looks at the top-level `"onionpir"` (main DB, db_id=0) and each entry in
/// `"databases":[ ... ]` with a nested `"onionpir"` object.
fn parse_onion_params_per_db(json: &str) -> std::collections::HashMap<u8, OnionDbParams> {
    let mut out = std::collections::HashMap::new();

    // Main DB (db_id=0) — only if top-level has an onionpir sub-object.
    if let Some(opi) = extract_json_object(json, "onionpir") {
        if let Some(p) = parse_onion_params_from_opi(opi) {
            out.insert(0u8, p);
        }
    }

    // Per-DB entries. The regex-free path: scan "databases":[...] and find
    // each { db_id:.., onionpir:{...} } block.
    if let Some(dbs) = extract_json_object_array(json, "databases") {
        for entry in dbs {
            let id = match json_u64(entry, "db_id") {
                Some(v) => v as u8,
                None => continue,
            };
            if let Some(opi) = extract_json_object(entry, "onionpir") {
                if let Some(p) = parse_onion_params_from_opi(opi) {
                    out.insert(id, p);
                }
            }
        }
    }

    out
}

fn parse_onion_params_from_opi(opi: &str) -> Option<OnionDbParams> {
    Some(OnionDbParams {
        total_packed: json_u64(opi, "total_packed_entries")? as usize,
        index_slots_per_bin: json_u64(opi, "index_slots_per_bin")? as usize,
        index_slot_size: json_u64(opi, "index_slot_size")? as usize,
    })
}

/// Parse per-DB OnionPIR per-bin Merkle info from the JSON info response.
///
/// Looks for a top-level `"onionpir_merkle"` sub-object (main DB, db_id=0)
/// and each entry in `"databases":[ ... ]` with a nested `"onionpir_merkle"`
/// object. Returns an empty map if the server has no Merkle commitment at
/// all — callers treat that as "skip verification" (analogous to
/// `DatabaseInfo::has_bucket_merkle=false`).
#[cfg(feature = "onion")]
fn parse_onion_merkle_per_db(json: &str) -> std::collections::HashMap<u8, OnionMerkleInfo> {
    let mut out = std::collections::HashMap::new();

    // Main DB (db_id=0) — top-level onionpir_merkle.
    if let Some(info) = parse_onionpir_merkle(json) {
        out.insert(0u8, info);
    }

    // Per-DB entries. Each element is a full JSON object so
    // parse_onionpir_merkle can locate the nested "onionpir_merkle" sub-object
    // on its own.
    if let Some(dbs) = extract_json_object_array(json, "databases") {
        for entry in dbs {
            let id = match json_u64(entry, "db_id") {
                Some(v) => v as u8,
                None => continue,
            };
            if let Some(info) = parse_onionpir_merkle(entry) {
                out.insert(id, info);
            }
        }
    }

    out
}

/// Extract array elements of a top-level `"key":[{...},{...},...]` JSON field.
/// Returns each object (including braces) as a `&str`.
fn extract_json_object_array<'a>(json: &'a str, key: &str) -> Option<Vec<&'a str>> {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)?;
    let start = pos + needle.len();
    let rest = json[start..].trim_start();
    let rest = rest.strip_prefix('[')?;
    let arr_start = json.len() - rest.len();

    let mut depth = 0i32;
    let mut objs = Vec::new();
    let mut current_start: Option<usize> = None;
    for (i, c) in rest.char_indices() {
        let abs = arr_start + i;
        match c {
            '{' => {
                if depth == 0 {
                    current_start = Some(abs);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = current_start.take() {
                        objs.push(&json[s..abs + 1]);
                    }
                }
            }
            ']' if depth == 0 => return Some(objs),
            _ => {}
        }
    }
    Some(objs)
}

/// Build a [`DatabaseCatalog`] from JSON info + optional DPF catalog.
///
/// Prefers DPF catalog data when present (gives real names and heights);
/// otherwise synthesizes a single full-snapshot entry per OnionPIR DB.
fn build_catalog(
    json: &str,
    onion_params: &std::collections::HashMap<u8, OnionDbParams>,
    dpf: Option<&DatabaseCatalog>,
) -> DatabaseCatalog {
    // Index OnionPIR-level params (index_bins, chunk_bins, index_k, chunk_k,
    // tag_seed) by db_id. Falls back to top-level fields if per-DB missing.
    let top_index_bins = json_u64(json, "index_bins_per_table").unwrap_or(0) as u32;
    let top_chunk_bins = json_u64(json, "chunk_bins_per_table").unwrap_or(0) as u32;
    let top_index_k = json_u64(json, "index_k").unwrap_or(75) as u8;
    let top_chunk_k = json_u64(json, "chunk_k").unwrap_or(80) as u8;
    let top_tag_seed = json_u64(json, "tag_seed").unwrap_or(0);
    let top_opi = extract_json_object(json, "onionpir");

    // Prefer DPF-catalog heights when available.
    if let Some(dc) = dpf {
        let mut dbs = Vec::with_capacity(dc.databases.len());
        for d in &dc.databases {
            if !onion_params.contains_key(&d.db_id) {
                // Skip DBs that don't have OnionPIR data on this server.
                continue;
            }
            // Override index/chunk bins with OnionPIR-specific values if present.
            let (opi_bins_idx, opi_bins_chunk, opi_index_k, opi_chunk_k, opi_tag_seed) =
                onion_level_params(json, d.db_id, top_index_bins, top_chunk_bins, top_index_k, top_chunk_k, top_tag_seed);
            dbs.push(DatabaseInfo {
                db_id: d.db_id,
                kind: d.kind,
                name: d.name.clone(),
                height: d.height,
                index_bins: opi_bins_idx,
                chunk_bins: opi_bins_chunk,
                index_k: opi_index_k,
                chunk_k: opi_chunk_k,
                tag_seed: opi_tag_seed,
                dpf_n_index: pir_core::params::compute_dpf_n(opi_bins_idx as usize),
                dpf_n_chunk: pir_core::params::compute_dpf_n(opi_bins_chunk as usize),
                has_bucket_merkle: false,
            });
        }
        if !dbs.is_empty() {
            return DatabaseCatalog { databases: dbs };
        }
    }

    // Fallback: synthesize from OnionPIR JSON alone.
    let mut dbs = Vec::new();
    let mut ids: Vec<u8> = onion_params.keys().copied().collect();
    ids.sort();
    for id in ids {
        let (bins_idx, bins_chunk, index_k, chunk_k, tag_seed) = onion_level_params(
            json, id, top_index_bins, top_chunk_bins, top_index_k, top_chunk_k, top_tag_seed,
        );
        dbs.push(DatabaseInfo {
            db_id: id,
            kind: DatabaseKind::Full,
            name: if id == 0 {
                "main".into()
            } else {
                format!("db{}", id)
            },
            height: 0,
            index_bins: bins_idx,
            chunk_bins: bins_chunk,
            index_k,
            chunk_k,
            tag_seed,
            dpf_n_index: pir_core::params::compute_dpf_n(bins_idx as usize),
            dpf_n_chunk: pir_core::params::compute_dpf_n(bins_chunk as usize),
            has_bucket_merkle: false,
        });
    }

    // Silence unused-warning when DPF branch didn't run but we built from JSON only.
    let _ = top_opi;

    DatabaseCatalog { databases: dbs }
}

/// Pick OnionPIR level params for a db_id, falling back to top-level defaults.
fn onion_level_params(
    json: &str,
    db_id: u8,
    fallback_index_bins: u32,
    fallback_chunk_bins: u32,
    fallback_index_k: u8,
    fallback_chunk_k: u8,
    fallback_tag_seed: u64,
) -> (u32, u32, u8, u8, u64) {
    let opi_section = if db_id == 0 {
        extract_json_object(json, "onionpir")
    } else {
        // Look for the matching entry in the databases array.
        extract_json_object_array(json, "databases")
            .and_then(|entries| {
                entries
                    .into_iter()
                    .find(|e| json_u64(e, "db_id") == Some(db_id as u64))
            })
            .and_then(|e| extract_json_object(e, "onionpir"))
    };
    if let Some(opi) = opi_section {
        let ib = json_u64(opi, "index_bins_per_table").unwrap_or(fallback_index_bins as u64) as u32;
        let cb = json_u64(opi, "chunk_bins_per_table").unwrap_or(fallback_chunk_bins as u64) as u32;
        let ik = json_u64(opi, "index_k").unwrap_or(fallback_index_k as u64) as u8;
        let ck = json_u64(opi, "chunk_k").unwrap_or(fallback_chunk_k as u64) as u8;
        let ts = json_u64(opi, "tag_seed").unwrap_or(fallback_tag_seed);
        (ib, cb, ik, ck, ts)
    } else {
        (
            fallback_index_bins,
            fallback_chunk_bins,
            fallback_index_k,
            fallback_chunk_k,
            fallback_tag_seed,
        )
    }
}

// ─── Misc helpers ──────────────────────────────────────────────────────────

/// First 8 hex chars of a script hash — for concise audit logs.
#[cfg(feature = "onion")]
fn hex_short(sh: &[u8]) -> String {
    let mut s = String::with_capacity(16 + 3);
    for b in sh.iter().take(8) {
        s.push_str(&format!("{:02x}", b));
    }
    s.push('.');
    s.push('.');
    s.push('.');
    s
}

/// Tiny deterministic PRNG (seeded from wall clock) for dummy query bins.
#[cfg(feature = "onion")]
struct SimpleRng {
    state: u64,
}

#[cfg(feature = "onion")]
impl SimpleRng {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xcafebabedeadbeef);
        Self {
            state: pir_core::hash::splitmix64(seed),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(pir_core::hash::GOLDEN_RATIO);
        pir_core::hash::splitmix64(self.state)
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_request_simple() {
        let buf = encode_request(0x03, &[]);
        assert_eq!(buf, vec![1, 0, 0, 0, 0x03]);
    }

    #[test]
    fn test_json_u64_decimal() {
        assert_eq!(json_u64(r#"{"k":42,"x":0}"#, "k"), Some(42));
        assert_eq!(json_u64(r#"{"foo":null,"k":7}"#, "k"), Some(7));
    }

    #[test]
    fn test_json_u64_hex() {
        assert_eq!(
            json_u64(r#"{"tag_seed":"0x71a2ef38b4c90d15"}"#, "tag_seed"),
            Some(0x71a2ef38b4c90d15),
        );
    }

    #[test]
    fn test_extract_json_object_nested() {
        let j = r#"{"outer":{"inner":{"a":1}},"x":2}"#;
        assert_eq!(extract_json_object(j, "outer"), Some(r#"{"inner":{"a":1}}"#));
        assert_eq!(extract_json_object(j, "inner"), Some(r#"{"a":1}"#));
    }

    #[test]
    fn test_parse_onion_params_main_only() {
        let j = r#"{"onionpir":{"total_packed_entries":1000,"index_bins_per_table":100,"chunk_bins_per_table":200,"tag_seed":"0x1","index_k":75,"chunk_k":80,"index_slots_per_bin":256,"index_slot_size":15,"chunk_slots_per_bin":1,"chunk_slot_size":3840}}"#;
        let params = parse_onion_params_per_db(j);
        assert_eq!(params.len(), 1);
        let p = params.get(&0).unwrap();
        assert_eq!(p.total_packed, 1000);
        assert_eq!(p.index_slots_per_bin, 256);
        assert_eq!(p.index_slot_size, 15);
    }

    #[test]
    fn test_parse_onion_params_multi_db() {
        let j = r#"{"onionpir":{"total_packed_entries":1000,"index_slots_per_bin":256,"index_slot_size":15},"databases":[{"db_id":0,"onionpir":{"total_packed_entries":1000,"index_slots_per_bin":256,"index_slot_size":15}},{"db_id":1,"onionpir":{"total_packed_entries":50,"index_slots_per_bin":128,"index_slot_size":15}}]}"#;
        let params = parse_onion_params_per_db(j);
        assert_eq!(params.len(), 2);
        assert_eq!(params.get(&0).unwrap().total_packed, 1000);
        assert_eq!(params.get(&1).unwrap().total_packed, 50);
        assert_eq!(params.get(&1).unwrap().index_slots_per_bin, 128);
    }

    #[test]
    fn test_parse_onion_params_no_onionpir() {
        let j = r#"{"index_bins_per_table":100,"chunk_bins_per_table":200}"#;
        assert!(parse_onion_params_per_db(j).is_empty());
    }

    #[test]
    fn test_build_catalog_from_json_only() {
        let j = r#"{"onionpir":{"total_packed_entries":1000,"index_bins_per_table":100,"chunk_bins_per_table":200,"tag_seed":"0xdeadbeef","index_k":75,"chunk_k":80,"index_slots_per_bin":256,"index_slot_size":15,"chunk_slots_per_bin":1,"chunk_slot_size":3840}}"#;
        let params = parse_onion_params_per_db(j);
        let catalog = build_catalog(j, &params, None);
        assert_eq!(catalog.databases.len(), 1);
        let db = &catalog.databases[0];
        assert_eq!(db.db_id, 0);
        assert_eq!(db.index_bins, 100);
        assert_eq!(db.chunk_bins, 200);
        assert_eq!(db.tag_seed, 0xdeadbeef);
        assert!(matches!(db.kind, DatabaseKind::Full));
    }

    #[test]
    fn test_onion_client_new_uninitialised() {
        let c = OnionClient::new("ws://localhost:8091");
        assert_eq!(c.backend_type(), PirBackendType::Onion);
        assert!(!c.is_connected());
        assert!(c.cached_catalog().is_none());
    }

    /// `batch_looks_evicted` must fire on an all-empty batch of ≥1 slot,
    /// which is the server's signal that our `client_id` has been
    /// LRU-evicted from SEAL's `KeyStore`. A legit response has at
    /// least one non-empty ciphertext, so the function must return
    /// `false` in that case.
    #[test]
    fn test_batch_looks_evicted_all_empty() {
        // All-empty batch of 3 slots: eviction.
        let batch = vec![Vec::<u8>::new(), Vec::<u8>::new(), Vec::<u8>::new()];
        assert!(batch_looks_evicted(&batch));
        // Single empty slot: eviction.
        let batch = vec![Vec::<u8>::new()];
        assert!(batch_looks_evicted(&batch));
    }

    #[test]
    fn test_batch_looks_evicted_mixed_and_full() {
        // Mixed: at least one non-empty → NOT eviction.
        let batch = vec![Vec::<u8>::new(), vec![0x01, 0x02]];
        assert!(!batch_looks_evicted(&batch));
        // All non-empty: clearly not eviction.
        let batch = vec![vec![0xaa], vec![0xbb], vec![0xcc]];
        assert!(!batch_looks_evicted(&batch));
    }

    #[test]
    fn test_batch_looks_evicted_zero_length() {
        // Zero-slot batch: NOT eviction — that would be a decode
        // error (num_groups=0 payload), handled upstream. This test
        // pins the contract so a future `.all(...)` simplification
        // (which returns true on an empty iterator) doesn't silently
        // start reporting "eviction" on decode bugs.
        let batch: Vec<Vec<u8>> = Vec::new();
        assert!(!batch_looks_evicted(&batch));
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_encode_register_keys_no_db_id() {
        let buf = encode_register_keys(&[1, 2, 3], &[9, 8], 0);
        // 4B len, variant, 4B galois_len=3, galois=[1,2,3], 4B gsw_len=2, gsw=[9,8]
        // payload_len = 1 + 4 + 3 + 4 + 2 = 14
        assert_eq!(&buf[0..4], &14u32.to_le_bytes());
        assert_eq!(buf[4], REQ_REGISTER_KEYS);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_encode_register_keys_with_db_id() {
        let buf = encode_register_keys(&[1], &[2], 3);
        // payload_len = 1 + 4 + 1 + 4 + 1 + 1 = 12 (trailing db_id byte)
        assert_eq!(&buf[0..4], &12u32.to_le_bytes());
        assert_eq!(*buf.last().unwrap(), 3);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_encode_onionpir_batch_query() {
        let qs = vec![vec![0xaau8, 0xbb], vec![0xcc]];
        let buf = encode_onionpir_batch_query(REQ_ONIONPIR_INDEX_QUERY, 7, &qs, 0);
        // payload: variant(1) + round_id(2) + num_groups(1) + [len(4)+bytes]*
        let expected_payload_len = 1 + 2 + 1 + (4 + 2) + (4 + 1);
        assert_eq!(&buf[0..4], &(expected_payload_len as u32).to_le_bytes());
        assert_eq!(buf[4], REQ_ONIONPIR_INDEX_QUERY);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_decode_onionpir_batch_result_roundtrip() {
        let qs = vec![vec![0x11, 0x22], vec![0x33]];
        let buf = encode_onionpir_batch_query(RESP_ONIONPIR_INDEX_RESULT, 0, &qs, 0);
        // Skip length prefix + variant byte.
        let decoded = decode_onionpir_batch_result(&buf[5..]).unwrap();
        assert_eq!(decoded, qs);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_scan_index_bin_hit() {
        // Single slot: tag=0x42, entry_id=7, byte_offset=100, num_entries=3
        let mut entry = vec![0u8; 15];
        entry[0..8].copy_from_slice(&0x42u64.to_le_bytes());
        entry[8..12].copy_from_slice(&7u32.to_le_bytes());
        entry[12..14].copy_from_slice(&100u16.to_le_bytes());
        entry[14] = 3;
        let ir = scan_index_bin(&entry, 0x42, 1, 15).expect("should find");
        assert_eq!(ir.entry_id, 7);
        assert_eq!(ir.byte_offset, 100);
        assert_eq!(ir.num_entries, 3);
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_scan_index_bin_miss() {
        let entry = vec![0u8; 15];
        assert!(scan_index_bin(&entry, 0x42, 1, 15).is_none());
    }

    #[cfg(feature = "onion")]
    #[test]
    fn test_chunk_cuckoo_roundtrip() {
        // Build a reverse index and cuckoo table, then verify every assigned
        // entry is findable. Load factor must be comfortably below 1.0 for
        // cuckoo to succeed — with total=200 and k_chunk=10 each group gets
        // ~60 entries (3 PBC hashes), so 256 bins gives ~23% load.
        let total = 200usize;
        let k_chunk = 10usize;
        let bins = 256usize;
        let rev = build_chunk_reverse_index(total, k_chunk);
        // Check all non-empty groups, not just the first — catches
        // regressions that only show up at higher loads.
        for (group, entries) in rev.iter().enumerate() {
            if entries.is_empty() {
                continue;
            }
            let table = build_chunk_cuckoo_for_group(group, &rev, bins);
            let keys = chunk_derive_keys(group);
            for &eid in entries {
                let bin = find_in_chunk_cuckoo(&table, eid, &keys, bins);
                assert!(
                    bin.is_some(),
                    "entry_id {} not found in group {} ({} entries, {} bins)",
                    eid,
                    group,
                    entries.len(),
                    bins
                );
            }
        }
    }

    /// Concurrency smoke test for the `unsafe impl Sync for SendClient`.
    ///
    /// The Sync claim only covers the two `&self` methods on
    /// `onionpir::Client`: `id` and `export_secret_key`. This test
    /// exercises both from multiple threads sharing a single
    /// `Arc<SendClient>`. If the `&self` FFI path touches any internal
    /// mutable state that isn't protected by a lock (a
    /// `mutable`-declared member, a non-thread-safe SEAL MemoryPool
    /// operation, a static cache, etc.), we expect this to either
    /// produce mismatched results, hang, or trip ASAN in CI.
    ///
    /// The test is a smoke test, not a proof — data races in SEAL
    /// could be demonic enough to only show up under load or with a
    /// particular allocator state. CI runs under tsan would make this
    /// considerably stronger, but the full SEAL stack is not tsan-clean
    /// (OpenMP is already tsan-unfriendly), so the lightweight check is
    /// the best we can do in-tree.
    ///
    /// Gated behind `feature = "onion"` because it constructs a real
    /// `onionpir::Client`, which requires the SEAL C++ toolchain.
    #[cfg(feature = "onion")]
    #[test]
    fn test_send_client_sync_smoke() {
        use std::sync::Arc;
        use std::thread;

        // Tiny num_entries so this is cheap. We only call `&self` methods.
        let client = onionpir::Client::new(1 << 10);
        let expected_id = client.id();
        let expected_sk = client.export_secret_key();
        let shared = Arc::new(SendClient(client));

        let handles: Vec<_> = (0..8)
            .map(|t| {
                let s = Arc::clone(&shared);
                let exp_id = expected_id;
                let exp_sk = expected_sk.clone();
                thread::spawn(move || {
                    // Alternate between `id` and `export_secret_key` across
                    // threads so both `&self` FFI entry points are hit.
                    for i in 0..50 {
                        if (t + i) % 2 == 0 {
                            assert_eq!(s.0.id(), exp_id, "id() disagrees across threads");
                        } else {
                            let sk = s.0.export_secret_key();
                            assert_eq!(
                                sk, exp_sk,
                                "export_secret_key() disagrees across threads"
                            );
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread panicked — possible data race in &self FFI path");
        }
    }

    /// Demonstrates the test-injection escape hatch: a client built with a
    /// [`MockTransport`](crate::transport::mock::MockTransport) reports
    /// `is_connected()` without ever opening a real socket. This is the
    /// core value prop of the `PirTransport` trait.
    #[test]
    fn connect_with_transport_marks_connected() {
        use crate::transport::mock::MockTransport;
        let mut client = OnionClient::new("wss://mock-onion");
        assert!(!client.is_connected());
        client.connect_with_transport(Box::new(MockTransport::new(
            "wss://mock-onion",
        )));
        assert!(client.is_connected());
    }
}
