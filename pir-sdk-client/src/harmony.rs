//! HarmonyPIR client implementation.
//!
//! HarmonyPIR is a two-server stateful PIR protocol:
//! - **Hint Server**: streams precomputed hint parities (one per group, per level)
//! - **Query Server**: answers per-group sorted-index queries against the cuckoo table
//!
//! The per-group state (relocation data structure + hints) is managed by
//! [`harmonypir_wasm::HarmonyGroup`], which is reused from the browser/JS
//! client. Although the wrapper was originally written for WASM, it is
//! exposed as an `rlib` and compiles fine for native targets — the
//! `#[wasm_bindgen]` attribute is a no-op off the `wasm32` target.
//!
//! ## Flow
//! 1. `connect()` opens WebSocket connections to both servers.
//! 2. `fetch_catalog()` sends [`REQ_HARMONY_GET_INFO`] and builds a
//!    single-entry catalog.
//! 3. `execute_step()` for each script hash:
//!    - Ensures per-group `HarmonyGroup` instances exist for this db
//!      (one per INDEX group and one per CHUNK group).
//!    - Fetches hints from the hint server once per db.
//!    - For each [`INDEX_CUCKOO_NUM_HASHES`] hash function, builds a
//!      padded batch request (real queries + synthetic dummies), sends
//!      it to the query server, and XORs hints with the response to
//!      recover the INDEX bin.
//!    - If an entry is found, runs the CHUNK rounds for the referenced
//!      chunk ids to recover UTXO bytes.
//!
//! The implementation mirrors the native reference
//! `runtime/src/bin/harmonypir_batch_e2e.rs` but fetches hints over
//! the wire instead of computing them from a local mmap.

#[cfg(not(target_arch = "wasm32"))]
use crate::connection::WsConnection;
use crate::hint_cache;
use crate::merkle_verify::{
    fetch_tree_tops, verify_bucket_merkle_batch_generic, BucketMerkleItem,
    BucketMerkleSiblingQuerier, TreeTop, BUCKET_MERKLE_ARITY, BUCKET_MERKLE_SIB_ROW_SIZE,
};
use crate::transport::PirTransport;
use crate::protocol::{
    decode_catalog, encode_request, REQ_GET_DB_CATALOG, RESP_DB_CATALOG, RESP_ERROR,
};
use async_trait::async_trait;
use harmonypir_wasm::HarmonyGroup;
use pir_core::params::{
    CHUNK_CUCKOO_NUM_HASHES, CHUNK_PARAMS, CHUNK_SIZE, CHUNK_SLOT_SIZE, CHUNK_SLOTS_PER_BIN,
    INDEX_CUCKOO_NUM_HASHES, INDEX_PARAMS, INDEX_SLOT_SIZE, INDEX_SLOTS_PER_BIN, TAG_SIZE,
};
use pir_sdk::{
    compute_sync_plan, merge_delta_batch, BucketRef, ConnectionState, DatabaseCatalog,
    DatabaseInfo, DatabaseKind, Instant, PirBackendType, PirClient, PirError, PirMetrics,
    PirResult, QueryResult, ScriptHash, StateListener, SyncPlan, SyncProgress, SyncResult,
    SyncStep, UtxoEntry,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

// ─── Wire protocol constants ────────────────────────────────────────────────

const REQ_HARMONY_GET_INFO: u8 = 0x40;
const RESP_HARMONY_INFO: u8 = 0x40;

const REQ_HARMONY_HINTS: u8 = 0x41;
const RESP_HARMONY_HINTS: u8 = 0x41;

const REQ_HARMONY_BATCH_QUERY: u8 = 0x43;
const RESP_HARMONY_BATCH_QUERY: u8 = 0x43;

// `REQ_GET_DB_CATALOG` / `RESP_DB_CATALOG` / `RESP_ERROR` come from
// `crate::protocol` — shared with `DpfClient` and `OnionClient`.

/// PRP backends (mirrors `harmonypir_wasm::PRP_*`).
pub const PRP_HMR12: u8 = 0;
pub const PRP_FASTPRP: u8 = 1;
pub const PRP_ALF: u8 = 2;

/// Which group-map `fetch_and_load_hints_into` should write into.
///
/// Keeps the hint-loading plumbing single-purpose — the caller supplies
/// both the wire `level` byte and the matching local destination.
#[derive(Copy, Clone, Debug)]
enum HintTarget {
    /// Main INDEX groups keyed by `group_id` (0..index_k).
    Index,
    /// Main CHUNK groups keyed by `group_id` (0..chunk_k).
    Chunk,
    /// Bucket-Merkle INDEX sibling groups at `sib_level` L (0..).
    IndexSib(usize),
    /// Bucket-Merkle CHUNK sibling groups at `sib_level` L (0..).
    ChunkSib(usize),
}

/// Per-group progress callback for the main-hint fetch path.
///
/// Fired once per group as its hint blob arrives over the wire and is
/// loaded into the local `HarmonyGroup`. `done` ranges from `1..=total`,
/// `total` is the constant `index_k + chunk_k` for the active database
/// (typically 75 + 80 = 155). `phase` is `"index"` while INDEX groups
/// stream in and `"chunk"` while CHUNK groups stream in.
///
/// Padding invariants are unaffected — the fetch wire shape is identical
/// to the no-callback path; this trait only observes when each per-group
/// response has been processed.
pub trait HintProgress: Send + Sync {
    /// Called after the `done`-th group's hints have been received and
    /// loaded into local state. See trait doc for argument contract.
    fn on_group_complete(&self, done: u32, total: u32, phase: &str);
}

// ─── Merkle verification traces ─────────────────────────────────────────────

/// Record of one INDEX cuckoo bin we checked during a query.
///
/// Mirrors `dpf.rs::IndexBinTrace`: populated for every cuckoo position probed
/// by `query_single`, consumed by the Merkle verifier to prove bin content is
/// consistent with the published root.
#[derive(Clone, Debug)]
struct IndexBinTrace {
    /// PBC group this bin belongs to (0..index_k).
    pbc_group: usize,
    /// Cuckoo bin index within the group's flat table.
    bin_index: u32,
    /// XOR-reconstructed bin content (INDEX_SLOTS_PER_BIN × INDEX_SLOT_SIZE bytes).
    bin_content: Vec<u8>,
}

/// Record of one CHUNK cuckoo bin we used to recover a retrieved chunk.
#[derive(Clone, Debug)]
struct ChunkBinTrace {
    /// PBC group this bin belongs to (0..chunk_k).
    pbc_group: usize,
    /// Cuckoo bin index within the group's flat table.
    bin_index: u32,
    /// XOR-reconstructed bin content.
    bin_content: Vec<u8>,
}

/// Metadata collected during a `query_single` call that downstream code
/// needs for Merkle verification. See `dpf.rs::QueryTraces` for the same
/// invariants.
#[derive(Clone, Debug)]
struct QueryTraces {
    /// Every INDEX bin we inspected. For NOT-FOUND this is all
    /// `INDEX_CUCKOO_NUM_HASHES` positions (required for the absence proof);
    /// for FOUND it can be up to the cuckoo position that matched.
    index_bins: Vec<IndexBinTrace>,
    /// If the query resolved to a match, the index in `index_bins` of the
    /// matching bin. `None` for NOT-FOUND or whale.
    matched_index_idx: Option<usize>,
    /// Per-chunk bin traces — one entry per chunk that was recovered.
    /// Empty for NOT-FOUND, whale, or zero-chunk matches.
    chunk_bins: Vec<ChunkBinTrace>,
}

// ─── Trace → BucketMerkleItem / BucketRef translators ───────────────────────
//
// These mirror the DPF client's helpers (`dpf.rs::items_from_trace` etc.):
// the point is to share exactly one item-layout convention between the
// hot-path Merkle verifier (which runs over fresh `QueryTraces`) and the
// deferred-verify path (which rebuilds items from already-persisted
// `QueryResult.index_bins` / `chunk_bins`). Any drift between the two
// sides would produce silent verification mismatches.

/// Build `BucketMerkleItem`s for one query from its internal trace —
/// emits one item per probed INDEX cuckoo bin, with CHUNK bins attached
/// only to the matched INDEX item (or none, if not matched). This
/// layout preserves the 🔒 Merkle INDEX Item-Count Symmetry invariant:
/// every query contributes exactly `INDEX_CUCKOO_NUM_HASHES` items
/// regardless of found / not-found / whale.
fn items_from_trace(trace: &QueryTraces) -> Vec<BucketMerkleItem> {
    trace
        .index_bins
        .iter()
        .enumerate()
        .map(|(bi, bin)| {
            let mut it = BucketMerkleItem {
                index_pbc_group: bin.pbc_group,
                index_bin_index: bin.bin_index,
                index_bin_content: bin.bin_content.clone(),
                chunk_pbc_groups: Vec::new(),
                chunk_bin_indices: Vec::new(),
                chunk_bin_contents: Vec::new(),
            };
            if trace.matched_index_idx == Some(bi) {
                for cb in &trace.chunk_bins {
                    it.chunk_pbc_groups.push(cb.pbc_group);
                    it.chunk_bin_indices.push(cb.bin_index);
                    it.chunk_bin_contents.push(cb.bin_content.clone());
                }
            }
            it
        })
        .collect()
}

/// Flatten a per-query traces list into a padded item list plus the
/// `item_index → query_index` backmapping the verifier needs to fold
/// per-item verdicts back to per-query verdicts.
fn collect_merkle_items_from_traces(
    traces: &[QueryTraces],
) -> (Vec<BucketMerkleItem>, Vec<usize>) {
    let mut items = Vec::new();
    let mut item_to_query = Vec::new();
    for (qi, trace) in traces.iter().enumerate() {
        for it in items_from_trace(trace) {
            items.push(it);
            item_to_query.push(qi);
        }
    }
    (items, item_to_query)
}

/// Build `BucketMerkleItem`s for one query from a `QueryResult`'s
/// inspector-populated fields. Symmetric with [`items_from_trace`] —
/// same per-query-item layout, same ordering — but works on the public
/// type so callers can reverify persisted results via
/// [`HarmonyClient::verify_merkle_batch_for_results`].
fn items_from_inspector_result(result: &QueryResult) -> Vec<BucketMerkleItem> {
    result
        .index_bins
        .iter()
        .enumerate()
        .map(|(bi, bin)| {
            let mut it = BucketMerkleItem {
                index_pbc_group: bin.pbc_group as usize,
                index_bin_index: bin.bin_index,
                index_bin_content: bin.bin_content.clone(),
                chunk_pbc_groups: Vec::new(),
                chunk_bin_indices: Vec::new(),
                chunk_bin_contents: Vec::new(),
            };
            if result.matched_index_idx == Some(bi) {
                for cb in &result.chunk_bins {
                    it.chunk_pbc_groups.push(cb.pbc_group as usize);
                    it.chunk_bin_indices.push(cb.bin_index);
                    it.chunk_bin_contents.push(cb.bin_content.clone());
                }
            }
            it
        })
        .collect()
}

/// Flatten a per-query `QueryResult` list into a padded item list plus
/// the `item_index → query_index` backmapping. `None` results
/// contribute zero items (nothing to verify).
fn collect_merkle_items_from_results(
    results: &[Option<QueryResult>],
) -> (Vec<BucketMerkleItem>, Vec<usize>) {
    let mut items = Vec::new();
    let mut item_to_query = Vec::new();
    for (qi, maybe_r) in results.iter().enumerate() {
        if let Some(r) = maybe_r {
            for it in items_from_inspector_result(r) {
                items.push(it);
                item_to_query.push(qi);
            }
        }
    }
    (items, item_to_query)
}

/// Convert an internal `IndexBinTrace` / `ChunkBinTrace` into the
/// public `BucketRef` shape. The public type widens `pbc_group` to
/// `u32` and drops the internal `ChunkBinTrace` vs `IndexBinTrace`
/// distinction — the discriminant is already encoded by which vec the
/// ref lives on (`QueryResult.index_bins` vs `QueryResult.chunk_bins`).
fn index_trace_to_bucket_ref(t: &IndexBinTrace) -> BucketRef {
    BucketRef {
        pbc_group: t.pbc_group as u32,
        bin_index: t.bin_index,
        bin_content: t.bin_content.clone(),
    }
}

fn chunk_trace_to_bucket_ref(t: &ChunkBinTrace) -> BucketRef {
    BucketRef {
        pbc_group: t.pbc_group as u32,
        bin_index: t.bin_index,
        bin_content: t.bin_content.clone(),
    }
}

// ─── HarmonyPIR Client ──────────────────────────────────────────────────────

/// HarmonyPIR client for two-server PIR queries.
///
/// HarmonyPIR is a stateful two-server PIR protocol that splits work
/// between a **hint server** (streams precomputed parities once per
/// database) and a **query server** (answers per-group cuckoo-bin
/// lookups). The per-client `HarmonyGroup` state must stay in sync
/// with the server's cuckoo table, so mid-session database switches
/// rebuild the groups from scratch; cross-session continuity is
/// provided by the hint cache (see [`with_hint_cache_dir`], plus
/// [`save_hints_bytes`] / [`load_hints_bytes`] for browser-side
/// IndexedDB mirrors).
///
/// # PRP backend selection
///
/// HarmonyPIR is parameterised by a pseudo-random permutation. The
/// default is HMR12 (portable, no extra deps); the `fastprp` cargo
/// feature enables FastPRP (2-3× faster per-group encode with a
/// precomputed cache) and the `alf` feature enables ALF. Select at
/// runtime via [`set_prp_backend`] with one of [`PRP_HMR12`],
/// [`PRP_FASTPRP`], or [`PRP_ALF`].
///
/// # Examples
///
/// Basic flow — create, connect, sync, use the results:
///
/// ```ignore
/// use pir_sdk_client::{HarmonyClient, PirClient, ScriptHash, PRP_HMR12};
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = HarmonyClient::new(
///         "ws://hint-server:8091",
///         "ws://query-server:8092",
///     );
///     client.set_prp_backend(PRP_HMR12);
///     client.connect().await.unwrap();
///
///     let script_hash: ScriptHash = [0u8; 20]; // your HASH160 script hash
///     let result = client.sync(&[script_hash], None).await.unwrap();
///
///     if let Some(qr) = &result.results[0] {
///         println!("Balance: {} sats", qr.total_balance());
///     }
/// }
/// ```
///
/// Resuming from a cached hint blob (avoids a full hint re-fetch on
/// reconnect when the database fingerprint matches):
///
/// ```ignore
/// use pir_sdk_client::{HarmonyClient, PirClient};
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = HarmonyClient::new(
///         "ws://hint-server:8091",
///         "ws://query-server:8092",
///     )
///     .with_hint_cache_dir("/var/cache/pir-sdk/hints");
///
///     // First sync populates the cache.
///     client.connect().await.unwrap();
///     let _ = client.sync(&[[0u8; 20]], None).await.unwrap();
///     client.disconnect().await.unwrap();
///
///     // Later reconnect: hint fetch short-circuits from the cache
///     // when the (key, backend, db_id, height, …) fingerprint matches.
///     client.connect().await.unwrap();
///     let _ = client.sync(&[[0u8; 20]], None).await.unwrap();
/// }
/// ```
///
/// [`with_hint_cache_dir`]: HarmonyClient::with_hint_cache_dir
/// [`save_hints_bytes`]: HarmonyClient::save_hints_bytes
/// [`load_hints_bytes`]: HarmonyClient::load_hints_bytes
/// [`set_prp_backend`]: HarmonyClient::set_prp_backend
pub struct HarmonyClient {
    hint_server_url: String,
    query_server_url: String,
    hint_conn: Option<Box<dyn PirTransport>>,
    query_conn: Option<Box<dyn PirTransport>>,
    catalog: Option<DatabaseCatalog>,
    prp_backend: u8,
    master_prp_key: [u8; 16],
    /// Groups are initialised lazily per db_id. When the id changes we
    /// drop existing groups and build a fresh set (hints are keyed on
    /// the db's cuckoo table).
    loaded_db_id: Option<u8>,
    index_groups: HashMap<u8, HarmonyGroup>,
    chunk_groups: HashMap<u8, HarmonyGroup>,
    /// Bucket-Merkle INDEX sibling groups, keyed by `(sib_level, local_group)`.
    /// Each level has exactly `index_k` groups; hints are fetched once per
    /// (db_id, level) and consumed during Merkle verification.
    index_sib_groups: HashMap<(usize, u8), HarmonyGroup>,
    /// Bucket-Merkle CHUNK sibling groups, keyed by `(sib_level, local_group)`.
    chunk_sib_groups: HashMap<(usize, u8), HarmonyGroup>,
    /// `Some(db_id)` when sibling groups + hints are loaded and fresh; reset
    /// whenever `loaded_db_id` changes or `master_prp_key`/`prp_backend`
    /// changes (via `invalidate_groups`).
    sibling_hints_loaded: Option<u8>,
    /// On-disk cache directory for hint blobs. `None` (the default) means
    /// "no filesystem cache" — `save_hints_bytes` / `load_hints_bytes`
    /// still work as explicit byte-level APIs, but nothing is read or
    /// written automatically. Set via
    /// [`HarmonyClient::with_hint_cache_dir`] or
    /// [`HarmonyClient::set_hint_cache_dir`].
    ///
    /// Session 5 will thread a wasm32-side IndexedDB wrapper through
    /// the same save/load byte APIs, so the filesystem path here only
    /// activates on native targets.
    hint_cache_dir: Option<PathBuf>,
    /// Optional observer invoked on every `ConnectionState` transition.
    /// Mirrors the DPF client's listener slot (see `dpf.rs` for the
    /// rationale behind `Arc<dyn StateListener>` over `Box`): sharing
    /// one sink between DPF + Harmony clients lets the WASM bindings
    /// plumb a single `Rc<RefCell<js_sys::Function>>` through both.
    state_listener: Option<Arc<dyn StateListener>>,
    /// Optional metrics recorder. When installed, fires
    /// `on_connect` / `on_disconnect` lifecycle events and
    /// `on_query_start` / `on_query_end` per-batch callbacks from the
    /// client layer, plus per-frame `on_bytes_sent` /
    /// `on_bytes_received` from the hint/query transports (wired on
    /// connect via `set_metrics_recorder`). Both transports are
    /// labelled `"harmony"` — a recorder can't tell which socket a
    /// byte count came from, but can split queries-vs-hints by
    /// observing the URL on `on_connect`.
    metrics_recorder: Option<Arc<dyn PirMetrics>>,
}

impl HarmonyClient {
    /// Create a new HarmonyPIR client.
    ///
    /// The master PRP key is derived from the current wall-clock time;
    /// use [`HarmonyClient::set_master_key`] to pin a specific key
    /// (useful for tests and for reusing cached hint state).
    pub fn new(hint_server_url: &str, query_server_url: &str) -> Self {
        let mut master_prp_key = [0u8; 16];
        let seed = crate::platform_time::seed_nanos();
        for i in 0..2 {
            let h = pir_core::hash::splitmix64(seed.wrapping_add(i as u64));
            master_prp_key[i * 8..(i + 1) * 8].copy_from_slice(&h.to_le_bytes());
        }

        Self {
            hint_server_url: hint_server_url.to_string(),
            query_server_url: query_server_url.to_string(),
            hint_conn: None,
            query_conn: None,
            catalog: None,
            prp_backend: PRP_HMR12,
            master_prp_key,
            loaded_db_id: None,
            index_groups: HashMap::new(),
            chunk_groups: HashMap::new(),
            index_sib_groups: HashMap::new(),
            chunk_sib_groups: HashMap::new(),
            sibling_hints_loaded: None,
            hint_cache_dir: None,
            state_listener: None,
            metrics_recorder: None,
        }
    }

    // ─── Metrics recorder ──────────────────────────────────────────────────

    /// Install (or replace) a metrics recorder.
    ///
    /// The recorder receives:
    /// * Per-frame `on_bytes_sent` / `on_bytes_received` callbacks from
    ///   the hint + query transports (both labelled `"harmony"`).
    /// * Per-batch `on_query_start` / `on_query_end` callbacks at
    ///   [`query_batch`](PirClient::query_batch) entry / exit.
    /// * `on_connect` on successful `connect` (one per transport) and
    ///   `on_disconnect` on `disconnect` (once).
    ///
    /// If the client is already connected when the recorder is
    /// installed, the recorder is propagated to both transports
    /// immediately. Pass `None` to uninstall.
    pub fn set_metrics_recorder(&mut self, recorder: Option<Arc<dyn PirMetrics>>) {
        self.metrics_recorder = recorder.clone();
        if let Some(ref mut c) = self.hint_conn {
            c.set_metrics_recorder(recorder.clone(), "harmony");
        }
        if let Some(ref mut c) = self.query_conn {
            c.set_metrics_recorder(recorder, "harmony");
        }
    }

    /// Fire `on_query_start` on the installed recorder, if any. Returns
    /// the `Instant` captured at start so a later
    /// [`fire_query_end`](Self::fire_query_end) can compute the
    /// wall-clock duration. `None` when no recorder is installed
    /// (preserves the zero-overhead no-recorder path).
    fn fire_query_start(&self, db_id: u8, num_queries: usize) -> Option<Instant> {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_query_start("harmony", db_id, num_queries);
            Some(Instant::now())
        } else {
            None
        }
    }

    /// Fire `on_query_end` on the installed recorder, if any. The
    /// `started_at` value comes from the matching
    /// [`fire_query_start`](Self::fire_query_start) call; `None`
    /// produces `Duration::ZERO` (best-effort observation per
    /// [`PirMetrics::on_query_end`] semantics).
    fn fire_query_end(
        &self,
        db_id: u8,
        num_queries: usize,
        success: bool,
        started_at: Option<Instant>,
    ) {
        if let Some(rec) = &self.metrics_recorder {
            let duration = started_at.map(|t| t.elapsed()).unwrap_or_default();
            rec.on_query_end("harmony", db_id, num_queries, success, duration);
        }
    }

    /// Fire `on_connect` for one transport, if a recorder is installed.
    fn fire_connect(&self, url: &str) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_connect("harmony", url);
        }
    }

    /// Fire `on_disconnect` on the installed recorder, if any.
    fn fire_disconnect(&self) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_disconnect("harmony");
        }
    }

    // ─── Hint cache configuration ───────────────────────────────────────────

    /// Configure an on-disk cache directory for hint blobs.
    ///
    /// When set, [`ensure_groups_ready`](Self::ensure_groups_ready) and
    /// [`ensure_sibling_groups_ready`](Self::ensure_sibling_groups_ready)
    /// will transparently restore hints from disk (skipping the server
    /// roundtrips) and persist them back after any fresh fetch. Cache
    /// files are named by the SHA-256 fingerprint of
    /// `(master_prp_key, prp_backend, db_id, height, index_bins,
    /// chunk_bins, tag_seed, index_k, chunk_k)`, so snapshots for
    /// different master keys / backends / databases never collide on
    /// disk.
    ///
    /// The cache preserves `HarmonyGroup::query_count` and the
    /// relocation log across restarts, so a client that persists after
    /// each sync resumes exactly where it left off (the usual
    /// per-group `max_queries` budget still applies — once a group is
    /// exhausted the next launch will see a schema mismatch and
    /// refetch).
    ///
    /// Any I/O or schema error during restore is swallowed and falls
    /// through to the network fetch path; persist errors are logged
    /// but do not fail the parent `ensure_*` call.
    ///
    /// The builder form (consumes `self`) is convenient for one-line
    /// construction; use [`set_hint_cache_dir`](Self::set_hint_cache_dir)
    /// from mutable contexts.
    pub fn with_hint_cache_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.hint_cache_dir = Some(dir.into());
        self
    }

    /// Mutable-reference counterpart to
    /// [`with_hint_cache_dir`](Self::with_hint_cache_dir). Passing
    /// `None` disables the on-disk cache for subsequent `ensure_*`
    /// calls without touching any already-restored in-memory state.
    pub fn set_hint_cache_dir(&mut self, dir: Option<PathBuf>) {
        self.hint_cache_dir = dir;
    }

    /// Return the currently configured cache directory, if any.
    pub fn hint_cache_dir(&self) -> Option<&std::path::Path> {
        self.hint_cache_dir.as_deref()
    }

    /// Resolve the on-disk cache path for `db_info` under the current
    /// `hint_cache_dir`. Returns `None` when no cache directory is
    /// configured.
    fn cache_path_for(&self, db_info: &DatabaseInfo) -> Option<PathBuf> {
        let dir = self.hint_cache_dir.as_ref()?;
        let key = hint_cache::CacheKey::from_db_info(
            self.master_prp_key,
            self.prp_backend,
            db_info,
        );
        Some(dir.join(key.filename()))
    }
}

impl HarmonyClient {

    /// The two server URLs this client was configured with, in
    /// `(hint_server, query_server)` order. Useful for display-only
    /// surfaces that want to show "connected to …" without
    /// reconstructing the URLs from caller state.
    pub fn server_urls(&self) -> (&str, &str) {
        (&self.hint_server_url, &self.query_server_url)
    }

    /// Register a callback that will be invoked on every
    /// [`ConnectionState`] transition (`Connecting` → `Connected` /
    /// `Disconnected`). Replaces any previously registered listener
    /// — only one listener per client; share one
    /// `Arc<dyn StateListener>` across multiple clients if you need a
    /// fan-in sink.
    ///
    /// No-op invocation if the listener is `None`; passing a fresh
    /// `None` clears the slot.
    pub fn set_state_listener(&mut self, listener: Option<Arc<dyn StateListener>>) {
        self.state_listener = listener;
    }

    /// Emit a state transition to the registered listener, if any.
    /// Kept as an inherent method so the async `connect`/`disconnect`
    /// trait impls can fire it without re-borrowing `self`.
    fn notify_state(&self, state: ConnectionState) {
        if let Some(listener) = &self.state_listener {
            listener.on_state_change(state);
        }
    }

    /// Install pre-built transports directly, bypassing the URL-based
    /// [`PirClient::connect`] path.
    ///
    /// This is the test-injection escape hatch the `PirTransport` trait was
    /// designed around: state-machine tests can hand in a
    /// [`MockTransport`](crate::transport::MockTransport) (or any other
    /// impl) and drive the client without opening real WebSockets.
    /// `PirClient::is_connected` returns `true` after this call.
    ///
    /// Fires the same `Connected` state event a URL-driven `connect()`
    /// would — lets injection-driven tests exercise the state listener
    /// without a real WebSocket handshake.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony"))]
    pub fn connect_with_transport(
        &mut self,
        hint_conn: Box<dyn PirTransport>,
        query_conn: Box<dyn PirTransport>,
    ) {
        self.hint_conn = Some(hint_conn);
        self.query_conn = Some(query_conn);
        // Propagate any installed recorder to the injected transports so
        // state-machine tests see per-frame byte counts just like the
        // URL-driven `connect()` path does. Both transports are
        // labelled `"harmony"`.
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(ref mut c) = self.hint_conn {
                c.set_metrics_recorder(Some(rec.clone()), "harmony");
            }
            if let Some(ref mut c) = self.query_conn {
                c.set_metrics_recorder(Some(rec), "harmony");
            }
        }
        self.fire_connect(&self.hint_server_url);
        self.fire_connect(&self.query_server_url);
        self.notify_state(ConnectionState::Connected);
    }

    /// Override the master PRP key (16 bytes).
    pub fn set_master_key(&mut self, key: [u8; 16]) {
        self.master_prp_key = key;
        self.invalidate_groups();
    }

    /// Set the PRP backend (`PRP_HMR12`, `PRP_FASTPRP`, or `PRP_ALF`).
    pub fn set_prp_backend(&mut self, backend: u8) {
        if backend != self.prp_backend {
            self.prp_backend = backend;
            self.invalidate_groups();
        }
    }

    fn invalidate_groups(&mut self) {
        self.index_groups.clear();
        self.chunk_groups.clear();
        self.index_sib_groups.clear();
        self.chunk_sib_groups.clear();
        self.loaded_db_id = None;
        self.sibling_hints_loaded = None;
    }

    // ─── Hint persistence: save / load ─────────────────────────────────────

    /// Serialize the currently loaded hint state (main + sibling groups)
    /// into a self-describing blob.
    ///
    /// Returns `Ok(None)` when nothing is loaded — callers can treat
    /// that as "no state to persist". On success the byte blob carries
    /// the cache key fingerprint in its header, so any later
    /// [`load_hints_bytes`](Self::load_hints_bytes) call that doesn't
    /// match the same master key + shape fails cleanly rather than
    /// silently loading mismatched state.
    ///
    /// This is the explicit byte-level API that Session 5 will wrap
    /// with IndexedDB persistence on wasm32. Native callers who want
    /// filesystem persistence should prefer
    /// [`with_hint_cache_dir`](Self::with_hint_cache_dir) +
    /// [`persist_hints_to_cache`](Self::persist_hints_to_cache),
    /// which handle path resolution and atomic rename for them.
    pub fn save_hints_bytes(&self) -> PirResult<Option<Vec<u8>>> {
        let db_id = match self.loaded_db_id {
            Some(id) => id,
            None => return Ok(None),
        };
        let catalog = self.catalog.as_ref().ok_or_else(|| {
            PirError::InvalidState(
                "save_hints_bytes: catalog not fetched (call fetch_catalog first)".into(),
            )
        })?;
        let db_info = catalog
            .get(db_id)
            .ok_or(PirError::DatabaseNotFound(db_id))?;

        let key =
            hint_cache::CacheKey::from_db_info(self.master_prp_key, self.prp_backend, db_info);
        let mut bundle = hint_cache::HintBundle::new();

        for (&gid, group) in &self.index_groups {
            bundle.main_index.insert(gid, group.serialize());
        }
        for (&gid, group) in &self.chunk_groups {
            bundle.main_chunk.insert(gid, group.serialize());
        }
        // Sibling level is stored in memory as `usize` but realistic
        // Merkle tree depths are well under 255 (typically <= 12);
        // narrow to u8 for the wire format.
        for (&(level, gid), group) in &self.index_sib_groups {
            debug_assert!(level < 256, "sibling level overflow at save time");
            bundle
                .index_sib
                .insert((level as u8, gid), group.serialize());
        }
        for (&(level, gid), group) in &self.chunk_sib_groups {
            debug_assert!(level < 256, "sibling level overflow at save time");
            bundle
                .chunk_sib
                .insert((level as u8, gid), group.serialize());
        }

        Ok(Some(hint_cache::encode_hints(&key, &bundle)))
    }

    /// Load hint state from a blob produced by
    /// [`save_hints_bytes`](Self::save_hints_bytes).
    ///
    /// The blob's embedded fingerprint is cross-checked against the
    /// caller-supplied `db_info` + this client's master key / PRP
    /// backend; a mismatch is reported as [`PirError::InvalidState`].
    /// Malformed or incompatible blobs surface as [`PirError::Decode`],
    /// so a calling `ensure_*` can treat any non-`Ok` outcome as
    /// "cache miss — fall back to network".
    ///
    /// On success, `loaded_db_id` is set to `db_info.db_id` and all
    /// groups present in the blob are materialised. If the blob
    /// includes sibling state, `sibling_hints_loaded` is also set;
    /// otherwise the sibling maps stay empty so the next
    /// [`ensure_sibling_groups_ready`](Self::ensure_sibling_groups_ready)
    /// will fetch them from the server.
    pub fn load_hints_bytes(
        &mut self,
        bytes: &[u8],
        db_info: &DatabaseInfo,
    ) -> PirResult<()> {
        let expected_fp =
            hint_cache::CacheKey::from_db_info(self.master_prp_key, self.prp_backend, db_info)
                .fingerprint();
        let decoded = hint_cache::decode_hints(bytes, Some(&expected_fp))?;
        self.load_bundle_into_groups(&decoded.bundle, db_info)?;
        Ok(())
    }

    /// Re-derive per-group `HarmonyGroup` instances from a
    /// [`hint_cache::HintBundle`].
    ///
    /// Group IDs follow the same layout convention as
    /// [`ensure_groups_ready`](Self::ensure_groups_ready) and
    /// [`ensure_sibling_groups_ready`](Self::ensure_sibling_groups_ready),
    /// so `HarmonyGroup::deserialize` can regenerate the same derived
    /// PRP keys the server uses:
    ///
    /// * main INDEX group g → `group_id = g`
    /// * main CHUNK group g → `group_id = k_index + g`
    /// * INDEX sib level L group g →
    ///   `group_id = (k_index + k_chunk) + L * k_index + g`
    /// * CHUNK sib level L group g →
    ///   `group_id = (k_index + k_chunk) + index_sib_levels * k_index
    ///              + L * k_chunk + g`
    ///
    /// `index_sib_levels` is inferred from the bundle (max cached
    /// level + 1); this is safe because the server always caches
    /// every level 0..N-1 together.
    fn load_bundle_into_groups(
        &mut self,
        bundle: &hint_cache::HintBundle,
        db_info: &DatabaseInfo,
    ) -> PirResult<()> {
        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;

        // Start from a clean slate so partial restores don't mix state
        // from an earlier `ensure_*` pass.
        self.index_groups.clear();
        self.chunk_groups.clear();
        self.index_sib_groups.clear();
        self.chunk_sib_groups.clear();
        self.loaded_db_id = None;
        self.sibling_hints_loaded = None;

        for (&gid, bytes) in &bundle.main_index {
            let group =
                HarmonyGroup::deserialize(bytes, &self.master_prp_key, gid as u32).map_err(
                    |e| {
                        PirError::BackendState(format!(
                            "deserialize main INDEX group {}: {:?}",
                            gid, e
                        ))
                    },
                )?;
            self.index_groups.insert(gid, group);
        }
        for (&gid, bytes) in &bundle.main_chunk {
            let group_id = (k_index + gid as usize) as u32;
            let group =
                HarmonyGroup::deserialize(bytes, &self.master_prp_key, group_id).map_err(|e| {
                    PirError::BackendState(format!(
                        "deserialize main CHUNK group {}: {:?}",
                        gid, e
                    ))
                })?;
            self.chunk_groups.insert(gid, group);
        }

        let index_sib_levels = bundle
            .index_sib
            .keys()
            .map(|(l, _)| *l as usize + 1)
            .max()
            .unwrap_or(0);

        for (&(level, gid), bytes) in &bundle.index_sib {
            let sl = level as usize;
            let g = gid as usize;
            let group_id = ((k_index + k_chunk) + sl * k_index + g) as u32;
            let group =
                HarmonyGroup::deserialize(bytes, &self.master_prp_key, group_id).map_err(|e| {
                    PirError::BackendState(format!(
                        "deserialize INDEX sib L{} g{}: {:?}",
                        sl, g, e
                    ))
                })?;
            self.index_sib_groups.insert((sl, gid), group);
        }
        for (&(level, gid), bytes) in &bundle.chunk_sib {
            let sl = level as usize;
            let g = gid as usize;
            let group_id =
                ((k_index + k_chunk) + index_sib_levels * k_index + sl * k_chunk + g) as u32;
            let group =
                HarmonyGroup::deserialize(bytes, &self.master_prp_key, group_id).map_err(|e| {
                    PirError::BackendState(format!(
                        "deserialize CHUNK sib L{} g{}: {:?}",
                        sl, g, e
                    ))
                })?;
            self.chunk_sib_groups.insert((sl, gid), group);
        }

        // Only claim "loaded" when all main groups this db expects are
        // present — a partial bundle (e.g. from a truncated legacy
        // format) must trigger a network refetch rather than serve a
        // half-state. Note: `k_index` and `k_chunk` are from the
        // caller's `db_info`, and the bundle header has already been
        // fingerprint-checked, so this length compare is a sanity
        // guard rather than a trust boundary.
        let full_main =
            bundle.main_index.len() == k_index && bundle.main_chunk.len() == k_chunk;
        if full_main {
            self.loaded_db_id = Some(db_info.db_id);
            // Tentatively claim sibling state if any are present; the
            // caller (`ensure_sibling_groups_ready`) will validate the
            // count against the server's tree-tops and re-fetch on
            // mismatch, so this is a fast-path hint rather than a
            // trust anchor.
            if !bundle.index_sib.is_empty() || !bundle.chunk_sib.is_empty() {
                self.sibling_hints_loaded = Some(db_info.db_id);
            }
        }
        Ok(())
    }

    // ─── Hint persistence: file-backed cache ───────────────────────────────

    /// Persist the current hint state to the configured cache directory.
    ///
    /// No-op when `hint_cache_dir` is unset or `save_hints_bytes`
    /// returns `None` (nothing loaded). Uses an atomic rename
    /// (`<file>.tmp` → `<file>`) so a crash mid-write leaves the
    /// previous cache file intact.
    pub fn persist_hints_to_cache(&self, db_info: &DatabaseInfo) -> PirResult<()> {
        let Some(path) = self.cache_path_for(db_info) else {
            return Ok(());
        };
        let Some(bytes) = self.save_hints_bytes()? else {
            return Ok(());
        };
        #[cfg(not(target_arch = "wasm32"))]
        {
            hint_cache::write_cache_file(&path, &bytes)?;
            log::info!(
                "[PIR-AUDIT] HarmonyPIR: persisted {} bytes to {}",
                bytes.len(),
                path.display()
            );
        }
        #[cfg(target_arch = "wasm32")]
        {
            // On wasm32 the filesystem path isn't available; Session 5
            // wires IndexedDB through the `save_hints_bytes` /
            // `load_hints_bytes` pair directly. Silently no-op rather
            // than fail so shared code paths stay oblivious.
            let _ = (path, bytes);
        }
        Ok(())
    }

    /// Try to restore hints from the configured cache directory.
    ///
    /// Returns `Ok(true)` if the cache file existed and was loaded
    /// successfully, `Ok(false)` when the cache is cold or the blob
    /// was rejected (bad magic, schema mismatch, fingerprint mismatch,
    /// truncation). Any transient I/O error (disk full, permissions,
    /// etc.) still bubbles up as `Err` so the caller can decide
    /// whether to retry or surface it.
    ///
    /// Always `Ok(false)` when `hint_cache_dir` is unset.
    pub fn restore_hints_from_cache(&mut self, db_info: &DatabaseInfo) -> PirResult<bool> {
        let Some(path) = self.cache_path_for(db_info) else {
            return Ok(false);
        };
        #[cfg(not(target_arch = "wasm32"))]
        {
            let Some(bytes) = hint_cache::read_cache_file(&path)? else {
                return Ok(false);
            };
            match self.load_hints_bytes(&bytes, db_info) {
                Ok(()) => {
                    log::info!(
                        "[PIR-AUDIT] HarmonyPIR: restored hints from {} \
                         ({} INDEX + {} CHUNK main, {} INDEX sib + {} CHUNK sib)",
                        path.display(),
                        self.index_groups.len(),
                        self.chunk_groups.len(),
                        self.index_sib_groups.len(),
                        self.chunk_sib_groups.len()
                    );
                    Ok(true)
                }
                Err(e) => {
                    log::warn!(
                        "[PIR-AUDIT] HarmonyPIR: rejected cache at {} ({}); refetching",
                        path.display(),
                        e
                    );
                    self.invalidate_groups();
                    Ok(false)
                }
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            let _ = path;
            Ok(false)
        }
    }

    /// Try to fetch the full `DatabaseCatalog` via `REQ_GET_DB_CATALOG`.
    ///
    /// Returns `Ok(Some(catalog))` on success, `Ok(None)` if the server
    /// replied with a shape the catalog decoder can't understand (e.g. a
    /// legacy hint server that doesn't implement `REQ_GET_DB_CATALOG` and
    /// echoes back some other variant byte, or a `RESP_ERROR`). A
    /// legitimate transport/I/O failure still bubbles up as `Err`.
    ///
    /// Both Harmony roles (hint + query) answer `REQ_GET_DB_CATALOG` —
    /// the match arm in `unified_server.rs` runs before any role check
    /// — so we can use whichever connection is convenient. We use
    /// `hint_conn` for consistency with `fetch_legacy_info`.
    async fn try_fetch_db_catalog(&mut self) -> PirResult<Option<DatabaseCatalog>> {
        let conn = self.hint_conn.as_mut().ok_or(PirError::NotConnected)?;
        let request = encode_request(REQ_GET_DB_CATALOG, &[]);
        let response = conn.roundtrip(&request).await?;

        if response.is_empty() {
            return Ok(None);
        }
        if response[0] == RESP_ERROR {
            // Server explicitly doesn't support catalog — fall back to legacy.
            return Ok(None);
        }
        if response[0] != RESP_DB_CATALOG {
            // Any unexpected variant byte — treat as unsupported rather
            // than a hard protocol error so the legacy fallback can run.
            return Ok(None);
        }
        let catalog = decode_catalog(&response[1..])?;
        Ok(Some(catalog))
    }

    /// Fetch server info (legacy single-database path).
    ///
    /// `REQ_HARMONY_GET_INFO` predates `DatabaseCatalog` and returns a
    /// `ServerInfo` shape with no `height` or `has_bucket_merkle` fields.
    /// The catalog this synthesises therefore has `height = 0` and
    /// `has_bucket_merkle = false`, which is fine for servers that don't
    /// publish bucket Merkle roots but is strictly worse than the
    /// `REQ_GET_DB_CATALOG` path — callers that cache by height won't work
    /// against a legacy-only server.
    async fn fetch_legacy_info(&mut self) -> PirResult<DatabaseInfo> {
        let conn = self.hint_conn.as_mut().ok_or(PirError::NotConnected)?;

        let request = encode_request(REQ_HARMONY_GET_INFO, &[]);
        let response = conn.roundtrip(&request).await?;

        if response.is_empty() || response[0] != RESP_HARMONY_INFO {
            return Err(PirError::Protocol("invalid harmony info response".into()));
        }
        if response.len() < 19 {
            return Err(PirError::Protocol("harmony info response too short".into()));
        }

        let index_bins = u32::from_le_bytes(response[1..5].try_into().unwrap());
        let chunk_bins = u32::from_le_bytes(response[5..9].try_into().unwrap());
        let index_k = response[9];
        let chunk_k = response[10];
        let tag_seed = u64::from_le_bytes(response[11..19].try_into().unwrap());

        Ok(DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: "main".into(),
            height: 0,
            index_bins,
            chunk_bins,
            index_k,
            chunk_k,
            tag_seed,
            dpf_n_index: pir_core::params::compute_dpf_n(index_bins as usize),
            dpf_n_chunk: pir_core::params::compute_dpf_n(chunk_bins as usize),
            has_bucket_merkle: false,
        })
    }

    /// Ensure the per-group `HarmonyGroup` instances exist for `db_info`
    /// and their hints are loaded.
    ///
    /// Fast path: if [`with_hint_cache_dir`](Self::with_hint_cache_dir)
    /// was called and a valid cache file exists for this db_info,
    /// groups are rehydrated from disk and the server roundtrips are
    /// skipped entirely. On cache miss / cache reject, the network
    /// fetch runs as before and the result is persisted back to disk.
    /// Sibling hints are only persisted once
    /// [`ensure_sibling_groups_ready`](Self::ensure_sibling_groups_ready)
    /// has populated them (see that method for the second persist).
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    async fn ensure_groups_ready(
        &mut self,
        db_info: &DatabaseInfo,
        progress: Option<&dyn HintProgress>,
    ) -> PirResult<()> {
        if self.loaded_db_id == Some(db_info.db_id)
            && !self.index_groups.is_empty()
            && !self.chunk_groups.is_empty()
        {
            // Fast path: hints already loaded from a prior call. Emit a
            // single terminal `total/total` tick so a UI driving its
            // progress bar off this callback flips to "done" rather than
            // silently sitting at the previous percentage.
            if let Some(p) = progress {
                let total = db_info.index_k as u32 + db_info.chunk_k as u32;
                if total > 0 {
                    p.on_group_complete(total, total, "chunk");
                }
            }
            return Ok(());
        }

        self.invalidate_groups();

        // ── Try the on-disk cache before hitting the wire ─────────────
        // Any cache error is swallowed and we fall through to network
        // fetch — the cache is a fast path, never a correctness
        // dependency. I/O errors propagate so the caller sees them.
        if self.restore_hints_from_cache(db_info)?
            && self.loaded_db_id == Some(db_info.db_id)
        {
            // Cache hit: emit one terminal tick so progress observers
            // mark the bar full even though no per-group wire roundtrips
            // happened.
            if let Some(p) = progress {
                let total = db_info.index_k as u32 + db_info.chunk_k as u32;
                if total > 0 {
                    p.on_group_complete(total, total, "chunk");
                }
            }
            return Ok(());
        }

        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;

        let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;
        let chunk_w = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE;

        for g in 0..k_index {
            let group = HarmonyGroup::new_with_backend(
                db_info.index_bins,
                index_w as u32,
                0, // T=0 means "pick balanced T"
                &self.master_prp_key,
                g as u32,
                self.prp_backend,
            )
            .map_err(|e| PirError::BackendState(format!("HarmonyGroup init: {:?}", e)))?;
            self.index_groups.insert(g as u8, group);
        }

        for g in 0..k_chunk {
            let group = HarmonyGroup::new_with_backend(
                db_info.chunk_bins,
                chunk_w as u32,
                0,
                &self.master_prp_key,
                (k_index + g) as u32,
                self.prp_backend,
            )
            .map_err(|e| PirError::BackendState(format!("HarmonyGroup init: {:?}", e)))?;
            self.chunk_groups.insert(g as u8, group);
        }

        let total = (k_index + k_chunk) as u32;
        let mut done: u32 = 0;
        {
            let mut on_index = |_gid: u8| {
                done += 1;
                if let Some(p) = progress {
                    p.on_group_complete(done, total, "index");
                }
            };
            self.fetch_and_load_hints_with_callback(
                db_info.db_id,
                0,
                k_index as u8,
                &mut on_index,
            )
            .await?;
        }
        {
            let mut on_chunk = |_gid: u8| {
                done += 1;
                if let Some(p) = progress {
                    p.on_group_complete(done, total, "chunk");
                }
            };
            self.fetch_and_load_hints_with_callback(
                db_info.db_id,
                1,
                k_chunk as u8,
                &mut on_chunk,
            )
            .await?;
        }

        self.loaded_db_id = Some(db_info.db_id);

        // Persist the freshly-fetched main hints so a warm restart
        // gets the fast path. Sibling state isn't loaded yet; it will
        // be persisted again by `ensure_sibling_groups_ready` once the
        // tree-tops RPC returns. Persist errors are logged and
        // ignored so a read-only cache dir doesn't wedge queries.
        if let Err(e) = self.persist_hints_to_cache(db_info) {
            log::warn!(
                "[PIR-AUDIT] HarmonyPIR: failed to persist main hints to cache: {}",
                e
            );
        }
        Ok(())
    }

    /// Send a hint request for all main groups at `level` (0=INDEX,
    /// 1=CHUNK) and load each response into its owning `HarmonyGroup`,
    /// invoking `on_group(group_id)` after each successful per-group
    /// load. The callback fires in the order responses arrive over the
    /// wire — usually but not strictly `0..num_groups`.
    async fn fetch_and_load_hints_with_callback(
        &mut self,
        db_id: u8,
        level: u8,
        num_groups: u8,
        on_group: &mut (dyn FnMut(u8) + Send),
    ) -> PirResult<()> {
        let target = if level == 0 {
            HintTarget::Index
        } else if level == 1 {
            HintTarget::Chunk
        } else {
            return Err(PirError::InvalidState(format!(
                "fetch_and_load_hints called with non-main level {}",
                level
            )));
        };
        self.fetch_and_load_hints_into(db_id, level, num_groups, target, Some(on_group))
            .await
    }

    /// Generalised hint fetch: issues a `REQ_HARMONY_HINTS` with the given
    /// `level` byte (0=INDEX, 1=CHUNK, 10+L=INDEX sib L, 20+L=CHUNK sib L)
    /// and streams responses into the group map pointed to by `target`.
    ///
    /// The server derives per-group PRP keys using `(prp_key, level, group_id)`
    /// internally — the client only needs to pass the correct `level` byte;
    /// the `k_offset` accounting in the server is transparent here.
    ///
    /// If `on_group` is `Some`, it is invoked with the just-loaded
    /// `group_id` after each per-group response is processed; sibling
    /// callers and tests pass `None`.
    async fn fetch_and_load_hints_into(
        &mut self,
        db_id: u8,
        level: u8,
        num_groups: u8,
        target: HintTarget,
        mut on_group: Option<&mut (dyn FnMut(u8) + Send)>,
    ) -> PirResult<()> {
        let mut payload = Vec::with_capacity(16 + 1 + 1 + 1 + num_groups as usize + 1);
        payload.extend_from_slice(&self.master_prp_key);
        payload.push(self.prp_backend);
        payload.push(level);
        payload.push(num_groups);
        for g in 0..num_groups {
            payload.push(g);
        }
        if db_id != 0 {
            payload.push(db_id);
        }
        let request = encode_request(REQ_HARMONY_HINTS, &payload);

        let conn = self.hint_conn.as_mut().ok_or(PirError::NotConnected)?;
        conn.send(request).await?;

        let mut received = 0u32;
        while received < num_groups as u32 {
            let msg = conn.recv().await?;
            if msg.len() < 5 {
                return Err(PirError::Protocol("truncated hint response".into()));
            }
            let body = &msg[4..]; // skip length prefix
            if body.is_empty() {
                return Err(PirError::Protocol("empty hint response body".into()));
            }

            if body[0] == RESP_ERROR {
                let reason = if body.len() > 1 {
                    String::from_utf8_lossy(&body[1..]).to_string()
                } else {
                    "hint server error".into()
                };
                return Err(PirError::ServerError(reason));
            }
            if body[0] != RESP_HARMONY_HINTS {
                return Err(PirError::Protocol(format!(
                    "unexpected hint response byte: 0x{:02x}",
                    body[0]
                )));
            }
            if body.len() < 14 {
                return Err(PirError::Protocol("hint response header truncated".into()));
            }

            let group_id = body[1];
            // bytes 2..14 are (n, t, m) metadata — not needed here, the
            // local HarmonyGroup was constructed with the same params.
            let hints_data = &body[14..];

            let group = match target {
                HintTarget::Index => self.index_groups.get_mut(&group_id),
                HintTarget::Chunk => self.chunk_groups.get_mut(&group_id),
                HintTarget::IndexSib(sl) => self.index_sib_groups.get_mut(&(sl, group_id)),
                HintTarget::ChunkSib(sl) => self.chunk_sib_groups.get_mut(&(sl, group_id)),
            };
            let group = group.ok_or_else(|| {
                PirError::Protocol(format!(
                    "hint for unknown group {} at level {}",
                    group_id, level
                ))
            })?;
            group
                .load_hints(hints_data)
                .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;

            if let Some(cb) = on_group.as_deref_mut() {
                cb(group_id);
            }

            received += 1;
        }

        Ok(())
    }

    /// Execute a single query step for a batch of script hashes.
    ///
    /// Runs PIR queries for each script hash, then — if the target database
    /// publishes a per-bucket Merkle tree (`DatabaseInfo::has_bucket_merkle`) —
    /// performs a single batched Merkle verification covering every INDEX
    /// cuckoo position inspected (two per not-found query) and every CHUNK
    /// bin that returned data. Items whose Merkle proof fails are coerced to
    /// `None` (treated as unverified; callers should treat them as an
    /// unknown/error state), mirroring the DPF client.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            backend = "harmony",
            db_id = _step.db_id,
            step = %_step.name,
            height = _step.tip_height,
            num_queries = script_hashes.len(),
        )
    )]
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        self.ensure_groups_ready(db_info, None).await?;

        log::info!(
            "[PIR-AUDIT] HarmonyPIR execute_step: db_id={}, name={}, height={}, queries={}, has_bucket_merkle={}",
            db_info.db_id,
            db_info.name,
            db_info.height,
            script_hashes.len(),
            db_info.has_bucket_merkle
        );

        let mut results: Vec<Option<QueryResult>> = Vec::with_capacity(script_hashes.len());
        let mut traces: Vec<QueryTraces> = Vec::with_capacity(script_hashes.len());
        for script_hash in script_hashes {
            let (result, trace) = self.query_single(script_hash, db_info).await?;
            results.push(result);
            traces.push(trace);
        }

        if db_info.has_bucket_merkle {
            self.run_merkle_verification(&mut results, &traces, db_info)
                .await?;
        } else {
            log::info!(
                "[PIR-AUDIT] HarmonyPIR Merkle verification SKIPPED (db_id={} has no bucket Merkle)",
                db_info.db_id
            );
        }

        Ok(results)
    }

    /// Query a single script hash.
    ///
    /// Runs up to [`INDEX_CUCKOO_NUM_HASHES`] INDEX rounds (one per hash
    /// function); on a hit, runs the CHUNK rounds to recover UTXO bytes.
    ///
    /// Also returns `QueryTraces` describing every INDEX/CHUNK cuckoo bin we
    /// inspected, so the caller (`execute_step`) can run per-bucket Merkle
    /// verification if `DatabaseInfo::has_bucket_merkle` is set.
    #[tracing::instrument(level = "trace", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    async fn query_single(
        &mut self,
        script_hash: &ScriptHash,
        db_info: &DatabaseInfo,
    ) -> PirResult<(Option<QueryResult>, QueryTraces)> {
        let k_index = db_info.index_k as usize;
        let index_bins = db_info.index_bins as usize;
        let tag_seed = db_info.tag_seed;

        // Pick the first of 3 candidate groups. The server replicates each
        // scripthash into ALL 3 candidate groups at build time
        // (see `build/src/build_cuckoo_generic.rs:87-90` and
        // `gen_4_build_merkle.rs:236-239`), so any one is sufficient to
        // retrieve an entry. This matches the reference Rust DPF binary
        // (`runtime/src/bin/client.rs:246`) and every web TS client's
        // single-query behavior (all reduce to `candGroups[0]` at N=1 via
        // `planRounds`). If this path is ever extended to batch multiple
        // scripthashes per HarmonyPIR round, switch to `pbc_plan_rounds` to
        // spread real queries across groups — but K padding
        // (`INDEX_PADDED_GROUPS` queries per round) and the Merkle INDEX
        // item-count symmetry must be preserved.
        let real_group = pir_core::hash::derive_groups_3(script_hash, k_index)[0];
        let my_tag = pir_core::hash::compute_tag(tag_seed, script_hash);

        log::info!(
            "[PIR-AUDIT] HarmonyPIR INDEX query: script_hash={}, assigned_group={}, k={}, bins={} (K-padded to {} groups per round)",
            format_hash_short(script_hash),
            real_group,
            k_index,
            index_bins,
            k_index
        );

        let mut traces = QueryTraces {
            index_bins: Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES),
            matched_index_idx: None,
            chunk_bins: Vec::new(),
        };
        let mut hit: Option<(u32, u8, bool)> = None;

        // Probe BOTH cuckoo positions — even after a match — so the Merkle
        // item count is uniform (INDEX_CUCKOO_NUM_HASHES items per query)
        // across found / not-found / whale. This closes the side channel
        // where the server could infer presence from INDEX Merkle pass count.
        // Each extra probe costs one padded HarmonyPIR INDEX round (K queries,
        // server-side still padded) on found@h=0 queries.
        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            let key =
                pir_core::hash::derive_cuckoo_key(INDEX_PARAMS.master_seed, real_group, h);
            let target_bin = pir_core::hash::cuckoo_hash(script_hash, key, index_bins);

            let answer = self
                .run_index_round(db_info.db_id, real_group as u8, target_bin as u32, h)
                .await?;

            let pos = traces.index_bins.len();
            traces.index_bins.push(IndexBinTrace {
                pbc_group: real_group,
                bin_index: target_bin as u32,
                bin_content: answer.clone(),
            });

            if hit.is_some() {
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR INDEX extra probe at cuckoo h={} (group={}, bin={}) — tracked for Merkle uniformity",
                    h, real_group, target_bin
                );
                continue;
            }

            if let Some(entry) = find_entry_in_index_result(&answer, my_tag) {
                let is_whale = entry.1 == 0;
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR INDEX FOUND at cuckoo h={} (group={}, bin={}): start_chunk={}, num_chunks={}, whale={}",
                    h, real_group, target_bin, entry.0, entry.1, is_whale
                );
                traces.matched_index_idx = Some(pos);
                hit = Some((entry.0, entry.1, is_whale));
            } else {
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR INDEX miss at cuckoo h={} (group={}, bin={})",
                    h, real_group, target_bin
                );
            }
        }

        let (start_chunk_id, num_chunks, is_whale) = match hit {
            Some(v) => v,
            None => {
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR INDEX NOT FOUND: verified {} cuckoo positions at group {} — all {} bins will be Merkle-verified for absence proof",
                    traces.index_bins.len(),
                    real_group,
                    traces.index_bins.len()
                );
                return Ok((None, traces));
            }
        };

        if num_chunks == 0 {
            return Ok((
                Some(QueryResult {
                    entries: Vec::new(),
                    is_whale,
                    // Optimistic default — `run_merkle_verification` flips
                    // this to `false` if the INDEX proof fails.
                    merkle_verified: true,
                    raw_chunk_data: None,
                    // HarmonyClient doesn't surface inspector state to
                    // `QueryResult` today (the per-group hints and
                    // cuckoo-position machinery are internal to the query
                    // path). Kept empty here so the struct shape matches
                    // the other clients; the WASM-side HarmonyClient
                    // inspector extensions are Session 5 territory.
                    index_bins: Vec::new(),
                    chunk_bins: Vec::new(),
                    matched_index_idx: None,
                }),
                traces,
            ));
        }

        let chunk_ids: Vec<u32> =
            (start_chunk_id..start_chunk_id + num_chunks as u32).collect();
        let (chunk_data, chunk_bins) = self.query_chunk_level(&chunk_ids, db_info).await?;
        traces.chunk_bins = chunk_bins;

        let entries = decode_utxo_entries(&chunk_data);
        Ok((
            Some(QueryResult {
                entries,
                is_whale,
                // Optimistic default — `run_merkle_verification` flips this
                // to `false` (and empties `entries`) if INDEX or CHUNK
                // proofs fail for this query.
                merkle_verified: true,
                raw_chunk_data: if db_info.kind.is_delta() {
                    Some(chunk_data)
                } else {
                    None
                },
                // See comment above — Harmony inspector state is out of
                // scope for Session 2.
                index_bins: Vec::new(),
                chunk_bins: Vec::new(),
                matched_index_idx: None,
            }),
            traces,
        ))
    }

    /// Build and send one INDEX batch (K groups, 1 sub-query each, real
    /// group + synthetic dummies). Returns the XOR-recovered bin for
    /// `(real_group, target_bin)`.
    ///
    /// `round_tag` is passed to the server as the `round_id` field —
    /// primarily useful for audit logging and load balancing.
    async fn run_index_round(
        &mut self,
        db_id: u8,
        real_group: u8,
        target_bin: u32,
        round_tag: usize,
    ) -> PirResult<Vec<u8>> {
        let k_index = self.index_groups.len() as u8;
        let mut batch_items: Vec<BatchItem> = Vec::with_capacity(k_index as usize);

        for g in 0..k_index {
            let group = self
                .index_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState(format!("missing INDEX group {}", g)))?;
            let bytes = if g == real_group {
                let req = group
                    .build_request(target_bin)
                    .map_err(|e| PirError::BackendState(format!("build_request: {:?}", e)))?;
                req.request()
            } else {
                group.build_synthetic_dummy()
            };
            batch_items.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes)?,
            });
        }

        let request = encode_batch_query(0, round_tag as u16, db_id, &batch_items);
        let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn.roundtrip(&request).await?;
        let results = decode_batch_response(&response)?;

        let data = results
            .get(&real_group)
            .ok_or_else(|| PirError::Protocol(format!("no response for group {}", real_group)))?;

        let group = self
            .index_groups
            .get_mut(&real_group)
            .ok_or_else(|| PirError::InvalidState("missing INDEX real group".into()))?;
        let answer = group
            .process_response(data)
            .map_err(|e| PirError::BackendState(format!("process_response: {:?}", e)))?;
        Ok(answer)
    }

    /// Execute CHUNK rounds to recover each chunk in `chunk_ids`.
    ///
    /// Returns `(chunk_data, chunk_bins)`:
    /// * `chunk_data` — assembled raw chunk bytes in the order of `chunk_ids`.
    /// * `chunk_bins` — per-chunk (pbc_group, bin_index, bin_content) for every
    ///   chunk we actually located. Used by the Merkle verifier to commit
    ///   the server to the chunk bin that served each slot.
    async fn query_chunk_level(
        &mut self,
        chunk_ids: &[u32],
        db_info: &DatabaseInfo,
    ) -> PirResult<(Vec<u8>, Vec<ChunkBinTrace>)> {
        let k_chunk = db_info.chunk_k as usize;
        let chunk_bins = db_info.chunk_bins as usize;

        // Map each chunk to its first candidate group. Two chunks may
        // collide on the same group — if so, only the first can be
        // queried in the current simple implementation. Follow-up work
        // could run PBC over multiple rounds the way the browser client
        // does; for now we fall back to whichever hash function places
        // the chunk in a free group.
        let mut pending: Vec<(u32, u8)> = Vec::new(); // (chunk_id, group)
        let mut used_groups: std::collections::HashSet<u8> =
            std::collections::HashSet::new();
        for &cid in chunk_ids {
            let candidates = pir_core::hash::derive_int_groups_3(cid, k_chunk);
            let mut placed = false;
            for &cand in &candidates {
                if !used_groups.contains(&(cand as u8)) {
                    pending.push((cid, cand as u8));
                    used_groups.insert(cand as u8);
                    placed = true;
                    break;
                }
            }
            if !placed {
                return Err(PirError::QueryFailed(format!(
                    "chunk {} collided on all {} candidate groups",
                    cid,
                    candidates.len()
                )));
            }
        }

        log::info!(
            "[PIR-AUDIT] HarmonyPIR CHUNK phase: {} chunks, k_chunk={}, bins={} (each round K_CHUNK-padded to {} groups)",
            chunk_ids.len(),
            k_chunk,
            chunk_bins,
            k_chunk
        );

        let mut chunk_data: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut chunk_trace_map: HashMap<u32, ChunkBinTrace> = HashMap::new();
        let mut recovered: std::collections::HashSet<u32> =
            std::collections::HashSet::new();

        for h in 0..CHUNK_CUCKOO_NUM_HASHES {
            let still_needed: Vec<(u32, u8)> = pending
                .iter()
                .copied()
                .filter(|(cid, _)| !recovered.contains(cid))
                .collect();

            if still_needed.is_empty() {
                break;
            }

            let round_answers = self
                .run_chunk_round(db_info.db_id, &still_needed, chunk_bins, h, h as u16)
                .await?;

            for (cid, group_id) in &still_needed {
                if let Some(answer) = round_answers.get(group_id) {
                    if let Some(data) = find_chunk_in_result(answer, *cid) {
                        // Recompute the bin index the same way `run_chunk_round`
                        // did, so our trace commits the server to the precise
                        // (group, bin) that served this chunk.
                        let key = pir_core::hash::derive_cuckoo_key(
                            CHUNK_PARAMS.master_seed,
                            *group_id as usize,
                            h,
                        );
                        let bin_index =
                            pir_core::hash::cuckoo_hash_int(*cid, key, chunk_bins) as u32;
                        chunk_data.insert(*cid, data.to_vec());
                        chunk_trace_map.insert(
                            *cid,
                            ChunkBinTrace {
                                pbc_group: *group_id as usize,
                                bin_index,
                                bin_content: answer.clone(),
                            },
                        );
                        log::info!(
                            "[PIR-AUDIT] HarmonyPIR CHUNK FOUND: chunk_id={}, group={}, bin={}, cuckoo_h={}",
                            cid, group_id, bin_index, h
                        );
                        recovered.insert(*cid);
                    }
                }
            }
        }

        for cid in chunk_ids {
            if !recovered.contains(cid) {
                log::warn!(
                    "[PIR-AUDIT] HarmonyPIR CHUNK MISSING: chunk_id={} (no cuckoo position matched)",
                    cid
                );
            }
        }

        let mut out = Vec::with_capacity(chunk_ids.len() * CHUNK_SIZE);
        let mut traces = Vec::with_capacity(chunk_ids.len());
        for cid in chunk_ids {
            if let Some(data) = chunk_data.get(cid) {
                out.extend_from_slice(data);
            }
            if let Some(trace) = chunk_trace_map.remove(cid) {
                traces.push(trace);
            }
        }

        Ok((out, traces))
    }

    /// Lazily create (and hint-load) sibling groups for per-bucket Merkle.
    ///
    /// Idempotent: re-runs are no-ops while `self.sibling_hints_loaded`
    /// matches the active db_id. Any change to `master_prp_key`,
    /// `prp_backend`, or `loaded_db_id` (via `invalidate_groups`) clears
    /// sibling state so the next call re-downloads.
    ///
    /// The number of sibling levels is derived from the server-supplied
    /// tree-tops: each tree's `cache_from_level` gives how many sibling
    /// rounds feed it, and the per-type max is the total sibling depth.
    /// `bins_per_table` at level L = `ceil(main_bins / arity^(L+1))`.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    async fn ensure_sibling_groups_ready(
        &mut self,
        db_info: &DatabaseInfo,
        tree_tops: &[TreeTop],
    ) -> PirResult<()> {
        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;
        if tree_tops.len() < k_index + k_chunk {
            return Err(PirError::Protocol(format!(
                "tree-tops has {} entries, expected at least {}",
                tree_tops.len(),
                k_index + k_chunk
            )));
        }
        let arity = BUCKET_MERKLE_ARITY as u64;
        let sib_w = BUCKET_MERKLE_SIB_ROW_SIZE as u32;

        let index_sib_levels = tree_tops[..k_index]
            .iter()
            .map(|t| t.cache_from_level)
            .max()
            .unwrap_or(0);
        let chunk_sib_levels = tree_tops[k_index..k_index + k_chunk]
            .iter()
            .map(|t| t.cache_from_level)
            .max()
            .unwrap_or(0);

        // Early-return only if our populated sibling state exactly
        // matches what the server-advertised tree-tops expect. Bare
        // "non-empty" was weaker: a cache restored from an older
        // snapshot with fewer levels would slip through and later
        // fail verification. This tighter check validates both
        // `sibling_hints_loaded` and the per-level group counts,
        // matching the invariants `persist_hints_to_cache` writes out.
        let expected_index_sib = index_sib_levels * k_index;
        let expected_chunk_sib = chunk_sib_levels * k_chunk;
        if self.sibling_hints_loaded == Some(db_info.db_id)
            && self.index_sib_groups.len() == expected_index_sib
            && self.chunk_sib_groups.len() == expected_chunk_sib
        {
            return Ok(());
        }

        // Reset any stale state before the refetch.
        self.index_sib_groups.clear();
        self.chunk_sib_groups.clear();
        self.sibling_hints_loaded = None;

        log::info!(
            "[PIR-AUDIT] HarmonyPIR sibling init: db_id={}, INDEX sib levels={}, CHUNK sib levels={}",
            db_info.db_id, index_sib_levels, chunk_sib_levels
        );

        // ── INDEX sibling groups ───────────────────────────────────────
        let mut nodes: u64 = db_info.index_bins as u64;
        for sl in 0..index_sib_levels {
            let level_n = nodes.div_ceil(arity);
            nodes = level_n;
            for g in 0..k_index {
                let group = HarmonyGroup::new_with_backend(
                    level_n as u32,
                    sib_w,
                    0,
                    &self.master_prp_key,
                    // Matches server `compute_hints_for_group` for level 10+sl:
                    //   k_offset = (k_index + k_chunk) + sl * k_index
                    //   derived_key uses k_offset + group_id.
                    ((k_index + k_chunk) + sl * k_index + g) as u32,
                    self.prp_backend,
                )
                .map_err(|e| {
                    PirError::BackendState(format!("INDEX sib HarmonyGroup init: {:?}", e))
                })?;
                self.index_sib_groups.insert((sl, g as u8), group);
            }
            self.fetch_and_load_hints_into(
                db_info.db_id,
                10 + sl as u8,
                k_index as u8,
                HintTarget::IndexSib(sl),
                None,
            )
            .await?;
            log::info!(
                "[PIR-AUDIT] HarmonyPIR INDEX sib L{}: loaded hints for {} groups (n={})",
                sl, k_index, level_n
            );
        }

        // ── CHUNK sibling groups ───────────────────────────────────────
        let mut nodes: u64 = db_info.chunk_bins as u64;
        for sl in 0..chunk_sib_levels {
            let level_n = nodes.div_ceil(arity);
            nodes = level_n;
            for g in 0..k_chunk {
                let group = HarmonyGroup::new_with_backend(
                    level_n as u32,
                    sib_w,
                    0,
                    &self.master_prp_key,
                    // Matches server `compute_hints_for_group` for level 20+sl:
                    //   k_offset = (k_index + k_chunk)
                    //            + index_sib_levels * k_index
                    //            + sl * k_chunk
                    ((k_index + k_chunk)
                        + index_sib_levels * k_index
                        + sl * k_chunk
                        + g) as u32,
                    self.prp_backend,
                )
                .map_err(|e| {
                    PirError::BackendState(format!("CHUNK sib HarmonyGroup init: {:?}", e))
                })?;
                self.chunk_sib_groups.insert((sl, g as u8), group);
            }
            self.fetch_and_load_hints_into(
                db_info.db_id,
                20 + sl as u8,
                k_chunk as u8,
                HintTarget::ChunkSib(sl),
                None,
            )
            .await?;
            log::info!(
                "[PIR-AUDIT] HarmonyPIR CHUNK sib L{}: loaded hints for {} groups (n={})",
                sl, k_chunk, level_n
            );
        }

        self.sibling_hints_loaded = Some(db_info.db_id);

        // Persist the combined main + sibling hint state — this is
        // the "complete" snapshot the fast path in
        // `ensure_groups_ready` will restore next launch. Persist
        // errors are logged and ignored (read-only cache dirs must
        // not fail live queries).
        if let Err(e) = self.persist_hints_to_cache(db_info) {
            log::warn!(
                "[PIR-AUDIT] HarmonyPIR: failed to persist hints (main+sib) to cache: {}",
                e
            );
        }
        Ok(())
    }

    /// Build `BucketMerkleItem`s from collected query traces and verify them
    /// in one padded batch via HarmonyPIR sibling queries.
    ///
    /// Mirrors `dpf.rs::run_merkle_verification`: on any bin failing
    /// verification, the corresponding query is coerced to
    /// `Some(QueryResult::merkle_failed())` to signal an unverified
    /// (untrusted) result.
    ///
    /// Implementation is a thin shim over the two helpers that also
    /// power the standalone
    /// [`verify_merkle_batch_for_results`](Self::verify_merkle_batch_for_results)
    /// API — items come from the per-query [`QueryTraces`], but the
    /// verifier itself is shared.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    async fn run_merkle_verification(
        &mut self,
        results: &mut [Option<QueryResult>],
        traces: &[QueryTraces],
        db_info: &DatabaseInfo,
    ) -> PirResult<()> {
        // Log the per-query outcome/item-count summary — kept here (not
        // in `collect_merkle_items_from_traces`) because this is the
        // path that feeds `[PIR-AUDIT]` audit logs. The
        // `verify_merkle_batch_for_results` path rebuilds items from
        // already-audited query results, so it doesn't need to re-log
        // the bin counts.
        for (qi, trace) in traces.iter().enumerate() {
            let outcome = match trace.matched_index_idx {
                Some(_) => {
                    let is_whale = results
                        .get(qi)
                        .and_then(|r| r.as_ref().map(|x| x.is_whale))
                        .unwrap_or(false);
                    if is_whale { "WHALE" } else { "FOUND" }
                }
                None => "NOT FOUND",
            };
            log::info!(
                "[PIR-AUDIT] HarmonyPIR Merkle: query #{} {} — verifying {} index bins + {} chunk bins",
                qi,
                outcome,
                trace.index_bins.len(),
                trace.chunk_bins.len()
            );
        }

        let (items, item_to_query) = collect_merkle_items_from_traces(traces);
        let verdicts = self
            .verify_merkle_items(&items, &item_to_query, results.len(), db_info)
            .await?;

        for (qi, verdict) in verdicts.into_iter().enumerate() {
            match verdict {
                None => continue, // not touched (no items attached to this query)
                Some(true) => {
                    log::info!("[PIR-AUDIT] HarmonyPIR Merkle PASSED for query #{}", qi);
                    // merkle_verified is already true by construction in query_single.
                }
                Some(false) => {
                    log::warn!(
                        "[PIR-AUDIT] HarmonyPIR Merkle FAILED for query #{}: \
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
        }

        Ok(())
    }

    /// Shared verifier backend used by both
    /// [`run_merkle_verification`](Self::run_merkle_verification) (inline,
    /// over fresh `QueryTraces`) and
    /// [`verify_merkle_batch_for_results`](Self::verify_merkle_batch_for_results)
    /// (standalone, over persisted `QueryResult.index_bins/chunk_bins`).
    ///
    /// Runs the full Merkle pipeline: `REQ_BUCKET_MERKLE_TREE_TOPS`
    /// fetch on the query server, `ensure_sibling_groups_ready` (which
    /// hits the hint server on cache miss), then
    /// [`verify_bucket_merkle_batch_generic`] via a
    /// [`HarmonySiblingQuerier`] holding mutable borrows of the sibling
    /// group maps + query connection.
    ///
    /// Returns one verdict per query:
    /// * `None`    — no items attached (query skipped verification).
    /// * `Some(true)`  — all attached items verified.
    /// * `Some(false)` — at least one item failed.
    ///
    /// Padding invariant: per-item Merkle work is uniform by
    /// construction — callers must always attach
    /// `INDEX_CUCKOO_NUM_HASHES` INDEX items per query, regardless of
    /// found/not-found (see CLAUDE.md "Merkle INDEX Item-Count
    /// Symmetry").
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", db_id = db_info.db_id, num_items = items.len(), num_queries)
    )]
    async fn verify_merkle_items(
        &mut self,
        items: &[BucketMerkleItem],
        item_to_query: &[usize],
        num_queries: usize,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<bool>>> {
        if items.is_empty() {
            log::info!(
                "[PIR-AUDIT] HarmonyPIR Merkle: no items to verify — nothing to do"
            );
            return Ok(vec![None; num_queries]);
        }

        // Fetch tree-tops blob via the query server (same blob both servers share).
        let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
        let tree_tops = fetch_tree_tops(conn, db_info.db_id).await?;

        // Ensure sibling groups + hints are initialised.
        self.ensure_sibling_groups_ready(db_info, &tree_tops).await?;

        // Drive the shared verifier with a Harmony-specific sibling querier.
        let index_k = db_info.index_k as usize;
        let chunk_k = db_info.chunk_k as usize;

        // Temporarily move sibling maps out of self so the querier can hold
        // mutable borrows of both them and the query connection. The maps
        // are restored before returning (on success OR failure).
        let mut index_sib_groups = std::mem::take(&mut self.index_sib_groups);
        let mut chunk_sib_groups = std::mem::take(&mut self.chunk_sib_groups);

        let per_item = {
            let query_conn = self
                .query_conn
                .as_mut()
                .ok_or(PirError::NotConnected)?;
            let mut querier = HarmonySiblingQuerier {
                query_conn,
                index_sib_groups: &mut index_sib_groups,
                chunk_sib_groups: &mut chunk_sib_groups,
            };
            verify_bucket_merkle_batch_generic(
                &mut querier,
                items,
                db_info.index_bins,
                db_info.chunk_bins,
                index_k,
                chunk_k,
                db_info.db_id,
                &tree_tops,
            )
            .await
        };

        // Restore sibling state regardless of success.
        self.index_sib_groups = index_sib_groups;
        self.chunk_sib_groups = chunk_sib_groups;

        let per_item = per_item?;

        // Aggregate per-item outcomes back to per-query verdicts: a
        // query passes iff ALL its items pass.
        let mut per_query: Vec<Option<bool>> = vec![None; num_queries];
        for (ii, ok) in per_item.iter().enumerate() {
            let qi = item_to_query[ii];
            per_query[qi] = match per_query[qi] {
                None => Some(*ok),
                Some(prev) => Some(prev && *ok),
            };
        }
        Ok(per_query)
    }

    /// Run a batch of PIR queries against `db_id` and return the raw
    /// per-query results **with inspector state populated**, deferring
    /// Merkle verification to a later
    /// [`verify_merkle_batch_for_results`](Self::verify_merkle_batch_for_results)
    /// call.
    ///
    /// # Shape vs. the trait-level `query_batch`
    ///
    /// Identical semantics to `DpfClient::query_batch_with_inspector`
    /// (see that method for the full contract). In short:
    ///
    /// * Every successful query returns `Some(QueryResult)` with
    ///   `index_bins` / `chunk_bins` / `matched_index_idx` populated
    ///   from the query's internal `QueryTraces`.
    /// * `matched_index_idx == None && entries.is_empty()` encodes
    ///   "not found".
    /// * `merkle_verified` is `true` — Merkle was **not** attempted.
    ///   Callers that care MUST pass the results to
    ///   `verify_merkle_batch_for_results` to get real verdicts.
    ///
    /// # 🔒 Padding invariant
    ///
    /// Same as the hot path — K=75 INDEX / K_CHUNK=80 CHUNK groups per
    /// round, synthetic HarmonyGroup dummies fill empty slots. This
    /// method only changes whether the client further requests Merkle
    /// siblings, not what the server sees at the query layer.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", db_id, num_queries = script_hashes.len())
    )]
    pub async fn query_batch_with_inspector(
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

        // Ensure groups are loaded for this db before firing queries;
        // `query_single` would do this per-call, but front-loading it
        // makes the inspector-path failure mode (hint-fetch errors)
        // cleaner — they surface as `Err` before any query runs.
        self.ensure_groups_ready(&db_info, None).await?;

        let mut results: Vec<Option<QueryResult>> = Vec::with_capacity(script_hashes.len());
        for script_hash in script_hashes {
            let (qr, trace) = self.query_single(script_hash, &db_info).await?;

            // Translate the trace into public `BucketRef`s. For
            // not-found we synthesise an empty `QueryResult` so the
            // inspector state isn't lost to the `None` return
            // convention.
            let with_inspector = match qr {
                Some(mut r) => {
                    r.index_bins = trace
                        .index_bins
                        .iter()
                        .map(index_trace_to_bucket_ref)
                        .collect();
                    r.chunk_bins = trace
                        .chunk_bins
                        .iter()
                        .map(chunk_trace_to_bucket_ref)
                        .collect();
                    r.matched_index_idx = trace.matched_index_idx;
                    Some(r)
                }
                None => {
                    let mut r = QueryResult::empty();
                    r.index_bins = trace
                        .index_bins
                        .iter()
                        .map(index_trace_to_bucket_ref)
                        .collect();
                    // chunk_bins empty by construction for not-found.
                    r.matched_index_idx = trace.matched_index_idx;
                    Some(r)
                }
            };
            results.push(with_inspector);
        }

        Ok(results)
    }

    /// Standalone per-bucket Merkle verifier for results previously
    /// returned by
    /// [`query_batch_with_inspector`](Self::query_batch_with_inspector)
    /// (or reconstructed by the caller from persisted storage — the
    /// verifier only needs `QueryResult.index_bins`, `chunk_bins`, and
    /// `matched_index_idx`).
    ///
    /// Rebuilds the same `BucketMerkleItem` set the inline
    /// [`run_merkle_verification`](Self::run_merkle_verification) path
    /// builds, then runs the networked verifier via the shared
    /// [`verify_merkle_items`](Self::verify_merkle_items) helper.
    ///
    /// Returns one `bool` per input query:
    /// * `true`  — all items verified, or no items attached (e.g. the
    ///   caller passed a `None` for that index, so there is nothing to
    ///   contradict).
    /// * `false` — at least one attached item failed the proof; the
    ///   corresponding result must be treated as untrusted and should
    ///   be discarded or surfaced as `QueryResult::merkle_failed()`.
    ///
    /// # 🔒 Padding invariant
    ///
    /// The underlying Merkle round is uniform by construction — the
    /// caller supplies items built from `INDEX_CUCKOO_NUM_HASHES`
    /// probes per query, and the shared verifier pads each level's
    /// sibling batch to K / K_CHUNK siblings (see CLAUDE.md "Query
    /// Padding").
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", db_id, num_results = results.len())
    )]
    pub async fn verify_merkle_batch_for_results(
        &mut self,
        results: &[Option<QueryResult>],
        db_id: u8,
    ) -> PirResult<Vec<bool>> {
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

        // If the database doesn't publish bucket Merkle, "verify" is a
        // no-op — mirrors `execute_step`'s skip branch so callers can
        // always call `verify_merkle_batch_for_results` without
        // pre-checking `has_bucket_merkle` first. Matches the
        // `QueryResult::merkle_verified` semantics ("no failure
        // detected").
        if !db_info.has_bucket_merkle {
            log::info!(
                "[PIR-AUDIT] HarmonyPIR verify_merkle_batch_for_results SKIPPED: \
                 db_id={} has no bucket Merkle",
                db_id
            );
            return Ok(vec![true; results.len()]);
        }

        // ensure_groups_ready + ensure_sibling_groups_ready need the
        // main groups to exist before sibling hints are fetched —
        // otherwise the HarmonySiblingQuerier would see empty
        // `index_sib_groups`/`chunk_sib_groups` maps.
        self.ensure_groups_ready(&db_info, None).await?;

        let (items, item_to_query) = collect_merkle_items_from_results(results);
        let verdicts = self
            .verify_merkle_items(&items, &item_to_query, results.len(), &db_info)
            .await?;

        // Translate `Option<bool>` to `bool` for the public surface:
        // `None` (no items attached) maps to `true` — consistent with
        // the "nothing to falsify" reading above.
        Ok(verdicts
            .into_iter()
            .map(|v| v.unwrap_or(true))
            .collect())
    }

    /// Like [`PirClient::sync`], but drives a [`SyncProgress`] observer
    /// through every step of the computed [`SyncPlan`]. Intended for
    /// UI surfaces (terminal spinner, JS `onProgress` callback) that
    /// want granular feedback on multi-step sync chains.
    ///
    /// Progress events fire in this order:
    /// 1. Per step, `on_step_start(step_index, total_steps, description)`
    ///    where `description` is the [`SyncStep::name`]
    ///    (e.g. `"full @940611"` or `"delta 940611→944000"`).
    /// 2. Per step, `on_step_progress(step_index, 1.0)` once the step's
    ///    PIR + Merkle work returns (step granularity — sub-step
    ///    progress isn't wired through the current `execute_step`).
    /// 3. Per step, `on_step_complete(step_index)`.
    /// 4. Once all steps succeed, `on_complete(synced_height)`.
    /// 5. On any error, `on_error(&e)` before the error is propagated.
    ///
    /// Padding invariants are preserved — progress is purely
    /// observational and doesn't change what's sent on the wire.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", num_queries = script_hashes.len(), last_height = ?last_height)
    )]
    pub async fn sync_with_progress(
        &mut self,
        script_hashes: &[ScriptHash],
        last_height: Option<u32>,
        progress: &dyn SyncProgress,
    ) -> PirResult<SyncResult> {
        let run = async {
            if !self.is_connected() {
                self.connect().await?;
            }

            let catalog = match &self.catalog {
                Some(c) => c.clone(),
                None => self.fetch_catalog().await?,
            };

            let plan = self.compute_sync_plan(&catalog, last_height)?;

            if plan.is_empty() {
                return Ok(SyncResult {
                    results: vec![None; script_hashes.len()],
                    synced_height: plan.target_height,
                    was_fresh_sync: false,
                });
            }

            let catalog = self
                .catalog
                .clone()
                .ok_or_else(|| PirError::InvalidState("no catalog".into()))?;

            let total = plan.steps.len();
            let mut merged: Vec<Option<QueryResult>> = vec![None; script_hashes.len()];
            for (step_idx, step) in plan.steps.iter().enumerate() {
                progress.on_step_start(step_idx, total, &step.name);

                let db_info = catalog
                    .get(step.db_id)
                    .ok_or(PirError::DatabaseNotFound(step.db_id))?
                    .clone();

                let step_results = self.execute_step(script_hashes, step, &db_info).await?;

                // Single coarse tick per step — see doc comment above
                // for why finer granularity isn't wired yet.
                progress.on_step_progress(step_idx, 1.0);

                if step.is_full() {
                    merged = step_results;
                } else {
                    merged = merge_delta_batch(&merged, &step_results)?;
                }
                progress.on_step_complete(step_idx);
            }

            let result = SyncResult {
                results: merged,
                synced_height: plan.target_height,
                was_fresh_sync: plan.is_fresh_sync,
            };
            progress.on_complete(result.synced_height);
            Ok(result)
        }
        .await;

        if let Err(e) = &run {
            progress.on_error(e);
        }
        run
    }

    // ─── Session 5 DB-switch + hint stats API ──────────────────────────────

    /// Get the db_id the currently loaded hint state corresponds to,
    /// or `None` if no hints are loaded.
    ///
    /// Mirrors `loaded_db_id` — after a
    /// [`set_db_id`](Self::set_db_id) to a different id, a subsequent
    /// `ensure_groups_ready` has to refetch hints (or restore from
    /// cache) before this matches again.
    pub fn db_id(&self) -> Option<u8> {
        self.loaded_db_id
    }

    /// Pre-fetch the main hint state for `db_info`, firing `progress`
    /// after each per-group response is processed.
    ///
    /// On a fresh fetch the callback is invoked exactly
    /// `db_info.index_k + db_info.chunk_k` times (typically 75 + 80 =
    /// 155), with `(done, total, phase)` reflecting cumulative progress.
    /// On a cache hit (or if hints for `db_info.db_id` are already
    /// loaded in memory) the callback fires once with
    /// `(total, total, "chunk")` so a UI driving its progress bar off
    /// this signal flips to "done" rather than silently sitting at 0%.
    ///
    /// This is a public entry point used by the WASM bridge to expose
    /// per-group progress to JS without forcing callers to issue a
    /// dummy query just to warm the hint state. After a successful
    /// call, [`db_id`](Self::db_id) returns `Some(db_info.db_id)` and
    /// subsequent queries skip the hint-fetch roundtrips.
    ///
    /// 🔒 Padding invariants are preserved — the wire shape is
    /// identical to the no-progress hint-fetch path; the callback is
    /// purely observational.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", db_id = db_info.db_id))]
    pub async fn fetch_hints_with_progress(
        &mut self,
        db_info: &DatabaseInfo,
        progress: &dyn HintProgress,
    ) -> PirResult<()> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }
        self.ensure_groups_ready(db_info, Some(progress)).await
    }

    /// Invalidate any loaded hint state and pin subsequent queries to
    /// `db_id`. No network traffic yet; the next
    /// [`execute_step`](Self::execute_step) /
    /// [`query_batch`](Self::query_batch) /
    /// [`query_batch_with_inspector`](Self::query_batch_with_inspector)
    /// will see the db mismatch and refetch (or restore from the hint
    /// cache if configured).
    ///
    /// Use this when an app pins a wallet to a specific db_id ahead of
    /// time — e.g. a browser session that just fetched a fresh
    /// catalog and wants to preload hints for db_id=0 before the user
    /// initiates a query.
    ///
    /// Passing the *same* `db_id` that's already loaded is a no-op;
    /// switching to any other id clears all in-memory hint state.
    /// This intentionally drops cached sibling groups too — a
    /// different db has different tree tops, so stale siblings would
    /// fail verification on their next use.
    pub fn set_db_id(&mut self, db_id: u8) {
        if self.loaded_db_id == Some(db_id) {
            return;
        }
        self.invalidate_groups();
    }

    /// Minimum remaining per-group query budget across every loaded
    /// `HarmonyGroup` (main INDEX/CHUNK and sibling INDEX/CHUNK). If
    /// nothing is loaded, returns `None` — callers should treat that
    /// as "unknown, call `ensure_groups_ready` first".
    ///
    /// HarmonyPIR groups each carry a `max_queries` budget; once any
    /// group in the batch exhausts, the next PIR round will error out
    /// on that group. This accessor is the primitive the browser UI
    /// uses to decide "time to refresh hints" proactively.
    pub fn min_queries_remaining(&self) -> Option<u32> {
        let mut min: Option<u32> = None;
        for g in self.index_groups.values() {
            let r = g.queries_remaining();
            min = Some(match min {
                None => r,
                Some(m) => m.min(r),
            });
        }
        for g in self.chunk_groups.values() {
            let r = g.queries_remaining();
            min = Some(match min {
                None => r,
                Some(m) => m.min(r),
            });
        }
        for g in self.index_sib_groups.values() {
            let r = g.queries_remaining();
            min = Some(match min {
                None => r,
                Some(m) => m.min(r),
            });
        }
        for g in self.chunk_sib_groups.values() {
            let r = g.queries_remaining();
            min = Some(match min {
                None => r,
                Some(m) => m.min(r),
            });
        }
        min
    }

    /// Byte size of the blob [`save_hints_bytes`](Self::save_hints_bytes)
    /// would produce **right now**. Returns 0 when no state is loaded.
    ///
    /// This calls `save_hints_bytes()` internally and measures the
    /// resulting blob length. It is therefore O(total hint bytes) —
    /// fine for UI-polling-with-a-few-seconds-period cadence, but
    /// callers should not call it in the hot query path. Silently
    /// returns 0 on any internal error so UI surfaces don't have to
    /// care about transport state — this is a display-only estimate.
    pub fn estimate_hint_size_bytes(&self) -> usize {
        match self.save_hints_bytes() {
            Ok(Some(bytes)) => bytes.len(),
            _ => 0,
        }
    }

    /// 16-byte fingerprint of the on-disk / in-memory cache key for
    /// `db_info` under this client's current master key and PRP
    /// backend. Useful for JS-side cache eviction policies (e.g.
    /// IndexedDB key derivation) without recomputing the hash in TS.
    ///
    /// This is exactly the same fingerprint embedded in the
    /// [`save_hints_bytes`](Self::save_hints_bytes) blob header and
    /// used as the on-disk cache filename stem — so
    /// `fingerprint(db_info) == load_hints_bytes(save_hints_bytes()?.?,
    /// db_info)`'s expected fingerprint. The accessor is a pure
    /// function of `(master_prp_key, prp_backend, db_info)` — no
    /// network traffic, safe to call from anywhere.
    pub fn cache_fingerprint(&self, db_info: &DatabaseInfo) -> [u8; 16] {
        hint_cache::CacheKey::from_db_info(self.master_prp_key, self.prp_backend, db_info)
            .fingerprint()
    }

    /// Build and send one CHUNK batch (K_CHUNK groups, 1 sub-query each).
    async fn run_chunk_round(
        &mut self,
        db_id: u8,
        real_queries: &[(u32, u8)],
        chunk_bins: usize,
        hash_fn: usize,
        round_id: u16,
    ) -> PirResult<HashMap<u8, Vec<u8>>> {
        let k_chunk = self.chunk_groups.len() as u8;
        let real_map: HashMap<u8, u32> = real_queries.iter().map(|&(c, g)| (g, c)).collect();

        let mut batch_items: Vec<BatchItem> = Vec::with_capacity(k_chunk as usize);

        for g in 0..k_chunk {
            let group = self
                .chunk_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState(format!("missing CHUNK group {}", g)))?;
            let bytes = if let Some(&cid) = real_map.get(&g) {
                let key =
                    pir_core::hash::derive_cuckoo_key(CHUNK_PARAMS.master_seed, g as usize, hash_fn);
                let target_bin = pir_core::hash::cuckoo_hash_int(cid, key, chunk_bins);
                let req = group.build_request(target_bin as u32).map_err(|e| {
                    PirError::BackendState(format!("build_request (chunk): {:?}", e))
                })?;
                req.request()
            } else {
                group.build_synthetic_dummy()
            };
            batch_items.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes)?,
            });
        }

        let request = encode_batch_query(1, round_id, db_id, &batch_items);
        let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn.roundtrip(&request).await?;
        let raw_results = decode_batch_response(&response)?;

        let mut out = HashMap::new();
        for &g in real_map.keys() {
            let data = raw_results.get(&g).ok_or_else(|| {
                PirError::Protocol(format!("no CHUNK response for group {}", g))
            })?;
            let group = self
                .chunk_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState("missing CHUNK real group".into()))?;
            let answer = group.process_response(data).map_err(|e| {
                PirError::BackendState(format!("process_response (chunk): {:?}", e))
            })?;
            out.insert(g, answer);
        }
        Ok(out)
    }
}

#[async_trait]
impl PirClient for HarmonyClient {
    fn backend_type(&self) -> PirBackendType {
        PirBackendType::Harmony
    }

    #[tracing::instrument(level = "info", skip_all, fields(backend = "harmony", hint = %self.hint_server_url, query = %self.query_server_url))]
    async fn connect(&mut self) -> PirResult<()> {
        log::info!(
            "Connecting to HarmonyPIR servers: hint={}, query={}",
            self.hint_server_url,
            self.query_server_url
        );
        self.notify_state(ConnectionState::Connecting);

        // Native → tokio::try_join! over tokio-tungstenite; WASM →
        // futures::future::try_join over web-sys WebSocket. See `DpfClient`
        // for the same pattern with an explanation.
        #[cfg(not(target_arch = "wasm32"))]
        let dial_result: PirResult<(Box<dyn PirTransport>, Box<dyn PirTransport>)> = async {
            let (h, q) = tokio::try_join!(
                WsConnection::connect(&self.hint_server_url),
                WsConnection::connect(&self.query_server_url),
            )?;
            Ok((
                Box::new(h) as Box<dyn PirTransport>,
                Box::new(q) as Box<dyn PirTransport>,
            ))
        }
        .await;
        #[cfg(target_arch = "wasm32")]
        let dial_result: PirResult<(Box<dyn PirTransport>, Box<dyn PirTransport>)> = async {
            use crate::wasm_transport::WasmWebSocketTransport;
            let (h, q) = futures::future::try_join(
                WasmWebSocketTransport::connect(&self.hint_server_url),
                WasmWebSocketTransport::connect(&self.query_server_url),
            )
            .await?;
            Ok((
                Box::new(h) as Box<dyn PirTransport>,
                Box::new(q) as Box<dyn PirTransport>,
            ))
        }
        .await;

        let (hint_conn, query_conn) = match dial_result {
            Ok(v) => v,
            Err(e) => {
                // Handshake failed — fall back to `Disconnected`, not
                // `Connecting`, so observers don't get stuck on an
                // intermediate state if they didn't install a catch-all.
                self.notify_state(ConnectionState::Disconnected);
                return Err(e);
            }
        };

        self.hint_conn = Some(hint_conn);
        self.query_conn = Some(query_conn);

        // Propagate any installed recorder to the fresh transports so
        // per-frame byte counts start flowing immediately. Done after
        // both slots are populated so a mid-connect observer can't see
        // half-installed state.
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(ref mut c) = self.hint_conn {
                c.set_metrics_recorder(Some(rec.clone()), "harmony");
            }
            if let Some(ref mut c) = self.query_conn {
                c.set_metrics_recorder(Some(rec), "harmony");
            }
        }

        log::info!("Connected to both HarmonyPIR servers");
        self.fire_connect(&self.hint_server_url);
        self.fire_connect(&self.query_server_url);
        self.notify_state(ConnectionState::Connected);
        Ok(())
    }

    #[tracing::instrument(level = "info", skip_all, fields(backend = "harmony"))]
    async fn disconnect(&mut self) -> PirResult<()> {
        if let Some(ref mut conn) = self.hint_conn {
            let _ = conn.close().await;
        }
        if let Some(ref mut conn) = self.query_conn {
            let _ = conn.close().await;
        }
        self.hint_conn = None;
        self.query_conn = None;
        self.catalog = None;
        self.invalidate_groups();
        self.fire_disconnect();
        self.notify_state(ConnectionState::Disconnected);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.hint_conn.is_some() && self.query_conn.is_some()
    }

    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony"))]
    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }

        // Prefer `REQ_GET_DB_CATALOG`: it carries real `height` and
        // `has_bucket_merkle` fields and reports every database the server
        // is serving (fresh + deltas), so `SyncResult::synced_height` is
        // accurate and cache-by-height works correctly. Fall back to the
        // legacy `REQ_HARMONY_GET_INFO` only for servers that don't support
        // the newer request (empty reply, unknown variant byte, or
        // `RESP_ERROR`).
        if let Some(catalog) = self.try_fetch_db_catalog().await? {
            log::info!(
                "[PIR-AUDIT] HarmonyClient fetched DatabaseCatalog via REQ_GET_DB_CATALOG: \
                 {} database(s), latest_tip={:?}",
                catalog.databases.len(),
                catalog.latest_tip()
            );
            self.catalog = Some(catalog.clone());
            return Ok(catalog);
        }

        log::warn!(
            "[PIR-AUDIT] HarmonyClient server did not respond to REQ_GET_DB_CATALOG; \
             falling back to legacy REQ_HARMONY_GET_INFO (height will be 0, Merkle off)"
        );
        let info = self.fetch_legacy_info().await?;
        let catalog = DatabaseCatalog {
            databases: vec![info],
        };
        self.catalog = Some(catalog.clone());
        Ok(catalog)
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

    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(backend = "harmony", num_queries = script_hashes.len(), last_height = ?last_height)
    )]
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

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            backend = "harmony",
            num_queries = script_hashes.len(),
            num_steps = plan.steps.len(),
            target_height = plan.target_height,
            is_fresh_sync = plan.is_fresh_sync,
        )
    )]
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
                "[{}/{}] HarmonyPIR querying {} (db_id={}, height={})",
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

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "harmony", db_id, num_queries = script_hashes.len())
    )]
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

        // Fire query lifecycle callbacks so a recorder can time the
        // batch end-to-end without needing mid-layer hooks. `fire_*`
        // is a no-op when no recorder is installed; the
        // `Option<Instant>` returned by `fire_query_start` carries
        // the start moment when a recorder is installed and is `None`
        // otherwise (zero-overhead no-recorder path).
        let num_queries = script_hashes.len();
        let started_at = self.fire_query_start(db_id, num_queries);
        let step = SyncStep::from_db_info(&db_info);
        let result = self.execute_step(script_hashes, &step, &db_info).await;
        self.fire_query_end(db_id, num_queries, result.is_ok(), started_at);
        result
    }
}

// ─── Wire protocol helpers ──────────────────────────────────────────────────

struct BatchItem {
    group_id: u8,
    indices: Vec<u32>,
}

/// Wire format (matches `runtime::protocol::HarmonyBatchQuery::encode()`):
///
/// ```text
/// [4B msg_len LE]
/// [1B 0x43]
/// [1B level]
/// [2B round_id LE]
/// [2B num_groups LE]
/// [1B sub_queries_per_group = 1]
/// per group:
///   [1B group_id]
///   [4B count LE]
///   [count × 4B u32 LE]
/// [optional 1B db_id if db_id != 0]
/// ```
fn encode_batch_query(level: u8, round_id: u16, db_id: u8, items: &[BatchItem]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(level);
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.extend_from_slice(&(items.len() as u16).to_le_bytes());
    payload.push(1u8); // sub_queries_per_group

    for item in items {
        payload.push(item.group_id);
        payload.extend_from_slice(&(item.indices.len() as u32).to_le_bytes());
        for idx in &item.indices {
            payload.extend_from_slice(&idx.to_le_bytes());
        }
    }

    if db_id != 0 {
        payload.push(db_id);
    }

    encode_request(REQ_HARMONY_BATCH_QUERY, &payload)
}

/// Decode a `HarmonyBatchResult` payload (caller has already stripped
/// the 4-byte length prefix via `roundtrip`). Returns a `group_id ->
/// first_sub_result` map (we always send 1 sub-query per group).
///
/// Wire format:
/// ```text
/// [1B 0x43]
/// [1B level]
/// [2B round_id LE]
/// [2B num_groups LE]
/// [1B sub_results_per_group]
/// per group:
///   [1B group_id]
///   per sub-result:
///     [4B data_len LE]
///     [data_len bytes]
/// ```
fn decode_batch_response(body: &[u8]) -> PirResult<HashMap<u8, Vec<u8>>> {
    if body.is_empty() {
        return Err(PirError::Decode("empty batch response".into()));
    }
    if body[0] == RESP_ERROR {
        let reason = if body.len() > 1 {
            String::from_utf8_lossy(&body[1..]).to_string()
        } else {
            "query server error".into()
        };
        return Err(PirError::ServerError(reason));
    }
    if body[0] != RESP_HARMONY_BATCH_QUERY {
        return Err(PirError::Protocol(format!(
            "unexpected batch response byte: 0x{:02x}",
            body[0]
        )));
    }
    if body.len() < 7 {
        return Err(PirError::Decode("batch response header truncated".into()));
    }
    let mut pos = 1;
    let _level = body[pos];
    pos += 1;
    let _round_id = u16::from_le_bytes(body[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_groups = u16::from_le_bytes(body[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    let sub_per_group = body[pos] as usize;
    pos += 1;

    let mut out: HashMap<u8, Vec<u8>> = HashMap::with_capacity(num_groups);

    for _ in 0..num_groups {
        if pos >= body.len() {
            return Err(PirError::Decode("group id truncated".into()));
        }
        let gid = body[pos];
        pos += 1;

        let mut first_sub: Option<Vec<u8>> = None;
        for s in 0..sub_per_group {
            if pos + 4 > body.len() {
                return Err(PirError::Decode("sub-result length truncated".into()));
            }
            let dlen = u32::from_le_bytes(body[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + dlen > body.len() {
                return Err(PirError::Decode("sub-result data truncated".into()));
            }
            if s == 0 {
                first_sub = Some(body[pos..pos + dlen].to_vec());
            }
            pos += dlen;
        }

        if let Some(d) = first_sub {
            out.insert(gid, d);
        }
    }

    Ok(out)
}

fn bytes_to_u32_vec(data: &[u8]) -> PirResult<Vec<u32>> {
    if !data.len().is_multiple_of(4) {
        return Err(PirError::Encode(format!(
            "request index bytes not a multiple of 4 (got {})",
            data.len()
        )));
    }
    Ok(data
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect())
}

// ─── PIR helpers ────────────────────────────────────────────────────────────

/// Scan the XOR-recovered INDEX bin for an entry matching `expected_tag`.
/// Returns `(start_chunk_id, num_chunks)` if found.
fn find_entry_in_index_result(result: &[u8], expected_tag: u64) -> Option<(u32, u8)> {
    for slot in 0..INDEX_SLOTS_PER_BIN {
        let base = slot * INDEX_SLOT_SIZE;
        if base + INDEX_SLOT_SIZE > result.len() {
            break;
        }
        let slot_tag = u64::from_le_bytes(result[base..base + TAG_SIZE].try_into().unwrap());
        if slot_tag == expected_tag {
            let start_chunk_id = u32::from_le_bytes(
                result[base + TAG_SIZE..base + TAG_SIZE + 4].try_into().unwrap(),
            );
            let num_chunks = result[base + TAG_SIZE + 4];
            return Some((start_chunk_id, num_chunks));
        }
    }
    None
}

/// Scan a CHUNK bin for the slot whose chunk_id matches `chunk_id`.
fn find_chunk_in_result(result: &[u8], chunk_id: u32) -> Option<&[u8]> {
    let target = chunk_id.to_le_bytes();
    for slot in 0..CHUNK_SLOTS_PER_BIN {
        let base = slot * CHUNK_SLOT_SIZE;
        if base + CHUNK_SLOT_SIZE > result.len() {
            break;
        }
        if result[base..base + 4] == target {
            return Some(&result[base + 4..base + CHUNK_SLOT_SIZE]);
        }
    }
    None
}

/// Decode concatenated UTXO chunk bytes into a `Vec<UtxoEntry>`.
fn decode_utxo_entries(data: &[u8]) -> Vec<UtxoEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos + CHUNK_SIZE <= data.len() {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let vout = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let amount_compressed = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        if txid.iter().all(|&b| b == 0) {
            continue;
        }

        entries.push(UtxoEntry {
            txid,
            vout,
            amount_sats: amount_compressed as u64,
        });
    }
    entries
}

/// Hex-format a 20-byte script hash as "aabbcc..eeff" (first and last 4 bytes).
/// Avoids pulling in the `hex` crate for one audit-log string; mirrors the
/// helper in `dpf.rs` so both clients log query traces identically.
fn format_hash_short(h: &[u8]) -> String {
    if h.len() <= 8 {
        let mut s = String::with_capacity(h.len() * 2);
        for b in h {
            s.push_str(&format!("{:02x}", b));
        }
        return s;
    }
    let mut s = String::with_capacity(22);
    for b in &h[..4] {
        s.push_str(&format!("{:02x}", b));
    }
    s.push_str("..");
    for b in &h[h.len() - 4..] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ─── HarmonyPIR sibling querier for per-bucket Merkle ───────────────────────

/// HarmonyPIR-specific [`BucketMerkleSiblingQuerier`] impl.
///
/// One instance drives all sibling-level batches for one call to
/// `verify_bucket_merkle_batch_generic`. It borrows the query connection
/// and the sibling-group maps (owned by [`HarmonyClient`]) for the
/// duration of the verification, so the caller must `std::mem::take` them
/// out first to satisfy the borrow checker — see
/// `HarmonyClient::run_merkle_verification` for the pattern.
///
/// Each call to [`BucketMerkleSiblingQuerier::query_pass`] runs one
/// server round-trip on the query server:
///
/// * exactly K (INDEX) or K_CHUNK (CHUNK) sub-queries — one per PBC group —
///   matching `pass_targets.len()`;
/// * real slots use `HarmonyGroup::build_request` + `process_response`
///   to recover the 256-byte sibling row;
/// * padding slots use `HarmonyGroup::build_synthetic_dummy` so the server
///   cannot distinguish real from padding (see CLAUDE.md "Query Padding").
///
/// The `level` byte sent on the wire is `10 + merkle_level` for INDEX
/// sibling rounds and `20 + merkle_level` for CHUNK, matching the server
/// convention (see `runtime::protocol::HarmonyBatchQuery`).
struct HarmonySiblingQuerier<'a> {
    /// Query server transport — held mutably across the verification.
    /// Typed as `&mut dyn PirTransport` so the verifier works against
    /// any PirTransport impl (WsConnection in production; MockTransport
    /// in tests; a future WASM WebSocket impl without a code change).
    query_conn: &'a mut dyn PirTransport,
    /// INDEX sibling groups keyed by `(merkle_level, group_id)`.
    /// Populated by `HarmonyClient::ensure_sibling_groups_ready`.
    index_sib_groups: &'a mut HashMap<(usize, u8), HarmonyGroup>,
    /// CHUNK sibling groups keyed by `(merkle_level, group_id)`.
    chunk_sib_groups: &'a mut HashMap<(usize, u8), HarmonyGroup>,
}

#[async_trait]
impl BucketMerkleSiblingQuerier for HarmonySiblingQuerier<'_> {
    async fn query_pass(
        &mut self,
        table_type: u8,
        level: usize,
        _level_bins_per_table: u32,
        pass_targets: &[Option<u32>],
        db_id: u8,
    ) -> PirResult<Vec<Option<Vec<u8>>>> {
        let table_k = pass_targets.len();

        // Wire `level` byte: 10+L for INDEX sib L, 20+L for CHUNK sib L.
        let wire_level: u8 = match table_type {
            0 => 10u8
                .checked_add(level as u8)
                .ok_or_else(|| PirError::InvalidState(format!(
                    "INDEX sib level {} does not fit in wire byte",
                    level
                )))?,
            1 => 20u8
                .checked_add(level as u8)
                .ok_or_else(|| PirError::InvalidState(format!(
                    "CHUNK sib level {} does not fit in wire byte",
                    level
                )))?,
            other => {
                return Err(PirError::InvalidState(format!(
                    "unknown sibling table_type {}",
                    other
                )))
            }
        };

        // Track which slots issued a real request so we can call
        // process_response on exactly those groups.
        let mut real_slots: Vec<u8> = Vec::new();
        let mut batch_items: Vec<BatchItem> = Vec::with_capacity(table_k);

        for (g_idx, target) in pass_targets.iter().enumerate() {
            let g = g_idx as u8;
            let group = match table_type {
                0 => self.index_sib_groups.get_mut(&(level, g)),
                1 => self.chunk_sib_groups.get_mut(&(level, g)),
                _ => None,
            };
            let group = group.ok_or_else(|| {
                PirError::InvalidState(format!(
                    "missing {} sib group ({}, {})",
                    if table_type == 0 { "INDEX" } else { "CHUNK" },
                    level,
                    g
                ))
            })?;

            let bytes = if let Some(t) = *target {
                real_slots.push(g);
                let req = group.build_request(t).map_err(|e| {
                    PirError::BackendState(format!("sib build_request: {:?}", e))
                })?;
                req.request()
            } else {
                group.build_synthetic_dummy()
            };

            batch_items.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes)?,
            });
        }

        // round_id mirrors the DPF querier's convention so audit logs align.
        let round_id = (table_type as u16) * 100 + level as u16;
        let request = encode_batch_query(wire_level, round_id, db_id, &batch_items);
        let response = self.query_conn.roundtrip(&request).await?;
        let raw_results = decode_batch_response(&response)?;

        let mut out: Vec<Option<Vec<u8>>> = vec![None; table_k];
        for g in &real_slots {
            let data = raw_results.get(g).ok_or_else(|| {
                PirError::Protocol(format!(
                    "no sibling response for group {} at table_type={}, level={}",
                    g, table_type, level
                ))
            })?;
            let group = match table_type {
                0 => self.index_sib_groups.get_mut(&(level, *g)),
                1 => self.chunk_sib_groups.get_mut(&(level, *g)),
                _ => None,
            };
            let group = group.ok_or_else(|| {
                PirError::InvalidState(format!(
                    "sib group vanished mid-pass ({}, {})",
                    level, g
                ))
            })?;
            let row = group.process_response(data).map_err(|e| {
                PirError::BackendState(format!("sib process_response: {:?}", e))
            })?;
            if row.len() != BUCKET_MERKLE_SIB_ROW_SIZE {
                return Err(PirError::Protocol(format!(
                    "sib response has {} bytes, expected {}",
                    row.len(),
                    BUCKET_MERKLE_SIB_ROW_SIZE
                )));
            }
            out[*g as usize] = Some(row);
        }

        Ok(out)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_client() {
        let client = HarmonyClient::new("ws://localhost:8080", "ws://localhost:8081");
        assert!(!client.is_connected());
        assert_eq!(client.backend_type(), PirBackendType::Harmony);
        assert_eq!(client.prp_backend, PRP_HMR12);
    }

    #[test]
    fn test_set_master_key_invalidates_groups() {
        let mut client = HarmonyClient::new("ws://localhost:8080", "ws://localhost:8081");
        client.loaded_db_id = Some(0);
        // No groups yet, but invalidation should clear the id.
        client.set_master_key([7u8; 16]);
        assert!(client.loaded_db_id.is_none());
    }

    #[test]
    fn test_encode_batch_roundtrip() {
        let items = vec![
            BatchItem {
                group_id: 3,
                indices: vec![1, 2, 3, 4],
            },
            BatchItem {
                group_id: 7,
                indices: vec![],
            },
        ];
        let wire = encode_batch_query(0, 5, 0, &items);
        // First 4 bytes are length; skip them.
        assert_eq!(wire[4], REQ_HARMONY_BATCH_QUERY);
        assert_eq!(wire[5], 0); // level
        assert_eq!(u16::from_le_bytes([wire[6], wire[7]]), 5); // round_id
        assert_eq!(u16::from_le_bytes([wire[8], wire[9]]), 2); // num_groups
        assert_eq!(wire[10], 1); // sub_queries_per_group
    }

    #[test]
    fn test_bytes_to_u32_vec() {
        let bytes = vec![1u8, 0, 0, 0, 2, 0, 0, 0];
        let v = bytes_to_u32_vec(&bytes).unwrap();
        assert_eq!(v, vec![1u32, 2u32]);
        assert!(bytes_to_u32_vec(&[1, 2, 3]).is_err());
    }

    /// Demonstrates the test-injection escape hatch: a client built with a
    /// pair of [`MockTransport`](crate::transport::mock::MockTransport)s
    /// reports `is_connected()` without ever opening a real socket. This is
    /// the core value prop of the `PirTransport` trait.
    #[test]
    fn connect_with_transport_marks_connected() {
        use crate::transport::mock::MockTransport;
        let mut client =
            HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        assert!(!client.is_connected());
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-hint")),
            Box::new(MockTransport::new("wss://mock-query")),
        );
        assert!(client.is_connected());
    }

    // ─── Hint cache plumbing tests ─────────────────────────────────────────

    fn sample_db_info() -> DatabaseInfo {
        DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: "test".into(),
            height: 100,
            // Keep params tiny so HarmonyGroup::new runs in milliseconds.
            // INDEX + CHUNK bins don't need to be realistic; we only
            // exercise state round-trip, not PIR correctness.
            index_bins: 32,
            chunk_bins: 32,
            index_k: 2,
            chunk_k: 2,
            tag_seed: 0x1234_5678_9ABC_DEF0,
            dpf_n_index: 5,
            dpf_n_chunk: 5,
            has_bucket_merkle: false,
        }
    }

    /// Populate a client's main groups locally without touching the
    /// network — mirrors what `ensure_groups_ready` does on a cache
    /// miss, minus the `fetch_and_load_hints` network roundtrips.
    /// This lets us exercise `save_hints_bytes` / `load_hints_bytes`
    /// purely in-process.
    fn populate_main_groups(client: &mut HarmonyClient, info: &DatabaseInfo) {
        let k_index = info.index_k as usize;
        let k_chunk = info.chunk_k as usize;
        let index_w = (INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE) as u32;
        let chunk_w = (CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE) as u32;

        for g in 0..k_index {
            let group = HarmonyGroup::new_with_backend(
                info.index_bins,
                index_w,
                0,
                &client.master_prp_key,
                g as u32,
                client.prp_backend,
            )
            .expect("HarmonyGroup init");
            client.index_groups.insert(g as u8, group);
        }
        for g in 0..k_chunk {
            let group = HarmonyGroup::new_with_backend(
                info.chunk_bins,
                chunk_w,
                0,
                &client.master_prp_key,
                (k_index + g) as u32,
                client.prp_backend,
            )
            .expect("HarmonyGroup init");
            client.chunk_groups.insert(g as u8, group);
        }
        client.loaded_db_id = Some(info.db_id);
    }

    #[test]
    fn with_hint_cache_dir_sets_and_reads() {
        let client = HarmonyClient::new("wss://h", "wss://q")
            .with_hint_cache_dir("/tmp/pir-test-cache");
        assert_eq!(
            client.hint_cache_dir(),
            Some(std::path::Path::new("/tmp/pir-test-cache"))
        );
    }

    #[test]
    fn set_hint_cache_dir_mutates_and_clears() {
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        assert!(client.hint_cache_dir().is_none());
        client.set_hint_cache_dir(Some(PathBuf::from("/tmp/x")));
        assert_eq!(
            client.hint_cache_dir(),
            Some(std::path::Path::new("/tmp/x"))
        );
        client.set_hint_cache_dir(None);
        assert!(client.hint_cache_dir().is_none());
    }

    #[test]
    fn save_hints_bytes_returns_none_when_nothing_loaded() {
        let client = HarmonyClient::new("wss://h", "wss://q");
        // Even though loaded_db_id is None by default, also require a
        // populated catalog to avoid false positives.
        let out = client.save_hints_bytes().unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn save_hints_bytes_errors_when_catalog_missing() {
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        client.loaded_db_id = Some(0);
        // No catalog installed → InvalidState.
        let err = client.save_hints_bytes().unwrap_err();
        assert!(matches!(err, PirError::InvalidState(_)));
    }

    #[test]
    fn save_and_load_hints_bytes_round_trips_main_groups() {
        let info = sample_db_info();
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        client.set_master_key([0x42u8; 16]);
        client.catalog = Some(DatabaseCatalog {
            databases: vec![info.clone()],
        });
        populate_main_groups(&mut client, &info);

        let bytes = client.save_hints_bytes().unwrap().expect("some bytes");
        assert!(!bytes.is_empty());

        // Reset the client and reload from the blob.
        let mut client2 = HarmonyClient::new("wss://h", "wss://q");
        client2.set_master_key([0x42u8; 16]);
        client2.catalog = Some(DatabaseCatalog {
            databases: vec![info.clone()],
        });
        client2.load_hints_bytes(&bytes, &info).unwrap();

        assert_eq!(client2.loaded_db_id, Some(info.db_id));
        assert_eq!(client2.index_groups.len(), info.index_k as usize);
        assert_eq!(client2.chunk_groups.len(), info.chunk_k as usize);
        // Sibling state wasn't populated; shouldn't be claimed.
        assert!(client2.sibling_hints_loaded.is_none());
    }

    #[test]
    fn load_hints_bytes_rejects_master_key_mismatch() {
        let info = sample_db_info();
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        client.set_master_key([0x11u8; 16]);
        client.catalog = Some(DatabaseCatalog {
            databases: vec![info.clone()],
        });
        populate_main_groups(&mut client, &info);
        let bytes = client.save_hints_bytes().unwrap().expect("some bytes");

        // Second client with a different master key should refuse.
        let mut client2 = HarmonyClient::new("wss://h", "wss://q");
        client2.set_master_key([0x22u8; 16]);
        let err = client2.load_hints_bytes(&bytes, &info).unwrap_err();
        assert!(
            matches!(err, PirError::InvalidState(_)),
            "expected InvalidState, got {:?}",
            err
        );
    }

    #[test]
    fn load_hints_bytes_rejects_shape_mismatch() {
        let info_a = sample_db_info();
        let mut info_b = sample_db_info();
        info_b.index_bins *= 2;

        let mut client = HarmonyClient::new("wss://h", "wss://q");
        client.set_master_key([0x33u8; 16]);
        client.catalog = Some(DatabaseCatalog {
            databases: vec![info_a.clone()],
        });
        populate_main_groups(&mut client, &info_a);
        let bytes = client.save_hints_bytes().unwrap().expect("bytes");

        // Load with db info that has different shape → fingerprint
        // mismatch.
        let mut client2 = HarmonyClient::new("wss://h", "wss://q");
        client2.set_master_key([0x33u8; 16]);
        let err = client2.load_hints_bytes(&bytes, &info_b).unwrap_err();
        assert!(matches!(err, PirError::InvalidState(_)));
    }

    #[test]
    fn persist_and_restore_hints_to_cache_round_trips() {
        let info = sample_db_info();
        let tmp = std::env::temp_dir().join(format!(
            "pir-sdk-harmony-cache-{}-{}",
            std::process::id(),
            pir_core::merkle::sha256(b"persist-restore")[0]
        ));
        // Fresh client writes a cache file.
        let mut client = HarmonyClient::new("wss://h", "wss://q")
            .with_hint_cache_dir(&tmp);
        client.set_master_key([0x77u8; 16]);
        client.catalog = Some(DatabaseCatalog {
            databases: vec![info.clone()],
        });
        populate_main_groups(&mut client, &info);
        client.persist_hints_to_cache(&info).unwrap();

        // Second client reads it back.
        let mut client2 = HarmonyClient::new("wss://h", "wss://q")
            .with_hint_cache_dir(&tmp);
        client2.set_master_key([0x77u8; 16]);
        // No catalog needed on restore — fingerprint includes db shape
        // + master key, both of which we supply here directly.
        let restored = client2.restore_hints_from_cache(&info).unwrap();
        assert!(restored);
        assert_eq!(client2.loaded_db_id, Some(info.db_id));
        assert_eq!(client2.index_groups.len(), info.index_k as usize);
        assert_eq!(client2.chunk_groups.len(), info.chunk_k as usize);

        // Cold-cache path: different master key → fingerprint mismatch
        // → `restore_hints_from_cache` returns false (not an error),
        // the groups stay invalidated.
        let mut client3 = HarmonyClient::new("wss://h", "wss://q")
            .with_hint_cache_dir(&tmp);
        client3.set_master_key([0x88u8; 16]); // different key
        let restored3 = client3.restore_hints_from_cache(&info).unwrap();
        assert!(!restored3);
        assert!(client3.loaded_db_id.is_none());
        assert!(client3.index_groups.is_empty());

        // Cleanup.
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn restore_hints_from_cache_returns_false_when_dir_unset() {
        let info = sample_db_info();
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        assert!(!client.restore_hints_from_cache(&info).unwrap());
    }

    #[test]
    fn restore_hints_from_cache_returns_false_when_file_missing() {
        let info = sample_db_info();
        let tmp = std::env::temp_dir().join(format!(
            "pir-sdk-harmony-missing-{}-{}",
            std::process::id(),
            pir_core::merkle::sha256(b"missing")[0]
        ));
        let mut client = HarmonyClient::new("wss://h", "wss://q")
            .with_hint_cache_dir(&tmp);
        // No file yet → cold cache returns false.
        let restored = client.restore_hints_from_cache(&info).unwrap();
        assert!(!restored);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn persist_hints_to_cache_is_noop_when_nothing_loaded() {
        // Sanity: if we haven't loaded anything, persist is a no-op
        // even with a cache directory set (no panics, no stray files).
        let info = sample_db_info();
        let tmp = std::env::temp_dir().join(format!(
            "pir-sdk-harmony-noop-{}-{}",
            std::process::id(),
            pir_core::merkle::sha256(b"noop")[0]
        ));
        let client = HarmonyClient::new("wss://h", "wss://q")
            .with_hint_cache_dir(&tmp);
        client.persist_hints_to_cache(&info).unwrap();
        // No file should have been written.
        let path = client.cache_path_for(&info).unwrap();
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn cache_path_for_is_none_when_dir_unset() {
        let client = HarmonyClient::new("wss://h", "wss://q");
        assert!(client.cache_path_for(&sample_db_info()).is_none());
    }

    #[test]
    fn cache_path_for_uses_fingerprint_filename() {
        let info = sample_db_info();
        let client = HarmonyClient::new("wss://h", "wss://q")
            .with_hint_cache_dir("/tmp/dir");
        let path = client.cache_path_for(&info).unwrap();
        assert_eq!(path.parent(), Some(std::path::Path::new("/tmp/dir")));
        let filename = path.file_name().unwrap().to_string_lossy();
        assert!(filename.ends_with(".hints"));
        assert_eq!(filename.len(), 32 + ".hints".len());
    }

    // ─── Session 5: state listener + server_urls + db_id tests ─────────────

    /// Recorder impl of [`StateListener`] — records every transition in a
    /// mutex-guarded vec so assertions can check ordering across the
    /// async connect/disconnect transitions.
    struct RecordingListener {
        events: std::sync::Mutex<Vec<ConnectionState>>,
    }

    impl StateListener for RecordingListener {
        fn on_state_change(&self, state: ConnectionState) {
            self.events.lock().unwrap().push(state);
        }
    }

    /// `connect_with_transport` fires a `Connected` event on the
    /// registered listener. This is the main state-listener contract
    /// the WASM `onStateChange` surface relies on.
    #[test]
    fn state_listener_fires_on_connect_with_transport() {
        use crate::transport::mock::MockTransport;
        let listener = Arc::new(RecordingListener {
            events: std::sync::Mutex::new(Vec::new()),
        });
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_state_listener(Some(listener.clone()));
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-hint")),
            Box::new(MockTransport::new("wss://mock-query")),
        );
        let events = listener.events.lock().unwrap();
        assert_eq!(&*events, &[ConnectionState::Connected]);
    }

    /// `set_state_listener(None)` silences a previously registered
    /// listener — subsequent transitions must not reach it.
    #[test]
    fn set_state_listener_none_silences_listener() {
        use crate::transport::mock::MockTransport;
        let listener = Arc::new(RecordingListener {
            events: std::sync::Mutex::new(Vec::new()),
        });
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_state_listener(Some(listener.clone()));
        client.set_state_listener(None);
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-hint")),
            Box::new(MockTransport::new("wss://mock-query")),
        );
        assert!(listener.events.lock().unwrap().is_empty());
    }

    /// Replacing the listener must swap the sink cleanly — only the
    /// new listener sees subsequent events.
    #[test]
    fn set_state_listener_replaces_previous() {
        use crate::transport::mock::MockTransport;
        let old = Arc::new(RecordingListener {
            events: std::sync::Mutex::new(Vec::new()),
        });
        let new = Arc::new(RecordingListener {
            events: std::sync::Mutex::new(Vec::new()),
        });
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_state_listener(Some(old.clone()));
        client.set_state_listener(Some(new.clone()));
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-hint")),
            Box::new(MockTransport::new("wss://mock-query")),
        );
        assert!(old.events.lock().unwrap().is_empty());
        assert_eq!(
            &*new.events.lock().unwrap(),
            &[ConnectionState::Connected]
        );
    }

    /// Smoke test: `server_urls()` echoes the constructor arguments in
    /// `(hint, query)` order — mirrors DPF's `(server0, server1)`.
    #[test]
    fn server_urls_returns_configured_urls() {
        let client = HarmonyClient::new("wss://hint.example", "wss://query.example");
        let (h, q) = client.server_urls();
        assert_eq!(h, "wss://hint.example");
        assert_eq!(q, "wss://query.example");
    }

    /// `db_id()` initially None, becomes `Some(id)` after hints populate,
    /// and `set_db_id(same)` is an idempotent no-op.
    #[test]
    fn db_id_roundtrip_with_same_id_is_noop() {
        let info = sample_db_info();
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        assert_eq!(client.db_id(), None);
        populate_main_groups(&mut client, &info);
        assert_eq!(client.db_id(), Some(info.db_id));
        // Same id → groups stay loaded.
        client.set_db_id(info.db_id);
        assert_eq!(client.db_id(), Some(info.db_id));
        assert!(!client.index_groups.is_empty());
    }

    /// `set_db_id(different)` must invalidate ALL group maps — main
    /// AND sibling. Different db has different tree tops, so stale
    /// siblings would fail verification on next use.
    #[test]
    fn set_db_id_different_invalidates_all_groups() {
        let info = sample_db_info();
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        populate_main_groups(&mut client, &info);
        // Simulate some sibling state being loaded too.
        client.sibling_hints_loaded = Some(info.db_id);

        client.set_db_id(info.db_id + 1);
        assert_eq!(client.db_id(), None);
        assert!(client.index_groups.is_empty());
        assert!(client.chunk_groups.is_empty());
        assert!(client.index_sib_groups.is_empty());
        assert!(client.chunk_sib_groups.is_empty());
        assert!(client.sibling_hints_loaded.is_none());
    }

    /// `min_queries_remaining()` is None when no groups are loaded, and
    /// returns the *min* across all loaded group maps once populated.
    #[test]
    fn min_queries_remaining_aggregates_across_group_maps() {
        let info = sample_db_info();
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        assert_eq!(client.min_queries_remaining(), None);
        populate_main_groups(&mut client, &info);
        // All freshly-populated groups carry `max_queries` budget; the
        // min must be Some and equal the group budget.
        let min = client.min_queries_remaining();
        assert!(min.is_some());
        let max_q = client
            .index_groups
            .values()
            .next()
            .unwrap()
            .max_queries();
        assert_eq!(min, Some(max_q));
    }

    /// `estimate_hint_size_bytes` is 0 when nothing is loaded, and
    /// positive (and matches `save_hints_bytes().len()`) when loaded.
    #[test]
    fn estimate_hint_size_bytes_matches_save_hints_length() {
        let info = sample_db_info();
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        client.set_master_key([0x55u8; 16]);
        assert_eq!(client.estimate_hint_size_bytes(), 0);

        client.catalog = Some(DatabaseCatalog {
            databases: vec![info.clone()],
        });
        populate_main_groups(&mut client, &info);
        let bytes = client.save_hints_bytes().unwrap().expect("bytes");
        assert_eq!(client.estimate_hint_size_bytes(), bytes.len());
        assert!(bytes.len() > 0);
    }

    /// `cache_fingerprint` is a pure function of `(master_key,
    /// prp_backend, db_info)` — calling it twice returns identical bytes,
    /// and it matches the fingerprint embedded in the save-hints blob
    /// header (bytes 6..22 after `PSH1` magic + 2-byte version + 32-byte
    /// schema-hash).
    #[test]
    fn cache_fingerprint_is_stable_and_matches_blob_header() {
        let info = sample_db_info();
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        client.set_master_key([0xA5u8; 16]);

        let fp1 = client.cache_fingerprint(&info);
        let fp2 = client.cache_fingerprint(&info);
        assert_eq!(fp1, fp2);

        // Different master key → different fingerprint.
        let mut other = HarmonyClient::new("wss://h", "wss://q");
        other.set_master_key([0xB6u8; 16]);
        assert_ne!(fp1, other.cache_fingerprint(&info));

        // Cross-check against hint_cache::CacheKey directly — that's
        // the authoritative source for the blob-header fingerprint.
        let expected = hint_cache::CacheKey::from_db_info(
            client.master_prp_key,
            client.prp_backend,
            &info,
        )
        .fingerprint();
        assert_eq!(fp1, expected);
    }

    // ─── Tracing smoke test ──────────────────────────────────────────────
    //
    // Companion to the `tracing_instrument_emits_backend_field_for_dpf`
    // test in `dpf.rs`. Installs a scoped `tracing_subscriber::fmt`
    // subscriber backed by an in-memory buffer, drives an instrumented
    // method, and asserts the Harmony span emitted `backend="harmony"`.
    // Catches accidental `#[tracing::instrument]` removal or a
    // `backend` field rename at test time instead of only in production
    // log searches.

    #[derive(Clone)]
    struct BufferWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufferWriter {
        type Writer = BufferWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn tracing_instrument_emits_backend_field_for_harmony() {
        use crate::transport::mock::MockTransport;
        use tracing_subscriber::fmt;

        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = fmt::Subscriber::builder()
            .with_span_events(fmt::format::FmtSpan::CLOSE)
            .with_writer(BufferWriter(buf.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut client =
                HarmonyClient::new("wss://mock-hint", "wss://mock-query");
            client.connect_with_transport(
                Box::new(MockTransport::new("wss://mock-hint")),
                Box::new(MockTransport::new("wss://mock-query")),
            );
        });

        let captured = String::from_utf8(buf.lock().unwrap().clone())
            .expect("tracing writer produced valid UTF-8");
        assert!(
            captured.contains("connect_with_transport"),
            "expected span name in captured output, got: {}",
            captured
        );
        assert!(
            captured.contains("backend=\"harmony\""),
            "expected backend=\"harmony\" field in captured output, got: {}",
            captured
        );
    }

    // ─── Metrics recorder tests ─────────────────────────────────────────────

    /// Installing a recorder before `connect_with_transport` fires one
    /// `on_connect` per transport (hint + query) and propagates the
    /// recorder to both transports.
    #[test]
    fn metrics_recorder_fires_on_connect_via_inject() {
        use crate::transport::mock::MockTransport;
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_metrics_recorder(Some(recorder.clone()));

        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-hint")),
            Box::new(MockTransport::new("wss://mock-query")),
        );

        let snap = recorder.snapshot();
        assert_eq!(
            snap.connects, 2,
            "expected one on_connect per transport (2 total)"
        );
        assert_eq!(snap.disconnects, 0);
    }

    /// `disconnect` fires a single `on_disconnect`.
    #[tokio::test]
    async fn metrics_recorder_fires_on_disconnect() {
        use crate::transport::mock::MockTransport;
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_metrics_recorder(Some(recorder.clone()));

        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-hint")),
            Box::new(MockTransport::new("wss://mock-query")),
        );
        client.disconnect().await.unwrap();

        let snap = recorder.snapshot();
        assert_eq!(snap.connects, 2);
        assert_eq!(snap.disconnects, 1);
    }

    /// Installing the recorder after `connect_with_transport` still
    /// propagates the handle to both transports. Proved by driving a
    /// `send` through each and reading back the byte counts.
    #[tokio::test]
    async fn metrics_recorder_propagates_to_transports_after_connect() {
        use crate::transport::mock::MockTransport;
        use crate::transport::PirTransport;
        use pir_sdk::AtomicMetrics;

        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-hint")),
            Box::new(MockTransport::new("wss://mock-query")),
        );

        let recorder = Arc::new(AtomicMetrics::new());
        client.set_metrics_recorder(Some(recorder.clone()));

        client.hint_conn.as_mut().unwrap().send(vec![1, 2, 3]).await.unwrap();
        client.query_conn.as_mut().unwrap().send(vec![4, 5]).await.unwrap();

        let snap = recorder.snapshot();
        assert_eq!(snap.bytes_sent, 5);
        assert_eq!(snap.frames_sent, 2);
    }

    /// `set_metrics_recorder(None)` silences both client-level and
    /// transport-level callbacks.
    #[tokio::test]
    async fn metrics_recorder_uninstall_silences_everything() {
        use crate::transport::mock::MockTransport;
        use crate::transport::PirTransport;
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_metrics_recorder(Some(recorder.clone()));
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-hint")),
            Box::new(MockTransport::new("wss://mock-query")),
        );

        client.set_metrics_recorder(None);
        client.hint_conn.as_mut().unwrap().send(vec![9; 42]).await.unwrap();
        client.disconnect().await.unwrap();

        let snap = recorder.snapshot();
        assert_eq!(snap.connects, 2);
        assert_eq!(snap.disconnects, 0);
        assert_eq!(snap.bytes_sent, 0);
        assert_eq!(snap.frames_sent, 0);
    }

    /// `fire_query_start` returns `Some(Instant)` only when a recorder
    /// is installed — keeps the no-recorder path at zero overhead.
    #[test]
    fn fire_query_start_returns_instant_only_when_recorder_installed() {
        use pir_sdk::AtomicMetrics;

        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        assert!(client.fire_query_start(0, 10).is_none());

        let recorder = Arc::new(AtomicMetrics::new());
        client.set_metrics_recorder(Some(recorder));
        assert!(client.fire_query_start(0, 10).is_some());
    }

    /// `fire_query_end` records non-zero duration when threading the
    /// captured `Instant`. We sleep a few ms to make the measured
    /// duration comfortably distinguishable from clock jitter.
    #[test]
    fn fire_query_end_records_non_zero_duration_with_recorder() {
        use pir_sdk::AtomicMetrics;
        use std::thread::sleep;
        use std::time::Duration as StdDuration;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_metrics_recorder(Some(recorder.clone()));

        let started = client.fire_query_start(0, 10);
        assert!(started.is_some());
        sleep(StdDuration::from_millis(5));
        client.fire_query_end(0, 10, true, started);

        let snap = recorder.snapshot();
        assert_eq!(snap.queries_started, 1);
        assert_eq!(snap.queries_completed, 1);
        assert!(
            snap.min_query_latency_micros >= 1_000,
            "expected min_query_latency_micros >= 1000, got {}",
            snap.min_query_latency_micros
        );
    }

    /// `fire_query_end` with `started_at = None` records `Duration::ZERO`
    /// — best-effort observation per [`PirMetrics::on_query_end`].
    #[test]
    fn fire_query_end_with_none_start_records_zero_duration() {
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");

        let started = client.fire_query_start(0, 10); // None (no recorder yet)
        client.set_metrics_recorder(Some(recorder.clone()));
        client.fire_query_end(0, 10, true, started);

        let snap = recorder.snapshot();
        assert_eq!(snap.queries_completed, 1);
        assert_eq!(snap.min_query_latency_micros, 0);
        assert_eq!(snap.max_query_latency_micros, 0);
    }
}
