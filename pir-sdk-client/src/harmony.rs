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
    fetch_tree_tops, verify_bucket_merkle_batch_generic,
    verify_bucket_merkle_batch_parallel, BucketMerkleItem,
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
    INDEX_CUCKOO_NUM_HASHES, INDEX_PARAMS, INDEX_SLOT_SIZE, INDEX_SLOTS_PER_BIN, NUM_HASHES, TAG_SIZE,
};
use pir_sdk::{
    compute_sync_plan, merge_delta_batch, BucketRef, ConnectionState, DatabaseCatalog,
    DatabaseInfo, DatabaseKind, Instant, LeakageRecorder, PirBackendType, PirClient, PirError,
    PirMetrics, PirResult, QueryResult, RoundKind, RoundProfile, ScriptHash, StateListener,
    SyncPlan, SyncProgress, SyncResult, SyncStep, UtxoEntry,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

// ─── Wire protocol constants ────────────────────────────────────────────────

const REQ_HARMONY_GET_INFO: u8 = 0x40;
const RESP_HARMONY_INFO: u8 = 0x40;

const REQ_HARMONY_HINTS: u8 = 0x41;
const RESP_HARMONY_HINTS: u8 = 0x41;

/// V2: server generates the PRP key. Request variant.
const REQ_HARMONY_HINTS_V2: u8 = 0x44;
/// V2: key preamble response variant.
const RESP_HARMONY_HINTS_KEY: u8 = 0x44;

/// V2 half-stream hint request — pairs with `REQ_HARMONY_HINTS_V2` but
/// splits the response into INDEX-only (side=0) or CHUNK-only (side=1)
/// halves. Two parallel requests carrying the same 16-byte session
/// token are matched server-side to the same pool entry, so both halves
/// expose the same PRP key. See
/// [`HarmonyClient::ensure_groups_ready_v2_half`] for the client-side
/// parallel fetch path.
const REQ_HARMONY_HINTS_V2_HALF: u8 = 0x46;

const REQ_HARMONY_BATCH_QUERY: u8 = 0x43;
const RESP_HARMONY_BATCH_QUERY: u8 = 0x43;

// `REQ_GET_DB_CATALOG` / `RESP_DB_CATALOG` / `RESP_ERROR` come from
// `crate::protocol` — shared with `DpfClient` and `OnionClient`.

/// PRP backends (mirrors `harmonypir_wasm::PRP_*`).
pub const PRP_HMR12: u8 = 0;
pub const PRP_FASTPRP: u8 = 1;
// PRP_ALF (= 2) was removed 2026-05-12: ALF panicked on domain<65536
// (sibling Merkle tables hit this), causing pir-vpsbg crash loops.

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

/// Per-group role for a single CHUNK PIR round.
///
/// `Real(chunk_id)` — the group has a real chunk to retrieve; the
/// caller computes the cuckoo target bin and dispatches via
/// [`harmonypir_wasm::HarmonyGroup::build_request`].
///
/// `Dummy` — no real chunk is assigned to this group; caller falls
/// back to [`harmonypir_wasm::HarmonyGroup::build_synthetic_dummy`],
/// whose T-1-padded shape is byte-shape-identical to a real request
/// per the existing "HarmonyPIR Per-Group Request-Count Symmetry"
/// invariant. The two branches of `run_chunk_round` therefore emit
/// indistinguishable per-group payloads on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkGroupRole {
    Real(u32),
    Dummy,
}

/// Classify each of the `k_chunk` groups for one HarmonyPIR CHUNK
/// round.
///
/// Pure function: no I/O, no allocation outside the result `Vec`, no
/// RNG. The structural witness for **CHUNK Round-Presence Symmetry
/// P1** is `result.len() == k_chunk` regardless of
/// `real_queries.len()`. The structural witness for **P2** is
/// "every entry is `Dummy` when `real_queries.is_empty()`", which
/// makes the all-dummy round byte-shape-identical to any real round
/// (modulo fixed-shape `build_request` vs `build_synthetic_dummy`,
/// already established by the per-group request-count symmetry).
///
/// **Semantics on duplicate group_ids** — when `real_queries`
/// contains two entries with the same `group_id`, the *later* entry
/// wins. This matches the original `HashMap::collect` semantics that
/// `run_chunk_round` used pre-refactor; CHUNK PBC planning never
/// produces such duplicates within a single round, but preserving
/// the tie-break rule keeps the refactor observably equivalent.
///
/// **Out-of-range group_ids** — entries with `group_id >= k_chunk`
/// are silently ignored (the original code's `for g in 0..k_chunk`
/// loop never queried them). Same observable behaviour.
pub(crate) fn classify_chunk_groups(
    real_queries: &[(u32, u8)],
    k_chunk: u8,
) -> Vec<ChunkGroupRole> {
    let mut roles = vec![ChunkGroupRole::Dummy; k_chunk as usize];
    for &(cid, group) in real_queries {
        if (group as usize) < (k_chunk as usize) {
            // Last-wins matches HashMap::collect (pre-refactor behaviour).
            roles[group as usize] = ChunkGroupRole::Real(cid);
        }
    }
    roles
}

/// INDEX-side analog of [`ChunkGroupRole`], used by the Option-B
/// `index_max_items_per_group_per_level` closure. `Real(target_bin)`
/// marks a group as carrying a real INDEX query for some scripthash
/// in this round; `Dummy` marks a group as needing
/// `build_synthetic_dummy()`. The structural witness for the closure
/// is `result.len() == k_index` regardless of how many scripthashes
/// the PBC plan placed in this round — every wire INDEX request
/// covers all K groups, so the per-group payload count is a function
/// of `k_index` alone, not of the batch's collision pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexGroupRole {
    Real(u32),
    Dummy,
}

/// Classify each of the `k_index` groups for one batched HarmonyPIR
/// INDEX round (one cuckoo position `h` × one PBC round). Mirrors
/// [`classify_chunk_groups`] in shape: pure, no I/O, no RNG. Last
/// duplicate wins so the structural invariant is observably equivalent
/// to the pre-Option-B single-real-group path when the placement list
/// has exactly one entry.
pub(crate) fn classify_index_groups(
    placements: &[(u8, u32)],
    k_index: u8,
) -> Vec<IndexGroupRole> {
    let mut roles = vec![IndexGroupRole::Dummy; k_index as usize];
    for &(group, target_bin) in placements {
        if (group as usize) < (k_index as usize) {
            roles[group as usize] = IndexGroupRole::Real(target_bin);
        }
    }
    roles
}

/// Build `BucketMerkleItem`s for one query from its internal trace —
/// emits one item per probed INDEX cuckoo bin, with the query's CHUNK
/// bins attached to the first probed INDEX item (`bi == 0`). The layout
/// preserves the 🔒 Merkle INDEX Item-Count Symmetry invariant: every
/// query contributes exactly `INDEX_CUCKOO_NUM_HASHES` items regardless
/// of found / not-found / whale.
///
/// M=16 padding REMOVED (PLAN_MERKLE_CODING.md Phase 2): `trace.chunk_bins`
/// now holds exactly the query's REAL chunk count — `N` for a found query,
/// `0` for not-found / whale. The chunk-bin attachment stays unconditional
/// (all on `bi == 0`); a not-found query simply attaches zero chunk items,
/// and the per-bucket Merkle still issues >=1 all-dummy CHUNK-Merkle pass.
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
            // Attach all chunk Merkle items to the first INDEX item
            // (`bi == 0`). A found query attaches its real chunks; a
            // not-found / whale query attaches none.
            if bi == 0 {
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
/// precomputed cache). Select at runtime via [`set_prp_backend`] with
/// one of [`PRP_HMR12`] or [`PRP_FASTPRP`]. (PRP_ALF was removed
/// 2026-05-12 — see harmony.rs:81 note.)
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
    /// Secondary hint-server WebSocket, used to split parallel sibling
    /// hint downloads (INDEX-tree levels on primary, CHUNK-tree levels
    /// on secondary) across two sockets. Same rationale as
    /// [`query_conn_secondary`] — the bandwidth-delay-product cap on
    /// one TCP stream is the bottleneck for the ~26 MB of sibling
    /// hints, so two streams cut wall time substantially.
    ///
    /// `None` means single-socket fallback (identical behaviour to
    /// pre-pool code). Set when `HARMONY_HINT_POOL_SIZE` env var is
    /// 2 (default) or higher.
    hint_conn_secondary: Option<Box<dyn PirTransport>>,
    query_conn: Option<Box<dyn PirTransport>>,
    /// Secondary query-server WebSocket, used to split parallel rounds
    /// (CHUNK h=0/h=1 pair, INDEX/CHUNK Merkle sub-trees) across two
    /// sockets so we can saturate the path's bandwidth-delay product
    /// instead of being capped by a single-TCP-stream limit. `None`
    /// means single-socket fallback (identical behaviour to pre-pool
    /// code).
    ///
    /// Opened in parallel with [`query_conn`] at [`connect`] time when
    /// the `HARMONY_QUERY_POOL_SIZE` env var is set to 2 (default) or
    /// higher. Pool size 1 leaves this `None` and all rounds run on
    /// `query_conn` alone.
    ///
    /// Privacy invariants are preserved per socket — the wire shape of
    /// each round is unchanged. The server can't distinguish a
    /// two-socket client from two single-socket clients running back
    /// to back: each socket is its own connection and gets its own
    /// stateless K-padded batch queries.
    query_conn_secondary: Option<Box<dyn PirTransport>>,
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
    /// Optional leakage recorder. When installed, every transport-level
    /// roundtrip (hint refresh, INDEX query, CHUNK query, Merkle
    /// tree-tops, Merkle sibling pass) emits a structured
    /// [`RoundProfile`] with the wire-observable shape. `server_id` is
    /// 0 for the query server and 1 for the hint server. Independent
    /// of `metrics_recorder` — install neither, either, or both.
    leakage_recorder: Option<Arc<dyn LeakageRecorder>>,
    /// If true, use V2 hint protocol: server generates the PRP key.
    /// Default: true for new clients. Set to false for V1 fallback
    /// (client generates key, sends in request).
    use_v2_protocol: bool,
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
            hint_conn_secondary: None,
            query_conn: None,
            query_conn_secondary: None,
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
            leakage_recorder: None,
            use_v2_protocol: true,
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
        if let Some(ref mut c) = self.hint_conn_secondary {
            c.set_metrics_recorder(recorder.clone(), "harmony");
        }
        if let Some(ref mut c) = self.query_conn {
            c.set_metrics_recorder(recorder.clone(), "harmony");
        }
        if let Some(ref mut c) = self.query_conn_secondary {
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

    /// Install (or replace) a leakage recorder. Independent of
    /// [`set_metrics_recorder`](Self::set_metrics_recorder).
    /// `server_id = 0` is the query server, `1` is the hint server.
    /// Pass `None` to uninstall.
    pub fn set_leakage_recorder(&mut self, recorder: Option<Arc<dyn LeakageRecorder>>) {
        self.leakage_recorder = recorder;
    }

    /// Emit a [`RoundProfile`] to the installed leakage recorder, if any.
    fn record_round(&self, round: RoundProfile) {
        if let Some(rec) = &self.leakage_recorder {
            rec.record_round("harmony", round);
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

    /// Send REQ_ATTEST to one of the connected servers (`server_index`:
    /// 0 = hint server, 1 = query server) and return the verification
    /// result. See [`super::DpfClient::attest`] for the full semantics.
    pub async fn attest(
        &mut self,
        server_index: u8,
        nonce: [u8; 32],
    ) -> PirResult<crate::attest::AttestVerification> {
        let conn = match server_index {
            0 => self.hint_conn.as_mut().ok_or_else(|| {
                PirError::Protocol("attest: hint server not connected".into())
            })?,
            1 => self.query_conn.as_mut().ok_or_else(|| {
                PirError::Protocol("attest: query server not connected".into())
            })?,
            _ => {
                return Err(PirError::Protocol(format!(
                    "attest: server_index must be 0 (hint) or 1 (query), got {}",
                    server_index
                )))
            }
        };
        crate::attest::attest(conn.as_mut(), nonce).await
    }

    /// Send REQ_ANNOUNCE to the chosen server (0 = hint, 1 = query).
    /// See [`super::DpfClient::announce`] for full semantics.
    pub async fn announce(
        &mut self,
        server_index: u8,
    ) -> PirResult<crate::announce::AnnounceVerification> {
        let conn = match server_index {
            0 => self.hint_conn.as_mut().ok_or_else(|| {
                PirError::Protocol("announce: hint server not connected".into())
            })?,
            1 => self.query_conn.as_mut().ok_or_else(|| {
                PirError::Protocol("announce: query server not connected".into())
            })?,
            _ => {
                return Err(PirError::Protocol(format!(
                    "announce: server_index must be 0 (hint) or 1 (query), got {}",
                    server_index
                )))
            }
        };
        crate::announce::announce(conn.as_mut()).await
    }

    /// Replace both server connections with secure-channel-wrapped
    /// versions. See [`super::DpfClient::upgrade_to_secure_channel`]
    /// for the full semantics. Argument order matches the
    /// `(hint_server, query_server)` URL order.
    pub async fn upgrade_to_secure_channel(
        &mut self,
        hint_server_static_pub: [u8; 32],
        query_server_static_pub: [u8; 32],
    ) -> PirResult<()> {
        let mut eph_h = [0u8; 32];
        let mut nonce_h = [0u8; 32];
        let mut eph_q = [0u8; 32];
        let mut nonce_q = [0u8; 32];
        getrandom::getrandom(&mut eph_h)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut nonce_h)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut eph_q)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;
        getrandom::getrandom(&mut nonce_q)
            .map_err(|e| PirError::Protocol(format!("getrandom: {}", e)))?;

        self.upgrade_to_secure_channel_with_seeds(
            hint_server_static_pub,
            eph_h,
            nonce_h,
            query_server_static_pub,
            eph_q,
            nonce_q,
        )
        .await
    }

    /// Binding-friendly overload: thread the same `eph_seed_*` you
    /// passed to [`crate::attest::attest_with_eph_binding`] for the
    /// corresponding server so the attestation covers this exact
    /// handshake. See
    /// [`super::DpfClient::upgrade_to_secure_channel_with_seeds`] for
    /// rationale. `hs_nonce_*` are HKDF salts (CSPRNG-fresh per call).
    pub async fn upgrade_to_secure_channel_with_seeds(
        &mut self,
        hint_server_static_pub: [u8; 32],
        eph_seed_hint: [u8; 32],
        hs_nonce_hint: [u8; 32],
        query_server_static_pub: [u8; 32],
        eph_seed_query: [u8; 32],
        hs_nonce_query: [u8; 32],
    ) -> PirResult<()> {
        let raw_hint = self
            .hint_conn
            .take()
            .ok_or_else(|| PirError::Protocol("upgrade: hint server not connected".into()))?;
        let raw_query = match self.query_conn.take() {
            Some(c) => c,
            None => {
                self.hint_conn = Some(raw_hint);
                return Err(PirError::Protocol(
                    "upgrade: query server not connected".into(),
                ));
            }
        };

        let wrapped_hint = crate::channel::establish(
            raw_hint,
            hint_server_static_pub,
            eph_seed_hint,
            hs_nonce_hint,
        )
        .await?;
        let wrapped_query = crate::channel::establish(
            raw_query,
            query_server_static_pub,
            eph_seed_query,
            hs_nonce_query,
        )
        .await?;

        self.hint_conn = Some(Box::new(wrapped_hint));
        self.query_conn = Some(Box::new(wrapped_query));

        // Drop the secondary query socket on secure-channel upgrade —
        // the channel handshake is single-socket today, and parallel
        // round-fanout would have to re-handshake the secondary too.
        // Single-socket fallback is correct (just slower) under
        // secure-channel mode; ship parallel-pool channel as a
        // follow-up if real users hit this combination.
        if let Some(ref mut c) = self.query_conn_secondary.take() {
            let _ = c.close().await;
        }
        Ok(())
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

    /// Set the PRP backend (`PRP_HMR12` or `PRP_FASTPRP`).
    pub fn set_prp_backend(&mut self, backend: u8) {
        if backend != self.prp_backend {
            self.prp_backend = backend;
            self.invalidate_groups();
        }
    }

    /// Enable or disable V2 hint protocol (server-generated PRP key).
    ///
    /// Default: `true` for new clients. Set to `false` to fall back to V1
    /// (client sends PRP key in hint request — needed for older servers).
    pub fn set_use_v2_protocol(&mut self, v2: bool) {
        if v2 != self.use_v2_protocol {
            self.use_v2_protocol = v2;
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
        let request_bytes = request.len() as u64;
        let response = conn.roundtrip(&request).await?;
        // `roundtrip` strips the 4-byte length prefix; add it back so the
        // recorded byte count matches what a wire-level observer sees.
        self.record_round(RoundProfile {
            kind: RoundKind::Info,
            server_id: 1,
            db_id: None,
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: Vec::new(),
        });

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
        let request_bytes = request.len() as u64;
        let response = conn.roundtrip(&request).await?;
        self.record_round(RoundProfile {
            kind: RoundKind::Info,
            server_id: 1,
            db_id: None,
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: Vec::new(),
        });

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

        // Dispatch matrix for main hint fetch (cold cache only — the
        // warm-cache fast path returned above):
        //
        //   pool=2 AND v2:           → V2-half (parallel; this commit)
        //   pool=2 AND v1-opt-in:    → V1 parallel (slow; bench/fallback only)
        //   pool=1 AND v2:           → V2 full single-stream
        //   pool=1 AND !v2:          → V1 single-stream serial
        //
        // V2 (full or half) uses the server's pre-computed hint pool —
        // zero server CPU per request, just stream bytes. V1 triggers
        // on-the-fly `compute_hints_for_group` server-side (several
        // seconds of CPU even on the pool-less path), so it's never
        // the default for cold-cache fetch.
        //
        // V2-half is preferred over V2 full when a secondary hint
        // socket is available because it splits the ~20 MB stream
        // across two TCP connections — each connection gets its own
        // bandwidth-delay-product budget, halving wall time on far
        // (high-RTT) clients. Falls back to V2 full on any error
        // (older servers, network hiccups, etc.).
        let want_v1_parallel =
            matches!(std::env::var("HARMONY_USE_V1_PARALLEL").as_deref(), Ok("1"));
        if want_v1_parallel && self.hint_conn_secondary.is_some() {
            return self.ensure_groups_ready_v1_parallel(db_info, progress).await;
        }
        if self.use_v2_protocol && self.hint_conn_secondary.is_some() {
            match self
                .ensure_groups_ready_v2_half(db_info, progress)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    log::warn!(
                        "[PIR-AUDIT] V2-half failed ({}); falling back to V2 full",
                        e
                    );
                    // Continue to V2 full below.
                }
            }
        }
        if self.use_v2_protocol {
            return self.ensure_groups_ready_v2(db_info, progress).await;
        }
        if self.hint_conn_secondary.is_some() {
            return self.ensure_groups_ready_v1_parallel(db_info, progress).await;
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

    /// V2 hint fetch: single round-trip for both INDEX and CHUNK levels.
    ///
    /// Sends `REQ_HARMONY_HINTS_V2`, receives the key preamble (server-
    /// generated PRP key + backend), creates HarmonyGroup instances, then
    /// receives all per-group frames from the pool.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", v2 = true, db_id = db_info.db_id))]
    async fn ensure_groups_ready_v2(
        &mut self,
        db_info: &DatabaseInfo,
        progress: Option<&dyn HintProgress>,
    ) -> PirResult<()> {
        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;
        let total = (k_index + k_chunk) as u32;
        let db_id = db_info.db_id;

        // ── 1. Send V2 request ──────────────────────────────────────────
        let mut payload = Vec::with_capacity(4);
        payload.push(0xFFu8); // level_sentinel: all levels
        payload.push(0x00u8); // reserved
        if db_id != 0 {
            payload.push(db_id);
        }
        // Trailing db_id byte
        let request = crate::protocol::encode_request(REQ_HARMONY_HINTS_V2, &payload);
        let request_bytes = request.len() as u64;

        let conn = self.hint_conn.as_mut().ok_or(PirError::NotConnected)?;
        conn.send(request).await?;

        // ── 2. Receive key preamble ─────────────────────────────────────
        let preamble = conn.recv().await?;
        if preamble.len() < 5 {
            return Err(PirError::Protocol("truncated V2 key preamble".into()));
        }
        let body = &preamble[4..]; // strip outer length prefix
        if body.is_empty() || body[0] != RESP_HARMONY_HINTS_KEY {
            if !body.is_empty() && body[0] == RESP_ERROR {
                let reason = String::from_utf8_lossy(&body[1..]).to_string();
                return Err(PirError::ServerError(reason));
            }
            return Err(PirError::Protocol(format!(
                "expected V2 key preamble (0x{:02x}), got 0x{:02x}",
                RESP_HARMONY_HINTS_KEY,
                body.first().copied().unwrap_or(0),
            )));
        }
        // Layout: [RESP_HARMONY_HINTS_KEY=0x44][1B prp_backend][1B level_sentinel=0xFF][1B total_groups][16B prp_key]
        if body.len() < 20 {
            return Err(PirError::Protocol("V2 key preamble truncated".into()));
        }
        let prp_backend = body[1];
        // body[2] = level_sentinel, body[3] = total_groups (informational)
        let mut prp_key = [0u8; 16];
        prp_key.copy_from_slice(&body[4..20]);

        self.prp_backend = prp_backend;
        self.master_prp_key = prp_key;

        // ── 3. Create HarmonyGroup instances with the server-assigned key ──
        let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;
        let chunk_w = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE;

        for g in 0..k_index {
            let group = HarmonyGroup::new_with_backend(
                db_info.index_bins,
                index_w as u32,
                0,
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

        // ── 4. Receive per-group INDEX frames ───────────────────────────
        let mut done: u32 = 0;
        let mut total_response_bytes: u64 = 0;
        for _g in 0..k_index {
            let msg = conn.recv().await?;
            total_response_bytes = total_response_bytes.saturating_add(msg.len() as u64);
            if msg.len() < 5 {
                return Err(PirError::Protocol("truncated V2 hint frame".into()));
            }
            let body = &msg[4..];
            if body.is_empty() {
                return Err(PirError::Protocol("empty V2 hint frame body".into()));
            }
            if body[0] == RESP_ERROR {
                let reason = String::from_utf8_lossy(&body[1..]).to_string();
                return Err(PirError::ServerError(reason));
            }
            if body[0] != RESP_HARMONY_HINTS {
                return Err(PirError::Protocol(format!(
                    "expected RESP_HARMONY_HINTS, got 0x{:02x}",
                    body[0]
                )));
            }
            if body.len() < 14 {
                return Err(PirError::Protocol("V2 hint frame header truncated".into()));
            }
            let group_id = body[1];
            let hints_data = &body[14..];

            let group = self.index_groups.get_mut(&group_id).ok_or_else(|| {
                PirError::Protocol(format!("V2: unexpected INDEX group {}", group_id))
            })?;
            group
                .load_hints(hints_data)
                .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;

            done += 1;
            if let Some(p) = progress {
                p.on_group_complete(done, total, "index");
            }
        }

        // ── 5. Receive per-group CHUNK frames ───────────────────────────
        for _g in 0..k_chunk {
            let msg = conn.recv().await?;
            total_response_bytes = total_response_bytes.saturating_add(msg.len() as u64);
            if msg.len() < 5 {
                return Err(PirError::Protocol("truncated V2 hint frame".into()));
            }
            let body = &msg[4..];
            if body.is_empty() {
                return Err(PirError::Protocol("empty V2 hint frame body".into()));
            }
            if body[0] == RESP_ERROR {
                let reason = String::from_utf8_lossy(&body[1..]).to_string();
                return Err(PirError::ServerError(reason));
            }
            if body[0] != RESP_HARMONY_HINTS {
                return Err(PirError::Protocol(format!(
                    "expected RESP_HARMONY_HINTS, got 0x{:02x}",
                    body[0]
                )));
            }
            if body.len() < 14 {
                return Err(PirError::Protocol("V2 hint frame header truncated".into()));
            }
            let group_id = body[1];
            let hints_data = &body[14..];

            // CHUNK groups are stored under the local offset (0..79),
            // matching the wire group_id byte.
            let group = self.chunk_groups.get_mut(&group_id).ok_or_else(|| {
                PirError::Protocol(format!("V2: unexpected CHUNK group {}", group_id))
            })?;
            group
                .load_hints(hints_data)
                .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;

            done += 1;
            if let Some(p) = progress {
                p.on_group_complete(done, total, "chunk");
            }
        }

        // ── 6. Receive terminal sentinel ────────────────────────────────
        let _terminal = conn.recv().await?;

        self.loaded_db_id = Some(db_info.db_id);

        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   V2 main hint stream: req {}B  resp_total {}B  (k_index={}, k_chunk={})",
                request_bytes, total_response_bytes, k_index, k_chunk,
            );
        }

        // Record the round.
        self.record_round(RoundProfile {
            kind: RoundKind::HarmonyHintRefresh,
            server_id: 1,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: total_response_bytes,
            items: vec![1u32; total as usize],
        });

        // Persist to cache.
        if let Err(e) = self.persist_hints_to_cache(db_info) {
            log::warn!(
                "[PIR-AUDIT] HarmonyPIR V2: failed to persist main hints to cache: {}",
                e
            );
        }

        Ok(())
    }

    /// V2 half-stream parallel main hint fetch.
    ///
    /// Splits the V2 main hint response across two TCP/WebSocket sockets:
    /// INDEX-half (side=0) goes to the primary hint socket, CHUNK-half
    /// (side=1) to the secondary. Both halves share a 16-byte session
    /// token that the server uses to match them to the same pool entry,
    /// so both halves carry the same PRP key in their preambles.
    ///
    /// The wire shape on each socket is identical to the corresponding
    /// portion of a full V2 response (key preamble + per-group frames +
    /// sentinel), so the per-half receive loop reuses the same parsing
    /// code as `ensure_groups_ready_v2`. Only the dispatch
    /// (parallel send + matched-key check after) differs.
    ///
    /// Returns `Err` on any wire / protocol error so the caller (the
    /// `ensure_groups_ready` dispatch matrix) can fall back to V2 full
    /// single-stream — older servers that don't recognize
    /// `REQ_HARMONY_HINTS_V2_HALF` will return a `RESP_ERROR` and this
    /// function bails, letting the fallback proceed.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", v2_half = true, db_id = db_info.db_id))]
    async fn ensure_groups_ready_v2_half(
        &mut self,
        db_info: &DatabaseInfo,
        progress: Option<&dyn HintProgress>,
    ) -> PirResult<()> {
        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;
        let total = (k_index + k_chunk) as u32;
        let db_id = db_info.db_id;

        // Generate a 16-byte random session token. Both halves carry
        // the same token; server matches them to the same pool entry.
        let mut session_token = [0u8; 16];
        getrandom::getrandom(&mut session_token)
            .map_err(|e| PirError::Protocol(format!("session_token getrandom: {}", e)))?;

        // Build the two half requests up front.
        let make_request = |side: u8| -> Vec<u8> {
            let mut payload = Vec::with_capacity(16 + 1 + 1);
            payload.extend_from_slice(&session_token);
            payload.push(side);
            if db_id != 0 {
                payload.push(db_id);
            }
            crate::protocol::encode_request(REQ_HARMONY_HINTS_V2_HALF, &payload)
        };
        let request_index = make_request(0);
        let request_chunk = make_request(1);
        let request_index_bytes = request_index.len() as u64;
        let request_chunk_bytes = request_chunk.len() as u64;

        // Take both hint sockets out of `self` so the parallel futures
        // can each hold one mutably. Restored after the join.
        let mut hint_primary = self.hint_conn.take().ok_or(PirError::NotConnected)?;
        let mut hint_secondary = self
            .hint_conn_secondary
            .take()
            .expect("only called when hint_conn_secondary is_some");

        let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;
        let chunk_w = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE;

        // Per-half receive+build+load loop.
        //
        // The receive logic is identical to the V2-full path
        // (preamble → K frames → sentinel) but as soon as the preamble
        // arrives — i.e. as soon as the key is known — the loop builds
        // all this half's `HarmonyGroup` instances and then loads
        // hints into them per-frame as they stream in. This INTERLEAVES
        // the per-group PRP setup (~10–20 ms × K, single-thread CPU)
        // with the network wait time, instead of stacking them serial
        // after the join. Matches V2-full's wire-vs-CPU interleaving.
        //
        // Returns `(prp_backend, prp_key, built_groups, total_bytes)`.
        // The shared-key check on the call site runs against the
        // returned `prp_key`s; the built groups are then moved into
        // `self.{index,chunk}_groups`.
        #[allow(clippy::too_many_arguments)]
        async fn drain_half_build(
            conn: &mut Box<dyn PirTransport>,
            num_groups: u8,
            label: &str,
            // Group construction params (same for every group at this
            // level — only the per-group offset varies).
            bins: u32,
            slot_size: u32,
            base_offset: usize, // 0 for INDEX, k_index for CHUNK
        ) -> PirResult<(u8, [u8; 16], HashMap<u8, HarmonyGroup>, u64)> {
            // 1. Receive key preamble.
            let preamble = conn.recv().await?;
            let mut total_resp: u64 = preamble.len() as u64;
            if preamble.len() < 5 {
                return Err(PirError::Protocol(format!(
                    "{}: truncated V2-half key preamble",
                    label
                )));
            }
            let body = &preamble[4..];
            if body.is_empty() || body[0] != RESP_HARMONY_HINTS_KEY {
                if !body.is_empty() && body[0] == RESP_ERROR {
                    let reason = String::from_utf8_lossy(&body[1..]).to_string();
                    return Err(PirError::ServerError(reason));
                }
                return Err(PirError::Protocol(format!(
                    "{}: expected V2-half key preamble (0x{:02x}), got 0x{:02x}",
                    label,
                    RESP_HARMONY_HINTS_KEY,
                    body.first().copied().unwrap_or(0),
                )));
            }
            // Layout: [RESP_HARMONY_HINTS_KEY][prp_backend][level_sentinel=0xFF][total_groups][16B prp_key]
            if body.len() < 20 {
                return Err(PirError::Protocol(format!(
                    "{}: V2-half key preamble truncated ({} bytes)",
                    label,
                    body.len()
                )));
            }
            let prp_backend = body[1];
            let mut prp_key = [0u8; 16];
            prp_key.copy_from_slice(&body[4..20]);

            // 2. Build all `num_groups` HarmonyGroup instances using
            //    the just-received key. This is the CPU-heavy part —
            //    overlapped with the upcoming `recv()` waits.
            let mut groups: HashMap<u8, HarmonyGroup> =
                HashMap::with_capacity(num_groups as usize);
            for g in 0..num_groups {
                let group = HarmonyGroup::new_with_backend(
                    bins,
                    slot_size,
                    0,
                    &prp_key,
                    (base_offset + g as usize) as u32,
                    prp_backend,
                )
                .map_err(|e| {
                    PirError::BackendState(format!(
                        "{}: HarmonyGroup init: {:?}",
                        label, e
                    ))
                })?;
                groups.insert(g, group);
            }

            // 3. Receive N per-group frames and load hints in-place.
            for _ in 0..num_groups {
                let msg = conn.recv().await?;
                total_resp = total_resp.saturating_add(msg.len() as u64);
                if msg.len() < 5 {
                    return Err(PirError::Protocol(format!(
                        "{}: truncated V2-half hint frame",
                        label
                    )));
                }
                let body = &msg[4..];
                if body.is_empty() {
                    return Err(PirError::Protocol(format!(
                        "{}: empty V2-half hint frame body",
                        label
                    )));
                }
                if body[0] == RESP_ERROR {
                    let reason = String::from_utf8_lossy(&body[1..]).to_string();
                    return Err(PirError::ServerError(reason));
                }
                if body[0] != RESP_HARMONY_HINTS {
                    return Err(PirError::Protocol(format!(
                        "{}: expected RESP_HARMONY_HINTS, got 0x{:02x}",
                        label, body[0]
                    )));
                }
                if body.len() < 14 {
                    return Err(PirError::Protocol(format!(
                        "{}: V2-half hint frame header truncated",
                        label
                    )));
                }
                let group_id = body[1];
                // bytes 2..14 = (n, t, m) metadata — unused
                let hints_data = &body[14..];
                let group = groups.get_mut(&group_id).ok_or_else(|| {
                    PirError::Protocol(format!(
                        "{}: unexpected group {}",
                        label, group_id
                    ))
                })?;
                group
                    .load_hints(hints_data)
                    .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;
            }

            // 4. Receive terminal sentinel.
            let _terminal = conn.recv().await?;

            Ok((prp_backend, prp_key, groups, total_resp))
        }

        let t_half_start = Instant::now();

        let index_fut = async {
            hint_primary.send(request_index).await?;
            let r = drain_half_build(
                &mut hint_primary,
                k_index as u8,
                "V2-half INDEX",
                db_info.index_bins,
                index_w as u32,
                0, // base_offset for INDEX groups
            )
            .await?;
            Ok::<_, PirError>((hint_primary, r))
        };
        let chunk_fut = async {
            hint_secondary.send(request_chunk).await?;
            let r = drain_half_build(
                &mut hint_secondary,
                k_chunk as u8,
                "V2-half CHUNK",
                db_info.chunk_bins,
                chunk_w as u32,
                k_index, // base_offset for CHUNK groups
            )
            .await?;
            Ok::<_, PirError>((hint_secondary, r))
        };

        #[cfg(not(target_arch = "wasm32"))]
        let join_res = tokio::try_join!(index_fut, chunk_fut);
        #[cfg(target_arch = "wasm32")]
        let join_res = futures::future::try_join(index_fut, chunk_fut).await;

        // Always restore the connections to self, even on error, so a
        // fallback to V2 full has a working primary socket and the
        // secondary slot is restored for subsequent rounds.
        let (idx_out, chk_out) = match join_res {
            Ok(v) => v,
            Err(e) => {
                // Best-effort: we don't have the moved conns back here,
                // so they're dropped. The next reconnect will rebuild.
                return Err(e);
            }
        };

        let (hp, (idx_backend, idx_key, idx_groups, idx_bytes)) = idx_out;
        let (hs, (chk_backend, chk_key, chk_groups, chk_bytes)) = chk_out;

        self.hint_conn = Some(hp);
        self.hint_conn_secondary = Some(hs);

        // Both halves must agree on the PRP key + backend; if they
        // don't, the server mis-paired the session — bail.
        if idx_key != chk_key {
            return Err(PirError::Protocol(format!(
                "V2-half: INDEX and CHUNK PRP keys mismatch (INDEX={:02x?}..., CHUNK={:02x?}...)",
                &idx_key[..4],
                &chk_key[..4],
            )));
        }
        if idx_backend != chk_backend {
            return Err(PirError::Protocol(format!(
                "V2-half: INDEX and CHUNK PRP backends mismatch ({} vs {})",
                idx_backend, chk_backend
            )));
        }

        let dt_wire = t_half_start.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   V2-half parallel hint+build: total {:?} (req {}B+{}B, resp {}B+{}B, k_index={}, k_chunk={})",
                dt_wire,
                request_index_bytes, request_chunk_bytes,
                idx_bytes, chk_bytes,
                k_index, k_chunk,
            );
        }

        self.prp_backend = idx_backend;
        self.master_prp_key = idx_key;

        // Move the already-built + hint-loaded groups into self.
        self.index_groups = idx_groups;
        self.chunk_groups = chk_groups;

        // Surface a single terminal progress tick — per-group ticks
        // are buried inside the parallel build loops and the API
        // doesn't currently thread a callback through `drain_half_build`.
        if let Some(p) = progress {
            if total > 0 {
                p.on_group_complete(total, total, "chunk");
            }
        }

        self.loaded_db_id = Some(db_info.db_id);

        // Record both wire rounds.
        self.record_round(RoundProfile {
            kind: RoundKind::HarmonyHintRefresh,
            server_id: 1,
            db_id: Some(db_id),
            request_bytes: request_index_bytes,
            response_bytes: idx_bytes,
            items: vec![1u32; k_index],
        });
        self.record_round(RoundProfile {
            kind: RoundKind::HarmonyHintRefresh,
            server_id: 1,
            db_id: Some(db_id),
            request_bytes: request_chunk_bytes,
            response_bytes: chk_bytes,
            items: vec![1u32; k_chunk],
        });

        // Persist to cache.
        if let Err(e) = self.persist_hints_to_cache(db_info) {
            log::warn!(
                "[PIR-AUDIT] HarmonyPIR V2-half: failed to persist main hints to cache: {}",
                e
            );
        }
        Ok(())
    }

    /// V1-protocol parallel main hint fetch.
    ///
    /// Sends `REQ_HARMONY_HINTS` at level=0 (INDEX) on the primary
    /// hint socket and level=1 (CHUNK) on the secondary, awaited
    /// concurrently via `tokio::try_join!`. Each level's response is
    /// a stream of K independent hint frames; the two streams transfer
    /// in parallel on disjoint TCP connections, each getting its own
    /// bandwidth-delay-product budget.
    ///
    /// Functional contract identical to [`ensure_groups_ready_v2`]:
    /// `self.index_groups` and `self.chunk_groups` are populated with
    /// hint-loaded `HarmonyGroup` instances, `loaded_db_id` is set,
    /// and (on success) the combined state is persisted to cache.
    ///
    /// The client uses its own `master_prp_key` (set at `new()` time)
    /// rather than a server-generated key — see the dispatch comment
    /// in `ensure_groups_ready` for the threat-model rationale.
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "harmony", v1_parallel = true, db_id = db_info.db_id))]
    async fn ensure_groups_ready_v1_parallel(
        &mut self,
        db_info: &DatabaseInfo,
        progress: Option<&dyn HintProgress>,
    ) -> PirResult<()> {
        let k_index = db_info.index_k as usize;
        let k_chunk = db_info.chunk_k as usize;

        let index_w = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;
        let chunk_w = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE;

        // Build groups (CPU work; serial within each tree). The two
        // trees could be built in parallel via rayon on native but the
        // gain is small relative to the hint-download wall time, and
        // wasm32 is single-threaded anyway. Keep serial.
        for g in 0..k_index {
            let group = HarmonyGroup::new_with_backend(
                db_info.index_bins,
                index_w as u32,
                0,
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

        // Move state into the two parallel futures so each holds
        // disjoint mutable borrows. Restored after the join.
        let mut index_groups = std::mem::take(&mut self.index_groups);
        let mut chunk_groups = std::mem::take(&mut self.chunk_groups);
        let mut hint_primary = self.hint_conn.take().ok_or(PirError::NotConnected)?;
        let mut hint_secondary = self
            .hint_conn_secondary
            .take()
            .expect("only called when hint_conn_secondary is_some");
        let master_prp_key = self.master_prp_key;
        let prp_backend = self.prp_backend;
        let db_id = db_info.db_id;

        let t_main_start = Instant::now();

        let index_fut = async {
            let profile = fetch_and_load_main_hints_into_map(
                hint_primary.as_mut(),
                &mut index_groups,
                db_id,
                0, // wire_level = 0 → INDEX main
                k_index as u8,
                &master_prp_key,
                prp_backend,
            )
            .await?;
            Ok::<_, PirError>((hint_primary, index_groups, profile))
        };

        let chunk_fut = async {
            let profile = fetch_and_load_main_hints_into_map(
                hint_secondary.as_mut(),
                &mut chunk_groups,
                db_id,
                1, // wire_level = 1 → CHUNK main
                k_chunk as u8,
                &master_prp_key,
                prp_backend,
            )
            .await?;
            Ok::<_, PirError>((hint_secondary, chunk_groups, profile))
        };

        #[cfg(not(target_arch = "wasm32"))]
        let (idx_out, chk_out) = tokio::try_join!(index_fut, chunk_fut)?;
        #[cfg(target_arch = "wasm32")]
        let (idx_out, chk_out) = futures::future::try_join(index_fut, chunk_fut).await?;

        let (hp, idx_groups, idx_profile) = idx_out;
        let (hs, chk_groups, chk_profile) = chk_out;

        let dt_main = t_main_start.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   V1 parallel main hint stream: total {:?} (req INDEX+CHUNK in parallel on 2 sockets, k_index={}, k_chunk={})",
                dt_main, k_index, k_chunk,
            );
        }

        // Restore state to self.
        self.hint_conn = Some(hp);
        self.hint_conn_secondary = Some(hs);
        self.index_groups = idx_groups;
        self.chunk_groups = chk_groups;

        // Record the two rounds (deferred from inside the parallel
        // futures because `record_round` needs `&mut self`).
        self.record_round(idx_profile);
        self.record_round(chk_profile);

        self.loaded_db_id = Some(db_info.db_id);

        // Emit one terminal progress tick — V1 parallel doesn't easily
        // surface per-group ticks since both streams are interleaved.
        // A future improvement would thread a per-group `on_group_complete`
        // callback through the free helper; not worth the API
        // complexity for the wall-time win.
        if let Some(p) = progress {
            let total = (k_index + k_chunk) as u32;
            if total > 0 {
                p.on_group_complete(total, total, "chunk");
            }
        }

        // Persist freshly-fetched main hints to disk cache so a warm
        // restart skips the download entirely. Errors are logged and
        // ignored — a read-only cache must never wedge live queries.
        if let Err(e) = self.persist_hints_to_cache(db_info) {
            log::warn!(
                "[PIR-AUDIT] HarmonyPIR V1 parallel: failed to persist main hints to cache: {}",
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
        let request_bytes = request.len() as u64;

        let t_send = Instant::now();
        let conn = self.hint_conn.as_mut().ok_or(PirError::NotConnected)?;
        conn.send(request).await?;
        let dt_send = t_send.elapsed();

        // The hint server streams `num_groups` separate response frames.
        // Sum their sizes for a single `HarmonyHintRefresh` round event —
        // a wire observer sees one request followed by N responses, all
        // logically tied to this one hint refresh. Round is emitted only
        // on the success path; error returns mid-stream skip emission
        // (matches the early-error semantics of the other rounds).
        let mut received = 0u32;
        let mut total_response_bytes: u64 = 0;
        let t_first_byte = Instant::now();
        let mut dt_first: Option<std::time::Duration> = None;
        let mut dt_recv_total = std::time::Duration::ZERO;
        let mut dt_load_total = std::time::Duration::ZERO;
        while received < num_groups as u32 {
            let t_msg = Instant::now();
            let msg = conn.recv().await?;
            dt_recv_total += t_msg.elapsed();
            if dt_first.is_none() {
                dt_first = Some(t_first_byte.elapsed());
            }
            total_response_bytes = total_response_bytes.saturating_add(msg.len() as u64);
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
            let t_load = Instant::now();
            group
                .load_hints(hints_data)
                .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;
            dt_load_total += t_load.elapsed();

            if let Some(cb) = on_group.as_deref_mut() {
                cb(group_id);
            }

            received += 1;
        }

        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]     fetch_and_load_hints(level={:02}): send={:?} first_byte={:?} recv_total={:?} load_total={:?} groups={} bytes={}",
                level, dt_send,
                dt_first.unwrap_or_default(),
                dt_recv_total, dt_load_total,
                num_groups, total_response_bytes,
            );
        }

        self.record_round(RoundProfile {
            kind: RoundKind::HarmonyHintRefresh,
            server_id: 1,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: total_response_bytes,
            items: vec![1u32; num_groups as usize],
        });
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
        // Phase-level timing for diagnostics. Guarded by env var so it
        // only fires when the operator explicitly opts in.
        let _bench = std::env::var("HARMONY_BENCH").is_ok();
        let t_step_start = Instant::now();
        let t_hint_start = Instant::now();
        self.ensure_groups_ready(db_info, None).await?;
        let t_hint = t_hint_start.elapsed();
        if _bench {
            eprintln!("[HARMONY_BENCH] db={} queries={} ensure_groups_ready: {:?}", db_info.db_id, script_hashes.len(), t_hint);
        }

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

        // Phase 1: batched INDEX via PBC plan. Drives one or more
        // K-padded HarmonyPIR INDEX rounds (one per cuckoo position
        // per PBC round) covering all scripthashes; each scripthash's
        // two INDEX Merkle items inherit a unique-per-batch
        // `pbc_group`, so `index_max_items_per_group_per_level = 2`
        // independently of the batch's collision pattern.
        let t_index_start = Instant::now();
        let index_outcomes = self
            .query_index_phase_batched(script_hashes, db_info)
            .await?;
        let t_index = t_index_start.elapsed();
        if _bench {
            eprintln!("[HARMONY_BENCH] db={} INDEX phase: {:?}", db_info.db_id, t_index);
        }

        // Phase 2: per-scripthash CHUNK + result assembly. Each query
        // fetches/verifies its REAL chunk count — found queries fetch
        // their UTXO chunks, not-found / whale queries fetch none.
        //
        // M=16 chunk-Merkle padding REMOVED — 2026-05-17, see
        // PLAN_MERKLE_CODING.md Phase 2 (mirrors the Phase 1 DPF
        // change). Found-vs-not-found stays hidden: an all-not-found
        // batch still emits one dummy K_CHUNK-padded CHUNK round pair
        // (`query_chunk_phase_batched`'s all-empty branch), and the
        // per-bucket Merkle always issues >=1 (all-dummy) CHUNK-Merkle
        // pass (the `chunk_sub_items.is_empty()` skip was removed in
        // merkle_verify.rs). The per-query chunk count is now an
        // admitted leak — mild; ~99% of addresses have 1 chunk.
        let t_chunk_start = Instant::now();

        // Phase 2 PREPROCESS: project each scripthash's INDEX outcome into
        // (real_count, is_whale, has_real_match, real_chunk_ids) up
        // front, in scripthash order. We need these lists indexable by
        // scripthash idx so the batched CHUNK fetch can run once and we
        // still emit per-scripthash QueryResults in original order.
        let outcomes: Vec<(Option<(u32, u8, bool)>, Vec<IndexBinTrace>, Option<usize>)> =
            index_outcomes.into_iter().collect();
        let mut per_q_real_count: Vec<usize> = Vec::with_capacity(outcomes.len());
        let mut per_q_is_whale: Vec<bool> = Vec::with_capacity(outcomes.len());
        let mut per_q_has_match: Vec<bool> = Vec::with_capacity(outcomes.len());
        let mut per_q_real_chunks: Vec<Vec<u32>> = Vec::with_capacity(outcomes.len());
        for (found_info, _ibins, _matched) in outcomes.iter() {
            let (real_chunk_ids, is_whale, has_real_match): (Vec<u32>, bool, bool) =
                match found_info {
                    Some((start, num, whale)) if *num > 0 => (
                        (*start..*start + *num as u32).collect(),
                        *whale,
                        true,
                    ),
                    Some((_start, _num, whale)) => (Vec::new(), *whale, true),
                    None => (Vec::new(), false, false),
                };
            per_q_real_count.push(real_chunk_ids.len());
            per_q_is_whale.push(is_whale);
            per_q_has_match.push(has_real_match);
            per_q_real_chunks.push(real_chunk_ids);
        }

        // Phase 2: BATCHED CHUNK fetch — one PBC plan over all queries'
        // REAL chunk lists; ceil(total_chunks / K_CHUNK) PBC rounds × 2
        // cuckoo positions of wire round-trips. For typical wallet syncs
        // (N ≫ 1) this batches every scripthash's chunks into shared
        // K_CHUNK-padded rounds. An all-not-found batch still emits one
        // dummy round pair (round-presence — see `query_chunk_phase_batched`).
        let chunk_results = self
            .query_chunk_phase_batched(&per_q_real_chunks, db_info)
            .await?;

        for (i, ((_found_info, index_bins, matched_idx), (chunk_data, chunk_bins))) in
            outcomes.into_iter().zip(chunk_results.into_iter()).enumerate()
        {
            let q_traces = QueryTraces {
                index_bins,
                matched_index_idx: matched_idx,
                chunk_bins,
            };
            let real_count = per_q_real_count[i];
            let is_whale = per_q_is_whale[i];
            let has_real_match = per_q_has_match[i];
            log::info!(
                "[PIR-AUDIT] HarmonyPIR CHUNK: query #{} fetching {} real chunk(s)",
                i, real_count,
            );

            // `chunk_data` holds exactly this scripthash's real chunks;
            // `real_data_len` is its full length (the slice below is a
            // defensive no-op unless the server dropped a chunk).
            let real_data_len = real_count * pir_core::params::CHUNK_SIZE;
            let real_data: Vec<u8> = if real_data_len <= chunk_data.len() {
                chunk_data[..real_data_len].to_vec()
            } else {
                chunk_data.clone()
            };

            if !has_real_match {
                results.push(None);
                traces.push(q_traces);
                continue;
            }

            if !is_whale && real_count == 0 {
                log::warn!(
                    "[PIR-AUDIT] HarmonyPIR CHUNK closure: query #{} matched a non-whale INDEX entry with num_chunks=0; treating as whale",
                    i,
                );
            }

            // [DBG_HEX] Hex-dump the raw chunk bytes the server returned, so
            // we can manually trace the varint parse and confirm the decoder
            // is reading the right bytes. Gated on env to avoid noise.
            if std::env::var("PIR_DUMP_RAW_CHUNKS").is_ok() {
                let preview_len = std::cmp::min(real_data.len(), 80);
                let preview: String = real_data[..preview_len]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                eprintln!(
                    "[DBG_HEX] HarmonyPIR query #{} real_count={} real_data_len={} (raw chunk_data_len={}) bytes[0..{}]={}",
                    i, real_count, real_data.len(), chunk_data.len(), preview_len, preview,
                );
            }

            let entries = decode_utxo_entries(&real_data);

            results.push(Some(QueryResult {
                entries,
                is_whale,
                merkle_verified: true,
                raw_chunk_data: if db_info.kind.is_delta() && real_count > 0 {
                    Some(real_data)
                } else {
                    None
                },
                index_bins: Vec::new(),
                chunk_bins: Vec::new(),
                matched_index_idx: None,
            }));
            traces.push(q_traces);
        }

        let t_chunk = t_chunk_start.elapsed();
        if _bench {
            eprintln!("[HARMONY_BENCH] db={} CHUNK phase ({} queries): {:?}", db_info.db_id, script_hashes.len(), t_chunk);
        }

        let t_merkle_start = Instant::now();
        if db_info.has_bucket_merkle {
            self.run_merkle_verification(&mut results, &traces, db_info)
                .await?;
        } else {
            log::info!(
                "[PIR-AUDIT] HarmonyPIR Merkle verification SKIPPED (db_id={} has no bucket Merkle)",
                db_info.db_id
            );
        }
        let t_merkle = t_merkle_start.elapsed();
        if _bench {
            eprintln!("[HARMONY_BENCH] db={} Merkle verification: {:?}", db_info.db_id, t_merkle);
            eprintln!("[HARMONY_BENCH] db={} TOTAL execute_step: {:?}  (hint {:?} / index {:?} / chunk {:?} / merkle {:?})",
                db_info.db_id, t_step_start.elapsed(), t_hint, t_index, t_chunk, t_merkle);
        }

        Ok(results)
    }

    /// Batched INDEX phase for the Option-B
    /// `index_max_items_per_group_per_level` closure (Harmony analog
    /// of `DpfClient::query_index_phase_batched`).
    ///
    /// Plans PBC rounds over the batch's candidate groups, then for
    /// each PBC round runs `INDEX_CUCKOO_NUM_HASHES = 2` wire INDEX
    /// rounds (one per cuckoo position `h`) — each wire round packs
    /// every placed scripthash's bin for that `h` into the same
    /// K-padded HarmonyPIR INDEX request. Per-scripthash output is
    /// the same `(found_info, index_bins, matched_idx)` triple
    /// `query_single` produced pre-Option-B; the wire-observable
    /// difference is the round count is now `2 × n_pbc_rounds`
    /// (typically 2 for batches with `N ≤ k`) instead of
    /// `2 × N` (one per scripthash × 2 cuckoo positions).
    ///
    /// HarmonyPIR's per-group hint state is consumed in lock-step
    /// across placed groups: each wire round consumes one hint from
    /// every placed group's `HarmonyGroup`. For a single-query batch
    /// this matches pre-Option-B hint usage; for multi-query batches
    /// hint consumption is more balanced (no concentration on
    /// `derive_groups_3[0]`), which delays exhaustion-driven refresh
    /// rounds.
    #[tracing::instrument(level = "trace", skip_all, fields(backend = "harmony", db_id = db_info.db_id, num_queries = script_hashes.len()))]
    async fn query_index_phase_batched(
        &mut self,
        script_hashes: &[ScriptHash],
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<(Option<(u32, u8, bool)>, Vec<IndexBinTrace>, Option<usize>)>> {
        let k_index = db_info.index_k as usize;
        let index_bins = db_info.index_bins as usize;
        let tag_seed = db_info.tag_seed;
        let n = script_hashes.len();

        // PBC plan over each scripthash's three candidate groups.
        let candidate_groups: Vec<[usize; NUM_HASHES]> = script_hashes
            .iter()
            .map(|sh| pir_core::hash::derive_groups_3(sh, k_index))
            .collect();
        let rounds = pir_core::pbc::pbc_plan_rounds(&candidate_groups, k_index, NUM_HASHES, 500);

        // Build a placement view for downstream decode + Merkle traces.
        // Each scripthash's INDEX query (and its INDEX Merkle items)
        // inherits the planner-assigned group; this is the structural
        // change the closure relies on.
        let mut placement: Vec<(usize, usize)> = vec![(0, 0); n];
        for (round_id, round) in rounds.iter().enumerate() {
            for &(sh_idx, pbc_group) in round {
                placement[sh_idx] = (round_id, pbc_group);
            }
        }

        log::info!(
            "[PIR-AUDIT] HarmonyPIR INDEX batched query: {} queries planned into {} PBC round(s) (K={})",
            n, rounds.len(), k_index,
        );

        // Per-scripthash output buffers.
        let mut found_info: Vec<Option<(u32, u8, bool)>> = vec![None; n];
        let mut index_bins_per_sh: Vec<Vec<IndexBinTrace>> =
            (0..n).map(|_| Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES)).collect();
        let mut matched_idx_per_sh: Vec<Option<usize>> = vec![None; n];

        // Pair-mode batching requires exactly 2 cuckoo positions per
        // scripthash (the wrapper's `build_request_pair` takes two query
        // indices). If `INDEX_CUCKOO_NUM_HASHES` ever changes, the
        // pair-mode path needs a redesign.
        const _: () = assert!(INDEX_CUCKOO_NUM_HASHES == 2);

        for (round_id, round) in rounds.iter().enumerate() {
            // Compute (group, target_bin) placements for both cuckoo
            // positions. The cuckoo key is keyed on the placed group,
            // matching what the server stores at build time.
            let mut placements_per_h: [Vec<(u8, u32)>; INDEX_CUCKOO_NUM_HASHES] =
                std::array::from_fn(|_| Vec::with_capacity(round.len()));
            for h in 0..INDEX_CUCKOO_NUM_HASHES {
                for &(sh_idx, pbc_group) in round {
                    let key = pir_core::hash::derive_cuckoo_key(
                        INDEX_PARAMS.master_seed,
                        pbc_group,
                        h,
                    );
                    let target_bin = pir_core::hash::cuckoo_hash(
                        &script_hashes[sh_idx],
                        key,
                        index_bins,
                    );
                    placements_per_h[h].push((pbc_group as u8, target_bin as u32));
                }
            }

            // Pipelined pair INDEX round: 1 RTT instead of 2. Wire format
            // and hint accounting are identical to two sequential
            // `run_index_round` calls — see `run_index_round_pair` docs.
            // round_tag encodes (round_id, h) so audit logs can tell
            // which wire round corresponds to which (PBC round, cuckoo
            // position) pair.
            let round_tag_h0 = round_id * INDEX_CUCKOO_NUM_HASHES;
            let round_tag_h1 = round_tag_h0 + 1;
            let (answers_h0, answers_h1) = self
                .run_index_round_pair(
                    db_info.db_id,
                    &placements_per_h[0],
                    &placements_per_h[1],
                    round_tag_h0,
                    round_tag_h1,
                )
                .await?;
            let answers_per_h: [&HashMap<u8, Vec<u8>>; INDEX_CUCKOO_NUM_HASHES] =
                [&answers_h0, &answers_h1];

            // Map each placement back to its scripthash; record bin
            // trace + match. Iteration order (h=0 first, then h=1) is
            // unchanged from the sequential path, so per-scripthash
            // bookkeeping (matched_idx_per_sh, found_info, audit logs)
            // is bit-for-bit equivalent.
            for h in 0..INDEX_CUCKOO_NUM_HASHES {
                let answers = answers_per_h[h];
                for &(sh_idx, pbc_group) in round {
                    let g = pbc_group as u8;
                    let key = pir_core::hash::derive_cuckoo_key(
                        INDEX_PARAMS.master_seed,
                        pbc_group,
                        h,
                    );
                    let target_bin = pir_core::hash::cuckoo_hash(
                        &script_hashes[sh_idx],
                        key,
                        index_bins,
                    ) as u32;
                    let answer = answers.get(&g).ok_or_else(|| {
                        PirError::Protocol(format!(
                            "INDEX round group {} dropped for sh_idx {}",
                            g, sh_idx
                        ))
                    })?;

                    let pos = index_bins_per_sh[sh_idx].len();
                    index_bins_per_sh[sh_idx].push(IndexBinTrace {
                        pbc_group,
                        bin_index: target_bin,
                        bin_content: answer.clone(),
                    });

                    if found_info[sh_idx].is_some() {
                        log::info!(
                            "[PIR-AUDIT] HarmonyPIR INDEX[sh={}] extra probe at h={} (group={}, bin={}) — tracked for Merkle uniformity",
                            sh_idx, h, pbc_group, target_bin,
                        );
                        continue;
                    }

                    let my_tag =
                        pir_core::hash::compute_tag(tag_seed, &script_hashes[sh_idx]);
                    if let Some(entry) = find_entry_in_index_result(answer, my_tag) {
                        let is_whale = entry.1 == 0;
                        log::info!(
                            "[PIR-AUDIT] HarmonyPIR INDEX[sh={}] FOUND at h={} (group={}, bin={}): start_chunk={}, num_chunks={}, whale={}",
                            sh_idx, h, pbc_group, target_bin, entry.0, entry.1, is_whale,
                        );
                        matched_idx_per_sh[sh_idx] = Some(pos);
                        found_info[sh_idx] = Some((entry.0, entry.1, is_whale));
                    } else {
                        log::info!(
                            "[PIR-AUDIT] HarmonyPIR INDEX[sh={}] miss at h={} (group={}, bin={})",
                            sh_idx, h, pbc_group, target_bin,
                        );
                    }
                }
            }
        }

        // Suppress an unused-binding warning if no scripthashes were
        // placed (degenerate empty-batch case the planner handles gracefully).
        let _ = placement;

        Ok((0..n)
            .map(|i| (found_info[i], std::mem::take(&mut index_bins_per_sh[i]), matched_idx_per_sh[i]))
            .collect())
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

            let placements = [(real_group as u8, target_bin as u32)];
            let mut round_results = self
                .run_index_round(db_info.db_id, &placements, h)
                .await?;
            let answer = round_results.remove(&(real_group as u8)).ok_or_else(|| {
                PirError::Protocol(format!(
                    "INDEX round dropped real group {} response",
                    real_group
                ))
            })?;

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
                // 🔒 CHUNK Round-Presence Symmetry (CLAUDE.md): not-found
                // queries still issue one K_CHUNK-padded CHUNK PIR round so
                // the server cannot infer found-vs-not-found from CHUNK
                // round absence. Empty `chunk_ids` triggers the dummy-round
                // path inside `query_chunk_level`.
                let _ = self.query_chunk_level(&[], db_info).await?;
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR CHUNK round-presence padding: not-found query issued 1 dummy CHUNK round"
                );
                return Ok((None, traces));
            }
        };

        if num_chunks == 0 {
            // Whale: same dummy CHUNK round as not-found for indistinguishability.
            let _ = self.query_chunk_level(&[], db_info).await?;
            log::info!(
                "[PIR-AUDIT] HarmonyPIR CHUNK round-presence padding: whale query issued 1 dummy CHUNK round"
            );
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

    /// Build and send one INDEX batch (K groups, 1 sub-query each).
    /// `placements` lists the `(group_id, target_bin)` pairs that
    /// carry real queries this round; remaining groups send
    /// `build_synthetic_dummy()`. Returns a `HashMap<group_id,
    /// XOR-recovered bin content>` covering every group flagged as
    /// `Real`, leaving the caller to map placements back to scripthashes.
    ///
    /// Pre-Option-B this function only ever received a single placement
    /// (the assigned-group `derive_groups_3[0]` of the active
    /// scripthash). The Option-B closure for the
    /// `index_max_items_per_group_per_level` axis fans real placements
    /// across multiple groups within a single PBC round, halving the
    /// wire INDEX round count for batches and forcing
    /// `max_items_per_group_per_level = 2` regardless of input collision
    /// pattern. Wire format unchanged — the server still processes K
    /// BatchItems × (T-1) indices each indistinguishably.
    async fn run_index_round(
        &mut self,
        db_id: u8,
        placements: &[(u8, u32)],
        round_tag: usize,
    ) -> PirResult<HashMap<u8, Vec<u8>>> {
        let k_index = self.index_groups.len() as u8;
        let roles = classify_index_groups(placements, k_index);
        let mut batch_items: Vec<BatchItem> = Vec::with_capacity(k_index as usize);

        for g in 0..k_index {
            let role = roles[g as usize];
            let group = self
                .index_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState(format!("missing INDEX group {}", g)))?;
            let bytes = match role {
                IndexGroupRole::Real(target_bin) => {
                    let req = group
                        .build_request(target_bin)
                        .map_err(|e| PirError::BackendState(format!("build_request: {:?}", e)))?;
                    req.request()
                }
                IndexGroupRole::Dummy => group.build_synthetic_dummy(),
            };
            batch_items.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes)?,
            });
        }

        let request = encode_batch_query(0, round_tag as u16, db_id, &batch_items);
        let request_bytes = request.len() as u64;
        // Per-group request shape: each group sends its `T - 1` indices
        // (the HarmonyPIR per-group invariant from CLAUDE.md). Capturing
        // `batch_items[g].indices.len()` lets a test assert the invariant
        // directly from the leakage profile.
        let items_per_group: Vec<u32> =
            batch_items.iter().map(|it| it.indices.len() as u32).collect();
        let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn.roundtrip(&request).await?;
        self.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: items_per_group,
        });
        let raw_results = decode_batch_response(&response)?;

        // Decode only groups marked `Real` — unprocessed dummy responses
        // mirror the chunk-side pattern, where decoding dummies would
        // advance HarmonyGroup state for no caller-visible benefit.
        let mut out = HashMap::new();
        for g in 0..k_index {
            if !matches!(roles[g as usize], IndexGroupRole::Real(_)) {
                continue;
            }
            let data = raw_results.get(&g).ok_or_else(|| {
                PirError::Protocol(format!("no INDEX response for group {}", g))
            })?;
            let group = self
                .index_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState("missing INDEX real group".into()))?;
            let answer = group
                .process_response(data)
                .map_err(|e| PirError::BackendState(format!("process_response: {:?}", e)))?;
            out.insert(g, answer);
        }
        Ok(out)
    }

    /// Pair-mode INDEX round: runs both cuckoo positions (h=0 and h=1) of
    /// one PBC round in a single pipelined network round-trip via the
    /// wrapper's `build_request_pair` / `process_response_pair` API.
    ///
    /// Wire format is identical to two back-to-back [`Self::run_index_round`]
    /// calls — each of the two emitted requests is K-padded with K
    /// `BatchItem`s of `T-1` indices, exactly as the sequential path. The
    /// only observable difference is the network ordering: both requests
    /// are sent before either response is awaited, so the two RTTs collapse
    /// into one (the second send overlaps the first response's flight
    /// time, and once both requests are in flight the responses arrive
    /// pipelined).
    ///
    /// Hint accounting is unchanged: each real group consumes 2 hints
    /// (one per cuckoo position), exactly as the sequential path. The
    /// upstream pair API guarantees bit-for-bit equivalence with two
    /// sequential `build_request` + `process_response` cycles given the
    /// same RNG seed (see `harmonypir-wasm::test_pair_equiv_sequential_*`).
    ///
    /// Dummy groups are *not* covered by the wrapper's `PendingPair`
    /// state — they call `build_synthetic_dummy()` twice (once per wire
    /// round). This is safe per the wrapper docs ("`build_synthetic_dummy`
    /// is safe to call" during the in-flight period — it only advances
    /// the RNG and never touches DS') and matches the sequential path's
    /// dummy emission shape.
    ///
    /// Both `placements_h0` and `placements_h1` MUST cover the same set
    /// of PBC groups (the same scripthashes are placed in the same groups
    /// across both cuckoo positions; only the `target_bin` differs). The
    /// function asserts this in debug builds.
    async fn run_index_round_pair(
        &mut self,
        db_id: u8,
        placements_h0: &[(u8, u32)],
        placements_h1: &[(u8, u32)],
        round_tag_h0: usize,
        round_tag_h1: usize,
    ) -> PirResult<(HashMap<u8, Vec<u8>>, HashMap<u8, Vec<u8>>)> {
        let k_index = self.index_groups.len() as u8;

        // Both cuckoo positions reuse the same group placement (a real
        // group at h=0 is also real at h=1; only the target_bin differs).
        // We classify from h=0 and assert the Real/Dummy split matches
        // h=1 — the actual bin index per Real group legitimately differs
        // between cuckoo positions, so we strip the Real(bin) payload
        // before comparing.
        let roles = classify_index_groups(placements_h0, k_index);
        debug_assert!(
            {
                let roles_h1 = classify_index_groups(placements_h1, k_index);
                roles.iter().zip(roles_h1.iter()).all(|(a, b)| {
                    matches!(
                        (a, b),
                        (IndexGroupRole::Real(_), IndexGroupRole::Real(_))
                            | (IndexGroupRole::Dummy, IndexGroupRole::Dummy),
                    )
                })
            },
            "pair-mode INDEX requires identical Real/Dummy split for h=0 and h=1",
        );

        // Per-group target-bin lookup. `placements_*` is a slice of
        // (group_id, target_bin); turn into a HashMap so we can pluck the
        // bin for each group during the pair build below.
        let h0_bins: HashMap<u8, u32> = placements_h0.iter().copied().collect();
        let h1_bins: HashMap<u8, u32> = placements_h1.iter().copied().collect();

        let mut batch_items_h0: Vec<BatchItem> = Vec::with_capacity(k_index as usize);
        let mut batch_items_h1: Vec<BatchItem> = Vec::with_capacity(k_index as usize);

        for g in 0..k_index {
            let role = roles[g as usize];
            let group = self
                .index_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState(format!("missing INDEX group {}", g)))?;
            let (bytes_h0, bytes_h1) = match role {
                IndexGroupRole::Real(_) => {
                    let bin_h0 = *h0_bins.get(&g).ok_or_else(|| {
                        PirError::InvalidState(format!("missing h=0 bin for real group {}", g))
                    })?;
                    let bin_h1 = *h1_bins.get(&g).ok_or_else(|| {
                        PirError::InvalidState(format!("missing h=1 bin for real group {}", g))
                    })?;
                    let pair = group.build_request_pair(bin_h0, bin_h1).map_err(|e| {
                        PirError::BackendState(format!("build_request_pair: {:?}", e))
                    })?;
                    let (req_1, req_2) = pair.into_parts();
                    (req_1.request(), req_2.request())
                }
                IndexGroupRole::Dummy => {
                    // Two independent K-padded synthetic dummies — one per
                    // wire round. RNG advances naturally so the two dummies
                    // differ on the wire. Per wrapper docs,
                    // `build_synthetic_dummy` is safe during the pair's
                    // in-flight period (it never touches DS').
                    let d_h0 = group.build_synthetic_dummy();
                    let d_h1 = group.build_synthetic_dummy();
                    (d_h0, d_h1)
                }
            };
            batch_items_h0.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes_h0)?,
            });
            batch_items_h1.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes_h1)?,
            });
        }

        let request_h0 = encode_batch_query(0, round_tag_h0 as u16, db_id, &batch_items_h0);
        let request_h1 = encode_batch_query(0, round_tag_h1 as u16, db_id, &batch_items_h1);
        let request_h0_bytes = request_h0.len() as u64;
        let request_h1_bytes = request_h1.len() as u64;
        let items_per_group_h0: Vec<u32> = batch_items_h0
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();
        let items_per_group_h1: Vec<u32> = batch_items_h1
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();

        // ── Pipelined network round-trip ──
        // Same fan-out treatment as `run_chunk_round_pair`: if a
        // secondary query socket is connected, send h=0 on conn0 and
        // h=1 on conn1 in parallel via `tokio::try_join!`. Each
        // socket gets its own TCP BDP budget at high RTT — the wire
        // saving is smaller for INDEX (~4 MB per side, ~1-2 s
        // typical) than for CHUNK (~15 MB per side, ~3 s) but the
        // logic is identical.
        //
        // Note: `conn.recv()` returns the raw frame INCLUDING the 4-byte
        // length prefix (unlike `conn.roundtrip()`, which strips it).
        // We strip with `[4..]` below, mirroring `dpf.rs:1442-1443`.
        let t_wire = Instant::now();
        let (response_h0, response_h1) = if self.query_conn_secondary.is_some() {
            let conn0 = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            let conn1 = self
                .query_conn_secondary
                .as_mut()
                .expect("checked is_some above");
            #[cfg(not(target_arch = "wasm32"))]
            let (r0, r1) = tokio::try_join!(
                async {
                    conn0.send(request_h0).await?;
                    conn0.recv().await
                },
                async {
                    conn1.send(request_h1).await?;
                    conn1.recv().await
                },
            )?;
            #[cfg(target_arch = "wasm32")]
            let (r0, r1) = futures::future::try_join(
                async {
                    conn0.send(request_h0).await?;
                    conn0.recv().await
                },
                async {
                    conn1.send(request_h1).await?;
                    conn1.recv().await
                },
            )
            .await?;
            (r0, r1)
        } else {
            let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            conn.send(request_h0).await?;
            conn.send(request_h1).await?;
            let r0 = conn.recv().await?;
            let r1 = conn.recv().await?;
            (r0, r1)
        };
        let dt_wire = t_wire.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            let mode = if self.query_conn_secondary.is_some() {
                "parallel-2-socket"
            } else {
                "pipelined-1-socket"
            };
            eprintln!(
                "[HARMONY_BENCH]   INDEX pair (round_tags={}/{}, {}): wire RTT {:?}  (req {}B+{}B resp {}B+{}B, k_index={})",
                round_tag_h0, round_tag_h1, mode, dt_wire,
                request_h0_bytes, request_h1_bytes,
                response_h0.len(), response_h1.len(),
                k_index,
            );
        }
        if response_h0.len() < 4 || response_h1.len() < 4 {
            return Err(PirError::Protocol(
                "INDEX pair response too short to carry length prefix".into(),
            ));
        }

        // Record both wire rounds in the leakage profile separately —
        // wire-observable shape is unchanged from the sequential path.
        // `response_bytes` is the raw frame length (length-prefix
        // included), matching the `dpf.rs` raw-recv path.
        self.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h0_bytes,
            response_bytes: response_h0.len() as u64,
            items: items_per_group_h0,
        });
        self.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h1_bytes,
            response_bytes: response_h1.len() as u64,
            items: items_per_group_h1,
        });

        let raw_results_h0 = decode_batch_response(&response_h0[4..])?;
        let raw_results_h1 = decode_batch_response(&response_h1[4..])?;

        // Decode real groups via the pair API. Dummies are not surfaced.
        let mut out_h0 = HashMap::new();
        let mut out_h1 = HashMap::new();
        for g in 0..k_index {
            if !matches!(roles[g as usize], IndexGroupRole::Real(_)) {
                continue;
            }
            let data_h0 = raw_results_h0.get(&g).ok_or_else(|| {
                PirError::Protocol(format!("no INDEX response (h=0) for group {}", g))
            })?;
            let data_h1 = raw_results_h1.get(&g).ok_or_else(|| {
                PirError::Protocol(format!("no INDEX response (h=1) for group {}", g))
            })?;
            let group = self
                .index_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState("missing INDEX real group".into()))?;
            let answer_pair = group
                .process_response_pair(data_h0, data_h1)
                .map_err(|e| {
                    PirError::BackendState(format!("process_response_pair: {:?}", e))
                })?;
            let (answer_h0, answer_h1) = answer_pair.into_parts();
            out_h0.insert(g, answer_h0);
            out_h1.insert(g, answer_h1);
        }
        Ok((out_h0, out_h1))
    }

    /// Execute CHUNK rounds to recover each chunk in `chunk_ids`.
    ///
    /// Returns `(chunk_data, chunk_bins)`:
    /// * `chunk_data` — assembled raw chunk bytes in the order of `chunk_ids`.
    /// * `chunk_bins` — per-chunk (pbc_group, bin_index, bin_content) for every
    ///   chunk we actually located. Used by the Merkle verifier to commit
    ///   the server to the chunk bin that served each slot.
    ///
    /// 🔒 CHUNK Round-Presence Symmetry (CLAUDE.md): if `chunk_ids` is
    /// empty (not-found / whale callers), this function still issues
    /// exactly one K_CHUNK-padded CHUNK round (all groups synthesised via
    /// `build_synthetic_dummy`) so the server cannot infer
    /// found-vs-not-found from absence of CHUNK traffic.
    async fn query_chunk_level(
        &mut self,
        chunk_ids: &[u32],
        db_info: &DatabaseInfo,
    ) -> PirResult<(Vec<u8>, Vec<ChunkBinTrace>)> {
        let k_chunk = db_info.chunk_k as usize;
        let chunk_bins = db_info.chunk_bins as usize;

        // CHUNK Round-Presence Symmetry: empty input still emits one
        // K_CHUNK-padded round so the wire signature is uniform across
        // found / not-found / whale. `run_chunk_round` with an empty
        // `real_queries` slice falls into the all-dummy path
        // (`build_synthetic_dummy` per group), exactly the wire shape
        // we need.
        if chunk_ids.is_empty() {
            log::info!(
                "[PIR-AUDIT] HarmonyPIR CHUNK round-presence padding: emitting 1 dummy K_CHUNK-padded round (all-synthetic, no real chunks)"
            );
            let _ = self.run_chunk_round(db_info.db_id, &[], chunk_bins, 0, 0).await?;
            return Ok((Vec::new(), Vec::new()));
        }

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

    /// Batched CHUNK phase across multiple scripthashes — single
    /// network round-trip pair (CHUNK_CUCKOO_NUM_HASHES=2 wire rounds)
    /// per PBC round, instead of one full K_CHUNK-padded round per
    /// scripthash. Mirrors the [`query_index_phase_batched`] PBC
    /// pattern but for CHUNK queries.
    ///
    /// `per_query_chunks[i]` is the REAL chunk_id list for scripthash
    /// `i` — `N` ids for a found query with `N` UTXO chunks, empty for
    /// not-found / whale. (M=16 padding removed — PLAN_MERKLE_CODING.md
    /// Phase 2; the per-query chunk count is now an admitted leak.)
    ///
    /// Returns one `(chunk_data, chunk_bins)` pair per scripthash, in
    /// the same order — `chunk_data` is concatenated payload bytes
    /// for that scripthash's slots, `chunk_bins` is the per-slot
    /// Merkle trace ready for `run_merkle_verification`.
    ///
    /// Wire-format and HarmonyGroup-state invariants are identical to
    /// the per-scripthash path's `run_chunk_round` calls: every wire
    /// round is K_CHUNK-padded, every group sends `T - 1` indices,
    /// every group consumes one hint per wire round. The only thing
    /// that changes is *how chunks are scheduled* into rounds —
    /// before, one scripthash filled one round (mostly padding);
    /// now, up to K_CHUNK chunks from any mix of scripthashes share
    /// a round.
    ///
    /// CHUNK Round-Presence Symmetry: when every per-scripthash list
    /// is empty (all not-found / whale in a "this DB has no found
    /// queries" batch), this function still issues one dummy
    /// K_CHUNK-padded `run_chunk_round_pair` — byte-shape-identical to
    /// a real single-PBC-round CHUNK fetch, so an all-not-found batch
    /// is wire-indistinguishable from a found batch.
    async fn query_chunk_phase_batched(
        &mut self,
        per_query_chunks: &[Vec<u32>],
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<(Vec<u8>, Vec<ChunkBinTrace>)>> {
        let k_chunk = db_info.chunk_k as usize;
        let chunk_bins = db_info.chunk_bins as usize;
        let n = per_query_chunks.len();

        // Empty: still emit one dummy round pair for symmetry. With the
        // M=16 padding removed (PLAN_MERKLE_CODING.md Phase 2) a
        // not-found / whale query owns 0 real chunks, so an
        // all-not-found batch reaches here. It must emit the SAME wire
        // shape as a found batch's single PBC round —
        // `run_chunk_round_pair`, two K_CHUNK-padded wire rounds
        // (h=0, h=1) — not a single `run_chunk_round`, or
        // found-vs-not-found would leak via the CHUNK round count.
        if per_query_chunks.iter().all(|cids| cids.is_empty()) {
            log::info!(
                "[PIR-AUDIT] HarmonyPIR CHUNK batched: emitting 1 dummy K_CHUNK-padded round pair (no real chunks across {} queries)",
                n,
            );
            let _ = self
                .run_chunk_round_pair(db_info.db_id, &[], chunk_bins, 0, 1)
                .await?;
            return Ok((0..n).map(|_| (Vec::new(), Vec::new())).collect());
        }

        // Flatten to a single global list: (sh_idx, slot_in_sh, chunk_id).
        // The slot is the chunk's position within its owning scripthash's
        // padded list — needed to put recovered bytes back in the right
        // order for `decode_utxo_entries`.
        let mut flat: Vec<(usize, usize, u32)> = Vec::new();
        for (sh_idx, cids) in per_query_chunks.iter().enumerate() {
            for (slot, &cid) in cids.iter().enumerate() {
                flat.push((sh_idx, slot, cid));
            }
        }

        // PBC plan: each chunk's NUM_HASHES = 3 candidate groups are
        // derived the same way the server's build path does it
        // (`derive_int_groups_3`), so the planner-assigned group is
        // valid for serving on the server side too.
        let candidate_groups: Vec<[usize; NUM_HASHES]> = flat
            .iter()
            .map(|&(_, _, cid)| pir_core::hash::derive_int_groups_3(cid, k_chunk))
            .collect();
        let rounds = pir_core::pbc::pbc_plan_rounds(
            &candidate_groups,
            k_chunk,
            NUM_HASHES,
            500,
        );
        log::info!(
            "[PIR-AUDIT] HarmonyPIR CHUNK batched: {} total chunks across {} queries → {} PBC round(s) × {} cuckoo positions = {} wire round(s) (K_CHUNK={})",
            flat.len(),
            n,
            rounds.len(),
            CHUNK_CUCKOO_NUM_HASHES,
            rounds.len() * CHUNK_CUCKOO_NUM_HASHES,
            k_chunk,
        );
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   CHUNK plan: {} chunks × {} queries → {} PBC × {} h = {} wire rounds",
                flat.len(), n, rounds.len(), CHUNK_CUCKOO_NUM_HASHES, rounds.len() * CHUNK_CUCKOO_NUM_HASHES,
            );
        }

        // Per-(sh, slot) outputs. We use HashMap<(sh, slot), _> rather
        // than HashMap<cid, _> because two scripthashes could pad to
        // the same synthetic chunk_id; (sh, slot) is the unambiguous
        // key.
        let mut chunk_data: HashMap<(usize, usize), Vec<u8>> = HashMap::new();
        let mut chunk_traces: HashMap<(usize, usize), ChunkBinTrace> = HashMap::new();
        let mut recovered: std::collections::HashSet<usize> = std::collections::HashSet::new(); // flat_idx

        // For each PBC round, pipeline the two cuckoo positions via
        // `run_chunk_round_pair`. The pre-2026-05-13 serial path looped
        // over `h ∈ 0..CHUNK_CUCKOO_NUM_HASHES` and filtered out
        // already-recovered chunks at h=1 — we lose that
        // "retry-only-missed-chunks" optimization here, but K_CHUNK
        // padding makes every wire round identical in shape anyway, so
        // bandwidth is unchanged. The benefit: one RTT + one
        // server-walk pipelined into the other, ~3 s of wall-time
        // saved per query batch against the public Hetzner deployment
        // (see `[HARMONY_BENCH]` numbers in
        // `docs/PLAN_HARMONY_PERF_AUDIT.md`).
        //
        // We assert `CHUNK_CUCKOO_NUM_HASHES == 2` here — pair-mode
        // would need generalisation to 3+ cuckoo positions. The
        // constant is fixed at 2 in `pir-core::params` so this is a
        // compile-time invariant; the assertion catches any future
        // params change.
        debug_assert_eq!(
            CHUNK_CUCKOO_NUM_HASHES, 2,
            "run_chunk_round_pair assumes exactly 2 cuckoo positions",
        );
        for (round_id, round) in rounds.iter().enumerate() {
            let still_pending: Vec<(usize, u8)> = round
                .iter()
                .map(|&(flat_idx, pbc_group)| (flat_idx, pbc_group as u8))
                .collect();
            if still_pending.is_empty() {
                continue;
            }

            let placements: Vec<(u32, u8)> = still_pending
                .iter()
                .map(|&(flat_idx, pbc_group)| {
                    let (_, _, cid) = flat[flat_idx];
                    (cid, pbc_group)
                })
                .collect();

            let round_tag_h0 = (round_id * CHUNK_CUCKOO_NUM_HASHES) as u16;
            let round_tag_h1 = (round_id * CHUNK_CUCKOO_NUM_HASHES + 1) as u16;
            let (answers_h0, answers_h1) = self
                .run_chunk_round_pair(
                    db_info.db_id,
                    &placements,
                    chunk_bins,
                    round_tag_h0,
                    round_tag_h1,
                )
                .await?;

            // Decode + reattribute to (sh_idx, slot). The chunk_id's
            // cuckoo placement deterministically picks ONE of h=0 / h=1
            // — try h=0 first, then h=1. The other position will
            // contain a different bin that doesn't have our chunk_id
            // slot (so `find_chunk_in_result` returns None), and we
            // skip it. If neither has the chunk, it's missing (e.g.
            // server lacks the entry).
            for &(flat_idx, pbc_group) in &still_pending {
                let (sh_idx, slot, cid) = flat[flat_idx];
                for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                    let answers = if h == 0 { &answers_h0 } else { &answers_h1 };
                    let Some(answer) = answers.get(&pbc_group) else {
                        continue;
                    };
                    let Some(data) = find_chunk_in_result(answer, cid) else {
                        continue;
                    };
                    let key = pir_core::hash::derive_cuckoo_key(
                        CHUNK_PARAMS.master_seed,
                        pbc_group as usize,
                        h,
                    );
                    let bin_index =
                        pir_core::hash::cuckoo_hash_int(cid, key, chunk_bins) as u32;
                    chunk_data.insert((sh_idx, slot), data.to_vec());
                    chunk_traces.insert(
                        (sh_idx, slot),
                        ChunkBinTrace {
                            pbc_group: pbc_group as usize,
                            bin_index,
                            bin_content: answer.clone(),
                        },
                    );
                    recovered.insert(flat_idx);
                    break;
                }
            }
        }

        // Reassemble per-scripthash output, preserving slot order so
        // `decode_utxo_entries` reads bytes in the correct sequence.
        let mut output = Vec::with_capacity(n);
        for sh_idx in 0..n {
            let cids = &per_query_chunks[sh_idx];
            let mut data = Vec::with_capacity(cids.len() * pir_core::params::CHUNK_SIZE);
            let mut bins = Vec::with_capacity(cids.len());
            for slot in 0..cids.len() {
                if let Some(d) = chunk_data.get(&(sh_idx, slot)) {
                    data.extend_from_slice(d);
                }
                if let Some(t) = chunk_traces.get(&(sh_idx, slot)) {
                    bins.push(t.clone());
                }
            }
            output.push((data, bins));
        }

        Ok(output)
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
        let _t_sib_start = Instant::now();
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

        // Capture readonly state to avoid borrow-checker conflicts when
        // taking mutable borrows of the various self fields below.
        let master_prp_key = self.master_prp_key;
        let prp_backend = self.prp_backend;
        let db_id = db_info.db_id;
        let index_bins_total = db_info.index_bins;
        let chunk_bins_total = db_info.chunk_bins;

        if self.hint_conn_secondary.is_some() {
            // ── Parallel path: INDEX siblings on hint primary, CHUNK
            // siblings on hint secondary. Each tree's levels stay
            // serial within its own future (level L+1 doesn't depend
            // on level L's hints — the dependency is at Merkle-verify
            // time, after sibling hints are loaded — but we keep the
            // intra-tree order to minimize peak memory growth from
            // group_init).
            //
            // Move everything the parallel futures need out of self
            // so they can hold disjoint mutable state. Restored after
            // the join.
            let mut index_sib_groups = std::mem::take(&mut self.index_sib_groups);
            let mut chunk_sib_groups = std::mem::take(&mut self.chunk_sib_groups);
            let mut hint_primary =
                self.hint_conn.take().ok_or(PirError::NotConnected)?;
            let mut hint_secondary = self.hint_conn_secondary.take().expect(
                "checked is_some above; field is private and not mutated mid-await",
            );

            let index_fut = async {
                let mut profiles = Vec::with_capacity(index_sib_levels);
                let mut nodes: u64 = index_bins_total as u64;
                for sl in 0..index_sib_levels {
                    let level_n = nodes.div_ceil(arity);
                    nodes = level_n;
                    let t_init = Instant::now();
                    for g in 0..k_index {
                        let group = HarmonyGroup::new_with_backend(
                            level_n as u32,
                            sib_w,
                            0,
                            &master_prp_key,
                            ((k_index + k_chunk) + sl * k_index + g) as u32,
                            prp_backend,
                        )
                        .map_err(|e| {
                            PirError::BackendState(format!(
                                "INDEX sib HarmonyGroup init: {:?}",
                                e
                            ))
                        })?;
                        index_sib_groups.insert((sl, g as u8), group);
                    }
                    let dt_init = t_init.elapsed();
                    let t_fetch = Instant::now();
                    let profile = fetch_and_load_sib_hints_into_map(
                        hint_primary.as_mut(),
                        &mut index_sib_groups,
                        sl,
                        db_id,
                        10 + sl as u8,
                        k_index as u8,
                        &master_prp_key,
                        prp_backend,
                    )
                    .await?;
                    let dt_fetch = t_fetch.elapsed();
                    if std::env::var("HARMONY_BENCH").is_ok() {
                        eprintln!(
                            "[HARMONY_BENCH]   sib INDEX L{} (parallel): group_init={:?}  fetch+load={:?}  (k={}, level_n={})",
                            sl, dt_init, dt_fetch, k_index, level_n,
                        );
                    }
                    profiles.push(profile);
                }
                Ok::<_, PirError>((hint_primary, index_sib_groups, profiles))
            };

            let chunk_fut = async {
                let mut profiles = Vec::with_capacity(chunk_sib_levels);
                let mut nodes: u64 = chunk_bins_total as u64;
                for sl in 0..chunk_sib_levels {
                    let level_n = nodes.div_ceil(arity);
                    nodes = level_n;
                    let t_init = Instant::now();
                    for g in 0..k_chunk {
                        let group = HarmonyGroup::new_with_backend(
                            level_n as u32,
                            sib_w,
                            0,
                            &master_prp_key,
                            ((k_index + k_chunk)
                                + index_sib_levels * k_index
                                + sl * k_chunk
                                + g) as u32,
                            prp_backend,
                        )
                        .map_err(|e| {
                            PirError::BackendState(format!(
                                "CHUNK sib HarmonyGroup init: {:?}",
                                e
                            ))
                        })?;
                        chunk_sib_groups.insert((sl, g as u8), group);
                    }
                    let dt_init = t_init.elapsed();
                    let t_fetch = Instant::now();
                    let profile = fetch_and_load_sib_hints_into_map(
                        hint_secondary.as_mut(),
                        &mut chunk_sib_groups,
                        sl,
                        db_id,
                        20 + sl as u8,
                        k_chunk as u8,
                        &master_prp_key,
                        prp_backend,
                    )
                    .await?;
                    let dt_fetch = t_fetch.elapsed();
                    if std::env::var("HARMONY_BENCH").is_ok() {
                        eprintln!(
                            "[HARMONY_BENCH]   sib CHUNK L{} (parallel): group_init={:?}  fetch+load={:?}  (k={}, level_n={})",
                            sl, dt_init, dt_fetch, k_chunk, level_n,
                        );
                    }
                    profiles.push(profile);
                }
                Ok::<_, PirError>((hint_secondary, chunk_sib_groups, profiles))
            };

            #[cfg(not(target_arch = "wasm32"))]
            let (idx_out, chk_out) = tokio::try_join!(index_fut, chunk_fut)?;
            #[cfg(target_arch = "wasm32")]
            let (idx_out, chk_out) = futures::future::try_join(index_fut, chunk_fut).await?;

            let (hp, idx_groups, idx_profiles) = idx_out;
            let (hs, chk_groups, chk_profiles) = chk_out;

            // Restore connections + sib groups to self.
            self.hint_conn = Some(hp);
            self.hint_conn_secondary = Some(hs);
            self.index_sib_groups = idx_groups;
            self.chunk_sib_groups = chk_groups;

            // Record one round per fetched level (deferred from inside
            // the parallel futures — `record_round` needs `&mut self`
            // which we couldn't hold there).
            for p in idx_profiles {
                self.record_round(p);
            }
            for p in chk_profiles {
                self.record_round(p);
            }

            log::info!(
                "[PIR-AUDIT] HarmonyPIR sibling init (parallel 2-socket): INDEX L0..{} + CHUNK L0..{} fetched concurrently",
                index_sib_levels,
                chunk_sib_levels
            );
        } else {
            // ── Single-socket fallback path (pre-pool semantics) ──

            // ── INDEX sibling groups ───────────────────────────────────────
            let mut nodes: u64 = db_info.index_bins as u64;
            for sl in 0..index_sib_levels {
                let level_n = nodes.div_ceil(arity);
                nodes = level_n;
                let t_init = Instant::now();
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
                let dt_init = t_init.elapsed();
                let t_fetch = Instant::now();
                self.fetch_and_load_hints_into(
                    db_info.db_id,
                    10 + sl as u8,
                    k_index as u8,
                    HintTarget::IndexSib(sl),
                    None,
                )
                .await?;
                let dt_fetch = t_fetch.elapsed();
                if std::env::var("HARMONY_BENCH").is_ok() {
                    eprintln!(
                        "[HARMONY_BENCH]   sib INDEX L{}: group_init={:?}  fetch+load_hints={:?}  (k={}, level_n={})",
                        sl, dt_init, dt_fetch, k_index, level_n,
                    );
                }
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
                let t_init = Instant::now();
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
                let dt_init = t_init.elapsed();
                let t_fetch = Instant::now();
                self.fetch_and_load_hints_into(
                    db_info.db_id,
                    20 + sl as u8,
                    k_chunk as u8,
                    HintTarget::ChunkSib(sl),
                    None,
                )
                .await?;
                let dt_fetch = t_fetch.elapsed();
                if std::env::var("HARMONY_BENCH").is_ok() {
                    eprintln!(
                        "[HARMONY_BENCH]   sib CHUNK L{}: group_init={:?}  fetch+load_hints={:?}  (k={}, level_n={})",
                        sl, dt_init, dt_fetch, k_chunk, level_n,
                    );
                }
                log::info!(
                    "[PIR-AUDIT] HarmonyPIR CHUNK sib L{}: loaded hints for {} groups (n={})",
                    sl, k_chunk, level_n
                );
            }
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
        // Tree-tops fetch goes over the query server (server_id = 0).
        let leakage = self.leakage_recorder.clone();
        let tree_tops =
            fetch_tree_tops(conn, db_info.db_id, leakage.as_ref(), "harmony", 0).await?;

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

        // Merkle leakage rounds are BUFFERED, not recorded inline:
        // `verify_bucket_merkle_batch_parallel` drives two queriers
        // concurrently on separate sockets, and recording inline would
        // interleave INDEX- and CHUNK-Merkle rounds in wall-clock order.
        // That interleaving varies run-to-run and correlates with
        // found-vs-not-found, making a found query wire-distinguishable
        // from a not-found one by Merkle-round ORDER alone. The buffers
        // are drained below in a fixed INDEX-then-CHUNK sequence.
        let mut merkle_rounds_first: Vec<RoundProfile> = Vec::new();
        let mut merkle_rounds_second: Vec<RoundProfile> = Vec::new();

        let per_item = if self.query_conn_secondary.is_some() {
            // ── Parallel path: split INDEX and CHUNK sib trees across
            // the two sockets. Each querier holds the full map for
            // its table_type, plus an empty placeholder for the other
            // (it will never be accessed because the parallel verifier
            // only ever calls table_type=0 on q_index and table_type=1
            // on q_chunk).
            let mut empty_chunk_placeholder: HashMap<(usize, u8), HarmonyGroup> = HashMap::new();
            let mut empty_index_placeholder: HashMap<(usize, u8), HarmonyGroup> = HashMap::new();

            // Disjoint borrows on the two `Option` fields.
            let conn0 = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            let conn1 = self
                .query_conn_secondary
                .as_mut()
                .expect("checked is_some above");

            // `q_index` buffers INDEX-Merkle rounds, `q_chunk` buffers
            // CHUNK-Merkle rounds — into disjoint Vecs, so the two
            // concurrent sockets never interleave each other's rounds.
            let mut q_index = HarmonySiblingQuerier {
                query_conn: conn0,
                index_sib_groups: &mut index_sib_groups,
                chunk_sib_groups: &mut empty_chunk_placeholder,
                recorded: &mut merkle_rounds_first,
            };
            let mut q_chunk = HarmonySiblingQuerier {
                query_conn: conn1,
                index_sib_groups: &mut empty_index_placeholder,
                chunk_sib_groups: &mut chunk_sib_groups,
                recorded: &mut merkle_rounds_second,
            };

            verify_bucket_merkle_batch_parallel(
                &mut q_index,
                &mut q_chunk,
                items,
                db_info.index_bins,
                db_info.chunk_bins,
                index_k,
                chunk_k,
                db_info.db_id,
                &tree_tops,
            )
            .await
        } else {
            // ── Single-socket fallback: one querier verifies INDEX then
            // CHUNK sequentially, so `merkle_rounds_first` already ends
            // up in canonical INDEX-then-CHUNK order on its own.
            let query_conn = self
                .query_conn
                .as_mut()
                .ok_or(PirError::NotConnected)?;
            let mut querier = HarmonySiblingQuerier {
                query_conn,
                index_sib_groups: &mut index_sib_groups,
                chunk_sib_groups: &mut chunk_sib_groups,
                recorded: &mut merkle_rounds_first,
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

        // Emit the buffered Merkle leakage rounds in a fixed order — ALL
        // INDEX-Merkle rounds, then ALL CHUNK-Merkle rounds — regardless
        // of which socket's response landed first. This is the same
        // order the sequential DPF verifier produces, and it is what
        // keeps a found query's profile byte-identical to a not-found
        // query's (CLAUDE.md "found-vs-not-found"). Done here, after the
        // queriers drop and the sib maps are restored, because
        // `record_round` borrows `self`.
        for round in merkle_rounds_first {
            self.record_round(round);
        }
        for round in merkle_rounds_second {
            self.record_round(round);
        }

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
    ///
    /// The per-group dispatch (`build_request` for real groups,
    /// `build_synthetic_dummy` for the rest) is driven by the role
    /// list returned by [`classify_chunk_groups`]. That helper is
    /// `pub(crate)` and Kani-verified — see harness module
    /// `kani_harnesses` at the bottom of this file. The structural
    /// witnesses:
    ///
    /// * `roles.len() == k_chunk` regardless of `real_queries.len()`
    ///   ⇒ batch length is `k_chunk` ⇒ wire round count is `k_chunk`
    ///   sub-queries (CHUNK Round-Presence Symmetry P1).
    /// * When `real_queries.is_empty()` every entry is `Dummy`, so
    ///   every group routes through `build_synthetic_dummy`, whose
    ///   T-1-padded shape (HarmonyPIR Per-Group Request-Count
    ///   Symmetry) makes the wire bytes indistinguishable from a
    ///   round with one or more real groups (P2).
    async fn run_chunk_round(
        &mut self,
        db_id: u8,
        real_queries: &[(u32, u8)],
        chunk_bins: usize,
        hash_fn: usize,
        round_id: u16,
    ) -> PirResult<HashMap<u8, Vec<u8>>> {
        let k_chunk = self.chunk_groups.len() as u8;
        let roles = classify_chunk_groups(real_queries, k_chunk);

        let mut batch_items: Vec<BatchItem> = Vec::with_capacity(k_chunk as usize);

        for g in 0..k_chunk {
            let role = roles[g as usize];
            let group = self
                .chunk_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState(format!("missing CHUNK group {}", g)))?;
            let bytes = match role {
                ChunkGroupRole::Real(cid) => {
                    let key = pir_core::hash::derive_cuckoo_key(
                        CHUNK_PARAMS.master_seed,
                        g as usize,
                        hash_fn,
                    );
                    let target_bin = pir_core::hash::cuckoo_hash_int(cid, key, chunk_bins);
                    let req = group.build_request(target_bin as u32).map_err(|e| {
                        PirError::BackendState(format!("build_request (chunk): {:?}", e))
                    })?;
                    req.request()
                }
                ChunkGroupRole::Dummy => group.build_synthetic_dummy(),
            };
            batch_items.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes)?,
            });
        }

        let t_build = Instant::now();
        let request = encode_batch_query(1, round_id, db_id, &batch_items);
        let dt_build = t_build.elapsed();
        let request_bytes = request.len() as u64;
        let items_per_group: Vec<u32> =
            batch_items.iter().map(|it| it.indices.len() as u32).collect();
        let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
        let t_wire = Instant::now();
        let response = conn.roundtrip(&request).await?;
        let dt_wire = t_wire.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   CHUNK round (h={}, round_id={}): build {:?}  wire RTT {:?}  (req {}B resp {}B, k_chunk={})",
                hash_fn, round_id, dt_build, dt_wire, request_bytes, response.len() + 4, k_chunk,
            );
        }
        self.record_round(RoundProfile {
            kind: RoundKind::Chunk,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: items_per_group,
        });
        let t_decode = Instant::now();
        let raw_results = decode_batch_response(&response)?;

        // Decode only the groups the role list marks as Real — same set
        // of group_ids the original HashMap-based code processed (last
        // duplicate wins, identical to `HashMap::collect` semantics).
        let mut out = HashMap::new();
        for g in 0..k_chunk {
            if !matches!(roles[g as usize], ChunkGroupRole::Real(_)) {
                continue;
            }
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
        let dt_decode = t_decode.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   CHUNK round decode: {:?}  ({} real groups)",
                dt_decode, out.len(),
            );
        }
        Ok(out)
    }

    /// Pipelined two-cuckoo-position CHUNK wire round, mirror of
    /// [`run_index_round_pair`](Self::run_index_round_pair).
    ///
    /// Performs the same work as two sequential [`run_chunk_round`] calls
    /// (one at `hash_fn = 0`, one at `hash_fn = 1`) for the SAME
    /// `real_queries` set, but pipelines the two requests so the two
    /// RTTs collapse into one — `conn.send(req_h0); conn.send(req_h1);
    /// conn.recv(); conn.recv();`. Privacy + wire-shape invariants are
    /// unchanged: each round is K_CHUNK-padded, every group emits
    /// either a real (T-1 sorted distinct indices) or synthetic
    /// (still T-1 indices) request.
    ///
    /// Bandwidth note: pair-mode always sends BOTH `h=0` and `h=1` for
    /// every group in `real_queries`. The serial path's "retry only
    /// missed chunks at h=1" optimization is removed — but K_CHUNK
    /// padding means the wire shape is invariant anyway, so the only
    /// real cost is the redundant decode of one extra response per
    /// real group. The wall-time saving (one RTT + one server walk
    /// pipelined into the other) typically dominates the decode
    /// overhead by ~3x.
    ///
    /// State invariant: every real group's `HarmonyGroup` consumes two
    /// hints (one per cuckoo position), exactly matching the serial
    /// path's `query_count += 2` semantics. The pair API (upstream
    /// `harmonypir`) is bit-for-bit equivalent to two sequential
    /// `build_request` + `process_response` cycles given the same RNG
    /// seed — see `harmonypir-wasm::test_pair_equiv_sequential_*`.
    ///
    /// Returns `(out_h0, out_h1)` — two `HashMap<group_id, answer>`
    /// maps keyed by PBC group, containing the `process_response_pair`
    /// answers for the real groups only. Dummies are not surfaced.
    /// Callers run `find_chunk_in_result` on each map to extract the
    /// chunk_id slot from whichever cuckoo position actually held it.
    async fn run_chunk_round_pair(
        &mut self,
        db_id: u8,
        real_queries: &[(u32, u8)],
        chunk_bins: usize,
        round_id_h0: u16,
        round_id_h1: u16,
    ) -> PirResult<(HashMap<u8, Vec<u8>>, HashMap<u8, Vec<u8>>)> {
        let k_chunk = self.chunk_groups.len() as u8;
        let roles = classify_chunk_groups(real_queries, k_chunk);

        let mut batch_items_h0: Vec<BatchItem> = Vec::with_capacity(k_chunk as usize);
        let mut batch_items_h1: Vec<BatchItem> = Vec::with_capacity(k_chunk as usize);

        for g in 0..k_chunk {
            let role = roles[g as usize];
            let group = self
                .chunk_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState(format!("missing CHUNK group {}", g)))?;
            let (bytes_h0, bytes_h1) = match role {
                ChunkGroupRole::Real(cid) => {
                    let key_h0 = pir_core::hash::derive_cuckoo_key(
                        CHUNK_PARAMS.master_seed,
                        g as usize,
                        0,
                    );
                    let key_h1 = pir_core::hash::derive_cuckoo_key(
                        CHUNK_PARAMS.master_seed,
                        g as usize,
                        1,
                    );
                    let bin_h0 = pir_core::hash::cuckoo_hash_int(cid, key_h0, chunk_bins) as u32;
                    let bin_h1 = pir_core::hash::cuckoo_hash_int(cid, key_h1, chunk_bins) as u32;
                    let pair = group.build_request_pair(bin_h0, bin_h1).map_err(|e| {
                        PirError::BackendState(format!("build_request_pair (chunk): {:?}", e))
                    })?;
                    let (req_1, req_2) = pair.into_parts();
                    (req_1.request(), req_2.request())
                }
                ChunkGroupRole::Dummy => {
                    // Two independent K-padded synthetic dummies — one
                    // per wire round. Matches the dummy emission shape
                    // of the sequential path (`run_chunk_round` called
                    // twice would also issue two dummies for a Dummy
                    // role).
                    let d_h0 = group.build_synthetic_dummy();
                    let d_h1 = group.build_synthetic_dummy();
                    (d_h0, d_h1)
                }
            };
            batch_items_h0.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes_h0)?,
            });
            batch_items_h1.push(BatchItem {
                group_id: g,
                indices: bytes_to_u32_vec(&bytes_h1)?,
            });
        }

        let request_h0 = encode_batch_query(1, round_id_h0, db_id, &batch_items_h0);
        let request_h1 = encode_batch_query(1, round_id_h1, db_id, &batch_items_h1);
        let request_h0_bytes = request_h0.len() as u64;
        let request_h1_bytes = request_h1.len() as u64;
        let items_per_group_h0: Vec<u32> = batch_items_h0
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();
        let items_per_group_h1: Vec<u32> = batch_items_h1
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();

        // ── Pipelined network round-trip ──
        // Pool path: when a secondary query socket is connected, fan
        // h=0 onto conn0 and h=1 onto conn1 in parallel via
        // `tokio::try_join!`. Each socket gets its own TCP
        // bandwidth-delay-product budget — at high RTT this roughly
        // halves wall time vs. single-socket pipelining because the
        // two ~15 MB responses transfer concurrently instead of
        // sharing one stream's congestion window.
        //
        // Single-socket fallback: send both requests then recv both
        // (unchanged from pre-pool behaviour, kept identical so the
        // pool-size=1 code path is bit-for-bit equivalent).
        let t_wire = Instant::now();
        let (response_h0, response_h1) = if self.query_conn_secondary.is_some() {
            // Disjoint borrows on different `Option` fields → safe to
            // hold both `&mut` simultaneously.
            let conn0 = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            let conn1 = self
                .query_conn_secondary
                .as_mut()
                .expect("checked is_some above");
            #[cfg(not(target_arch = "wasm32"))]
            let (r0, r1) = tokio::try_join!(
                async {
                    conn0.send(request_h0).await?;
                    conn0.recv().await
                },
                async {
                    conn1.send(request_h1).await?;
                    conn1.recv().await
                },
            )?;
            #[cfg(target_arch = "wasm32")]
            let (r0, r1) = futures::future::try_join(
                async {
                    conn0.send(request_h0).await?;
                    conn0.recv().await
                },
                async {
                    conn1.send(request_h1).await?;
                    conn1.recv().await
                },
            )
            .await?;
            (r0, r1)
        } else {
            let conn = self.query_conn.as_mut().ok_or(PirError::NotConnected)?;
            conn.send(request_h0).await?;
            conn.send(request_h1).await?;
            let r0 = conn.recv().await?;
            let r1 = conn.recv().await?;
            (r0, r1)
        };
        let dt_wire = t_wire.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            let mode = if self.query_conn_secondary.is_some() {
                "parallel-2-socket"
            } else {
                "pipelined-1-socket"
            };
            eprintln!(
                "[HARMONY_BENCH]   CHUNK pair (round_ids={}/{}, {}): wire RTT {:?}  (req {}B+{}B resp {}B+{}B, k_chunk={})",
                round_id_h0, round_id_h1, mode, dt_wire,
                request_h0_bytes, request_h1_bytes,
                response_h0.len(), response_h1.len(),
                k_chunk,
            );
        }
        if response_h0.len() < 4 || response_h1.len() < 4 {
            return Err(PirError::Protocol(
                "CHUNK pair response too short to carry length prefix".into(),
            ));
        }

        // Record both wire rounds in the leakage profile separately —
        // wire-observable shape is unchanged from the sequential path.
        self.record_round(RoundProfile {
            kind: RoundKind::Chunk,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h0_bytes,
            response_bytes: response_h0.len() as u64,
            items: items_per_group_h0,
        });
        self.record_round(RoundProfile {
            kind: RoundKind::Chunk,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h1_bytes,
            response_bytes: response_h1.len() as u64,
            items: items_per_group_h1,
        });

        let raw_results_h0 = decode_batch_response(&response_h0[4..])?;
        let raw_results_h1 = decode_batch_response(&response_h1[4..])?;

        // Decode only real groups, via the pair API.
        let t_decode = Instant::now();
        let mut out_h0 = HashMap::new();
        let mut out_h1 = HashMap::new();
        for g in 0..k_chunk {
            if !matches!(roles[g as usize], ChunkGroupRole::Real(_)) {
                continue;
            }
            let data_h0 = raw_results_h0.get(&g).ok_or_else(|| {
                PirError::Protocol(format!("no CHUNK pair response (h=0) for group {}", g))
            })?;
            let data_h1 = raw_results_h1.get(&g).ok_or_else(|| {
                PirError::Protocol(format!("no CHUNK pair response (h=1) for group {}", g))
            })?;
            let group = self
                .chunk_groups
                .get_mut(&g)
                .ok_or_else(|| PirError::InvalidState("missing CHUNK real group".into()))?;
            let answer_pair =
                group.process_response_pair(data_h0, data_h1).map_err(|e| {
                    PirError::BackendState(format!("process_response_pair (chunk): {:?}", e))
                })?;
            let (answer_h0, answer_h1) = answer_pair.into_parts();
            out_h0.insert(g, answer_h0);
            out_h1.insert(g, answer_h1);
        }
        let dt_decode = t_decode.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   CHUNK pair decode: {:?}  ({} real groups × 2)",
                dt_decode, out_h0.len(),
            );
        }

        Ok((out_h0, out_h1))
    }
}

/// Free-function variant of [`HarmonyClient::fetch_and_load_hints_into`]
/// for MAIN hints (INDEX or CHUNK level, not sibling). Same structure
/// as [`fetch_and_load_sib_hints_into_map`] but the map key is just
/// `group_id: u8` (not `(sib_level, group_id)`).
///
/// Used by the parallel V1-protocol main hint path in
/// [`HarmonyClient::ensure_groups_ready_v1_parallel`]: client sends
/// `REQ_HARMONY_HINTS` at level=0 (INDEX) on the primary hint socket
/// and level=1 (CHUNK) on the secondary in parallel via
/// `tokio::try_join!`, so the two ~7-10 MB streams transfer
/// concurrently instead of sharing one TCP congestion window.
#[allow(clippy::too_many_arguments)]
async fn fetch_and_load_main_hints_into_map(
    conn: &mut dyn PirTransport,
    main_groups: &mut HashMap<u8, HarmonyGroup>,
    db_id: u8,
    wire_level: u8,
    num_groups: u8,
    master_prp_key: &[u8; 16],
    prp_backend: u8,
) -> PirResult<RoundProfile> {
    let mut payload = Vec::with_capacity(16 + 1 + 1 + 1 + num_groups as usize + 1);
    payload.extend_from_slice(master_prp_key);
    payload.push(prp_backend);
    payload.push(wire_level);
    payload.push(num_groups);
    for g in 0..num_groups {
        payload.push(g);
    }
    if db_id != 0 {
        payload.push(db_id);
    }
    let request = encode_request(REQ_HARMONY_HINTS, &payload);
    let request_bytes = request.len() as u64;

    let t_send = Instant::now();
    conn.send(request).await?;
    let dt_send = t_send.elapsed();

    let mut received = 0u32;
    let mut total_response_bytes: u64 = 0;
    let t_first_byte = Instant::now();
    let mut dt_first: Option<std::time::Duration> = None;
    let mut dt_recv_total = std::time::Duration::ZERO;
    let mut dt_load_total = std::time::Duration::ZERO;
    while received < num_groups as u32 {
        let t_msg = Instant::now();
        let msg = conn.recv().await?;
        dt_recv_total += t_msg.elapsed();
        if dt_first.is_none() {
            dt_first = Some(t_first_byte.elapsed());
        }
        total_response_bytes = total_response_bytes.saturating_add(msg.len() as u64);
        if msg.len() < 5 {
            return Err(PirError::Protocol("truncated main hint response".into()));
        }
        let body = &msg[4..];
        if body.is_empty() {
            return Err(PirError::Protocol("empty main hint response body".into()));
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
                "unexpected main hint response byte: 0x{:02x}",
                body[0]
            )));
        }
        if body.len() < 14 {
            return Err(PirError::Protocol("main hint response header truncated".into()));
        }
        let group_id = body[1];
        let hints_data = &body[14..];
        let group = main_groups.get_mut(&group_id).ok_or_else(|| {
            PirError::Protocol(format!(
                "main hint for unknown group {} at wire level {}",
                group_id, wire_level
            ))
        })?;
        let t_load = Instant::now();
        group
            .load_hints(hints_data)
            .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;
        dt_load_total += t_load.elapsed();
        received += 1;
    }

    if std::env::var("HARMONY_BENCH").is_ok() {
        eprintln!(
            "[HARMONY_BENCH]   main_fetch(level={:02}): send={:?} first_byte={:?} recv_total={:?} load_total={:?} groups={} bytes={}",
            wire_level, dt_send,
            dt_first.unwrap_or_default(),
            dt_recv_total, dt_load_total,
            num_groups, total_response_bytes,
        );
    }

    Ok(RoundProfile {
        kind: RoundKind::HarmonyHintRefresh,
        server_id: 1,
        db_id: Some(db_id),
        request_bytes,
        response_bytes: total_response_bytes,
        items: vec![1u32; num_groups as usize],
    })
}

/// Free-function variant of [`HarmonyClient::fetch_and_load_hints_into`]
/// for sibling hints — takes the connection and the specific sib_groups
/// map by mutable reference so two instances can run on disjoint state
/// in parallel via `tokio::try_join!`.
///
/// Used by the parallel path in `ensure_sibling_groups_ready` when a
/// secondary hint socket is available: INDEX sibling hints fetch on
/// the primary hint conn into `index_sib_groups`, CHUNK sibling hints
/// on the secondary into `chunk_sib_groups`, with both futures
/// polled concurrently.
///
/// Returns the `RoundProfile` to be recorded by the caller after the
/// parallel join completes — `record_round` needs `&mut self`, which
/// we don't hold inside the parallel future.
#[allow(clippy::too_many_arguments)]
async fn fetch_and_load_sib_hints_into_map(
    conn: &mut dyn PirTransport,
    sib_groups: &mut HashMap<(usize, u8), HarmonyGroup>,
    sib_level: usize,
    db_id: u8,
    wire_level: u8,
    num_groups: u8,
    master_prp_key: &[u8; 16],
    prp_backend: u8,
) -> PirResult<RoundProfile> {
    let mut payload = Vec::with_capacity(16 + 1 + 1 + 1 + num_groups as usize + 1);
    payload.extend_from_slice(master_prp_key);
    payload.push(prp_backend);
    payload.push(wire_level);
    payload.push(num_groups);
    for g in 0..num_groups {
        payload.push(g);
    }
    if db_id != 0 {
        payload.push(db_id);
    }
    let request = encode_request(REQ_HARMONY_HINTS, &payload);
    let request_bytes = request.len() as u64;

    let t_send = Instant::now();
    conn.send(request).await?;
    let dt_send = t_send.elapsed();

    let mut received = 0u32;
    let mut total_response_bytes: u64 = 0;
    let t_first_byte = Instant::now();
    let mut dt_first: Option<std::time::Duration> = None;
    let mut dt_recv_total = std::time::Duration::ZERO;
    let mut dt_load_total = std::time::Duration::ZERO;
    while received < num_groups as u32 {
        let t_msg = Instant::now();
        let msg = conn.recv().await?;
        dt_recv_total += t_msg.elapsed();
        if dt_first.is_none() {
            dt_first = Some(t_first_byte.elapsed());
        }
        total_response_bytes = total_response_bytes.saturating_add(msg.len() as u64);
        if msg.len() < 5 {
            return Err(PirError::Protocol("truncated sib hint response".into()));
        }
        let body = &msg[4..];
        if body.is_empty() {
            return Err(PirError::Protocol("empty sib hint response body".into()));
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
                "unexpected sib hint response byte: 0x{:02x}",
                body[0]
            )));
        }
        if body.len() < 14 {
            return Err(PirError::Protocol("sib hint response header truncated".into()));
        }
        let group_id = body[1];
        let hints_data = &body[14..];
        let group = sib_groups.get_mut(&(sib_level, group_id)).ok_or_else(|| {
            PirError::Protocol(format!(
                "sib hint for unknown group ({}, {}) at wire level {}",
                sib_level, group_id, wire_level
            ))
        })?;
        let t_load = Instant::now();
        group
            .load_hints(hints_data)
            .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;
        dt_load_total += t_load.elapsed();
        received += 1;
    }

    if std::env::var("HARMONY_BENCH").is_ok() {
        eprintln!(
            "[HARMONY_BENCH]     sib_fetch(level={:02}): send={:?} first_byte={:?} recv_total={:?} load_total={:?} groups={} bytes={}",
            wire_level, dt_send,
            dt_first.unwrap_or_default(),
            dt_recv_total, dt_load_total,
            num_groups, total_response_bytes,
        );
    }

    Ok(RoundProfile {
        kind: RoundKind::HarmonyHintRefresh,
        server_id: 1,
        db_id: Some(db_id),
        request_bytes,
        response_bytes: total_response_bytes,
        items: vec![1u32; num_groups as usize],
    })
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

        // Pool sizes: 1 = single-socket (legacy behaviour); 2 = open a
        // secondary socket too so parallel paths can fan rounds across
        // A/B. We cap at 2 today — the structurally parallel axis
        // count maxes out at 3 and within-level fan-out beyond the
        // current pipelining gives diminishing returns. Default is 2
        // because the iperf data on the public deployment shows
        // ~3× wall-time savings vs single socket per server.
        //
        // `HARMONY_QUERY_POOL_SIZE` controls pir2 (query server).
        // `HARMONY_HINT_POOL_SIZE`  controls pir1 (hint  server).
        // Independent because the two servers have independent
        // bandwidth-delay-product characteristics.
        let query_pool: usize = std::env::var("HARMONY_QUERY_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2)
            .clamp(1, 2);
        let hint_pool: usize = std::env::var("HARMONY_HINT_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2)
            .clamp(1, 2);

        // Dial up to 4 sockets in parallel (2× hint, 2× query) so the
        // cold-connect cost is one RTT, not four. The secondary slots
        // for each server are `Option` because pool_size=1 leaves them
        // empty (single-socket fallback).
        type DialResult = PirResult<(
            Box<dyn PirTransport>,
            Option<Box<dyn PirTransport>>,
            Box<dyn PirTransport>,
            Option<Box<dyn PirTransport>>,
        )>;
        #[cfg(not(target_arch = "wasm32"))]
        let dial_result: DialResult = {
            // tokio::try_join! is variadic up to 64 args at compile
            // time; we use a small fixed shape (1-4 sockets) here.
            let hint_primary = WsConnection::connect(&self.hint_server_url);
            let query_primary = WsConnection::connect(&self.query_server_url);
            match (hint_pool >= 2, query_pool >= 2) {
                (true, true) => {
                    let hint_secondary = WsConnection::connect(&self.hint_server_url);
                    let query_secondary = WsConnection::connect(&self.query_server_url);
                    let (h, hs, q, qs) = tokio::try_join!(
                        hint_primary,
                        hint_secondary,
                        query_primary,
                        query_secondary
                    )?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        Some(Box::new(hs) as Box<dyn PirTransport>),
                        Box::new(q) as Box<dyn PirTransport>,
                        Some(Box::new(qs) as Box<dyn PirTransport>),
                    ))
                }
                (true, false) => {
                    let hint_secondary = WsConnection::connect(&self.hint_server_url);
                    let (h, hs, q) =
                        tokio::try_join!(hint_primary, hint_secondary, query_primary)?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        Some(Box::new(hs) as Box<dyn PirTransport>),
                        Box::new(q) as Box<dyn PirTransport>,
                        None,
                    ))
                }
                (false, true) => {
                    let query_secondary = WsConnection::connect(&self.query_server_url);
                    let (h, q, qs) =
                        tokio::try_join!(hint_primary, query_primary, query_secondary)?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        None,
                        Box::new(q) as Box<dyn PirTransport>,
                        Some(Box::new(qs) as Box<dyn PirTransport>),
                    ))
                }
                (false, false) => {
                    let (h, q) = tokio::try_join!(hint_primary, query_primary)?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        None,
                        Box::new(q) as Box<dyn PirTransport>,
                        None,
                    ))
                }
            }
        };
        #[cfg(target_arch = "wasm32")]
        let dial_result: DialResult = async {
            use crate::wasm_transport::WasmWebSocketTransport;
            // wasm32 doesn't have a 4-tuple try_join; fall back to
            // try_join3 / try_join2 with the same shape conditionals.
            let hint_primary = WasmWebSocketTransport::connect(&self.hint_server_url);
            let query_primary = WasmWebSocketTransport::connect(&self.query_server_url);
            match (hint_pool >= 2, query_pool >= 2) {
                (true, true) => {
                    let hint_secondary =
                        WasmWebSocketTransport::connect(&self.hint_server_url);
                    let query_secondary =
                        WasmWebSocketTransport::connect(&self.query_server_url);
                    // Pair-up two try_joins to avoid needing a 4-arg variant.
                    let (a, b) = futures::future::try_join(
                        futures::future::try_join(hint_primary, hint_secondary),
                        futures::future::try_join(query_primary, query_secondary),
                    )
                    .await?;
                    let (h, hs) = a;
                    let (q, qs) = b;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        Some(Box::new(hs) as Box<dyn PirTransport>),
                        Box::new(q) as Box<dyn PirTransport>,
                        Some(Box::new(qs) as Box<dyn PirTransport>),
                    ))
                }
                (true, false) => {
                    let hint_secondary =
                        WasmWebSocketTransport::connect(&self.hint_server_url);
                    let (h, hs, q) =
                        futures::future::try_join3(hint_primary, hint_secondary, query_primary)
                            .await?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        Some(Box::new(hs) as Box<dyn PirTransport>),
                        Box::new(q) as Box<dyn PirTransport>,
                        None,
                    ))
                }
                (false, true) => {
                    let query_secondary =
                        WasmWebSocketTransport::connect(&self.query_server_url);
                    let (h, q, qs) =
                        futures::future::try_join3(hint_primary, query_primary, query_secondary)
                            .await?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        None,
                        Box::new(q) as Box<dyn PirTransport>,
                        Some(Box::new(qs) as Box<dyn PirTransport>),
                    ))
                }
                (false, false) => {
                    let (h, q) = futures::future::try_join(hint_primary, query_primary).await?;
                    Ok((
                        Box::new(h) as Box<dyn PirTransport>,
                        None,
                        Box::new(q) as Box<dyn PirTransport>,
                        None,
                    ))
                }
            }
        }
        .await;

        let (hint_conn, hint_conn_secondary, query_conn, query_conn_secondary) = match dial_result
        {
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
        self.hint_conn_secondary = hint_conn_secondary;
        self.query_conn = Some(query_conn);
        self.query_conn_secondary = query_conn_secondary;

        // Propagate any installed recorder to the fresh transports so
        // per-frame byte counts start flowing immediately. Done after
        // both slots are populated so a mid-connect observer can't see
        // half-installed state.
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(ref mut c) = self.hint_conn {
                c.set_metrics_recorder(Some(rec.clone()), "harmony");
            }
            if let Some(ref mut c) = self.hint_conn_secondary {
                c.set_metrics_recorder(Some(rec.clone()), "harmony");
            }
            if let Some(ref mut c) = self.query_conn {
                c.set_metrics_recorder(Some(rec.clone()), "harmony");
            }
            if let Some(ref mut c) = self.query_conn_secondary {
                c.set_metrics_recorder(Some(rec), "harmony");
            }
        }

        log::info!(
            "Connected to HarmonyPIR servers (hint pool size {}, query pool size {})",
            if self.hint_conn_secondary.is_some() { 2 } else { 1 },
            if self.query_conn_secondary.is_some() { 2 } else { 1 },
        );
        self.fire_connect(&self.hint_server_url);
        if self.hint_conn_secondary.is_some() {
            self.fire_connect(&self.hint_server_url);
        }
        self.fire_connect(&self.query_server_url);
        if self.query_conn_secondary.is_some() {
            self.fire_connect(&self.query_server_url);
        }
        self.notify_state(ConnectionState::Connected);
        Ok(())
    }

    #[tracing::instrument(level = "info", skip_all, fields(backend = "harmony"))]
    async fn disconnect(&mut self) -> PirResult<()> {
        if let Some(ref mut conn) = self.hint_conn {
            let _ = conn.close().await;
        }
        if let Some(ref mut conn) = self.hint_conn_secondary {
            let _ = conn.close().await;
        }
        if let Some(ref mut conn) = self.query_conn {
            let _ = conn.close().await;
        }
        if let Some(ref mut conn) = self.query_conn_secondary {
            let _ = conn.close().await;
        }
        self.hint_conn = None;
        self.hint_conn_secondary = None;
        self.query_conn = None;
        self.query_conn_secondary = None;
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
/// Decode UTXO entries from assembled chunk bytes.
///
/// Wire format (matches the build pipeline at
/// `build/src/build_utxo_chunks.rs::serialize_group_sorted` and the
/// reference decoder at `pir_core::codec::parse_utxo_data`):
///
///   `[varint num_utxos][per entry: 32B txid | varint vout | varint amount]`
///
/// Padding bytes after the last entry (the assembled chunk_data is a
/// `N * CHUNK_SIZE`-byte buffer; the encoded entries usually don't fill
/// it exactly) are ignored.
///
/// **Bug history (2026-05-13).** The old in-file decoder here (and in
/// `dpf.rs`) assumed fixed 40-byte slots — `[32B txid | 4B vout LE |
/// 4B amount LE]` — which silently produced garbage `vout` / `amount`
/// values from byte ranges that actually held the varint stream's
/// continuation bytes. OnionPIR's decoder (`onion.rs:1892`) and
/// `pir_core::codec::parse_utxo_data` were always correct; the
/// regression only affected DPF + HarmonyPIR.
fn decode_utxo_entries(data: &[u8]) -> Vec<UtxoEntry> {
    let mut entries = Vec::new();
    if data.is_empty() {
        return entries;
    }
    let (count, mut pos) = pir_core::codec::read_varint(data);
    for _ in 0..count {
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
    /// Merkle leakage rounds, buffered in this querier's own issue
    /// order — level 0 → N, and pass h0 → h1 within a level. Each pass
    /// appends one `IndexMerkleSiblings` / `ChunkMerkleSiblings` round
    /// tagged `server_id = 0` (HarmonyPIR Merkle has no per-server
    /// fan-out).
    ///
    /// Rounds are BUFFERED here, not recorded inline, because
    /// `verify_bucket_merkle_batch_parallel` drives two queriers
    /// concurrently on separate sockets. Recording inline would
    /// interleave INDEX- and CHUNK-Merkle rounds in wall-clock order —
    /// a timing artifact that varies run-to-run and, worse, correlates
    /// with found-vs-not-found (the CHUNK querier spends a hair more
    /// CPU building a real slot than a dummy). That makes a found
    /// query wire-distinguishable from a not-found one purely by
    /// Merkle-round order. `verify_merkle_items` drains the buffer(s)
    /// into the real recorder in a fixed INDEX-then-CHUNK sequence —
    /// matching the sequential DPF verifier — so the leakage profile
    /// stays deterministic and content-independent.
    recorded: &'a mut Vec<RoundProfile>,
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
        let request_bytes = request.len() as u64;
        // Per-group request shape — every Harmony query slot must send
        // exactly `T - 1` indices (CLAUDE.md "HarmonyPIR Per-Group
        // Request-Count Symmetry"). Capture the actual `indices.len()`
        // so a test can assert the invariant directly.
        let items_per_group: Vec<u32> =
            batch_items.iter().map(|it| it.indices.len() as u32).collect();
        let t_send = Instant::now();
        let response = self.query_conn.roundtrip(&request).await?;
        let dt_wire = t_send.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   Merkle pass (table={}, level={}): wire RTT {:?} (req {}B resp {}B)",
                table_type, level, dt_wire, request_bytes, response.len() + 4,
            );
        }
        // Buffer this pass's leakage round; `verify_merkle_items` drains
        // the buffer in a fixed INDEX-then-CHUNK order once both Merkle
        // trees finish — see `HarmonySiblingQuerier.recorded` for why
        // inline recording would leak found-vs-not-found via round order.
        let kind = match table_type {
            1 => RoundKind::ChunkMerkleSiblings { level: level as u8 },
            _ => RoundKind::IndexMerkleSiblings { level: level as u8 },
        };
        self.recorded.push(RoundProfile {
            kind,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes,
            response_bytes: (response.len() as u64).saturating_add(4),
            items: items_per_group,
        });
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

    /// Pipelined override for the same-level pass batch.
    ///
    /// Within a sibling level, different passes may hit the SAME PBC
    /// group with different items (e.g. INDEX Merkle at the INDEX
    /// Merkle Group-Symmetry collision case: two scripthashes whose
    /// cuckoo positions collide on the same PBC group). For those
    /// groups, the call pattern across passes is
    /// `build_request → build_request → process_response →
    /// process_response`, which corrupts the single-query `last_*`
    /// state slots inside `HarmonyGroup` (the second `build_request`
    /// overwrites the first's state before `process_response` ever
    /// reads it).
    ///
    /// To pipeline safely, we classify each group by its (pass0,
    /// pass1) Real/Dummy pattern and emit calls per-group:
    /// * **RealReal**  → `build_request_pair` + `process_response_pair`.
    ///   The pair API stashes both states in `pending_pair` and
    ///   consumes both atomically — exact equivalent of two sequential
    ///   `build_request`+`process_response` cycles given the same RNG
    ///   seed (verified by `harmonypir-wasm::test_pair_equiv_sequential_*`).
    /// * **RealDummy** → `build_request(t)` then `build_synthetic_dummy()`.
    ///   The dummy doesn't touch `last_*`, so pass 0's `process_response`
    ///   reads the real state correctly. Pass 1's dummy slot in
    ///   `pass_out` stays `None`.
    /// * **DummyReal** → `build_synthetic_dummy()` then `build_request(t)`.
    ///   Symmetric to the above; pass 0's slot is `None`, pass 1's is
    ///   the real row.
    /// * **DummyDummy** → two synthetic dummies, no `process_response`
    ///   at all. Both slots stay `None`.
    ///
    /// Currently specialised for `passes.len() == 2` (INDEX Merkle's
    /// `max_items_per_group_per_level = 2`). For other arities we fall
    /// back to the default serial implementation.
    async fn query_passes(
        &mut self,
        table_type: u8,
        level: usize,
        _level_bins_per_table: u32,
        passes: &[Vec<Option<u32>>],
        db_id: u8,
    ) -> PirResult<Vec<Vec<Option<Vec<u8>>>>> {
        if passes.is_empty() {
            return Ok(Vec::new());
        }
        if passes.len() == 1 {
            // Single-pass case: just call query_pass.
            let rows = self
                .query_pass(table_type, level, _level_bins_per_table, &passes[0], db_id)
                .await?;
            return Ok(vec![rows]);
        }
        if passes.len() != 2 {
            // Fallback for >2 passes — not exercised by current
            // production layouts. Default impl serialises.
            let mut out = Vec::with_capacity(passes.len());
            for p in passes {
                let rows = self
                    .query_pass(table_type, level, _level_bins_per_table, p, db_id)
                    .await?;
                out.push(rows);
            }
            return Ok(out);
        }

        let wire_level: u8 = match table_type {
            0 => 10u8.checked_add(level as u8).ok_or_else(|| {
                PirError::InvalidState(format!(
                    "INDEX sib level {} does not fit in wire byte",
                    level
                ))
            })?,
            1 => 20u8.checked_add(level as u8).ok_or_else(|| {
                PirError::InvalidState(format!(
                    "CHUNK sib level {} does not fit in wire byte",
                    level
                ))
            })?,
            other => {
                return Err(PirError::InvalidState(format!(
                    "unknown sibling table_type {}",
                    other
                )))
            }
        };

        let table_k = passes[0].len();
        if passes[1].len() != table_k {
            return Err(PirError::InvalidState(format!(
                "Merkle pipelined passes: pass 0 has {} targets but pass 1 has {}",
                table_k,
                passes[1].len()
            )));
        }

        // Per-group dispatch classification for the 2-pass case.
        #[derive(Clone, Copy)]
        enum PassPattern {
            RealReal(u32, u32),
            RealDummy(u32),
            DummyReal(u32),
            DummyDummy,
        }
        let mut patterns: Vec<PassPattern> = Vec::with_capacity(table_k);
        for g in 0..table_k {
            let p0 = passes[0][g];
            let p1 = passes[1][g];
            patterns.push(match (p0, p1) {
                (Some(t0), Some(t1)) => PassPattern::RealReal(t0, t1),
                (Some(t0), None) => PassPattern::RealDummy(t0),
                (None, Some(t1)) => PassPattern::DummyReal(t1),
                (None, None) => PassPattern::DummyDummy,
            });
        }

        // ── Build per-group request bytes for both passes ──
        let mut bytes_h0: Vec<Vec<u8>> = Vec::with_capacity(table_k);
        let mut bytes_h1: Vec<Vec<u8>> = Vec::with_capacity(table_k);

        for (g_idx, pat) in patterns.iter().enumerate() {
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

            match *pat {
                PassPattern::RealReal(t0, t1) => {
                    let pair = group.build_request_pair(t0, t1).map_err(|e| {
                        PirError::BackendState(format!(
                            "sib build_request_pair: {:?}",
                            e
                        ))
                    })?;
                    let (req_1, req_2) = pair.into_parts();
                    bytes_h0.push(req_1.request());
                    bytes_h1.push(req_2.request());
                }
                PassPattern::RealDummy(t0) => {
                    let req = group.build_request(t0).map_err(|e| {
                        PirError::BackendState(format!("sib build_request: {:?}", e))
                    })?;
                    bytes_h0.push(req.request());
                    bytes_h1.push(group.build_synthetic_dummy());
                }
                PassPattern::DummyReal(t1) => {
                    bytes_h0.push(group.build_synthetic_dummy());
                    let req = group.build_request(t1).map_err(|e| {
                        PirError::BackendState(format!("sib build_request: {:?}", e))
                    })?;
                    bytes_h1.push(req.request());
                }
                PassPattern::DummyDummy => {
                    bytes_h0.push(group.build_synthetic_dummy());
                    bytes_h1.push(group.build_synthetic_dummy());
                }
            }
        }

        // Assemble BatchItem lists and encode both wire requests.
        let batch_items_h0: Vec<BatchItem> = bytes_h0
            .iter()
            .enumerate()
            .map(|(g_idx, b)| {
                Ok(BatchItem {
                    group_id: g_idx as u8,
                    indices: bytes_to_u32_vec(b)?,
                })
            })
            .collect::<PirResult<Vec<_>>>()?;
        let batch_items_h1: Vec<BatchItem> = bytes_h1
            .iter()
            .enumerate()
            .map(|(g_idx, b)| {
                Ok(BatchItem {
                    group_id: g_idx as u8,
                    indices: bytes_to_u32_vec(b)?,
                })
            })
            .collect::<PirResult<Vec<_>>>()?;

        // round_id encodes (table_type, level, pass_idx) so audit logs
        // can disambiguate the two passes.
        let round_id_h0 = (table_type as u16) * 1000 + (level as u16) * 10;
        let round_id_h1 = round_id_h0 + 1;
        let request_h0 = encode_batch_query(wire_level, round_id_h0, db_id, &batch_items_h0);
        let request_h1 = encode_batch_query(wire_level, round_id_h1, db_id, &batch_items_h1);
        let request_h0_bytes = request_h0.len() as u64;
        let request_h1_bytes = request_h1.len() as u64;
        let items_per_group_h0: Vec<u32> = batch_items_h0
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();
        let items_per_group_h1: Vec<u32> = batch_items_h1
            .iter()
            .map(|it| it.indices.len() as u32)
            .collect();

        // ── Pipelined send / recv ──
        let t_wire = Instant::now();
        self.query_conn.send(request_h0).await?;
        self.query_conn.send(request_h1).await?;
        let resp_h0_raw = self.query_conn.recv().await?;
        let resp_h1_raw = self.query_conn.recv().await?;
        let dt_wire = t_wire.elapsed();
        if std::env::var("HARMONY_BENCH").is_ok() {
            eprintln!(
                "[HARMONY_BENCH]   Merkle pipelined passes (table={}, level={}, n_passes=2): wire {:?} (req {}B+{}B, resp {}B+{}B)",
                table_type, level, dt_wire,
                request_h0_bytes, request_h1_bytes,
                resp_h0_raw.len(), resp_h1_raw.len(),
            );
        }
        if resp_h0_raw.len() < 4 || resp_h1_raw.len() < 4 {
            return Err(PirError::Protocol(
                "Merkle pipelined sib response too short to carry length prefix".into(),
            ));
        }

        // Buffer both passes' leakage rounds in pass order (h0 then h1);
        // `verify_merkle_items` drains the buffer in a fixed
        // INDEX-then-CHUNK order — see `HarmonySiblingQuerier.recorded`.
        let kind = match table_type {
            1 => RoundKind::ChunkMerkleSiblings { level: level as u8 },
            _ => RoundKind::IndexMerkleSiblings { level: level as u8 },
        };
        self.recorded.push(RoundProfile {
            kind,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h0_bytes,
            response_bytes: resp_h0_raw.len() as u64,
            items: items_per_group_h0,
        });
        self.recorded.push(RoundProfile {
            kind,
            server_id: 0,
            db_id: Some(db_id),
            request_bytes: request_h1_bytes,
            response_bytes: resp_h1_raw.len() as u64,
            items: items_per_group_h1,
        });

        let raw_results_h0 = decode_batch_response(&resp_h0_raw[4..])?;
        let raw_results_h1 = decode_batch_response(&resp_h1_raw[4..])?;

        // ── Decode responses per-group via the matching API ──
        let mut out_h0: Vec<Option<Vec<u8>>> = vec![None; table_k];
        let mut out_h1: Vec<Option<Vec<u8>>> = vec![None; table_k];

        for (g_idx, pat) in patterns.iter().enumerate() {
            let g = g_idx as u8;
            let group = match table_type {
                0 => self.index_sib_groups.get_mut(&(level, g)),
                1 => self.chunk_sib_groups.get_mut(&(level, g)),
                _ => None,
            };
            let group = group.ok_or_else(|| {
                PirError::InvalidState(format!(
                    "sib group vanished mid-batch ({}, {})",
                    level, g
                ))
            })?;

            match *pat {
                PassPattern::RealReal(_, _) => {
                    let data_h0 = raw_results_h0.get(&g).ok_or_else(|| {
                        PirError::Protocol(format!(
                            "no pipelined sib h=0 response for group {} (table={}, level={})",
                            g, table_type, level
                        ))
                    })?;
                    let data_h1 = raw_results_h1.get(&g).ok_or_else(|| {
                        PirError::Protocol(format!(
                            "no pipelined sib h=1 response for group {} (table={}, level={})",
                            g, table_type, level
                        ))
                    })?;
                    let pair = group
                        .process_response_pair(data_h0, data_h1)
                        .map_err(|e| {
                            PirError::BackendState(format!(
                                "sib process_response_pair: {:?}",
                                e
                            ))
                        })?;
                    let (row0, row1) = pair.into_parts();
                    if row0.len() != BUCKET_MERKLE_SIB_ROW_SIZE
                        || row1.len() != BUCKET_MERKLE_SIB_ROW_SIZE
                    {
                        return Err(PirError::Protocol(format!(
                            "pipelined sib pair response has {}/{} bytes, expected {}",
                            row0.len(),
                            row1.len(),
                            BUCKET_MERKLE_SIB_ROW_SIZE
                        )));
                    }
                    out_h0[g_idx] = Some(row0);
                    out_h1[g_idx] = Some(row1);
                }
                PassPattern::RealDummy(_) => {
                    let data_h0 = raw_results_h0.get(&g).ok_or_else(|| {
                        PirError::Protocol(format!(
                            "no pipelined sib h=0 response for real-dummy group {} (table={}, level={})",
                            g, table_type, level
                        ))
                    })?;
                    let row = group.process_response(data_h0).map_err(|e| {
                        PirError::BackendState(format!(
                            "sib process_response (h=0 of real-dummy): {:?}",
                            e
                        ))
                    })?;
                    if row.len() != BUCKET_MERKLE_SIB_ROW_SIZE {
                        return Err(PirError::Protocol(format!(
                            "pipelined sib (real-dummy) response has {} bytes, expected {}",
                            row.len(),
                            BUCKET_MERKLE_SIB_ROW_SIZE
                        )));
                    }
                    out_h0[g_idx] = Some(row);
                    // out_h1 stays None.
                }
                PassPattern::DummyReal(_) => {
                    let data_h1 = raw_results_h1.get(&g).ok_or_else(|| {
                        PirError::Protocol(format!(
                            "no pipelined sib h=1 response for dummy-real group {} (table={}, level={})",
                            g, table_type, level
                        ))
                    })?;
                    let row = group.process_response(data_h1).map_err(|e| {
                        PirError::BackendState(format!(
                            "sib process_response (h=1 of dummy-real): {:?}",
                            e
                        ))
                    })?;
                    if row.len() != BUCKET_MERKLE_SIB_ROW_SIZE {
                        return Err(PirError::Protocol(format!(
                            "pipelined sib (dummy-real) response has {} bytes, expected {}",
                            row.len(),
                            BUCKET_MERKLE_SIB_ROW_SIZE
                        )));
                    }
                    out_h1[g_idx] = Some(row);
                    // out_h0 stays None.
                }
                PassPattern::DummyDummy => {
                    // Both slots stay None — caller treats this group as
                    // not participating at this level. The default
                    // implementation does the same thing.
                }
            }
        }

        Ok(vec![out_h0, out_h1])
    }
}

// ─── Kani harnesses ─────────────────────────────────────────────────────────
//
// Bounded model checking for the CHUNK Round-Presence Symmetry
// invariant (CLAUDE.md). The invariant says every HarmonyPIR INDEX
// query — found, not-found, or whale — emits a K_CHUNK-padded CHUNK
// PIR round on the wire. The structural witness lives in
// `classify_chunk_groups`: its result length is `k_chunk` regardless
// of how many real queries were passed in, and when no real queries
// are passed every entry is `Dummy`.
//
// `run_chunk_round` consumes the role list directly, so verifying
// `classify_chunk_groups` lifts to verifying the wire-batch length:
// the dispatch loop pushes one `BatchItem` per role, so the resulting
// `Vec<BatchItem>` has exactly `k_chunk` elements. Every group either
// goes through `build_request` (real) or `build_synthetic_dummy`
// (dummy) — both produce T-1 sorted indices per the existing
// "HarmonyPIR Per-Group Request-Count Symmetry" invariant — so the
// wire bytes are shape-uniform.
//
// The harnesses live behind `#[cfg(kani)]` so a normal build doesn't
// compile them. Run with `cargo kani -p pir-sdk-client`.

#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    /// **P1** — round-count uniformity. For any `(real_queries,
    /// k_chunk)`, the role list has length exactly `k_chunk`. The
    /// caller's dispatch loop in `run_chunk_round` pushes one
    /// `BatchItem` per role, so the wire batch length equals
    /// `k_chunk` regardless of `real_queries.len()`. This is the
    /// structural witness that found / not-found / whale queries
    /// all emit `k_chunk` per-group sub-queries on the wire.
    ///
    /// Bound: `k_chunk ∈ {1, 2, 3, 4}`, `real_queries.len() ∈
    /// {0, 1, 2}` with each `(group_id < k_chunk)`. Bounds are
    /// small to keep CBMC tractable; the property is a length
    /// equality so the bound is illustrative — the proof
    /// generalises by symbolic execution on each concrete `k_chunk`.
    #[kani::proof]
    #[kani::unwind(5)]
    fn classify_chunk_groups_emits_k_chunk_entries() {
        let k_chunk: u8 = kani::any();
        kani::assume(k_chunk >= 1 && k_chunk <= 4);
        let n_real: usize = kani::any();
        kani::assume(n_real <= 2);
        let mut real_queries: Vec<(u32, u8)> = Vec::with_capacity(n_real);
        for _ in 0..n_real {
            let cid: u32 = kani::any();
            let group: u8 = kani::any();
            // Restrict group_ids to the valid range so we exercise
            // the in-range branch (out-of-range is silently dropped
            // — covered separately if a regression invents a panic).
            kani::assume(group < k_chunk);
            real_queries.push((cid, group));
        }

        let roles = classify_chunk_groups(&real_queries, k_chunk);

        assert_eq!(
            roles.len(),
            k_chunk as usize,
            "CHUNK Round-Presence Symmetry P1: role list length must \
             equal k_chunk so the dispatch loop emits exactly k_chunk \
             per-group sub-queries on the wire",
        );
    }

    /// **P2** — wire indistinguishability of the all-dummy round.
    /// When `real_queries` is empty (the not-found / whale path), the
    /// role list is `[Dummy, Dummy, …, Dummy]` of length `k_chunk`.
    /// `run_chunk_round` then routes every group through
    /// `HarmonyGroup::build_synthetic_dummy`, which produces a
    /// shape-identical payload to a real `build_request` (per the
    /// existing per-group request-count symmetry). The result: a
    /// CHUNK round driven purely by dummies is byte-shape-identical
    /// to a CHUNK round with one or more real queries.
    #[kani::proof]
    #[kani::unwind(5)]
    fn classify_chunk_groups_all_dummy_when_no_real_queries() {
        let k_chunk: u8 = kani::any();
        kani::assume(k_chunk >= 1 && k_chunk <= 4);

        let roles = classify_chunk_groups(&[], k_chunk);

        assert_eq!(roles.len(), k_chunk as usize);
        for g in 0..k_chunk as usize {
            assert!(
                matches!(roles[g], ChunkGroupRole::Dummy),
                "CHUNK Round-Presence Symmetry P2: empty real_queries \
                 must produce all-Dummy roles so every group routes \
                 through build_synthetic_dummy on the wire",
            );
        }
    }

    /// Negative: a real query at a specific group must mark exactly
    /// that group as `Real`, leaving every other group as `Dummy`.
    /// Catches a hypothetical regression that mis-routes the role
    /// (e.g. off-by-one on the group index, or marking too many
    /// groups Real and shrinking the dummy padding).
    #[kani::proof]
    #[kani::unwind(5)]
    fn classify_chunk_groups_marks_only_specified_group_real() {
        let k_chunk: u8 = kani::any();
        kani::assume(k_chunk >= 1 && k_chunk <= 4);
        let target_group: u8 = kani::any();
        kani::assume(target_group < k_chunk);
        let cid: u32 = kani::any();

        let roles = classify_chunk_groups(&[(cid, target_group)], k_chunk);

        assert_eq!(roles.len(), k_chunk as usize);
        for g in 0..k_chunk as usize {
            if g == target_group as usize {
                assert!(
                    matches!(roles[g], ChunkGroupRole::Real(c) if c == cid),
                    "target group must carry the supplied chunk_id",
                );
            } else {
                assert!(
                    matches!(roles[g], ChunkGroupRole::Dummy),
                    "non-target groups must remain Dummy",
                );
            }
        }
    }

    /// Out-of-range `group_id`s are silently dropped — same
    /// observable behaviour as the pre-refactor
    /// `for g in 0..k_chunk` loop, which never queried groups
    /// `>= k_chunk` even if they were in the HashMap. Captured here
    /// so a future regression that panics or grows the role list
    /// fires loudly.
    #[kani::proof]
    #[kani::unwind(5)]
    fn classify_chunk_groups_drops_out_of_range_groups() {
        let k_chunk: u8 = kani::any();
        kani::assume(k_chunk >= 1 && k_chunk <= 3);
        let bad_group: u8 = kani::any();
        kani::assume(bad_group >= k_chunk);
        let cid: u32 = kani::any();

        let roles = classify_chunk_groups(&[(cid, bad_group)], k_chunk);

        assert_eq!(roles.len(), k_chunk as usize);
        for g in 0..k_chunk as usize {
            assert!(
                matches!(roles[g], ChunkGroupRole::Dummy),
                "out-of-range group_id must not poison any in-range \
                 role — every group stays Dummy",
            );
        }
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

    // ─── Merkle INDEX item-count symmetry invariant ─────────────────
    //
    // Mirrors the DPF tests in `dpf.rs`. CLAUDE.md "Merkle INDEX
    // Item-Count Symmetry" requires every INDEX query to emit exactly
    // `INDEX_CUCKOO_NUM_HASHES` Merkle items regardless of outcome.
    // For HarmonyPIR specifically, the extra probe costs one extra
    // wire round per `found@h=0` query (the two cuckoo positions are
    // separate per-h batch queries, not a single XOR'd response like
    // DPF/Onion), so the loop in `query_single` must NOT early-exit
    // on match.

    fn h_idx_bin(bin_index: u32) -> IndexBinTrace {
        IndexBinTrace {
            pbc_group: 3,
            bin_index,
            bin_content: vec![0u8; 16],
        }
    }

    fn h_chk_bin(bin_index: u32) -> ChunkBinTrace {
        ChunkBinTrace {
            pbc_group: 5,
            bin_index,
            bin_content: vec![0u8; 32],
        }
    }

    #[test]
    fn items_from_trace_found_at_h0_emits_two() {
        let trace = QueryTraces {
            index_bins: vec![h_idx_bin(100), h_idx_bin(200)],
            matched_index_idx: Some(0),
            chunk_bins: vec![h_chk_bin(50)],
        };
        let items = items_from_trace(&trace);
        assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
        assert_eq!(items[0].chunk_bin_indices.len(), 1);
        assert_eq!(items[1].chunk_bin_indices.len(), 0);
    }

    #[test]
    fn items_from_trace_found_at_h1_emits_two() {
        let trace = QueryTraces {
            index_bins: vec![h_idx_bin(100), h_idx_bin(200)],
            matched_index_idx: Some(1),
            chunk_bins: vec![h_chk_bin(50)],
        };
        let items = items_from_trace(&trace);
        assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
        // Chunks always live on items[0], regardless of which INDEX
        // position matched. Mirrors the dpf::items_from_trace shape.
        assert_eq!(items[0].chunk_bin_indices.len(), 1);
        assert_eq!(items[1].chunk_bin_indices.len(), 0);
    }

    #[test]
    fn items_from_trace_not_found_emits_two() {
        let trace = QueryTraces {
            index_bins: vec![h_idx_bin(100), h_idx_bin(200)],
            matched_index_idx: None,
            chunk_bins: vec![],
        };
        let items = items_from_trace(&trace);
        assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
        assert_eq!(items[0].chunk_bin_indices.len(), 0);
        assert_eq!(items[1].chunk_bin_indices.len(), 0);
    }

    #[test]
    fn items_from_trace_whale_emits_two_no_chunks() {
        let trace = QueryTraces {
            index_bins: vec![h_idx_bin(100), h_idx_bin(200)],
            matched_index_idx: Some(0),
            chunk_bins: vec![],
        };
        let items = items_from_trace(&trace);
        assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
        assert_eq!(items[0].chunk_bin_indices.len(), 0);
        assert_eq!(items[1].chunk_bin_indices.len(), 0);
    }

    // ─── Leakage recorder wiring ────────────────────────────────────────────

    /// `record_round` emits to an installed buffering recorder.
    #[test]
    fn leakage_recorder_records_via_helper_harmony() {
        use pir_sdk::BufferingLeakageRecorder;

        let rec = Arc::new(BufferingLeakageRecorder::new());
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_leakage_recorder(Some(rec.clone()));

        // T - 1 indices per slot is the HarmonyPIR per-group invariant —
        // a hypothetical T=8 here yields items[g] = 7.
        client.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(3),
            request_bytes: 1234,
            response_bytes: 5678,
            items: vec![7; 75],
        });

        let snap = rec.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(matches!(snap[0].kind, RoundKind::Index));
        assert_eq!(snap[0].server_id, 0); // 0 = query server for harmony
        assert_eq!(snap[0].items.len(), 75);
        assert!(snap[0].items.iter().all(|&x| x == 7));
    }

    /// `set_leakage_recorder(None)` silences subsequent emissions.
    #[test]
    fn leakage_recorder_uninstall_silences_harmony() {
        use pir_sdk::BufferingLeakageRecorder;

        let rec = Arc::new(BufferingLeakageRecorder::new());
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_leakage_recorder(Some(rec.clone()));
        client.set_leakage_recorder(None);

        client.record_round(RoundProfile {
            kind: RoundKind::HarmonyHintRefresh,
            server_id: 1,
            db_id: Some(0),
            request_bytes: 100,
            response_bytes: 200,
            items: vec![1; 75],
        });

        assert!(rec.is_empty());
    }

    /// Driving a real `fetch_legacy_info` through `MockTransport` emits
    /// exactly one `Info` round on server 1 (hint server).
    #[tokio::test]
    async fn leakage_recorder_captures_info_round_end_to_end_harmony() {
        use crate::transport::mock::MockTransport;
        use pir_sdk::BufferingLeakageRecorder;

        let rec = Arc::new(BufferingLeakageRecorder::new());
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_leakage_recorder(Some(rec.clone()));

        // Valid REQ_HARMONY_GET_INFO (0x40) response shape mirrors
        // REQ_GET_INFO: [4B len=19][1B variant=0x40][4B index_bins]
        // [4B chunk_bins][1B index_k][1B chunk_k][8B tag_seed].
        let mut hint_mock = MockTransport::new("wss://mock-hint");
        let mut info_resp = Vec::with_capacity(23);
        info_resp.extend_from_slice(&19u32.to_le_bytes());
        info_resp.push(0x40); // RESP_HARMONY_INFO
        info_resp.extend_from_slice(&1024u32.to_le_bytes()); // index_bins
        info_resp.extend_from_slice(&2048u32.to_le_bytes()); // chunk_bins
        info_resp.push(75); // index_k
        info_resp.push(80); // chunk_k
        info_resp.extend_from_slice(&0u64.to_le_bytes()); // tag_seed
        assert_eq!(info_resp.len(), 23);
        hint_mock.enqueue_response(info_resp);

        client.connect_with_transport(
            Box::new(hint_mock),
            Box::new(MockTransport::new("wss://mock-query")),
        );
        let _info = client.fetch_legacy_info().await.unwrap();

        let snap = rec.snapshot();
        assert_eq!(snap.len(), 1, "expected exactly one Info round");
        let r = &snap[0];
        assert!(matches!(r.kind, RoundKind::Info));
        assert_eq!(r.server_id, 1, "harmony info goes to hint server");
        assert_eq!(r.db_id, None);
        // request: REQ_HARMONY_GET_INFO is `[4B len=1][1B 0x40]` = 5 bytes.
        assert_eq!(r.request_bytes, 5);
        // response: 23 bytes on the wire (4-byte prefix + 19-byte payload).
        assert_eq!(r.response_bytes, 23);
        assert!(r.items.is_empty());
    }

    /// Leakage and metrics recorders coexist independently.
    #[tokio::test]
    async fn leakage_and_metrics_recorders_are_independent_harmony() {
        use crate::transport::mock::MockTransport;
        use pir_sdk::{AtomicMetrics, BufferingLeakageRecorder};

        let leakage = Arc::new(BufferingLeakageRecorder::new());
        let metrics = Arc::new(AtomicMetrics::new());
        let mut client = HarmonyClient::new("wss://mock-hint", "wss://mock-query");
        client.set_leakage_recorder(Some(leakage.clone()));
        client.set_metrics_recorder(Some(metrics.clone()));

        let mut hint_mock = MockTransport::new("wss://mock-hint");
        let mut info_resp = Vec::with_capacity(23);
        info_resp.extend_from_slice(&19u32.to_le_bytes());
        info_resp.push(0x40);
        info_resp.extend_from_slice(&1024u32.to_le_bytes());
        info_resp.extend_from_slice(&2048u32.to_le_bytes());
        info_resp.push(75);
        info_resp.push(80);
        info_resp.extend_from_slice(&0u64.to_le_bytes());
        hint_mock.enqueue_response(info_resp);

        client.connect_with_transport(
            Box::new(hint_mock),
            Box::new(MockTransport::new("wss://mock-query")),
        );
        let _info = client.fetch_legacy_info().await.unwrap();

        assert_eq!(leakage.len(), 1);
        let snap = metrics.snapshot();
        assert!(snap.bytes_sent > 0);
        assert!(snap.bytes_received > 0);
    }
}
