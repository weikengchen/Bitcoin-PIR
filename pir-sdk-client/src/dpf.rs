//! DPF-PIR client implementation.
//!
//! This implements the two-level Batch PIR protocol using Distributed Point Functions.
//! Queries are split across two servers; XORing their responses reveals the actual data.

#[cfg(not(target_arch = "wasm32"))]
use crate::connection::WsConnection;
use crate::merkle_verify::{
    fetch_tree_tops, verify_bucket_merkle_batch_dpf, BucketMerkleItem,
};
use crate::protocol::{decode_catalog, encode_request, REQ_GET_DB_CATALOG, RESP_DB_CATALOG};
use crate::transport::PirTransport;
use async_trait::async_trait;
use libdpf::Dpf;
use pir_sdk::{
    compute_sync_plan, merge_delta_batch, BucketRef, ConnectionState, DatabaseCatalog,
    DatabaseInfo, DatabaseKind, Instant, LeakageRecorder, PirBackendType, PirClient, PirError,
    PirMetrics, PirResult, QueryResult, RoundKind, RoundProfile, ScriptHash, StateListener,
    SyncPlan, SyncProgress, SyncResult, SyncStep, UtxoEntry,
};
use std::sync::Arc;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Number of cuckoo hash functions for index level.
const INDEX_CUCKOO_NUM_HASHES: usize = 2;

/// Number of cuckoo hash functions for chunk level.
const CHUNK_CUCKOO_NUM_HASHES: usize = 2;

/// Index slot size: 8B tag + 4B start_chunk_id + 1B num_chunks = 13 bytes.
const INDEX_SLOT_SIZE: usize = 13;

/// Slots per index bin.
const INDEX_SLOTS_PER_BIN: usize = 4;

// NOTE: `INDEX_RESULT_SIZE = INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE` is
// not tracked as a constant here — the XOR'd bin content arrives from
// the server already sized, and the two component constants are what
// downstream code indexes against. The equivalent constant lives in
// `runtime/src/eval.rs` for the server-side table layout.

/// Tag size in bytes.
const TAG_SIZE: usize = 8;

/// Chunk data size.
const CHUNK_SIZE: usize = 40;

/// Chunk slot size: 4B chunk_id + 40B data.
const CHUNK_SLOT_SIZE: usize = 4 + CHUNK_SIZE;

/// Slots per chunk bin.
const CHUNK_SLOTS_PER_BIN: usize = 3;

// NOTE: `CHUNK_RESULT_SIZE = CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE` is
// not tracked as a constant here for the same reason as
// `INDEX_RESULT_SIZE` above — see the comment there.

/// Number of PBC hash functions.
const NUM_HASHES: usize = 3;

// ─── Pure request-shape helpers (extracted for Kani verification) ──────────

/// Build the K × INDEX_CUCKOO_NUM_HASHES matrix of `alpha` values for a
/// single DPF INDEX request. Each `alpha` is the bin index that
/// `dpf.gen(alpha, dpf_n)` will hide inside its keys: the assigned
/// group's cuckoo positions for the real query, fresh random bins for
/// every other group. The K-padding invariant — every wire request
/// covers all K groups, regardless of match outcome — is a structural
/// property of this matrix shape.
///
/// Pulled out as a pure function so a Kani harness can prove the
/// shape exhaustively for every (k, assigned_group, my_locs) shape in
/// a small bound. The caller (`query_index_level`) feeds each `alpha`
/// into `dpf.gen` separately; the SHAPE of the resulting key Vec
/// equals the SHAPE of this alpha matrix.
///
/// `next_random_bin` is an `FnMut` returning a u64 in `[0, u64::MAX]`
/// — the function applies `% bins` itself to bound the alpha into
/// `[0, bins)`. Production callers wrap their `SimpleRng::next_u64`;
/// the Kani harness wraps `kani::any::<u64>()`, which sidesteps
/// modelling `splitmix64` symbolically.
pub(crate) fn build_index_alphas(
    k: usize,
    assigned_group: usize,
    my_locs: &[u64; INDEX_CUCKOO_NUM_HASHES],
    bins: usize,
    mut next_random_bin: impl FnMut() -> u64,
) -> Vec<Vec<u64>> {
    let mut alphas = Vec::with_capacity(k);
    for b in 0..k {
        let mut group = Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES);
        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            let alpha = if b == assigned_group {
                my_locs[h]
            } else {
                next_random_bin() % bins as u64
            };
            group.push(alpha);
        }
        alphas.push(group);
    }
    alphas
}

// ─── Multi-query INDEX PBC plan (Option B index_max closure) ───────────────

/// Per-scripthash placement output from the INDEX PBC planner.
/// `round_id` indexes into the `rounds` Vec returned alongside; `pbc_group`
/// is the group within `[0, k)` the scripthash was assigned to in that
/// round. Both INDEX bins (h = 0, 1) and both INDEX Merkle items for this
/// scripthash inherit `pbc_group` — that coupling is what
/// `index_max_items_per_group_per_level = 2` relies on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IndexPlanSlot {
    pub round_id: usize,
    pub pbc_group: usize,
}

/// Plan a multi-round INDEX PBC layout for a batch of scripthashes.
///
/// Wraps `pir_core::pbc::pbc_plan_rounds` over each scripthash's three
/// candidate groups and returns BOTH views the call site needs:
///
/// * `rounds[r]` — list of `(sh_idx, pbc_group)` placements for round `r`.
///   Used by the alpha-matrix builder to know which group each round's
///   real query lives in.
/// * `placement[sh_idx]` — `(round_id, pbc_group)` for each scripthash.
///   Used by the per-scripthash decode + Merkle-trace builder so it
///   knows which round's response to read and which group its Merkle
///   items inherit.
///
/// The plan is deterministic over the scripthashes and `k`; with N=1
/// it always returns one round placing the single scripthash in
/// `derive_groups_3(_, k)[0]`, exactly matching the pre-Option-B
/// single-query behaviour. For N≥2 the planner spreads collisions
/// across alternate candidate groups, driving the wire-observable
/// `max_items_per_group_per_level` to 2 regardless of input.
pub(crate) fn plan_index_pbc_rounds(
    candidate_groups: &[[usize; NUM_HASHES]],
    k: usize,
) -> (Vec<Vec<(usize, usize)>>, Vec<IndexPlanSlot>) {
    let rounds = pir_core::pbc::pbc_plan_rounds(candidate_groups, k, NUM_HASHES, 500);
    let mut placement = vec![
        IndexPlanSlot { round_id: 0, pbc_group: 0 };
        candidate_groups.len()
    ];
    for (round_id, round) in rounds.iter().enumerate() {
        for &(sh_idx, pbc_group) in round {
            placement[sh_idx] = IndexPlanSlot { round_id, pbc_group };
        }
    }
    (rounds, placement)
}

/// Build the `K × INDEX_CUCKOO_NUM_HASHES` alpha matrix for ONE PBC round
/// of a batched DPF INDEX request. `placed_locs[g]` carries the cuckoo
/// positions of the scripthash placed in group `g` in this round; groups
/// with no placement get fresh random dummy bins (the K-padding invariant).
///
/// Reduces to the single-query `build_index_alphas` shape when exactly one
/// group has a placement; the batched version generalises to any subset
/// of groups holding real queries within a single round. Same `Vec<Vec<u64>>`
/// shape and same per-group cardinality (= INDEX_CUCKOO_NUM_HASHES), so the
/// wire-format DPF key matrix is identical.
pub(crate) fn build_index_alphas_batched(
    k: usize,
    placed_locs: &[Option<[u64; INDEX_CUCKOO_NUM_HASHES]>],
    bins: usize,
    mut next_random_bin: impl FnMut() -> u64,
) -> Vec<Vec<u64>> {
    debug_assert_eq!(placed_locs.len(), k, "placed_locs must have length k");
    let mut alphas = Vec::with_capacity(k);
    for g in 0..k {
        let mut group = Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES);
        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            let alpha = match placed_locs[g] {
                Some(locs) => locs[h],
                None => next_random_bin() % bins as u64,
            };
            group.push(alpha);
        }
        alphas.push(group);
    }
    alphas
}

// ─── Merkle verification traces ─────────────────────────────────────────────

/// Record of one INDEX cuckoo bin we checked during a query.
///
/// Populated by `query_index_level` for every cuckoo position it probes.
/// Consumed by the Merkle verifier to prove the bin content (and therefore
/// the FOUND/NOT-FOUND conclusion) is consistent with the published root.
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
/// needs for Merkle verification. Built regardless of whether verification
/// will run — the overhead is negligible (we already have the XOR'd bins).
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

/// Build `BucketMerkleItem`s for one query from its internal trace —
/// emits one item per probed INDEX cuckoo bin, with CHUNK bins attached
/// only to the matched INDEX item (or none, if not matched). This layout
/// preserves the 🔒 Merkle INDEX Item-Count Symmetry invariant: every
/// query contributes exactly `INDEX_CUCKOO_NUM_HASHES` items regardless
/// of found / not-found / whale.
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
/// inspector-populated fields (`index_bins`, `chunk_bins`,
/// `matched_index_idx`). Symmetric with [`items_from_trace`] — same
/// per-query-item layout, same ordering — but works on the public type
/// so callers can reverify persisted results via
/// [`DpfClient::verify_merkle_batch_for_results`].
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
/// the `item_index → query_index` backmapping. `None` results contribute
/// zero items (nothing to verify).
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

/// Convert an internal `IndexBinTrace` / `ChunkBinTrace` into the public
/// `BucketRef` shape. The public type widens `pbc_group` to `u32` and
/// drops the internal `ChunkBinTrace` vs `IndexBinTrace` distinction —
/// the discriminant is already encoded by which vec the ref lives on
/// (`QueryResult.index_bins` vs `QueryResult.chunk_bins`).
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

// ─── DPF Client ─────────────────────────────────────────────────────────────

/// DPF-PIR client for two-server PIR queries.
///
/// DPF-PIR is a non-colluding two-server PIR protocol based on
/// Distributed Point Functions. The client splits each query into two
/// DPF keys and sends one to each server; XORing the two servers'
/// responses reveals the target row. Neither server alone learns the
/// queried index, provided the servers don't collude.
///
/// # Examples
///
/// ```ignore
/// use pir_sdk_client::{DpfClient, PirClient, ScriptHash};
///
/// #[tokio::main]
/// async fn main() {
///     let mut client = DpfClient::new(
///         "ws://server0:8091",
///         "ws://server1:8092",
///     );
///     client.connect().await.unwrap();
///
///     let script_hash: ScriptHash = [0u8; 20]; // your HASH160 script hash
///     let result = client.sync(&[script_hash], None).await.unwrap();
///
///     if let Some(qr) = &result.results[0] {
///         for entry in &qr.entries {
///             println!("UTXO: {} sats at {}:{}",
///                 entry.amount_sats,
///                 hex::encode(entry.txid),
///                 entry.vout);
///         }
///         println!("Balance: {} sats", qr.total_balance());
///     }
/// }
/// ```
///
/// Delta sync — pass the last synced height to avoid re-querying
/// unchanged rows:
///
/// ```ignore
/// # use pir_sdk_client::{DpfClient, PirClient, ScriptHash};
/// # #[tokio::main]
/// # async fn main() {
/// # let mut client = DpfClient::new("ws://s0", "ws://s1");
/// # client.connect().await.unwrap();
/// # let script_hashes: Vec<ScriptHash> = vec![[0u8; 20]];
/// let result = client.sync(&script_hashes, None).await.unwrap();
/// let height = result.synced_height;
///
/// // Later: only query what's changed since `height`.
/// let updated = client.sync(&script_hashes, Some(height)).await.unwrap();
/// # }
/// ```
pub struct DpfClient {
    server0_url: String,
    server1_url: String,
    conn0: Option<Box<dyn PirTransport>>,
    conn1: Option<Box<dyn PirTransport>>,
    catalog: Option<DatabaseCatalog>,
    /// Optional observer invoked on every `ConnectionState` transition.
    /// `Arc` instead of `Box` so one listener can be shared between a
    /// DPF client, a Harmony client, a logger, etc. — mirrors how the
    /// WASM side stores an `Rc<RefCell<Closure>>` behind a `Wasm32Shim`.
    state_listener: Option<Arc<dyn StateListener>>,
    /// Optional metrics recorder. When installed, fires
    /// `on_connect` / `on_disconnect` lifecycle events and
    /// `on_query_start` / `on_query_end` per-batch callbacks from the
    /// client layer, plus per-frame `on_bytes_sent` /
    /// `on_bytes_received` from the two transports below (wired on
    /// connect via `set_metrics_recorder`).
    metrics_recorder: Option<Arc<dyn PirMetrics>>,
    /// Optional leakage recorder. When installed, every transport-level
    /// roundtrip emits a structured [`RoundProfile`] capturing the
    /// wire-observable shape (round kind, server id, request/response
    /// bytes, per-group or per-query item counts). Used by the
    /// differential-testing harness in `PLAN_LEAKAGE_VERIFICATION.md`.
    /// Independent of `metrics_recorder` — install neither, either, or
    /// both.
    leakage_recorder: Option<Arc<dyn LeakageRecorder>>,
}

impl DpfClient {
    /// Create a new DPF client.
    pub fn new(server0_url: &str, server1_url: &str) -> Self {
        Self {
            server0_url: server0_url.to_string(),
            server1_url: server1_url.to_string(),
            conn0: None,
            conn1: None,
            catalog: None,
            state_listener: None,
            metrics_recorder: None,
            leakage_recorder: None,
        }
    }

    /// Install (or replace) a metrics recorder.
    ///
    /// The recorder receives:
    /// * Per-frame `on_bytes_sent` / `on_bytes_received` callbacks from
    ///   each of the two transports (both labelled `"dpf"`).
    /// * Per-batch `on_query_start` / `on_query_end` callbacks fired at
    ///   [`query_batch`](Self::query_batch) entry / exit.
    /// * `on_connect` on successful [`connect`] / `on_disconnect` on
    ///   [`disconnect`].
    ///
    /// If the client is already connected when the recorder is
    /// installed, the recorder is propagated to both transports
    /// immediately (so it starts seeing byte traffic on the next
    /// frame); otherwise it's held until `connect` wires the fresh
    /// transports.
    ///
    /// Pass `None` to uninstall — subsequent callbacks are silenced,
    /// and the transports are told to drop their recorder too.
    pub fn set_metrics_recorder(&mut self, recorder: Option<Arc<dyn PirMetrics>>) {
        self.metrics_recorder = recorder.clone();
        if let Some(ref mut c) = self.conn0 {
            c.set_metrics_recorder(recorder.clone(), "dpf");
        }
        if let Some(ref mut c) = self.conn1 {
            c.set_metrics_recorder(recorder, "dpf");
        }
    }

    /// Fire `on_query_start` on the installed recorder, if any. Returns
    /// the `Instant` captured at the start of the query so a later
    /// [`fire_query_end`](Self::fire_query_end) can compute the
    /// wall-clock duration. Returns `None` when no recorder is
    /// installed — the timing path is short-circuited so the
    /// no-recorder case stays at zero overhead.
    fn fire_query_start(&self, db_id: u8, num_queries: usize) -> Option<Instant> {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_query_start("dpf", db_id, num_queries);
            Some(Instant::now())
        } else {
            None
        }
    }

    /// Fire `on_query_end` on the installed recorder, if any. The
    /// `started_at` value comes from the matching
    /// [`fire_query_start`](Self::fire_query_start) call (i.e. it is
    /// `Some` exactly when a recorder was installed at start time);
    /// `None` produces a `Duration::ZERO`, which the
    /// `AtomicMetrics` recorder treats as a best-effort observation
    /// (see the `Duration::ZERO` semantics on
    /// [`PirMetrics::on_query_end`]).
    fn fire_query_end(
        &self,
        db_id: u8,
        num_queries: usize,
        success: bool,
        started_at: Option<Instant>,
    ) {
        if let Some(rec) = &self.metrics_recorder {
            let duration = started_at.map(|t| t.elapsed()).unwrap_or_default();
            rec.on_query_end("dpf", db_id, num_queries, success, duration);
        }
    }

    /// Fire `on_connect` for a given URL. Both transports are labelled
    /// `"dpf"`, but we still pass the URL through so a recorder can
    /// distinguish server0 from server1.
    fn fire_connect(&self, url: &str) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_connect("dpf", url);
        }
    }

    /// Fire `on_disconnect` on the installed recorder, if any.
    fn fire_disconnect(&self) {
        if let Some(rec) = &self.metrics_recorder {
            rec.on_disconnect("dpf");
        }
    }

    /// Install (or replace) a leakage recorder.
    ///
    /// Independent of [`set_metrics_recorder`](Self::set_metrics_recorder)
    /// — leakage recorders observe per-round structural events
    /// (round kind, item counts, per-server bytes), while metrics
    /// recorders aggregate byte / latency counters. Tests installing a
    /// [`BufferingLeakageRecorder`](pir_sdk::BufferingLeakageRecorder)
    /// can call [`take_profile`](pir_sdk::BufferingLeakageRecorder::take_profile)
    /// after a query to inspect the recorded sequence of
    /// [`RoundProfile`]s.
    ///
    /// Pass `None` to uninstall — subsequent rounds are silenced.
    pub fn set_leakage_recorder(&mut self, recorder: Option<Arc<dyn LeakageRecorder>>) {
        self.leakage_recorder = recorder;
    }

    /// Emit a [`RoundProfile`] to the installed leakage recorder, if any.
    /// No-op when no recorder is installed — the typical case in
    /// production.
    fn record_round(&self, round: RoundProfile) {
        if let Some(rec) = &self.leakage_recorder {
            rec.record_round("dpf", round);
        }
    }

    /// Register a callback that will be invoked on every
    /// [`ConnectionState`] transition (`Connecting` → `Connected` /
    /// `Disconnected`). Replaces any previously registered listener —
    /// only one listener per client; share one `Arc<dyn StateListener>`
    /// across multiple clients if you need a fan-in sink.
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
    /// designed around: state-machine tests can hand in a [`MockTransport`]
    /// (or any other impl) and drive the client without opening a real
    /// WebSocket. `PirClient::is_connected` returns `true` after this call,
    /// so `fetch_catalog` / `sync_with_plan` work as usual.
    ///
    /// [`MockTransport`]: crate::transport::MockTransport
    #[tracing::instrument(level = "debug", skip_all, fields(backend = "dpf"))]
    pub fn connect_with_transport(
        &mut self,
        conn0: Box<dyn PirTransport>,
        conn1: Box<dyn PirTransport>,
    ) {
        self.conn0 = Some(conn0);
        self.conn1 = Some(conn1);
        // Propagate any installed recorder to the injected transports so
        // state-machine tests see per-frame byte counts just like the
        // URL-driven `connect()` path does.
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(ref mut c) = self.conn0 {
                c.set_metrics_recorder(Some(rec.clone()), "dpf");
            }
            if let Some(ref mut c) = self.conn1 {
                c.set_metrics_recorder(Some(rec), "dpf");
            }
        }
        // Same `Connected` event a URL-driven `connect()` fires — lets
        // injection-driven tests exercise the state listener without a
        // real WebSocket handshake.
        self.fire_connect(&self.server0_url);
        self.fire_connect(&self.server1_url);
        self.notify_state(ConnectionState::Connected);
    }

    /// Fetch server info and build catalog entry for legacy servers.
    async fn fetch_legacy_info(&mut self) -> PirResult<DatabaseInfo> {
        let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;

        // REQ_GET_INFO = 0x01
        let request = encode_request(0x01, &[]);
        let request_bytes = request.len() as u64;
        let response = conn0.roundtrip(&request).await?;
        // `roundtrip` strips the 4-byte length prefix on success, so the
        // observable response payload size on the wire is `response.len() + 4`
        // — matches what `request.len()` reports (which still includes the
        // outgoing 4-byte prefix).
        let response_bytes = (response.len() as u64).saturating_add(4);
        self.record_round(RoundProfile {
            kind: RoundKind::Info,
            server_id: 0,
            db_id: None,
            request_bytes,
            response_bytes,
            items: Vec::new(),
        });

        if response.is_empty() || response[0] != 0x01 {
            return Err(PirError::Protocol("invalid info response".into()));
        }

        // Parse: [4B index_bins][4B chunk_bins][1B index_k][1B chunk_k][8B tag_seed]
        if response.len() < 19 {
            return Err(PirError::Protocol("info response too short".into()));
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

    /// Execute a single query step for a batch of script hashes.
    ///
    /// Runs PIR queries for each script hash, then — if the target database
    /// publishes a per-bucket Merkle tree (`DatabaseInfo::has_bucket_merkle`) —
    /// performs a single batched Merkle verification covering every INDEX
    /// cuckoo position inspected (two per not-found query) and every CHUNK bin
    /// that returned data. Items whose Merkle proof fails are zeroed (treated
    /// as unverified; callers should treat them as an unknown/error state).
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(
            backend = "dpf",
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
        let mut results: Vec<Option<QueryResult>> = Vec::with_capacity(script_hashes.len());
        let mut traces: Vec<QueryTraces> = Vec::with_capacity(script_hashes.len());

        log::info!(
            "[PIR-AUDIT] execute_step: db_id={}, name={}, height={}, queries={}, has_bucket_merkle={}",
            db_info.db_id,
            db_info.name,
            db_info.height,
            script_hashes.len(),
            db_info.has_bucket_merkle
        );

        // Phase 1: batched INDEX via PBC plan. Drives one or more
        // K-padded DPF INDEX rounds covering all scripthashes; each
        // scripthash's two INDEX Merkle items inherit a unique-per-batch
        // `pbc_group`, so `index_max_items_per_group_per_level = 2`
        // independently of the batch's collision pattern.
        let index_outcomes = self
            .query_index_phase_batched(script_hashes, db_info)
            .await?;

        // Phase 2: per-scripthash CHUNK + result assembly. Mirrors the
        // legacy `query_single` body for the post-INDEX path: found
        // queries fetch their chunks; not-found / whale queries still
        // emit a K_CHUNK-padded dummy CHUNK round (CHUNK Round-Presence
        // Symmetry).
        for (i, (found_info, index_bins, matched_idx)) in index_outcomes.into_iter().enumerate() {
            let mut q_traces = QueryTraces {
                index_bins,
                matched_index_idx: matched_idx,
                chunk_bins: Vec::new(),
            };

            let (start_chunk_id, num_chunks, is_whale) = match found_info {
                Some((start, num, whale)) => (start, num, whale),
                None => {
                    let _ = self.query_chunk_level(&[], db_info).await?;
                    log::info!(
                        "[PIR-AUDIT] CHUNK round-presence padding: not-found query #{} issued 1 dummy CHUNK round",
                        i,
                    );
                    results.push(None);
                    traces.push(q_traces);
                    continue;
                }
            };

            if num_chunks == 0 {
                let _ = self.query_chunk_level(&[], db_info).await?;
                log::info!(
                    "[PIR-AUDIT] CHUNK round-presence padding: whale query #{} issued 1 dummy CHUNK round",
                    i,
                );
                results.push(Some(QueryResult {
                    entries: Vec::new(),
                    is_whale,
                    merkle_verified: true,
                    raw_chunk_data: None,
                    index_bins: Vec::new(),
                    chunk_bins: Vec::new(),
                    matched_index_idx: None,
                }));
                traces.push(q_traces);
                continue;
            }

            let chunk_ids: Vec<u32> =
                (start_chunk_id..start_chunk_id + num_chunks as u32).collect();
            let (chunk_data, chunk_bins) = self.query_chunk_level(&chunk_ids, db_info).await?;
            q_traces.chunk_bins = chunk_bins;
            let entries = decode_utxo_entries(&chunk_data);

            results.push(Some(QueryResult {
                entries,
                is_whale,
                merkle_verified: true,
                raw_chunk_data: if db_info.kind.is_delta() {
                    Some(chunk_data)
                } else {
                    None
                },
                index_bins: Vec::new(),
                chunk_bins: Vec::new(),
                matched_index_idx: None,
            }));
            traces.push(q_traces);
        }

        if db_info.has_bucket_merkle {
            self.run_merkle_verification(&mut results, &traces, db_info)
                .await?;
        } else {
            log::info!(
                "[PIR-AUDIT] Merkle verification SKIPPED (db_id={} has no bucket Merkle)",
                db_info.db_id
            );
        }

        Ok(results)
    }

    /// Build `BucketMerkleItem`s from collected query traces and verify them
    /// in one padded batch.
    ///
    /// On any bin failing verification, the corresponding query is coerced to
    /// `Some(QueryResult::merkle_failed())` (empty entries, `merkle_verified =
    /// false`) so the caller can distinguish verification failure from a
    /// genuine not-found.
    ///
    /// Implementation is a thin shim over the two helpers that also power
    /// the standalone [`verify_merkle_batch_for_results`](Self::verify_merkle_batch_for_results)
    /// API — items come from the per-query [`QueryTraces`], but the verifier
    /// itself is shared.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "dpf", db_id = db_info.db_id)
    )]
    async fn run_merkle_verification(
        &mut self,
        results: &mut [Option<QueryResult>],
        traces: &[QueryTraces],
        db_info: &DatabaseInfo,
    ) -> PirResult<()> {
        // Log the per-query outcome/item-count summary — kept here (not in
        // `collect_merkle_items_from_traces`) because this is the path that
        // feeds `[PIR-AUDIT]` audit logs. The `verify_merkle_batch_for_results`
        // path rebuilds items from already-audited query results, so it
        // doesn't need to re-log the bin counts.
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
                "[PIR-AUDIT] Merkle: query #{} {} — verifying {} index bins + {} chunk bins",
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
                    log::info!("[PIR-AUDIT] Merkle PASSED for query #{}", qi);
                    // merkle_verified is already `true` by construction in query_single.
                }
                Some(false) => {
                    log::warn!(
                        "[PIR-AUDIT] Merkle FAILED for query #{}: \
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

    /// Shared verifier backend used by both [`run_merkle_verification`]
    /// (inline, over fresh `QueryTraces`) and
    /// [`verify_merkle_batch_for_results`](Self::verify_merkle_batch_for_results)
    /// (standalone, over persisted `QueryResult.index_bins/chunk_bins`).
    ///
    /// Runs the full Merkle pipeline: `REQ_BUCKET_MERKLE_TREE_TOPS` fetch
    /// on server 0, then [`verify_bucket_merkle_batch_dpf`] (K-padded
    /// sibling rounds across both servers, XOR fold, walk to root).
    /// Returns one verdict per query:
    /// * `None`    — no items attached (query skipped verification).
    /// * `Some(true)`  — all attached items verified.
    /// * `Some(false)` — at least one item failed.
    ///
    /// Padding invariant: per-item Merkle work is uniform by construction
    /// — callers must always attach `INDEX_CUCKOO_NUM_HASHES` INDEX items
    /// per query, regardless of found/not-found (see CLAUDE.md "Merkle
    /// INDEX Item-Count Symmetry").
    async fn verify_merkle_items(
        &mut self,
        items: &[BucketMerkleItem],
        item_to_query: &[usize],
        num_queries: usize,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<bool>>> {
        if items.is_empty() {
            log::info!("[PIR-AUDIT] Merkle: no items to verify — nothing to do");
            return Ok(vec![None; num_queries]);
        }

        // Fetch tree-tops blob (server 0 only — both servers share it).
        let leakage = self.leakage_recorder.clone();
        let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
        let tree_tops =
            fetch_tree_tops(conn0, db_info.db_id, leakage.as_ref(), "dpf", 0).await?;

        // Disjoint field borrows: `self.conn0` and `self.conn1` are separate
        // Option fields, so we can borrow both mutably at once.
        let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
        let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
        let index_k = db_info.index_k as usize;
        let chunk_k = db_info.chunk_k as usize;
        let per_item = verify_bucket_merkle_batch_dpf(
            conn0,
            conn1,
            items,
            db_info.index_bins,
            db_info.chunk_bins,
            index_k,
            chunk_k,
            db_info.db_id,
            &tree_tops,
            leakage,
        )
        .await?;

        // Aggregate per-item outcomes back to per-query verdicts:
        // a query passes iff ALL its items pass.
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

    /// Query a single script hash against a database.
    ///
    /// Also returns `QueryTraces` describing every INDEX/CHUNK cuckoo bin we
    /// inspected, so the caller (`execute_step`) can run per-bucket Merkle
    /// verification if `DatabaseInfo::has_bucket_merkle` is set.
    async fn query_single(
        &mut self,
        script_hash: &ScriptHash,
        db_info: &DatabaseInfo,
    ) -> PirResult<(Option<QueryResult>, QueryTraces)> {
        // Step 1: Index-level PIR query
        let (found_info, index_bins, matched_idx) =
            self.query_index_level(script_hash, db_info).await?;

        let mut traces = QueryTraces {
            index_bins,
            matched_index_idx: matched_idx,
            chunk_bins: Vec::new(),
        };

        let (start_chunk_id, num_chunks, is_whale) = match found_info {
            Some((start, num, whale)) => (start, num, whale),
            None => {
                // 🔒 CHUNK Round-Presence Symmetry (CLAUDE.md): not-found
                // queries still issue one K_CHUNK-padded CHUNK PIR round so
                // the server cannot infer found-vs-not-found from CHUNK
                // round absence. Empty `chunk_ids` triggers the dummy-round
                // path inside `query_chunk_level`. Returned data is
                // discarded (no chunk_bins recorded into `traces`, so
                // CHUNK Merkle items are not synthesised — the residual
                // Merkle item-count leak is a separately-tracked decision).
                let _ = self.query_chunk_level(&[], db_info).await?;
                log::info!(
                    "[PIR-AUDIT] CHUNK round-presence padding: not-found query issued 1 dummy CHUNK round"
                );
                return Ok((None, traces));
            }
        };

        if num_chunks == 0 {
            // Whale (matched tag but no chunks to retrieve). Same padding
            // as not-found — see invariant comment in the `None` arm above.
            let _ = self.query_chunk_level(&[], db_info).await?;
            log::info!(
                "[PIR-AUDIT] CHUNK round-presence padding: whale query issued 1 dummy CHUNK round"
            );
            return Ok((
                Some(QueryResult {
                    entries: Vec::new(),
                    is_whale,
                    // Optimistic default — `run_merkle_verification` flips
                    // this to `false` if the INDEX proof fails.
                    merkle_verified: true,
                    raw_chunk_data: None,
                    // Inspector fields stay empty here — only the inspector
                    // path (`query_batch_with_inspector`) populates them
                    // from `traces`.
                    index_bins: Vec::new(),
                    chunk_bins: Vec::new(),
                    matched_index_idx: None,
                }),
                traces,
            ));
        }

        // Step 2: Chunk-level PIR queries (multi-round)
        let chunk_ids: Vec<u32> = (start_chunk_id..start_chunk_id + num_chunks as u32).collect();
        let (chunk_data, chunk_bins) = self.query_chunk_level(&chunk_ids, db_info).await?;
        traces.chunk_bins = chunk_bins;

        // Step 3: Decode UTXO entries
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
                // Inspector fields stay empty here — only the inspector
                // path (`query_batch_with_inspector`) copies them from
                // `traces` into the result.
                index_bins: Vec::new(),
                chunk_bins: Vec::new(),
                matched_index_idx: None,
            }),
            traces,
        ))
    }

    /// Execute index-level PIR query.
    ///
    /// Returns `(found_info, index_bins, matched_idx)`:
    /// * `found_info` — `Some((start_chunk, num_chunks, is_whale))` on match.
    /// * `index_bins` — one trace per cuckoo position we actually inspected.
    ///   For NOT-FOUND this is always exactly `INDEX_CUCKOO_NUM_HASHES` bins
    ///   (required for the absence proof). For FOUND we stop probing as soon
    ///   as the tag is located, matching the TS client.
    /// * `matched_idx` — index into `index_bins` of the matching bin.
    ///
    /// Padding invariant: the underlying PIR batch always covers all K groups
    /// regardless of match outcome (CLAUDE.md privacy requirement).
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(backend = "dpf", db_id = db_info.db_id)
    )]
    async fn query_index_level(
        &mut self,
        script_hash: &ScriptHash,
        db_info: &DatabaseInfo,
    ) -> PirResult<(Option<(u32, u8, bool)>, Vec<IndexBinTrace>, Option<usize>)> {
        let k = db_info.index_k as usize;
        let bins = db_info.index_bins as usize;
        let dpf_n = db_info.dpf_n_index;
        let tag_seed = db_info.tag_seed;
        let master_seed = pir_core::params::INDEX_PARAMS.master_seed;

        // Compute candidate groups for our script hash.
        //
        // NOTE: the server REPLICATES every scripthash into all 3 candidate
        // groups at build time (see `build/src/build_cuckoo_generic.rs:87-90`
        // and `gen_4_build_merkle.rs:236-239`). Any one of the 3 groups is
        // therefore sufficient to retrieve an entry. For a single-query round
        // we just pick the first group — matching the reference Rust client
        // (`runtime/src/bin/client.rs:246`), the web TS client
        // (`web/src/client.ts` via `planRounds` which reduces to `candGroups[0]`
        // at N=1), and the Python plugin. When this function is ever extended
        // to batch multiple scripthashes in a single DPF request (like
        // `OnionClient::query_index_level`), replace this with
        // `pbc_plan_rounds` to balance load across groups; the padding
        // invariant (K queries per round) and the Merkle INDEX item-count
        // symmetry (`INDEX_CUCKOO_NUM_HASHES = 2` items per query) must be
        // preserved.
        let my_groups = pir_core::hash::derive_groups_3(script_hash, k);
        let assigned_group = my_groups[0];

        // Compute cuckoo hash locations in the assigned group
        let mut my_locs_arr = [0u64; INDEX_CUCKOO_NUM_HASHES];
        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            let key = pir_core::hash::derive_cuckoo_key(master_seed, assigned_group, h);
            my_locs_arr[h] = pir_core::hash::cuckoo_hash(script_hash, key, bins) as u64;
        }
        let my_locs = my_locs_arr.to_vec();

        log::info!(
            "[PIR-AUDIT] INDEX query: script_hash={}, assigned_group={}, k={}, bins={}, cuckoo_positions={:?} (K-padded to {} groups)",
            format_hash_short(script_hash),
            assigned_group,
            k,
            bins,
            my_locs,
            k
        );

        // Build the K × INDEX_CUCKOO_NUM_HASHES alpha matrix via the
        // pure shape-builder (so a Kani harness can prove the K-padding
        // invariant exhaustively for every input shape) and feed each
        // alpha through `dpf.gen` to produce the wire keys.
        let dpf = Dpf::with_default_key();
        let mut rng = SimpleRng::new();
        let alphas = build_index_alphas(
            k,
            assigned_group,
            &my_locs_arr,
            bins,
            || rng.next_u64(),
        );

        let mut s0_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(k);
        let mut s1_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(k);
        for group_alphas in &alphas {
            let mut s0_group = Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES);
            let mut s1_group = Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES);
            for &alpha in group_alphas {
                let (k0, k1) = dpf.gen(alpha, dpf_n);
                s0_group.push(k0.to_bytes());
                s1_group.push(k1.to_bytes());
            }
            s0_keys.push(s0_group);
            s1_keys.push(s1_group);
        }

        // Send to both servers
        let req0 = encode_batch_query(0x11, 0, 0, db_info.db_id, &s0_keys);
        let req1 = encode_batch_query(0x11, 0, 0, db_info.db_id, &s1_keys);

        // Capture wire shape before `send` consumes the request buffers.
        // Per-group item counts come from the actual nested Vec lengths so
        // the leakage profile reflects the wire payload, not constants the
        // test might also be wrong about.
        let req0_bytes = req0.len() as u64;
        let req1_bytes = req1.len() as u64;
        let items_s0: Vec<u32> = s0_keys.iter().map(|g| g.len() as u32).collect();
        let items_s1: Vec<u32> = s1_keys.iter().map(|g| g.len() as u32).collect();

        let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
        conn0.send(req0).await?;

        let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
        conn1.send(req1).await?;

        // Receive responses
        let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
        let resp0 = conn0.recv().await?;

        let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
        let resp1 = conn1.recv().await?;

        self.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(db_info.db_id),
            request_bytes: req0_bytes,
            response_bytes: resp0.len() as u64,
            items: items_s0,
        });
        self.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 1,
            db_id: Some(db_info.db_id),
            request_bytes: req1_bytes,
            response_bytes: resp1.len() as u64,
            items: items_s1,
        });

        // Parse responses
        let results0 = decode_batch_response(&resp0[4..])?; // skip length prefix
        let results1 = decode_batch_response(&resp1[4..])?;

        // Compute expected tag
        let my_tag = pir_core::hash::compute_tag(tag_seed, script_hash);

        // XOR results for assigned group and look for our entry.
        // Record every bin we inspect so the Merkle verifier can cover both
        // cuckoo positions uniformly — see CLAUDE.md "Merkle INDEX item-count
        // symmetry" (we emit INDEX_CUCKOO_NUM_HASHES items per query regardless
        // of found/not-found to avoid leaking presence via pass count).
        let mut index_bins: Vec<IndexBinTrace> = Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES);
        let mut found: Option<(u32, u8, bool)> = None;
        let mut matched_idx: Option<usize> = None;

        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            let mut bin_content = results0[assigned_group][h].clone();
            xor_into(&mut bin_content, &results1[assigned_group][h]);

            let bin_index = my_locs[h] as u32;
            let pos = index_bins.len();
            index_bins.push(IndexBinTrace {
                pbc_group: assigned_group,
                bin_index,
                bin_content: bin_content.clone(),
            });

            if found.is_some() {
                // Already matched earlier; still probe this position so the
                // Merkle item count is uniform across found/not-found.
                log::info!(
                    "[PIR-AUDIT] INDEX extra probe at cuckoo h={} (group={}, bin={}) — tracked for Merkle uniformity",
                    h, assigned_group, bin_index
                );
                continue;
            }

            if let Some((start_chunk, num_chunks)) =
                find_entry_in_index_result(&bin_content, my_tag)
            {
                let is_whale = num_chunks == 0;
                log::info!(
                    "[PIR-AUDIT] INDEX FOUND at cuckoo h={} (group={}, bin={}): start_chunk={}, num_chunks={}, whale={}",
                    h, assigned_group, bin_index, start_chunk, num_chunks, is_whale
                );
                matched_idx = Some(pos);
                found = Some((start_chunk, num_chunks as u8, is_whale));
            } else {
                log::info!(
                    "[PIR-AUDIT] INDEX miss at cuckoo h={} (group={}, bin={})",
                    h, assigned_group, bin_index
                );
            }
        }

        if found.is_none() {
            log::info!(
                "[PIR-AUDIT] INDEX NOT FOUND: verified {} cuckoo positions at group {} — all {} bins will be Merkle-verified for absence proof",
                index_bins.len(),
                assigned_group,
                index_bins.len()
            );
        }

        Ok((found, index_bins, matched_idx))
    }

    /// Batched INDEX phase for Option-B `index_max_items_per_group_per_level`
    /// closure. Drives one or more PBC rounds (each a single K-padded DPF
    /// INDEX request per server) covering `script_hashes.len()` queries
    /// in total, then decodes per-scripthash results out of the per-round
    /// XOR responses.
    ///
    /// At N=1 the planner places the single scripthash in
    /// `derive_groups_3(_, k)[0]` and emits one round, exactly matching
    /// the legacy single-query behaviour of [`query_index_level`]. At
    /// N≥2 the planner spreads colliding-`[0]` scripthashes across their
    /// alternate candidate groups, so every round has at most one
    /// real query per group and each scripthash's two INDEX Merkle
    /// items inherit a unique-per-batch `pbc_group`. The wire-observable
    /// `max_items_per_group_per_level` is then 2 (independent of which
    /// scripthashes were queried), which is exactly the closure target
    /// for the `index_max_items_per_group_per_level` axis admitted in
    /// `proofs/easycrypt/Leakage.ec`.
    ///
    /// Per-server wire round count = `n_pbc_rounds`; for typical
    /// batches with `N ≤ k` the planner packs into 1 round.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(backend = "dpf", db_id = db_info.db_id, num_queries = script_hashes.len())
    )]
    async fn query_index_phase_batched(
        &mut self,
        script_hashes: &[ScriptHash],
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<(Option<(u32, u8, bool)>, Vec<IndexBinTrace>, Option<usize>)>> {
        let k = db_info.index_k as usize;
        let bins = db_info.index_bins as usize;
        let dpf_n = db_info.dpf_n_index;
        let tag_seed = db_info.tag_seed;
        let master_seed = pir_core::params::INDEX_PARAMS.master_seed;
        let n = script_hashes.len();

        // PBC plan over candidate groups. The placement view tells us
        // each scripthash's `(round_id, pbc_group)` so we know which
        // round's response to read and which group its Merkle items
        // inherit; the rounds view is what the alpha matrix needs.
        let candidate_groups: Vec<[usize; NUM_HASHES]> = script_hashes
            .iter()
            .map(|sh| pir_core::hash::derive_groups_3(sh, k))
            .collect();
        let (rounds, placement) = plan_index_pbc_rounds(&candidate_groups, k);

        log::info!(
            "[PIR-AUDIT] INDEX batched query: {} queries planned into {} PBC round(s) (K={})",
            n, rounds.len(), k,
        );

        // Pre-compute each scripthash's cuckoo positions in ITS PLANNED
        // group. The cuckoo key is keyed on `pbc_group`, so a scripthash
        // routed to its [1] gets a different bin than at its [0]. This
        // matches what the server stores at build time (the build script
        // replicates entries to all 3 candidate groups, each indexed by
        // its group-specific cuckoo key).
        let mut my_locs_per_sh: Vec<[u64; INDEX_CUCKOO_NUM_HASHES]> = Vec::with_capacity(n);
        for (sh_idx, sh) in script_hashes.iter().enumerate() {
            let pbc_group = placement[sh_idx].pbc_group;
            let mut locs = [0u64; INDEX_CUCKOO_NUM_HASHES];
            for h in 0..INDEX_CUCKOO_NUM_HASHES {
                let key = pir_core::hash::derive_cuckoo_key(master_seed, pbc_group, h);
                locs[h] = pir_core::hash::cuckoo_hash(sh, key, bins) as u64;
            }
            my_locs_per_sh.push(locs);
        }

        // Per-scripthash output buffers.
        let mut found_info: Vec<Option<(u32, u8, bool)>> = vec![None; n];
        let mut index_bins_per_sh: Vec<Vec<IndexBinTrace>> =
            (0..n).map(|_| Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES)).collect();
        let mut matched_idx_per_sh: Vec<Option<usize>> = vec![None; n];

        let dpf = Dpf::with_default_key();
        let mut rng = SimpleRng::new();

        for (round_id, round) in rounds.iter().enumerate() {
            // Build placed_locs[g] for this round.
            let mut placed_locs: Vec<Option<[u64; INDEX_CUCKOO_NUM_HASHES]>> =
                (0..k).map(|_| None).collect();
            for &(sh_idx, pbc_group) in round {
                placed_locs[pbc_group] = Some(my_locs_per_sh[sh_idx]);
            }

            // Build alpha matrix and DPF keys (same shape every round).
            let alphas = build_index_alphas_batched(
                k,
                &placed_locs,
                bins,
                || rng.next_u64(),
            );
            let mut s0_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(k);
            let mut s1_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(k);
            for group_alphas in &alphas {
                let mut s0_group = Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES);
                let mut s1_group = Vec::with_capacity(INDEX_CUCKOO_NUM_HASHES);
                for &alpha in group_alphas {
                    let (k0, k1) = dpf.gen(alpha, dpf_n);
                    s0_group.push(k0.to_bytes());
                    s1_group.push(k1.to_bytes());
                }
                s0_keys.push(s0_group);
                s1_keys.push(s1_group);
            }

            // Wire format identical to the single-query path —
            // `encode_batch_query` packs the K × INDEX_CUCKOO_NUM_HASHES
            // matrix unchanged. round_id encodes the PBC round so a
            // future server update could distinguish multi-round batches
            // for telemetry; today's server ignores it for INDEX.
            let req0 = encode_batch_query(0x11, 0, round_id as u16, db_info.db_id, &s0_keys);
            let req1 = encode_batch_query(0x11, 0, round_id as u16, db_info.db_id, &s1_keys);

            let req0_bytes = req0.len() as u64;
            let req1_bytes = req1.len() as u64;
            let items_s0: Vec<u32> = s0_keys.iter().map(|g| g.len() as u32).collect();
            let items_s1: Vec<u32> = s1_keys.iter().map(|g| g.len() as u32).collect();

            let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
            conn0.send(req0).await?;
            let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
            conn1.send(req1).await?;
            let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
            let resp0 = conn0.recv().await?;
            let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
            let resp1 = conn1.recv().await?;

            self.record_round(RoundProfile {
                kind: RoundKind::Index,
                server_id: 0,
                db_id: Some(db_info.db_id),
                request_bytes: req0_bytes,
                response_bytes: resp0.len() as u64,
                items: items_s0,
            });
            self.record_round(RoundProfile {
                kind: RoundKind::Index,
                server_id: 1,
                db_id: Some(db_info.db_id),
                request_bytes: req1_bytes,
                response_bytes: resp1.len() as u64,
                items: items_s1,
            });

            let results0 = decode_batch_response(&resp0[4..])?;
            let results1 = decode_batch_response(&resp1[4..])?;

            // Decode each scripthash placed in THIS round.
            for &(sh_idx, pbc_group) in round {
                let sh = &script_hashes[sh_idx];
                let my_tag = pir_core::hash::compute_tag(tag_seed, sh);
                let my_locs = my_locs_per_sh[sh_idx];

                for h in 0..INDEX_CUCKOO_NUM_HASHES {
                    let mut bin_content = results0[pbc_group][h].clone();
                    xor_into(&mut bin_content, &results1[pbc_group][h]);

                    let bin_index = my_locs[h] as u32;
                    let pos = index_bins_per_sh[sh_idx].len();
                    index_bins_per_sh[sh_idx].push(IndexBinTrace {
                        pbc_group,
                        bin_index,
                        bin_content: bin_content.clone(),
                    });

                    if found_info[sh_idx].is_some() {
                        log::info!(
                            "[PIR-AUDIT] INDEX[sh={}] extra probe at h={} (group={}, bin={}) — tracked for Merkle uniformity",
                            sh_idx, h, pbc_group, bin_index,
                        );
                        continue;
                    }

                    if let Some((start_chunk, num_chunks)) =
                        find_entry_in_index_result(&bin_content, my_tag)
                    {
                        let is_whale = num_chunks == 0;
                        log::info!(
                            "[PIR-AUDIT] INDEX[sh={}] FOUND at h={} (group={}, bin={}): start_chunk={}, num_chunks={}, whale={}",
                            sh_idx, h, pbc_group, bin_index, start_chunk, num_chunks, is_whale,
                        );
                        matched_idx_per_sh[sh_idx] = Some(pos);
                        found_info[sh_idx] = Some((start_chunk, num_chunks as u8, is_whale));
                    } else {
                        log::info!(
                            "[PIR-AUDIT] INDEX[sh={}] miss at h={} (group={}, bin={})",
                            sh_idx, h, pbc_group, bin_index,
                        );
                    }
                }
            }
        }

        Ok((0..n)
            .map(|i| (found_info[i], std::mem::take(&mut index_bins_per_sh[i]), matched_idx_per_sh[i]))
            .collect())
    }

    /// Execute chunk-level PIR queries (multi-round).
    ///
    /// Returns `(chunk_data, chunk_bins)`:
    /// * `chunk_data` — assembled raw chunk bytes in the order of `chunk_ids`.
    /// * `chunk_bins` — per-chunk (pbc_group, bin_index, bin_content) for every
    ///   chunk we actually located. The `bin_content` is the XOR-reconstructed
    ///   full bin (all `CHUNK_SLOTS_PER_BIN` slots), which is what the per-bucket
    ///   Merkle tree commits to.
    ///
    /// Padding invariants:
    /// 1. Each round emits exactly K_CHUNK DPF queries regardless of how
    ///    many real chunks that round carries (per-round PBC padding).
    /// 2. **CHUNK Round-Presence Symmetry** (CLAUDE.md): when `chunk_ids`
    ///    is empty (not-found / whale callers), still issue exactly one
    ///    K_CHUNK-padded round so the server cannot infer found-vs-not-found
    ///    from absence of CHUNK traffic. The dummy round's response is
    ///    discarded.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(backend = "dpf", db_id = db_info.db_id)
    )]
    async fn query_chunk_level(
        &mut self,
        chunk_ids: &[u32],
        db_info: &DatabaseInfo,
    ) -> PirResult<(Vec<u8>, Vec<ChunkBinTrace>)> {
        let k = db_info.chunk_k as usize;
        let bins = db_info.chunk_bins as usize;
        let dpf_n = db_info.dpf_n_chunk;
        let master_seed = pir_core::params::CHUNK_PARAMS.master_seed;

        // Plan multi-round chunk retrieval. When the caller passed an
        // empty `chunk_ids` list (not-found or whale path), force one
        // empty round so we still emit a K_CHUNK-padded DPF batch on
        // the wire — see invariant 2 in the doc comment above. The
        // padding lives in the small pure helper
        // `pad_chunk_rounds_for_presence` so we can Kani-verify the
        // `result.len() >= 1` postcondition in isolation.
        let planned = plan_chunk_rounds(chunk_ids, k);
        let was_empty = planned.is_empty();
        let rounds = pad_chunk_rounds_for_presence(planned);
        if was_empty {
            log::info!(
                "[PIR-AUDIT] CHUNK round-presence padding: chunk_ids empty → \
                 emitting 1 dummy K_CHUNK-padded round (all-random alphas)"
            );
        }

        log::info!(
            "[PIR-AUDIT] CHUNK phase: {} chunks across {} rounds, k={}, bins={} (each round K_CHUNK-padded to {} groups)",
            chunk_ids.len(),
            rounds.len(),
            k,
            bins,
            k
        );

        let mut all_data = Vec::new();
        let mut chunk_data_map: std::collections::HashMap<u32, Vec<u8>> =
            std::collections::HashMap::new();
        // One trace per chunk successfully located; keyed by chunk_id so later
        // loss-order preservation matches `chunk_ids`.
        let mut chunk_trace_map: std::collections::HashMap<u32, ChunkBinTrace> =
            std::collections::HashMap::new();

        for (round_id, round) in rounds.iter().enumerate() {
            // Generate DPF keys for this round
            let dpf = Dpf::with_default_key();
            let mut rng = SimpleRng::new();

            let mut s0_keys: Vec<Vec<Vec<u8>>> = vec![Vec::new(); k];
            let mut s1_keys: Vec<Vec<Vec<u8>>> = vec![Vec::new(); k];

            // Track which chunk is in which group for this round
            let mut group_to_chunk: std::collections::HashMap<usize, u32> =
                std::collections::HashMap::new();

            for &(chunk_id, group_id) in round {
                group_to_chunk.insert(group_id, chunk_id);
            }

            // Per-group, per-cuckoo-hash bin index that real queries will hit.
            // We need these later to record (group, bin_index) for each chunk
            // we actually find.
            let mut real_locs: std::collections::HashMap<(usize, usize), u32> =
                std::collections::HashMap::new();

            for g in 0..k {
                for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                    let alpha = if let Some(&chunk_id) = group_to_chunk.get(&g) {
                        let key = pir_core::hash::derive_cuckoo_key(master_seed, g, h);
                        let loc = pir_core::hash::cuckoo_hash_int(chunk_id, key, bins) as u64;
                        real_locs.insert((g, h), loc as u32);
                        loc
                    } else {
                        rng.next_u64() % bins as u64
                    };

                    let (k0, k1) = dpf.gen(alpha, dpf_n);
                    s0_keys[g].push(k0.to_bytes());
                    s1_keys[g].push(k1.to_bytes());
                }
            }

            // Send to both servers
            let req0 = encode_batch_query(0x21, 1, round_id as u16, db_info.db_id, &s0_keys);
            let req1 = encode_batch_query(0x21, 1, round_id as u16, db_info.db_id, &s1_keys);

            // Capture wire shape before `send` consumes the request buffers.
            // CHUNK item counts vary per-group (admitted leak — reveals UTXO
            // count for found queries); recording the actual lengths is what
            // makes the leakage profile capture that variation.
            let req0_bytes = req0.len() as u64;
            let req1_bytes = req1.len() as u64;
            let items_s0: Vec<u32> = s0_keys.iter().map(|g| g.len() as u32).collect();
            let items_s1: Vec<u32> = s1_keys.iter().map(|g| g.len() as u32).collect();

            let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
            conn0.send(req0).await?;

            let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
            conn1.send(req1).await?;

            // Receive responses
            let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
            let resp0 = conn0.recv().await?;

            let conn1 = self.conn1.as_mut().ok_or(PirError::NotConnected)?;
            let resp1 = conn1.recv().await?;

            self.record_round(RoundProfile {
                kind: RoundKind::Chunk,
                server_id: 0,
                db_id: Some(db_info.db_id),
                request_bytes: req0_bytes,
                response_bytes: resp0.len() as u64,
                items: items_s0,
            });
            self.record_round(RoundProfile {
                kind: RoundKind::Chunk,
                server_id: 1,
                db_id: Some(db_info.db_id),
                request_bytes: req1_bytes,
                response_bytes: resp1.len() as u64,
                items: items_s1,
            });

            // Parse and XOR results
            let results0 = decode_batch_response(&resp0[4..])?;
            let results1 = decode_batch_response(&resp1[4..])?;

            // Extract chunk data for each chunk in this round
            for &(chunk_id, group_id) in round {
                let mut found_any = false;
                for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                    let mut bin_content = results0[group_id][h].clone();
                    xor_into(&mut bin_content, &results1[group_id][h]);

                    if find_chunk_in_result(&bin_content, chunk_id).is_some() {
                        // Slice the actual chunk payload for decoding.
                        let data = find_chunk_in_result(&bin_content, chunk_id)
                            .expect("find_chunk_in_result returned Some above")
                            .to_vec();
                        let bin_index = *real_locs.get(&(group_id, h)).ok_or_else(|| {
                            PirError::InvalidState(format!(
                                "missing recorded loc for chunk_id={} group={} h={}",
                                chunk_id, group_id, h
                            ))
                        })?;
                        chunk_data_map.insert(chunk_id, data);
                        chunk_trace_map.insert(
                            chunk_id,
                            ChunkBinTrace {
                                pbc_group: group_id,
                                bin_index,
                                bin_content,
                            },
                        );
                        log::info!(
                            "[PIR-AUDIT] CHUNK FOUND: chunk_id={}, group={}, bin={}, cuckoo_h={}",
                            chunk_id, group_id, bin_index, h
                        );
                        found_any = true;
                        break;
                    }
                }
                if !found_any {
                    log::warn!(
                        "[PIR-AUDIT] CHUNK MISSING: chunk_id={}, group={} (no cuckoo position matched)",
                        chunk_id, group_id
                    );
                }
            }
        }

        // Assemble chunk data + traces in the order of `chunk_ids`.
        let mut chunk_bins = Vec::with_capacity(chunk_ids.len());
        for chunk_id in chunk_ids {
            if let Some(data) = chunk_data_map.get(chunk_id) {
                all_data.extend_from_slice(data);
            }
            if let Some(trace) = chunk_trace_map.remove(chunk_id) {
                chunk_bins.push(trace);
            }
        }

        Ok((all_data, chunk_bins))
    }

    /// The two server URLs this client was configured with, in
    /// `(server0, server1)` order. Useful for display-only surfaces that
    /// want to show "connected to …" without reconstructing the URLs
    /// from caller state.
    pub fn server_urls(&self) -> (&str, &str) {
        (&self.server0_url, &self.server1_url)
    }

    /// Run a batch of PIR queries against `db_id` and return the raw
    /// per-query results **with inspector state populated**, deferring
    /// Merkle verification to a later
    /// [`verify_merkle_batch_for_results`](Self::verify_merkle_batch_for_results)
    /// call.
    ///
    /// # Shape vs. the trait-level `query_batch`
    ///
    /// The `PirClient::query_batch` method runs Merkle verification
    /// inline and collapses failed proofs to
    /// `Some(QueryResult::merkle_failed())`, so the inspector fields on
    /// its returned `QueryResult`s stay empty (the hot path keeps the
    /// trace off the public type). This method is the opposite:
    ///
    /// * Every successful query (found, not-found, or whale) returns
    ///   `Some(QueryResult)` with `index_bins` / `chunk_bins` /
    ///   `matched_index_idx` populated from the query's internal
    ///   `QueryTraces`. `None` entries should not occur in practice —
    ///   protocol errors propagate via `Err`.
    /// * `matched_index_idx == None && entries.is_empty()` encodes
    ///   "not found" (the caller must still honour the
    ///   `INDEX_CUCKOO_NUM_HASHES` padding in `index_bins` for a valid
    ///   absence proof — that invariant is preserved end-to-end by
    ///   `query_index_level`).
    /// * `merkle_verified` is `true` — Merkle was **not** attempted.
    ///   Callers that care MUST pass the results to
    ///   `verify_merkle_batch_for_results`, which returns the real
    ///   verdicts.
    ///
    /// # 🔒 Padding invariant
    ///
    /// The underlying PIR batch is unchanged — K=75 INDEX / K_CHUNK=80
    /// CHUNK groups per round, random dummy DPF keys fill empty slots.
    /// This method only changes whether the client further requests
    /// Merkle siblings, not what the server sees at the query layer.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "dpf", db_id, num_queries = script_hashes.len())
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
            .ok_or_else(|| PirError::DatabaseNotFound(db_id))?
            .clone();

        let mut results: Vec<Option<QueryResult>> = Vec::with_capacity(script_hashes.len());
        for script_hash in script_hashes {
            let (qr, trace) = self.query_single(script_hash, &db_info).await?;

            // Translate the trace into public `BucketRef`s. For not-found
            // we synthesise an empty `QueryResult` so the inspector state
            // isn't lost to the `None` return convention.
            let with_inspector = match qr {
                Some(mut r) => {
                    r.index_bins = trace.index_bins.iter().map(index_trace_to_bucket_ref).collect();
                    r.chunk_bins = trace.chunk_bins.iter().map(chunk_trace_to_bucket_ref).collect();
                    r.matched_index_idx = trace.matched_index_idx;
                    Some(r)
                }
                None => {
                    // NOT FOUND — emit an empty, inspector-populated
                    // QueryResult so callers can verify absence via
                    // `verify_merkle_batch_for_results`. Sentinel values:
                    // `entries.is_empty()`, `!is_whale`,
                    // `matched_index_idx.is_none()`, and (by the symmetry
                    // invariant) `index_bins.len() == INDEX_CUCKOO_NUM_HASHES`.
                    let mut r = QueryResult::empty();
                    r.index_bins = trace.index_bins.iter().map(index_trace_to_bucket_ref).collect();
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
    /// returned by [`query_batch_with_inspector`](Self::query_batch_with_inspector)
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
    /// caller supplies items built from INDEX_CUCKOO_NUM_HASHES probes
    /// per query, and the shared verifier pads each level's sibling
    /// batch to 25 siblings (see CLAUDE.md "Query Padding").
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "dpf", db_id, num_results = results.len())
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
            .ok_or_else(|| PirError::DatabaseNotFound(db_id))?
            .clone();

        // If the database doesn't publish bucket Merkle, "verify" is a
        // no-op — mirrors `execute_step`'s skip branch so callers can
        // always call `verify_merkle_batch_for_results` without needing
        // to pre-check `has_bucket_merkle` first. Matches the
        // `QueryResult::merkle_verified` semantics ("no failure
        // detected").
        if !db_info.has_bucket_merkle {
            log::info!(
                "[PIR-AUDIT] verify_merkle_batch_for_results SKIPPED: db_id={} has no bucket Merkle",
                db_id
            );
            return Ok(vec![true; results.len()]);
        }

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
    /// through every step of the computed [`SyncPlan`]. Intended for UI
    /// surfaces (terminal spinner, JS `onProgress` callback) that want
    /// granular feedback on multi-step sync chains.
    ///
    /// Progress events fire in this order:
    /// 1. Per step, `on_step_start(step_index, total_steps, description)`
    ///    where `description` is the [`SyncStep::name`]
    ///    (e.g. `"full @940611"` or `"delta 940611→944000"`).
    /// 2. Per step, `on_step_progress(step_index, 1.0)` once the step's
    ///    PIR + Merkle work returns (step granularity — sub-step progress
    ///    isn't wired through the current `execute_step` because the
    ///    inner loop is bounded by `script_hashes.len()` × K and driven
    ///    synchronously).
    /// 3. Per step, `on_step_complete(step_index)`.
    /// 4. Once all steps succeed, `on_complete(synced_height)`.
    /// 5. On any error, `on_error(&e)` before the error is propagated.
    ///
    /// Padding invariants are preserved — progress is purely
    /// observational and doesn't change what's sent on the wire.
    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(backend = "dpf", num_queries = script_hashes.len(), last_height = ?last_height)
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
                    .ok_or_else(|| PirError::DatabaseNotFound(step.db_id))?
                    .clone();

                let step_results = self.execute_step(script_hashes, step, &db_info).await?;

                // Single coarse tick per step — see doc comment above for why
                // finer granularity isn't wired yet.
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
}

#[async_trait]
impl PirClient for DpfClient {
    fn backend_type(&self) -> PirBackendType {
        PirBackendType::Dpf
    }

    #[tracing::instrument(level = "info", skip_all, fields(backend = "dpf", server0 = %self.server0_url, server1 = %self.server1_url))]
    async fn connect(&mut self) -> PirResult<()> {
        log::info!(
            "Connecting to servers: {}, {}",
            self.server0_url,
            self.server1_url
        );
        self.notify_state(ConnectionState::Connecting);

        // Dial both servers in parallel. On native we use `tokio::try_join!`
        // (runs on the tokio reactor); on wasm32 we use
        // `futures::future::try_join` (runs on the browser's single-threaded
        // event loop via `wasm-bindgen-futures`). Both complete when the
        // second handshake finishes, short-circuiting on the first error.
        #[cfg(not(target_arch = "wasm32"))]
        let dial_result: PirResult<(Box<dyn PirTransport>, Box<dyn PirTransport>)> = async {
            let (c0, c1) = tokio::try_join!(
                WsConnection::connect(&self.server0_url),
                WsConnection::connect(&self.server1_url),
            )?;
            Ok((
                Box::new(c0) as Box<dyn PirTransport>,
                Box::new(c1) as Box<dyn PirTransport>,
            ))
        }
        .await;
        #[cfg(target_arch = "wasm32")]
        let dial_result: PirResult<(Box<dyn PirTransport>, Box<dyn PirTransport>)> = async {
            use crate::wasm_transport::WasmWebSocketTransport;
            let (c0, c1) = futures::future::try_join(
                WasmWebSocketTransport::connect(&self.server0_url),
                WasmWebSocketTransport::connect(&self.server1_url),
            )
            .await?;
            Ok((
                Box::new(c0) as Box<dyn PirTransport>,
                Box::new(c1) as Box<dyn PirTransport>,
            ))
        }
        .await;

        let (conn0, conn1) = match dial_result {
            Ok(v) => v,
            Err(e) => {
                // Handshake failed — fall back to `Disconnected`, not
                // `Connecting`, so observers don't get stuck on an
                // intermediate state if they didn't install a catch-all.
                self.notify_state(ConnectionState::Disconnected);
                return Err(e);
            }
        };

        self.conn0 = Some(conn0);
        self.conn1 = Some(conn1);

        // Propagate any installed recorder to the fresh transports so
        // per-frame byte counts start flowing immediately. Done *after*
        // both `conn0`/`conn1` slots are populated so a mid-connect
        // observer can't see half-installed state.
        if let Some(rec) = self.metrics_recorder.clone() {
            if let Some(ref mut c) = self.conn0 {
                c.set_metrics_recorder(Some(rec.clone()), "dpf");
            }
            if let Some(ref mut c) = self.conn1 {
                c.set_metrics_recorder(Some(rec), "dpf");
            }
        }

        log::info!("Connected to both servers");
        self.fire_connect(&self.server0_url);
        self.fire_connect(&self.server1_url);
        self.notify_state(ConnectionState::Connected);
        Ok(())
    }

    #[tracing::instrument(level = "info", skip_all, fields(backend = "dpf"))]
    async fn disconnect(&mut self) -> PirResult<()> {
        if let Some(ref mut conn) = self.conn0 {
            let _ = conn.close().await;
        }
        if let Some(ref mut conn) = self.conn1 {
            let _ = conn.close().await;
        }
        self.conn0 = None;
        self.conn1 = None;
        self.catalog = None;
        self.fire_disconnect();
        self.notify_state(ConnectionState::Disconnected);
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.conn0.is_some() && self.conn1.is_some()
    }

    #[tracing::instrument(level = "debug", skip_all, fields(backend = "dpf"))]
    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog> {
        if !self.is_connected() {
            return Err(PirError::NotConnected);
        }

        // Try to fetch full catalog first
        let request = encode_request(REQ_GET_DB_CATALOG, &[]);
        let conn0 = self.conn0.as_mut().ok_or(PirError::NotConnected)?;
        let response = conn0.roundtrip(&request).await?;

        if response.is_empty() {
            return Err(PirError::Protocol("empty catalog response".into()));
        }

        // Check if server supports catalog (RESP_DB_CATALOG)
        if response[0] == RESP_DB_CATALOG {
            let catalog = decode_catalog(&response[1..])?;
            self.catalog = Some(catalog.clone());
            return Ok(catalog);
        }

        // Fall back to legacy single-database info
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
        fields(backend = "dpf", num_queries = script_hashes.len(), last_height = ?last_height)
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
            backend = "dpf",
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
                "[{}/{}] Querying {} (db_id={}, height={})",
                step_idx + 1,
                plan.steps.len(),
                step.name,
                step.db_id,
                step.tip_height
            );

            let db_info = catalog
                .get(step.db_id)
                .ok_or_else(|| PirError::DatabaseNotFound(step.db_id))?
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
        fields(backend = "dpf", db_id, num_queries = script_hashes.len())
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
            .ok_or_else(|| PirError::DatabaseNotFound(db_id))?
            .clone();

        // Fire `on_query_start` before the step kicks off and
        // `on_query_end` after it resolves either way. The
        // `Option<Instant>` returned by `fire_query_start` carries the
        // start moment when a recorder is installed (and is `None`
        // when no recorder is installed, leaving the timing path at
        // zero overhead). `fire_query_end` computes the wall-clock
        // duration from it and forwards to `PirMetrics::on_query_end`.
        let num_queries = script_hashes.len();
        let started_at = self.fire_query_start(db_id, num_queries);
        let step = SyncStep::from_db_info(&db_info);
        let result = self.execute_step(script_hashes, &step, &db_info).await;
        self.fire_query_end(db_id, num_queries, result.is_ok(), started_at);
        result
    }
}

// ─── Protocol helpers ───────────────────────────────────────────────────────

/// Encode a batch query request.
///
/// Wire format matches `runtime/src/protocol.rs::encode_batch_query`:
/// ```text
/// [4B total_len LE][1B variant]
///   [2B round_id LE]
///   [1B num_groups]
///   [1B keys_per_group]     // SINGLE top-level byte, not per-group
///   For each group:
///     For each key (keys_per_group times):
///       [2B key_len LE][key_data]
///   [1B db_id]              // OPTIONAL, only appended when db_id != 0
/// ```
///
/// Note: no `level` byte on the wire — the server distinguishes index
/// (variant=0x11) from chunk (variant=0x21) via the variant byte alone.
/// The `level` field inside `BatchQuery` is reset to 0 by the server
/// decoder and re-derived from the variant.
fn encode_batch_query(
    variant: u8,
    _level: u8,
    round_id: u16,
    db_id: u8,
    keys: &[Vec<Vec<u8>>],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.push(keys.len() as u8); // num_groups
    let keys_per_group = keys.first().map_or(0, |k| k.len()) as u8;
    payload.push(keys_per_group);

    for group_keys in keys {
        for key in group_keys {
            payload.extend_from_slice(&(key.len() as u16).to_le_bytes());
            payload.extend_from_slice(key);
        }
    }

    // Trailing db_id byte — only appended when non-zero, matches server
    // backward-compatible decode (`decode_batch_query` defaults to 0 when
    // the byte is absent).
    if db_id != 0 {
        payload.push(db_id);
    }

    let total_len = 1 + payload.len();
    let mut buf = Vec::with_capacity(4 + total_len);
    buf.extend_from_slice(&(total_len as u32).to_le_bytes());
    buf.push(variant);
    buf.extend_from_slice(&payload);
    buf
}

/// Decode a batch response into per-group, per-key results.
///
/// Wire format matches `runtime/src/protocol.rs::encode_batch_result`:
/// ```text
/// [1B variant]
/// [2B round_id LE]
/// [1B num_groups]
/// [1B results_per_group]    // SINGLE top-level byte, not per-group
/// For each group:
///   For each result (results_per_group times):
///     [2B res_len LE][res_data]
/// ```
///
/// Note: no `level` byte on the wire.
fn decode_batch_response(data: &[u8]) -> PirResult<Vec<Vec<Vec<u8>>>> {
    if data.is_empty() {
        return Err(PirError::Decode("empty batch response".into()));
    }

    // Skip variant byte
    let _variant = data[0];
    let mut pos = 1;

    // [round_id][num_groups][results_per_group]
    if pos + 4 > data.len() {
        return Err(PirError::Decode("truncated batch response header".into()));
    }
    let _round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_groups = data[pos] as usize;
    pos += 1;
    let results_per_group = data[pos] as usize;
    pos += 1;

    let mut results = Vec::with_capacity(num_groups);

    for _ in 0..num_groups {
        let mut group_results = Vec::with_capacity(results_per_group);
        for _ in 0..results_per_group {
            if pos + 2 > data.len() {
                return Err(PirError::Decode("truncated result length".into()));
            }
            let result_len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;

            if pos + result_len > data.len() {
                return Err(PirError::Decode("truncated result data".into()));
            }
            group_results.push(data[pos..pos + result_len].to_vec());
            pos += result_len;
        }
        results.push(group_results);
    }

    Ok(results)
}

// ─── PIR helpers ────────────────────────────────────────────────────────────

/// XOR src into dst.
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Find a matching tag in an index-level result.
fn find_entry_in_index_result(result: &[u8], expected_tag: u64) -> Option<(u32, u32)> {
    for slot in 0..INDEX_SLOTS_PER_BIN {
        let base = slot * INDEX_SLOT_SIZE;
        if base + INDEX_SLOT_SIZE > result.len() {
            break;
        }
        let slot_tag = u64::from_le_bytes(result[base..base + TAG_SIZE].try_into().unwrap());
        if slot_tag == expected_tag {
            let start_chunk_id =
                u32::from_le_bytes(result[base + TAG_SIZE..base + TAG_SIZE + 4].try_into().unwrap());
            let num_chunks = result[base + TAG_SIZE + 4] as u32;
            return Some((start_chunk_id, num_chunks));
        }
    }
    None
}

/// Find a chunk_id in a chunk-level result.
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

/// Force at least one CHUNK round on the wire.
///
/// CHUNK Round-Presence Symmetry (CLAUDE.md): a not-found / whale
/// query passes an empty `chunk_ids` slice into `query_chunk_level`,
/// which planned to zero rounds. To keep the wire transcript
/// indistinguishable from a small-found query we upgrade an empty
/// plan to a single empty round; the caller's `for g in 0..k_chunk`
/// loop then emits one fully-synthetic K_CHUNK-padded batch (every
/// group's α is drawn from `SimpleRng`).
///
/// This is a pure transformation on the planned-round list — kept in
/// its own function so a Kani harness can verify the
/// `result.len() >= 1` postcondition without modelling
/// `plan_chunk_rounds` (which dispatches to `pir_core::pbc`).
///
/// Generic so the same helper services any `T` (the actual call site
/// uses `Vec<(u32, usize)>` per round).
fn pad_chunk_rounds_for_presence<T>(rounds: Vec<Vec<T>>) -> Vec<Vec<T>> {
    if rounds.is_empty() {
        vec![Vec::new()]
    } else {
        rounds
    }
}

/// Plan multi-round chunk retrieval using PBC.
fn plan_chunk_rounds(chunk_ids: &[u32], k: usize) -> Vec<Vec<(u32, usize)>> {
    let cand_groups: Vec<[usize; 3]> = chunk_ids
        .iter()
        .map(|&cid| pir_core::hash::derive_int_groups_3(cid, k))
        .collect();

    let rounds = pir_core::pbc::pbc_plan_rounds(&cand_groups, k, NUM_HASHES, 500);

    rounds
        .into_iter()
        .map(|round| {
            round
                .into_iter()
                .map(|(item_idx, group)| (chunk_ids[item_idx], group))
                .collect()
        })
        .collect()
}

/// Decode UTXO entries from raw chunk data.
fn decode_utxo_entries(data: &[u8]) -> Vec<UtxoEntry> {
    let mut entries = Vec::new();
    let mut pos = 0;

    // Each chunk is 40 bytes: 32B txid + 4B vout + 4B amount (compressed)
    while pos + CHUNK_SIZE <= data.len() {
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        let vout = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // Amount is stored as 4 bytes (compressed satoshis)
        let amount_compressed = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // Skip empty slots (zero txid)
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
/// Avoids pulling in the `hex` crate for one audit-log string.
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

// ─── Simple RNG ─────────────────────────────────────────────────────────────

/// Simple PRNG for generating dummy query indices.
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new() -> Self {
        Self {
            state: pir_core::hash::splitmix64(crate::platform_time::seed_nanos()),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        pir_core::hash::splitmix64(self.state)
    }
}

// ─── Kani harnesses ────────────────────────────────────────────────────────
//
// Kani is a bounded-model-checker for Rust: `cargo kani` exhausts every input
// up to a concrete bound and proves the harness's assertions. This complements
// the integration tests in `pir-sdk-client/tests/leakage_integration_test.rs`,
// which exercise specific corpus inputs against a live server but cannot
// enumerate every possible (matched_index_idx, chunk_bins) shape.
//
// Install: `cargo install --locked kani-verifier && cargo kani setup`.
// Run:     `cargo kani -p pir-sdk-client`.
//
// The harnesses live behind `#[cfg(kani)]` so a normal `cargo build` /
// `cargo test` doesn't compile them — Kani's own driver injects the cfg
// when running.

#[cfg(kani)]
mod kani_harnesses {
    use super::*;

    /// Pick one of four matched-index cases from a 2-bit symbolic. Keeps
    /// the symbolic state space small — `kani::any::<Option<usize>>()`
    /// expands to `2^64 + None` cases, which is what blew up CBMC on
    /// the first iteration of these harnesses.
    fn symbolic_matched_idx() -> Option<usize> {
        let raw: u8 = kani::any();
        kani::assume(raw < 4);
        match raw {
            0 => Some(0),  // matched at h=0
            1 => Some(1),  // matched at h=1
            2 => Some(7),  // out-of-range (degenerate / bug-shape input)
            _ => None,     // not matched
        }
    }

    /// Prove that `items_from_trace` preserves the length of
    /// `trace.index_bins` (= INDEX_CUCKOO_NUM_HASHES = 2 by caller
    /// contract).
    ///
    /// Why this matters: the Merkle INDEX Item-Count Symmetry invariant
    /// (CLAUDE.md) requires every INDEX query to contribute exactly
    /// `INDEX_CUCKOO_NUM_HASHES = 2` Merkle items. The integration tests
    /// verify the *caller* invariant — that `query_index_level` populates
    /// `trace.index_bins` with exactly 2 entries per query — but the
    /// pure-function transformation in `items_from_trace` is a separate
    /// preservation property: regardless of `matched_index_idx`, output
    /// length must equal input length.
    ///
    /// Bound: `chunk_bins` is empty (its content doesn't affect length
    /// preservation — keeping it empty avoids modelling a symbolic-size
    /// Vec, which exploded CBMC's state space in the first iteration).
    /// `matched_index_idx` ranges over {None, Some(0), Some(1),
    /// Some(out-of-range)}.
    #[kani::proof]
    #[kani::unwind(4)]
    fn items_from_trace_preserves_index_count() {
        let trace = QueryTraces {
            index_bins: vec![
                IndexBinTrace {
                    pbc_group: kani::any(),
                    bin_index: kani::any(),
                    bin_content: Vec::new(),
                },
                IndexBinTrace {
                    pbc_group: kani::any(),
                    bin_index: kani::any(),
                    bin_content: Vec::new(),
                },
            ],
            matched_index_idx: symbolic_matched_idx(),
            chunk_bins: Vec::new(),
        };

        let items = items_from_trace(&trace);

        assert_eq!(
            items.len(),
            INDEX_CUCKOO_NUM_HASHES,
            "items_from_trace must emit INDEX_CUCKOO_NUM_HASHES items \
             per query — Merkle INDEX Item-Count Symmetry invariant",
        );
        assert_eq!(items[0].index_pbc_group, trace.index_bins[0].pbc_group);
        assert_eq!(items[1].index_pbc_group, trace.index_bins[1].pbc_group);
    }

    /// Prove that `collect_merkle_items_from_traces` for a single trace
    /// emits exactly `INDEX_CUCKOO_NUM_HASHES` items with a degenerate
    /// `item_to_query = [0, 0]` backmap.
    ///
    /// (A multi-trace harness would prove the batch-level invariant
    /// `items.len() == n × INDEX_CUCKOO_NUM_HASHES` more powerfully but
    /// blows up CBMC's state space due to the nested Vec<QueryTraces>.
    /// The single-trace base case here, plus the inductive structure
    /// of the wrapper's `for trace in traces` loop, is sufficient to
    /// argue the batch invariant by inspection — a future paper-grade
    /// Kani harness could close this gap with explicit induction
    /// machinery.)
    /// Prove that `items_from_inspector_result` preserves the length of
    /// `result.index_bins` (= INDEX_CUCKOO_NUM_HASHES = 2 by inspector
    /// contract). Parallel to `items_from_trace_preserves_index_count`
    /// — `items_from_inspector_result` operates on the public
    /// [`QueryResult`] type instead of the internal [`QueryTraces`], so
    /// the same length-preservation property must hold across the two
    /// codepaths. Used by `verify_merkle_batch_for_results` for
    /// re-verifying persisted results, so any drift between the two
    /// would silently weaken offline re-verification.
    #[kani::proof]
    #[kani::unwind(4)]
    fn items_from_inspector_result_preserves_index_count() {
        // BucketRef is the public type — its `pbc_group` is u32 (vs
        // usize in IndexBinTrace), but the per-query item count is the
        // same wire-observable value.
        let result = QueryResult {
            entries: Vec::new(),
            is_whale: false,
            merkle_verified: true,
            raw_chunk_data: None,
            index_bins: vec![
                BucketRef {
                    pbc_group: kani::any(),
                    bin_index: kani::any(),
                    bin_content: Vec::new(),
                },
                BucketRef {
                    pbc_group: kani::any(),
                    bin_index: kani::any(),
                    bin_content: Vec::new(),
                },
            ],
            chunk_bins: Vec::new(),
            matched_index_idx: symbolic_matched_idx(),
        };

        let items = items_from_inspector_result(&result);

        assert_eq!(
            items.len(),
            INDEX_CUCKOO_NUM_HASHES,
            "items_from_inspector_result must emit INDEX_CUCKOO_NUM_HASHES \
             items per query — same invariant as items_from_trace",
        );
        // The inspector path widens pbc_group from u32 to usize, so
        // assert on the converted form.
        assert_eq!(
            items[0].index_pbc_group,
            result.index_bins[0].pbc_group as usize,
        );
        assert_eq!(
            items[1].index_pbc_group,
            result.index_bins[1].pbc_group as usize,
        );
    }

    // No multi-trace `collect_merkle_items_from_traces` harness: Kani
    // CBMC ran past 2.5 minutes with `traces.len() == 2` even after
    // bounding `matched_index_idx` to `None` (the wrapper's flatten
    // produces a Vec<usize> backmap whose equality assertion against
    // a literal generates a large state space). The wrapper's loop
    // structure — `for trace in traces { for it in items_from_trace(trace) {
    // push(it); push(qi) } }` — is trivially correct from the per-trace
    // invariant proven by `items_from_trace_preserves_index_count`,
    // so the marginal Kani coverage doesn't justify the runtime.

    #[kani::proof]
    #[kani::unwind(4)]
    fn collect_merkle_items_single_trace() {
        let traces = vec![QueryTraces {
            index_bins: vec![
                IndexBinTrace {
                    pbc_group: kani::any(),
                    bin_index: kani::any(),
                    bin_content: Vec::new(),
                },
                IndexBinTrace {
                    pbc_group: kani::any(),
                    bin_index: kani::any(),
                    bin_content: Vec::new(),
                },
            ],
            matched_index_idx: symbolic_matched_idx(),
            chunk_bins: Vec::new(),
        }];

        let (items, item_to_query) = collect_merkle_items_from_traces(&traces);

        assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
        assert_eq!(item_to_query.len(), INDEX_CUCKOO_NUM_HASHES);
        // Both items come from the single trace, so item_to_query is [0, 0].
        assert_eq!(item_to_query[0], 0);
        assert_eq!(item_to_query[1], 0);
    }

    // ─── CHUNK Round-Presence Symmetry (CLAUDE.md) ─────────────────────
    //
    // The "leak being closed" by the 2026-04-28 fix: not-found and whale
    // queries used to skip the CHUNK PIR phase entirely, exposing
    // found-vs-not-found per query at the wire level. The fix forces
    // every INDEX query to emit ≥1 K_CHUNK-padded CHUNK round. The
    // padding decision is split out into the pure helper
    // `pad_chunk_rounds_for_presence`; the harnesses below verify
    // both halves of the two-part theorem from
    // PLAN_CHUNK_ROUND_PRESENCE_VERIFICATION:
    //
    //   P1 (round-count uniformity): for any planned round list (real
    //       or empty), the post-padding round count is ≥ 1.
    //
    //   P2 (wire indistinguishability): when the input is empty, the
    //       padding emits exactly one round whose `Vec<T>` is empty —
    //       i.e. a fully-synthetic round whose downstream
    //       `for g in 0..k_chunk` loop emits all-random alphas. The
    //       payload bytes-per-group are then identical to a real
    //       round's bytes-per-group (DPF gen returns fixed-length
    //       keys).

    /// **P1**: `pad_chunk_rounds_for_presence` always returns at least
    /// one round, regardless of whether the input was empty or
    /// already non-empty. Symbolically explores input lengths
    /// `0..=2`. The bound is small because anything ≥ 0 is enough to
    /// distinguish the empty case from a "nothing to upgrade" case;
    /// 2 also covers the boundary where a single round is already
    /// present (no padding needed).
    #[kani::proof]
    #[kani::unwind(4)]
    fn pad_chunk_rounds_for_presence_emits_at_least_one_round() {
        let n: usize = kani::any();
        kani::assume(n <= 2);
        let mut rounds: Vec<Vec<(u32, usize)>> = Vec::with_capacity(n);
        for _ in 0..n {
            // Inner content is irrelevant to the property; keep empty.
            rounds.push(Vec::new());
        }

        let padded = pad_chunk_rounds_for_presence(rounds);

        assert!(
            !padded.is_empty(),
            "CHUNK Round-Presence Symmetry: pad_chunk_rounds_for_presence \
             must emit ≥1 round so the caller's K_CHUNK-padded loop \
             always runs at least once",
        );
    }

    /// **P2**: when the input is empty (the not-found / whale path),
    /// the output is exactly `[Vec::new()]` — one round whose entries
    /// list is empty, so the caller's `for g in 0..k_chunk` loop
    /// finds no real chunks for any group and falls through to the
    /// random-alpha branch for every group. The wire shape is then
    /// identical to a real round (same K_CHUNK-padded `dpf.gen` calls,
    /// same fixed-length key bytes per group). Anything other than
    /// `[Vec::new()]` would either drop the round (P1 violation) or
    /// inject phantom real entries that change per-group cuckoo
    /// behaviour.
    #[kani::proof]
    #[kani::unwind(4)]
    fn pad_chunk_rounds_for_presence_empty_input_emits_one_empty_round() {
        let rounds: Vec<Vec<(u32, usize)>> = Vec::new();
        let padded = pad_chunk_rounds_for_presence(rounds);
        assert_eq!(padded.len(), 1);
        assert!(
            padded[0].is_empty(),
            "the dummy round must carry zero real entries so every group \
             routes through the random-alpha branch (P2 wire shape)",
        );
    }

    /// **P1 negative**: when the input already has ≥1 round,
    /// padding is a no-op (length preserved). This rules out a
    /// hypothetical regression where padding *replaces* a real plan
    /// with an empty round.
    #[kani::proof]
    #[kani::unwind(4)]
    fn pad_chunk_rounds_for_presence_nonempty_input_is_identity() {
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 2);
        let mut rounds: Vec<Vec<(u32, usize)>> = Vec::with_capacity(n);
        for _ in 0..n {
            rounds.push(Vec::new());
        }
        let original_len = rounds.len();
        let padded = pad_chunk_rounds_for_presence(rounds);
        assert_eq!(
            padded.len(),
            original_len,
            "padding must preserve length when input already non-empty",
        );
    }

    /// Prove the K-padding invariant for the DPF INDEX request shape
    /// at `k = 4` (the practical maximum for typical batches in the
    /// integration tests): `build_index_alphas` emits exactly 4
    /// outer groups, each with `INDEX_CUCKOO_NUM_HASHES = 2` alphas.
    /// This is the structural form of CLAUDE.md's "Query Padding":
    /// within each PIR round, queries are padded to a fixed count
    /// regardless of how many real queries there are.
    ///
    /// Single concrete `k`: the function body is `for b in 0..k {
    /// fixed-loop-body }` with no early-exit and no branch on `k`
    /// size, so verifying the shape at `k = 4` covers `k ∈ {1, 2,
    /// 3}` by induction on loop count (each iteration appends one
    /// 2-element group; running the loop fewer times produces
    /// proportionally fewer outer entries with the same inner shape).
    /// Everything else is concrete (`assigned_group = 0`, `bins = 8`,
    /// `my_locs = [0, 1]`, random closure returns 0) — symbolic-k
    /// with dynamic `Vec::with_capacity(k)` blew up CBMC past 31 %
    /// RAM in the first iteration.
    #[kani::proof]
    #[kani::unwind(6)]
    fn build_index_alphas_emits_k_groups_two_hashes_each() {
        let my_locs: [u64; INDEX_CUCKOO_NUM_HASHES] = [0, 1];

        let alphas = build_index_alphas(
            /* k */ 4,
            /* assigned_group */ 0,
            &my_locs,
            /* bins */ 8,
            || 0u64,
        );

        assert_eq!(alphas.len(), 4);
        for g in 0..4 {
            assert_eq!(alphas[g].len(), INDEX_CUCKOO_NUM_HASHES);
        }
    }

    /// Prove that the real-query group's alphas are exactly `my_locs`
    /// — i.e. the assigned group carries the precomputed cuckoo
    /// positions, not random bins. Pinned with `k = 4` and a
    /// symbolic in-range `assigned_group` so every position
    /// (0..=3) is exercised.
    #[kani::proof]
    #[kani::unwind(6)]
    fn build_index_alphas_real_query_uses_my_locs() {
        let raw_ag: u8 = kani::any();
        kani::assume(raw_ag < 4);
        let assigned_group = raw_ag as usize;

        let my_locs: [u64; INDEX_CUCKOO_NUM_HASHES] = [42, 43];

        let alphas = build_index_alphas(
            /* k */ 4,
            assigned_group,
            &my_locs,
            /* bins */ 8,
            || 0u64,
        );

        // The real-query group carries `my_locs` verbatim (no `% bins`
        // applied — these are pre-computed cuckoo positions which are
        // already in [0, bins) by `cuckoo_hash`'s contract).
        assert_eq!(alphas[assigned_group][0], 42);
        assert_eq!(alphas[assigned_group][1], 43);
    }

    // ─── Option B index_max closure: batched PBC plan ────────────────────

    /// Prove the K-padding shape invariant for the BATCHED INDEX alpha
    /// matrix at `k = 4`: regardless of which subset of groups carry
    /// placements vs. dummies, the output has exactly `k` outer entries
    /// with `INDEX_CUCKOO_NUM_HASHES = 2` inner alphas each. This is
    /// the structural prerequisite for the wire-format DPF key matrix
    /// to be byte-identical between batched and single-query rounds —
    /// the server can't tell from request shape whether a round
    /// carries one real query or four.
    #[kani::proof]
    #[kani::unwind(6)]
    fn build_index_alphas_batched_emits_k_groups_two_hashes_each() {
        // 2-bit mask deciding which of the 4 groups carries a placement;
        // covers all 16 (real, dummy) configurations including empty
        // (all-dummy = should-not-happen-in-practice but the helper
        // must still produce the K-padded shape) and full (every
        // group has a placement = adversarial worst-case batch).
        let mask: u8 = kani::any();
        kani::assume(mask < 16);
        let placed_locs: Vec<Option<[u64; INDEX_CUCKOO_NUM_HASHES]>> = (0..4u8)
            .map(|g| if (mask >> g) & 1 == 1 {
                Some([100 + g as u64, 200 + g as u64])
            } else {
                None
            })
            .collect();

        let alphas = build_index_alphas_batched(
            /* k */ 4,
            &placed_locs,
            /* bins */ 8,
            || 0u64,
        );

        assert_eq!(alphas.len(), 4);
        for g in 0..4 {
            assert_eq!(alphas[g].len(), INDEX_CUCKOO_NUM_HASHES);
        }
    }

    /// Prove that placed groups carry their `placed_locs[g]` alphas
    /// verbatim (no `% bins` applied). Combined with the shape harness
    /// above, this nails the batched alpha matrix's correctness pointwise:
    /// every placed group reflects the planner's intent; every unplaced
    /// group is a random dummy in `[0, bins)`.
    #[kani::proof]
    #[kani::unwind(6)]
    fn build_index_alphas_batched_placed_groups_use_locs() {
        let raw_g: u8 = kani::any();
        kani::assume(raw_g < 4);
        let g = raw_g as usize;

        let mut placed_locs: Vec<Option<[u64; INDEX_CUCKOO_NUM_HASHES]>> =
            (0..4).map(|_| None).collect();
        placed_locs[g] = Some([7, 11]);

        let alphas = build_index_alphas_batched(
            /* k */ 4,
            &placed_locs,
            /* bins */ 8,
            || 0u64,
        );

        assert_eq!(alphas[g][0], 7);
        assert_eq!(alphas[g][1], 11);
    }

    /// Prove that for unplaced groups the alpha is bounded by `bins`
    /// (the random-dummy branch applies `% bins`). Pinned `bins = 8`
    /// so the modulo math is a constant. Placement of group 0 ensures
    /// the test exercises the unplaced branch on at least one group;
    /// the remaining three groups must all carry dummies < 8.
    #[kani::proof]
    #[kani::unwind(6)]
    fn build_index_alphas_batched_unplaced_groups_bounded_by_bins() {
        let mut placed_locs: Vec<Option<[u64; INDEX_CUCKOO_NUM_HASHES]>> =
            (0..4).map(|_| None).collect();
        placed_locs[0] = Some([0, 0]);  // anchor one placement

        // Symbolic random callback; every call returns a fresh symbolic u64.
        let alphas = build_index_alphas_batched(
            /* k */ 4,
            &placed_locs,
            /* bins */ 8,
            || kani::any::<u64>(),
        );

        for g in 1..4 {
            for h in 0..INDEX_CUCKOO_NUM_HASHES {
                assert!(
                    alphas[g][h] < 8,
                    "unplaced group {} hash {}: alpha {} should be < bins=8",
                    g, h, alphas[g][h],
                );
            }
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::mock::MockTransport;
    use std::sync::Mutex;

    /// Demonstrates the test-injection escape hatch: a client built with a
    /// pair of [`MockTransport`]s reports `is_connected()` without ever
    /// opening a real socket. This is the core value prop of the
    /// `PirTransport` trait — without it, unit tests would need a live
    /// WebSocket to even exercise client state.
    #[test]
    fn connect_with_transport_marks_connected() {
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        assert!(!client.is_connected());
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-0")),
            Box::new(MockTransport::new("wss://mock-1")),
        );
        assert!(client.is_connected());
    }

    /// Recorder impl of [`StateListener`] — records every transition in a
    /// mutex-guarded vec so assertions can check ordering across the
    /// async connect/disconnect transitions.
    struct RecordingListener {
        events: Mutex<Vec<ConnectionState>>,
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
        let listener = Arc::new(RecordingListener {
            events: Mutex::new(Vec::new()),
        });
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_state_listener(Some(listener.clone()));
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-0")),
            Box::new(MockTransport::new("wss://mock-1")),
        );
        let events = listener.events.lock().unwrap();
        assert_eq!(&*events, &[ConnectionState::Connected]);
    }

    /// `set_state_listener(None)` silences a previously registered
    /// listener — subsequent transitions must not reach it.
    #[test]
    fn set_state_listener_none_silences_listener() {
        let listener = Arc::new(RecordingListener {
            events: Mutex::new(Vec::new()),
        });
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_state_listener(Some(listener.clone()));
        client.set_state_listener(None);
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-0")),
            Box::new(MockTransport::new("wss://mock-1")),
        );
        assert!(listener.events.lock().unwrap().is_empty());
    }

    /// Replacing the listener must swap the sink cleanly — only the
    /// new listener sees subsequent events.
    #[test]
    fn set_state_listener_replaces_previous() {
        let old = Arc::new(RecordingListener {
            events: Mutex::new(Vec::new()),
        });
        let new = Arc::new(RecordingListener {
            events: Mutex::new(Vec::new()),
        });
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_state_listener(Some(old.clone()));
        client.set_state_listener(Some(new.clone()));
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-0")),
            Box::new(MockTransport::new("wss://mock-1")),
        );
        assert!(old.events.lock().unwrap().is_empty());
        assert_eq!(
            &*new.events.lock().unwrap(),
            &[ConnectionState::Connected]
        );
    }

    /// Smoke test: `server_urls()` echoes the constructor arguments in
    /// `(server0, server1)` order.
    #[test]
    fn server_urls_returns_configured_urls() {
        let client = DpfClient::new("wss://a.example", "wss://b.example");
        let (a, b) = client.server_urls();
        assert_eq!(a, "wss://a.example");
        assert_eq!(b, "wss://b.example");
    }

    /// [`ConnectionState::as_str`] contract: the JS-side `onStateChange`
    /// callback switches on these exact strings. Any rename here must
    /// be reflected in web/src/ TS consumers.
    #[test]
    fn connection_state_as_str_contract() {
        assert_eq!(ConnectionState::Connecting.as_str(), "connecting");
        assert_eq!(ConnectionState::Connected.as_str(), "connected");
        assert_eq!(ConnectionState::Disconnected.as_str(), "disconnected");
    }

    // ─── Tracing smoke test ──────────────────────────────────────────────
    //
    // Captures the formatted span output emitted by
    // `#[tracing::instrument]` on inherent methods, so that a future
    // accidental `#[tracing::instrument]` removal or field-name rename is
    // caught at test time. We install a scoped subscriber backed by a
    // shared `Vec<u8>` buffer, run the instrumented method, then parse
    // the captured bytes and assert on the contained span name + fields.
    //
    // The subscriber is scoped via `with_default`, not
    // `set_global_default` — global subscribers can only be set once per
    // process, and this test has to coexist with the other crate tests.
    // Scoped subscribers are per-async-task / per-thread and cleaned up
    // when the guard drops.

    /// `MakeWriter` adapter over an `Arc<Mutex<Vec<u8>>>` so
    /// `tracing_subscriber::fmt` can append formatted events to a shared
    /// in-memory buffer that the test assertion can read back.
    #[derive(Clone)]
    struct BufferWriter(Arc<Mutex<Vec<u8>>>);

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
    fn tracing_instrument_emits_backend_field_for_dpf() {
        use tracing_subscriber::fmt;

        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let subscriber = fmt::Subscriber::builder()
            // `span::close` events are what `instrument` emits at method
            // exit; we enable them so the formatter records the span's
            // recorded fields after the method returns.
            .with_span_events(fmt::format::FmtSpan::CLOSE)
            .with_writer(BufferWriter(buf.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
            client.connect_with_transport(
                Box::new(MockTransport::new("wss://mock-0")),
                Box::new(MockTransport::new("wss://mock-1")),
            );
        });

        let captured = String::from_utf8(buf.lock().unwrap().clone())
            .expect("tracing writer produced valid UTF-8");
        // The `connect_with_transport` span must:
        //  (a) fire on the close event (= method returned), and
        //  (b) carry `backend="dpf"` as a recorded field.
        assert!(
            captured.contains("connect_with_transport"),
            "expected span name in captured output, got: {}",
            captured
        );
        assert!(
            captured.contains("backend=\"dpf\""),
            "expected backend=\"dpf\" field in captured output, got: {}",
            captured
        );
    }

    // ─── Metrics recorder tests ─────────────────────────────────────────────

    /// Installing a recorder *before* `connect_with_transport` must
    /// fire an `on_connect` callback per transport (the DPF client
    /// holds two, one per server URL) plus propagate the recorder
    /// down to both transports so subsequent per-frame byte callbacks
    /// flow through. Using `connect_with_transport` so no network.
    #[test]
    fn metrics_recorder_fires_on_connect_via_inject() {
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_metrics_recorder(Some(recorder.clone()));

        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-0")),
            Box::new(MockTransport::new("wss://mock-1")),
        );

        let snap = recorder.snapshot();
        assert_eq!(
            snap.connects, 2,
            "expected one on_connect per transport (2 total)"
        );
        assert_eq!(snap.disconnects, 0);
    }

    /// `disconnect` fires a single `on_disconnect` — we don't fire it
    /// per-transport because the semantic signal is "client left the
    /// connected state", which happens once regardless of how many
    /// transports it owns.
    #[tokio::test]
    async fn metrics_recorder_fires_on_disconnect() {
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_metrics_recorder(Some(recorder.clone()));

        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-0")),
            Box::new(MockTransport::new("wss://mock-1")),
        );
        client.disconnect().await.unwrap();

        let snap = recorder.snapshot();
        assert_eq!(snap.connects, 2);
        assert_eq!(snap.disconnects, 1);
    }

    /// Installing the recorder *after* `connect_with_transport` still
    /// propagates the handle to both transports. Exercised via an
    /// in-memory mock `send` — each send must fire
    /// `on_bytes_sent("dpf", N)` on the recorder even though it was
    /// installed post-connect.
    #[tokio::test]
    async fn metrics_recorder_propagates_to_transports_after_connect() {
        use crate::transport::PirTransport;
        use pir_sdk::AtomicMetrics;

        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-0")),
            Box::new(MockTransport::new("wss://mock-1")),
        );

        // Install the recorder post-connect.
        let recorder = Arc::new(AtomicMetrics::new());
        client.set_metrics_recorder(Some(recorder.clone()));

        // Drive one send through each transport directly — this is
        // the fastest way to prove the recorder is wired without
        // standing up a full PIR query round.
        client.conn0.as_mut().unwrap().send(vec![1, 2, 3]).await.unwrap();
        client.conn1.as_mut().unwrap().send(vec![4, 5]).await.unwrap();

        let snap = recorder.snapshot();
        assert_eq!(snap.bytes_sent, 5);
        assert_eq!(snap.frames_sent, 2);
    }

    /// `set_metrics_recorder(None)` silences both the client-level
    /// and transport-level callbacks.
    #[tokio::test]
    async fn metrics_recorder_uninstall_silences_everything() {
        use crate::transport::PirTransport;
        use pir_sdk::AtomicMetrics;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_metrics_recorder(Some(recorder.clone()));
        client.connect_with_transport(
            Box::new(MockTransport::new("wss://mock-0")),
            Box::new(MockTransport::new("wss://mock-1")),
        );

        // Uninstall mid-session.
        client.set_metrics_recorder(None);
        // Neither the client-level disconnect callback nor the
        // transport-level send callback should fire now.
        client.conn0.as_mut().unwrap().send(vec![9; 42]).await.unwrap();
        client.disconnect().await.unwrap();

        let snap = recorder.snapshot();
        // Only the pre-uninstall connect ticks survive.
        assert_eq!(snap.connects, 2);
        assert_eq!(snap.disconnects, 0);
        assert_eq!(snap.bytes_sent, 0);
        assert_eq!(snap.frames_sent, 0);
    }

    /// `fire_query_start` returns `Some(Instant)` when a recorder is
    /// installed and `None` when not. The `None` case keeps the
    /// no-recorder path at zero overhead — no `Instant::now()` call,
    /// no allocation, just a null-check on the `Option<Arc>`.
    #[test]
    fn fire_query_start_returns_instant_only_when_recorder_installed() {
        use pir_sdk::AtomicMetrics;

        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");

        // No recorder installed → no Instant captured.
        assert!(client.fire_query_start(0, 10).is_none());

        // Install recorder → Instant captured.
        let recorder = Arc::new(AtomicMetrics::new());
        client.set_metrics_recorder(Some(recorder));
        assert!(client.fire_query_start(0, 10).is_some());
    }

    /// Threading the captured `Instant` through `fire_query_end`
    /// yields a non-zero duration on the installed recorder. We sleep
    /// a few milliseconds between start and end so the measured
    /// duration is comfortably distinguishable from clock jitter.
    #[test]
    fn fire_query_end_records_non_zero_duration_with_recorder() {
        use pir_sdk::AtomicMetrics;
        use std::thread::sleep;
        use std::time::Duration as StdDuration;

        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_metrics_recorder(Some(recorder.clone()));

        let started = client.fire_query_start(0, 10);
        assert!(started.is_some());
        sleep(StdDuration::from_millis(5));
        client.fire_query_end(0, 10, true, started);

        let snap = recorder.snapshot();
        assert_eq!(snap.queries_started, 1);
        assert_eq!(snap.queries_completed, 1);
        assert_eq!(snap.query_errors, 0);
        // 5ms = 5_000us; allow generous slack for slow CI runners but
        // require strictly positive (the "no recorder" path produces
        // zero, so any positive value proves the timing path fired).
        assert!(
            snap.min_query_latency_micros >= 1_000,
            "expected min_query_latency_micros >= 1000, got {}",
            snap.min_query_latency_micros
        );
        assert_eq!(
            snap.max_query_latency_micros, snap.min_query_latency_micros,
            "single-completion: min and max must coincide",
        );
    }

    /// `fire_query_end` with `started_at = None` (no recorder at start
    /// time) records `Duration::ZERO` — distinct from the no-recorder
    /// path (which fires nothing at all). This is the documented
    /// "best-effort observation" semantics from
    /// [`PirMetrics::on_query_end`].
    #[test]
    fn fire_query_end_with_none_start_records_zero_duration() {
        use pir_sdk::AtomicMetrics;

        // Install the recorder *between* start and end, simulating a
        // late-install race. `fire_query_start` returned `None`
        // (recorder absent), so `fire_query_end` sees no Instant and
        // forwards Duration::ZERO.
        let recorder = Arc::new(AtomicMetrics::new());
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");

        let started = client.fire_query_start(0, 10); // None
        client.set_metrics_recorder(Some(recorder.clone()));
        client.fire_query_end(0, 10, true, started);

        let snap = recorder.snapshot();
        // The end-callback fired (count incremented), but with zero
        // duration — the recorder treats that as a best-effort point.
        assert_eq!(snap.queries_completed, 1);
        assert_eq!(snap.min_query_latency_micros, 0);
        assert_eq!(snap.max_query_latency_micros, 0);
        assert_eq!(snap.total_query_latency_micros, 0);
    }

    // ─── Merkle INDEX item-count symmetry invariant ─────────────────
    //
    // CLAUDE.md "Merkle INDEX Item-Count Symmetry" requires every INDEX
    // query to contribute exactly `INDEX_CUCKOO_NUM_HASHES` Merkle items,
    // regardless of found@h=0 / found@h=1 / not-found / whale. The
    // server observes per-level sibling pass count directly on the wire,
    // so any per-query item-count asymmetry leaks found-vs-not-found
    // and h-position. These tests pin that contract for both
    // `items_from_trace` (hot-path) and `items_from_inspector_result`
    // (deferred re-verify). A regression that re-introduced an early
    // `break` in `query_index_level` or a "skip empty bin" optimization
    // in the builder would fail at `cargo test`.

    fn idx_bin(bin_index: u32) -> IndexBinTrace {
        IndexBinTrace {
            pbc_group: 7,
            bin_index,
            bin_content: vec![0u8; 16],
        }
    }

    fn chk_bin(bin_index: u32) -> ChunkBinTrace {
        ChunkBinTrace {
            pbc_group: 11,
            bin_index,
            bin_content: vec![0u8; 32],
        }
    }

    #[test]
    fn items_from_trace_found_at_h0_emits_two() {
        let trace = QueryTraces {
            index_bins: vec![idx_bin(100), idx_bin(200)],
            matched_index_idx: Some(0),
            chunk_bins: vec![chk_bin(50)],
        };
        let items = items_from_trace(&trace);
        assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
        assert_eq!(items[0].chunk_bin_indices.len(), 1);
        assert_eq!(items[1].chunk_bin_indices.len(), 0);
    }

    #[test]
    fn items_from_trace_found_at_h1_emits_two() {
        let trace = QueryTraces {
            index_bins: vec![idx_bin(100), idx_bin(200)],
            matched_index_idx: Some(1),
            chunk_bins: vec![chk_bin(50)],
        };
        let items = items_from_trace(&trace);
        assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
        assert_eq!(items[0].chunk_bin_indices.len(), 0);
        assert_eq!(items[1].chunk_bin_indices.len(), 1);
    }

    #[test]
    fn items_from_trace_not_found_emits_two() {
        let trace = QueryTraces {
            index_bins: vec![idx_bin(100), idx_bin(200)],
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
        // Whale: matched at h=0 but `num_chunks == 0`, so `chunk_bins`
        // is empty. Both INDEX bins still emitted for symmetry.
        let trace = QueryTraces {
            index_bins: vec![idx_bin(100), idx_bin(200)],
            matched_index_idx: Some(0),
            chunk_bins: vec![],
        };
        let items = items_from_trace(&trace);
        assert_eq!(items.len(), INDEX_CUCKOO_NUM_HASHES);
        assert_eq!(items[0].chunk_bin_indices.len(), 0);
        assert_eq!(items[1].chunk_bin_indices.len(), 0);
    }

    // ─── build_index_alphas: K-padding shape ────────────────────────────────

    /// Concrete sanity check: a 4-group request with assigned_group=2
    /// produces 4 outer groups of 2 alphas each. The assigned group
    /// echoes `my_locs`; other groups receive the random-bin closure
    /// output reduced mod `bins`.
    #[test]
    fn build_index_alphas_concrete_shape() {
        let mut counter: u64 = 1000;
        let alphas = build_index_alphas(
            /* k */ 4,
            /* assigned_group */ 2,
            &[7, 13],
            /* bins */ 100,
            || {
                let v = counter;
                counter = counter.wrapping_add(1);
                v
            },
        );
        assert_eq!(alphas.len(), 4);
        for g in 0..4 {
            assert_eq!(alphas[g].len(), INDEX_CUCKOO_NUM_HASHES);
        }
        // Real-query group carries my_locs verbatim.
        assert_eq!(alphas[2], vec![7, 13]);
        // Padding groups apply `% bins`, so all values are in [0, bins).
        for g in [0usize, 1, 3] {
            for &alpha in &alphas[g] {
                assert!(alpha < 100);
            }
        }
    }

    /// Out-of-range `assigned_group` is degraded but safe: every group
    /// receives random alphas (no real query), and the K-padding shape
    /// is preserved. Documents the invariant for the
    /// `assigned_group >= k` edge case the Kani harness explores.
    #[test]
    fn build_index_alphas_out_of_range_assigned_group_keeps_shape() {
        let mut counter: u64 = 0;
        let alphas = build_index_alphas(
            /* k */ 3,
            /* assigned_group */ 99,
            &[42, 43],
            /* bins */ 50,
            || {
                let v = counter;
                counter = counter.wrapping_add(1);
                v
            },
        );
        assert_eq!(alphas.len(), 3);
        for g in 0..3 {
            assert_eq!(alphas[g].len(), INDEX_CUCKOO_NUM_HASHES);
            for &alpha in &alphas[g] {
                assert!(alpha < 50);
            }
        }
    }

    // ─── Leakage recorder wiring ────────────────────────────────────────────

    /// `record_round` emits to an installed buffering recorder. Direct
    /// helper-method coverage so the recorder integration is testable
    /// independent of a full PIR query flow.
    #[test]
    fn leakage_recorder_records_via_helper() {
        use pir_sdk::BufferingLeakageRecorder;

        let rec = Arc::new(BufferingLeakageRecorder::new());
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_leakage_recorder(Some(rec.clone()));

        client.record_round(RoundProfile {
            kind: RoundKind::Index,
            server_id: 0,
            db_id: Some(7),
            request_bytes: 100,
            response_bytes: 200,
            items: vec![2; 75],
        });

        let snap = rec.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(matches!(snap[0].kind, RoundKind::Index));
        assert_eq!(snap[0].server_id, 0);
        assert_eq!(snap[0].db_id, Some(7));
        assert_eq!(snap[0].items.len(), 75);
    }

    /// `set_leakage_recorder(None)` silences subsequent emissions.
    #[test]
    fn leakage_recorder_uninstall_silences() {
        use pir_sdk::BufferingLeakageRecorder;

        let rec = Arc::new(BufferingLeakageRecorder::new());
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_leakage_recorder(Some(rec.clone()));
        client.set_leakage_recorder(None);

        client.record_round(RoundProfile {
            kind: RoundKind::Info,
            server_id: 0,
            db_id: None,
            request_bytes: 5,
            response_bytes: 19,
            items: Vec::new(),
        });

        assert!(rec.is_empty());
    }

    /// Driving a real `fetch_legacy_info` through `MockTransport`
    /// emits exactly one `Info` round on server 0. Proves the wiring
    /// at the actual emission site (not just the helper).
    #[tokio::test]
    async fn leakage_recorder_captures_info_round_end_to_end() {
        use pir_sdk::BufferingLeakageRecorder;

        let rec = Arc::new(BufferingLeakageRecorder::new());
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_leakage_recorder(Some(rec.clone()));

        let mut mock0 = MockTransport::new("wss://mock-0");
        // Valid REQ_GET_INFO response: [4B len=19][1B variant=0x01]
        // [4B index_bins][4B chunk_bins][1B index_k][1B chunk_k]
        // [8B tag_seed] — total wire frame is 23 bytes.
        let mut info_resp = Vec::with_capacity(23);
        info_resp.extend_from_slice(&19u32.to_le_bytes()); // length prefix
        info_resp.push(0x01); // variant
        info_resp.extend_from_slice(&1024u32.to_le_bytes()); // index_bins
        info_resp.extend_from_slice(&2048u32.to_le_bytes()); // chunk_bins
        info_resp.push(75); // index_k
        info_resp.push(80); // chunk_k
        info_resp.extend_from_slice(&0u64.to_le_bytes()); // tag_seed
        assert_eq!(info_resp.len(), 23);
        mock0.enqueue_response(info_resp);

        client.connect_with_transport(
            Box::new(mock0),
            Box::new(MockTransport::new("wss://mock-1")),
        );
        let _info = client.fetch_legacy_info().await.unwrap();

        let snap = rec.snapshot();
        assert_eq!(snap.len(), 1, "expected exactly one Info round");
        let r = &snap[0];
        assert!(matches!(r.kind, RoundKind::Info));
        assert_eq!(r.server_id, 0);
        assert_eq!(r.db_id, None);
        // request: REQ_GET_INFO is `[4B len=1][1B 0x01]` = 5 bytes.
        assert_eq!(r.request_bytes, 5);
        // response: full wire frame is 23 bytes (length prefix + payload).
        // `roundtrip` strips the prefix so the client sees 19 bytes;
        // recording adds 4 back to match what a wire-level observer sees.
        assert_eq!(r.response_bytes, 23);
        assert!(r.items.is_empty());
    }

    /// Leakage and metrics recorders are independent — installing both
    /// causes both to fire on the same query, neither blocks the other.
    #[tokio::test]
    async fn leakage_and_metrics_recorders_are_independent() {
        use pir_sdk::{AtomicMetrics, BufferingLeakageRecorder};

        let leakage = Arc::new(BufferingLeakageRecorder::new());
        let metrics = Arc::new(AtomicMetrics::new());
        let mut client = DpfClient::new("wss://mock-0", "wss://mock-1");
        client.set_leakage_recorder(Some(leakage.clone()));
        client.set_metrics_recorder(Some(metrics.clone()));

        let mut mock0 = MockTransport::new("wss://mock-0");
        let mut info_resp = Vec::with_capacity(23);
        info_resp.extend_from_slice(&19u32.to_le_bytes());
        info_resp.push(0x01);
        info_resp.extend_from_slice(&1024u32.to_le_bytes());
        info_resp.extend_from_slice(&2048u32.to_le_bytes());
        info_resp.push(75);
        info_resp.push(80);
        info_resp.extend_from_slice(&0u64.to_le_bytes());
        mock0.enqueue_response(info_resp);

        client.connect_with_transport(
            Box::new(mock0),
            Box::new(MockTransport::new("wss://mock-1")),
        );
        let _info = client.fetch_legacy_info().await.unwrap();

        // Leakage saw the structured round.
        assert_eq!(leakage.len(), 1);
        // Metrics saw the byte counts via the transport.
        let snap = metrics.snapshot();
        assert!(snap.bytes_sent > 0);
        assert!(snap.bytes_received > 0);
    }
}
