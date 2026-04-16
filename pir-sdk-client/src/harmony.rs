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

use crate::connection::WsConnection;
use crate::merkle_verify::{
    fetch_tree_tops, verify_bucket_merkle_batch_generic, BucketMerkleItem,
    BucketMerkleSiblingQuerier, TreeTop, BUCKET_MERKLE_ARITY, BUCKET_MERKLE_SIB_ROW_SIZE,
};
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
    compute_sync_plan, merge_delta_batch, DatabaseCatalog, DatabaseInfo, DatabaseKind,
    PirBackendType, PirClient, PirError, PirResult, QueryResult, ScriptHash, SyncPlan, SyncResult,
    SyncStep, UtxoEntry,
};
use std::collections::HashMap;

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
pub const PRP_HOANG: u8 = 0;
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

// ─── HarmonyPIR Client ──────────────────────────────────────────────────────

/// HarmonyPIR client for two-server PIR queries.
pub struct HarmonyClient {
    hint_server_url: String,
    query_server_url: String,
    hint_conn: Option<WsConnection>,
    query_conn: Option<WsConnection>,
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
}

impl HarmonyClient {
    /// Create a new HarmonyPIR client.
    ///
    /// The master PRP key is derived from the current wall-clock time;
    /// use [`HarmonyClient::set_master_key`] to pin a specific key
    /// (useful for tests and for reusing cached hint state).
    pub fn new(hint_server_url: &str, query_server_url: &str) -> Self {
        let mut master_prp_key = [0u8; 16];
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
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
            prp_backend: PRP_HOANG,
            master_prp_key,
            loaded_db_id: None,
            index_groups: HashMap::new(),
            chunk_groups: HashMap::new(),
            index_sib_groups: HashMap::new(),
            chunk_sib_groups: HashMap::new(),
            sibling_hints_loaded: None,
        }
    }

    /// Override the master PRP key (16 bytes).
    pub fn set_master_key(&mut self, key: [u8; 16]) {
        self.master_prp_key = key;
        self.invalidate_groups();
    }

    /// Set the PRP backend (`PRP_HOANG`, `PRP_FASTPRP`, or `PRP_ALF`).
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
    async fn ensure_groups_ready(&mut self, db_info: &DatabaseInfo) -> PirResult<()> {
        if self.loaded_db_id == Some(db_info.db_id)
            && !self.index_groups.is_empty()
            && !self.chunk_groups.is_empty()
        {
            return Ok(());
        }

        self.invalidate_groups();

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

        self.fetch_and_load_hints(db_info.db_id, 0, k_index as u8).await?;
        self.fetch_and_load_hints(db_info.db_id, 1, k_chunk as u8).await?;

        self.loaded_db_id = Some(db_info.db_id);
        Ok(())
    }

    /// Send a hint request for all groups at `level` (0=INDEX, 1=CHUNK)
    /// and load each response into its owning `HarmonyGroup`.
    async fn fetch_and_load_hints(
        &mut self,
        db_id: u8,
        level: u8,
        num_groups: u8,
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
        self.fetch_and_load_hints_into(db_id, level, num_groups, target)
            .await
    }

    /// Generalised hint fetch: issues a `REQ_HARMONY_HINTS` with the given
    /// `level` byte (0=INDEX, 1=CHUNK, 10+L=INDEX sib L, 20+L=CHUNK sib L)
    /// and streams responses into the group map pointed to by `target`.
    ///
    /// The server derives per-group PRP keys using `(prp_key, level, group_id)`
    /// internally — the client only needs to pass the correct `level` byte;
    /// the `k_offset` accounting in the server is transparent here.
    async fn fetch_and_load_hints_into(
        &mut self,
        db_id: u8,
        level: u8,
        num_groups: u8,
        target: HintTarget,
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
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        self.ensure_groups_ready(db_info).await?;

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
    async fn ensure_sibling_groups_ready(
        &mut self,
        db_info: &DatabaseInfo,
        tree_tops: &[TreeTop],
    ) -> PirResult<()> {
        if self.sibling_hints_loaded == Some(db_info.db_id)
            && !self.index_sib_groups.is_empty()
            && !self.chunk_sib_groups.is_empty()
        {
            return Ok(());
        }

        // Reset any stale state.
        self.index_sib_groups.clear();
        self.chunk_sib_groups.clear();
        self.sibling_hints_loaded = None;

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
            )
            .await?;
            log::info!(
                "[PIR-AUDIT] HarmonyPIR CHUNK sib L{}: loaded hints for {} groups (n={})",
                sl, k_chunk, level_n
            );
        }

        self.sibling_hints_loaded = Some(db_info.db_id);
        Ok(())
    }

    /// Build `BucketMerkleItem`s from collected query traces and verify them
    /// in one padded batch via HarmonyPIR sibling queries.
    ///
    /// Mirrors `dpf.rs::run_merkle_verification`: on any bin failing
    /// verification, the corresponding query is coerced to `None` to signal
    /// an unverified/untrusted result.
    async fn run_merkle_verification(
        &mut self,
        results: &mut [Option<QueryResult>],
        traces: &[QueryTraces],
        db_info: &DatabaseInfo,
    ) -> PirResult<()> {
        // Build items + mapping from item back to the query it covers.
        let mut items: Vec<BucketMerkleItem> = Vec::new();
        let mut item_to_query: Vec<usize> = Vec::new();

        for (qi, trace) in traces.iter().enumerate() {
            // Emit one BucketMerkleItem per probed INDEX bin so the Merkle
            // item count is uniform (INDEX_CUCKOO_NUM_HASHES items per query)
            // across found / not-found / whale. CHUNK bins attach only to the
            // matched INDEX item; the other item(s) get empty chunk vectors.
            //
            // Whales are verified on the INDEX side — the bin content with
            // num_chunks=0 is committed to the INDEX Merkle root, so verifying
            // it proves the server-reported whale status.
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

            for (bi, bin) in trace.index_bins.iter().enumerate() {
                let is_matched = trace.matched_index_idx == Some(bi);
                let mut it = BucketMerkleItem {
                    index_pbc_group: bin.pbc_group,
                    index_bin_index: bin.bin_index,
                    index_bin_content: bin.bin_content.clone(),
                    chunk_pbc_groups: Vec::new(),
                    chunk_bin_indices: Vec::new(),
                    chunk_bin_contents: Vec::new(),
                };
                if is_matched {
                    for cb in &trace.chunk_bins {
                        it.chunk_pbc_groups.push(cb.pbc_group);
                        it.chunk_bin_indices.push(cb.bin_index);
                        it.chunk_bin_contents.push(cb.bin_content.clone());
                    }
                }
                items.push(it);
                item_to_query.push(qi);
            }
        }

        if items.is_empty() {
            log::info!(
                "[PIR-AUDIT] HarmonyPIR Merkle: no items to verify — nothing to do"
            );
            return Ok(());
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
        // are restored before returning.
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
                &items,
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

        // Aggregate per-item outcomes back to per-query verdicts.
        let mut per_query_ok = vec![true; results.len()];
        let mut per_query_touched = vec![false; results.len()];
        for (ii, ok) in per_item.iter().enumerate() {
            let qi = item_to_query[ii];
            per_query_touched[qi] = true;
            if !ok {
                per_query_ok[qi] = false;
            }
        }

        for qi in 0..results.len() {
            if !per_query_touched[qi] {
                continue; // whale-without-INDEX-items or skipped
            }
            if !per_query_ok[qi] {
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
            } else {
                log::info!("[PIR-AUDIT] HarmonyPIR Merkle PASSED for query #{}", qi);
                // merkle_verified is already true by construction in query_single.
            }
        }

        Ok(())
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

    async fn connect(&mut self) -> PirResult<()> {
        log::info!(
            "Connecting to HarmonyPIR servers: hint={}, query={}",
            self.hint_server_url,
            self.query_server_url
        );

        let (hint_conn, query_conn) = tokio::try_join!(
            WsConnection::connect(&self.hint_server_url),
            WsConnection::connect(&self.query_server_url),
        )?;

        self.hint_conn = Some(hint_conn);
        self.query_conn = Some(query_conn);
        log::info!("Connected to both HarmonyPIR servers");
        Ok(())
    }

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
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.hint_conn.is_some() && self.query_conn.is_some()
    }

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
    /// Query server connection — held mutably across the verification.
    query_conn: &'a mut WsConnection,
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
        assert_eq!(client.prp_backend, PRP_HOANG);
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
}
