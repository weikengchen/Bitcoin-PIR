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

const RESP_ERROR: u8 = 0xff;

/// PRP backends (mirrors `harmonypir_wasm::PRP_*`).
pub const PRP_HOANG: u8 = 0;
pub const PRP_FASTPRP: u8 = 1;
pub const PRP_ALF: u8 = 2;

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
        self.loaded_db_id = None;
    }

    /// Fetch server info (legacy single-database path).
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

            let map = if level == 0 { &mut self.index_groups } else { &mut self.chunk_groups };
            let group = map.get_mut(&group_id).ok_or_else(|| {
                PirError::Protocol(format!("hint for unknown group {}", group_id))
            })?;
            group
                .load_hints(hints_data)
                .map_err(|e| PirError::BackendState(format!("load_hints: {:?}", e)))?;

            received += 1;
        }

        Ok(())
    }

    /// Execute a single query step for a batch of script hashes.
    async fn execute_step(
        &mut self,
        script_hashes: &[ScriptHash],
        _step: &SyncStep,
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<Option<QueryResult>>> {
        self.ensure_groups_ready(db_info).await?;

        let mut results = Vec::with_capacity(script_hashes.len());
        for script_hash in script_hashes {
            let result = self.query_single(script_hash, db_info).await?;
            results.push(result);
        }
        Ok(results)
    }

    /// Query a single script hash.
    ///
    /// Runs up to [`INDEX_CUCKOO_NUM_HASHES`] INDEX rounds (one per hash
    /// function); on a hit, runs the CHUNK rounds to recover UTXO bytes.
    async fn query_single(
        &mut self,
        script_hash: &ScriptHash,
        db_info: &DatabaseInfo,
    ) -> PirResult<Option<QueryResult>> {
        let k_index = db_info.index_k as usize;
        let index_bins = db_info.index_bins as usize;
        let tag_seed = db_info.tag_seed;

        let real_group = pir_core::hash::derive_groups_3(script_hash, k_index)[0];
        let my_tag = pir_core::hash::compute_tag(tag_seed, script_hash);

        let mut hit: Option<(u32, u8, bool)> = None;

        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            let key =
                pir_core::hash::derive_cuckoo_key(INDEX_PARAMS.master_seed, real_group, h);
            let target_bin = pir_core::hash::cuckoo_hash(script_hash, key, index_bins);

            let answer = self
                .run_index_round(db_info.db_id, real_group as u8, target_bin as u32, h)
                .await?;

            if let Some(entry) = find_entry_in_index_result(&answer, my_tag) {
                hit = Some((entry.0, entry.1, entry.1 == 0));
                break;
            }
        }

        let (start_chunk_id, num_chunks, is_whale) = match hit {
            Some(v) => v,
            None => return Ok(None),
        };

        if num_chunks == 0 {
            return Ok(Some(QueryResult {
                entries: Vec::new(),
                is_whale,
                raw_chunk_data: None,
            }));
        }

        let chunk_ids: Vec<u32> =
            (start_chunk_id..start_chunk_id + num_chunks as u32).collect();
        let chunk_data = self.query_chunk_level(&chunk_ids, db_info).await?;

        let entries = decode_utxo_entries(&chunk_data);
        Ok(Some(QueryResult {
            entries,
            is_whale,
            raw_chunk_data: if db_info.kind.is_delta() {
                Some(chunk_data)
            } else {
                None
            },
        }))
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
    async fn query_chunk_level(
        &mut self,
        chunk_ids: &[u32],
        db_info: &DatabaseInfo,
    ) -> PirResult<Vec<u8>> {
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

        let mut chunk_data: HashMap<u32, Vec<u8>> = HashMap::new();
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
                        chunk_data.insert(*cid, data.to_vec());
                        recovered.insert(*cid);
                    }
                }
            }
        }

        let mut out = Vec::with_capacity(chunk_ids.len() * CHUNK_SIZE);
        for cid in chunk_ids {
            if let Some(data) = chunk_data.get(cid) {
                out.extend_from_slice(data);
            }
        }

        Ok(out)
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

/// Encode a simple request with length prefix: `[4B len LE][1B variant][payload]`.
fn encode_request(variant: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 1 + payload.len();
    let mut buf = Vec::with_capacity(4 + total_len);
    buf.extend_from_slice(&(total_len as u32).to_le_bytes());
    buf.push(variant);
    buf.extend_from_slice(payload);
    buf
}

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
