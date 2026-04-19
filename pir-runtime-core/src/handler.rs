//! Request handler for PIR protocols.
//!
//! This module provides a reusable `RequestHandler` that processes PIR requests
//! against loaded databases. It can be used by both the `unified_server` binary
//! and the `pir-sdk-server` crate.

use crate::eval::{self, GroupTiming};
use crate::protocol::*;
use crate::table::{MappedDatabase, MappedSubTable, ServerState};
use libdpf::DpfKey;
use pir_core::params;
use rayon::prelude::*;
use std::time::Duration;

/// Handles PIR requests against a set of loaded databases.
pub struct RequestHandler {
    state: ServerState,
}

impl RequestHandler {
    /// Create a new request handler with the given databases.
    pub fn new(databases: Vec<MappedDatabase>) -> Self {
        Self {
            state: ServerState { databases },
        }
    }

    /// Get a database by ID.
    pub fn get_db(&self, db_id: u8) -> Option<&MappedDatabase> {
        self.state.get_db(db_id)
    }

    /// Get the main database (db_id = 0).
    pub fn main_db(&self) -> &MappedDatabase {
        &self.state.databases[0]
    }

    /// Get all databases.
    pub fn databases(&self) -> &[MappedDatabase] {
        &self.state.databases
    }

    /// Build a ServerInfo response.
    pub fn server_info(&self) -> ServerInfo {
        ServerInfo {
            index_bins_per_table: self.main_db().index.bins_per_table as u32,
            chunk_bins_per_table: self.main_db().chunk.bins_per_table as u32,
            index_k: self.main_db().index.params.k as u8,
            chunk_k: self.main_db().chunk.params.k as u8,
            tag_seed: self.main_db().index.tag_seed,
        }
    }

    /// Build a DatabaseCatalog response.
    pub fn build_catalog(&self) -> DatabaseCatalog {
        DatabaseCatalog {
            databases: self
                .state
                .databases
                .iter()
                .enumerate()
                .map(|(i, db)| DatabaseCatalogEntry {
                    db_id: i as u8,
                    db_type: match db.descriptor.db_type {
                        crate::table::DatabaseType::Full => 0,
                        crate::table::DatabaseType::Delta => 1,
                    },
                    name: db.descriptor.name.clone(),
                    base_height: db.descriptor.base_height,
                    height: db.descriptor.height,
                    index_bins_per_table: db.index.bins_per_table as u32,
                    chunk_bins_per_table: db.chunk.bins_per_table as u32,
                    index_k: db.index.params.k as u8,
                    chunk_k: db.chunk.params.k as u8,
                    tag_seed: db.index.tag_seed,
                    dpf_n_index: params::compute_dpf_n(db.index.bins_per_table),
                    dpf_n_chunk: params::compute_dpf_n(db.chunk.bins_per_table),
                    has_bucket_merkle: db.has_bucket_merkle(),
                })
                .collect(),
        }
    }

    /// Handle a PIR request and return a response.
    pub fn handle_request(&self, request: &Request) -> Response {
        match request {
            Request::Ping => Response::Pong,
            Request::GetInfo => Response::Info(self.server_info()),
            Request::GetDbCatalog => Response::DbCatalog(self.build_catalog()),
            Request::IndexBatch(query) => self.handle_index_batch(query),
            Request::ChunkBatch(query) => self.handle_chunk_batch(query),
            Request::MerkleSiblingBatch(query) => self.handle_merkle_sibling_batch(query),
            Request::BucketMerkleSibBatch(query) => self.handle_bucket_merkle_sib_batch(query),
            Request::HarmonyGetInfo => Response::HarmonyInfo(self.server_info()),
            Request::HarmonyHints(_) => {
                Response::Error("HarmonyPIR hints not supported in handler".into())
            }
            Request::HarmonyQuery(query) => self.handle_harmony_query(query),
            Request::HarmonyBatchQuery(query) => self.handle_harmony_batch_query(query),
        }
    }

    /// Handle an index-level DPF batch query.
    fn handle_index_batch(&self, query: &BatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        let (result, _dpf_time, _fetch_time) = self.process_index_batch(query, db);
        Response::IndexBatch(result)
    }

    /// Handle a chunk-level DPF batch query.
    fn handle_chunk_batch(&self, query: &BatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        let (result, _dpf_time, _fetch_time) = self.process_chunk_batch(query, db);
        Response::ChunkBatch(result)
    }

    /// Handle a Merkle sibling batch query.
    fn handle_merkle_sibling_batch(&self, query: &BatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        if !db.has_merkle() {
            return Response::Error("database has no Merkle data".into());
        }

        let (result, _dpf_time, _fetch_time) = self.process_merkle_sibling_batch(query, db);
        Response::MerkleSiblingBatch(result)
    }

    /// Handle a bucket Merkle sibling batch query.
    fn handle_bucket_merkle_sib_batch(&self, query: &BatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        if !db.has_bucket_merkle() {
            return Response::Error("database has no bucket Merkle data".into());
        }

        // level encoding: 0-74 = INDEX sibling L{level/75} group {level%75}
        //                 75-154 = CHUNK sibling L{(level-75)/80} group {(level-75)%80}
        let level = query.level as usize;
        let index_k = db.index.params.k;

        let table = if level < index_k {
            // INDEX sibling, compute L from round_id
            let sib_level = (query.round_id as usize) / 100;
            if sib_level >= db.bucket_merkle_index_siblings.len() {
                return Response::Error(format!(
                    "invalid index sibling level {}",
                    sib_level
                ));
            }
            &db.bucket_merkle_index_siblings[sib_level]
        } else {
            // CHUNK sibling
            let sib_level = (query.round_id as usize) / 100;
            if sib_level >= db.bucket_merkle_chunk_siblings.len() {
                return Response::Error(format!(
                    "invalid chunk sibling level {}",
                    sib_level
                ));
            }
            &db.bucket_merkle_chunk_siblings[sib_level]
        };

        let (result, _dpf_time, _fetch_time) = self.process_generic_batch(query, table);
        Response::BucketMerkleSibBatch(result)
    }

    /// Handle a HarmonyPIR query (Query Server role).
    fn handle_harmony_query(&self, query: &HarmonyQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        let (sub_table, entry_size) = match query.level {
            0 => (&db.index, db.index.params.bin_size()),
            1 => (&db.chunk, db.chunk.params.bin_size()),
            _ => return Response::Error("invalid level".into()),
        };

        let group_id = query.group_id as usize;
        let table_bytes = sub_table.group_bytes(group_id);

        let mut data = Vec::with_capacity(query.indices.len() * entry_size);
        for &idx in &query.indices {
            let idx_usize = idx as usize;
            if idx_usize >= sub_table.bins_per_table {
                return Response::Error(format!("index {} out of range", idx));
            }
            let offset = idx_usize * entry_size;
            data.extend_from_slice(&table_bytes[offset..offset + entry_size]);
        }

        Response::HarmonyQueryResult(HarmonyQueryResult {
            group_id: query.group_id,
            round_id: query.round_id,
            data,
        })
    }

    /// Handle a HarmonyPIR batch query.
    fn handle_harmony_batch_query(&self, query: &HarmonyBatchQuery) -> Response {
        let db = match self.state.get_db(query.db_id) {
            Some(d) => d,
            None => return Response::Error(format!("unknown db_id {}", query.db_id)),
        };

        let (sub_table, entry_size) = match query.level {
            0 => (&db.index, db.index.params.bin_size()),
            1 => (&db.chunk, db.chunk.params.bin_size()),
            _ => return Response::Error("invalid level".into()),
        };

        let items: Vec<HarmonyBatchResultItem> = query
            .items
            .par_iter()
            .map(|item| {
                let group_id = item.group_id as usize;
                let table_bytes = sub_table.group_bytes(group_id);

                let sub_results: Vec<Vec<u8>> = item
                    .sub_queries
                    .iter()
                    .map(|indices| {
                        let mut data = Vec::with_capacity(indices.len() * entry_size);
                        for &idx in indices {
                            let idx_usize = idx as usize;
                            if idx_usize < sub_table.bins_per_table {
                                let offset = idx_usize * entry_size;
                                data.extend_from_slice(&table_bytes[offset..offset + entry_size]);
                            }
                        }
                        data
                    })
                    .collect();

                HarmonyBatchResultItem {
                    group_id: item.group_id,
                    sub_results,
                }
            })
            .collect();

        Response::HarmonyBatchResult(HarmonyBatchResult {
            level: query.level,
            round_id: query.round_id,
            sub_results_per_group: query.sub_queries_per_group,
            items,
        })
    }

    // ─── Internal processing methods ────────────────────────────────────────

    fn process_index_batch(
        &self,
        query: &BatchQuery,
        db: &MappedDatabase,
    ) -> (BatchResult, Duration, Duration) {
        let k = db.index.params.k;
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b]
                    .iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = db.index.group_bytes(b);
                let (r0, r1, timing) = eval::process_index_group(
                    key_refs[0],
                    key_refs[1],
                    table_bytes,
                    db.index.bins_per_table,
                );
                (vec![r0, r1], timing)
            })
            .collect();

        let mut total_dpf = Duration::ZERO;
        let mut total_fetch = Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }

        (
            BatchResult {
                level: 0,
                round_id: 0,
                results,
            },
            total_dpf,
            total_fetch,
        )
    }

    fn process_chunk_batch(
        &self,
        query: &BatchQuery,
        db: &MappedDatabase,
    ) -> (BatchResult, Duration, Duration) {
        let k = db.chunk.params.k;
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b]
                    .iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = db.chunk.group_bytes(b);
                let (r, timing) =
                    eval::process_chunk_group(&key_refs, table_bytes, db.chunk.bins_per_table);
                (r, timing)
            })
            .collect();

        let mut total_dpf = Duration::ZERO;
        let mut total_fetch = Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }

        (
            BatchResult {
                level: 1,
                round_id: query.round_id,
                results,
            },
            total_dpf,
            total_fetch,
        )
    }

    fn process_merkle_sibling_batch(
        &self,
        query: &BatchQuery,
        db: &MappedDatabase,
    ) -> (BatchResult, Duration, Duration) {
        let level = (query.round_id as usize) / 100;
        let sib_table = &db.merkle_siblings[level];
        let k = sib_table.params.k;
        let result_size = sib_table.params.bin_size();
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b]
                    .iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = sib_table.group_bytes(b);
                let (r, timing) = eval::process_merkle_sibling_group(
                    &key_refs,
                    table_bytes,
                    sib_table.bins_per_table,
                    result_size,
                );
                (r, timing)
            })
            .collect();

        let mut total_dpf = Duration::ZERO;
        let mut total_fetch = Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }

        (
            BatchResult {
                level: 2,
                round_id: query.round_id,
                results,
            },
            total_dpf,
            total_fetch,
        )
    }

    fn process_generic_batch(
        &self,
        query: &BatchQuery,
        table: &MappedSubTable,
    ) -> (BatchResult, Duration, Duration) {
        let k = table.params.k;
        let result_size = table.params.bin_size();
        let num_groups = query.keys.len().min(k);

        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b]
                    .iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = table.group_bytes(b);
                let (r, timing) = eval::process_merkle_sibling_group(
                    &key_refs,
                    table_bytes,
                    table.bins_per_table,
                    result_size,
                );
                (r, timing)
            })
            .collect();

        let mut total_dpf = Duration::ZERO;
        let mut total_fetch = Duration::ZERO;
        let mut results = Vec::with_capacity(num_groups);
        for (r, t) in group_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }

        (
            BatchResult {
                level: query.level,
                round_id: query.round_id,
                results,
            },
            total_dpf,
            total_fetch,
        )
    }
}
