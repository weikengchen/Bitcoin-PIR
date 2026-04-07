//! Two-level Batch PIR WebSocket server.
//!
//! Loads both cuckoo tables (index + chunk) and serves DPF queries.
//! Each client sends batches of DPF keys; the server evaluates them
//! in parallel and returns XOR-accumulated results.
//!
//! Usage:
//!   cargo run --release -p runtime --bin server -- --port 8091

use runtime::eval::{self, GroupTiming};
use runtime::protocol::{BatchQuery, BatchResult, Request, Response, ServerInfo};
use runtime::protocol::{DatabaseCatalog, DatabaseCatalogEntry};
use build::common::*;
use futures_util::{SinkExt, StreamExt};
use libdpf::DpfKey;
use pir_core::params::{INDEX_PARAMS, CHUNK_PARAMS};
use rayon::prelude::*;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

// ─── Server data ────────────────────────────────────────────────────────────

use runtime::table::{CuckooTablePair, MappedDatabase, DatabaseDescriptor, ServerState};

struct ServerData {
    tables: CuckooTablePair,
    /// Multi-database state (empty if using legacy single-DB mode).
    multi_db: Option<ServerState>,
}

impl ServerData {
    fn load() -> Self {
        ServerData {
            tables: CuckooTablePair::load(),
            multi_db: None,
        }
    }

    /// Build a database catalog from the loaded state.
    fn build_catalog(&self) -> DatabaseCatalog {
        if let Some(ref state) = self.multi_db {
            DatabaseCatalog {
                databases: state.databases.iter().enumerate().map(|(i, db)| {
                    DatabaseCatalogEntry {
                        db_id: i as u8,
                        name: db.descriptor.name.clone(),
                        height: db.descriptor.height,
                        index_bins_per_table: db.index.bins_per_table as u32,
                        chunk_bins_per_table: db.chunk.bins_per_table as u32,
                        index_k: db.index.params.k as u8,
                        chunk_k: db.chunk.params.k as u8,
                        tag_seed: db.index.tag_seed,
                        dpf_n_index: db.index.params.dpf_n,
                        dpf_n_chunk: db.chunk.params.dpf_n,
                    }
                }).collect(),
            }
        } else {
            // Legacy single-DB mode
            DatabaseCatalog {
                databases: vec![DatabaseCatalogEntry {
                    db_id: 0,
                    name: "main".to_string(),
                    height: 0,
                    index_bins_per_table: self.tables.index_bins_per_table as u32,
                    chunk_bins_per_table: self.tables.chunk_bins_per_table as u32,
                    index_k: K as u8,
                    chunk_k: K_CHUNK as u8,
                    tag_seed: self.tables.tag_seed,
                    dpf_n_index: 20,
                    dpf_n_chunk: 21,
                }],
            }
        }
    }

    fn process_index_batch(&self, query: &BatchQuery) -> (BatchResult, Duration, Duration) {
        let num_groups = query.keys.len().min(K);
        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b].iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_offset = HEADER_SIZE + b * self.tables.index_table_byte_size;
                let table_bytes = &self.tables.index_cuckoo[table_offset..table_offset + self.tables.index_table_byte_size];
                let (r0, r1, timing) = eval::process_index_group(
                    &key_refs[0], &key_refs[1],
                    table_bytes,
                    self.tables.index_bins_per_table,
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

        (BatchResult { level: 0, round_id: 0, results }, total_dpf, total_fetch)
    }

    fn process_chunk_batch(&self, query: &BatchQuery) -> (BatchResult, Duration, Duration) {
        let num_groups = query.keys.len().min(K_CHUNK);
        let group_results: Vec<(Vec<Vec<u8>>, GroupTiming)> = (0..num_groups)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b].iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_offset = CHUNK_HEADER_SIZE + b * self.tables.chunk_table_byte_size;
                let table_bytes = &self.tables.chunk_cuckoo[table_offset..table_offset + self.tables.chunk_table_byte_size];
                let (r, timing) = eval::process_chunk_group(
                    &key_refs,
                    table_bytes,
                    self.tables.chunk_bins_per_table,
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

        (BatchResult { level: 1, round_id: query.round_id, results }, total_dpf, total_fetch)
    }

    /// Handle a HarmonyPIR query: simple indexed lookup into cuckoo tables.
    ///
    /// The client sends sorted non-empty DB indices (no EMPTY markers, no dummy).
    /// Returns RESP_HARMONY_QUERY with count × w bytes of individual entries.
    fn handle_harmony_batch_query(
        &self,
        query: &runtime::protocol::HarmonyBatchQuery,
    ) -> Response {
        let (table_bytes, bins_per_table, entry_size, header_size) = match query.level {
            0 => (
                &self.tables.index_cuckoo[..],
                self.tables.index_bins_per_table,
                INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE,
                HEADER_SIZE,
            ),
            1 => (
                &self.tables.chunk_cuckoo[..],
                self.tables.chunk_bins_per_table,
                CHUNK_SLOTS_PER_BIN * (4 + CHUNK_SIZE),
                CHUNK_HEADER_SIZE,
            ),
            _ => return Response::Error("invalid level".into()),
        };

        // Process all groups in parallel.
        let result_items: Vec<runtime::protocol::HarmonyBatchResultItem> = query
            .items
            .par_iter()
            .map(|item| {
                let group_id = item.group_id as usize;
                let table_offset = header_size + group_id * bins_per_table * entry_size;

                let sub_results: Vec<Vec<u8>> = item
                    .sub_queries
                    .iter()
                    .map(|indices| {
                        let mut data = Vec::with_capacity(indices.len() * entry_size);
                        for &idx in indices {
                            let idx_usize = idx as usize;
                            if idx_usize < bins_per_table {
                                let off = table_offset + idx_usize * entry_size;
                                let end = off + entry_size;
                                if end <= table_bytes.len() {
                                    data.extend_from_slice(&table_bytes[off..end]);
                                } else {
                                    data.extend(std::iter::repeat(0u8).take(entry_size));
                                }
                            } else {
                                // Virtual padded row — return zeros.
                                data.extend(std::iter::repeat(0u8).take(entry_size));
                            }
                        }
                        data
                    })
                    .collect();

                runtime::protocol::HarmonyBatchResultItem {
                    group_id: item.group_id,
                    sub_results,
                }
            })
            .collect();

        Response::HarmonyBatchResult(runtime::protocol::HarmonyBatchResult {
            level: query.level,
            round_id: query.round_id,
            sub_results_per_group: query.sub_queries_per_group,
            items: result_items,
        })
    }

    fn handle_harmony_query(&self, query: &runtime::protocol::HarmonyQuery) -> Response {
        let (table_bytes, bins_per_table, entry_size, header_size) = match query.level {
            0 => (
                &self.tables.index_cuckoo[..],
                self.tables.index_bins_per_table,
                INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE,
                HEADER_SIZE,
            ),
            1 => (
                &self.tables.chunk_cuckoo[..],
                self.tables.chunk_bins_per_table,
                CHUNK_SLOTS_PER_BIN * (4 + CHUNK_SIZE),
                CHUNK_HEADER_SIZE,
            ),
            _ => return Response::Error("invalid level".into()),
        };

        let group_id = query.group_id as usize;
        let table_offset = header_size + group_id * bins_per_table * entry_size;

        let mut data = Vec::with_capacity(query.indices.len() * entry_size);
        for &idx in &query.indices {
            let idx_usize = idx as usize;
            if idx_usize >= bins_per_table {
                return Response::Error(format!(
                    "index {} out of range (bins_per_table={})", idx, bins_per_table
                ));
            }
            let offset = table_offset + idx_usize * entry_size;
            let end = offset + entry_size;
            if end > table_bytes.len() {
                return Response::Error("table read out of bounds".into());
            }
            data.extend_from_slice(&table_bytes[offset..end]);
        }

        Response::HarmonyQueryResult(runtime::protocol::HarmonyQueryResult {
            group_id: query.group_id,
            round_id: query.round_id,
            data,
        })
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn parse_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 8091u16;
    let mut i = 1;
    while i < args.len() {
        if (args[i] == "--port" || args[i] == "-p") && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(8091);
            i += 1;
        }
        i += 1;
    }
    port
}

#[tokio::main]
async fn main() {
    let port = parse_port();

    println!("=== Two-Level Batch PIR Server ===");
    println!();

    let start = Instant::now();
    let data = ServerData::load();
    println!();
    println!("Data loaded in {:.2?}", start.elapsed());
    println!();

    let data = Arc::new(data);

    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("Listening on ws://{}", addr);
    println!("  Index: K={}, bins_per_table={}, cuckoo={}-hash bs={}",
        K, data.tables.index_bins_per_table, INDEX_CUCKOO_NUM_HASHES, INDEX_SLOTS_PER_BIN);
    println!("  Chunk: K={}, bins_per_table={}, cuckoo={}-hash bs={}",
        K_CHUNK, data.tables.chunk_bins_per_table, CHUNK_CUCKOO_NUM_HASHES, CHUNK_SLOTS_PER_BIN);
    println!();

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Accept error: {}", e);
                continue;
            }
        };
        println!("[{}] Connected", peer);

        let data = Arc::clone(&data);
        tokio::spawn(async move {
            let ws = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("[{}] WebSocket handshake failed: {}", peer, e);
                    return;
                }
            };

            let (mut sink, mut stream) = ws.split();

            while let Some(msg) = stream.next().await {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("[{}] Read error: {}", peer, e);
                        break;
                    }
                };

                let bin = match msg {
                    Message::Binary(b) => b,
                    Message::Ping(p) => {
                        let _ = sink.send(Message::Pong(p)).await;
                        continue;
                    }
                    Message::Close(_) => break,
                    _ => continue,
                };

                // Decode: skip 4-byte length prefix
                if bin.len() < 4 {
                    continue;
                }
                let payload = &bin[4..];

                let request = match Request::decode(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[{}] Bad request: {}", peer, e);
                        let resp = Response::Error(format!("decode error: {}", e));
                        let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        continue;
                    }
                };

                let data_ref = Arc::clone(&data);
                let response = tokio::task::spawn_blocking(move || {
                    match request {
                        Request::Ping => Response::Pong,
                        Request::GetDbCatalog => {
                            Response::DbCatalog(data_ref.build_catalog())
                        }
                        Request::GetInfo => Response::Info(ServerInfo {
                            index_bins_per_table: data_ref.tables.index_bins_per_table as u32,
                            chunk_bins_per_table: data_ref.tables.chunk_bins_per_table as u32,
                            index_k: K as u8,
                            chunk_k: K_CHUNK as u8,
                            tag_seed: data_ref.tables.tag_seed,
                        }),
                        Request::IndexBatch(q) => {
                            let t = Instant::now();
                            let n = q.keys.len();
                            let (batch, dpf_sum, fetch_sum) = data_ref.process_index_batch(&q);
                            let wall = t.elapsed();
                            println!("[index] {} groups {:.2?} wall | sum: dpf {:.2?} fetch+xor {:.2?} | avg: dpf {:.1?} fetch+xor {:.1?}",
                                n, wall, dpf_sum, fetch_sum,
                                dpf_sum / n as u32, fetch_sum / n as u32);
                            Response::IndexBatch(batch)
                        }
                        Request::ChunkBatch(q) => {
                            let t = Instant::now();
                            let round = q.round_id;
                            let n = q.keys.len();
                            let (batch, dpf_sum, fetch_sum) = data_ref.process_chunk_batch(&q);
                            let wall = t.elapsed();
                            println!("[chunk] r{} {} groups {:.2?} wall | sum: dpf {:.2?} fetch+xor {:.2?} | avg: dpf {:.1?} fetch+xor {:.1?}",
                                round, n, wall, dpf_sum, fetch_sum,
                                dpf_sum / n as u32, fetch_sum / n as u32);
                            Response::ChunkBatch(batch)
                        }
                        Request::MerkleSiblingBatch(_) | Request::BucketMerkleSibBatch(_) => {
                            Response::Error("merkle queries not supported by legacy server".into())
                        }
                        Request::HarmonyGetInfo => Response::HarmonyInfo(ServerInfo {
                            index_bins_per_table: data_ref.tables.index_bins_per_table as u32,
                            chunk_bins_per_table: data_ref.tables.chunk_bins_per_table as u32,
                            index_k: K as u8,
                            chunk_k: K_CHUNK as u8,
                            tag_seed: data_ref.tables.tag_seed,
                        }),
                        Request::HarmonyQuery(q) => {
                            let t = Instant::now();
                            let result = data_ref.handle_harmony_query(&q);
                            let wall = t.elapsed();
                            println!("[harmony] L{} B{} {} indices {:.2?}",
                                q.level, q.group_id, q.indices.len(), wall);
                            result
                        }
                        Request::HarmonyBatchQuery(q) => {
                            let t = Instant::now();
                            let n = q.items.len();
                            let result = data_ref.handle_harmony_batch_query(&q);
                            let wall = t.elapsed();
                            println!("[harmony-batch] L{} {} groups × {} sub-q {:.2?}",
                                q.level, n, q.sub_queries_per_group, wall);
                            result
                        }
                        Request::HarmonyHints(_) => {
                            // Hint generation is handled by the dedicated Hint Server,
                            // not the Query Server.
                            Response::Error("hint requests not supported on query server".into())
                        }
                    }
                }).await.unwrap();

                let encoded = response.encode();
                if let Err(e) = sink.send(Message::Binary(encoded.into())).await {
                    eprintln!("[{}] Send error: {}", peer, e);
                    break;
                }
            }

            println!("[{}] Disconnected", peer);
        });
    }
}
