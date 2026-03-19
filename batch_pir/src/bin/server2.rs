//! Two-level Batch PIR WebSocket server.
//!
//! Loads both cuckoo tables (index + chunk) and serves DPF queries.
//! Each client sends batches of DPF keys; the server evaluates them
//! in parallel and returns XOR-accumulated results.
//!
//! Usage:
//!   cargo run --release -p batch_pir --bin server2 -- --port 8093

use batch_pir::eval;
use batch_pir::protocol::{BatchQuery, BatchResult, Request, Response, ServerInfo};
use build_batchdb::common::*;
use futures_util::{SinkExt, StreamExt};
use libdpf::DpfKey;
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::{self, File};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

// ─── Server data ────────────────────────────────────────────────────────────

struct ServerData {
    // Level 1 (Index)
    index_cuckoo: Vec<u8>,
    index_data: Mmap,
    index_bins_per_table: usize,
    index_table_byte_size: usize,

    // Level 2 (Chunk)
    chunk_cuckoo: Vec<u8>,
    chunks_data: Mmap,
    chunk_bins_per_table: usize,
    chunk_table_byte_size: usize,
}

impl ServerData {
    fn load() -> Self {
        println!("[1] Loading index cuckoo: {}", CUCKOO_FILE);
        let index_cuckoo = fs::read(CUCKOO_FILE).expect("read index cuckoo");
        let index_bins_per_table = read_cuckoo_header(&index_cuckoo);
        let index_table_byte_size = index_bins_per_table * CUCKOO_BUCKET_SIZE * 4;
        println!("  bins_per_table = {}, table_size = {:.1} MB",
            index_bins_per_table,
            index_table_byte_size as f64 / (1024.0 * 1024.0));

        println!("[2] Loading index data: {}", INDEX_FILE);
        let index_file = File::open(INDEX_FILE).expect("open index");
        let index_data = unsafe { Mmap::map(&index_file) }.expect("mmap index");
        println!("  {} entries ({:.1} MB)",
            index_data.len() / INDEX_ENTRY_SIZE,
            index_data.len() as f64 / (1024.0 * 1024.0));

        println!("[3] Loading chunk cuckoo: {}", CHUNK_CUCKOO_FILE);
        let chunk_cuckoo = fs::read(CHUNK_CUCKOO_FILE).expect("read chunk cuckoo");
        let chunk_bins_per_table = read_chunk_cuckoo_header(&chunk_cuckoo);
        let chunk_table_byte_size = chunk_bins_per_table * CUCKOO_BUCKET_SIZE * 4;
        println!("  bins_per_table = {}, table_size = {:.1} MB",
            chunk_bins_per_table,
            chunk_table_byte_size as f64 / (1024.0 * 1024.0));

        println!("[4] Loading chunks data: {}", CHUNKS_DATA_FILE);
        let chunks_file = File::open(CHUNKS_DATA_FILE).expect("open chunks");
        let chunks_data = unsafe { Mmap::map(&chunks_file) }.expect("mmap chunks");
        println!("  {:.2} GB", chunks_data.len() as f64 / (1024.0 * 1024.0 * 1024.0));

        ServerData {
            index_cuckoo,
            index_data,
            index_bins_per_table,
            index_table_byte_size,
            chunk_cuckoo,
            chunks_data,
            chunk_bins_per_table,
            chunk_table_byte_size,
        }
    }

    fn process_index_batch(&self, query: &BatchQuery) -> BatchResult {
        let num_buckets = query.keys.len().min(K);
        let results: Vec<(Vec<u8>, Vec<u8>)> = (0..num_buckets)
            .into_par_iter()
            .map(|b| {
                let key_q0 = DpfKey::from_bytes(&query.keys[b].0).expect("bad dpf key q0");
                let key_q1 = DpfKey::from_bytes(&query.keys[b].1).expect("bad dpf key q1");
                let table_offset = HEADER_SIZE + b * self.index_table_byte_size;
                let table_bytes = &self.index_cuckoo[table_offset..table_offset + self.index_table_byte_size];
                eval::process_index_bucket(
                    &key_q0, &key_q1,
                    table_bytes, &self.index_data,
                    self.index_bins_per_table,
                )
            })
            .collect();

        BatchResult {
            level: 0,
            round_id: 0,
            results,
        }
    }

    fn process_chunk_batch(&self, query: &BatchQuery) -> BatchResult {
        let num_buckets = query.keys.len().min(K_CHUNK);
        let results: Vec<(Vec<u8>, Vec<u8>)> = (0..num_buckets)
            .into_par_iter()
            .map(|b| {
                let key_q0 = DpfKey::from_bytes(&query.keys[b].0).expect("bad dpf key q0");
                let key_q1 = DpfKey::from_bytes(&query.keys[b].1).expect("bad dpf key q1");
                let table_offset = HEADER_SIZE + b * self.chunk_table_byte_size;
                let table_bytes = &self.chunk_cuckoo[table_offset..table_offset + self.chunk_table_byte_size];
                eval::process_chunk_bucket(
                    &key_q0, &key_q1,
                    table_bytes, &self.chunks_data,
                    self.chunk_bins_per_table,
                )
            })
            .collect();

        BatchResult {
            level: 1,
            round_id: query.round_id,
            results,
        }
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn parse_port() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 8093u16;
    let mut i = 1;
    while i < args.len() {
        if (args[i] == "--port" || args[i] == "-p") && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(8093);
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
    println!("  Index: K={}, bins_per_table={}", K, data.index_bins_per_table);
    println!("  Chunk: K={}, bins_per_table={}, CHUNKS_PER_UNIT={}",
        K_CHUNK, data.chunk_bins_per_table, CHUNKS_PER_UNIT);
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
                        Request::GetInfo => Response::Info(ServerInfo {
                            index_bins_per_table: data_ref.index_bins_per_table as u32,
                            chunk_bins_per_table: data_ref.chunk_bins_per_table as u32,
                            index_k: K as u8,
                            chunk_k: K_CHUNK as u8,
                        }),
                        Request::IndexBatch(q) => {
                            let t = Instant::now();
                            let r = data_ref.process_index_batch(&q);
                            println!("[index] {} buckets in {:.2?}", q.keys.len(), t.elapsed());
                            Response::IndexBatch(r)
                        }
                        Request::ChunkBatch(q) => {
                            let t = Instant::now();
                            let round = q.round_id;
                            let r = data_ref.process_chunk_batch(&q);
                            println!("[chunk] round {} {} buckets in {:.2?}", round, q.keys.len(), t.elapsed());
                            Response::ChunkBatch(r)
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
