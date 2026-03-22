//! Two-level Batch PIR WebSocket server.
//!
//! Loads both cuckoo tables (index + chunk) and serves DPF queries.
//! Each client sends batches of DPF keys; the server evaluates them
//! in parallel and returns XOR-accumulated results.
//!
//! Usage:
//!   cargo run --release -p runtime --bin server -- --port 8091

use runtime::eval::{self, BucketTiming};
use runtime::protocol::{BatchQuery, BatchResult, Request, Response, ServerInfo};
use build::common::*;
use futures_util::{SinkExt, StreamExt};
use libdpf::DpfKey;
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

// ─── Server data ────────────────────────────────────────────────────────────

struct ServerData {
    // Level 1 (Index) — inlined cuckoo table
    index_cuckoo: Mmap,
    index_bins_per_table: usize,
    index_table_byte_size: usize,
    tag_seed: u64,

    // Level 2 (Chunk) — inlined cuckoo table
    chunk_cuckoo: Mmap,
    chunk_bins_per_table: usize,
    chunk_table_byte_size: usize,
}

impl ServerData {
    fn load() -> Self {
        println!("[1] Loading inlined index cuckoo: {}", CUCKOO_FILE);
        let index_cuckoo_file = File::open(CUCKOO_FILE).expect("open index cuckoo");
        let index_cuckoo = unsafe { Mmap::map(&index_cuckoo_file) }.expect("mmap index cuckoo");
        let (index_bins_per_table, tag_seed) = read_cuckoo_header(&index_cuckoo);
        // Inlined: each bin has CUCKOO_BUCKET_SIZE slots × INDEX_SLOT_SIZE bytes
        let index_table_byte_size = index_bins_per_table * CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE;
        println!("  bins_per_table = {}, slot_size = {}B, table_size = {:.1} MB",
            index_bins_per_table, INDEX_SLOT_SIZE,
            index_table_byte_size as f64 / (1024.0 * 1024.0));
        println!("  tag_seed = 0x{:016x}", tag_seed);
        println!("  total file = {:.2} GB", index_cuckoo.len() as f64 / (1024.0 * 1024.0 * 1024.0));

        // Advise sequential access for the inlined table
        #[cfg(unix)]
        {
            use libc::{madvise, MADV_SEQUENTIAL};
            unsafe {
                madvise(
                    index_cuckoo.as_ptr() as *mut libc::c_void,
                    index_cuckoo.len(),
                    MADV_SEQUENTIAL,
                );
            }
        }

        println!("[2] Loading inlined chunk cuckoo: {}", CHUNK_CUCKOO_FILE);
        let chunk_cuckoo_file = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
        let chunk_cuckoo = unsafe { Mmap::map(&chunk_cuckoo_file) }.expect("mmap chunk cuckoo");
        let chunk_bins_per_table = read_chunk_cuckoo_header(&chunk_cuckoo);
        // Inlined: each bin has CHUNK_CUCKOO_BUCKET_SIZE slots × CHUNK_SLOT_SIZE bytes
        let chunk_slot_size = 4 + CHUNK_SIZE; // 44 bytes
        let chunk_table_byte_size = chunk_bins_per_table * CHUNK_CUCKOO_BUCKET_SIZE * chunk_slot_size;
        println!("  bins_per_table = {}, slot_size = {}B, table_size = {:.1} MB",
            chunk_bins_per_table, chunk_slot_size,
            chunk_table_byte_size as f64 / (1024.0 * 1024.0));
        println!("  total file = {:.2} GB", chunk_cuckoo.len() as f64 / (1024.0 * 1024.0 * 1024.0));

        // Advise sequential access for the inlined table
        #[cfg(unix)]
        {
            use libc::{madvise, MADV_SEQUENTIAL};
            unsafe {
                madvise(
                    chunk_cuckoo.as_ptr() as *mut libc::c_void,
                    chunk_cuckoo.len(),
                    MADV_SEQUENTIAL,
                );
            }
        }

        ServerData {
            index_cuckoo,
            index_bins_per_table,
            index_table_byte_size,
            tag_seed,
            chunk_cuckoo,
            chunk_bins_per_table,
            chunk_table_byte_size,
        }
    }

    fn process_index_batch(&self, query: &BatchQuery) -> (BatchResult, Duration, Duration) {
        let num_buckets = query.keys.len().min(K);
        let bucket_results: Vec<(Vec<Vec<u8>>, BucketTiming)> = (0..num_buckets)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b].iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_offset = HEADER_SIZE + b * self.index_table_byte_size;
                let table_bytes = &self.index_cuckoo[table_offset..table_offset + self.index_table_byte_size];
                let (r0, r1, timing) = eval::process_index_bucket(
                    &key_refs[0], &key_refs[1],
                    table_bytes,
                    self.index_bins_per_table,
                );
                (vec![r0, r1], timing)
            })
            .collect();

        let mut total_dpf = Duration::ZERO;
        let mut total_fetch = Duration::ZERO;
        let mut results = Vec::with_capacity(num_buckets);
        for (r, t) in bucket_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }

        (BatchResult { level: 0, round_id: 0, results }, total_dpf, total_fetch)
    }

    fn process_chunk_batch(&self, query: &BatchQuery) -> (BatchResult, Duration, Duration) {
        let num_buckets = query.keys.len().min(K_CHUNK);
        let bucket_results: Vec<(Vec<Vec<u8>>, BucketTiming)> = (0..num_buckets)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b].iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_offset = CHUNK_HEADER_SIZE + b * self.chunk_table_byte_size;
                let table_bytes = &self.chunk_cuckoo[table_offset..table_offset + self.chunk_table_byte_size];
                let (r, timing) = eval::process_chunk_bucket(
                    &key_refs,
                    table_bytes,
                    self.chunk_bins_per_table,
                );
                (r, timing)
            })
            .collect();

        let mut total_dpf = Duration::ZERO;
        let mut total_fetch = Duration::ZERO;
        let mut results = Vec::with_capacity(num_buckets);
        for (r, t) in bucket_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }

        (BatchResult { level: 1, round_id: query.round_id, results }, total_dpf, total_fetch)
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
        K, data.index_bins_per_table, INDEX_CUCKOO_NUM_HASHES, CUCKOO_BUCKET_SIZE);
    println!("  Chunk: K={}, bins_per_table={}, cuckoo={}-hash bs={}",
        K_CHUNK, data.chunk_bins_per_table, CHUNK_CUCKOO_NUM_HASHES, CHUNK_CUCKOO_BUCKET_SIZE);
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
                            tag_seed: data_ref.tag_seed,
                        }),
                        Request::IndexBatch(q) => {
                            let t = Instant::now();
                            let n = q.keys.len();
                            let (batch, dpf_sum, fetch_sum) = data_ref.process_index_batch(&q);
                            let wall = t.elapsed();
                            println!("[index] {} buckets {:.2?} wall | sum: dpf {:.2?} fetch+xor {:.2?} | avg: dpf {:.1?} fetch+xor {:.1?}",
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
                            println!("[chunk] r{} {} buckets {:.2?} wall | sum: dpf {:.2?} fetch+xor {:.2?} | avg: dpf {:.1?} fetch+xor {:.1?}",
                                round, n, wall, dpf_sum, fetch_sum,
                                dpf_sum / n as u32, fetch_sum / n as u32);
                            Response::ChunkBatch(batch)
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
