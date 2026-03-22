//! OnionPIR v2 server — new 3840B entry layout with shared NTT store.
//!
//! Loads:
//!   - Shared NTT store (13 GB mmap, chunk level)
//!   - Chunk cuckoo tables (bin → entry_id mapping)
//!   - Index PIR databases (75 preprocessed files)
//!
//! Architecture:
//!   - 80 chunk PirServer instances using set_shared_database (shared NTT store)
//!   - 75 index PirServer instances using load_db (per-group preprocessed files)
//!   - All PIR operations on a dedicated OS thread (not Send/Sync)
//!   - WebSocket interface, same wire protocol as v1
//!
//! Usage:
//!   cargo run --release -p runtime --bin onionpir2_server -- --port 8091

use runtime::onionpir::*;
use runtime::protocol;
use futures_util::{SinkExt, StreamExt};
use memmap2::Mmap;
use onionpir::{self, Server as PirServer, KeyStore};
use std::fs::File;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

// ─── Data file paths ────────────────────────────────────────────────────────

const NTT_STORE_FILE: &str = "/Volumes/Bitcoin/data/onion_shared_ntt.bin";
const CHUNK_CUCKOO_FILE: &str = "/Volumes/Bitcoin/data/onion_chunk_cuckoo.bin";
const INDEX_PIR_DIR: &str = "/Volumes/Bitcoin/data/onion_index_pir";
const INDEX_META_FILE: &str = "/Volumes/Bitcoin/data/onion_index_meta.bin";

/// OnionPIR entry size
#[allow(dead_code)]
const PACKED_ENTRY_SIZE: usize = 3840;

// ─── Chunk cuckoo file header ───────────────────────────────────────────────

const CHUNK_CUCKOO_MAGIC: u64 = 0xBA7C_0010_0000_0001;
const CHUNK_CUCKOO_HEADER_SIZE: usize = 36;

#[allow(dead_code)]
struct ChunkCuckooHeader {
    k_chunk: usize,
    cuckoo_num_hashes: usize,
    bins_per_table: usize,
    master_seed: u64,
    num_packed_entries: usize,
}

fn read_chunk_cuckoo_header(data: &[u8]) -> ChunkCuckooHeader {
    assert!(data.len() >= CHUNK_CUCKOO_HEADER_SIZE);
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(magic, CHUNK_CUCKOO_MAGIC, "Bad chunk cuckoo magic");
    ChunkCuckooHeader {
        k_chunk: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        cuckoo_num_hashes: u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        master_seed: u64::from_le_bytes(data[20..28].try_into().unwrap()),
        num_packed_entries: u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize,
    }
}

// ─── Index meta file ────────────────────────────────────────────────────────

const INDEX_META_MAGIC: u64 = 0xBA7C_0010_0000_0002;

#[allow(dead_code)]
struct IndexMeta {
    k: usize,
    cuckoo_num_hashes: usize,
    cuckoo_bucket_size: usize,
    bins_per_table: usize,
    master_seed: u64,
    tag_seed: u64,
    slot_size: usize,
}

fn read_index_meta(data: &[u8]) -> IndexMeta {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(magic, INDEX_META_MAGIC, "Bad index meta magic");
    IndexMeta {
        k: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        cuckoo_num_hashes: u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize,
        cuckoo_bucket_size: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize,
        master_seed: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        tag_seed: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        slot_size: u32::from_le_bytes(data[40..44].try_into().unwrap()) as usize,
    }
}

// ─── Commands for PIR worker thread ─────────────────────────────────────────

enum PirCommand {
    RegisterKeys {
        client_id: u64,
        galois_keys: Vec<u8>,
        gsw_keys: Vec<u8>,
        reply: oneshot::Sender<()>,
    },
    AnswerBatch {
        client_id: u64,
        level: u8, // 0=index, 1=chunk
        round_id: u16,
        queries: Vec<Vec<u8>>,
        reply: oneshot::Sender<Vec<Vec<u8>>>,
    },
}

// ─── Server info for clients ────────────────────────────────────────────────

struct ServerInfoV2 {
    index_k: u8,
    chunk_k: u8,
    index_bins_per_table: u32,
    chunk_bins_per_table: u32,
    tag_seed: u64,
    total_packed_entries: u32,
    index_cuckoo_bucket_size: u16,
    index_slot_size: u8,
}

impl ServerInfoV2 {
    fn encode(&self) -> Vec<u8> {
        let payload_len = 1 + 1 + 1 + 4 + 4 + 8 + 4 + 2 + 1; // 26
        let mut buf = Vec::with_capacity(4 + payload_len);
        buf.extend_from_slice(&(payload_len as u32).to_le_bytes());
        buf.push(protocol::RESP_INFO);
        buf.push(self.index_k);
        buf.push(self.chunk_k);
        buf.extend_from_slice(&self.index_bins_per_table.to_le_bytes());
        buf.extend_from_slice(&self.chunk_bins_per_table.to_le_bytes());
        buf.extend_from_slice(&self.tag_seed.to_le_bytes());
        buf.extend_from_slice(&self.total_packed_entries.to_le_bytes());
        buf.extend_from_slice(&self.index_cuckoo_bucket_size.to_le_bytes());
        buf.push(self.index_slot_size);
        buf
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn parse_args() -> u16 {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 8091u16;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--port" || args[i] == "-p" {
            port = args[i + 1].parse().unwrap_or(8091);
            i += 1;
        }
        i += 1;
    }
    port
}

#[tokio::main]
async fn main() {
    let port = parse_args();

    println!("=== OnionPIR v2 Server (3840B entries, shared NTT store) ===\n");
    let total_start = Instant::now();

    // ── 1. Load chunk cuckoo tables ─────────────────────────────────────
    println!("[1] Loading chunk cuckoo tables: {}", CHUNK_CUCKOO_FILE);
    let cuckoo_file = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
    let cuckoo_mmap = unsafe { Mmap::map(&cuckoo_file) }.expect("mmap chunk cuckoo");
    let ch = read_chunk_cuckoo_header(&cuckoo_mmap);
    println!("  K_chunk={}, bins_per_table={}, num_hashes={}, total_packed={}",
        ch.k_chunk, ch.bins_per_table, ch.cuckoo_num_hashes, ch.num_packed_entries);

    // Parse per-group cuckoo tables (array of u32 entry_ids)
    let mut chunk_tables: Vec<Vec<u32>> = Vec::with_capacity(ch.k_chunk);
    for g in 0..ch.k_chunk {
        let offset = CHUNK_CUCKOO_HEADER_SIZE + g * ch.bins_per_table * 4;
        let mut table = Vec::with_capacity(ch.bins_per_table);
        for b in 0..ch.bins_per_table {
            let pos = offset + b * 4;
            let eid = u32::from_le_bytes(cuckoo_mmap[pos..pos + 4].try_into().unwrap());
            table.push(eid);
        }
        chunk_tables.push(table);
    }

    // ── 2. Load shared NTT store ────────────────────────────────────────
    println!("[2] Loading shared NTT store: {}", NTT_STORE_FILE);
    let ntt_file = File::open(NTT_STORE_FILE).expect("open NTT store");
    let ntt_mmap = unsafe { Mmap::map(&ntt_file) }.expect("mmap NTT store");
    println!("  Size: {:.2} GB", ntt_mmap.len() as f64 / 1e9);

    // ── 3. Load index metadata ──────────────────────────────────────────
    println!("[3] Loading index metadata: {}", INDEX_META_FILE);
    let meta_file = File::open(INDEX_META_FILE).expect("open index meta");
    let meta_mmap = unsafe { Mmap::map(&meta_file) }.expect("mmap index meta");
    let im = read_index_meta(&meta_mmap);
    println!("  K={}, bins_per_table={}, bucket_size={}, slot_size={}",
        im.k, im.bins_per_table, im.cuckoo_bucket_size, im.slot_size);

    // ── 4. Set up PIR servers on worker thread ──────────────────────────
    let (pir_tx, mut pir_rx) = mpsc::channel::<PirCommand>(64);

    let k_index = im.k;
    let k_chunk = ch.k_chunk;
    let index_bins = im.bins_per_table;
    let chunk_bins = ch.bins_per_table;

    let _pir_thread = std::thread::spawn(move || {
        // ── Create shared key store ──────────────────────────────────
        // One KeyStore for all 155 servers — keys deserialized ONCE.
        // MUST be Box'd: set_key_store stores a raw pointer, so the
        // KeyStore must not move after servers are attached (same pattern
        // as chunk_index_tables for set_shared_database).
        let mut key_store = Box::new(KeyStore::new(0));

        // ── Set up chunk servers (shared NTT store) ─────────────────
        println!("\n[4a] Setting up {} chunk PIR servers (shared NTT store)...", k_chunk);
        let t = Instant::now();

        let p_chunk = onionpir::params_info(chunk_bins as u64);
        let padded_chunk = p_chunk.num_entries as usize;
        let _coeff_val_cnt = p_chunk.coeff_val_cnt as usize;

        let ntt_u64_ptr = ntt_mmap.as_ptr() as *const u64;

        // IMPORTANT: index tables must live as long as the servers, because
        // set_shared_database stores raw pointers (does NOT copy).
        let mut chunk_index_tables: Vec<Vec<u32>> = Vec::with_capacity(k_chunk);
        let mut chunk_servers: Vec<PirServer> = Vec::with_capacity(k_chunk);
        for g in 0..k_chunk {
            let mut server = PirServer::new(chunk_bins as u64);

            // Build index table: index_table[logical_pos] = entry_id in shared store
            let mut index_table = vec![0u32; padded_chunk];
            for bin in 0..chunk_bins {
                let eid = chunk_tables[g][bin];
                if eid != u32::MAX {
                    index_table[bin] = eid;
                }
            }

            unsafe {
                server.set_shared_database(ntt_u64_ptr, ch.num_packed_entries, &index_table);
                server.set_key_store(&key_store);
            }
            chunk_index_tables.push(index_table);
            chunk_servers.push(server);
        }
        // chunk_index_tables must not be dropped before chunk_servers
        println!("  Chunk servers ready in {:.2?}", t.elapsed());

        // ── Set up index servers (load preprocessed DBs) ────────────
        println!("[4b] Loading {} index PIR databases...", k_index);
        let t = Instant::now();

        let mut index_servers: Vec<PirServer> = Vec::with_capacity(k_index);
        for b in 0..k_index {
            let path = Path::new(INDEX_PIR_DIR).join(format!("bucket_{}.bin", b));
            let mut server = PirServer::new(index_bins as u64);
            assert!(
                server.load_db(path.to_str().unwrap()),
                "Failed to load index database: {:?}", path
            );
            unsafe { server.set_key_store(&key_store); }
            index_servers.push(server);
        }
        println!("  Index servers ready in {:.2?}", t.elapsed());
        println!();

        // ── Event loop ──────────────────────────────────────────────
        while let Some(cmd) = pir_rx.blocking_recv() {
            match cmd {
                PirCommand::RegisterKeys { client_id, galois_keys, gsw_keys, reply } => {
                    let t = Instant::now();
                    // Deserialize once into shared store — all servers see it
                    key_store.set_galois_key(client_id, &galois_keys);
                    key_store.set_gsw_key(client_id, &gsw_keys);
                    println!("[keys] client {} registered (shared store) in {:.2?}",
                        client_id, t.elapsed());
                    let _ = reply.send(());
                }
                PirCommand::AnswerBatch { client_id, level, round_id, queries, reply } => {
                    let t = Instant::now();
                    let servers = if level == 0 { &mut index_servers } else { &mut chunk_servers };
                    assert_eq!(queries.len(), servers.len(), "query count mismatch");
                    let results: Vec<Vec<u8>> = queries.iter().enumerate().map(|(b, q)| {
                        if q.is_empty() {
                            Vec::new()
                        } else {
                            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                servers[b].answer_query(client_id, q)
                            })) {
                                Ok(result) => result,
                                Err(e) => {
                                    eprintln!("[ERROR] answer_query panicked for group {}: {:?}", b, e);
                                    Vec::new()
                                }
                            }
                        }
                    }).collect();
                    let level_name = if level == 0 { "index" } else { "chunk" };
                    println!("[{}] r{} {} groups answered in {:.2?}",
                        level_name, round_id, queries.len(), t.elapsed());
                    let _ = reply.send(results);
                }
            }
        }
    });

    let info = Arc::new(ServerInfoV2 {
        index_k: k_index as u8,
        chunk_k: k_chunk as u8,
        index_bins_per_table: index_bins as u32,
        chunk_bins_per_table: chunk_bins as u32,
        tag_seed: im.tag_seed,
        total_packed_entries: ch.num_packed_entries as u32,
        index_cuckoo_bucket_size: im.cuckoo_bucket_size as u16,
        index_slot_size: im.slot_size as u8,
    });
    let pir_tx = Arc::new(pir_tx);

    println!("Data loaded in {:.2?}\n", total_start.elapsed());

    // ── Accept WebSocket connections ─────────────────────────────────────
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("Listening on ws://{}", addr);
    println!("  Index: K={}, bins_per_table={}, bucket_size={}",
        k_index, index_bins, im.cuckoo_bucket_size);
    println!("  Chunk: K={}, bins_per_table={}, total_packed={}",
        k_chunk, chunk_bins, ch.num_packed_entries);
    println!();

    let client_counter = std::sync::atomic::AtomicU64::new(1);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => { eprintln!("Accept error: {}", e); continue; }
        };

        let client_id = client_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        println!("[{}] Connected (client_id={})", peer, client_id);

        let info = Arc::clone(&info);
        let pir_tx = Arc::clone(&pir_tx);

        tokio::spawn(async move {
            let ws = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => { eprintln!("[{}] Handshake failed: {}", peer, e); return; }
            };
            let (mut sink, mut ws_stream) = ws.split();

            while let Some(msg) = ws_stream.next().await {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => { eprintln!("[{}] Read error: {}", peer, e); break; }
                };
                let bin = match msg {
                    Message::Binary(b) => b,
                    Message::Ping(p) => { let _ = sink.send(Message::Pong(p)).await; continue; }
                    Message::Close(_) => break,
                    _ => continue,
                };
                if bin.len() < 5 { continue; }
                let payload = &bin[4..];
                let variant = payload[0];
                let body = &payload[1..];

                match variant {
                    protocol::REQ_PING => {
                        let mut resp = Vec::with_capacity(5);
                        resp.extend_from_slice(&1u32.to_le_bytes());
                        resp.push(protocol::RESP_PONG);
                        let _ = sink.send(Message::Binary(resp.into())).await;
                    }
                    protocol::REQ_GET_INFO => {
                        let encoded = info.encode();
                        let _ = sink.send(Message::Binary(encoded.into())).await;
                    }
                    REQ_REGISTER_KEYS => {
                        match RegisterKeysMsg::decode(body) {
                            Ok(keys_msg) => {
                                let (tx, rx) = oneshot::channel();
                                let _ = pir_tx.send(PirCommand::RegisterKeys {
                                    client_id,
                                    galois_keys: keys_msg.galois_keys,
                                    gsw_keys: keys_msg.gsw_keys,
                                    reply: tx,
                                }).await;
                                let _ = rx.await;
                                let mut resp = Vec::with_capacity(5);
                                resp.extend_from_slice(&1u32.to_le_bytes());
                                resp.push(RESP_KEYS_ACK);
                                let _ = sink.send(Message::Binary(resp.into())).await;
                            }
                            Err(e) => eprintln!("[{}] Bad keys: {}", peer, e),
                        }
                    }
                    REQ_ONIONPIR_INDEX_QUERY => {
                        match OnionPirBatchQuery::decode(body) {
                            Ok(batch) => {
                                let (tx, rx) = oneshot::channel();
                                let _ = pir_tx.send(PirCommand::AnswerBatch {
                                    client_id, level: 0,
                                    round_id: batch.round_id,
                                    queries: batch.queries, reply: tx,
                                }).await;
                                let results = rx.await.unwrap();
                                let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                                let _ = sink.send(Message::Binary(result_msg.encode(RESP_ONIONPIR_INDEX_RESULT).into())).await;
                            }
                            Err(e) => eprintln!("[{}] Bad index query: {}", peer, e),
                        }
                    }
                    REQ_ONIONPIR_CHUNK_QUERY => {
                        match OnionPirBatchQuery::decode(body) {
                            Ok(batch) => {
                                let (tx, rx) = oneshot::channel();
                                let _ = pir_tx.send(PirCommand::AnswerBatch {
                                    client_id, level: 1,
                                    round_id: batch.round_id,
                                    queries: batch.queries, reply: tx,
                                }).await;
                                let results = rx.await.unwrap();
                                let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                                let _ = sink.send(Message::Binary(result_msg.encode(RESP_ONIONPIR_CHUNK_RESULT).into())).await;
                            }
                            Err(e) => eprintln!("[{}] Bad chunk query: {}", peer, e),
                        }
                    }
                    v => eprintln!("[{}] Unknown variant: 0x{:02x}", peer, v),
                }
            }
            println!("[{}] Disconnected (client_id={})", peer, client_id);
        });
    }
}
