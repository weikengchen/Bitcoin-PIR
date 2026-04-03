//! Unified PIR WebSocket server — serves all 3 protocols from one process.
//!
//! Roles:
//!   --role primary   (default): DPF + OnionPIR + HarmonyPIR (hint + query)
//!   --role secondary:           DPF only (2nd server for 2-server DPF protocol)
//!
//! Uses pir-core's MappedDatabase for table loading instead of legacy CuckooTablePair.
//!
//! Usage:
//!   unified_server --port 8091 [--data-dir /Volumes/Bitcoin/data] [--role primary|secondary]

use runtime::eval::{self, BucketTiming};
use runtime::protocol::*;
use runtime::onionpir::*;
use runtime::table::{MappedDatabase, MappedSubTable, DatabaseDescriptor};

use futures_util::{SinkExt, StreamExt};
use libdpf::DpfKey;
use pir_core::params::{self, INDEX_PARAMS, CHUNK_PARAMS};
use rayon::prelude::*;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

// HarmonyPIR imports
use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;

// OnionPIR imports
use memmap2::Mmap;
use onionpir::{self, Server as PirServer, KeyStore};

// ─── CLI ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum ServerRole {
    Primary,
    Secondary,
}

struct CliArgs {
    port: u16,
    data_dir: PathBuf,
    role: ServerRole,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 8091u16;
    let mut data_dir = PathBuf::from("/Volumes/Bitcoin/data");
    let mut role = ServerRole::Primary;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                port = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(8091);
                i += 1;
            }
            "--data-dir" | "-d" => {
                if let Some(dir) = args.get(i + 1) {
                    data_dir = PathBuf::from(dir);
                }
                i += 1;
            }
            "--role" | "-r" => {
                if let Some(r) = args.get(i + 1) {
                    role = match r.as_str() {
                        "secondary" | "s" | "2" => ServerRole::Secondary,
                        _ => ServerRole::Primary,
                    };
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    CliArgs { port, data_dir, role }
}

// ─── OnionPIR worker thread ─────────────────────────────────────────────────

enum PirCommand {
    RegisterKeys {
        client_id: u64,
        galois_keys: Vec<u8>,
        gsw_keys: Vec<u8>,
        reply: oneshot::Sender<()>,
    },
    AnswerBatch {
        client_id: u64,
        level: u8,
        round_id: u16,
        queries: Vec<Vec<u8>>,
        reply: oneshot::Sender<Vec<Vec<u8>>>,
    },
}

// ─── OnionPIR file paths + headers ──────────────────────────────────────────

const ONION_NTT_FILE: &str = "onion_shared_ntt.bin";
const ONION_CHUNK_CUCKOO_FILE: &str = "onion_chunk_cuckoo.bin";
const ONION_INDEX_PIR_DIR: &str = "onion_index_pir";
const ONION_INDEX_META_FILE: &str = "onion_index_meta.bin";

const ONION_CHUNK_MAGIC: u64 = 0xBA7C_0010_0000_0001;
const ONION_INDEX_META_MAGIC: u64 = 0xBA7C_0010_0000_0002;

struct OnionChunkHeader {
    k_chunk: usize,
    bins_per_table: usize,
    num_packed_entries: usize,
}

fn read_onion_chunk_header(data: &[u8]) -> OnionChunkHeader {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(magic, ONION_CHUNK_MAGIC, "Bad onion chunk cuckoo magic");
    OnionChunkHeader {
        k_chunk: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        num_packed_entries: u32::from_le_bytes(data[28..32].try_into().unwrap()) as usize,
    }
}

struct OnionIndexMeta {
    k: usize,
    bins_per_table: usize,
    cuckoo_bucket_size: usize,
    tag_seed: u64,
    slot_size: usize,
}

fn read_onion_index_meta(data: &[u8]) -> OnionIndexMeta {
    let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
    assert_eq!(magic, ONION_INDEX_META_MAGIC, "Bad onion index meta magic");
    OnionIndexMeta {
        k: u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize,
        bins_per_table: u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize,
        cuckoo_bucket_size: u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize,
        tag_seed: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        slot_size: u32::from_le_bytes(data[40..44].try_into().unwrap()) as usize,
    }
}

// ─── HarmonyPIR hint computation ────────────────────────────────────────────

fn derive_bucket_key(master_key: &[u8; 16], bucket_id: u32) -> [u8; 16] {
    let mut key = *master_key;
    let id_bytes = bucket_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
}

fn xor_into_hint(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

fn compute_hints_for_bucket(
    db: &MappedDatabase,
    prp_key: &[u8; 16],
    prp_backend: u8,
    level: u8,
    bucket_id: u8,
) -> (u8, u32, u32, u32, Vec<u8>) {
    let (sub_table, entry_size, k_offset) = match level {
        0 => (&db.index, db.index.params.bin_size(), 0u32),
        1 => (&db.chunk, db.chunk.params.bin_size(), db.index.params.k as u32),
        _ => panic!("invalid level"),
    };

    let real_n = sub_table.bins_per_table;
    let w = entry_size;

    let t_raw = harmonypir_wasm::find_best_t(real_n as u32);
    let (padded_n, t_val) = harmonypir_wasm::pad_n_for_t(real_n as u32, t_raw);
    let pn = padded_n as usize;
    let t = t_val as usize;

    let params = Params::new(pn, w, t).expect("valid params");
    let m = params.m;

    let derived_key = derive_bucket_key(prp_key, k_offset + bucket_id as u32);
    let domain = 2 * pn;
    let r = harmonypir_wasm::compute_rounds(padded_n);

    use harmonypir::prp::BatchPrp;
    use harmonypir::prp::fast::FastPrpWrapper;
    use harmonypir::prp::alf::AlfPrp;
    let cell_of: Vec<usize> = match prp_backend {
        harmonypir_wasm::PRP_FASTPRP => {
            let prp = FastPrpWrapper::new(&derived_key, domain);
            prp.batch_forward()
        }
        harmonypir_wasm::PRP_ALF => {
            let prp = AlfPrp::new(&derived_key, domain, &derived_key, 0x4250_4952);
            prp.batch_forward()
        }
        _ => {
            let prp = HoangPrp::new(domain, r, &derived_key);
            prp.batch_forward()
        }
    };

    let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();
    let table_bytes = sub_table.bucket_bytes(bucket_id as usize);
    for k in 0..pn {
        let segment = cell_of[k] / t;
        if k < real_n {
            let entry = &table_bytes[k * entry_size..(k + 1) * entry_size];
            xor_into_hint(&mut hints[segment], entry);
        }
    }

    let flat: Vec<u8> = hints.into_iter().flat_map(|h| h.into_iter()).collect();
    (bucket_id, padded_n, t_val as u32, m as u32, flat)
}

// ─── Server state ───────────────────────────────────────────────────────────

struct UnifiedServerData {
    db: MappedDatabase,
    role: ServerRole,
    /// OnionPIR worker channel (None if OnionPIR data not available or secondary role).
    onionpir_tx: Option<Arc<mpsc::Sender<PirCommand>>>,
    /// OnionPIR-specific info for the info response.
    onionpir_packed_entries: Option<u32>,
}

impl UnifiedServerData {
    fn server_info(&self) -> ServerInfo {
        ServerInfo {
            index_bins_per_table: self.db.index.bins_per_table as u32,
            chunk_bins_per_table: self.db.chunk.bins_per_table as u32,
            index_k: self.db.index.params.k as u8,
            chunk_k: self.db.chunk.params.k as u8,
            tag_seed: self.db.index.tag_seed,
        }
    }

    fn build_catalog(&self) -> DatabaseCatalog {
        DatabaseCatalog {
            databases: vec![DatabaseCatalogEntry {
                db_id: 0,
                name: self.db.descriptor.name.clone(),
                height: self.db.descriptor.height,
                index_bins_per_table: self.db.index.bins_per_table as u32,
                chunk_bins_per_table: self.db.chunk.bins_per_table as u32,
                index_k: self.db.index.params.k as u8,
                chunk_k: self.db.chunk.params.k as u8,
                tag_seed: self.db.index.tag_seed,
                dpf_n_index: params::compute_dpf_n(self.db.index.bins_per_table),
                dpf_n_chunk: params::compute_dpf_n(self.db.chunk.bins_per_table),
            }],
        }
    }

    fn process_index_batch(&self, query: &BatchQuery) -> (BatchResult, std::time::Duration, std::time::Duration) {
        let k = self.db.index.params.k;
        let num_buckets = query.keys.len().min(k);
        let bucket_results: Vec<(Vec<Vec<u8>>, BucketTiming)> = (0..num_buckets)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b].iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = self.db.index.bucket_bytes(b);
                let (r0, r1, timing) = eval::process_index_bucket(
                    &key_refs[0], &key_refs[1],
                    table_bytes,
                    self.db.index.bins_per_table,
                );
                (vec![r0, r1], timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_buckets);
        for (r, t) in bucket_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (BatchResult { level: 0, round_id: 0, results }, total_dpf, total_fetch)
    }

    fn process_chunk_batch(&self, query: &BatchQuery) -> (BatchResult, std::time::Duration, std::time::Duration) {
        let k = self.db.chunk.params.k;
        let num_buckets = query.keys.len().min(k);
        let bucket_results: Vec<(Vec<Vec<u8>>, BucketTiming)> = (0..num_buckets)
            .into_par_iter()
            .map(|b| {
                let dpf_keys: Vec<DpfKey> = query.keys[b].iter()
                    .map(|k| DpfKey::from_bytes(k).expect("bad dpf key"))
                    .collect();
                let key_refs: Vec<&DpfKey> = dpf_keys.iter().collect();
                let table_bytes = self.db.chunk.bucket_bytes(b);
                let (r, timing) = eval::process_chunk_bucket(
                    &key_refs,
                    table_bytes,
                    self.db.chunk.bins_per_table,
                );
                (r, timing)
            })
            .collect();

        let mut total_dpf = std::time::Duration::ZERO;
        let mut total_fetch = std::time::Duration::ZERO;
        let mut results = Vec::with_capacity(num_buckets);
        for (r, t) in bucket_results {
            total_dpf += t.dpf_eval;
            total_fetch += t.fetch_xor;
            results.push(r);
        }
        (BatchResult { level: 1, round_id: query.round_id, results }, total_dpf, total_fetch)
    }

    fn handle_harmony_query(&self, query: &HarmonyQuery) -> Response {
        let (sub_table, entry_size) = match query.level {
            0 => (&self.db.index, self.db.index.params.bin_size()),
            1 => (&self.db.chunk, self.db.chunk.params.bin_size()),
            _ => return Response::Error("invalid level".into()),
        };

        let bucket_id = query.bucket_id as usize;
        let table_bytes = sub_table.bucket_bytes(bucket_id);

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
            bucket_id: query.bucket_id,
            round_id: query.round_id,
            data,
        })
    }

    fn handle_harmony_batch_query(&self, query: &HarmonyBatchQuery) -> Response {
        let (sub_table, entry_size) = match query.level {
            0 => (&self.db.index, self.db.index.params.bin_size()),
            1 => (&self.db.chunk, self.db.chunk.params.bin_size()),
            _ => return Response::Error("invalid level".into()),
        };

        let result_items: Vec<HarmonyBatchResultItem> = query.items
            .par_iter()
            .map(|item| {
                let table_bytes = sub_table.bucket_bytes(item.bucket_id as usize);
                let sub_results: Vec<Vec<u8>> = item.sub_queries.iter().map(|indices| {
                    let mut data = Vec::with_capacity(indices.len() * entry_size);
                    for &idx in indices {
                        let idx_usize = idx as usize;
                        if idx_usize < sub_table.bins_per_table {
                            let off = idx_usize * entry_size;
                            data.extend_from_slice(&table_bytes[off..off + entry_size]);
                        } else {
                            data.extend(std::iter::repeat(0u8).take(entry_size));
                        }
                    }
                    data
                }).collect();
                HarmonyBatchResultItem { bucket_id: item.bucket_id, sub_results }
            })
            .collect();

        Response::HarmonyBatchResult(HarmonyBatchResult {
            level: query.level,
            round_id: query.round_id,
            sub_results_per_bucket: query.sub_queries_per_bucket,
            items: result_items,
        })
    }
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = parse_args();
    let role_name = match args.role {
        ServerRole::Primary => "primary",
        ServerRole::Secondary => "secondary",
    };

    println!("=== Unified PIR Server ({}) ===", role_name);
    println!("  Port:     {}", args.port);
    println!("  Data dir: {}", args.data_dir.display());
    println!();

    let total_start = Instant::now();

    // ── Load cuckoo tables via MappedDatabase ───────────────────────────

    let db = MappedDatabase::load(&args.data_dir, DatabaseDescriptor {
        name: "main".to_string(),
        height: 0,
        index_params: INDEX_PARAMS,
        chunk_params: CHUNK_PARAMS,
    });

    let index_k = db.index.params.k;
    let chunk_k = db.chunk.params.k;

    // ── Set up OnionPIR (primary only, if data available) ───────────────

    let mut onionpir_tx: Option<Arc<mpsc::Sender<PirCommand>>> = None;
    let mut onionpir_packed_entries: Option<u32> = None;

    let ntt_path = args.data_dir.join(ONION_NTT_FILE);
    if args.role == ServerRole::Primary && ntt_path.exists() {
        println!("[OnionPIR] Loading data...");

        let chunk_cuckoo_path = args.data_dir.join(ONION_CHUNK_CUCKOO_FILE);
        let index_pir_dir = args.data_dir.join(ONION_INDEX_PIR_DIR);
        let index_meta_path = args.data_dir.join(ONION_INDEX_META_FILE);

        // Read OnionPIR-specific headers
        let cuckoo_data = std::fs::read(&chunk_cuckoo_path).expect("read onion chunk cuckoo");
        let ch = read_onion_chunk_header(&cuckoo_data);
        let meta_data = std::fs::read(&index_meta_path).expect("read onion index meta");
        let im = read_onion_index_meta(&meta_data);

        println!("  Chunk: K={}, bins={}, packed={}", ch.k_chunk, ch.bins_per_table, ch.num_packed_entries);
        println!("  Index: K={}, bins={}, bucket_size={}", im.k, im.bins_per_table, im.cuckoo_bucket_size);

        onionpir_packed_entries = Some(ch.num_packed_entries as u32);

        // Parse chunk cuckoo tables
        let header_size = 36;
        let mut chunk_tables: Vec<Vec<u32>> = Vec::with_capacity(ch.k_chunk);
        for g in 0..ch.k_chunk {
            let offset = header_size + g * ch.bins_per_table * 4;
            let mut table = Vec::with_capacity(ch.bins_per_table);
            for b in 0..ch.bins_per_table {
                let pos = offset + b * 4;
                let eid = u32::from_le_bytes(cuckoo_data[pos..pos + 4].try_into().unwrap());
                table.push(eid);
            }
            chunk_tables.push(table);
        }

        // Load NTT store
        let ntt_file = std::fs::File::open(&ntt_path).expect("open NTT store");
        let ntt_mmap = unsafe { Mmap::map(&ntt_file) }.expect("mmap NTT store");
        println!("  NTT store: {:.2} GB", ntt_mmap.len() as f64 / 1e9);

        let k_index = im.k;
        let k_chunk = ch.k_chunk;
        let index_bins = im.bins_per_table;
        let chunk_bins = ch.bins_per_table;
        let index_pir_dir_clone = index_pir_dir.clone();

        let (tx, mut pir_rx) = mpsc::channel::<PirCommand>(64);
        onionpir_tx = Some(Arc::new(tx));

        // Spawn PIR worker thread
        std::thread::spawn(move || {
            let mut key_store = Box::new(KeyStore::new(0));

            // Set up chunk servers
            let p_chunk = onionpir::params_info(chunk_bins as u64);
            let padded_chunk = p_chunk.num_entries as usize;
            let ntt_u64_ptr = ntt_mmap.as_ptr() as *const u64;

            let mut chunk_index_tables: Vec<Vec<u32>> = Vec::with_capacity(k_chunk);
            let mut chunk_servers: Vec<PirServer> = Vec::with_capacity(k_chunk);
            for g in 0..k_chunk {
                let mut server = PirServer::new(chunk_bins as u64);
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
            println!("  [OnionPIR] {} chunk servers ready", k_chunk);

            // Set up index servers
            let mut index_servers: Vec<PirServer> = Vec::with_capacity(k_index);
            for b in 0..k_index {
                let path = index_pir_dir_clone.join(format!("bucket_{}.bin", b));
                let mut server = PirServer::new(index_bins as u64);
                assert!(server.load_db(path.to_str().unwrap()), "Failed to load {:?}", path);
                unsafe { server.set_key_store(&key_store); }
                index_servers.push(server);
            }
            println!("  [OnionPIR] {} index servers ready", k_index);

            // Event loop
            while let Some(cmd) = pir_rx.blocking_recv() {
                match cmd {
                    PirCommand::RegisterKeys { client_id, galois_keys, gsw_keys, reply } => {
                        let t = Instant::now();
                        key_store.set_galois_key(client_id, &galois_keys);
                        key_store.set_gsw_key(client_id, &gsw_keys);
                        println!("  [OnionPIR] client {} keys registered in {:.2?}", client_id, t.elapsed());
                        let _ = reply.send(());
                    }
                    PirCommand::AnswerBatch { client_id, level, round_id, queries, reply } => {
                        let t = Instant::now();
                        let servers = if level == 0 { &mut index_servers } else { &mut chunk_servers };
                        let results: Vec<Vec<u8>> = if level == 0 {
                            queries.iter().enumerate().map(|(i, q)| {
                                let g = i / 2;
                                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    servers[g].answer_query(client_id, q)
                                })) {
                                    Ok(r) => r,
                                    Err(e) => { eprintln!("[OnionPIR] panic in index group {}: {:?}", g, e); Vec::new() }
                                }
                            }).collect()
                        } else {
                            queries.iter().enumerate().map(|(b, q)| {
                                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    servers[b].answer_query(client_id, q)
                                })) {
                                    Ok(r) => r,
                                    Err(e) => { eprintln!("[OnionPIR] panic in chunk group {}: {:?}", b, e); Vec::new() }
                                }
                            }).collect()
                        };
                        let name = if level == 0 { "index" } else { "chunk" };
                        println!("  [OnionPIR] {} r{} {} queries in {:.2?}", name, round_id, queries.len(), t.elapsed());
                        let _ = reply.send(results);
                    }
                }
            }
        });
    } else if args.role == ServerRole::Primary {
        println!("[OnionPIR] Not available (no {} found)", ONION_NTT_FILE);
    }

    // ── Build server state ──────────────────────────────────────────────

    let server = Arc::new(UnifiedServerData {
        db,
        role: args.role,
        onionpir_tx,
        onionpir_packed_entries,
    });

    println!();
    println!("Data loaded in {:.2?}", total_start.elapsed());
    println!();

    // ── Accept WebSocket connections ────────────────────────────────────

    let addr: SocketAddr = format!("0.0.0.0:{}", args.port).parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("Listening on ws://{}", addr);
    println!("  Role: {}", role_name);
    println!("  Index: K={}, bins_per_table={}", index_k, server.db.index.bins_per_table);
    println!("  Chunk: K={}, bins_per_table={}", chunk_k, server.db.chunk.bins_per_table);
    println!("  OnionPIR: {}", if server.onionpir_tx.is_some() { "enabled" } else { "disabled" });
    match args.role {
        ServerRole::Primary => println!("  HarmonyPIR: query server"),
        ServerRole::Secondary => println!("  HarmonyPIR: hint server"),
    }
    if server.db.has_merkle() { println!("  Merkle: available"); }
    println!();

    let client_counter = std::sync::atomic::AtomicU64::new(1);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => { eprintln!("Accept error: {}", e); continue; }
        };

        let client_id = client_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let server = Arc::clone(&server);

        tokio::spawn(async move {
            let ws = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => { eprintln!("[{}] Handshake failed: {}", peer, e); return; }
            };
            println!("[{}] Connected (id={})", peer, client_id);
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

                // Route by variant byte
                match variant {
                    // ── Shared: info / ping ──────────────────────────────
                    REQ_PING => {
                        let _ = sink.send(Message::Binary(Response::Pong.encode().into())).await;
                    }
                    REQ_GET_INFO => {
                        let _ = sink.send(Message::Binary(Response::Info(server.server_info()).encode().into())).await;
                    }
                    REQ_GET_DB_CATALOG => {
                        let _ = sink.send(Message::Binary(Response::DbCatalog(server.build_catalog()).encode().into())).await;
                    }

                    // ── DPF batch queries (both roles) ──────────────────
                    REQ_INDEX_BATCH => {
                        if let Ok(Request::IndexBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let t = Instant::now();
                                let n = q.keys.len();
                                let (batch, dpf_sum, fetch_sum) = s.process_index_batch(&q);
                                let wall = t.elapsed();
                                println!("[index] {} buckets {:.2?} | dpf {:.2?} fetch+xor {:.2?}", n, wall, dpf_sum, fetch_sum);
                                Response::IndexBatch(batch)
                            }).await.unwrap();
                            let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        }
                    }
                    REQ_CHUNK_BATCH => {
                        if let Ok(Request::ChunkBatch(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || {
                                let t = Instant::now();
                                let n = q.keys.len();
                                let round = q.round_id;
                                let (batch, dpf_sum, fetch_sum) = s.process_chunk_batch(&q);
                                let wall = t.elapsed();
                                println!("[chunk] r{} {} buckets {:.2?} | dpf {:.2?} fetch+xor {:.2?}", round, n, wall, dpf_sum, fetch_sum);
                                Response::ChunkBatch(batch)
                            }).await.unwrap();
                            let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        }
                    }

                    // ── HarmonyPIR ────────────────────────────────────────
                    // Primary  = query server (REQ_HARMONY_QUERY, REQ_HARMONY_BATCH_QUERY)
                    // Secondary = hint server (REQ_HARMONY_HINTS)
                    // Both respond to REQ_HARMONY_GET_INFO
                    REQ_HARMONY_GET_INFO => {
                        let _ = sink.send(Message::Binary(
                            Response::HarmonyInfo(server.server_info()).encode().into()
                        )).await;
                    }
                    REQ_HARMONY_HINTS if server.role == ServerRole::Secondary => {
                        if let Ok(Request::HarmonyHints(hint_req)) = Request::decode(payload) {
                            let t_start = Instant::now();
                            let level = hint_req.level;
                            let num = hint_req.bucket_ids.len();
                            let prp_key: [u8; 16] = hint_req.prp_key;
                            let prp_backend = hint_req.prp_backend;
                            let bucket_ids = hint_req.bucket_ids.clone();
                            let s = Arc::clone(&server);

                            let (tx, mut rx) = tokio::sync::mpsc::channel::<(u8, u32, u32, u32, Vec<u8>)>(4);
                            tokio::task::spawn_blocking(move || {
                                bucket_ids.par_iter().for_each_with(tx, |tx, &bid| {
                                    let result = compute_hints_for_bucket(&s.db, &prp_key, prp_backend, level, bid);
                                    let _ = tx.blocking_send(result);
                                });
                            });

                            let mut sent = 0;
                            while let Some((bucket_id, n, t, m, flat_hints)) = rx.recv().await {
                                let hint_len = 1 + 1 + 4 + 4 + 4 + flat_hints.len();
                                let mut resp = Vec::with_capacity(4 + hint_len);
                                resp.extend_from_slice(&(hint_len as u32).to_le_bytes());
                                resp.push(RESP_HARMONY_HINTS);
                                resp.push(bucket_id);
                                resp.extend_from_slice(&n.to_le_bytes());
                                resp.extend_from_slice(&t.to_le_bytes());
                                resp.extend_from_slice(&m.to_le_bytes());
                                resp.extend_from_slice(&flat_hints);
                                if let Err(e) = sink.send(Message::Binary(resp.into())).await {
                                    eprintln!("[{}] Send error: {}", peer, e);
                                    break;
                                }
                                sent += 1;
                            }
                            println!("[harmony-hint] L{} {}/{} buckets in {:.2?}", level, sent, num, t_start.elapsed());
                        }
                    }
                    REQ_HARMONY_QUERY if server.role == ServerRole::Primary => {
                        if let Ok(Request::HarmonyQuery(q)) = Request::decode(payload) {
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || s.handle_harmony_query(&q)).await.unwrap();
                            let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        }
                    }
                    REQ_HARMONY_BATCH_QUERY if server.role == ServerRole::Primary => {
                        if let Ok(Request::HarmonyBatchQuery(q)) = Request::decode(payload) {
                            let t = Instant::now();
                            let n = q.items.len();
                            let level = q.level;
                            let s = Arc::clone(&server);
                            let resp = tokio::task::spawn_blocking(move || s.handle_harmony_batch_query(&q)).await.unwrap();
                            println!("[harmony-batch] L{} {} buckets in {:.2?}", level, n, t.elapsed());
                            let _ = sink.send(Message::Binary(resp.encode().into())).await;
                        }
                    }

                    // ── OnionPIR (primary only, if available) ────────────
                    REQ_REGISTER_KEYS if server.onionpir_tx.is_some() => {
                        if let Ok(keys_msg) = RegisterKeysMsg::decode(body) {
                            let tx = server.onionpir_tx.as_ref().unwrap();
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::RegisterKeys {
                                client_id,
                                galois_keys: keys_msg.galois_keys,
                                gsw_keys: keys_msg.gsw_keys,
                                reply: reply_tx,
                            }).await;
                            let _ = reply_rx.await;
                            let mut resp = Vec::with_capacity(5);
                            resp.extend_from_slice(&1u32.to_le_bytes());
                            resp.push(RESP_KEYS_ACK);
                            let _ = sink.send(Message::Binary(resp.into())).await;
                        }
                    }
                    REQ_ONIONPIR_INDEX_QUERY if server.onionpir_tx.is_some() => {
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            let tx = server.onionpir_tx.as_ref().unwrap();
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id, level: 0,
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = sink.send(Message::Binary(result_msg.encode(RESP_ONIONPIR_INDEX_RESULT).into())).await;
                        }
                    }
                    REQ_ONIONPIR_CHUNK_QUERY if server.onionpir_tx.is_some() => {
                        if let Ok(batch) = OnionPirBatchQuery::decode(body) {
                            let tx = server.onionpir_tx.as_ref().unwrap();
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let _ = tx.send(PirCommand::AnswerBatch {
                                client_id, level: 1,
                                round_id: batch.round_id,
                                queries: batch.queries, reply: reply_tx,
                            }).await;
                            let results = reply_rx.await.unwrap();
                            let result_msg = OnionPirBatchResult { round_id: batch.round_id, results };
                            let _ = sink.send(Message::Binary(result_msg.encode(RESP_ONIONPIR_CHUNK_RESULT).into())).await;
                        }
                    }

                    // ── Unsupported ──────────────────────────────────────
                    _ => {
                        let resp = Response::Error(format!("unsupported request 0x{:02x} for {} role", variant, role_name));
                        let _ = sink.send(Message::Binary(resp.encode().into())).await;
                    }
                }
            }

            println!("[{}] Disconnected (id={})", peer, client_id);
        });
    }
}
