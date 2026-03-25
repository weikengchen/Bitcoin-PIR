//! HarmonyPIR Hint Server.
//!
//! Loads the same cuckoo table files as the DPF server. When a client
//! connects and sends a PRP key, computes hint parities for each PBC
//! bucket and streams them back.
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_hint_server -- --port 8093

use build::common::*;
use runtime::protocol::*;

use futures_util::{SinkExt, StreamExt};
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::Prp;
use harmonypir::relocation::RelocationDS;
use harmonypir_wasm; // for find_best_t, pad_n_for_t, compute_rounds

// ─── Server data ────────────────────────────────────────────────────────────

struct HintServerData {
    index_cuckoo: Mmap,
    index_bins_per_table: usize,
    tag_seed: u64,

    chunk_cuckoo: Mmap,
    chunk_bins_per_table: usize,
}

impl HintServerData {
    fn load() -> Self {
        println!("[1] Loading index cuckoo: {}", CUCKOO_FILE);
        let f = File::open(CUCKOO_FILE).expect("open index cuckoo");
        let index_cuckoo = unsafe { Mmap::map(&f) }.expect("mmap index cuckoo");
        let (index_bins_per_table, tag_seed) = read_cuckoo_header(&index_cuckoo);
        println!("  bins_per_table = {}, tag_seed = 0x{:016x}", index_bins_per_table, tag_seed);

        println!("[2] Loading chunk cuckoo: {}", CHUNK_CUCKOO_FILE);
        let f = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
        let chunk_cuckoo = unsafe { Mmap::map(&f) }.expect("mmap chunk cuckoo");
        let chunk_bins_per_table = read_chunk_cuckoo_header(&chunk_cuckoo);
        println!("  bins_per_table = {}", chunk_bins_per_table);

        HintServerData {
            index_cuckoo,
            index_bins_per_table,
            tag_seed,
            chunk_cuckoo,
            chunk_bins_per_table,
        }
    }

    /// Compute hint parities for one bucket.
    ///
    /// Returns (bucket_id, n, t, m, flat_hints) where flat_hints is M × w bytes.
    fn compute_hints_for_bucket(
        &self,
        prp_key: &[u8; 16],
        level: u8,
        bucket_id: u8,
    ) -> (u8, u32, u32, u32, Vec<u8>) {
        let (table_bytes, bins_per_table, entry_size, header_size, k_offset) = match level {
            0 => (
                &self.index_cuckoo[..],
                self.index_bins_per_table,
                CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE,
                HEADER_SIZE,
                0u32,
            ),
            1 => (
                &self.chunk_cuckoo[..],
                self.chunk_bins_per_table,
                CHUNK_CUCKOO_BUCKET_SIZE * (4 + CHUNK_SIZE),
                CHUNK_HEADER_SIZE,
                K as u32, // Chunk buckets use offset bucket IDs for PRP derivation
            ),
            _ => panic!("invalid level"),
        };

        let real_n = bins_per_table;
        let w = entry_size;

        // Must use the SAME find_best_t + pad_n_for_t as the WASM client.
        // WASM: T = sqrt(2n).round(), then pad n up so 2*padded_n % T == 0.
        let t_raw = harmonypir_wasm::find_best_t(real_n as u32);
        let (padded_n, t_val) = harmonypir_wasm::pad_n_for_t(real_n as u32, t_raw);
        let pn = padded_n as usize;
        let t = t_val as usize;

        let params = Params::new(pn, w, t).expect("valid params");
        let m = params.m;

        // Derive per-bucket PRP key (same derivation as WASM client).
        let derived_key = derive_bucket_key(prp_key, k_offset + bucket_id as u32);

        // Compute PRP rounds using padded domain.
        let domain = 2 * pn;
        let r = harmonypir_wasm::compute_rounds(padded_n);

        let prp: Box<dyn Prp> = Box::new(HoangPrp::new(domain, r, &derived_key));
        let ds = RelocationDS::new(pn, t, prp).expect("DS init");

        // Compute hint parities.
        // Values 0..real_n are real DB rows; real_n..padded_n are virtual zeros.
        let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();

        let table_offset = header_size + bucket_id as usize * bins_per_table * entry_size;
        for k in 0..pn {
            let cell = ds.locate(k).expect("locate during hint computation");
            let segment = cell / t;

            if k < real_n {
                let entry_offset = table_offset + k * entry_size;
                let entry = &table_bytes[entry_offset..entry_offset + entry_size];
                xor_into(&mut hints[segment], entry);
            }
            // k >= real_n → virtual row, XOR with zeros = no-op
        }

        // Flatten hints.
        let flat: Vec<u8> = hints.into_iter().flat_map(|h| h.into_iter()).collect();

        (bucket_id, padded_n, t_val as u32, m as u32, flat)
    }
}

/// XOR src into dst.
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Derive per-bucket PRP key. Must match WASM client derivation.
fn derive_bucket_key(master_key: &[u8; 16], bucket_id: u32) -> [u8; 16] {
    let mut key = *master_key;
    let id_bytes = bucket_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
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

    println!("=== HarmonyPIR Hint Server ===");
    println!();

    let start = Instant::now();
    let data = HintServerData::load();
    println!();
    println!("Data loaded in {:.2?}", start.elapsed());
    println!();

    let data = Arc::new(data);

    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!("Listening on ws://{}", addr);
    println!("  Index: K={}, bins_per_table={}", K, data.index_bins_per_table);
    println!("  Chunk: K_CHUNK={}, bins_per_table={}", K_CHUNK, data.chunk_bins_per_table);
    println!();

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Accept error: {}", e);
                continue;
            }
        };

        let data = Arc::clone(&data);
        tokio::spawn(async move {
            let ws = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("[{}] Handshake failed: {}", peer, e);
                    return;
                }
            };
            println!("[{}] Connected", peer);
            let (mut sink, mut stream) = ws.split();

            while let Some(msg) = stream.next().await {
                let bin = match msg {
                    Ok(Message::Binary(b)) => b,
                    Ok(Message::Ping(_)) => continue,
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => continue,
                };

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

                match request {
                    Request::Ping => {
                        let _ = sink.send(Message::Binary(Response::Pong.encode().into())).await;
                    }
                    Request::HarmonyGetInfo | Request::GetInfo => {
                        let resp = Response::HarmonyInfo(ServerInfo {
                            index_bins_per_table: data.index_bins_per_table as u32,
                            chunk_bins_per_table: data.chunk_bins_per_table as u32,
                            index_k: K as u8,
                            chunk_k: K_CHUNK as u8,
                            tag_seed: data.tag_seed,
                        });
                        let _ = sink.send(Message::Binary(resp.encode().into())).await;
                    }
                    Request::HarmonyHints(hint_req) => {
                        let t_start = Instant::now();
                        let level = hint_req.level;
                        let num = hint_req.bucket_ids.len();
                        println!("[{}] Hint request: level={} buckets={}", peer, level, num);

                        // Stream hints as they complete.
                        // Use a channel: rayon workers produce hints, tokio sends them.
                        let prp_key: [u8; 16] = hint_req.prp_key;
                        let bucket_ids = hint_req.bucket_ids.clone();
                        let data_ref = Arc::clone(&data);

                        let (tx, mut rx) = tokio::sync::mpsc::channel::<(u8, u32, u32, u32, Vec<u8>)>(4);

                        // Spawn blocking rayon work that sends each hint as it's computed.
                        tokio::task::spawn_blocking(move || {
                            bucket_ids.par_iter().for_each_with(tx, |tx, &bid| {
                                let result = data_ref.compute_hints_for_bucket(&prp_key, level, bid);
                                let _ = tx.blocking_send(result);
                            });
                        });

                        // Receive and stream hints to client as they arrive.
                        let mut sent = 0;
                        while let Some((bucket_id, n, t, m, flat_hints)) = rx.recv().await {
                            let hint_payload_len = 1 + 1 + 4 + 4 + 4 + flat_hints.len();
                            let mut resp = Vec::with_capacity(4 + hint_payload_len);
                            resp.extend_from_slice(&(hint_payload_len as u32).to_le_bytes());
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

                        println!("[{}] Hints streamed: level={} {}/{} buckets in {:.2?}",
                            peer, level, sent, num, t_start.elapsed());
                    }
                    _ => {
                        let resp = Response::Error("unsupported request on hint server".into());
                        let _ = sink.send(Message::Binary(resp.encode().into())).await;
                    }
                }
            }

            println!("[{}] Disconnected", peer);
        });
    }
}
