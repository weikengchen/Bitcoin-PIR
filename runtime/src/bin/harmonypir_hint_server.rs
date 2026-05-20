//! HarmonyPIR Hint Server.
//!
//! Loads the same cuckoo table files as the DPF server. When a client
//! connects and sends a PRP key, computes hint parities for each PBC
//! group and streams them back.
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_hint_server -- --port 8093

use build::common::*;
use runtime::protocol::*;

use futures_util::{SinkExt, StreamExt};
use rayon::prelude::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;
 // for find_best_t, pad_n_for_t, compute_rounds
use rand::RngCore;

/// Target accumulation size before flushing a coalesced hint batch as one
/// WebSocket Binary message. Per-group hint records (~74 KB each on the
/// public deployment) are concatenated into this buffer; once the
/// threshold is crossed the buffer is flushed and a fresh one started.
///
/// Wire-format inside the buffer is unchanged — each record is still the
/// pre-existing `[4B len][RESP_HARMONY_HINTS][group_id][n][t][m][hints]`
/// frame. Only WS message boundaries are reduced (a HarmonyPIR query that
/// previously emitted ~622 RX HARMONY_HINTS frames now emits ~32).
///
/// Kept below 1 MiB so the message survives the Cloudflare WebSocket
/// proxy (~1 MB ceiling — see docs/PIR1_REGISTER_KEYS_TRUNCATION.md). The
/// standalone hint server isn't deployed behind Cloudflare, but a shared
/// constant keeps the framing identical across the unified-server V2 /
/// V2-half paths.
const HINT_BATCH_BYTES: usize = 768 * 1024;

// ─── Server data ────────────────────────────────────────────────────────────

use runtime::table::CuckooTablePair;

struct HintServerData {
    tables: CuckooTablePair,
}

impl HintServerData {
    fn load() -> Self {
        HintServerData {
            tables: CuckooTablePair::load(),
        }
    }

    /// Compute hint parities for one group.
    ///
    /// Returns (group_id, n, t, m, flat_hints) where flat_hints is M × w bytes.
    fn compute_hints_for_group(
        &self,
        prp_key: &[u8; 16],
        prp_backend: u8,
        level: u8,
        group_id: u8,
    ) -> (u8, u32, u32, u32, Vec<u8>) {
        let (table_bytes, bins_per_table, entry_size, header_size, k_offset) = match level {
            0 => (
                &self.tables.index_cuckoo[..],
                self.tables.index_bins_per_table,
                INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE,
                HEADER_SIZE,
                0u32,
            ),
            1 => (
                &self.tables.chunk_cuckoo[..],
                self.tables.chunk_bins_per_table,
                CHUNK_SLOTS_PER_BIN * (4 + CHUNK_SIZE),
                CHUNK_HEADER_SIZE,
                K as u32, // Chunk groups use offset group IDs for PRP derivation
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

        // Derive per-group PRP key (same derivation as WASM client).
        let derived_key = derive_group_key(prp_key, k_offset + group_id as u32);

        // Compute PRP rounds using padded domain.
        let domain = 2 * pn;
        let r = harmonypir_wasm::compute_rounds(padded_n);

        // Use batch_forward() for fast PRP evaluation.
        // At hint generation time there's no relocation history, so
        // locate(k) == prp.forward(k). batch_forward() is much faster
        // than sequential locate().
        use harmonypir::prp::BatchPrp;
        use harmonypir::prp::fast::FastPrpWrapper;
        // PRP_ALF removed 2026-05-12 — see harmonypir-wasm/src/lib.rs:36.
        let cell_of: Vec<usize> = match prp_backend {
            harmonypir_wasm::PRP_FASTPRP => {
                let prp = FastPrpWrapper::new(&derived_key, domain);
                prp.batch_forward()
            }
            _ => {
                // Default: HMR12 PRP
                let prp = HoangPrp::new(domain, r, &derived_key);
                prp.batch_forward()
            }
        };

        // Compute hint parities via scatter-XOR.
        // Values 0..real_n are real DB rows; real_n..padded_n are virtual zeros.
        let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();

        let table_offset = header_size + group_id as usize * bins_per_table * entry_size;
        for k in 0..pn {
            let segment = cell_of[k] / t;

            if k < real_n {
                let entry_offset = table_offset + k * entry_size;
                let entry = &table_bytes[entry_offset..entry_offset + entry_size];
                xor_into(&mut hints[segment], entry);
            }
        }

        // Flatten hints.
        let flat: Vec<u8> = hints.into_iter().flat_map(|h| h.into_iter()).collect();

        (group_id, padded_n, t_val, m as u32, flat)
    }
}

/// XOR src into dst.
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Derive per-group PRP key. Must match WASM client derivation.
fn derive_group_key(master_key: &[u8; 16], group_id: u32) -> [u8; 16] {
    let mut key = *master_key;
    let id_bytes = group_id.to_le_bytes();
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
    println!("  Index: K={}, bins_per_table={}", K, data.tables.index_bins_per_table);
    println!("  Chunk: K_CHUNK={}, bins_per_table={}", K_CHUNK, data.tables.chunk_bins_per_table);
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
                        let _ = sink.send(Message::Binary(resp.encode())).await;
                        continue;
                    }
                };

                match request {
                    Request::Ping => {
                        let _ = sink.send(Message::Binary(Response::Pong.encode())).await;
                    }
                    Request::HarmonyGetInfo | Request::GetInfo => {
                        let resp = Response::HarmonyInfo(ServerInfo {
                            index_bins_per_table: data.tables.index_bins_per_table as u32,
                            chunk_bins_per_table: data.tables.chunk_bins_per_table as u32,
                            index_k: K as u8,
                            chunk_k: K_CHUNK as u8,
                            tag_seed: data.tables.tag_seed,
                        });
                        let _ = sink.send(Message::Binary(resp.encode())).await;
                    }
                    Request::HarmonyHints(hint_req) => {
                        let t_start = Instant::now();
                        let level = hint_req.level;
                        let num = hint_req.group_ids.len();
                        let prp_backend = hint_req.prp_backend;
                        let backend_name = match prp_backend {
                            1 => "FastPRP",
                            2 => "ALF",
                            _ => "HMR12",
                        };
                        println!("[{}] Hint request: level={} groups={} prp={}",
                            peer, level, num, backend_name);

                        // Stream hints as they complete.
                        // Use a channel: rayon workers produce hints, tokio sends them.
                        let prp_key: [u8; 16] = hint_req.prp_key;
                        let group_ids = hint_req.group_ids.clone();
                        let data_ref = Arc::clone(&data);

                        let (tx, mut rx) = tokio::sync::mpsc::channel::<(u8, u32, u32, u32, Vec<u8>)>(4);

                        // Spawn blocking rayon work that sends each hint as it's computed.
                        tokio::task::spawn_blocking(move || {
                            group_ids.par_iter().for_each_with(tx, |tx, &bid| {
                                let result = data_ref.compute_hints_for_group(&prp_key, prp_backend, level, bid);
                                let _ = tx.blocking_send(result);
                            });
                        });

                        // Receive and stream hints to client as they arrive.
                        // Coalesce per-group records into ~HINT_BATCH_BYTES
                        // chunks so the client sees ~32 WS messages
                        // (one onmessage event each) instead of `num`
                        // (~155). Each record inside the buffer is the
                        // same `[4B len][RESP_HARMONY_HINTS][...]` frame
                        // the client was already parsing — only WS
                        // message boundaries change.
                        let mut sent = 0;
                        let mut batches = 0usize;
                        let mut buf: Vec<u8> = Vec::with_capacity(HINT_BATCH_BYTES + 128 * 1024);
                        while let Some((group_id, n, t, m, flat_hints)) = rx.recv().await {
                            let hint_payload_len = 1 + 1 + 4 + 4 + 4 + flat_hints.len();
                            buf.extend_from_slice(&(hint_payload_len as u32).to_le_bytes());
                            buf.push(RESP_HARMONY_HINTS);
                            buf.push(group_id);
                            buf.extend_from_slice(&n.to_le_bytes());
                            buf.extend_from_slice(&t.to_le_bytes());
                            buf.extend_from_slice(&m.to_le_bytes());
                            buf.extend_from_slice(&flat_hints);

                            if buf.len() >= HINT_BATCH_BYTES {
                                let batch = std::mem::take(&mut buf);
                                if let Err(e) = sink.send(Message::Binary(batch)).await {
                                    eprintln!("[{}] Send error: {}", peer, e);
                                    break;
                                }
                                buf.reserve(HINT_BATCH_BYTES + 128 * 1024);
                                batches += 1;
                            }
                            sent += 1;
                        }
                        // Flush the final partial batch.
                        if !buf.is_empty() {
                            if let Err(e) = sink.send(Message::Binary(buf)).await {
                                eprintln!("[{}] Final-batch send error: {}", peer, e);
                            } else {
                                batches += 1;
                            }
                        }

                        println!("[{}] Hints streamed: level={} {}/{} groups in {:.2?} ({} WS batches)",
                            peer, level, sent, num, t_start.elapsed(), batches);
                    }
                    Request::HarmonyHintsV2(_v2_req) => {
                        // V2: server generates PRP key, sends ALL groups for both
                        // INDEX and CHUNK levels. This is the on-demand equivalent
                        // of the unified_server's pre-computed hint pool path.
                        let t_start = Instant::now();
                        // ALF removed 2026-05-12 — was crashing on small sibling-table domains.
                        let prp_backend = harmonypir_wasm::PRP_FASTPRP;

                        // Generate random PRP key.
                        let mut prp_key = [0u8; 16];
                        rand::thread_rng().fill_bytes(&mut prp_key);

                        // Build and send key preamble.
                        // Wire layout: [RESP_HARMONY_HINTS_KEY][1B prp_backend][1B 0xFF][1B total_groups][16B prp_key]
                        let total_groups = (K + K_CHUNK) as u8;
                        let preamble_payload_len: u32 = 1 + 1 + 1 + 1 + 16;
                        let mut preamble = Vec::with_capacity(4 + preamble_payload_len as usize);
                        preamble.extend_from_slice(&preamble_payload_len.to_le_bytes());
                        preamble.push(RESP_HARMONY_HINTS_KEY); // 0x44
                        preamble.push(prp_backend);
                        preamble.push(0xFF); // HINT_LEVEL_ALL sentinel
                        preamble.push(total_groups);
                        preamble.extend_from_slice(&prp_key);

                        if let Err(e) = sink.send(Message::Binary(preamble)).await {
                            eprintln!("[{}] V2 preamble send error: {}", peer, e);
                            break;
                        }

                        println!("[{}] V2 hint request: prp_backend={} total_groups={}",
                            peer, prp_backend, total_groups);

                        // Compute and stream all INDEX + CHUNK groups in parallel.
                        let data_ref = Arc::clone(&data);
                        let key = prp_key;
                        let (tx, mut rx) = tokio::sync::mpsc::channel::<(u8, u32, u32, u32, Vec<u8>)>(8);

                        tokio::task::spawn_blocking(move || {
                            // Collect all (level, group_id) pairs into a Vec for rayon.
                            let mut all_groups: Vec<(u8, u8)> = Vec::with_capacity(K + K_CHUNK);
                            for g in 0..K as u8 {
                                all_groups.push((0, g));
                            }
                            for g in 0..K_CHUNK as u8 {
                                all_groups.push((1, g));
                            }
                            all_groups.into_par_iter().for_each_with(tx, |tx, (level, gid)| {
                                let result = data_ref.compute_hints_for_group(&key, prp_backend, level, gid);
                                let _ = tx.blocking_send(result);
                            });
                        });

                        // Stream frames as they arrive — coalesced into
                        // ~HINT_BATCH_BYTES-sized WS messages. See the V1
                        // path above for the rationale; the inner
                        // length-prefixed record stream is unchanged.
                        let mut sent = 0usize;
                        let mut batches = 0usize;
                        let mut buf: Vec<u8> = Vec::with_capacity(HINT_BATCH_BYTES + 128 * 1024);
                        while let Some((group_id, n, t, m, flat_hints)) = rx.recv().await {
                            let hint_payload_len: u32 = 1 + 1 + 4 + 4 + 4 + flat_hints.len() as u32;
                            buf.extend_from_slice(&hint_payload_len.to_le_bytes());
                            buf.push(RESP_HARMONY_HINTS);
                            buf.push(group_id);
                            buf.extend_from_slice(&n.to_le_bytes());
                            buf.extend_from_slice(&t.to_le_bytes());
                            buf.extend_from_slice(&m.to_le_bytes());
                            buf.extend_from_slice(&flat_hints);

                            if buf.len() >= HINT_BATCH_BYTES {
                                let batch = std::mem::take(&mut buf);
                                if let Err(e) = sink.send(Message::Binary(batch)).await {
                                    eprintln!("[{}] V2 hint send error: {}", peer, e);
                                    break;
                                }
                                buf.reserve(HINT_BATCH_BYTES + 128 * 1024);
                                batches += 1;
                            }
                            sent += 1;
                        }
                        // Flush the final partial batch.
                        if !buf.is_empty() {
                            if let Err(e) = sink.send(Message::Binary(buf)).await {
                                eprintln!("[{}] V2 final-batch send error: {}", peer, e);
                            } else {
                                batches += 1;
                            }
                        }

                        println!("[{}] V2 hints streamed: {}/{} groups in {:.2?} ({} WS batches)",
                            peer, sent, total_groups, t_start.elapsed(), batches);
                    }
                    _ => {
                        let resp = Response::Error("unsupported request on hint server".into());
                        let _ = sink.send(Message::Binary(resp.encode())).await;
                    }
                }
            }

            println!("[{}] Disconnected", peer);
        });
    }
}
