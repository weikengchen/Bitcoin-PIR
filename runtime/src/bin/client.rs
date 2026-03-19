//! Two-level Batch PIR client.
//!
//! Queries a Bitcoin script hash through two PIR servers:
//!   Level 1: index PIR → (offset, num_chunks)
//!   Level 2: chunk PIR → actual UTXO data (multi-round)
//!
//! Usage:
//!   cargo run --release -p runtime --bin client -- \
//!     --server0 ws://localhost:8093 --server1 ws://localhost:8094 \
//!     --hash <40-char hex script hash>

use runtime::eval::{self, DPF_N};
use runtime::protocol::{BatchQuery, Request, Response};
use build::common::*;
use futures_util::{SinkExt, StreamExt};
use libdpf::Dpf;
use std::time::Instant;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

// ─── CLI args ───────────────────────────────────────────────────────────────

struct Args {
    server0: String,
    server1: String,
    script_hash: [u8; SCRIPT_HASH_SIZE],
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut server0 = "ws://localhost:8093".to_string();
    let mut server1 = "ws://localhost:8094".to_string();
    let mut hash_hex = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server0" | "-s0" => { server0 = args[i + 1].clone(); i += 1; }
            "--server1" | "-s1" => { server1 = args[i + 1].clone(); i += 1; }
            "--hash" | "-h" => { hash_hex = args[i + 1].clone(); i += 1; }
            "--help" => {
                println!("Usage: client --hash <hex> [--server0 URL] [--server1 URL]");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    if hash_hex.len() != 40 {
        eprintln!("Error: --hash must be a 40-character hex string (20 bytes)");
        std::process::exit(1);
    }

    let mut script_hash = [0u8; SCRIPT_HASH_SIZE];
    for j in 0..SCRIPT_HASH_SIZE {
        script_hash[j] = u8::from_str_radix(&hash_hex[j * 2..j * 2 + 2], 16)
            .expect("invalid hex in --hash");
    }

    Args { server0, server1, script_hash }
}

// ─── PRNG for dummy queries ─────────────────────────────────────────────────

struct DummyRng { state: u64 }

impl DummyRng {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        Self { state: splitmix64(seed) }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        splitmix64(self.state)
    }
}

// ─── WebSocket helpers ──────────────────────────────────────────────────────

/// Send a request and receive a response over WebSocket.
async fn ws_roundtrip(
    sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    stream: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    req: &Request,
) -> Response {
    let encoded = req.encode();
    sink.send(Message::Binary(encoded.into())).await.expect("send");

    loop {
        let msg = stream.next().await.expect("no response").expect("read error");
        match msg {
            Message::Binary(b) => {
                let payload = &b[4..]; // skip length prefix
                return Response::decode(payload).expect("decode response");
            }
            Message::Ping(p) => {
                let _ = sink.send(Message::Pong(p)).await;
            }
            _ => continue,
        }
    }
}

// ─── Cuckoo assignment for chunk level (multi-round) ────────────────────────

/// Plan multi-round chunk retrieval for a set of chunk_ids.
/// Returns Vec of rounds, each round is Vec of (chunk_id, bucket_id).
fn plan_chunk_rounds(chunk_ids: &[u32]) -> Vec<Vec<(u32, u8)>> {
    let mut remaining: Vec<u32> = chunk_ids.to_vec();
    let mut rounds = Vec::new();

    while !remaining.is_empty() {
        let candidates: Vec<(u32, [usize; NUM_HASHES])> = remaining
            .iter()
            .map(|&cid| (cid, derive_chunk_buckets(cid)))
            .collect();

        // Try to place up to K_CHUNK items
        let mut buckets: [Option<usize>; K_CHUNK] = [None; K_CHUNK];
        let mut round_entries: Vec<(u32, u8)> = Vec::new();
        let mut placed_set = Vec::new();

        let cand_buckets: Vec<[usize; NUM_HASHES]> = candidates.iter().map(|c| c.1).collect();

        for i in 0..candidates.len() {
            if round_entries.len() >= K_CHUNK {
                break;
            }
            let saved = buckets;
            if cuckoo_place(&cand_buckets, &mut buckets, i, 500) {
                placed_set.push(i);
            } else {
                buckets = saved;
            }
        }

        // Extract placed entries
        for b in 0..K_CHUNK {
            if let Some(ci) = buckets[b] {
                round_entries.push((candidates[ci].0, b as u8));
            }
        }

        if round_entries.is_empty() {
            eprintln!("ERROR: could not place any chunks in round, {} remaining", remaining.len());
            break;
        }

        // Remove placed from remaining
        let placed_ids: Vec<u32> = placed_set.iter().map(|&i| candidates[i].0).collect();
        remaining.retain(|cid| !placed_ids.contains(cid));

        rounds.push(round_entries);
    }

    rounds
}

fn cuckoo_place(
    cand_buckets: &[[usize; NUM_HASHES]],
    buckets: &mut [Option<usize>; K_CHUNK],
    qi: usize,
    max_kicks: usize,
) -> bool {
    let cands = &cand_buckets[qi];
    for &c in cands {
        if buckets[c].is_none() {
            buckets[c] = Some(qi);
            return true;
        }
    }
    let mut current_qi = qi;
    let mut current_bucket = cand_buckets[current_qi][0];

    for kick in 0..max_kicks {
        let evicted_qi = buckets[current_bucket].unwrap();
        buckets[current_bucket] = Some(current_qi);
        let ev_cands = &cand_buckets[evicted_qi];

        for offset in 0..NUM_HASHES {
            let c = ev_cands[(kick + offset) % NUM_HASHES];
            if c == current_bucket { continue; }
            if buckets[c].is_none() {
                buckets[c] = Some(evicted_qi);
                return true;
            }
        }

        let mut next_bucket = ev_cands[0];
        for offset in 0..NUM_HASHES {
            let c = ev_cands[(kick + offset) % NUM_HASHES];
            if c != current_bucket {
                next_bucket = c;
                break;
            }
        }
        current_qi = evicted_qi;
        current_bucket = next_bucket;
    }
    false
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = parse_args();
    let hash_hex: String = args.script_hash.iter().map(|b| format!("{:02x}", b)).collect();

    println!("=== Two-Level Batch PIR Client ===");
    println!("  Script hash: {}", hash_hex);
    println!("  Server 0:    {}", args.server0);
    println!("  Server 1:    {}", args.server1);
    println!();

    let total_start = Instant::now();

    // ── Connect to both servers ─────────────────────────────────────────
    println!("[1] Connecting to servers...");
    let (ws0, _) = connect_async(&args.server0).await.expect("connect server0");
    let (ws1, _) = connect_async(&args.server1).await.expect("connect server1");
    let (mut sink0, mut stream0) = ws0.split();
    let (mut sink1, mut stream1) = ws1.split();
    println!("  Connected.");
    println!();

    // ── Get server info ─────────────────────────────────────────────────
    println!("[2] Getting server info...");
    let info_req = Request::GetInfo;
    let info0 = ws_roundtrip(&mut sink0, &mut stream0, &info_req).await;
    let info = match info0 {
        Response::Info(i) => i,
        Response::Error(e) => { eprintln!("Server error: {}", e); return; }
        _ => { eprintln!("Unexpected response"); return; }
    };
    // Also get info from server1 (just to verify, don't need it)
    let _ = ws_roundtrip(&mut sink1, &mut stream1, &info_req).await;

    let index_bins = info.index_bins_per_table as usize;
    let chunk_bins = info.chunk_bins_per_table as usize;
    println!("  Index: K={}, bins_per_table={}", info.index_k, index_bins);
    println!("  Chunk: K={}, bins_per_table={}", info.chunk_k, chunk_bins);
    println!();

    // ══════════════════════════════════════════════════════════════════════
    // LEVEL 1: Index PIR
    // ══════════════════════════════════════════════════════════════════════
    println!("[3] Level 1: Index PIR...");
    let l1_start = Instant::now();

    let dpf = Dpf::with_default_key();
    let mut rng = DummyRng::new();

    // Compute candidate buckets for our script hash
    let my_buckets = derive_buckets(&args.script_hash);
    let assigned_bucket = my_buckets[0]; // single query, just use first

    // Compute cuckoo hash locations in the assigned bucket
    let key0 = derive_cuckoo_key(assigned_bucket, 0);
    let key1 = derive_cuckoo_key(assigned_bucket, 1);
    let loc0 = cuckoo_hash(&args.script_hash, key0, index_bins) as u64;
    let loc1 = cuckoo_hash(&args.script_hash, key1, index_bins) as u64;

    println!("  Assigned bucket: {}", assigned_bucket);
    println!("  loc0={}, loc1={}", loc0, loc1);

    // Generate DPF keys for all K buckets
    let mut s0_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(K);
    let mut s1_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(K);

    for b in 0..K {
        let (alpha0, alpha1) = if b == assigned_bucket {
            (loc0, loc1)
        } else {
            (rng.next_u64() % index_bins as u64, rng.next_u64() % index_bins as u64)
        };
        let (k0_q0, k1_q0) = dpf.gen(alpha0, DPF_N);
        let (k0_q1, k1_q1) = dpf.gen(alpha1, DPF_N);
        s0_keys.push((k0_q0.to_bytes(), k0_q1.to_bytes()));
        s1_keys.push((k1_q0.to_bytes(), k1_q1.to_bytes()));
    }

    // Send to both servers concurrently
    let req0 = Request::IndexBatch(BatchQuery { level: 0, round_id: 0, keys: s0_keys });
    let req1 = Request::IndexBatch(BatchQuery { level: 0, round_id: 0, keys: s1_keys });

    let enc0 = req0.encode();
    let enc1 = req1.encode();

    sink0.send(Message::Binary(enc0.into())).await.expect("send s0");
    sink1.send(Message::Binary(enc1.into())).await.expect("send s1");

    // Receive from both
    let resp0 = recv_response(&mut stream0, &mut sink0).await;
    let resp1 = recv_response(&mut stream1, &mut sink1).await;

    let (r0, r1) = match (resp0, resp1) {
        (Response::IndexBatch(a), Response::IndexBatch(b)) => (a, b),
        _ => { eprintln!("Unexpected response type for index batch"); return; }
    };

    // XOR results for the assigned bucket
    let b = assigned_bucket;
    let mut result_q0 = r0.results[b].0.clone();
    eval::xor_into(&mut result_q0, &r1.results[b].0);
    let mut result_q1 = r0.results[b].1.clone();
    eval::xor_into(&mut result_q1, &r1.results[b].1);

    // Find our entry
    let (offset_half, num_chunks) =
        eval::find_entry_in_index_result(&result_q0, &args.script_hash)
        .or_else(|| eval::find_entry_in_index_result(&result_q1, &args.script_hash))
        .unwrap_or_else(|| {
            eprintln!("ERROR: script hash not found in index PIR result!");
            std::process::exit(1);
        });

    let start_chunk = (offset_half as u64 * 2 / CHUNK_SIZE as u64) as u32;
    let num_units = (num_chunks as usize + CHUNKS_PER_UNIT - 1) / CHUNKS_PER_UNIT;

    println!("  Found: offset_half={}, num_chunks={}, start_chunk={}", offset_half, num_chunks, start_chunk);
    println!("  Units to fetch: {} (CHUNKS_PER_UNIT={})", num_units, CHUNKS_PER_UNIT);
    println!("  Level 1 time: {:.2?}", l1_start.elapsed());
    println!();

    // ══════════════════════════════════════════════════════════════════════
    // LEVEL 2: Chunk PIR (multi-round)
    // ══════════════════════════════════════════════════════════════════════
    println!("[4] Level 2: Chunk PIR...");
    let l2_start = Instant::now();

    // Build list of chunk_ids to retrieve
    let chunk_ids: Vec<u32> = (0..num_units)
        .map(|u| start_chunk + (u as u32) * CHUNKS_PER_UNIT as u32)
        .collect();

    // Plan rounds
    let rounds = plan_chunk_rounds(&chunk_ids);
    println!("  {} chunks → {} rounds", chunk_ids.len(), rounds.len());

    // Execute each round
    let mut recovered_chunks: std::collections::HashMap<u32, Vec<u8>> =
        std::collections::HashMap::new();

    for (ri, round_plan) in rounds.iter().enumerate() {
        // Build target map: bucket → (loc0, loc1)
        let mut bucket_targets: Vec<Option<(u64, u64)>> = vec![None; K_CHUNK];
        for &(chunk_id, bucket_id) in round_plan {
            let b = bucket_id as usize;
            let ck0 = derive_chunk_cuckoo_key(b, 0);
            let ck1 = derive_chunk_cuckoo_key(b, 1);
            let l0 = cuckoo_hash_int(chunk_id, ck0, chunk_bins) as u64;
            let l1 = cuckoo_hash_int(chunk_id, ck1, chunk_bins) as u64;
            bucket_targets[b] = Some((l0, l1));
        }

        // Generate DPF keys for all K_CHUNK buckets
        let mut s0_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(K_CHUNK);
        let mut s1_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(K_CHUNK);

        for b in 0..K_CHUNK {
            let (alpha0, alpha1) = match bucket_targets[b] {
                Some(t) => t,
                None => (rng.next_u64() % chunk_bins as u64, rng.next_u64() % chunk_bins as u64),
            };
            let (k0_q0, k1_q0) = dpf.gen(alpha0, DPF_N);
            let (k0_q1, k1_q1) = dpf.gen(alpha1, DPF_N);
            s0_keys.push((k0_q0.to_bytes(), k0_q1.to_bytes()));
            s1_keys.push((k1_q0.to_bytes(), k1_q1.to_bytes()));
        }

        // Send to both servers
        let req0 = Request::ChunkBatch(BatchQuery { level: 1, round_id: ri as u16, keys: s0_keys });
        let req1 = Request::ChunkBatch(BatchQuery { level: 1, round_id: ri as u16, keys: s1_keys });

        let enc0 = req0.encode();
        let enc1 = req1.encode();

        sink0.send(Message::Binary(enc0.into())).await.expect("send s0");
        sink1.send(Message::Binary(enc1.into())).await.expect("send s1");

        let resp0 = recv_response(&mut stream0, &mut sink0).await;
        let resp1 = recv_response(&mut stream1, &mut sink1).await;

        let (cr0, cr1) = match (resp0, resp1) {
            (Response::ChunkBatch(a), Response::ChunkBatch(b)) => (a, b),
            _ => { eprintln!("Unexpected response for chunk batch"); return; }
        };

        // XOR and extract
        for &(chunk_id, bucket_id) in round_plan {
            let b = bucket_id as usize;

            let mut rq0 = cr0.results[b].0.clone();
            eval::xor_into(&mut rq0, &cr1.results[b].0);
            let mut rq1 = cr0.results[b].1.clone();
            eval::xor_into(&mut rq1, &cr1.results[b].1);

            let data = eval::find_chunk_in_result(&rq0, chunk_id)
                .or_else(|| eval::find_chunk_in_result(&rq1, chunk_id));

            if let Some(d) = data {
                recovered_chunks.insert(chunk_id, d.to_vec());
            } else {
                eprintln!("  WARNING: chunk {} not found in round {} bucket {}", chunk_id, ri, b);
            }
        }

        if (ri + 1) % 10 == 0 || ri + 1 == rounds.len() {
            println!("  Round {}/{}: recovered {}/{} chunks so far",
                ri + 1, rounds.len(), recovered_chunks.len(), chunk_ids.len());
        }
    }

    println!("  Level 2 time: {:.2?}", l2_start.elapsed());
    println!();

    // ══════════════════════════════════════════════════════════════════════
    // Reassemble and output
    // ══════════════════════════════════════════════════════════════════════
    println!("[5] Reassembling UTXO data...");

    let mut full_data = Vec::new();
    let mut missing = 0;
    for &cid in &chunk_ids {
        if let Some(d) = recovered_chunks.get(&cid) {
            full_data.extend_from_slice(d);
        } else {
            missing += 1;
            // Pad with zeros for missing chunks
            full_data.extend_from_slice(&vec![0u8; UNIT_DATA_SIZE]);
        }
    }

    println!("  Recovered: {}/{} units", chunk_ids.len() - missing, chunk_ids.len());
    if missing > 0 {
        println!("  WARNING: {} units missing!", missing);
    }
    println!("  Total data: {} bytes", full_data.len());
    println!();

    // Decode UTXO entries
    println!("[6] Decoding UTXO entries:");
    {
        let mut pos = 0;
        let (num_entries, bytes_read) = read_varint(&full_data[pos..]);
        pos += bytes_read;
        println!("  Number of UTXOs: {}", num_entries);
        println!();

        let mut total_sats: u64 = 0;
        for i in 0..num_entries as usize {
            if pos + 32 > full_data.len() {
                println!("  (data truncated at entry {})", i);
                break;
            }
            // 32 bytes txid (internal byte order, reverse for display)
            let txid_bytes = &full_data[pos..pos + 32];
            pos += 32;

            let mut txid_rev = [0u8; 32];
            for j in 0..32 {
                txid_rev[j] = txid_bytes[31 - j];
            }
            let txid_hex: String = txid_rev.iter().map(|b| format!("{:02x}", b)).collect();

            let (vout, vr) = read_varint(&full_data[pos..]);
            pos += vr;
            let (amount, ar) = read_varint(&full_data[pos..]);
            pos += ar;

            total_sats += amount;
            let btc = amount as f64 / 100_000_000.0;
            println!("  UTXO #{}: {}:{} — {} sats ({:.8} BTC)",
                i + 1, txid_hex, vout, amount, btc);
        }

        println!();
        let total_btc = total_sats as f64 / 100_000_000.0;
        println!("  Total: {} sats ({:.8} BTC) across {} UTXOs",
            total_sats, total_btc, num_entries);
    }

    println!();
    println!("=== Done ===");
    println!("  Total time: {:.2?}", total_start.elapsed());
    println!("  Script hash: {}", hash_hex);
    println!("  Chunks: {}, Rounds: {}", num_chunks, rounds.len());
}

// Decode a varint (LEB128 unsigned) from a byte slice.
// Returns (value, bytes_consumed).
fn read_varint(data: &[u8]) -> (u64, usize) {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return (value, i + 1);
        }
        shift += 7;
        if shift >= 64 {
            panic!("varint too large");
        }
    }
    panic!("unexpected end of varint data");
}

// Helper to receive a binary response, handling pings
async fn recv_response(
    stream: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    sink: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
) -> Response {
    loop {
        let msg = stream.next().await.expect("no response").expect("read error");
        match msg {
            Message::Binary(b) => {
                let payload = &b[4..];
                return Response::decode(payload).expect("decode response");
            }
            Message::Ping(p) => {
                let _ = sink.send(Message::Pong(p)).await;
            }
            _ => continue,
        }
    }
}
