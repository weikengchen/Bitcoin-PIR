//! Two-level Batch PIR client.
//!
//! Queries a Bitcoin script hash through two PIR servers:
//!   Level 1: index PIR → (offset, num_chunks)
//!   Level 2: chunk PIR → actual UTXO data (multi-round)
//!
//! Usage:
//!   cargo run --release -p runtime --bin client -- \
//!     --server0 ws://localhost:8091 --server1 ws://localhost:8092 \
//!     --hash <40-char hex script hash>

use runtime::eval;
use runtime::protocol::{BatchQuery, Request, Response};
use build::common::*;
use pir_core::merkle;
use pir_core::params::compute_dpf_n;
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
    let mut server0 = "ws://localhost:8091".to_string();
    let mut server1 = "ws://localhost:8092".to_string();
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
/// Returns Vec of rounds, each round is Vec of (chunk_id, group_id).
fn plan_chunk_rounds(chunk_ids: &[u32]) -> Vec<Vec<(u32, u8)>> {
    let cand_groups: Vec<[usize; NUM_HASHES]> = chunk_ids
        .iter()
        .map(|&cid| derive_chunk_groups(cid))
        .collect();

    let rounds = pbc_plan_rounds(&cand_groups, K_CHUNK, NUM_HASHES, 500);

    // Map (item_index, group_id) back to (chunk_id, group_id as u8)
    rounds
        .into_iter()
        .map(|round| {
            round
                .into_iter()
                .map(|(item_idx, group)| (chunk_ids[item_idx], group as u8))
                .collect()
        })
        .collect()
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
    // Use large max message size for bucket Merkle tree-top fetch (~185 MB)
    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(256 * 1024 * 1024), // 256 MB
        max_frame_size: Some(256 * 1024 * 1024),
        ..Default::default()
    };
    let (ws0, _) = tokio_tungstenite::connect_async_with_config(&args.server0, Some(ws_config), false)
        .await.expect("connect server0");
    let (ws1, _) = tokio_tungstenite::connect_async_with_config(&args.server1, Some(ws_config), false)
        .await.expect("connect server1");
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
    let tag_seed = info.tag_seed;
    let index_dpf_n = compute_dpf_n(index_bins);
    let chunk_dpf_n = compute_dpf_n(chunk_bins);
    println!("  Index: K={}, bins_per_table={}, dpf_n={}", info.index_k, index_bins, index_dpf_n);
    println!("  Chunk: K={}, bins_per_table={}, dpf_n={}", info.chunk_k, chunk_bins, chunk_dpf_n);
    println!("  tag_seed: 0x{:016x}", tag_seed);
    println!();

    // ══════════════════════════════════════════════════════════════════════
    // LEVEL 1: Index PIR
    // ══════════════════════════════════════════════════════════════════════
    println!("[3] Level 1: Index PIR...");
    let l1_start = Instant::now();

    let dpf = Dpf::with_default_key();
    let mut rng = DummyRng::new();

    // Compute candidate groups for our script hash
    let my_groups = derive_groups(&args.script_hash);
    let assigned_group = my_groups[0]; // single query, just use first

    // Compute cuckoo hash locations in the assigned group (INDEX_CUCKOO_NUM_HASHES = 2)
    let mut my_locs = Vec::new();
    for h in 0..INDEX_CUCKOO_NUM_HASHES {
        let key = derive_cuckoo_key(assigned_group, h);
        my_locs.push(cuckoo_hash(&args.script_hash, key, index_bins) as u64);
    }

    println!("  Assigned group: {}", assigned_group);
    println!("  locs: {:?}", my_locs);

    // Generate DPF keys for all K groups (INDEX_CUCKOO_NUM_HASHES keys per group)
    let mut s0_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(K);
    let mut s1_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(K);

    for b in 0..K {
        let mut s0_group = Vec::new();
        let mut s1_group = Vec::new();
        for h in 0..INDEX_CUCKOO_NUM_HASHES {
            let alpha = if b == assigned_group {
                my_locs[h]
            } else {
                rng.next_u64() % index_bins as u64
            };
            let (k0, k1) = dpf.gen(alpha, index_dpf_n);
            s0_group.push(k0.to_bytes());
            s1_group.push(k1.to_bytes());
        }
        s0_keys.push(s0_group);
        s1_keys.push(s1_group);
    }

    // Send to both servers concurrently
    let req0 = Request::IndexBatch(BatchQuery { level: 0, round_id: 0, db_id: 0, keys: s0_keys });
    let req1 = Request::IndexBatch(BatchQuery { level: 0, round_id: 0, db_id: 0, keys: s1_keys });

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

    // Compute fingerprint tag for our script hash
    let my_tag = compute_tag(tag_seed, &args.script_hash);

    // XOR results for the assigned group (each cuckoo hash gives one result)
    let b = assigned_group;
    let mut found_entry: Option<(u32, u32)> = None;
    let mut index_bin_index: usize = 0;
    let mut index_bin_content: Vec<u8> = Vec::new();
    for h in 0..INDEX_CUCKOO_NUM_HASHES {
        let mut result = r0.results[b][h].clone();
        eval::xor_into(&mut result, &r1.results[b][h]);
        if let Some(entry) = eval::find_entry_in_index_result(&result, my_tag) {
            found_entry = Some(entry);
            index_bin_index = my_locs[h] as usize;
            index_bin_content = result;
            break;
        }
    }

    // Find our entry
    let (start_chunk, num_chunks) = found_entry
        .unwrap_or_else(|| {
            eprintln!("ERROR: script hash not found in index PIR result!");
            std::process::exit(1);
        });

    let num_units = (num_chunks as usize + CHUNKS_PER_UNIT - 1) / CHUNKS_PER_UNIT;

    println!("  Found: start_chunk={}, num_chunks={}", start_chunk, num_chunks);
    println!("  Units to fetch: {} (CHUNKS_PER_UNIT={})", num_units, CHUNKS_PER_UNIT);
    println!("  Level 1 time: {:.2?}", l1_start.elapsed());
    println!();

    // ── Whale address detection ─────────────────────────────────────────
    if num_chunks == 0 {
        println!("=== WHALE ADDRESS (EXCLUDED) ===");
        println!("  This address has too many UTXOs (>100) and was excluded");
        println!("  from the PIR database. Use a full node or block explorer.");
        println!();
        println!("  Script hash: {}", hash_hex);
        println!("  Total time: {:.2?}", total_start.elapsed());
        return;
    }

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
    // Per-chunk Merkle info: chunk_id → (pbc_group, bin_index, bin_content)
    let mut chunk_merkle_info: std::collections::HashMap<u32, (usize, usize, Vec<u8>)> =
        std::collections::HashMap::new();

    for (ri, round_plan) in rounds.iter().enumerate() {
        // Always send CHUNK_CUCKOO_NUM_HASHES (2) DPF keys per group (uniform, no placement optimization)
        let mut group_targets: Vec<Option<Vec<u64>>> = vec![None; K_CHUNK];
        for &(chunk_id, group_id) in round_plan {
            let b = group_id as usize;
            let locs: Vec<u64> = (0..CHUNK_CUCKOO_NUM_HASHES)
                .map(|h| {
                    let key = derive_chunk_cuckoo_key(b, h);
                    cuckoo_hash_int(chunk_id, key, chunk_bins) as u64
                })
                .collect();
            group_targets[b] = Some(locs);
        }

        // Generate DPF keys
        let mut s0_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(K_CHUNK);
        let mut s1_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(K_CHUNK);

        for b in 0..K_CHUNK {
            let mut s0_group = Vec::new();
            let mut s1_group = Vec::new();
            for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                let alpha = match &group_targets[b] {
                    Some(locs) => locs[h],
                    None => rng.next_u64() % chunk_bins as u64,
                };
                let (k0, k1) = dpf.gen(alpha, chunk_dpf_n);
                s0_group.push(k0.to_bytes());
                s1_group.push(k1.to_bytes());
            }
            s0_keys.push(s0_group);
            s1_keys.push(s1_group);
        }

        // Send to both servers
        let req0 = Request::ChunkBatch(BatchQuery { level: 1, round_id: ri as u16, db_id: 0, keys: s0_keys });
        let req1 = Request::ChunkBatch(BatchQuery { level: 1, round_id: ri as u16, db_id: 0, keys: s1_keys });

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
        for &(chunk_id, group_id) in round_plan {
            let b = group_id as usize;
            let mut found = false;

            let num_results = cr0.results[b].len();
            for h in 0..num_results {
                let mut result = cr0.results[b][h].clone();
                eval::xor_into(&mut result, &cr1.results[b][h]);

                if let Some(d) = eval::find_chunk_in_result(&result, chunk_id) {
                    recovered_chunks.insert(chunk_id, d.to_vec());
                    let ck = derive_chunk_cuckoo_key(b, h);
                    let bin_idx = cuckoo_hash_int(chunk_id, ck, chunk_bins);
                    chunk_merkle_info.insert(chunk_id, (b, bin_idx, result));
                    found = true;
                    break;
                }
            }

            if !found {
                eprintln!("  WARNING: chunk {} not found in round {} group {}", chunk_id, ri, b);
            }
        }

        if (ri + 1) % 10 == 0 || ri + 1 == rounds.len() {
            println!("  Round {}/{}: recovered {}/{} chunks so far",
                ri + 1, rounds.len(), recovered_chunks.len(), chunk_ids.len());
        }
    }

    println!("  Level 2 time: {:.2?}", l2_start.elapsed());
    println!();

    // Build raw data for Merkle data_hash computation (ordered chunk bytes)
    let full_data_for_merkle: Vec<u8> = {
        let mut data = Vec::new();
        for &cid in &chunk_ids {
            if let Some(d) = recovered_chunks.get(&cid) {
                data.extend_from_slice(d);
            }
        }
        data
    };

    // ══════════════════════════════════════════════════════════════════════
    // LEVEL 3: Merkle sibling PIR (optional verification)
    // ══════════════════════════════════════════════════════════════════════
    //
    // ── Per-bucket bin Merkle verification ─────────────────────────────
    // Verify INDEX bin authenticity via flat sibling table queries (0x33).
    // Uses the same DPF batch query pattern as index/chunk queries.
    // TODO: Also verify CHUNK bins once confirmed working for INDEX.

    if num_chunks > 0 {
        println!("[4b] Per-bucket bin Merkle verification...");
        let l3_start = Instant::now();

        // Compute INDEX leaf hash: SHA256(bin_index_u32_LE || bin_content)
        let index_leaf = merkle::compute_bin_leaf_hash(index_bin_index as u32, &index_bin_content);
        println!("  INDEX leaf: group={}, bin={}, hash={:02x}{:02x}{:02x}{:02x}...",
            assigned_group, index_bin_index,
            index_leaf[0], index_leaf[1], index_leaf[2], index_leaf[3]);

        // Fetch tree-top caches from server (0x34)
        let top_req = vec![0x34u8]; // REQ_BUCKET_MERKLE_TREE_TOPS
        let top_msg = {
            let len = top_req.len() as u32;
            let mut m = Vec::with_capacity(4 + top_req.len());
            m.extend_from_slice(&len.to_le_bytes());
            m.extend_from_slice(&top_req);
            m
        };
        sink0.send(Message::Binary(top_msg.into())).await.expect("send tree-top req");
        let top_resp = recv_raw(&mut stream0).await;
        // Response: [4B len][1B variant=0x34][tree_tops_bytes...]
        let tree_tops_data = if top_resp.len() >= 6 && top_resp[4] == 0x34 {
            &top_resp[5..]
        } else {
            println!("  Tree-top fetch failed (server may not have bucket Merkle data)");
            &[][..]
        };

        if !tree_tops_data.is_empty() {
            // Parse tree-tops: [4B num_trees][per tree: header + level data]
            let num_trees = u32::from_le_bytes(tree_tops_data[0..4].try_into().unwrap()) as usize;
            println!("  Tree-tops: {} trees, {} bytes", num_trees, tree_tops_data.len());

            // Skip to the tree for our INDEX group
            let mut off = 4usize;
            let mut target_top: Option<(usize, Vec<Vec<[u8; 32]>>)> = None;
            for t_idx in 0..num_trees {
                let cache_from = tree_tops_data[off] as usize; off += 1;
                let _total_nodes = u32::from_le_bytes(tree_tops_data[off..off+4].try_into().unwrap()); off += 4;
                let _arity = u16::from_le_bytes(tree_tops_data[off..off+2].try_into().unwrap()); off += 2;
                let num_levels = tree_tops_data[off] as usize; off += 1;

                let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
                for _ in 0..num_levels {
                    let n = u32::from_le_bytes(tree_tops_data[off..off+4].try_into().unwrap()) as usize; off += 4;
                    let mut level = Vec::with_capacity(n);
                    for _ in 0..n {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&tree_tops_data[off..off+32]);
                        level.push(h);
                        off += 32;
                    }
                    levels.push(level);
                }

                if t_idx == assigned_group {
                    target_top = Some((cache_from, levels));
                }
            }

            if let Some((cache_from, cached_levels)) = target_top {
                // Query sibling levels via DPF (0x33)
                let merkle_arity = 8usize;
                let mut current_hash = index_leaf;
                let mut node_idx = index_bin_index;
                let mut merkle_ok = true;

                // Number of PIR sibling levels = cache_from (the tree-top starts there).
                // Compute groups per level from index_bins.
                let mut sib_level_groups = Vec::new();
                let mut nodes = index_bins;
                for _ in 0..cache_from {
                    let groups = (nodes + merkle_arity - 1) / merkle_arity;
                    sib_level_groups.push(groups);
                    nodes = groups;
                }

                println!("  Sibling levels: {} (groups: {:?}), cache_from={}", sib_level_groups.len(), sib_level_groups, cache_from);

                for (level, &num_groups) in sib_level_groups.iter().enumerate() {
                    let group_id = node_idx / merkle_arity;
                    let level_dpf_n = compute_dpf_n(num_groups);

                    // Generate DPF keys for all K groups (1 key per group for flat table)
                    let mut s0_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(K);
                    let mut s1_keys: Vec<Vec<Vec<u8>>> = Vec::with_capacity(K);

                    for g in 0..K {
                        let alpha = if g == assigned_group {
                            group_id as u64
                        } else {
                            rng.next_u64() % num_groups as u64
                        };
                        let (k0, k1) = dpf.gen(alpha, level_dpf_n);
                        s0_keys.push(vec![k0.to_bytes()]);
                        s1_keys.push(vec![k1.to_bytes()]);
                    }

                    // round_id = table_type * 100 + level (table_type=0 for INDEX)
                    let round_id = level as u16;
                    let req0 = Request::BucketMerkleSibBatch(BatchQuery {
                        level: 2, round_id, db_id: 0, keys: s0_keys,
                    });
                    let req1 = Request::BucketMerkleSibBatch(BatchQuery {
                        level: 2, round_id, db_id: 0, keys: s1_keys,
                    });

                    sink0.send(Message::Binary(req0.encode().into())).await.expect("send s0 sib");
                    sink1.send(Message::Binary(req1.encode().into())).await.expect("send s1 sib");

                    let resp0 = recv_response(&mut stream0, &mut sink0).await;
                    let resp1 = recv_response(&mut stream1, &mut sink1).await;

                    let (sr0, sr1) = match (resp0, resp1) {
                        (Response::BucketMerkleSibBatch(a), Response::BucketMerkleSibBatch(b)) => (a, b),
                        (Response::Error(e), _) | (_, Response::Error(e)) => {
                            println!("  Bucket Merkle not supported: {}", e);
                            merkle_ok = false;
                            break;
                        }
                        _ => { println!("  Unexpected response for bucket merkle sib"); merkle_ok = false; break; }
                    };

                    // XOR to get sibling row (256 bytes = 8 × 32B child hashes)
                    let g = assigned_group;
                    if g < sr0.results.len() && !sr0.results[g].is_empty() {
                        let mut row = sr0.results[g][0].clone();
                        eval::xor_into(&mut row, &sr1.results[g][0]);

                        // Replace child at our position with current_hash, compute parent
                        let child_pos = node_idx % merkle_arity;
                        let mut children: Vec<[u8; 32]> = Vec::with_capacity(merkle_arity);
                        for c in 0..merkle_arity {
                            if c == child_pos {
                                children.push(current_hash);
                            } else {
                                let off = c * 32;
                                if off + 32 <= row.len() {
                                    let mut h = [0u8; 32];
                                    h.copy_from_slice(&row[off..off + 32]);
                                    children.push(h);
                                } else {
                                    children.push(merkle::ZERO_HASH);
                                }
                            }
                        }
                        current_hash = merkle::compute_parent_n(&children);
                        node_idx = group_id;
                    } else {
                        println!("  L{}: no sibling data for group {}", level, g);
                        merkle_ok = false;
                        break;
                    }
                }

                if merkle_ok {
                    // Walk tree-top cache
                    for ci in 0..cached_levels.len().saturating_sub(1) {
                        let level_nodes = &cached_levels[ci];
                        let parent_start = (node_idx / merkle_arity) * merkle_arity;
                        let child_pos = node_idx % merkle_arity;
                        let mut children = Vec::with_capacity(merkle_arity);
                        for c in 0..merkle_arity {
                            let idx = parent_start + c;
                            if c == child_pos {
                                children.push(current_hash);
                            } else if idx < level_nodes.len() {
                                children.push(level_nodes[idx]);
                            } else {
                                children.push(merkle::ZERO_HASH);
                            }
                        }
                        current_hash = merkle::compute_parent_n(&children);
                        node_idx /= merkle_arity;
                    }

                    // The root is the last level's single entry in the tree-top.
                    let expected_root = cached_levels.last()
                        .and_then(|level| level.first().copied())
                        .unwrap_or(merkle::ZERO_HASH);

                    if current_hash == expected_root {
                        println!("  INDEX Merkle VERIFIED for group {}: root {:02x}{:02x}{:02x}{:02x}...",
                            assigned_group,
                            current_hash[0], current_hash[1], current_hash[2], current_hash[3]);
                    } else {
                        println!("  INDEX Merkle FAILED for group {}!", assigned_group);
                        println!("    Expected: {:02x}{:02x}{:02x}{:02x}...",
                            expected_root[0], expected_root[1], expected_root[2], expected_root[3]);
                        println!("    Got:      {:02x}{:02x}{:02x}{:02x}...",
                            current_hash[0], current_hash[1], current_hash[2], current_hash[3]);
                    }
                }

                println!("  Merkle verification time: {:.2?}", l3_start.elapsed());
            } else {
                println!("  Could not find tree-top for INDEX group {}", assigned_group);
            }
        }
        println!();
    }

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

// read_varint uses shared build::common::read_varint

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

/// Receive a raw binary message (for tree-top cache etc.).
async fn recv_raw(
    stream: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> Vec<u8> {
    loop {
        let msg = stream.next().await.expect("no response").expect("read error");
        match msg {
            Message::Binary(b) => return b.to_vec(),
            _ => continue,
        }
    }
}
