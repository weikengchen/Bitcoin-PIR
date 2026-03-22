//! OnionPIR v2 client — multi-address batch queries.
//!
//! Queries multiple Bitcoin script hashes through a single OnionPIR v2 server.
//! Uses PBC cuckoo placement to batch queries across addresses into rounds,
//! minimizing the number of server round-trips.
//!
//! Level 1 (Index): 2-hash cuckoo with 256 slots/bin → scan for tag match
//! Level 2 (Chunk): client computes 6-hash cuckoo table → knows exact bin → 1 query
//!
//! Usage:
//!   cargo run --release -p runtime --bin onionpir2_client -- \
//!     --server ws://localhost:8091 \
//!     --hash <hex1> --hash <hex2> ...
//!   Or with a file (one hex hash per line):
//!     --file addresses.txt

use runtime::onionpir::*;
use runtime::protocol;
use build::common::*;
use futures_util::{SinkExt, StreamExt};
use onionpir::Client as PirClient;
use std::collections::HashMap;
use std::time::Instant;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

// ─── Constants for the new layout ───────────────────────────────────────────

const PACKED_ENTRY_SIZE: usize = 3840;

/// Chunk cuckoo: 6 hash functions, bucket_size=1
const CHUNK_CUCKOO_NUM_HASHES: usize = 6;
const CHUNK_CUCKOO_MAX_KICKS: usize = 10000;
const CHUNK_CUCKOO_SEED: u64 = 0xa3f7c2d918e4b065;
const EMPTY: u32 = u32::MAX;

// ─── CLI args ───────────────────────────────────────────────────────────────

struct Args {
    server: String,
    script_hashes: Vec<[u8; SCRIPT_HASH_SIZE]>,
}

fn parse_hex_hash(hex: &str) -> [u8; SCRIPT_HASH_SIZE] {
    if hex.len() != 40 {
        eprintln!("Error: hash must be 40 hex chars, got {}: '{}'", hex.len(), hex);
        std::process::exit(1);
    }
    let mut hash = [0u8; SCRIPT_HASH_SIZE];
    for j in 0..SCRIPT_HASH_SIZE {
        hash[j] = u8::from_str_radix(&hex[j * 2..j * 2 + 2], 16)
            .unwrap_or_else(|_| { eprintln!("Invalid hex: {}", hex); std::process::exit(1); });
    }
    hash
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut server = "ws://localhost:8091".to_string();
    let mut hashes: Vec<[u8; SCRIPT_HASH_SIZE]> = Vec::new();
    let mut file_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" | "-s" => { server = args[i + 1].clone(); i += 1; }
            "--hash" | "-h" => {
                hashes.push(parse_hex_hash(&args[i + 1]));
                i += 1;
            }
            "--file" | "-f" => { file_path = Some(args[i + 1].clone()); i += 1; }
            "--help" => {
                println!("Usage: onionpir2_client [--hash <hex>]... [--file <path>] [--server URL]");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    if let Some(path) = file_path {
        let contents = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| { eprintln!("Error reading {}: {}", path, e); std::process::exit(1); });
        for line in contents.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                hashes.push(parse_hex_hash(trimmed));
            }
        }
    }

    if hashes.is_empty() {
        eprintln!("Error: no addresses specified. Use --hash <hex> or --file <path>");
        std::process::exit(1);
    }

    Args { server, script_hashes: hashes }
}

// ─── WebSocket helpers ──────────────────────────────────────────────────────

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    Message,
>;
type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
>;

async fn recv_binary(stream: &mut WsStream, sink: &mut WsSink) -> Vec<u8> {
    loop {
        let msg = stream.next().await.expect("no response").expect("read error");
        match msg {
            Message::Binary(b) => return b.to_vec(),
            Message::Ping(p) => { let _ = sink.send(Message::Pong(p)).await; }
            _ => continue,
        }
    }
}

// ─── PRNG for dummy queries ─────────────────────────────────────────────────

struct DummyRng { state: u64 }

impl DummyRng {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap()
            .as_nanos() as u64;
        Self { state: splitmix64(seed) }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        splitmix64(self.state)
    }
}

// ─── PBC batch placement ────────────────────────────────────────────────────

/// Place items into groups using PBC cuckoo hashing.
/// Each item has NUM_HASHES (3) candidate groups out of `k` total groups.
/// Returns rounds of (original_item_index, assigned_group).
/// Each group has at most 1 item per round.
fn plan_pbc_rounds(
    candidate_groups: &[[usize; NUM_HASHES]],
    k: usize,
) -> Vec<Vec<(usize, usize)>> {
    let mut remaining: Vec<usize> = (0..candidate_groups.len()).collect();
    let mut rounds = Vec::new();

    while !remaining.is_empty() {
        let round_cands: Vec<[usize; NUM_HASHES]> = remaining.iter()
            .map(|&orig| candidate_groups[orig])
            .collect();

        let mut buckets: Vec<Option<usize>> = vec![None; k];
        let mut placed_round_indices = Vec::new();

        for ri in 0..round_cands.len() {
            if placed_round_indices.len() >= k { break; }
            let saved = buckets.clone();
            if pbc_cuckoo_place(&round_cands, &mut buckets, ri, 500) {
                placed_round_indices.push(ri);
            } else {
                buckets = saved;
            }
        }

        let mut round = Vec::new();
        for g in 0..k {
            if let Some(ri) = buckets[g] {
                round.push((remaining[ri], g));
            }
        }

        if round.is_empty() {
            eprintln!("PBC placement failed for {} remaining items", remaining.len());
            break;
        }

        let placed_originals: Vec<usize> = placed_round_indices.iter()
            .map(|&ri| remaining[ri]).collect();
        remaining.retain(|idx| !placed_originals.contains(idx));

        rounds.push(round);
    }

    rounds
}

fn pbc_cuckoo_place(
    cands: &[[usize; NUM_HASHES]],
    buckets: &mut [Option<usize>],
    qi: usize,
    max_kicks: usize,
) -> bool {
    for &c in &cands[qi] {
        if buckets[c].is_none() {
            buckets[c] = Some(qi);
            return true;
        }
    }

    let mut current_qi = qi;
    let mut current_bucket = cands[qi][0];

    for kick in 0..max_kicks {
        let evicted_qi = buckets[current_bucket].unwrap();
        buckets[current_bucket] = Some(current_qi);

        for offset in 0..NUM_HASHES {
            let c = cands[evicted_qi][(kick + offset) % NUM_HASHES];
            if c == current_bucket { continue; }
            if buckets[c].is_none() {
                buckets[c] = Some(evicted_qi);
                return true;
            }
        }

        let mut next_bucket = cands[evicted_qi][0];
        for offset in 0..NUM_HASHES {
            let c = cands[evicted_qi][(kick + offset) % NUM_HASHES];
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

// ─── Chunk cuckoo hash utilities (6-hash, bucket_size=1) ────────────────────

#[inline]
fn chunk_derive_cuckoo_key(group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        CHUNK_CUCKOO_SEED
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

#[inline]
fn chunk_cuckoo_hash(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

/// Build the chunk cuckoo table for a specific group (deterministic).
/// Replicates what the server did in gen_2_onion.
fn build_chunk_cuckoo_for_group(
    group_id: usize,
    total_entries: usize,
    bins_per_table: usize,
) -> Vec<u32> {
    // Collect all entries assigned to this group
    let mut entries: Vec<u32> = Vec::new();
    for eid in 0..total_entries as u32 {
        let buckets = derive_chunk_buckets(eid);
        if buckets.contains(&group_id) {
            entries.push(eid);
        }
    }
    entries.sort_unstable(); // deterministic insertion order

    let mut keys = [0u64; CHUNK_CUCKOO_NUM_HASHES];
    for h in 0..CHUNK_CUCKOO_NUM_HASHES {
        keys[h] = chunk_derive_cuckoo_key(group_id, h);
    }

    let mut table = vec![EMPTY; bins_per_table];

    for &entry_id in &entries {
        let mut placed = false;
        for h in 0..CHUNK_CUCKOO_NUM_HASHES {
            let bin = chunk_cuckoo_hash(entry_id, keys[h], bins_per_table);
            if table[bin] == EMPTY {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if placed { continue; }

        let mut current_id = entry_id;
        let mut current_hash_fn = 0;
        let mut current_bin = chunk_cuckoo_hash(entry_id, keys[0], bins_per_table);
        let mut success = false;

        for kick in 0..CHUNK_CUCKOO_MAX_KICKS {
            let evicted = table[current_bin];
            table[current_bin] = current_id;

            for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                let try_h = (current_hash_fn + 1 + h) % CHUNK_CUCKOO_NUM_HASHES;
                let bin = chunk_cuckoo_hash(evicted, keys[try_h], bins_per_table);
                if bin == current_bin { continue; }
                if table[bin] == EMPTY {
                    table[bin] = evicted;
                    success = true;
                    break;
                }
            }
            if success { break; }

            let alt_h = (current_hash_fn + 1 + kick % (CHUNK_CUCKOO_NUM_HASHES - 1)) % CHUNK_CUCKOO_NUM_HASHES;
            let alt_bin = chunk_cuckoo_hash(evicted, keys[alt_h], bins_per_table);
            let final_bin = if alt_bin == current_bin {
                let h2 = (alt_h + 1) % CHUNK_CUCKOO_NUM_HASHES;
                chunk_cuckoo_hash(evicted, keys[h2], bins_per_table)
            } else {
                alt_bin
            };

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        if !success {
            panic!("Client cuckoo failed for entry_id={}", entry_id);
        }
    }

    table
}

/// Find which bin holds entry_id in a cuckoo table.
fn find_entry_in_cuckoo(
    table: &[u32],
    entry_id: u32,
    keys: &[u64; CHUNK_CUCKOO_NUM_HASHES],
    bins_per_table: usize,
) -> Option<usize> {
    for h in 0..CHUNK_CUCKOO_NUM_HASHES {
        let bin = chunk_cuckoo_hash(entry_id, keys[h], bins_per_table);
        if table[bin] == entry_id {
            return Some(bin);
        }
    }
    None
}

// ─── Varint ─────────────────────────────────────────────────────────────────

fn read_varint(data: &[u8]) -> (u64, usize) {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 { return (value, i + 1); }
        shift += 7;
        if shift >= 64 { panic!("varint too large"); }
    }
    panic!("unexpected end of varint");
}

// ─── Index query helpers ────────────────────────────────────────────────────

/// Result from the index level for one address.
struct IndexResult {
    entry_id: u32,
    byte_offset: u16,
    num_entries: u8,
}

/// Scan a decrypted index bin (256 slots) for a matching tag.
fn scan_index_bin(
    entry_bytes: &[u8],
    tag: u64,
    bucket_size: usize,
    slot_size: usize,
) -> Option<IndexResult> {
    for slot in 0..bucket_size {
        let off = slot * slot_size;
        if off + slot_size > entry_bytes.len() { break; }
        let slot_tag = u64::from_le_bytes(entry_bytes[off..off + 8].try_into().unwrap());
        if slot_tag == tag && slot_tag != 0 {
            let entry_id = u32::from_le_bytes(entry_bytes[off + 8..off + 12].try_into().unwrap());
            let byte_offset = u16::from_le_bytes(entry_bytes[off + 12..off + 14].try_into().unwrap());
            let num_entries = entry_bytes[off + 14];
            return Some(IndexResult { entry_id, byte_offset, num_entries });
        }
    }
    None
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = parse_args();
    let num_addresses = args.script_hashes.len();

    println!("=== OnionPIR v2 Client ({} address{}) ===",
        num_addresses, if num_addresses == 1 { "" } else { "es" });
    println!("  Server: {}", args.server);
    for (i, sh) in args.script_hashes.iter().enumerate() {
        let hex: String = sh.iter().map(|b| format!("{:02x}", b)).collect();
        println!("  [{}] {}", i + 1, hex);
    }
    println!();

    let total_start = Instant::now();

    // ── 1. Connect ──────────────────────────────────────────────────────
    println!("[1] Connecting...");
    let (ws, _) = connect_async(&args.server).await.expect("connect");
    let (mut sink, mut stream) = ws.split();
    println!("  Connected.\n");

    // ── 2. Get server info ──────────────────────────────────────────────
    println!("[2] Getting server info...");
    {
        let mut req = Vec::with_capacity(5);
        req.extend_from_slice(&1u32.to_le_bytes());
        req.push(protocol::REQ_GET_INFO);
        sink.send(Message::Binary(req.into())).await.expect("send");
    }
    let info_bytes = recv_binary(&mut stream, &mut sink).await;
    let info_payload = &info_bytes[4..];
    let body = &info_payload[1..];

    let index_k = body[0] as usize;
    let chunk_k = body[1] as usize;
    let index_bins = u32::from_le_bytes(body[2..6].try_into().unwrap()) as usize;
    let chunk_bins = u32::from_le_bytes(body[6..10].try_into().unwrap()) as usize;
    let tag_seed = u64::from_le_bytes(body[10..18].try_into().unwrap());
    let total_packed = u32::from_le_bytes(body[18..22].try_into().unwrap()) as usize;
    let index_bucket_size = u16::from_le_bytes(body[22..24].try_into().unwrap()) as usize;
    let index_slot_size = body[24] as usize;

    println!("  Index: K={}, bins={}, bucket_size={}, slot_size={}",
        index_k, index_bins, index_bucket_size, index_slot_size);
    println!("  Chunk: K={}, bins={}, total_packed={}", chunk_k, chunk_bins, total_packed);
    println!();

    // ── 3. Create PIR client and register keys (single registration) ────
    // Keys are independent of num_entries. We generate keys once, export the
    // secret key, then create per-level clients with the correct num_entries
    // for query generation and decryption.
    println!("[3] Creating PIR client...");
    let key_start = Instant::now();
    let mut keygen_client = PirClient::new(0);
    let client_id = keygen_client.id();
    let galois = keygen_client.generate_galois_keys();
    let gsw = keygen_client.generate_gsw_keys();
    let secret_key = keygen_client.export_secret_key();
    println!("  Key generation: {:.2?}", key_start.elapsed());

    // Create per-level clients sharing the same secret key
    let mut index_client = PirClient::new_from_secret_key(
        index_bins as u64, client_id, &secret_key,
    );
    let mut chunk_client = PirClient::new_from_secret_key(
        chunk_bins as u64, client_id, &secret_key,
    );

    // Register keys once — shared across all levels
    let reg_msg = RegisterKeysMsg {
        galois_keys: galois,
        gsw_keys: gsw,
    };
    sink.send(Message::Binary(reg_msg.encode().into())).await.expect("send keys");
    let ack = recv_binary(&mut stream, &mut sink).await;
    assert_eq!(ack[4], RESP_KEYS_ACK);
    println!("  Keys registered (single registration, shared secret key).\n");

    // ══════════════════════════════════════════════════════════════════════
    // LEVEL 1: Index PIR (batched across addresses)
    // ══════════════════════════════════════════════════════════════════════
    println!("[4] Level 1: Index PIR ({} addresses)...", num_addresses);
    let l1_start = Instant::now();

    // Prepare per-address info
    struct AddrInfo {
        tag: u64,
        groups: [usize; NUM_HASHES],
    }
    let addr_infos: Vec<AddrInfo> = args.script_hashes.iter().map(|sh| {
        AddrInfo {
            tag: compute_tag(tag_seed, sh),
            groups: derive_buckets(sh),
        }
    }).collect();

    let mut index_results: Vec<Option<IndexResult>> = (0..num_addresses).map(|_| None).collect();
    let mut rng = DummyRng::new();
    let mut total_index_rounds = 0u16;

    // PBC place all addresses — group assignments reused for hash1 retry
    let all_groups: Vec<[usize; NUM_HASHES]> = addr_infos.iter().map(|a| a.groups).collect();
    let index_rounds = plan_pbc_rounds(&all_groups, index_k);
    println!("  PBC placement: {} addresses → {} round{}",
        num_addresses, index_rounds.len(),
        if index_rounds.len() == 1 { "" } else { "s" });

    // Track group assignment per address for hash1 retry (must use same group)
    let mut addr_group_assignment: HashMap<usize, usize> = HashMap::new();

    // Hash0 pass
    for round in &index_rounds {
        let mut group_map: HashMap<usize, (usize, usize)> = HashMap::new();
        for &(addr_idx, group) in round {
            addr_group_assignment.insert(addr_idx, group);
            let key0 = derive_cuckoo_key(group, 0);
            let bin0 = cuckoo_hash(&args.script_hashes[addr_idx], key0, index_bins);
            group_map.insert(group, (addr_idx, bin0));
        }

        let mut queries = Vec::with_capacity(index_k);
        for g in 0..index_k {
            let idx = if let Some(&(_, bin)) = group_map.get(&g) {
                bin as u64
            } else {
                rng.next_u64() % index_bins as u64
            };
            queries.push(index_client.generate_query(idx));
        }

        let batch = OnionPirBatchQuery { round_id: total_index_rounds, queries };
        sink.send(Message::Binary(batch.encode(REQ_ONIONPIR_INDEX_QUERY).into())).await.expect("send");
        total_index_rounds += 1;

        let resp_bytes = recv_binary(&mut stream, &mut sink).await;
        let resp_payload = &resp_bytes[4..];
        assert_eq!(resp_payload[0], RESP_ONIONPIR_INDEX_RESULT);
        let result_batch = OnionPirBatchResult::decode(&resp_payload[1..]).expect("decode");

        for &(addr_idx, group) in round {
            let (_, bin) = group_map[&group];
            let entry_bytes = index_client.decrypt_response(
                bin as u64,
                &result_batch.results[group],
            );
            if let Some(ir) = scan_index_bin(&entry_bytes, addr_infos[addr_idx].tag, index_bucket_size, index_slot_size) {
                index_results[addr_idx] = Some(ir);
            }
        }
    }

    // Hash1 retry — reuse SAME group assignments from hash0
    let missed_h0: Vec<usize> = (0..num_addresses)
        .filter(|&i| index_results[i].is_none())
        .collect();

    if !missed_h0.is_empty() {
        println!("  {} missed hash0, retrying hash1 (same groups)...", missed_h0.len());

        // All missed addresses have non-colliding group assignments from hash0
        let mut group_map: HashMap<usize, (usize, usize)> = HashMap::new();
        for &addr_idx in &missed_h0 {
            let group = addr_group_assignment[&addr_idx];
            let key1 = derive_cuckoo_key(group, 1);
            let bin1 = cuckoo_hash(&args.script_hashes[addr_idx], key1, index_bins);
            group_map.insert(group, (addr_idx, bin1));
        }

        let mut queries = Vec::with_capacity(index_k);
        for g in 0..index_k {
            let idx = if let Some(&(_, bin)) = group_map.get(&g) {
                bin as u64
            } else {
                rng.next_u64() % index_bins as u64
            };
            queries.push(index_client.generate_query(idx));
        }

        let batch = OnionPirBatchQuery { round_id: total_index_rounds, queries };
        sink.send(Message::Binary(batch.encode(REQ_ONIONPIR_INDEX_QUERY).into())).await.expect("send");
        total_index_rounds += 1;

        let resp_bytes = recv_binary(&mut stream, &mut sink).await;
        let resp_payload = &resp_bytes[4..];
        assert_eq!(resp_payload[0], RESP_ONIONPIR_INDEX_RESULT);
        let result_batch = OnionPirBatchResult::decode(&resp_payload[1..]).expect("decode");

        for &addr_idx in &missed_h0 {
            let group = addr_group_assignment[&addr_idx];
            let (_, bin) = group_map[&group];
            let entry_bytes = index_client.decrypt_response(
                bin as u64,
                &result_batch.results[group],
            );
            if let Some(ir) = scan_index_bin(&entry_bytes, addr_infos[addr_idx].tag, index_bucket_size, index_slot_size) {
                index_results[addr_idx] = Some(ir);
            }
        }
    }

    // Report index results
    let found_count = index_results.iter().filter(|r| r.is_some()).count();
    let whale_count = index_results.iter().filter(|r| {
        matches!(r, Some(ir) if ir.num_entries == FLAG_WHALE)
    }).count();
    println!("  Found: {}/{} addresses ({} whale, {} not found)",
        found_count, num_addresses, whale_count, num_addresses - found_count);
    println!("  Level 1: {} rounds in {:.2?}", total_index_rounds, l1_start.elapsed());
    println!();

    // ══════════════════════════════════════════════════════════════════════
    // LEVEL 2: Chunk PIR (batched across all entry_ids)
    // ══════════════════════════════════════════════════════════════════════
    println!("[5] Level 2: Chunk PIR...");
    let l2_start = Instant::now();

    // Collect all unique entry_ids needed BEFORE registering chunk keys
    let mut unique_entry_ids: Vec<u32> = Vec::new();
    let mut entry_id_set: HashMap<u32, usize> = HashMap::new();

    for ir in &index_results {
        if let Some(ir) = ir {
            if ir.num_entries == FLAG_WHALE {
                println!("  (whale address excluded)");
                continue;
            }
            for i in 0..ir.num_entries as u32 {
                let eid = ir.entry_id + i;
                if !entry_id_set.contains_key(&eid) {
                    let idx = unique_entry_ids.len();
                    entry_id_set.insert(eid, idx);
                    unique_entry_ids.push(eid);
                }
            }
        }
    }

    // Decrypted entry data: entry_id → raw bytes
    let mut decrypted_entries: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut chunk_rounds_count = 0usize;

    if unique_entry_ids.is_empty() {
        println!("  No entries to fetch — skipping chunk phase.");
    } else {
    // PBC place entries into chunk groups
    let entry_pbc_groups: Vec<[usize; NUM_HASHES]> = unique_entry_ids.iter()
        .map(|&eid| derive_chunk_buckets(eid))
        .collect();
    let chunk_rounds = plan_pbc_rounds(&entry_pbc_groups, chunk_k);

    println!("  {} unique entries → {} chunk round{}",
        unique_entry_ids.len(), chunk_rounds.len(),
        if chunk_rounds.len() == 1 { "" } else { "s" });

    // Cuckoo table cache (group_id → table)
    let mut cuckoo_cache: HashMap<usize, Vec<u32>> = HashMap::new();

    for (ri, round) in chunk_rounds.iter().enumerate() {
        // For each entry in this round, build cuckoo table if needed and find bin
        struct ChunkQuery {
            entry_id: u32,
            group: usize,
            bin: usize,
        }
        let mut chunk_queries: Vec<ChunkQuery> = Vec::new();
        let mut group_to_qi: HashMap<usize, usize> = HashMap::new();

        let t_cuckoo = Instant::now();
        let mut tables_built = 0usize;

        for &(ei, group) in round {
            let eid = unique_entry_ids[ei];

            if !cuckoo_cache.contains_key(&group) {
                let table = build_chunk_cuckoo_for_group(group, total_packed, chunk_bins);
                cuckoo_cache.insert(group, table);
                tables_built += 1;
            }

            let mut keys = [0u64; CHUNK_CUCKOO_NUM_HASHES];
            for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                keys[h] = chunk_derive_cuckoo_key(group, h);
            }
            let bin = find_entry_in_cuckoo(cuckoo_cache.get(&group).unwrap(), eid, &keys, chunk_bins)
                .unwrap_or_else(|| panic!("entry_id {} not in cuckoo table for group {}", eid, group));

            let qi = chunk_queries.len();
            chunk_queries.push(ChunkQuery { entry_id: eid, group, bin });
            group_to_qi.insert(group, qi);
        }

        if tables_built > 0 {
            println!("  Round {}: built {} cuckoo table{} in {:.2?}",
                ri + 1, tables_built,
                if tables_built == 1 { "" } else { "s" },
                t_cuckoo.elapsed());
        }

        // Generate 80 queries (real for assigned groups, dummy for rest)
        let mut queries = Vec::with_capacity(chunk_k);
        for g in 0..chunk_k {
            let idx = if let Some(&qi) = group_to_qi.get(&g) {
                chunk_queries[qi].bin as u64
            } else {
                rng.next_u64() % chunk_bins as u64
            };
            queries.push(chunk_client.generate_query(idx));
        }

        let batch = OnionPirBatchQuery { round_id: ri as u16, queries };
        sink.send(Message::Binary(batch.encode(REQ_ONIONPIR_CHUNK_QUERY).into())).await.expect("send");

        let resp_bytes = recv_binary(&mut stream, &mut sink).await;
        let resp_payload = &resp_bytes[4..];
        assert_eq!(resp_payload[0], RESP_ONIONPIR_CHUNK_RESULT);
        let result_batch = OnionPirBatchResult::decode(&resp_payload[1..]).expect("decode");

        // Decrypt and store entries
        for cq in &chunk_queries {
            let entry_bytes = chunk_client.decrypt_response(
                cq.bin as u64,
                &result_batch.results[cq.group],
            );
            decrypted_entries.insert(cq.entry_id, entry_bytes[..PACKED_ENTRY_SIZE].to_vec());
        }
    }

    chunk_rounds_count = chunk_rounds.len();
    } // end if unique_entry_ids not empty

    println!("  Level 2: {} rounds in {:.2?}", chunk_rounds_count, l2_start.elapsed());
    println!();

    // ══════════════════════════════════════════════════════════════════════
    // Decode and output UTXO data per address
    // ══════════════════════════════════════════════════════════════════════
    println!("[6] Results:\n");

    for (addr_idx, sh) in args.script_hashes.iter().enumerate() {
        let hex: String = sh.iter().map(|b| format!("{:02x}", b)).collect();

        let ir = match &index_results[addr_idx] {
            Some(ir) => ir,
            None => {
                println!("  Address {}/{}: {} — NOT FOUND\n", addr_idx + 1, num_addresses, hex);
                continue;
            }
        };

        if ir.num_entries == FLAG_WHALE {
            println!("  Address {}/{}: {} — WHALE (excluded)\n", addr_idx + 1, num_addresses, hex);
            continue;
        }

        // Assemble data from entries
        let mut full_data = Vec::new();
        for i in 0..ir.num_entries as u32 {
            let eid = ir.entry_id + i;
            let entry = decrypted_entries.get(&eid)
                .unwrap_or_else(|| panic!("missing entry_id {}", eid));

            if i == 0 {
                let start = ir.byte_offset as usize;
                full_data.extend_from_slice(&entry[start..]);
            } else {
                full_data.extend_from_slice(entry);
            }
        }

        // Decode UTXOs
        let mut pos = 0;
        let (num_utxos, vr) = read_varint(&full_data[pos..]);
        pos += vr;

        println!("  Address {}/{}: {} ({} UTXOs)", addr_idx + 1, num_addresses, hex, num_utxos);

        let mut total_sats: u64 = 0;
        for i in 0..num_utxos as usize {
            if pos + 32 > full_data.len() {
                println!("    (data truncated at UTXO {})", i);
                break;
            }
            let txid_bytes = &full_data[pos..pos + 32];
            pos += 32;

            let mut txid_rev = [0u8; 32];
            for j in 0..32 { txid_rev[j] = txid_bytes[31 - j]; }
            let txid_hex: String = txid_rev.iter().map(|b| format!("{:02x}", b)).collect();

            let (vout, vr) = read_varint(&full_data[pos..]);
            pos += vr;
            let (amount, ar) = read_varint(&full_data[pos..]);
            pos += ar;

            total_sats += amount;
            let btc = amount as f64 / 100_000_000.0;
            println!("    UTXO #{}: {}:{} — {} sats ({:.8} BTC)", i + 1, txid_hex, vout, amount, btc);
        }

        let total_btc = total_sats as f64 / 100_000_000.0;
        println!("    Total: {} sats ({:.8} BTC)\n", total_sats, total_btc);
    }

    // ── Summary ─────────────────────────────────────────────────────────
    println!("=== Done ===");
    println!("  {} addresses, {} index rounds, {} chunk rounds",
        num_addresses, total_index_rounds, chunk_rounds_count);
    println!("  Total time: {:.2?}", total_start.elapsed());

    let _ = sink.send(Message::Close(None)).await;
}
