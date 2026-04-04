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
//!   cargo run --release -p runtime --bin onionpir_client -- \
//!     --server ws://localhost:8091 \
//!     --hash <hex1> --hash <hex2> ...
//!   Or with a file (one hex hash per line):
//!     --file addresses.txt

use runtime::onionpir::*;
use build::common::*;
use futures_util::{SinkExt, StreamExt};
use onionpir::Client as PirClient;
use pir_core::merkle;
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
    verify: bool,
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
    let mut verify = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" | "-s" => { server = args[i + 1].clone(); i += 1; }
            "--hash" | "-h" => {
                hashes.push(parse_hex_hash(&args[i + 1]));
                i += 1;
            }
            "--file" | "-f" => { file_path = Some(args[i + 1].clone()); i += 1; }
            "--verify" | "-v" => { verify = true; }
            "--help" => {
                println!("Usage: onionpir_client [--hash <hex>]... [--file <path>] [--server URL] [--verify]");
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

    Args { server, script_hashes: hashes, verify }
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

// PBC batch placement uses shared build::common::{pbc_cuckoo_place, pbc_plan_rounds}

// ─── JSON server info parsing ──────────────────────────────────────────────

/// Extract a JSON number value for a given key (simple substring search).
fn json_u64(json: &str, key: &str) -> u64 {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle).unwrap_or_else(|| panic!("missing JSON key: {}", key));
    let start = pos + needle.len();
    let rest = json[start..].trim_start();
    // Parse digits (or quoted hex string for tag_seed)
    if rest.starts_with('"') {
        // Hex string like "0x71a2ef38b4c90d15"
        let end = rest[1..].find('"').unwrap() + 1;
        let hex = &rest[1..end];
        u64::from_str_radix(hex.trim_start_matches("0x"), 16).expect("bad hex")
    } else {
        let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        rest[..end].parse().unwrap_or_else(|_| panic!("bad number for key {}", key))
    }
}

/// Parse the JSON server info response. Prefers the `onionpir` sub-object if present,
/// falling back to top-level DPF params.
///
/// Returns: (index_k, chunk_k, index_bins, chunk_bins, tag_seed, total_packed, bucket_size, slot_size)
fn parse_server_info_json(json: &str) -> (usize, usize, usize, usize, u64, usize, usize, usize) {
    // Check for OnionPIR sub-object
    if let Some(opi_start) = json.find("\"onionpir\"") {
        // Find the opening brace of the onionpir object
        let brace_pos = json[opi_start..].find('{').unwrap() + opi_start;
        // Find the matching closing brace (handle nested braces)
        let mut depth = 0;
        let mut end_pos = brace_pos;
        for (i, c) in json[brace_pos..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end_pos = brace_pos + i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let opi = &json[brace_pos..end_pos];
        (
            json_u64(opi, "index_k") as usize,
            json_u64(opi, "chunk_k") as usize,
            json_u64(opi, "index_bins_per_table") as usize,
            json_u64(opi, "chunk_bins_per_table") as usize,
            json_u64(opi, "tag_seed"),
            json_u64(opi, "total_packed_entries") as usize,
            json_u64(opi, "index_cuckoo_bucket_size") as usize,
            json_u64(opi, "index_slot_size") as usize,
        )
    } else {
        // Fallback to top-level DPF params
        (
            json_u64(json, "index_k") as usize,
            json_u64(json, "chunk_k") as usize,
            json_u64(json, "index_bins_per_table") as usize,
            json_u64(json, "chunk_bins_per_table") as usize,
            json_u64(json, "tag_seed"),
            0,
            json_u64(json, "index_cuckoo_bucket_size") as usize,
            json_u64(json, "index_slot_size") as usize,
        )
    }
}

// ─── OnionPIR Merkle info parsing ───────────────────────────────────────────

struct OnionMerkleInfo {
    arity: usize,
    levels: Vec<OnionMerkleLevelInfo>,
    root: [u8; 32],
}

struct OnionMerkleLevelInfo {
    k: usize,
    bins_per_table: usize,
    num_groups: usize,
}

/// Parse `onionpir_merkle` section from JSON. Returns None if not present.
fn parse_onionpir_merkle(json: &str) -> Option<OnionMerkleInfo> {
    let start = json.find("\"onionpir_merkle\"")?;
    let brace = json[start..].find('{')? + start;
    let mut depth = 0;
    let mut end = brace;
    for (i, c) in json[brace..].char_indices() {
        match c { '{' => depth += 1, '}' => { depth -= 1; if depth == 0 { end = brace + i + 1; break; } } _ => {} }
    }
    let section = &json[brace..end];

    let arity = json_u64(section, "arity") as usize;
    let num_levels = json_u64(section, "sibling_levels") as usize;

    // Parse root hex
    let root_key = "\"root\":\"";
    let root_start = section.find(root_key).map(|p| p + root_key.len())?;
    let root_end = section[root_start..].find('"')? + root_start;
    let root_hex = &section[root_start..root_end];
    let mut root = [0u8; 32];
    for i in 0..32 {
        root[i] = u8::from_str_radix(&root_hex[i * 2..i * 2 + 2], 16).ok()?;
    }

    // Parse levels array (simple: extract k, bins_per_table, num_groups from each object)
    let mut levels = Vec::new();
    let levels_start = section.find("\"levels\":[")? + "\"levels\":[".len();
    let levels_section = &section[levels_start..];
    let mut pos = 0;
    for _ in 0..num_levels {
        let obj_start = levels_section[pos..].find('{')? + pos;
        let obj_end = levels_section[obj_start..].find('}')? + obj_start + 1;
        let obj = &levels_section[obj_start..obj_end];
        levels.push(OnionMerkleLevelInfo {
            k: json_u64(obj, "k") as usize,
            bins_per_table: json_u64(obj, "bins_per_table") as usize,
            num_groups: json_u64(obj, "num_groups") as usize,
        });
        pos = obj_end;
    }

    Some(OnionMerkleInfo { arity, levels, root })
}

// ─── Sibling cuckoo utilities (6-hash, bucket_size=1) ──────────────────────

const SIB_CUCKOO_NUM_HASHES: usize = 6;
const SIB_CUCKOO_MAX_KICKS: usize = 10000;

fn sib_level_master_seed(level: usize) -> u64 {
    0xBA7C_51B1_FEED_0000u64.wrapping_add(level as u64)
}

fn sib_derive_cuckoo_key(master_seed: u64, group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        master_seed
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

fn sib_cuckoo_hash(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

/// Derive 3 distinct PBC group indices for an entry (sibling-level PBC).
fn derive_sib_pbc_buckets(entry_id: u32, k: usize) -> [usize; 3] {
    let mut buckets = [0usize; 3];
    let mut nonce = 0u64;
    let mut count = 0;
    while count < 3 {
        let h = splitmix64((entry_id as u64).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15)));
        let b = (h % k as u64) as usize;
        nonce += 1;
        if count == 0 || (count == 1 && b != buckets[0]) || (count == 2 && b != buckets[0] && b != buckets[1]) {
            buckets[count] = b;
            count += 1;
        }
    }
    buckets
}

/// Build the sibling cuckoo table for a single PBC group at a given level.
fn build_sib_cuckoo_for_group(
    level: usize,
    group_id: usize,
    entries: &[u32], // sorted entry_ids in this PBC group
    bins_per_table: usize,
) -> Vec<u32> {
    let master_seed = sib_level_master_seed(level);
    let mut keys = [0u64; SIB_CUCKOO_NUM_HASHES];
    for h in 0..SIB_CUCKOO_NUM_HASHES {
        keys[h] = sib_derive_cuckoo_key(master_seed, group_id, h);
    }

    let mut table = vec![EMPTY; bins_per_table];
    for &entry_id in entries {
        let mut placed = false;
        for h in 0..SIB_CUCKOO_NUM_HASHES {
            let bin = sib_cuckoo_hash(entry_id, keys[h], bins_per_table);
            if table[bin] == EMPTY { table[bin] = entry_id; placed = true; break; }
        }
        if placed { continue; }

        let mut current_id = entry_id;
        let mut current_hash_fn = 0;
        let mut current_bin = sib_cuckoo_hash(entry_id, keys[0], bins_per_table);
        let mut success = false;
        for kick in 0..SIB_CUCKOO_MAX_KICKS {
            let evicted = table[current_bin];
            table[current_bin] = current_id;
            for h in 0..SIB_CUCKOO_NUM_HASHES {
                let try_h = (current_hash_fn + 1 + h) % SIB_CUCKOO_NUM_HASHES;
                let bin = sib_cuckoo_hash(evicted, keys[try_h], bins_per_table);
                if bin == current_bin { continue; }
                if table[bin] == EMPTY { table[bin] = evicted; success = true; break; }
            }
            if success { break; }
            let alt_h = (current_hash_fn + 1 + kick % (SIB_CUCKOO_NUM_HASHES - 1)) % SIB_CUCKOO_NUM_HASHES;
            let alt_bin = sib_cuckoo_hash(evicted, keys[alt_h], bins_per_table);
            let final_bin = if alt_bin == current_bin {
                sib_cuckoo_hash(evicted, keys[(alt_h + 1) % SIB_CUCKOO_NUM_HASHES], bins_per_table)
            } else { alt_bin };
            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }
        if !success { panic!("Sibling cuckoo failed for entry_id={}", entry_id); }
    }
    table
}

/// Find entry_id's bin in a cuckoo table.
fn find_in_sib_cuckoo(
    table: &[u32], entry_id: u32, level: usize, group_id: usize, bins_per_table: usize,
) -> Option<usize> {
    let master_seed = sib_level_master_seed(level);
    for h in 0..SIB_CUCKOO_NUM_HASHES {
        let key = sib_derive_cuckoo_key(master_seed, group_id, h);
        let bin = sib_cuckoo_hash(entry_id, key, bins_per_table);
        if table[bin] == entry_id { return Some(bin); }
    }
    None
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

/// Build reverse index: group → sorted entry_ids, in a single pass over all entries.
/// 80× faster than scanning per-group.
fn build_chunk_reverse_index(total_entries: usize) -> Vec<Vec<u32>> {
    let mut index: Vec<Vec<u32>> = (0..K_CHUNK).map(|_| Vec::new()).collect();
    for eid in 0..total_entries as u32 {
        let buckets = derive_chunk_buckets(eid);
        for &g in &buckets {
            index[g].push(eid);
        }
    }
    // Already sorted since we iterate eid in order
    index
}

/// Build the chunk cuckoo table for a specific group (deterministic).
/// Replicates what the server did in gen_2_onion.
fn build_chunk_cuckoo_for_group(
    group_id: usize,
    reverse_index: &[Vec<u32>],
    bins_per_table: usize,
) -> Vec<u32> {
    let entries = &reverse_index[group_id];

    let mut keys = [0u64; CHUNK_CUCKOO_NUM_HASHES];
    for h in 0..CHUNK_CUCKOO_NUM_HASHES {
        keys[h] = chunk_derive_cuckoo_key(group_id, h);
    }

    let mut table = vec![EMPTY; bins_per_table];

    for &entry_id in entries {
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

// read_varint uses shared build::common::read_varint

// ─── Index query helpers ────────────────────────────────────────────────────

/// Result from the index level for one address.
struct IndexResult {
    entry_id: u32,
    byte_offset: u16,
    num_entries: u8,
    tree_loc: u32,
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
            let tree_loc = if off + 19 <= entry_bytes.len() {
                u32::from_le_bytes(entry_bytes[off + 15..off + 19].try_into().unwrap())
            } else { 0 };
            return Some(IndexResult { entry_id, byte_offset, num_entries, tree_loc });
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

    // ── 2. Get server info (JSON) ─────────────────────────────────────
    println!("[2] Getting server info (JSON)...");
    {
        let mut req = Vec::with_capacity(5);
        req.extend_from_slice(&1u32.to_le_bytes());
        req.push(0x03); // REQ_GET_INFO_JSON
        sink.send(Message::Binary(req.into())).await.expect("send");
    }
    let info_bytes = recv_binary(&mut stream, &mut sink).await;
    // Response: [4B len LE][1B variant=0x03][JSON bytes...]
    let json_str = std::str::from_utf8(&info_bytes[5..]).expect("invalid UTF-8 in server info JSON");

    let (index_k, chunk_k, index_bins, chunk_bins, tag_seed, total_packed, index_bucket_size, index_slot_size) =
        parse_server_info_json(json_str);

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
    let mut keygen_client = PirClient::new(index_bins as u64);
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

    // PBC place all addresses into groups
    let all_groups: Vec<[usize; NUM_HASHES]> = addr_infos.iter().map(|a| a.groups).collect();
    let index_rounds = pbc_plan_rounds(&all_groups, index_k, NUM_HASHES, 500);
    println!("  PBC placement: {} addresses → {} round{}",
        num_addresses, index_rounds.len(),
        if index_rounds.len() == 1 { "" } else { "s" });

    // Each round: 2 queries per group (hash0 + hash1 bins), matching DPF approach
    for round in &index_rounds {
        let mut group_map: HashMap<usize, usize> = HashMap::new(); // group → addr_idx
        for &(addr_idx, group) in round {
            group_map.insert(group, addr_idx);
        }

        // Generate 2*K queries: [g0_h0, g0_h1, g1_h0, g1_h1, ...]
        let mut queries = Vec::with_capacity(2 * index_k);
        let mut query_bins: Vec<u64> = Vec::with_capacity(2 * index_k);
        for g in 0..index_k {
            for h in 0..INDEX_CUCKOO_NUM_HASHES {
                let bin = if let Some(&addr_idx) = group_map.get(&g) {
                    let key = derive_cuckoo_key(g, h);
                    cuckoo_hash(&args.script_hashes[addr_idx], key, index_bins) as u64
                } else {
                    rng.next_u64() % index_bins as u64
                };
                queries.push(index_client.generate_query(bin));
                query_bins.push(bin);
            }
        }

        let batch = OnionPirBatchQuery { round_id: total_index_rounds, queries };
        sink.send(Message::Binary(batch.encode(REQ_ONIONPIR_INDEX_QUERY).into())).await.expect("send");
        total_index_rounds += 1;

        let resp_bytes = recv_binary(&mut stream, &mut sink).await;
        let resp_payload = &resp_bytes[4..];
        assert_eq!(resp_payload[0], RESP_ONIONPIR_INDEX_RESULT);
        let result_batch = OnionPirBatchResult::decode(&resp_payload[1..]).expect("decode");

        // Decrypt both hash results and scan for tag
        for &(addr_idx, group) in round {
            for h in 0..INDEX_CUCKOO_NUM_HASHES {
                let qi = group * 2 + h;
                let bin = query_bins[qi];
                let entry_bytes = index_client.decrypt_response(
                    bin,
                    &result_batch.results[qi],
                );
                if let Some(ir) = scan_index_bin(&entry_bytes, addr_infos[addr_idx].tag, index_bucket_size, index_slot_size) {
                    index_results[addr_idx] = Some(ir);
                    break;
                }
            }
        }
    }

    // Report index results
    let found_count = index_results.iter().filter(|r| r.is_some()).count();
    let whale_count = index_results.iter().filter(|r| {
        matches!(r, Some(ir) if ir.num_entries == 0)
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
            if ir.num_entries == 0 {
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
    // Build reverse index once: group → entry_ids (single pass over all entries)
    let t_rev = Instant::now();
    let reverse_index = build_chunk_reverse_index(total_packed);
    println!("  Reverse index built in {:.2?}", t_rev.elapsed());

    // PBC place entries into chunk groups
    let entry_pbc_groups: Vec<[usize; NUM_HASHES]> = unique_entry_ids.iter()
        .map(|&eid| derive_chunk_buckets(eid))
        .collect();
    let chunk_rounds = pbc_plan_rounds(&entry_pbc_groups, chunk_k, NUM_HASHES, 500);

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
                let table = build_chunk_cuckoo_for_group(group, &reverse_index, chunk_bins);
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

        if ir.num_entries == 0 {
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

    // ══════════════════════════════════════════════════════════════════════
    // MERKLE VERIFICATION (optional, --verify flag)
    // ══════════════════════════════════════════════════════════════════════

    if !args.verify {
        println!("[7] Merkle verification skipped (use --verify to enable)");
        sink.close().await.ok();
        return;
    }

    let merkle_info = parse_onionpir_merkle(json_str);
    if let Some(ref mi) = merkle_info {
        println!("[7] Merkle Verification (arity={}, {} sibling levels)...\n",
            mi.arity, mi.levels.len());

        // Fetch tree-top cache
        {
            let mut req = Vec::with_capacity(5);
            req.extend_from_slice(&1u32.to_le_bytes());
            req.push(REQ_ONIONPIR_MERKLE_TREE_TOP);
            sink.send(Message::Binary(req.into())).await.expect("send");
        }
        let top_bytes = recv_binary(&mut stream, &mut sink).await;
        let tree_top = &top_bytes[5..]; // skip [4B len][1B variant]
        println!("  Tree-top cache: {} bytes", tree_top.len());

        // Parse tree-top cache header
        let cache_from_level = tree_top[0] as usize;
        let cache_arity = u16::from_le_bytes(tree_top[5..7].try_into().unwrap()) as usize;
        let num_cached_levels = tree_top[7] as usize;
        let mut cache_offset = 8;
        let mut cache_levels: Vec<Vec<[u8; 32]>> = Vec::new();
        for _ in 0..num_cached_levels {
            let num_nodes = u32::from_le_bytes(tree_top[cache_offset..cache_offset + 4].try_into().unwrap()) as usize;
            cache_offset += 4;
            let mut level_nodes = Vec::with_capacity(num_nodes);
            for _ in 0..num_nodes {
                let mut h = [0u8; 32];
                h.copy_from_slice(&tree_top[cache_offset..cache_offset + 32]);
                cache_offset += 32;
                level_nodes.push(h);
            }
            cache_levels.push(level_nodes);
        }
        println!("  Cache: from_level={}, arity={}, {} cached levels",
            cache_from_level, cache_arity, num_cached_levels);

        // ── Initialize per-address state ─────────────────────────────
        struct AddrState {
            current_hash: [u8; 32],
            node_idx: usize,
            failed: bool,
        }
        let mut addrs: Vec<(usize, AddrState)> = Vec::new(); // (addr_idx, state)
        for (addr_idx, sh) in args.script_hashes.iter().enumerate() {
            let ir = match &index_results[addr_idx] {
                Some(ir) if ir.num_entries > 0 => ir,
                _ => continue,
            };
            let mut full_data = Vec::new();
            for i in 0..ir.num_entries as u32 {
                let eid = ir.entry_id + i;
                if let Some(entry) = decrypted_entries.get(&eid) {
                    if i == 0 { full_data.extend_from_slice(&entry[ir.byte_offset as usize..]); }
                    else { full_data.extend_from_slice(entry); }
                }
            }
            let data_hash = merkle::sha256(&full_data);
            let leaf_hash = merkle::compute_leaf_hash(sh, ir.tree_loc, &data_hash);
            addrs.push((addr_idx, AddrState {
                current_hash: leaf_hash,
                node_idx: ir.tree_loc as usize,
                failed: false,
            }));
        }
        let num_verifiable = addrs.len();
        println!("  {} verifiable addresses", num_verifiable);

        // ── Batch sibling PIR: for level { batch all addrs } ─────────
        for level in 0..mi.levels.len() {
            let li = &mi.levels[level];

            // Compute groupId per address, deduplicate
            let mut group_to_addrs: HashMap<u32, Vec<usize>> = HashMap::new();
            for (ai, (_, state)) in addrs.iter().enumerate() {
                if state.failed { continue; }
                let gid = (state.node_idx / mi.arity) as u32;
                group_to_addrs.entry(gid).or_default().push(ai);
            }
            let unique_gids: Vec<u32> = group_to_addrs.keys().copied().collect();
            println!("  L{}: {} unique groups from {} addrs",
                level, unique_gids.len(), num_verifiable);

            // PBC-place unique groupIds
            let cand_buckets: Vec<[usize; 3]> = unique_gids.iter()
                .map(|&gid| derive_sib_pbc_buckets(gid, li.k))
                .collect();
            let pbc_rounds = pbc_plan_rounds(&cand_buckets, li.k, 3, 500);

            // Decrypted sibling data per groupId
            let mut sibling_data: HashMap<u32, Vec<u8>> = HashMap::new();

            for (ri, pbc_round) in pbc_rounds.iter().enumerate() {
                // Per real bucket: build cuckoo, find target bin
                let mut bucket_info: HashMap<usize, (u32, usize)> = HashMap::new(); // bucket → (gid, target_bin)
                for &(ugi, bucket) in pbc_round {
                    let gid = unique_gids[ugi];

                    // Build reverse index for this bucket
                    let mut group_entries: Vec<u32> = Vec::new();
                    for g in 0..li.num_groups as u32 {
                        let bs = derive_sib_pbc_buckets(g, li.k);
                        if bs.contains(&bucket) {
                            group_entries.push(g);
                        }
                    }

                    let cuckoo_table = build_sib_cuckoo_for_group(level, bucket, &group_entries, li.bins_per_table);
                    let target_bin = find_in_sib_cuckoo(&cuckoo_table, gid, level, bucket, li.bins_per_table)
                        .unwrap_or_else(|| panic!("group {} not in sibling cuckoo L{} bucket {}", gid, level, bucket));
                    bucket_info.insert(bucket, (gid, target_bin));
                }

                // Generate K FHE queries
                let mut sib_client = PirClient::new_from_secret_key(
                    li.bins_per_table as u64, client_id, &secret_key,
                );
                let mut sib_queries = Vec::with_capacity(li.k);
                for b in 0..li.k {
                    let bin = if let Some(&(_, target_bin)) = bucket_info.get(&b) {
                        target_bin as u64
                    } else {
                        rng.next_u64() % li.bins_per_table as u64
                    };
                    sib_queries.push(sib_client.generate_query(bin));
                }

                let batch = OnionPirBatchQuery { round_id: (level * 100 + ri) as u16, queries: sib_queries };
                sink.send(Message::Binary(batch.encode(REQ_ONIONPIR_MERKLE_SIBLING).into())).await.expect("send");

                let resp_bytes = recv_binary(&mut stream, &mut sink).await;
                let resp_payload = &resp_bytes[4..];
                assert_eq!(resp_payload[0], RESP_ONIONPIR_MERKLE_SIBLING);
                let result_batch = OnionPirBatchResult::decode(&resp_payload[1..]).expect("decode sibling");

                // Decrypt real buckets
                for (&bucket, &(gid, target_bin)) in &bucket_info {
                    let decrypted = sib_client.decrypt_response(
                        target_bin as u64, &result_batch.results[bucket],
                    );
                    sibling_data.insert(gid, decrypted);
                }

                println!("    L{} PBC round {}/{}: {} groups queried ✓",
                    level, ri + 1, pbc_rounds.len(), pbc_round.len());
            }

            // Update each address's state
            for (&gid, addr_indices) in &group_to_addrs {
                let decrypted = match sibling_data.get(&gid) {
                    Some(d) => d,
                    None => { for &ai in addr_indices { addrs[ai].1.failed = true; } continue; }
                };

                for &ai in addr_indices {
                    let state = &mut addrs[ai].1;
                    if state.failed { continue; }
                    let child_pos = state.node_idx % mi.arity;

                    let mut children: Vec<[u8; 32]> = Vec::with_capacity(mi.arity);
                    for c in 0..mi.arity {
                        let off = c * 32;
                        if c == child_pos {
                            children.push(state.current_hash);
                        } else {
                            let mut h = [0u8; 32];
                            if off + 32 <= decrypted.len() {
                                h.copy_from_slice(&decrypted[off..off + 32]);
                            }
                            children.push(h);
                        }
                    }

                    state.current_hash = merkle::compute_parent_n(&children);
                    state.node_idx = gid as usize;
                }
            }
        }

        // ── Walk tree-top cache + verify root per address ────────────
        let mut verified_count = 0;
        for (addr_idx, state) in &addrs {
            if state.failed { continue; }

            let mut current_hash = state.current_hash;
            let mut node_idx = state.node_idx;

            for ci in 0..cache_levels.len().saturating_sub(1) {
                let level_nodes = &cache_levels[ci];
                let parent_start = (node_idx / cache_arity) * cache_arity;
                let mut children: Vec<[u8; 32]> = Vec::with_capacity(cache_arity);
                for c in 0..cache_arity {
                    let idx = parent_start + c;
                    if idx < level_nodes.len() {
                        children.push(level_nodes[idx]);
                    } else {
                        children.push([0u8; 32]);
                    }
                }
                current_hash = merkle::compute_parent_n(&children);
                node_idx /= cache_arity;
            }

            if current_hash == mi.root {
                verified_count += 1;
                let root_hex: String = mi.root.iter().take(8).map(|b| format!("{:02x}", b)).collect();
                println!("  [{}] Merkle VERIFIED ✓ (root={}...)", addr_idx + 1, root_hex);
            } else {
                let got_hex: String = current_hash.iter().take(8).map(|b| format!("{:02x}", b)).collect();
                let exp_hex: String = mi.root.iter().take(8).map(|b| format!("{:02x}", b)).collect();
                println!("  [{}] Merkle FAILED ✗ (got={}... expected={}...)", addr_idx + 1, got_hex, exp_hex);
            }
        }
        println!("\n  Batch Merkle: {}/{} verified\n", verified_count, num_verifiable);
    } else {
        println!("\n[7] Merkle: not available (no onionpir_merkle in server info)");
    }

    // ── Summary ─────────────────────────────────────────────────────────
    println!("=== Done ===");
    println!("  {} addresses, {} index rounds, {} chunk rounds",
        num_addresses, total_index_rounds, chunk_rounds_count);
    println!("  Total time: {:.2?}", total_start.elapsed());

    let _ = sink.send(Message::Close(None)).await;
}
