//! OnionPIR per-bin Merkle verification.
//!
//! This is a *different* Merkle subsystem from the per-bucket Merkle that
//! powers DPF / Harmony verification in [`crate::merkle_verify`]:
//!
//! | Aspect                  | per-bucket Merkle (DPF/Harmony) | OnionPIR Merkle (this module) |
//! |-------------------------|---------------------------------|-------------------------------|
//! | Tree(s)                 | one per PBC bucket, super-root  | two flat trees: INDEX + DATA  |
//! | Leaf hash               | `SHA256(bin_idx_u32_LE ∥ bin)`  | `SHA256(decrypted_bin_bytes)` |
//! | Sibling cuckoo hashes   | K=1 DPF key per group           | 6-hash cuckoo, 1 slot per bin |
//! | Sibling query           | DPF (`0x33`) / Harmony (`0x43`) | FHE (`0x53` INDEX / `0x55` DATA) |
//! | Tree-top request        | `0x34`                          | `0x54` INDEX / `0x56` DATA    |
//!
//! The protocol mirrors the reference implementations in
//! `runtime/src/bin/onionpir_client.rs` and
//! `web/src/onionpir_client.ts` (`verifyMerkleBatch`).
//!
//! # Privacy invariants preserved
//!
//! * **K padding** — every sibling PBC round sends exactly `K` FHE queries
//!   (one per PBC group), with random-bin dummies filling empty groups.
//! * **INDEX leaf symmetry** — the caller is expected to submit
//!   `INDEX_CUCKOO_NUM_HASHES = 2` INDEX leaves per query (both probed cuckoo
//!   positions), regardless of match outcome. This matches CLAUDE.md's
//!   "Merkle INDEX item-count symmetry" requirement.
//!
//! The module is only compiled under the `onion` feature flag because it
//! creates per-level FHE clients (`onionpir::Client`) for sibling decryption.

#![cfg(feature = "onion")]

use crate::transport::PirTransport;
use pir_core::hash::{cuckoo_hash_int, derive_cuckoo_key, derive_int_groups_3, splitmix64, GOLDEN_RATIO};
use pir_core::merkle::{compute_parent_n, sha256, Hash256};
use pir_core::pbc::pbc_plan_rounds;
use pir_sdk::{PirError, PirResult};
use std::collections::HashMap;

// ─── Wire codes (match runtime/src/onionpir.rs) ─────────────────────────────

/// Request: fetch INDEX tree-top cache.
pub const REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP: u8 = 0x54;
/// Response: INDEX tree-top cache blob.
pub const RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP: u8 = 0x54;
/// Request: batched encrypted INDEX-tree sibling queries.
pub const REQ_ONIONPIR_MERKLE_INDEX_SIBLING: u8 = 0x53;
/// Response: batched encrypted INDEX-tree sibling results.
pub const RESP_ONIONPIR_MERKLE_INDEX_SIBLING: u8 = 0x53;
/// Request: fetch DATA tree-top cache.
pub const REQ_ONIONPIR_MERKLE_DATA_TREE_TOP: u8 = 0x56;
/// Response: DATA tree-top cache blob.
pub const RESP_ONIONPIR_MERKLE_DATA_TREE_TOP: u8 = 0x56;
/// Request: batched encrypted DATA-tree sibling queries.
pub const REQ_ONIONPIR_MERKLE_DATA_SIBLING: u8 = 0x55;
/// Response: batched encrypted DATA-tree sibling results.
pub const RESP_ONIONPIR_MERKLE_DATA_SIBLING: u8 = 0x55;

// ─── Layout constants ───────────────────────────────────────────────────────

/// Sibling cuckoo: 6 hash functions, 1 slot per bin (matches server layout).
pub const ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES: usize = 6;

const SIB_CUCKOO_MAX_KICKS: usize = 10000;
const EMPTY: u32 = u32::MAX;
const NUM_PBC_HASHES: usize = 3;

/// Master seed base for INDEX-tree sibling cuckoo derivation.
/// The per-level master seed is `INDEX_SIBLING_SEED_BASE + level`.
pub const INDEX_SIBLING_SEED_BASE: u64 = 0xBA7C_51B1_FEED_0100;
/// Master seed base for DATA-tree sibling cuckoo derivation.
/// The per-level master seed is `DATA_SIBLING_SEED_BASE + level`.
pub const DATA_SIBLING_SEED_BASE: u64 = 0xBA7C_51B1_FEED_0200;

// ─── Send wrapper for onionpir::Client ─────────────────────────────────────
//
// `onionpir::Client` wraps an opaque C++ pointer via FFI and is `!Send` by
// default. The sibling-fetch loop instantiates one locally and must hold it
// across an `await` on `conn.roundtrip(...)`, which requires the whole
// future to be `Send`.
//
// Note that — unlike `SendClient` in `onion.rs` — this newtype intentionally
// does *not* implement `Sync`. `SibSendClient` is a purely single-task value
// (constructed, used through a few `&mut` calls, then dropped, all inside
// the same async fn), so only `Send` is needed. See the extended safety
// audit on `SendClient` in `onion.rs` for the argument that holds equally
// well here: `onionpir::Client` owns a unique C++ object via an opaque
// handle, all mutating FFI entry points take `&mut self`, and there is no
// internal sharing.
struct SibSendClient(onionpir::Client);
// Safety: no shared state; all mutation gated behind `&mut self`.
// See `pir-sdk-client/src/onion.rs` for the full audit.
unsafe impl Send for SibSendClient {}

// Compile-time assertion: `SibSendClient` must remain `Send` so the
// sibling-fetch future stays `Send`. If someone adds a `!Send` field without
// wrapping it, this breaks at the declaration instead of at the future-type
// inference site inside the fetch loop (which produces truly cryptic errors).
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<SibSendClient>();
};

// ─── Types ──────────────────────────────────────────────────────────────────

/// Which of the two OnionPIR Merkle trees a leaf belongs to.
///
/// `Hash` is required so `(OnionTreeKind, leaf_pos)` can be a `HashMap` key
/// in the verdict map returned by `verify_onion_merkle_batch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OnionTreeKind {
    Index,
    Data,
}

impl OnionTreeKind {
    fn seed_base(self) -> u64 {
        match self {
            OnionTreeKind::Index => INDEX_SIBLING_SEED_BASE,
            OnionTreeKind::Data => DATA_SIBLING_SEED_BASE,
        }
    }

    fn req_tree_top(self) -> u8 {
        match self {
            OnionTreeKind::Index => REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP,
            OnionTreeKind::Data => REQ_ONIONPIR_MERKLE_DATA_TREE_TOP,
        }
    }

    fn resp_tree_top(self) -> u8 {
        match self {
            OnionTreeKind::Index => RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP,
            OnionTreeKind::Data => RESP_ONIONPIR_MERKLE_DATA_TREE_TOP,
        }
    }

    fn req_sibling(self) -> u8 {
        match self {
            OnionTreeKind::Index => REQ_ONIONPIR_MERKLE_INDEX_SIBLING,
            OnionTreeKind::Data => REQ_ONIONPIR_MERKLE_DATA_SIBLING,
        }
    }

    fn resp_sibling(self) -> u8 {
        match self {
            OnionTreeKind::Index => RESP_ONIONPIR_MERKLE_INDEX_SIBLING,
            OnionTreeKind::Data => RESP_ONIONPIR_MERKLE_DATA_SIBLING,
        }
    }

    fn name(self) -> &'static str {
        match self {
            OnionTreeKind::Index => "index",
            OnionTreeKind::Data => "data",
        }
    }
}

/// Parameters for one sibling level of an OnionPIR Merkle sub-tree.
#[derive(Clone, Debug)]
pub struct OnionMerkleLevelInfo {
    pub k: usize,
    pub bins_per_table: usize,
    pub num_groups: usize,
}

/// One of the two OnionPIR per-bin Merkle trees.
#[derive(Clone, Debug)]
pub struct OnionMerkleSubTree {
    /// Per-level sibling-cuckoo layout (level 0 = closest to the leaves).
    pub levels: Vec<OnionMerkleLevelInfo>,
    /// Expected root hash (`Hash256`) to compare the walk against.
    pub root: Hash256,
}

/// Container for both OnionPIR Merkle sub-trees (INDEX + DATA).
#[derive(Clone, Debug)]
pub struct OnionMerkleInfo {
    /// Merkle arity (number of children per internal node) — same for both sub-trees.
    pub arity: usize,
    pub index_tree: OnionMerkleSubTree,
    pub data_tree: OnionMerkleSubTree,
}

/// One leaf to be verified.
#[derive(Clone, Debug)]
pub struct OnionMerkleLeaf {
    /// Which tree this leaf lives in.
    pub tree: OnionTreeKind,
    /// `leaf_pos` in the leaf level — for INDEX, `pbc_group * bins_per_table + bin`;
    /// for DATA, `chunk_pbc_group * chunk_bins + chunk_bin`.
    pub leaf_pos: usize,
    /// `SHA256(decrypted_bin_bytes)` — the leaf hash the server committed to.
    pub hash: Hash256,
    /// Back-reference to the query this leaf belongs to, so callers can
    /// aggregate per-query verification verdicts.
    pub result_idx: usize,
}

/// Parsed tree-top cache (for one sub-tree).
#[derive(Clone, Debug)]
pub struct OnionTreeTopCache {
    /// Sibling-level depth below the first cached level.
    pub cache_from_level: usize,
    /// Merkle arity (number of children per internal node).
    pub arity: usize,
    /// Cached hashes, bottom-up. Last level is `[root]` (length 1).
    pub levels: Vec<Vec<Hash256>>,
}

// ─── JSON parsing (mirrors runtime/src/bin/onionpir_client.rs) ───────────────

/// Parse the `onionpir_merkle` section from the server's JSON info.
///
/// Returns `None` if the server doesn't expose OnionPIR per-bin Merkle for
/// this DB.
pub fn parse_onionpir_merkle(json: &str) -> Option<OnionMerkleInfo> {
    let section = extract_json_object(json, "onionpir_merkle")?;
    let arity = json_u64(section, "arity")? as usize;

    let index_section = extract_json_object(section, "index")?;
    let data_section = extract_json_object(section, "data")?;

    Some(OnionMerkleInfo {
        arity,
        index_tree: parse_sub_tree(index_section)?,
        data_tree: parse_sub_tree(data_section)?,
    })
}

fn parse_sub_tree(section: &str) -> Option<OnionMerkleSubTree> {
    let num_levels = json_u64(section, "sibling_levels")? as usize;

    // Root as a hex string. Tolerate whitespace between the colon and the
    // opening quote so JSON pretty-printed by serde / hand-written test data
    // both parse — same convention as `json_u64`.
    let root_needle = "\"root\":";
    let root_key_pos = section.find(root_needle)?;
    let after_colon = section[root_key_pos + root_needle.len()..].trim_start();
    let after_quote = after_colon.strip_prefix('"')?;
    let inner_end = after_quote.find('"')?;
    let root_hex = &after_quote[..inner_end];
    if root_hex.len() != 64 {
        return None;
    }
    let mut root = [0u8; 32];
    for i in 0..32 {
        root[i] = u8::from_str_radix(&root_hex[i * 2..i * 2 + 2], 16).ok()?;
    }

    let mut levels = Vec::with_capacity(num_levels);
    // Tolerate whitespace between `"levels":` and `[` for the same reason as
    // `"root":`.
    let levels_needle = "\"levels\":";
    if let Some(levels_pos) = section.find(levels_needle) {
        let after_colon = section[levels_pos + levels_needle.len()..].trim_start();
        let levels_section = after_colon.strip_prefix('[').unwrap_or(after_colon);
        let mut pos = 0usize;
        for _ in 0..num_levels {
            let obj_start = match levels_section[pos..].find('{') {
                Some(p) => p + pos,
                None => break,
            };
            let obj_end = match levels_section[obj_start..].find('}') {
                Some(p) => obj_start + p + 1,
                None => break,
            };
            let obj = &levels_section[obj_start..obj_end];
            levels.push(OnionMerkleLevelInfo {
                k: json_u64(obj, "k")? as usize,
                bins_per_table: json_u64(obj, "bins_per_table")? as usize,
                num_groups: json_u64(obj, "num_groups")? as usize,
            });
            pos = obj_end;
        }
    }

    Some(OnionMerkleSubTree { levels, root })
}

fn json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)?;
    let start = pos + needle.len();
    let rest = json[start..].trim_start();
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        let hex = &rest[..end];
        u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    }
}

fn extract_json_object<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)?;
    let brace = json[start..].find('{')? + start;
    let mut depth = 0i32;
    let mut end = brace;
    for (i, c) in json[brace..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = brace + i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    Some(&json[brace..end])
}

// ─── Tree-top cache parsing ─────────────────────────────────────────────────

/// Parse an OnionPIR tree-top cache blob.
///
/// Wire format (single tree, unlike the multi-tree per-bucket blob):
///
/// ```text
/// [1B cache_from_level]
/// [4B total_nodes LE]       (informational, ignored)
/// [2B arity LE]
/// [1B num_cached_levels]
/// per cached level:
///   [4B num_nodes LE]
///   [num_nodes × 32B hashes]
/// ```
pub fn parse_onion_tree_top_cache(data: &[u8]) -> PirResult<OnionTreeTopCache> {
    if data.len() < 8 {
        return Err(PirError::Decode(
            "onionpir tree-top cache blob too short".into(),
        ));
    }
    let cache_from_level = data[0] as usize;
    let arity = u16::from_le_bytes(data[5..7].try_into().unwrap()) as usize;
    let num_levels = data[7] as usize;
    if arity == 0 {
        return Err(PirError::Decode("onionpir tree-top cache: arity=0".into()));
    }

    let mut off = 8usize;
    let mut levels = Vec::with_capacity(num_levels);
    for l in 0..num_levels {
        if off + 4 > data.len() {
            return Err(PirError::Decode(format!(
                "onionpir tree-top cache: truncated header for level {}",
                l
            )));
        }
        let n = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if off + n * 32 > data.len() {
            return Err(PirError::Decode(format!(
                "onionpir tree-top cache: truncated hashes for level {}",
                l
            )));
        }
        let mut nodes = Vec::with_capacity(n);
        for _ in 0..n {
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[off..off + 32]);
            nodes.push(h);
            off += 32;
        }
        levels.push(nodes);
    }
    Ok(OnionTreeTopCache {
        cache_from_level,
        arity,
        levels,
    })
}

// ─── Wire encoders ──────────────────────────────────────────────────────────

/// Encode a tree-top-cache request. Wire: `[4B len][1B variant]([1B db_id] if non-zero)`.
pub fn encode_tree_top_request(variant: u8, db_id: u8) -> Vec<u8> {
    let payload_len: usize = if db_id != 0 { 2 } else { 1 };
    let mut buf = Vec::with_capacity(4 + payload_len);
    buf.extend_from_slice(&(payload_len as u32).to_le_bytes());
    buf.push(variant);
    if db_id != 0 {
        buf.push(db_id);
    }
    buf
}

/// Encode an FHE sibling batch query.
/// Same wire format as `REQ_ONIONPIR_INDEX_QUERY` / `REQ_ONIONPIR_CHUNK_QUERY`.
pub fn encode_sibling_batch_query(
    variant: u8,
    round_id: u16,
    queries: &[Vec<u8>],
    db_id: u8,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(variant);
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.push(queries.len() as u8);
    for q in queries {
        payload.extend_from_slice(&(q.len() as u32).to_le_bytes());
        payload.extend_from_slice(q);
    }
    if db_id != 0 {
        payload.push(db_id);
    }
    let mut msg = Vec::with_capacity(4 + payload.len());
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(&payload);
    msg
}

/// Decode an FHE batch response payload (after the length prefix and variant byte).
///
/// Wire: `[2B round_id][1B num_groups]({ [4B len][bytes] })*`.
pub fn decode_sibling_batch_result(data: &[u8]) -> PirResult<Vec<Vec<u8>>> {
    if data.len() < 3 {
        return Err(PirError::Decode("sibling result batch too short".into()));
    }
    let mut pos = 2; // skip round_id
    let num_groups = data[pos] as usize;
    pos += 1;
    let mut results = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        if pos + 4 > data.len() {
            return Err(PirError::Decode("truncated sibling result len".into()));
        }
        let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + len > data.len() {
            return Err(PirError::Decode("truncated sibling result bytes".into()));
        }
        results.push(data[pos..pos + len].to_vec());
        pos += len;
    }
    Ok(results)
}

// ─── Sibling-cuckoo helpers (6-hash, slots_per_bin=1) ────────────────────────

/// Level master seed for a `(tree, level)` pair.
#[inline]
pub fn sib_level_master_seed(tree: OnionTreeKind, level: usize) -> u64 {
    tree.seed_base().wrapping_add(level as u64)
}

/// 6-hash sibling-cuckoo bin placement (matches runtime/server).
#[inline]
pub fn sib_derive_cuckoo_key(master_seed: u64, group_id: usize, hash_fn: usize) -> u64 {
    // Matches `pir_core::hash::derive_cuckoo_key` for consistency.
    derive_cuckoo_key(master_seed, group_id, hash_fn)
}

#[inline]
pub fn sib_cuckoo_hash(entry_id: u32, key: u64, num_bins: usize) -> usize {
    cuckoo_hash_int(entry_id, key, num_bins)
}

/// Build the sibling cuckoo table for a single PBC group at a given level.
///
/// Returns a `vec![EMPTY; bins_per_table]`, with `entries` slotted via the
/// 6-hash cuckoo. Mirrors the server's construction exactly so bin placements
/// agree.
pub fn build_sib_cuckoo_for_group(
    tree: OnionTreeKind,
    level: usize,
    group_id: usize,
    entries: &[u32],
    bins_per_table: usize,
) -> Vec<u32> {
    let master_seed = sib_level_master_seed(tree, level);
    let mut keys = [0u64; ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES];
    for (h, k) in keys.iter_mut().enumerate() {
        *k = sib_derive_cuckoo_key(master_seed, group_id, h);
    }

    let mut table = vec![EMPTY; bins_per_table];
    for &entry_id in entries {
        // Try primary placements.
        let mut placed = false;
        for &key in keys.iter() {
            let bin = sib_cuckoo_hash(entry_id, key, bins_per_table);
            if table[bin] == EMPTY {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if placed {
            continue;
        }

        // Kick loop — matches runtime/src/bin/onionpir_client.rs exactly.
        let mut current_id = entry_id;
        let mut current_hash_fn = 0usize;
        let mut current_bin = sib_cuckoo_hash(entry_id, keys[0], bins_per_table);
        let mut success = false;
        for kick in 0..SIB_CUCKOO_MAX_KICKS {
            let evicted = table[current_bin];
            table[current_bin] = current_id;
            for h in 0..ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES {
                let try_h = (current_hash_fn + 1 + h) % ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES;
                let bin = sib_cuckoo_hash(evicted, keys[try_h], bins_per_table);
                if bin == current_bin {
                    continue;
                }
                if table[bin] == EMPTY {
                    table[bin] = evicted;
                    success = true;
                    break;
                }
            }
            if success {
                break;
            }
            let alt_h = (current_hash_fn + 1 + kick % (ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES - 1))
                % ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES;
            let alt_bin = sib_cuckoo_hash(evicted, keys[alt_h], bins_per_table);
            let final_bin = if alt_bin == current_bin {
                sib_cuckoo_hash(
                    evicted,
                    keys[(alt_h + 1) % ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES],
                    bins_per_table,
                )
            } else {
                alt_bin
            };
            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }
        if !success {
            // Don't panic — caller handles as a verification failure.
            log::error!(
                "OnionPIR sibling cuckoo failed for entry_id={} group={} level={}",
                entry_id,
                group_id,
                level
            );
        }
    }
    table
}

/// Find which bin in a sibling cuckoo table holds `entry_id`.
pub fn find_in_sib_cuckoo(
    table: &[u32],
    entry_id: u32,
    tree: OnionTreeKind,
    level: usize,
    group_id: usize,
    bins_per_table: usize,
) -> Option<usize> {
    let master_seed = sib_level_master_seed(tree, level);
    for h in 0..ONIONPIR_MERKLE_SIBLING_CUCKOO_NUM_HASHES {
        let key = sib_derive_cuckoo_key(master_seed, group_id, h);
        let bin = sib_cuckoo_hash(entry_id, key, bins_per_table);
        if table[bin] == entry_id {
            return Some(bin);
        }
    }
    None
}

/// Collect the full list of (Merkle) group-IDs at `level` that are assigned
/// to PBC sibling group `pbc_group` via the 3-way PBC hash.
fn entries_in_sib_pbc_group(
    pbc_group: usize,
    num_merkle_groups: usize,
    k: usize,
) -> Vec<u32> {
    let mut out = Vec::new();
    for g in 0..num_merkle_groups as u32 {
        let groups = derive_int_groups_3(g, k);
        if groups.contains(&pbc_group) {
            out.push(g);
        }
    }
    out
}

// ─── Tiny RNG for dummy-query bin selection ─────────────────────────────────

struct SibRng {
    state: u64,
}

impl SibRng {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xcafe_babe_dead_beef);
        Self {
            state: splitmix64(seed),
        }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(GOLDEN_RATIO);
        splitmix64(self.state)
    }
}

// ─── Verifier ───────────────────────────────────────────────────────────────

/// Per-leaf verification verdict: `(tree_kind, leaf_pos) → verified`.
///
/// `verified == true` means the leaf hash reconstructed to the sub-tree root.
pub type OnionMerkleVerdicts = HashMap<(OnionTreeKind, usize), bool>;

/// Verify all OnionPIR Merkle leaves across both INDEX and DATA sub-trees.
///
/// * `conn` — the same WebSocket used for the regular queries. The caller
///   must have already registered FHE keys for `db_id`.
/// * `info` — parsed `OnionMerkleInfo` for the current DB.
/// * `leaves` — one entry per probed leaf, pre-populated with
///   `(tree_kind, leaf_pos, hash, result_idx)`. Duplicates (same
///   `(tree_kind, leaf_pos)`) are deduplicated internally.
/// * `client_id`, `secret_key` — FHE state from the `OnionClient`'s
///   `FheState`. Each sibling PBC round creates fresh per-level clients
///   from these.
/// * `db_id` — DB under verification.
///
/// On decode / protocol error the function propagates; on individual leaf
/// verification failure the verdict map entry is `false` (not an error).
pub async fn verify_onion_merkle_batch(
    conn: &mut dyn PirTransport,
    info: &OnionMerkleInfo,
    leaves: &[OnionMerkleLeaf],
    client_id: u64,
    secret_key: &[u8],
    db_id: u8,
) -> PirResult<OnionMerkleVerdicts> {
    let mut verdicts: OnionMerkleVerdicts = HashMap::new();

    let index_leaves: Vec<&OnionMerkleLeaf> = leaves
        .iter()
        .filter(|l| l.tree == OnionTreeKind::Index)
        .collect();
    let data_leaves: Vec<&OnionMerkleLeaf> = leaves
        .iter()
        .filter(|l| l.tree == OnionTreeKind::Data)
        .collect();

    if !index_leaves.is_empty() {
        let per_leaf = verify_sub_tree(
            conn,
            OnionTreeKind::Index,
            &info.index_tree,
            info.arity,
            &index_leaves,
            client_id,
            secret_key,
            db_id,
        )
        .await?;
        for (lp, ok) in per_leaf {
            verdicts.insert((OnionTreeKind::Index, lp), ok);
        }
    }

    if !data_leaves.is_empty() {
        let per_leaf = verify_sub_tree(
            conn,
            OnionTreeKind::Data,
            &info.data_tree,
            info.arity,
            &data_leaves,
            client_id,
            secret_key,
            db_id,
        )
        .await?;
        for (lp, ok) in per_leaf {
            verdicts.insert((OnionTreeKind::Data, lp), ok);
        }
    }

    Ok(verdicts)
}

/// Verify a single sub-tree (INDEX or DATA). Returns `leaf_pos → verified`.
#[allow(clippy::too_many_arguments)]
async fn verify_sub_tree(
    conn: &mut dyn PirTransport,
    tree: OnionTreeKind,
    sub_tree: &OnionMerkleSubTree,
    arity: usize,
    leaves: &[&OnionMerkleLeaf],
    client_id: u64,
    secret_key: &[u8],
    db_id: u8,
) -> PirResult<HashMap<usize, bool>> {
    let mut out: HashMap<usize, bool> = HashMap::new();
    if leaves.is_empty() {
        return Ok(out);
    }

    // ── 1. Fetch tree-top cache ─────────────────────────────────────────
    let req = encode_tree_top_request(tree.req_tree_top(), db_id);
    let resp = conn.roundtrip(&req).await?;
    if resp.is_empty() || resp[0] != tree.resp_tree_top() {
        return Err(PirError::Protocol(format!(
            "expected {} tree-top response (0x{:02x}), got variant 0x{:02x}",
            tree.name(),
            tree.resp_tree_top(),
            resp.first().copied().unwrap_or(0),
        )));
    }
    let tree_top = parse_onion_tree_top_cache(&resp[1..])?;
    log::info!(
        "[PIR-AUDIT] OnionPIR Merkle {} tree-top: {} cached levels, arity={}",
        tree.name(),
        tree_top.levels.len(),
        tree_top.arity,
    );

    // ── 2. Deduplicate leaves by leaf_pos ───────────────────────────────
    let mut unique: HashMap<usize, Hash256> = HashMap::new();
    for l in leaves {
        unique.entry(l.leaf_pos).or_insert(l.hash);
    }
    let leaf_pos_arr: Vec<usize> = unique.keys().copied().collect();
    let n = leaf_pos_arr.len();
    let mut current_hash: Vec<Hash256> = leaf_pos_arr.iter().map(|lp| unique[lp]).collect();
    let mut node_idx: Vec<usize> = leaf_pos_arr.clone();
    let mut failed: Vec<bool> = vec![false; n];

    log::info!(
        "[PIR-AUDIT] OnionPIR Merkle {}: verifying {} unique leaves across {} sibling levels",
        tree.name(),
        n,
        sub_tree.levels.len(),
    );

    let mut rng = SibRng::new();

    // ── 3. Walk sibling levels with FHE queries ─────────────────────────
    for (level, level_info) in sub_tree.levels.iter().enumerate() {
        // Group leaves by the Merkle-group they need at this level.
        let mut group_to_items: HashMap<u32, Vec<usize>> = HashMap::new();
        for i in 0..n {
            if failed[i] {
                continue;
            }
            let gid = (node_idx[i] / arity) as u32;
            group_to_items.entry(gid).or_default().push(i);
        }
        let unique_gids: Vec<u32> = group_to_items.keys().copied().collect();
        if unique_gids.is_empty() {
            break;
        }

        // PBC-place unique gids into this level's sibling PBC groups.
        let cand_groups: Vec<[usize; NUM_PBC_HASHES]> = unique_gids
            .iter()
            .map(|&gid| derive_int_groups_3(gid, level_info.k))
            .collect();
        let pbc_rounds = pbc_plan_rounds(&cand_groups, level_info.k, NUM_PBC_HASHES, 500);
        let mut sibling_data: HashMap<u32, Vec<u8>> = HashMap::new();

        for (ri, pbc_round) in pbc_rounds.iter().enumerate() {
            // Build cuckoo for each PBC group so we know which bin each gid lives in.
            struct Assigned {
                gid: u32,
                target_bin: usize,
            }
            let mut group_info: HashMap<usize, Assigned> = HashMap::new();
            for &(ugi, pbc_group) in pbc_round {
                let gid = unique_gids[ugi];
                let entries = entries_in_sib_pbc_group(
                    pbc_group,
                    level_info.num_groups,
                    level_info.k,
                );
                let table = build_sib_cuckoo_for_group(
                    tree,
                    level,
                    pbc_group,
                    &entries,
                    level_info.bins_per_table,
                );
                match find_in_sib_cuckoo(
                    &table,
                    gid,
                    tree,
                    level,
                    pbc_group,
                    level_info.bins_per_table,
                ) {
                    Some(bin) => {
                        group_info.insert(pbc_group, Assigned { gid, target_bin: bin });
                    }
                    None => {
                        // Mark all items under this gid as failed.
                        if let Some(items) = group_to_items.get(&gid) {
                            for &i in items {
                                failed[i] = true;
                            }
                        }
                        log::warn!(
                            "[PIR-AUDIT] OnionPIR Merkle {} L{}: gid={} not in PBC group {} cuckoo table",
                            tree.name(),
                            level,
                            gid,
                            pbc_group,
                        );
                    }
                }
            }

            // Generate K FHE queries (real + random-bin dummies).
            //
            // Wrap the FFI client in `SibSendClient` so the enclosing future
            // stays `Send` across the roundtrip `.await` below — the raw
            // `onionpir::Client` holds a `*mut c_void` which is `!Send`.
            let mut sib_client = SibSendClient(onionpir::Client::new_from_secret_key(
                level_info.bins_per_table as u64,
                client_id,
                secret_key,
            ));
            let mut queries = Vec::with_capacity(level_info.k);
            for b in 0..level_info.k {
                let bin = if let Some(a) = group_info.get(&b) {
                    a.target_bin as u64
                } else {
                    rng.next_u64() % level_info.bins_per_table as u64
                };
                queries.push(sib_client.0.generate_query(bin));
            }

            let round_id = (level * 100 + ri) as u16;
            let msg = encode_sibling_batch_query(tree.req_sibling(), round_id, &queries, db_id);
            let resp = conn.roundtrip(&msg).await?;
            if resp.is_empty() || resp[0] != tree.resp_sibling() {
                return Err(PirError::Protocol(format!(
                    "expected {} sibling response (0x{:02x}), got variant 0x{:02x}",
                    tree.name(),
                    tree.resp_sibling(),
                    resp.first().copied().unwrap_or(0),
                )));
            }
            let batch = decode_sibling_batch_result(&resp[1..])?;

            for (&pbc_group, assigned) in &group_info {
                if pbc_group >= batch.len() {
                    log::warn!(
                        "[PIR-AUDIT] OnionPIR Merkle {} L{} round {}: result batch truncated at pbc_group={} (len={})",
                        tree.name(),
                        level,
                        ri,
                        pbc_group,
                        batch.len()
                    );
                    // Mark items failed.
                    if let Some(items) = group_to_items.get(&assigned.gid) {
                        for &i in items {
                            failed[i] = true;
                        }
                    }
                    continue;
                }
                let decrypted = sib_client
                    .0
                    .decrypt_response(assigned.target_bin as u64, &batch[pbc_group]);
                sibling_data.insert(assigned.gid, decrypted);
            }
        }

        // ── 4. Combine each leaf's current hash with siblings at this level ─
        for (&gid, items) in &group_to_items {
            let decrypted = match sibling_data.get(&gid) {
                Some(d) => d,
                None => {
                    for &i in items {
                        failed[i] = true;
                    }
                    continue;
                }
            };
            for &i in items {
                if failed[i] {
                    continue;
                }
                let child_pos = node_idx[i] % arity;
                let mut children: Vec<Hash256> = Vec::with_capacity(arity);
                for c in 0..arity {
                    if c == child_pos {
                        children.push(current_hash[i]);
                    } else {
                        let off = c * 32;
                        let mut h = [0u8; 32];
                        if off + 32 <= decrypted.len() {
                            h.copy_from_slice(&decrypted[off..off + 32]);
                        }
                        children.push(h);
                    }
                }
                current_hash[i] = compute_parent_n(&children);
                node_idx[i] = gid as usize;
            }
        }
    }

    // ── 5. Walk tree-top cache up to root ───────────────────────────────
    let cache_arity = tree_top.arity;
    let num_cache_levels = tree_top.levels.len();
    for i in 0..n {
        if failed[i] {
            out.insert(leaf_pos_arr[i], false);
            continue;
        }
        let mut hash = current_hash[i];
        let mut idx = node_idx[i];
        // All cached levels except the root (last level is `[root]`).
        for ci in 0..num_cache_levels.saturating_sub(1) {
            let level_nodes = &tree_top.levels[ci];
            let parent_start = (idx / cache_arity) * cache_arity;
            let mut children: Vec<Hash256> = Vec::with_capacity(cache_arity);
            for c in 0..cache_arity {
                let child_idx = parent_start + c;
                children.push(if child_idx < level_nodes.len() {
                    level_nodes[child_idx]
                } else {
                    [0u8; 32]
                });
            }
            hash = compute_parent_n(&children);
            idx /= cache_arity;
        }
        let ok = hash == sub_tree.root;
        out.insert(leaf_pos_arr[i], ok);
    }

    let verified = out.values().filter(|b| **b).count();
    log::info!(
        "[PIR-AUDIT] OnionPIR Merkle {}: {}/{} leaves verified",
        tree.name(),
        verified,
        n
    );

    Ok(out)
}

/// Convenience: hash a decrypted OnionPIR bin (`SHA256(bytes)`).
///
/// OnionPIR leaves are raw `SHA256` over the first `PACKED_ENTRY_SIZE` bytes
/// of the decrypted bin — no `bin_idx` prefix (that's the per-bucket
/// convention, not OnionPIR's).
#[inline]
pub fn onion_leaf_hash(bin_bytes: &[u8]) -> Hash256 {
    sha256(bin_bytes)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tree_top(arity: usize, leaves: &[Hash256]) -> (Vec<u8>, Hash256) {
        // Build a Merkle tree with given `arity` bottom-up, emit as a tree-top
        // with all levels cached and the final root appended.
        let mut levels: Vec<Vec<Hash256>> = Vec::new();
        levels.push(leaves.to_vec());
        loop {
            let prev = levels.last().unwrap();
            if prev.len() <= 1 {
                break;
            }
            let mut next = Vec::new();
            let mut i = 0;
            while i < prev.len() {
                let mut children = Vec::with_capacity(arity);
                for c in 0..arity {
                    children.push(if i + c < prev.len() {
                        prev[i + c]
                    } else {
                        [0u8; 32]
                    });
                }
                next.push(compute_parent_n(&children));
                i += arity;
            }
            levels.push(next);
        }

        let root = *levels.last().unwrap().first().unwrap();
        // Encode: [1B cache_from_level=0][4B total_nodes=sum][2B arity][1B num_levels]
        //         per level: [4B num_nodes][num_nodes*32B]
        let mut blob = Vec::new();
        blob.push(0u8); // cache_from_level
        let total: u32 = levels.iter().map(|l| l.len() as u32).sum();
        blob.extend_from_slice(&total.to_le_bytes());
        blob.extend_from_slice(&(arity as u16).to_le_bytes());
        blob.push(levels.len() as u8);
        for lvl in &levels {
            blob.extend_from_slice(&(lvl.len() as u32).to_le_bytes());
            for h in lvl {
                blob.extend_from_slice(h);
            }
        }
        (blob, root)
    }

    #[test]
    fn test_parse_onion_tree_top_cache_roundtrip() {
        let leaves = (0..5u8)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = i;
                h
            })
            .collect::<Vec<_>>();
        let (blob, root) = dummy_tree_top(8, &leaves);
        let parsed = parse_onion_tree_top_cache(&blob).unwrap();
        assert_eq!(parsed.arity, 8);
        assert_eq!(parsed.cache_from_level, 0);
        assert!(parsed.levels.len() >= 2);
        assert_eq!(parsed.levels.last().unwrap(), &vec![root]);
    }

    #[test]
    fn test_parse_onion_tree_top_cache_too_short() {
        assert!(parse_onion_tree_top_cache(&[]).is_err());
        assert!(parse_onion_tree_top_cache(&[0u8; 7]).is_err());
    }

    #[test]
    fn test_parse_onion_tree_top_cache_arity_zero() {
        // arity=0 is invalid and must be rejected (otherwise walks divide by zero).
        let mut blob = vec![0u8; 8];
        blob[0] = 0; // cache_from_level
        // arity=0 at offset 5..7
        blob[7] = 0; // num_cached_levels
        assert!(parse_onion_tree_top_cache(&blob).is_err());
    }

    #[test]
    fn test_parse_onionpir_merkle_basic() {
        let j = r#"{
            "onionpir_merkle": {
                "arity": 8,
                "index": {
                    "sibling_levels": 1,
                    "root": "0000000000000000000000000000000000000000000000000000000000000000",
                    "levels": [{"k":10,"bins_per_table":128,"num_groups":50}]
                },
                "data": {
                    "sibling_levels": 2,
                    "root": "1111111111111111111111111111111111111111111111111111111111111111",
                    "levels": [
                        {"k":20,"bins_per_table":256,"num_groups":100},
                        {"k":10,"bins_per_table":128,"num_groups":30}
                    ]
                }
            }
        }"#;
        let info = parse_onionpir_merkle(j).unwrap();
        assert_eq!(info.arity, 8);
        assert_eq!(info.index_tree.levels.len(), 1);
        assert_eq!(info.index_tree.levels[0].k, 10);
        assert_eq!(info.index_tree.levels[0].bins_per_table, 128);
        assert_eq!(info.index_tree.levels[0].num_groups, 50);
        assert_eq!(info.data_tree.levels.len(), 2);
        assert_eq!(info.data_tree.levels[1].k, 10);
        assert_eq!(info.index_tree.root, [0u8; 32]);
        assert_eq!(info.data_tree.root, [0x11u8; 32]);
    }

    #[test]
    fn test_parse_onionpir_merkle_missing() {
        assert!(parse_onionpir_merkle(r#"{"foo":1}"#).is_none());
    }

    #[test]
    fn test_sib_cuckoo_roundtrip_index() {
        // Insert 10 entry_ids into the INDEX tree's sibling cuckoo at level 0,
        // then find each back.
        let bins_per_table = 128usize;
        let group_id = 3usize;
        let entries: Vec<u32> = (100..110).collect();
        let table = build_sib_cuckoo_for_group(
            OnionTreeKind::Index,
            0,
            group_id,
            &entries,
            bins_per_table,
        );
        for &e in &entries {
            let bin = find_in_sib_cuckoo(
                &table,
                e,
                OnionTreeKind::Index,
                0,
                group_id,
                bins_per_table,
            );
            assert!(bin.is_some(), "entry_id {} not findable", e);
        }
    }

    #[test]
    fn test_sib_cuckoo_roundtrip_data() {
        // Same as above but DATA tree — different seed base.
        let bins_per_table = 64usize;
        let group_id = 7usize;
        let entries: Vec<u32> = (0..12).collect();
        let table = build_sib_cuckoo_for_group(
            OnionTreeKind::Data,
            2,
            group_id,
            &entries,
            bins_per_table,
        );
        for &e in &entries {
            assert!(
                find_in_sib_cuckoo(
                    &table,
                    e,
                    OnionTreeKind::Data,
                    2,
                    group_id,
                    bins_per_table
                )
                .is_some(),
                "entry_id {} not findable",
                e
            );
        }
    }

    #[test]
    fn test_seed_bases_differ_per_tree_and_level() {
        // INDEX and DATA trees must derive different keys, and each tree's levels
        // must derive different keys. (If not, an INDEX level proof could be
        // mis-replayed against a DATA level.)
        let index_l0 = sib_level_master_seed(OnionTreeKind::Index, 0);
        let index_l1 = sib_level_master_seed(OnionTreeKind::Index, 1);
        let data_l0 = sib_level_master_seed(OnionTreeKind::Data, 0);
        let data_l1 = sib_level_master_seed(OnionTreeKind::Data, 1);
        assert_ne!(index_l0, index_l1);
        assert_ne!(data_l0, data_l1);
        assert_ne!(index_l0, data_l0);
        assert_ne!(index_l1, data_l1);
    }

    #[test]
    fn test_entries_in_sib_pbc_group_covers_all() {
        // Every gid should land in NUM_PBC_HASHES=3 PBC groups. Union of all
        // groups should cover all gids exactly 3 times.
        let k = 10usize;
        let num_gids = 50usize;
        let mut counts = vec![0usize; num_gids];
        for g in 0..k {
            for &gid in &entries_in_sib_pbc_group(g, num_gids, k) {
                counts[gid as usize] += 1;
            }
        }
        for c in counts {
            assert_eq!(c, NUM_PBC_HASHES);
        }
    }

    #[test]
    fn test_wire_code_pairing() {
        // Request/response are the same variant byte per feature (server convention).
        assert_eq!(REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP, RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP);
        assert_eq!(REQ_ONIONPIR_MERKLE_INDEX_SIBLING, RESP_ONIONPIR_MERKLE_INDEX_SIBLING);
        assert_eq!(REQ_ONIONPIR_MERKLE_DATA_TREE_TOP, RESP_ONIONPIR_MERKLE_DATA_TREE_TOP);
        assert_eq!(REQ_ONIONPIR_MERKLE_DATA_SIBLING, RESP_ONIONPIR_MERKLE_DATA_SIBLING);
        assert_eq!(REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP, 0x54);
        assert_eq!(REQ_ONIONPIR_MERKLE_INDEX_SIBLING, 0x53);
        assert_eq!(REQ_ONIONPIR_MERKLE_DATA_TREE_TOP, 0x56);
        assert_eq!(REQ_ONIONPIR_MERKLE_DATA_SIBLING, 0x55);
    }

    #[test]
    fn test_encode_tree_top_request_no_db_id() {
        let buf = encode_tree_top_request(REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP, 0);
        assert_eq!(buf, vec![1, 0, 0, 0, 0x54]);
    }

    #[test]
    fn test_encode_tree_top_request_with_db_id() {
        let buf = encode_tree_top_request(REQ_ONIONPIR_MERKLE_DATA_TREE_TOP, 7);
        assert_eq!(buf, vec![2, 0, 0, 0, 0x56, 7]);
    }

    #[test]
    fn test_sibling_batch_roundtrip() {
        let qs = vec![vec![0x11, 0x22], vec![0x33]];
        let buf = encode_sibling_batch_query(REQ_ONIONPIR_MERKLE_INDEX_SIBLING, 0, &qs, 0);
        // buf[0..4] = length, buf[4] = variant; skip length prefix + variant.
        let decoded = decode_sibling_batch_result(&buf[5..]).unwrap();
        assert_eq!(decoded, qs);
    }

    #[test]
    fn test_onion_leaf_hash_matches_sha256() {
        let bytes = b"hello world";
        assert_eq!(onion_leaf_hash(bytes), sha256(bytes));
    }
}
