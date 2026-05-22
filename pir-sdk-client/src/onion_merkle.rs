//! OnionPIR per-group Merkle verification.
//!
//! This is a *different* Merkle subsystem from the per-bucket Merkle that
//! powers DPF / Harmony verification in [`crate::merkle_verify`], but since
//! the Phase-3 per-group redesign (PLAN_MERKLE_CODING.md /
//! MERKLE_COLOCATION_REVIEW.md §2–§6) the two are *structurally identical* —
//! one independent Merkle tree per PBC group, anchored by a single
//! `super_root`. They differ only in the sibling-fetch primitive:
//!
//! | Aspect                  | per-bucket Merkle (DPF/Harmony)   | OnionPIR Merkle (this module)      |
//! |-------------------------|-----------------------------------|------------------------------------|
//! | Tree(s)                 | one per PBC group, super-root     | one per PBC group, super-root      |
//! | Leaf hash               | `SHA256(bin_idx_u32_LE ∥ bin)`    | `SHA256(decrypted_bin_bytes)` (§2e)|
//! | Sibling levels          | DPF/Harmony, possibly multi-level | FHE, **one** level (leaf→level-1)  |
//! | Sibling query           | DPF (`0x33`) / Harmony (`0x43`)   | FHE (`0x53` INDEX / `0x55` DATA)   |
//! | Tree-top request        | `0x34`                            | `0x54` INDEX / `0x56` DATA         |
//!
//! Each PBC group `g` has its own arity-`arity` (`≈ entry_size/32`) tree over
//! that group's cuckoo bins. The leaf level is the single PIR sibling level;
//! every level above it is held in the public per-group tree-top cache. A
//! sibling pass = **one FHE-PIR query per group** into that group's tiny
//! sibling DB (whose plaintexts are the level-1 parent rows). The verifier
//! then walks the cached tree-top to the per-group root.
//!
//! The flat per-table trees — and the `gid`-cuckoo + `pbc_plan_rounds`-over-
//! gids machinery their sibling fetch needed (the batch-size leak,
//! MERKLE_COLOCATION_REVIEW.md §1) — are **gone**.
//!
//! # Trust model
//!
//! The pinned trust anchor is `super_root` = `SHA256` of the 155 concatenated
//! per-group roots (§2f). The 155 roots themselves ride in the *untrusted*,
//! server-supplied tree-top blob. [`check_tree_top_anchor`] binds that blob
//! to `super_root` — **this is the soundness-critical check**. Skip or weaken
//! it and a malicious server can fabricate a self-consistent blob + sibling
//! responses, and every leaf "verifies" against forged roots.
//!
//! # Privacy invariants preserved
//!
//! * **K padding** — every sibling pass sends exactly `K` (INDEX) /
//!   `K_CHUNK` (DATA) FHE queries, one per PBC group; empty groups send a
//!   random-row dummy, indistinguishable under FHE.
//! * **CHUNK-Merkle round-presence** — [`verify_onion_merkle_batch`] always
//!   verifies *both* sub-trees. A not-found / whale batch contributes 0 DATA
//!   leaves, but `verify_sub_tree` still issues one all-dummy K_CHUNK sibling
//!   pass, so found-vs-not-found cannot be inferred from CHUNK-Merkle traffic
//!   (CLAUDE.md "CHUNK Round-Presence Symmetry"; PLAN_MERKLE_CODING.md C.1).
//! * **INDEX leaf symmetry** — the caller submits `INDEX_CUCKOO_NUM_HASHES = 2`
//!   INDEX leaves per query (both probed cuckoo positions), regardless of
//!   outcome (CLAUDE.md "Merkle INDEX item-count symmetry").
//!
//! The module is only compiled under the `onion` feature flag because it
//! creates an FHE client (`onionpir::Client`) for sibling decryption.

#![cfg(feature = "onion")]

use crate::merkle_verify::SimpleRng;
use crate::transport::PirTransport;
use pir_core::merkle::{compute_parent_n, sha256, Hash256, ZERO_HASH};
use pir_sdk::{LeakageRecorder, PirError, PirResult, RoundKind, RoundProfile};
use std::collections::HashMap;
use std::sync::Arc;

// ─── Wire codes (match runtime/src/onionpir.rs — UNCHANGED by Phase 3) ──────

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

/// Which of the two OnionPIR Merkle tree kinds a leaf belongs to.
///
/// `Hash` is required so `(OnionTreeKind, pbc_group, bin)` can be a `HashMap`
/// key in the verdict map returned by [`verify_onion_merkle_batch`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OnionTreeKind {
    Index,
    Data,
}

impl OnionTreeKind {
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

/// Per-kind sibling-DB parameters (one for INDEX, one for DATA).
#[derive(Clone, Copy, Debug)]
pub struct OnionMerkleKindInfo {
    /// Number of PBC groups = number of per-group trees = number of FHE
    /// queries in one sibling pass.
    pub k: usize,
    /// Plaintexts in each per-group sibling DB (= the level-1 parent-row
    /// count of the per-group tree). The sibling FHE `Client` is sized to
    /// this; `generate_query`'s row index is in `[0, num_pt)`.
    pub num_pt: usize,
}

/// Per-group OnionPIR Merkle metadata for one DB, parsed from the server's
/// `onionpir_merkle` JSON section.
#[derive(Clone, Debug)]
pub struct OnionMerkleInfo {
    /// Merkle arity (children per internal node) — `≈ entry_size / 32`,
    /// same for every per-group tree.
    pub arity: usize,
    /// **The pinned trust anchor** — `SHA256` of the 155 concatenated
    /// per-group roots (MERKLE_COLOCATION_REVIEW.md §2f). The 155 roots
    /// themselves ride in the (untrusted) tree-top blob; binding the blob
    /// to this value is the soundness-critical check (see
    /// [`check_tree_top_anchor`]).
    pub super_root: Hash256,
    /// `SHA256` of the whole `merkle_onion_tree_tops.bin` blob — a
    /// JSON-declared integrity value. `super_root` is the cryptographic
    /// anchor; this is a cheap belt-and-suspenders check that catches blob
    /// truncation / corruption with a clearer diagnostic.
    pub tree_tops_hash: Hash256,
    /// Byte length of the tree-top blob, as declared in the JSON.
    pub tree_tops_size: usize,
    /// INDEX per-group sibling-DB parameters.
    pub index: OnionMerkleKindInfo,
    /// DATA per-group sibling-DB parameters.
    pub data: OnionMerkleKindInfo,
}

impl OnionMerkleInfo {
    fn kind(&self, tree: OnionTreeKind) -> &OnionMerkleKindInfo {
        match tree {
            OnionTreeKind::Index => &self.index,
            OnionTreeKind::Data => &self.data,
        }
    }
}

/// One leaf to be verified.
#[derive(Clone, Debug)]
pub struct OnionMerkleLeaf {
    /// Which tree kind this leaf lives in.
    pub tree: OnionTreeKind,
    /// PBC group index (`0..k`) — selects the per-group tree.
    pub pbc_group: usize,
    /// Cuckoo bin index within the group = the leaf index in that group's
    /// per-group Merkle tree.
    pub bin: u32,
    /// `SHA256(decrypted_bin_bytes)` — the leaf hash the server committed to
    /// (OnionPIR's no-prefix leaf hash, §2e).
    pub hash: Hash256,
    /// Back-reference to the query this leaf belongs to, so callers can
    /// aggregate per-query verification verdicts.
    pub result_idx: usize,
}

/// Per-shard transport view for sharded merkle sibling routing.
///
/// The merkle per-group sibling DBs are partitioned across shards exactly
/// like the INDEX / CHUNK group DBs: shard `s` answers the sibling queries
/// for the groups in `index_range` (INDEX tree) / `chunk_range` (DATA tree).
/// The public tree-top blob is small and present on every shard, so it is
/// fetched from the first shard only. A single shard with full ranges
/// (`0..K` / `0..K_CHUNK`) is byte-identical to the pre-sharding path.
pub struct MerkleShardConn<'a> {
    /// Transport to this shard.
    pub conn: &'a mut dyn PirTransport,
    /// INDEX-tree group range this shard serves (subset of `0..K`).
    pub index_range: std::ops::Range<usize>,
    /// DATA-tree group range this shard serves (subset of `0..K_CHUNK`).
    pub chunk_range: std::ops::Range<usize>,
}

impl MerkleShardConn<'_> {
    /// The group range this shard serves for `tree`.
    fn range_for(&self, tree: OnionTreeKind) -> std::ops::Range<usize> {
        match tree {
            OnionTreeKind::Index => self.index_range.clone(),
            OnionTreeKind::Data => self.chunk_range.clone(),
        }
    }
}

/// Parsed tree-top cache for **one** per-group Merkle tree.
#[derive(Clone, Debug)]
pub struct OnionTreeTopCache {
    /// Tree-level index of the first cached level (always `1` in the
    /// per-group design — the leaf level is the single PIR sibling level).
    ///
    /// Parse-only metadata: the walker derives its stop depth from
    /// `levels.len()` directly. Kept to preserve parse-shape symmetry with
    /// the shared per-bucket tree-top schema (`crate::merkle_verify`).
    #[allow(dead_code)]
    pub cache_from_level: usize,
    /// Merkle arity recorded in this tree's header — cross-checked against
    /// `OnionMerkleInfo::arity` by [`check_tree_top_anchor`].
    pub arity: usize,
    /// Cached hashes, bottom-up. `levels[0]` is the first cached level
    /// (level-1 nodes); the last level is `[root]` (length 1).
    pub levels: Vec<Vec<Hash256>>,
}

impl OnionTreeTopCache {
    /// The per-group root = the single hash in the last cached level.
    pub fn root(&self) -> Option<Hash256> {
        self.levels.last().and_then(|lvl| lvl.first().copied())
    }
}

// ─── JSON parsing (mirrors unified_server.rs::append_onionpir_merkle_json) ───

/// Parse the `onionpir_merkle` section from the server's JSON info.
///
/// Per-group schema (Phase 3):
/// ```json
/// "onionpir_merkle": {
///   "arity": 104,
///   "super_root": "<64 hex>",
///   "tree_tops_hash": "<64 hex>",
///   "tree_tops_size": 1245184,
///   "index": {"k": 75, "num_pt": 99},
///   "data":  {"k": 80, "num_pt": 364}
/// }
/// ```
///
/// Returns `None` if the server doesn't expose per-group OnionPIR Merkle for
/// this DB, or if any required field is missing / malformed — callers treat
/// `None` as "skip verification" (analogous to `has_bucket_merkle = false`).
/// A missing / zero-length `super_root` therefore makes the verifier
/// fail-safe: no anchor ⇒ no verification, rather than verifying against a
/// zero anchor.
pub fn parse_onionpir_merkle(json: &str) -> Option<OnionMerkleInfo> {
    let section = extract_json_object(json, "onionpir_merkle")?;
    let arity = json_u64(section, "arity")? as usize;
    if arity == 0 {
        // arity=0 would divide-by-zero every Merkle walk.
        return None;
    }
    let super_root = json_hex32(section, "super_root")?;
    let tree_tops_hash = json_hex32(section, "tree_tops_hash")?;
    let tree_tops_size = json_u64(section, "tree_tops_size")? as usize;

    let index = parse_kind_info(extract_json_object(section, "index")?)?;
    let data = parse_kind_info(extract_json_object(section, "data")?)?;

    Some(OnionMerkleInfo {
        arity,
        super_root,
        tree_tops_hash,
        tree_tops_size,
        index,
        data,
    })
}

fn parse_kind_info(section: &str) -> Option<OnionMerkleKindInfo> {
    let k = json_u64(section, "k")? as usize;
    let num_pt = json_u64(section, "num_pt")? as usize;
    if k == 0 || num_pt == 0 {
        // A degenerate / broken sibling DB — fail safe to "skip".
        return None;
    }
    Some(OnionMerkleKindInfo { k, num_pt })
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

/// Parse a 64-hex-character string-valued JSON field into a `Hash256`.
/// Tolerates whitespace between the colon and the opening quote so
/// serde-pretty-printed and hand-written test JSON both parse.
fn json_hex32(json: &str, key: &str) -> Option<Hash256> {
    let needle = format!("\"{}\":", key);
    let pos = json.find(&needle)?;
    let after_colon = json[pos + needle.len()..].trim_start();
    let after_quote = after_colon.strip_prefix('"')?;
    let inner_end = after_quote.find('"')?;
    let hex = &after_quote[..inner_end];
    if hex.len() != 64 {
        return None;
    }
    let mut out = ZERO_HASH;
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
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

// ─── Tree-top blob parsing ──────────────────────────────────────────────────

/// Parse the consolidated 155-tree tree-top blob `merkle_onion_tree_tops.bin`.
///
/// The whole blob is served on either TREE_TOP opcode (`0x54` / `0x56`); the
/// caller parses all 155 trees — 75 INDEX trees first, then 80 DATA trees
/// (the same order `gen_4_build_merkle_onion` writes them).
///
/// Wire format (identical to the shared per-bucket tree-tops blob —
/// `crate::merkle_verify::parse_tree_tops`):
///
/// ```text
/// [4B num_trees LE]
/// per tree:
///   [1B cache_from_level]
///   [4B total_nodes LE]      (informational, ignored)
///   [2B arity LE]
///   [1B num_cached_levels]
///   per cached level:
///     [4B num_nodes LE]
///     [num_nodes × 32B hashes]
/// ```
pub fn parse_onion_tree_top_cache(data: &[u8]) -> PirResult<Vec<OnionTreeTopCache>> {
    if data.len() < 4 {
        return Err(PirError::Decode(
            "onionpir tree-tops blob too short (need 4B num_trees)".into(),
        ));
    }
    let num_trees = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut off = 4usize;
    let mut out = Vec::with_capacity(num_trees);

    for t in 0..num_trees {
        if off + 8 > data.len() {
            return Err(PirError::Decode(format!(
                "onionpir tree-tops: truncated header for tree {}",
                t
            )));
        }
        let cache_from_level = data[off] as usize;
        off += 1;
        let _total_nodes = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        let arity = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
        off += 2;
        let num_levels = data[off] as usize;
        off += 1;
        if arity == 0 {
            return Err(PirError::Decode(format!(
                "onionpir tree-tops: tree {} has arity=0",
                t
            )));
        }

        let mut levels = Vec::with_capacity(num_levels);
        for l in 0..num_levels {
            if off + 4 > data.len() {
                return Err(PirError::Decode(format!(
                    "onionpir tree-tops: truncated level-{} count for tree {}",
                    l, t
                )));
            }
            let n = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if off + n * 32 > data.len() {
                return Err(PirError::Decode(format!(
                    "onionpir tree-tops: truncated hashes for tree {} level {}",
                    t, l
                )));
            }
            let mut nodes = Vec::with_capacity(n);
            for _ in 0..n {
                let mut h = ZERO_HASH;
                h.copy_from_slice(&data[off..off + 32]);
                nodes.push(h);
                off += 32;
            }
            levels.push(nodes);
        }
        out.push(OnionTreeTopCache {
            cache_from_level,
            arity,
            levels,
        });
    }
    Ok(out)
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
/// Same wire format as `REQ_ONIONPIR_INDEX_QUERY` / `REQ_ONIONPIR_CHUNK_QUERY`
/// (`OnionPirBatchQuery` in `runtime/src/onionpir.rs` — UNCHANGED by Phase 3).
///
/// `round_id` is vestigial under the per-group design (the server no longer
/// decodes a sibling level from `round_id / 100`); callers pass `0`.
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

// ─── Trust-anchor check (SOUNDNESS-CRITICAL) ────────────────────────────────

/// Bind the fetched tree-top blob to the pinned trust anchor.
///
/// **SOUNDNESS-CRITICAL.** The 155 per-group roots ride in the (untrusted,
/// server-supplied) tree-top blob; `info.super_root` is the pinned anchor
/// (`SHA256` of the 155 concatenated roots — MERKLE_COLOCATION_REVIEW.md §2f).
/// If this check is skipped or weakened, a malicious server can fabricate a
/// self-consistent tree-top blob + sibling responses and every leaf
/// "verifies" against forged roots.
///
/// Returns `true` iff the blob is bound to the anchor. Three checks, all
/// required:
///
/// 1. The blob has exactly `index.k + data.k` trees.
/// 2. The blob length / `SHA256` match the JSON-declared `tree_tops_size` /
///    `tree_tops_hash` (integrity — both come from the same trusted JSON as
///    `super_root`; this just yields a clearer diagnostic on corruption).
/// 3. **`SHA256(concat of the 155 per-group roots) == super_root`** — the
///    load-bearing cryptographic anchor check.
fn check_tree_top_anchor(
    info: &OnionMerkleInfo,
    blob: &[u8],
    all_tops: &[OnionTreeTopCache],
) -> bool {
    let expected_trees = info.index.k + info.data.k;
    if all_tops.len() != expected_trees {
        log::error!(
            "[PIR-AUDIT] OnionPIR Merkle: tree-top blob has {} trees, \
             expected {} (index_k={} + data_k={}) — REJECTING ALL LEAVES",
            all_tops.len(),
            expected_trees,
            info.index.k,
            info.data.k,
        );
        return false;
    }

    // Integrity: blob size + hash vs the JSON-declared values.
    if blob.len() != info.tree_tops_size {
        log::error!(
            "[PIR-AUDIT] OnionPIR Merkle: tree-top blob is {} B, JSON \
             declared tree_tops_size={} — REJECTING ALL LEAVES",
            blob.len(),
            info.tree_tops_size,
        );
        return false;
    }
    if sha256(blob) != info.tree_tops_hash {
        log::error!(
            "[PIR-AUDIT] OnionPIR Merkle: tree-top blob hash != JSON \
             tree_tops_hash — REJECTING ALL LEAVES (blob corrupt or server lied)",
        );
        return false;
    }

    // Per-tree arity must match the JSON arity (build/JSON drift guard).
    for (t, top) in all_tops.iter().enumerate() {
        if top.arity != info.arity {
            log::error!(
                "[PIR-AUDIT] OnionPIR Merkle: tree {} arity {} != JSON \
                 arity {} — REJECTING ALL LEAVES",
                t,
                top.arity,
                info.arity,
            );
            return false;
        }
    }

    // SOUNDNESS-CRITICAL: the 155 per-group roots must hash to super_root.
    let mut preimage: Vec<u8> = Vec::with_capacity(all_tops.len() * 32);
    for (t, top) in all_tops.iter().enumerate() {
        match top.root() {
            Some(r) => preimage.extend_from_slice(&r),
            None => {
                log::error!(
                    "[PIR-AUDIT] OnionPIR Merkle: tree-top {} has no root \
                     level — REJECTING ALL LEAVES",
                    t,
                );
                return false;
            }
        }
    }
    let computed = sha256(&preimage);
    if computed != info.super_root {
        log::error!(
            "[PIR-AUDIT] OnionPIR Merkle: SUPER-ROOT MISMATCH — computed \
             {:02x}{:02x}{:02x}{:02x}.. from {} per-group roots, pinned \
             anchor is {:02x}{:02x}{:02x}{:02x}.. — REJECTING ALL LEAVES",
            computed[0],
            computed[1],
            computed[2],
            computed[3],
            all_tops.len(),
            info.super_root[0],
            info.super_root[1],
            info.super_root[2],
            info.super_root[3],
        );
        return false;
    }
    true
}

// ─── Tree-top walk ──────────────────────────────────────────────────────────

/// Walk a per-group tree-top from a known internal node up to the group root.
///
/// `start_hash` is the hash of the level-`cache_from_level` (= level-1) node
/// that the FHE sibling pass reconstructed; `start_idx` is its index within
/// that level. `top.levels[0]` holds that level's nodes, `top.levels[ci]`
/// the next cached levels, and `top.levels[last]` is `[root]`.
///
/// At each step the running hash replaces the child at `idx % arity` of its
/// parent's `arity` children (the rest read from the cached level), the
/// parent is recomputed via `SHA256` of the concatenated children, and `idx`
/// advances to the parent. Returns the reconstructed root.
fn walk_tree_top_to_root(
    start_hash: Hash256,
    start_idx: u32,
    top: &OnionTreeTopCache,
    arity: usize,
) -> Hash256 {
    let mut hash = start_hash;
    let mut idx = start_idx;
    // Walk every cached level except the last (which IS the root).
    for ci in 0..top.levels.len().saturating_sub(1) {
        let level_nodes = &top.levels[ci];
        let parent_start = (idx / arity as u32) * arity as u32;
        let child_pos = (idx as usize) % arity;
        let mut children: Vec<Hash256> = Vec::with_capacity(arity);
        for c in 0..arity {
            let node_i = parent_start as usize + c;
            if c == child_pos {
                children.push(hash);
            } else if node_i < level_nodes.len() {
                children.push(level_nodes[node_i]);
            } else {
                children.push(ZERO_HASH);
            }
        }
        hash = compute_parent_n(&children);
        idx /= arity as u32;
    }
    hash
}

// ─── Verifier ───────────────────────────────────────────────────────────────

/// Per-leaf verification verdict: `(tree_kind, pbc_group, bin) → verified`.
///
/// `verified == true` means the leaf hash reconstructed to the per-group
/// root, and that per-group root is bound to the pinned `super_root`.
pub type OnionMerkleVerdicts = HashMap<(OnionTreeKind, usize, u32), bool>;

/// Verify all OnionPIR Merkle leaves across both INDEX and DATA sub-trees.
///
/// * `shards` — per-shard transports (same connections used for the regular
///   queries). Each shard answers the sibling queries for its group ranges;
///   the tree-top blob is fetched from the first shard. N=1 (one shard, full
///   ranges) is the single-server path. The caller must have already
///   registered FHE keys for `db_id` with every shard.
/// * `info` — parsed [`OnionMerkleInfo`] for the current DB.
/// * `leaves` — one entry per probed leaf, pre-populated with
///   `(tree, pbc_group, bin, hash, result_idx)`. Duplicates (same
///   `(tree, pbc_group, bin)`) are deduplicated internally.
/// * `client_id`, `secret_key` — FHE state from the `OnionClient`'s
///   `FheState`. The sibling FHE client is created from these.
/// * `db_id` — DB under verification.
///
/// **Both** sub-trees are always verified, even when one has no leaves —
/// `verify_sub_tree` issues one all-dummy K-padded sibling pass for an empty
/// sub-tree so a not-found / whale batch (0 DATA leaves) is wire-
/// indistinguishable from a found batch (CHUNK-Merkle round-presence).
///
/// On decode / protocol error the function propagates; on individual leaf
/// verification failure the verdict map entry is `false` (not an error).
pub async fn verify_onion_merkle_batch(
    shards: &mut [MerkleShardConn<'_>],
    info: &OnionMerkleInfo,
    leaves: &[OnionMerkleLeaf],
    client_id: u64,
    secret_key: &[u8],
    db_id: u8,
    leakage_recorder: Option<Arc<dyn LeakageRecorder>>,
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

    // Verify the INDEX sub-tree.
    let index_verdicts = verify_sub_tree(
        shards,
        OnionTreeKind::Index,
        info,
        &index_leaves,
        client_id,
        secret_key,
        db_id,
        leakage_recorder.as_ref(),
    )
    .await?;
    for ((g, b), ok) in index_verdicts {
        verdicts.insert((OnionTreeKind::Index, g, b), ok);
    }

    // Verify the DATA sub-tree — ALWAYS, even with zero DATA leaves. An
    // all-not-found / whale batch contributes 0 DATA leaves; `verify_sub_tree`
    // still issues one all-dummy K_CHUNK sibling pass, so found-vs-not-found
    // cannot be inferred from CHUNK-Merkle traffic (CLAUDE.md "CHUNK
    // Round-Presence Symmetry"; PLAN_MERKLE_CODING.md cross-cutting C.1).
    let data_verdicts = verify_sub_tree(
        shards,
        OnionTreeKind::Data,
        info,
        &data_leaves,
        client_id,
        secret_key,
        db_id,
        leakage_recorder.as_ref(),
    )
    .await?;
    for ((g, b), ok) in data_verdicts {
        verdicts.insert((OnionTreeKind::Data, g, b), ok);
    }

    Ok(verdicts)
}

/// Verify a single sub-tree (INDEX or DATA). Returns `(pbc_group, bin) → verified`.
///
/// Per-group walk: fetch + anchor-check the tree-top blob, then for each
/// "pass" issue one K-padded FHE sibling round (one query per PBC group,
/// real-row for groups with a leaf, random-row dummy for the rest), fold the
/// decrypted sibling row into the leaf's running hash, and walk the cached
/// per-group tree-top to the group root.
///
/// `max(1, max_items_per_group)` passes run: ≥1 even for an empty sub-tree
/// (round-presence) and one extra per within-group collision (e.g. the two
/// INDEX cuckoo positions of a not-found query land in the same group).
#[allow(clippy::too_many_arguments)]
async fn verify_sub_tree(
    shards: &mut [MerkleShardConn<'_>],
    tree: OnionTreeKind,
    info: &OnionMerkleInfo,
    leaves: &[&OnionMerkleLeaf],
    client_id: u64,
    secret_key: &[u8],
    db_id: u8,
    leakage_recorder: Option<&Arc<dyn LeakageRecorder>>,
) -> PirResult<HashMap<(usize, u32), bool>> {
    let arity = info.arity;
    let kind = *info.kind(tree);
    let k = kind.k;
    let num_pt = kind.num_pt;

    let mut out: HashMap<(usize, u32), bool> = HashMap::new();

    // ── 1. Fetch the consolidated 155-tree tree-top blob ────────────────
    let req = encode_tree_top_request(tree.req_tree_top(), db_id);
    let request_bytes = req.len() as u64;
    // The 155-tree tree-top blob is small + public + present on every shard;
    // fetch it from the first shard only (server_id 0).
    let resp = {
        let primary = shards
            .first_mut()
            .ok_or_else(|| PirError::Protocol("merkle: no shards configured".into()))?;
        primary.conn.roundtrip(&req).await?
    };
    if let Some(rec) = leakage_recorder {
        rec.record_round(
            "onion",
            RoundProfile {
                kind: RoundKind::MerkleTreeTops,
                server_id: 0,
                db_id: Some(db_id),
                request_bytes,
                response_bytes: (resp.len() as u64).saturating_add(4),
                items: Vec::new(),
            },
        );
    }
    if resp.is_empty() || resp[0] != tree.resp_tree_top() {
        return Err(PirError::Protocol(format!(
            "expected {} tree-top response (0x{:02x}), got variant 0x{:02x}",
            tree.name(),
            tree.resp_tree_top(),
            resp.first().copied().unwrap_or(0),
        )));
    }
    let blob = &resp[1..];
    let all_tops = parse_onion_tree_top_cache(blob)?;
    log::info!(
        "[PIR-AUDIT] OnionPIR Merkle {} tree-top: {} trees parsed (arity={})",
        tree.name(),
        all_tops.len(),
        arity,
    );

    // ── 2. Bind the blob to the pinned super-root (SOUNDNESS-CRITICAL) ──
    //
    // A super-root mismatch means the server's whole Merkle commitment is
    // untrusted (malicious server, or a DB-version skew). Every probed leaf
    // fails; the sibling rounds would prove nothing, so skip them.
    if !check_tree_top_anchor(info, blob, &all_tops) {
        for l in leaves {
            out.insert((l.pbc_group, l.bin), false);
        }
        return Ok(out);
    }
    let index_k = info.index.k;

    // ── 3. Deduplicate leaves by (pbc_group, bin) ───────────────────────
    let mut unique: HashMap<(usize, u32), Hash256> = HashMap::new();
    for l in leaves {
        unique.entry((l.pbc_group, l.bin)).or_insert(l.hash);
    }
    let keys: Vec<(usize, u32)> = unique.keys().copied().collect();
    let n = keys.len();
    // Per-leaf running state.
    let mut current_hash: Vec<Hash256> = keys.iter().map(|k| unique[k]).collect();
    let mut node_idx: Vec<u32> = keys.iter().map(|(_, bin)| *bin).collect();
    let mut failed: Vec<bool> = vec![false; n];

    log::info!(
        "[PIR-AUDIT] OnionPIR Merkle {}: verifying {} unique leaves (k={})",
        tree.name(),
        n,
        k,
    );

    // ── 4. Group leaves by PBC group ────────────────────────────────────
    // Multiple leaves share a group only for the INDEX-not-found case
    // (both cuckoo positions) or batch collisions; each surplus leaf
    // becomes one extra pass, each pass itself fully K-padded.
    let mut items_by_group: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, &(g, _)) in keys.iter().enumerate() {
        items_by_group.entry(g).or_default().push(i);
    }
    // ≥1: an empty sub-tree still issues one all-dummy pass (round-presence).
    let max_items_per_group = items_by_group
        .values()
        .map(|v| v.len())
        .max()
        .unwrap_or(0)
        .max(1);

    // ── 5. FHE sibling client (one per sub-tree — fixed num_pt) ─────────
    let sib_client = SibSendClient(
        onionpir::Client::from_secret_key(num_pt as u64, client_id, secret_key).ok_or_else(
            || {
                PirError::InvalidState(format!(
                    "OnionPIR sib Client::from_secret_key returned None \
                     (num_pt={}, client_id={}, sk_len={}). \
                     Likely cause: onionpir rev / ACTIVE_CONFIG drift \
                     between this binary and the session-master key. \
                     Recovery: drop FheState + restart the session.",
                    num_pt,
                    client_id,
                    secret_key.len()
                ))
            },
        )?,
    );
    let pinfo = onionpir::params_info(num_pt as u64);
    if pinfo.entry_size as usize != arity * 32 {
        return Err(PirError::Protocol(format!(
            "OnionPIR Merkle {}: sibling DB entry_size {} != arity*32 ({}) \
             — onionpir rev / build-shape drift",
            tree.name(),
            pinfo.entry_size,
            arity * 32,
        )));
    }
    let mut rng = SimpleRng::new();

    // ── 6. Sibling passes: one K-padded FHE round per pass ──────────────
    //
    // There is exactly ONE PIR sibling level (leaf → level-1). Each pass
    // handles at most one leaf per group, and every leaf is in exactly one
    // pass, so per-pass updates of `node_idx` / `current_hash` never
    // interfere — no deferred-update bookkeeping is needed (unlike the
    // multi-level per-bucket walk in `crate::merkle_verify`).
    for pass in 0..max_items_per_group {
        // Which leaf (if any) each group contributes at this pass.
        let mut pass_group_to_item: HashMap<usize, usize> = HashMap::new();
        for (&g, arr) in &items_by_group {
            if let Some(&item) = arr.get(pass) {
                pass_group_to_item.insert(g, item);
            }
        }

        // K FHE queries — real row for a group with a pass-`pass` leaf,
        // random-row dummy for the rest. K-padding: the server sees K
        // indistinguishable FHE queries every pass, regardless of how many
        // leaves are real (privacy requirement, CLAUDE.md "Query Padding").
        let mut queries: Vec<Vec<u8>> = Vec::with_capacity(k);
        for g in 0..k {
            let row = match pass_group_to_item.get(&g) {
                Some(&item) => node_idx[item] as u64 / arity as u64,
                None => rng.next_u64() % num_pt as u64,
            };
            queries.push(sib_client.0.generate_query(row));
        }

        // Split the K positional sibling queries by each shard's group range
        // for this tree, send each shard its slice, and merge the per-shard
        // responses back into one K-length positional `batch` (group g at
        // index g). N=1 with a full range is a single roundtrip with
        // server_id 0 + items=[1;K] — byte-identical to the pre-sharding
        // path. round_id is vestigial under the per-group design — send 0.
        let mut batch: Vec<Vec<u8>> = vec![Vec::new(); k];
        for (shard_idx, shard) in shards.iter_mut().enumerate() {
            let range = shard.range_for(tree);
            if range.end > k {
                return Err(PirError::Protocol(format!(
                    "merkle {} shard {} group range {}..{} exceeds tree group count {}",
                    tree.name(),
                    shard_idx,
                    range.start,
                    range.end,
                    k,
                )));
            }
            if range.start >= range.end {
                continue;
            }
            let sub: Vec<Vec<u8>> = queries[range.start..range.end].to_vec();
            let msg = encode_sibling_batch_query(tree.req_sibling(), 0, &sub, db_id);
            let request_bytes = msg.len() as u64;
            let resp = shard.conn.roundtrip(&msg).await?;
            if let Some(rec) = leakage_recorder {
                // One PIR sibling level ⇒ level is always 0.
                let kind = match tree {
                    OnionTreeKind::Index => RoundKind::IndexMerkleSiblings { level: 0 },
                    OnionTreeKind::Data => RoundKind::ChunkMerkleSiblings { level: 0 },
                };
                // One FHE query per PBC group in this shard's range — items[g]=1.
                rec.record_round(
                    "onion",
                    RoundProfile {
                        kind,
                        server_id: shard_idx as u8,
                        db_id: Some(db_id),
                        request_bytes,
                        response_bytes: (resp.len() as u64).saturating_add(4),
                        items: vec![1u32; range.end - range.start],
                    },
                );
            }
            if resp.is_empty() || resp[0] != tree.resp_sibling() {
                return Err(PirError::Protocol(format!(
                    "expected {} sibling response (0x{:02x}), got variant 0x{:02x}",
                    tree.name(),
                    tree.resp_sibling(),
                    resp.first().copied().unwrap_or(0),
                )));
            }
            let part = decode_sibling_batch_result(&resp[1..])?;
            if part.len() != range.end - range.start {
                return Err(PirError::Protocol(format!(
                    "merkle {} shard {} returned {} sibling results, expected {}",
                    tree.name(),
                    shard_idx,
                    part.len(),
                    range.end - range.start,
                )));
            }
            for (j, r) in part.into_iter().enumerate() {
                batch[range.start + j] = r;
            }
        }

        // Fold each real group's decrypted sibling row into its leaf.
        for (&g, &item) in &pass_group_to_item {
            if failed[item] {
                continue;
            }
            if g >= batch.len() {
                log::warn!(
                    "[PIR-AUDIT] OnionPIR Merkle {} pass {}: result batch \
                     truncated at group {} (len {})",
                    tree.name(),
                    pass,
                    g,
                    batch.len(),
                );
                failed[item] = true;
                continue;
            }
            let raw_pt = sib_client.0.decrypt_response(&batch[g]);
            let row = pir_core::onion_unpack::unpack_onion_plaintext(
                &raw_pt,
                pinfo.poly_degree as usize,
                pinfo.entry_size as usize,
            )
            .ok_or_else(|| {
                PirError::Protocol(format!(
                    "onion_unpack rejected {} sibling plaintext (len={} N={} es={})",
                    tree.name(),
                    raw_pt.len(),
                    pinfo.poly_degree,
                    pinfo.entry_size
                ))
            })?;

            // Recompute the level-1 parent of bin `node_idx[item]`: the
            // decrypted row holds that parent's `arity` leaf children;
            // replace the child at `bin % arity` with the leaf's own
            // committed hash, then hash the `arity` children. If the
            // server lied about any sibling, the parent — and hence the
            // root — will not match (root propagation, see §7).
            let child_pos = (node_idx[item] as usize) % arity;
            let mut children: Vec<Hash256> = Vec::with_capacity(arity);
            for c in 0..arity {
                if c == child_pos {
                    children.push(current_hash[item]);
                } else {
                    let off = c * 32;
                    let mut h = ZERO_HASH;
                    if off + 32 <= row.len() {
                        h.copy_from_slice(&row[off..off + 32]);
                    }
                    children.push(h);
                }
            }
            current_hash[item] = compute_parent_n(&children);
            node_idx[item] /= arity as u32;
        }
    }

    // ── 7. Walk each leaf's cached tree-top to its per-group root ───────
    for i in 0..n {
        let (pbc_group, bin) = keys[i];
        if failed[i] {
            out.insert((pbc_group, bin), false);
            continue;
        }
        // 75 INDEX trees first, then 80 DATA trees.
        let top_idx = match tree {
            OnionTreeKind::Index => pbc_group,
            OnionTreeKind::Data => index_k + pbc_group,
        };
        let top = match all_tops.get(top_idx) {
            Some(t) => t,
            None => {
                log::warn!(
                    "[PIR-AUDIT] OnionPIR Merkle {}: no tree-top for group {} \
                     (leaf bin {})",
                    tree.name(),
                    pbc_group,
                    bin,
                );
                out.insert((pbc_group, bin), false);
                continue;
            }
        };
        let walked = walk_tree_top_to_root(current_hash[i], node_idx[i], top, arity);
        // `top.root()` is `Some` here — `check_tree_top_anchor` already
        // rejected any tree-top without a root level.
        let expected = top.root().unwrap_or(ZERO_HASH);
        let ok = walked == expected;
        if !ok {
            log::warn!(
                "[PIR-AUDIT] OnionPIR Merkle {} group {} bin {}: root MISMATCH \
                 (walked {:02x}{:02x}{:02x}{:02x}.., expected {:02x}{:02x}{:02x}{:02x}..)",
                tree.name(),
                pbc_group,
                bin,
                walked[0],
                walked[1],
                walked[2],
                walked[3],
                expected[0],
                expected[1],
                expected[2],
                expected[3],
            );
        }
        out.insert((pbc_group, bin), ok);
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
/// OnionPIR leaves are raw `SHA256` over the decrypted bin bytes — no
/// `bin_idx` prefix (that's the per-bucket convention, not OnionPIR's; see
/// MERKLE_COLOCATION_REVIEW.md §2e).
///
/// Not currently called from the in-crate verifier (which inlines `sha256`
/// at the INDEX / CHUNK decrypt sites in `onion.rs`), but exported as part of
/// the public onion Merkle API surface so external consumers of the `onion`
/// feature can reproduce leaf hashing without reaching into `pir_core::merkle`.
/// Exercised by `test_onion_leaf_hash_matches_sha256` in the tests module.
#[allow(dead_code)]
#[inline]
pub fn onion_leaf_hash(bin_bytes: &[u8]) -> Hash256 {
    sha256(bin_bytes)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one per-group arity-`arity` Merkle tree over `leaves`, returning
    /// `(all levels bottom-up, root)`. Incomplete groups pad with `ZERO_HASH`
    /// — mirrors `gen_4_build_merkle_onion::build_group_tree`.
    fn build_tree(arity: usize, leaves: &[Hash256]) -> (Vec<Vec<Hash256>>, Hash256) {
        let mut levels: Vec<Vec<Hash256>> = vec![leaves.to_vec()];
        loop {
            let prev = levels.last().unwrap();
            if prev.len() <= 1 {
                break;
            }
            let next_len = prev.len().div_ceil(arity);
            let mut next = Vec::with_capacity(next_len);
            for i in 0..next_len {
                let start = i * arity;
                let end = (start + arity).min(prev.len());
                let mut children: Vec<Hash256> = prev[start..end].to_vec();
                children.resize(arity, ZERO_HASH);
                next.push(compute_parent_n(&children));
            }
            levels.push(next);
        }
        let root = *levels.last().unwrap().first().unwrap();
        (levels, root)
    }

    /// Encode one tree-top (cached levels = `levels[cache_from..]`) into the
    /// per-tree wire layout, appending to `blob`.
    fn encode_one_tree_top(
        blob: &mut Vec<u8>,
        arity: usize,
        cache_from: usize,
        levels: &[Vec<Hash256>],
    ) {
        let cached = &levels[cache_from..];
        let total: u32 = cached.iter().map(|l| l.len() as u32).sum();
        blob.push(cache_from as u8);
        blob.extend_from_slice(&total.to_le_bytes());
        blob.extend_from_slice(&(arity as u16).to_le_bytes());
        blob.push(cached.len() as u8);
        for lvl in cached {
            blob.extend_from_slice(&(lvl.len() as u32).to_le_bytes());
            for h in lvl {
                blob.extend_from_slice(h);
            }
        }
    }

    fn h(seed: u8) -> Hash256 {
        let mut x = ZERO_HASH;
        x[0] = seed;
        x[31] = seed.wrapping_mul(7);
        x
    }

    /// Build a full 155-tree-style blob with `n_index` + `n_data` identical
    /// small trees, returning `(blob, super_root)`.
    fn build_blob(
        arity: usize,
        leaves: &[Hash256],
        n_index: usize,
        n_data: usize,
    ) -> (Vec<u8>, Hash256) {
        let (levels, root) = build_tree(arity, leaves);
        let num_trees = n_index + n_data;
        let mut blob = Vec::new();
        blob.extend_from_slice(&(num_trees as u32).to_le_bytes());
        for _ in 0..num_trees {
            encode_one_tree_top(&mut blob, arity, 1, &levels);
        }
        // super_root = SHA256(concat of all per-group roots). Every tree is
        // identical here, so the preimage is `root` repeated `num_trees`x.
        let mut preimage = Vec::new();
        for _ in 0..num_trees {
            preimage.extend_from_slice(&root);
        }
        (blob, sha256(&preimage))
    }

    #[test]
    fn test_parse_onion_tree_top_cache_multi_tree() {
        let leaves: Vec<Hash256> = (0..40u8).map(h).collect();
        let (blob, _root) = build_blob(8, &leaves, 3, 2);
        let tops = parse_onion_tree_top_cache(&blob).unwrap();
        assert_eq!(tops.len(), 5);
        for t in &tops {
            assert_eq!(t.arity, 8);
            assert_eq!(t.cache_from_level, 1);
            // 40 leaves, arity 8 → levels [40, 5, 1]; cached from 1 → [5, 1].
            assert_eq!(t.levels.len(), 2);
            assert_eq!(t.levels[0].len(), 5);
            assert_eq!(t.levels.last().unwrap().len(), 1);
            assert!(t.root().is_some());
        }
    }

    #[test]
    fn test_parse_onion_tree_top_cache_too_short() {
        assert!(parse_onion_tree_top_cache(&[]).is_err());
        assert!(parse_onion_tree_top_cache(&[0u8, 0, 0]).is_err());
    }

    #[test]
    fn test_parse_onion_tree_top_cache_arity_zero() {
        // One tree, arity=0 — must be rejected (else walks divide by zero).
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes()); // num_trees = 1
        blob.push(1); // cache_from_level
        blob.extend_from_slice(&0u32.to_le_bytes()); // total_nodes
        blob.extend_from_slice(&0u16.to_le_bytes()); // arity = 0
        blob.push(0); // num_cached_levels
        assert!(parse_onion_tree_top_cache(&blob).is_err());
    }

    #[test]
    fn test_parse_onion_tree_top_cache_truncated_tree() {
        // Claims 2 trees but only encodes 1.
        let leaves: Vec<Hash256> = (0..16u8).map(h).collect();
        let (levels, _) = build_tree(8, &leaves);
        let mut blob = Vec::new();
        blob.extend_from_slice(&2u32.to_le_bytes());
        encode_one_tree_top(&mut blob, 8, 1, &levels);
        assert!(parse_onion_tree_top_cache(&blob).is_err());
    }

    #[test]
    fn test_parse_onionpir_merkle_basic() {
        let j = r#"{
            "onionpir_merkle": {
                "arity": 104,
                "super_root": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "tree_tops_hash": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
                "tree_tops_size": 1245184,
                "index": {"k": 75, "num_pt": 99},
                "data":  {"k": 80, "num_pt": 364}
            }
        }"#;
        let info = parse_onionpir_merkle(j).unwrap();
        assert_eq!(info.arity, 104);
        assert_eq!(info.index.k, 75);
        assert_eq!(info.index.num_pt, 99);
        assert_eq!(info.data.k, 80);
        assert_eq!(info.data.num_pt, 364);
        assert_eq!(info.tree_tops_size, 1245184);
        assert_eq!(info.super_root[0], 0x00);
        assert_eq!(info.super_root[1], 0x11);
        assert_eq!(info.super_root[31], 0xff);
        assert_eq!(info.tree_tops_hash[0], 0xff);
        assert_eq!(info.tree_tops_hash[31], 0x00);
    }

    #[test]
    fn test_parse_onionpir_merkle_missing() {
        assert!(parse_onionpir_merkle(r#"{"foo":1}"#).is_none());
    }

    #[test]
    fn test_parse_onionpir_merkle_rejects_bad_super_root() {
        // super_root not 64 hex chars → None (fail-safe: skip verification).
        let j = r#"{"onionpir_merkle":{"arity":104,"super_root":"deadbeef",
            "tree_tops_hash":"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
            "tree_tops_size":10,"index":{"k":75,"num_pt":99},"data":{"k":80,"num_pt":364}}}"#;
        assert!(parse_onionpir_merkle(j).is_none());
    }

    #[test]
    fn test_parse_onionpir_merkle_rejects_arity_zero() {
        let j = r#"{"onionpir_merkle":{"arity":0,
            "super_root":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "tree_tops_hash":"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
            "tree_tops_size":10,"index":{"k":75,"num_pt":99},"data":{"k":80,"num_pt":364}}}"#;
        assert!(parse_onionpir_merkle(j).is_none());
    }

    fn merkle_info(arity: usize, super_root: Hash256, hash: Hash256, size: usize) -> OnionMerkleInfo {
        OnionMerkleInfo {
            arity,
            super_root,
            tree_tops_hash: hash,
            tree_tops_size: size,
            index: OnionMerkleKindInfo { k: 3, num_pt: 5 },
            data: OnionMerkleKindInfo { k: 2, num_pt: 5 },
        }
    }

    #[test]
    fn test_check_tree_top_anchor_accepts_matching_super_root() {
        let leaves: Vec<Hash256> = (0..40u8).map(h).collect();
        let (blob, super_root) = build_blob(8, &leaves, 3, 2);
        let tops = parse_onion_tree_top_cache(&blob).unwrap();
        let info = merkle_info(8, super_root, sha256(&blob), blob.len());
        assert!(check_tree_top_anchor(&info, &blob, &tops));
    }

    #[test]
    fn test_check_tree_top_anchor_rejects_wrong_super_root() {
        // SOUNDNESS: a tampered super-root (server fabricated the blob) must
        // be rejected even though the blob is internally consistent.
        let leaves: Vec<Hash256> = (0..40u8).map(h).collect();
        let (blob, super_root) = build_blob(8, &leaves, 3, 2);
        let tops = parse_onion_tree_top_cache(&blob).unwrap();
        let mut bad = super_root;
        bad[0] ^= 0x01;
        let info = merkle_info(8, bad, sha256(&blob), blob.len());
        assert!(!check_tree_top_anchor(&info, &blob, &tops));
    }

    #[test]
    fn test_check_tree_top_anchor_rejects_tampered_blob() {
        // Flipping a byte inside the blob breaks tree_tops_hash even when the
        // declared super_root happens to still match the parsed roots.
        let leaves: Vec<Hash256> = (0..40u8).map(h).collect();
        let (mut blob, super_root) = build_blob(8, &leaves, 3, 2);
        let good_hash = sha256(&blob);
        let size = blob.len();
        // Tamper a hash byte deep in the blob (a leaf-of-an-internal-level).
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let tops = parse_onion_tree_top_cache(&blob).unwrap();
        let info = merkle_info(8, super_root, good_hash, size);
        assert!(!check_tree_top_anchor(&info, &blob, &tops));
    }

    #[test]
    fn test_check_tree_top_anchor_rejects_wrong_tree_count() {
        let leaves: Vec<Hash256> = (0..40u8).map(h).collect();
        // Blob has 5 trees; info expects index.k + data.k = 3 + 2 = 5 — OK.
        // Now make the blob have only 4 trees.
        let (blob, super_root) = build_blob(8, &leaves, 2, 2);
        let tops = parse_onion_tree_top_cache(&blob).unwrap();
        let info = merkle_info(8, super_root, sha256(&blob), blob.len());
        assert!(!check_tree_top_anchor(&info, &blob, &tops));
    }

    #[test]
    fn test_check_tree_top_anchor_rejects_arity_drift() {
        let leaves: Vec<Hash256> = (0..40u8).map(h).collect();
        let (blob, super_root) = build_blob(8, &leaves, 3, 2);
        let tops = parse_onion_tree_top_cache(&blob).unwrap();
        // JSON arity (16) disagrees with the blob's per-tree arity (8).
        let info = merkle_info(16, super_root, sha256(&blob), blob.len());
        assert!(!check_tree_top_anchor(&info, &blob, &tops));
    }

    #[test]
    fn test_walk_tree_top_to_root_good() {
        // 64 leaves, arity 8 → levels [64, 8, 1]. Cache from level 1 → the
        // tree-top is [[8 level-1 nodes], [root]]. Walking from each level-1
        // node must reproduce the root.
        let leaves: Vec<Hash256> = (0..64u8).map(h).collect();
        let (levels, root) = build_tree(8, &leaves);
        let top = OnionTreeTopCache {
            cache_from_level: 1,
            arity: 8,
            levels: levels[1..].to_vec(),
        };
        for (idx, node) in levels[1].iter().enumerate() {
            let walked = walk_tree_top_to_root(*node, idx as u32, &top, 8);
            assert_eq!(walked, root, "level-1 node {} did not reach root", idx);
        }
    }

    #[test]
    fn test_walk_tree_top_to_root_tampered_fails() {
        // A wrong level-1 node hash must NOT reconstruct the root.
        let leaves: Vec<Hash256> = (0..64u8).map(h).collect();
        let (levels, root) = build_tree(8, &leaves);
        let top = OnionTreeTopCache {
            cache_from_level: 1,
            arity: 8,
            levels: levels[1..].to_vec(),
        };
        let mut tampered = levels[1][3];
        tampered[0] ^= 0x01;
        let walked = walk_tree_top_to_root(tampered, 3, &top, 8);
        assert_ne!(walked, root);
    }

    #[test]
    fn test_walk_tree_top_deep_tree() {
        // 4096 leaves, arity 8 → levels [4096, 512, 64, 8, 1]. Cache from
        // level 1 → tree-top [[512],[64],[8],[1]]. Exercises a 3-level walk.
        let leaves: Vec<Hash256> = (0..255u8)
            .cycle()
            .take(4096)
            .map(h)
            .collect();
        let (levels, root) = build_tree(8, &leaves);
        assert_eq!(levels.len(), 5);
        let top = OnionTreeTopCache {
            cache_from_level: 1,
            arity: 8,
            levels: levels[1..].to_vec(),
        };
        for idx in [0usize, 1, 17, 200, 511] {
            let walked = walk_tree_top_to_root(levels[1][idx], idx as u32, &top, 8);
            assert_eq!(walked, root, "level-1 node {} did not reach root", idx);
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
