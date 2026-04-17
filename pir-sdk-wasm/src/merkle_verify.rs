//! WASM bindings for per-bucket bin Merkle verification (DPF/Harmony).
//!
//! This module exposes the **pure-crypto** half of the Merkle verifier to
//! JavaScript: tree-top blob parsing, leaf / parent hash primitives, and a
//! per-item walk from leaf through pre-fetched sibling rows up to the cached
//! root. The **network** half (fetching sibling rows via DPF round-trips and
//! XORing server0 ⊕ server1 responses) stays in JS — the Rust-side
//! equivalent lives in `pir-sdk-client::merkle_verify` and is tightly coupled
//! to `tokio-tungstenite`, which does not compile to `wasm32-unknown-unknown`.
//!
//! ## Why a JS-driven split
//!
//! The native Rust client does
//!
//! ```text
//! verify_bucket_merkle_batch_generic(&mut querier, items, …)
//! ```
//!
//! where `querier` issues K-padded sibling-batch round-trips over
//! `WsConnection`. In the browser, the WebSocket lifecycle is owned by
//! JavaScript (via `ManagedWebSocket` / Web Workers), and existing TS clients
//! already run the padded multi-pass fetch loop. Rewriting transport-heavy
//! async code in WASM is a strictly-larger refactor than we need here —
//! the duplicated code that actually matters is the SHA-256 walk, not the
//! network dance. Exposing only the pure walk lets the web client drop its
//! ~400-LOC TS verifier in favour of one shared Rust implementation.
//!
//! ## JS usage pattern
//!
//! ```javascript
//! // 1. Parse server-supplied tree-tops once per (db_id, height).
//! const tops = WasmBucketMerkleTreeTops.fromBytes(treeTopsBlob);
//!
//! // 2. For each item, run the existing multi-pass sibling fetch to collect
//! //    all XOR'd 256B rows (one per level below cache_from_level) for this
//! //    item's PBC group, then flatten them in order.
//! const siblingRowsFlat = concat(prefetchedRowsForItem); // (levels × 256) bytes
//!
//! // 3. Call the pure verifier.
//! const ok = verifyBucketMerkleItem(
//!   item.binIndex,
//!   item.binContent,
//!   item.pbcGroup,
//!   siblingRowsFlat,
//!   tops,
//! );
//! ```
//!
//! The sibling-row byte layout exactly matches what the server sends back via
//! `REQ_BUCKET_MERKLE_SIB_BATCH` (0x33), XOR'd across the two DPF shards —
//! 8 child hashes × 32B each = 256B per level.

use pir_core::merkle::{compute_bin_leaf_hash, compute_parent_n, sha256, Hash256, ZERO_HASH};
use wasm_bindgen::prelude::*;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Arity of each per-PBC-group bin-Merkle tree. Must match the server and the
/// native Rust verifier (`pir-sdk-client::merkle_verify::BUCKET_MERKLE_ARITY`).
pub const BUCKET_MERKLE_ARITY: usize = 8;

/// Size of one sibling row: `arity × 32B hash = 256B`.
pub const BUCKET_MERKLE_SIB_ROW_SIZE: usize = BUCKET_MERKLE_ARITY * 32;

// ─── Tree-top blob parsing (pure) ───────────────────────────────────────────

/// One parsed tree-top cache (per PBC group).
///
/// `cache_from_level` is the sibling depth below which the server cached
/// every node. The client therefore runs `cache_from_level` sibling rounds
/// bottom-up, then walks the cached top `levels.len() - 1` times to reach
/// the root. The **last** level is always `[root]` (length 1).
#[derive(Clone, Debug)]
pub struct TreeTop {
    pub cache_from_level: usize,
    pub levels: Vec<Vec<Hash256>>,
}

impl TreeTop {
    pub fn root(&self) -> Option<Hash256> {
        self.levels.last().and_then(|lvl| lvl.first().copied())
    }
}

/// Parse the tree-tops blob returned by `REQ_BUCKET_MERKLE_TREE_TOPS` (0x34).
///
/// Wire format — must match `runtime/src/bin/unified_server.rs` and the
/// Rust-native parser in `pir-sdk-client::merkle_verify::parse_tree_tops`:
///
/// ```text
/// [4B num_trees LE]
/// per tree:
///   [1B cache_from_level]
///   [4B total_nodes LE]       (informational, ignored)
///   [2B arity LE]             (always 8, informational)
///   [1B num_cached_levels]
///   per cached level:
///     [4B num_nodes LE]
///     [num_nodes × 32B hashes]
/// ```
///
/// The server emits `K` INDEX trees then `K_CHUNK` CHUNK trees in that order;
/// the caller slices accordingly.
pub fn parse_tree_tops_bytes(data: &[u8]) -> Result<Vec<TreeTop>, String> {
    if data.len() < 4 {
        return Err("tree-tops blob too short (<4B)".into());
    }
    let num_trees = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut off = 4usize;
    let mut out = Vec::with_capacity(num_trees);

    for t in 0..num_trees {
        if off + 8 > data.len() {
            return Err(format!("truncated header for tree {}", t));
        }
        let cache_from_level = data[off] as usize;
        off += 1;
        let _total_nodes = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        off += 4;
        let _arity = u16::from_le_bytes(data[off..off + 2].try_into().unwrap());
        off += 2;
        let num_levels = data[off] as usize;
        off += 1;

        let mut levels = Vec::with_capacity(num_levels);
        for lvl in 0..num_levels {
            if off + 4 > data.len() {
                return Err(format!(
                    "truncated level count for tree {} level {}",
                    t, lvl
                ));
            }
            let n = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if off + n * 32 > data.len() {
                return Err(format!(
                    "truncated hashes for tree {} level {}",
                    t, lvl
                ));
            }
            let mut nodes = Vec::with_capacity(n);
            for _ in 0..n {
                let mut h: Hash256 = ZERO_HASH;
                h.copy_from_slice(&data[off..off + 32]);
                nodes.push(h);
                off += 32;
            }
            levels.push(nodes);
        }
        out.push(TreeTop {
            cache_from_level,
            levels,
        });
    }
    Ok(out)
}

// ─── WASM handle for parsed tree-tops ───────────────────────────────────────

/// Opaque handle over a parsed tree-tops blob. Owns the parsed data so JS
/// can pass it to multiple `verifyBucketMerkleItem` calls without reparsing.
///
/// Treat as immutable after construction.
#[wasm_bindgen]
pub struct WasmBucketMerkleTreeTops {
    tops: Vec<TreeTop>,
}

#[wasm_bindgen]
impl WasmBucketMerkleTreeTops {
    /// Parse a raw tree-tops blob (the payload *after* the `RESP_*` variant
    /// byte on the wire — see `REQ_BUCKET_MERKLE_TREE_TOPS` = 0x34).
    ///
    /// Returns an error string on malformed input.
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<WasmBucketMerkleTreeTops, JsError> {
        let tops = parse_tree_tops_bytes(data)
            .map_err(|e| JsError::new(&format!("tree-tops parse: {}", e)))?;
        Ok(WasmBucketMerkleTreeTops { tops })
    }

    /// Total number of parsed trees (should equal `K + K_CHUNK` — the server
    /// emits INDEX trees `[0..K)` followed by CHUNK trees `[K..K+K_CHUNK)`).
    #[wasm_bindgen(getter, js_name = treeCount)]
    pub fn tree_count(&self) -> usize {
        self.tops.len()
    }

    /// `cache_from_level` for the tree at `group_idx`. This is the number of
    /// bottom-up sibling-query rounds the client must run before hitting the
    /// cached top. Returns `None`-equivalent `u32::MAX` on out-of-range so the
    /// JS caller can surface it as a verification failure.
    #[wasm_bindgen(js_name = cacheFromLevel)]
    pub fn cache_from_level(&self, group_idx: usize) -> u32 {
        self.tops
            .get(group_idx)
            .map(|t| t.cache_from_level as u32)
            .unwrap_or(u32::MAX)
    }

    /// Published per-group root (the last cached level's only entry). Empty
    /// `Uint8Array` on out-of-range or if the tree-top has no levels.
    #[wasm_bindgen(js_name = root)]
    pub fn root(&self, group_idx: usize) -> Vec<u8> {
        self.tops
            .get(group_idx)
            .and_then(|t| t.root())
            .map(|h| h.to_vec())
            .unwrap_or_default()
    }
}

// ─── Hash primitives ────────────────────────────────────────────────────────

/// SHA-256 of `data`. Thin wrapper over `pir_core::merkle::sha256` exposed so
/// JS can drop its own polyfill in favour of the same implementation used by
/// the server and native Rust client.
#[wasm_bindgen(js_name = bucketMerkleSha256)]
pub fn bucket_merkle_sha256(data: &[u8]) -> Vec<u8> {
    sha256(data).to_vec()
}

/// `SHA256(bin_index_u32_LE || bin_content)` — the leaf commitment used by
/// every per-bucket bin-Merkle tree.
#[wasm_bindgen(js_name = bucketMerkleLeafHash)]
pub fn bucket_merkle_leaf_hash(bin_index: u32, bin_content: &[u8]) -> Vec<u8> {
    compute_bin_leaf_hash(bin_index, bin_content).to_vec()
}

/// Compute an arity-N internal-node hash: `SHA256(child_0 || child_1 || …)`.
///
/// `children_flat` must be a multiple of 32 bytes (one 32B hash per child).
/// Returns an empty array on malformed input so JS can coerce it to a
/// verification failure.
#[wasm_bindgen(js_name = bucketMerkleParentN)]
pub fn bucket_merkle_parent_n(children_flat: &[u8]) -> Vec<u8> {
    if children_flat.is_empty() || children_flat.len() % 32 != 0 {
        return Vec::new();
    }
    let n = children_flat.len() / 32;
    let mut children: Vec<Hash256> = Vec::with_capacity(n);
    for c in 0..n {
        let mut h: Hash256 = ZERO_HASH;
        h.copy_from_slice(&children_flat[c * 32..(c + 1) * 32]);
        children.push(h);
    }
    compute_parent_n(&children).to_vec()
}

// ─── Per-item verifier (pure) ───────────────────────────────────────────────

/// Walk one bin-Merkle proof from leaf to root.
///
/// `sibling_rows_flat` must carry `cache_from_level × BUCKET_MERKLE_SIB_ROW_SIZE`
/// bytes, with one 256B row per sibling level, bottom-up. Each row is the
/// XOR of server0 ⊕ server1 responses to that level's `REQ_BUCKET_MERKLE_SIB_BATCH`
/// query — it holds the 8 child hashes at `(node_idx / 8) × 8 .. +8`, one of
/// which is this item's current hash. The walker recomputes the parent by
/// substituting the running hash at `node_idx % 8`.
///
/// After `cache_from_level` sibling rounds, the walker reads the cached
/// levels from `tree_tops[pbc_group]` and keeps combining children until it
/// reaches the root; the result is compared against the published root.
///
/// Returns `true` iff the reconstruction matches. Any shape mismatch (row
/// too short, out-of-range group, missing tree-top, etc.) returns `false`
/// rather than erroring — it's a verification failure, not a programming
/// bug, and the caller must already handle "some items failed" as a normal
/// outcome (the native client coerces failures to `QueryResult::merkle_failed()`).
///
/// See `pir-sdk-client::merkle_verify::verify_sibling_levels` for the
/// reference implementation this tracks; the two functions must stay in sync.
#[wasm_bindgen(js_name = verifyBucketMerkleItem)]
pub fn verify_bucket_merkle_item(
    bin_index: u32,
    bin_content: &[u8],
    pbc_group: usize,
    sibling_rows_flat: &[u8],
    tree_tops: &WasmBucketMerkleTreeTops,
) -> bool {
    let Some(top) = tree_tops.tops.get(pbc_group) else {
        return false;
    };
    if top.levels.is_empty() {
        return false;
    }

    let arity = BUCKET_MERKLE_ARITY;
    let mut hash = compute_bin_leaf_hash(bin_index, bin_content);
    let mut node_idx = bin_index;

    // ── Sibling rounds ──
    let sib_levels = top.cache_from_level;
    if sibling_rows_flat.len() < sib_levels * BUCKET_MERKLE_SIB_ROW_SIZE {
        return false;
    }
    for level in 0..sib_levels {
        let row = &sibling_rows_flat
            [level * BUCKET_MERKLE_SIB_ROW_SIZE..(level + 1) * BUCKET_MERKLE_SIB_ROW_SIZE];
        let child_pos = (node_idx as usize) % arity;
        let mut children: Vec<Hash256> = Vec::with_capacity(arity);
        for c in 0..arity {
            if c == child_pos {
                children.push(hash);
            } else {
                let off = c * 32;
                let mut h: Hash256 = ZERO_HASH;
                h.copy_from_slice(&row[off..off + 32]);
                children.push(h);
            }
        }
        hash = compute_parent_n(&children);
        node_idx /= arity as u32;
    }

    // ── Tree-top walk ──
    let cached_len = top.levels.len();
    // Walk every cached level except the last (which IS the root).
    for cl in 0..cached_len.saturating_sub(1) {
        let level_nodes = &top.levels[cl];
        let parent_start = (node_idx / arity as u32) * arity as u32;
        let child_pos = (node_idx as usize) % arity;
        let mut children: Vec<Hash256> = Vec::with_capacity(arity);
        for c in 0..arity {
            let node_i = (parent_start as usize) + c;
            if c == child_pos {
                children.push(hash);
            } else if node_i < level_nodes.len() {
                children.push(level_nodes[node_i]);
            } else {
                children.push(ZERO_HASH);
            }
        }
        hash = compute_parent_n(&children);
        node_idx /= arity as u32;
    }

    let expected_root = top.root().unwrap_or(ZERO_HASH);
    hash == expected_root
}

// ─── Sibling-row XOR helper ─────────────────────────────────────────────────

/// XOR two sibling-batch responses of equal length and return the result.
///
/// Returns an empty array if the inputs are different lengths (the DPF XOR
/// only makes sense for identical-length responses; a mismatch is always a
/// protocol error the caller should surface as a verification failure).
///
/// This is a convenience for JS so the `server0 ⊕ server1` fold lives next
/// to the rest of the verifier instead of being hand-rolled per client.
#[wasm_bindgen(js_name = xorBuffers)]
pub fn xor_buffers(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.len() != b.len() {
        return Vec::new();
    }
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

// ─── Tests (native-only) ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn arity8_leaves(count: usize) -> Vec<Hash256> {
        // Deterministic mock leaves — just hash `i` as the bin content.
        (0..count)
            .map(|i| compute_bin_leaf_hash(i as u32, &(i as u64).to_le_bytes()))
            .collect()
    }

    /// Build a full tree (no sibling levels — everything cached) from
    /// `leaves`, serialised as a tree-tops blob with `cache_from_level=0`.
    fn build_full_cache_blob(leaves: &[Hash256]) -> Vec<u8> {
        // Build the tree bottom-up; every level is cached.
        let mut levels: Vec<Vec<Hash256>> = vec![leaves.to_vec()];
        while levels.last().unwrap().len() > 1 {
            let cur = levels.last().unwrap();
            let mut next: Vec<Hash256> = Vec::new();
            let chunks = (cur.len() + 7) / 8;
            for c in 0..chunks {
                let mut children: Vec<Hash256> = Vec::with_capacity(8);
                for k in 0..8 {
                    let i = c * 8 + k;
                    children.push(if i < cur.len() { cur[i] } else { ZERO_HASH });
                }
                next.push(compute_parent_n(&children));
            }
            levels.push(next);
        }

        // Serialise as one-tree blob.
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes()); // num_trees
        blob.push(0u8); // cache_from_level = 0
        blob.extend_from_slice(&(leaves.len() as u32).to_le_bytes()); // total_nodes (informational)
        blob.extend_from_slice(&8u16.to_le_bytes()); // arity (informational)
        blob.push(levels.len() as u8); // num_cached_levels
        for level in &levels {
            blob.extend_from_slice(&(level.len() as u32).to_le_bytes());
            for h in level {
                blob.extend_from_slice(h);
            }
        }
        blob
    }

    #[test]
    fn empty_blob_errors() {
        assert!(parse_tree_tops_bytes(&[]).is_err());
        assert!(parse_tree_tops_bytes(&[1, 2]).is_err());
    }

    #[test]
    fn zero_trees_parses_to_empty() {
        let blob = 0u32.to_le_bytes().to_vec();
        let tops = parse_tree_tops_bytes(&blob).unwrap();
        assert!(tops.is_empty());
    }

    #[test]
    fn leaf_hash_matches_core() {
        let content = b"hello world";
        let got = bucket_merkle_leaf_hash(42, content);
        let want = compute_bin_leaf_hash(42, content).to_vec();
        assert_eq!(got, want);
    }

    #[test]
    fn parent_n_matches_core() {
        // Three children, 32B each.
        let mut flat = Vec::new();
        for i in 0..3u8 {
            flat.extend_from_slice(&[i; 32]);
        }
        let got = bucket_merkle_parent_n(&flat);
        let children: Vec<Hash256> = (0..3).map(|i: u8| [i; 32]).collect();
        let want = compute_parent_n(&children).to_vec();
        assert_eq!(got, want);
    }

    #[test]
    fn parent_n_rejects_odd_length() {
        // Not a multiple of 32: returns empty instead of panicking.
        assert!(bucket_merkle_parent_n(&[0u8; 33]).is_empty());
        assert!(bucket_merkle_parent_n(&[]).is_empty());
    }

    #[test]
    fn verifier_accepts_fully_cached_tree() {
        // 16 leaves → two-level arity-8 tree. With cache_from_level=0, the
        // sibling walk is a no-op and verification reduces to a tree-top walk.
        let leaves = arity8_leaves(16);
        let blob = build_full_cache_blob(&leaves);
        let tops = WasmBucketMerkleTreeTops::from_bytes(&blob).unwrap();
        assert_eq!(tops.tree_count(), 1);

        // bin_index = 5 → re-derive content as the test leaf did.
        let content = (5u64).to_le_bytes();
        // Empty sibling rows because cache_from_level = 0.
        let ok = verify_bucket_merkle_item(5, &content, 0, &[], &tops);
        assert!(ok, "verifier should accept a correct proof");
    }

    #[test]
    fn verifier_rejects_tampered_bin_content() {
        let leaves = arity8_leaves(16);
        let blob = build_full_cache_blob(&leaves);
        let tops = WasmBucketMerkleTreeTops::from_bytes(&blob).unwrap();

        // Wrong content → wrong leaf → different root.
        let ok = verify_bucket_merkle_item(5, b"bogus", 0, &[], &tops);
        assert!(!ok, "verifier should reject tampered content");
    }

    #[test]
    fn verifier_rejects_wrong_bin_index() {
        let leaves = arity8_leaves(16);
        let blob = build_full_cache_blob(&leaves);
        let tops = WasmBucketMerkleTreeTops::from_bytes(&blob).unwrap();

        // Right content for bin 5, but presented at bin 6 — the leaf prefix
        // bind fails.
        let content = (5u64).to_le_bytes();
        let ok = verify_bucket_merkle_item(6, &content, 0, &[], &tops);
        assert!(!ok, "verifier should reject a leaf presented at the wrong index");
    }

    #[test]
    fn verifier_rejects_out_of_range_group() {
        let leaves = arity8_leaves(16);
        let blob = build_full_cache_blob(&leaves);
        let tops = WasmBucketMerkleTreeTops::from_bytes(&blob).unwrap();

        let content = (5u64).to_le_bytes();
        let ok = verify_bucket_merkle_item(5, &content, /* pbc_group */ 99, &[], &tops);
        assert!(!ok, "out-of-range group should fail, not panic");
    }

    #[test]
    fn verifier_with_one_sibling_level() {
        // Build an 8-leaf tree manually: cache_from_level = 1 means the
        // client must XOR one sibling row before hitting the cached root.
        let leaves = arity8_leaves(8);
        let root = compute_parent_n(&leaves);

        // Serialise: one tree, cache_from_level=1, one cached level = [root].
        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes()); // num_trees
        blob.push(1u8); // cache_from_level = 1
        blob.extend_from_slice(&1u32.to_le_bytes()); // total_nodes
        blob.extend_from_slice(&8u16.to_le_bytes()); // arity
        blob.push(1u8); // num_cached_levels
        blob.extend_from_slice(&1u32.to_le_bytes()); // nodes at this level
        blob.extend_from_slice(&root);

        let tops = WasmBucketMerkleTreeTops::from_bytes(&blob).unwrap();
        assert_eq!(tops.cache_from_level(0), 1);
        assert_eq!(tops.root(0), root.to_vec());

        // The sibling row for item 3 is all 8 leaves XOR'd into position —
        // it contains the real 8 sibling hashes because the padded pass has
        // one real child at child_pos=3. The verifier substitutes its own
        // running hash at child_pos=3, so the row can legitimately carry
        // *any* value there; the rest must equal leaves[c] for c != 3.
        let mut row = Vec::with_capacity(BUCKET_MERKLE_SIB_ROW_SIZE);
        for (c, leaf) in leaves.iter().enumerate() {
            if c == 3 {
                // Slot the verifier ignores — stuff garbage in to prove it
                // isn't being read.
                row.extend_from_slice(&[0xAAu8; 32]);
            } else {
                row.extend_from_slice(leaf);
            }
        }

        let content = (3u64).to_le_bytes();
        let ok = verify_bucket_merkle_item(3, &content, 0, &row, &tops);
        assert!(ok, "verifier should accept correct sibling row");

        // Flip a byte in a sibling slot (NOT the one the verifier overwrites)
        // and confirm the walk fails.
        let mut bad_row = row.clone();
        bad_row[0] ^= 0x01;
        let ok = verify_bucket_merkle_item(3, &content, 0, &bad_row, &tops);
        assert!(!ok, "tampered sibling row must fail");
    }

    #[test]
    fn xor_buffers_equal_length() {
        let a = [0x0F, 0xF0, 0xAA];
        let b = [0xF0, 0x0F, 0x55];
        assert_eq!(xor_buffers(&a, &b), vec![0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn xor_buffers_length_mismatch() {
        assert!(xor_buffers(&[0u8; 3], &[0u8; 4]).is_empty());
    }

    #[test]
    fn short_sibling_rows_fail_gracefully() {
        let leaves = arity8_leaves(8);
        let root = compute_parent_n(&leaves);

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.push(1u8); // cache_from_level = 1 → needs 256B of sibling rows
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&8u16.to_le_bytes());
        blob.push(1u8);
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&root);
        let tops = WasmBucketMerkleTreeTops::from_bytes(&blob).unwrap();

        // Only 200B provided — fewer than one full row. Verifier must return
        // false rather than panic.
        let content = (3u64).to_le_bytes();
        let short_row = vec![0u8; 200];
        assert!(!verify_bucket_merkle_item(3, &content, 0, &short_row, &tops));
    }
}
