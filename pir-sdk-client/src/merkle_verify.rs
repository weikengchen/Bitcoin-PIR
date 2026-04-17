//! Per-bucket bin Merkle verification for native DPF clients.
//!
//! This mirrors the web TypeScript implementation in
//! `web/src/merkle-verify-bucket.ts`.
//!
//! Each PBC group (K=75 INDEX, K_CHUNK=80 CHUNK) has its own arity-8 Merkle
//! tree over the cuckoo bins. Sibling tables are flat (row = 8 × 32B child
//! hashes), indexed directly by `bin_index / 8` at each level.
//!
//! ## Flow
//!
//! 1. Compute `leaf = SHA256(bin_index_u32_LE || bin_content)` (see
//!    `pir_core::merkle::compute_bin_leaf_hash`).
//! 2. For each sibling level, issue a padded batch DPF query (`REQ_BUCKET_MERKLE_SIB_BATCH`
//!    = 0x33) across all K groups. Real queries target the group's current
//!    `node_idx / 8`; empty groups get random dummies so the server cannot
//!    distinguish real from padding (privacy requirement in CLAUDE.md).
//! 3. XOR server0 / server1 responses → 256-byte row of 8 child hashes.
//!    Replace the child at `node_idx % 8` with the running hash, recompute
//!    parent, and advance `node_idx /= 8`.
//! 4. Walk the per-group tree-top cache (fetched via `REQ_BUCKET_MERKLE_TREE_TOPS`
//!    = 0x34) to the root.
//! 5. Compare with the per-group root from the tree-top blob.
//!
//! ## Padding preservation
//!
//! Within each sibling-level round, exactly K (INDEX) / K_CHUNK (CHUNK) DPF
//! queries are sent — one per group. When two items share the same PBC group
//! (e.g. both cuckoo positions of a not-found query), we run multiple passes;
//! each pass is itself fully padded to K. Never optimize this away — it is a
//! privacy requirement, not an artifact.

use crate::transport::PirTransport;
use async_trait::async_trait;
use libdpf::Dpf;
use pir_core::merkle::{compute_bin_leaf_hash, compute_parent_n, Hash256, ZERO_HASH};
use pir_core::params::compute_dpf_n;
use pir_sdk::{PirError, PirResult};

use std::collections::HashMap;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Arity of the per-bucket bin Merkle tree (matches web client / pir-core).
pub const BUCKET_MERKLE_ARITY: usize = 8;

/// One sibling row is `arity × 32B = 256B` child hashes.
pub const BUCKET_MERKLE_SIB_ROW_SIZE: usize = BUCKET_MERKLE_ARITY * 32;

const REQ_BUCKET_MERKLE_SIB_BATCH: u8 = 0x33;
const RESP_BUCKET_MERKLE_SIB_BATCH: u8 = 0x33;
const REQ_BUCKET_MERKLE_TREE_TOPS: u8 = 0x34;
const RESP_BUCKET_MERKLE_TREE_TOPS: u8 = 0x34;

// ─── Types ──────────────────────────────────────────────────────────────────

/// One verifiable Merkle "item" — all bins that must pass for a single query
/// to be considered verified.
///
/// The mapping from scripthash queries to items is:
///
/// * FOUND query → exactly one item (one INDEX bin + N CHUNK bins).
/// * NOT-FOUND query → `INDEX_CUCKOO_NUM_HASHES` items, one per bin checked,
///   each with empty chunk vectors. All must pass to prove absence.
#[derive(Clone, Debug)]
pub struct BucketMerkleItem {
    /// PBC group for this INDEX bin (0..K-1).
    pub index_pbc_group: usize,
    /// Cuckoo bin index within the group (the leaf index in the group's tree).
    pub index_bin_index: u32,
    /// Raw XOR'd bin content from PIR (INDEX_SLOTS_PER_BIN × INDEX_SLOT_SIZE bytes).
    pub index_bin_content: Vec<u8>,
    /// Per-chunk PBC group (0..K_CHUNK-1).
    pub chunk_pbc_groups: Vec<usize>,
    /// Per-chunk bin index.
    pub chunk_bin_indices: Vec<u32>,
    /// Per-chunk XOR'd bin content (CHUNK_SLOTS_PER_BIN × CHUNK_SLOT_SIZE bytes).
    pub chunk_bin_contents: Vec<Vec<u8>>,
}

/// Parsed tree-top cache for one per-group Merkle tree.
#[derive(Clone, Debug)]
pub struct TreeTop {
    /// The sibling-level depth below the first cached level.
    /// Equals the number of DPF sibling rounds needed per item.
    pub cache_from_level: usize,
    /// Cached hashes, bottom-up. Last level is always `[root]` (length 1).
    pub levels: Vec<Vec<Hash256>>,
}

impl TreeTop {
    /// Returns the root hash for this group, or `None` if the top is empty.
    pub fn root(&self) -> Option<Hash256> {
        self.levels.last().and_then(|lvl| lvl.first().copied())
    }
}

// ─── Tree-top blob parsing ───────────────────────────────────────────────────

/// Parse the tree-tops blob returned by `REQ_BUCKET_MERKLE_TREE_TOPS`.
///
/// Wire format (matches server `runtime/src/bin/unified_server.rs` and
/// the TS parser in `web/src/merkle-verify-bucket.ts`):
///
/// ```text
/// [4B num_trees LE]
/// per tree:
///   [1B cache_from_level]
///   [4B total_nodes LE]       (informational, ignored)
///   [2B arity LE]             (always 8; informational)
///   [1B num_cached_levels]
///   per cached level:
///     [4B num_nodes LE]
///     [num_nodes × 32B hashes]
/// ```
///
/// The server emits K (INDEX) trees followed by K_CHUNK (CHUNK) trees,
/// in that order. Callers slice appropriately: INDEX at `[0..K)`, CHUNK at
/// `[K..K+K_CHUNK)`.
pub fn parse_tree_tops(data: &[u8]) -> PirResult<Vec<TreeTop>> {
    if data.len() < 4 {
        return Err(PirError::Decode("tree-tops blob too short".into()));
    }
    let num_trees = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut off = 4usize;
    let mut out = Vec::with_capacity(num_trees);

    for t in 0..num_trees {
        if off + 8 > data.len() {
            return Err(PirError::Decode(format!(
                "tree-tops: truncated header for tree {}",
                t
            )));
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
                return Err(PirError::Decode(format!(
                    "tree-tops: truncated level count for tree {} level {}",
                    t, lvl
                )));
            }
            let n = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            off += 4;
            if off + n * 32 > data.len() {
                return Err(PirError::Decode(format!(
                    "tree-tops: truncated hashes for tree {} level {}",
                    t, lvl
                )));
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

// ─── Wire format helpers ────────────────────────────────────────────────────

/// Encode a `REQ_BUCKET_MERKLE_TREE_TOPS` request.
///
/// Wire format:
/// * `db_id == 0`: `[4B len=1][0x34]`
/// * `db_id != 0`: `[4B len=2][0x34][db_id]`
///
/// (Matches the backward-compatible optional-trailing-byte convention used
/// throughout runtime/src/protocol.rs.)
pub fn encode_tree_tops_request(db_id: u8) -> Vec<u8> {
    let payload: &[u8] = if db_id != 0 {
        &[REQ_BUCKET_MERKLE_TREE_TOPS, db_id]
    } else {
        &[REQ_BUCKET_MERKLE_TREE_TOPS]
    };
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Encode a `REQ_BUCKET_MERKLE_SIB_BATCH` (0x33) request.
///
/// Wire layout — see `runtime/src/protocol.rs::encode_batch_query`:
///
/// ```text
/// [4B total_len LE]
/// [1B variant = 0x33]
/// [2B round_id LE]
/// [1B num_groups]
/// [1B keys_per_group = 1]
/// per group:
///   [2B key_len LE][key_bytes]
/// [1B db_id]                 (omitted when db_id == 0)
/// ```
pub fn encode_sibling_batch(db_id: u8, round_id: u16, keys_per_group: &[Vec<u8>]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(REQ_BUCKET_MERKLE_SIB_BATCH);
    payload.extend_from_slice(&round_id.to_le_bytes());
    payload.push(keys_per_group.len() as u8);
    payload.push(1u8); // 1 DPF key per group (flat table)
    for key in keys_per_group {
        payload.extend_from_slice(&(key.len() as u16).to_le_bytes());
        payload.extend_from_slice(key);
    }
    if db_id != 0 {
        payload.push(db_id);
    }

    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(&payload);
    buf
}

/// Decoded sibling-batch response: `[group][key_idx] = result_bytes`.
type SiblingResults = Vec<Vec<Vec<u8>>>;

/// Decode a `RESP_BUCKET_MERKLE_SIB_BATCH` (0x33) response.
///
/// Input is the payload AFTER the 4-byte length prefix (raw message body).
pub fn decode_sibling_batch(data: &[u8]) -> PirResult<SiblingResults> {
    if data.is_empty() {
        return Err(PirError::Decode("empty sibling response".into()));
    }
    match data[0] {
        RESP_BUCKET_MERKLE_SIB_BATCH => {}
        0xFF => {
            // RESP_ERROR in the middle of a Merkle sibling round is a
            // pipeline-level verification failure — by the time we're here
            // we've already fetched tree-tops successfully, so a mid-round
            // error means the server can't produce the sibling evidence
            // needed to verify. Surface as `MerkleVerificationFailed` so
            // callers can distinguish "untrusted data" from generic
            // server errors.
            if data.len() < 5 {
                return Err(PirError::MerkleVerificationFailed(
                    "bucket merkle: short error".into(),
                ));
            }
            let len = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
            let msg = String::from_utf8_lossy(&data[5..5 + len.min(data.len() - 5)]).to_string();
            return Err(PirError::MerkleVerificationFailed(format!(
                "bucket merkle: {}",
                msg
            )));
        }
        v => {
            return Err(PirError::Decode(format!(
                "unexpected sibling response variant: 0x{:02x}",
                v
            )))
        }
    }
    // Skip variant byte; body matches runtime/src/protocol.rs::decode_batch_result.
    let body = &data[1..];
    if body.len() < 4 {
        return Err(PirError::Decode("sibling batch body too short".into()));
    }
    let mut pos = 0;
    let _round_id = u16::from_le_bytes(body[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_groups = body[pos] as usize;
    pos += 1;
    let results_per_group = body[pos] as usize;
    pos += 1;
    let mut results = Vec::with_capacity(num_groups);
    for g in 0..num_groups {
        let mut group = Vec::with_capacity(results_per_group);
        for k in 0..results_per_group {
            if pos + 2 > body.len() {
                return Err(PirError::Decode(format!(
                    "sibling batch: truncated length for group {} key {}",
                    g, k
                )));
            }
            let len = u16::from_le_bytes(body[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + len > body.len() {
                return Err(PirError::Decode(format!(
                    "sibling batch: truncated data for group {} key {}",
                    g, k
                )));
            }
            group.push(body[pos..pos + len].to_vec());
            pos += len;
        }
        results.push(group);
    }
    Ok(results)
}

// ─── Fetch tree-tops ─────────────────────────────────────────────────────────

/// Fetch and parse the tree-tops blob from server 0.
///
/// Returns all trees concatenated: indices `[0..K)` are INDEX trees,
/// `[K..K+K_CHUNK)` are CHUNK trees (matching web client layout).
///
/// Takes `&mut dyn PirTransport` so tests can drive this against a mock
/// transport, and a future WASM build can plug in a `web-sys::WebSocket`
/// impl without changing this call site.
pub async fn fetch_tree_tops(
    conn0: &mut dyn PirTransport,
    db_id: u8,
) -> PirResult<Vec<TreeTop>> {
    let req = encode_tree_tops_request(db_id);
    conn0.send(req).await?;
    let raw = conn0.recv().await?;
    // Response: [4B len][1B variant=0x34][blob...]
    if raw.len() < 6 {
        return Err(PirError::Protocol(
            "tree-tops response too short".into(),
        ));
    }
    let variant = raw[4];
    if variant == 0xFF {
        // Catalog advertised `has_bucket_merkle = true` but the server
        // rejects the tree-tops request — that's a skew between what
        // the catalog claims and what the server actually implements.
        return Err(PirError::ProtocolSkew {
            expected: "bucket_merkle support (per catalog has_bucket_merkle=true)"
                .into(),
            actual: "RESP_ERROR from REQ_BUCKET_MERKLE_TREE_TOPS".into(),
        });
    }
    if variant != RESP_BUCKET_MERKLE_TREE_TOPS {
        return Err(PirError::UnexpectedResponse {
            expected: "RESP_BUCKET_MERKLE_TREE_TOPS",
            actual: format!("0x{:02x}", variant),
        });
    }
    parse_tree_tops(&raw[5..])
}

// ─── Sibling querier trait ──────────────────────────────────────────────────

/// Abstract one K-padded sibling-query round at a given Merkle level.
///
/// Separates the DPF- vs. HarmonyPIR-specific wire plumbing from the
/// shared Merkle-walk logic. Implementors are responsible for issuing
/// exactly one server round-trip covering `table_k = pass_targets.len()`
/// groups — both real targets and random/synthetic dummies — and
/// returning the XOR-reconstructed 256-byte sibling rows for the real
/// slots.
///
/// # Contract
///
/// * **`pass_targets[g] = Some(target_group_idx)`** — real query. `target_group_idx`
///   is the child-group index at this Merkle level (i.e. `node_idx / arity`).
///   The querier MUST send a genuine query for that index and return the
///   reconstructed row in `Ok(rows[g] = Some(..))`.
/// * **`pass_targets[g] = None`** — padding slot. The querier MUST still
///   issue a dummy query for that group (K-padding preservation is a
///   privacy requirement — see CLAUDE.md "Query Padding"). The returned
///   `rows[g]` must be `None`.
///
/// Returned rows MUST be exactly [`BUCKET_MERKLE_SIB_ROW_SIZE`] (= 256)
/// bytes; shorter rows are treated as an error and coerced to `ZERO_HASH`
/// by the caller.
///
/// `table_type` is `0` for INDEX trees and `1` for CHUNK trees. `level` is
/// the sibling level (0-indexed, bottom-up).
/// `level_bins_per_table` is the number of bins per group at *this* level
/// (= `ceil(main_bins / arity^(level+1))`). Querier impls that use DPF
/// internally need it to size the DPF domain; HarmonyPIR impls need it
/// when sizing/building group state.
#[async_trait]
pub trait BucketMerkleSiblingQuerier: Send {
    async fn query_pass(
        &mut self,
        table_type: u8,
        level: usize,
        level_bins_per_table: u32,
        pass_targets: &[Option<u32>],
        db_id: u8,
    ) -> PirResult<Vec<Option<Vec<u8>>>>;
}

// ─── DPF sibling querier ────────────────────────────────────────────────────

/// `BucketMerkleSiblingQuerier` impl that fulfils each pass with a two-server
/// DPF sibling batch (variant `REQ_BUCKET_MERKLE_SIB_BATCH = 0x33`).
///
/// Borrows both transports mutably for its lifetime so one pass = exactly
/// one request/response per server. Generic over `&mut dyn PirTransport` so
/// callers can plug in `WsConnection` (the production path) or any other
/// transport (tests, future WASM WebSocket impl).
pub struct DpfSiblingQuerier<'a> {
    conn0: &'a mut dyn PirTransport,
    conn1: &'a mut dyn PirTransport,
    dpf: Dpf,
    rng: SimpleRng,
}

impl<'a> DpfSiblingQuerier<'a> {
    pub fn new(
        conn0: &'a mut dyn PirTransport,
        conn1: &'a mut dyn PirTransport,
    ) -> Self {
        Self {
            conn0,
            conn1,
            dpf: Dpf::with_default_key(),
            rng: SimpleRng::new(),
        }
    }
}

#[async_trait]
impl BucketMerkleSiblingQuerier for DpfSiblingQuerier<'_> {
    async fn query_pass(
        &mut self,
        table_type: u8,
        level: usize,
        level_bins_per_table: u32,
        pass_targets: &[Option<u32>],
        db_id: u8,
    ) -> PirResult<Vec<Option<Vec<u8>>>> {
        let table_k = pass_targets.len();
        let num_groups_at_level = level_bins_per_table as u64;
        let level_dpf_n = compute_dpf_n(num_groups_at_level as usize);

        let mut s0_keys: Vec<Vec<u8>> = Vec::with_capacity(table_k);
        let mut s1_keys: Vec<Vec<u8>> = Vec::with_capacity(table_k);
        for target in pass_targets.iter() {
            let alpha = match *target {
                Some(t) => t as u64,
                None => {
                    if num_groups_at_level == 0 {
                        0
                    } else {
                        self.rng.next_u64() % num_groups_at_level
                    }
                }
            };
            let (k0, k1) = self.dpf.gen(alpha, level_dpf_n);
            s0_keys.push(k0.to_bytes());
            s1_keys.push(k1.to_bytes());
        }

        // round_id mirrors the TS convention: table_type * 100 + level.
        let round_id = (table_type as u16) * 100 + level as u16;
        let req0 = encode_sibling_batch(db_id, round_id, &s0_keys);
        let req1 = encode_sibling_batch(db_id, round_id, &s1_keys);
        self.conn0.send(req0).await?;
        self.conn1.send(req1).await?;
        let resp0_raw = self.conn0.recv().await?;
        let resp1_raw = self.conn1.recv().await?;
        if resp0_raw.len() < 4 || resp1_raw.len() < 4 {
            return Err(PirError::Protocol(
                "sibling response missing length prefix".into(),
            ));
        }
        let r0 = decode_sibling_batch(&resp0_raw[4..])?;
        let r1 = decode_sibling_batch(&resp1_raw[4..])?;

        let mut out: Vec<Option<Vec<u8>>> = vec![None; table_k];
        for (g, target) in pass_targets.iter().enumerate() {
            if target.is_none() {
                continue;
            }
            if g >= r0.len() || g >= r1.len() || r0[g].is_empty() || r1[g].is_empty() {
                // Let the caller handle the missing row by coercing to ZERO_HASH.
                continue;
            }
            let mut row = r0[g][0].clone();
            xor_into(&mut row, &r1[g][0]);
            out[g] = Some(row);
        }
        Ok(out)
    }
}

// ─── Main verification ──────────────────────────────────────────────────────

/// Batch-verify per-bucket bin Merkle proofs using DPF sibling queries.
///
/// Convenience wrapper: builds a [`DpfSiblingQuerier`] and calls
/// [`verify_bucket_merkle_batch_generic`]. See that function for details.
///
/// Preserves K / K_CHUNK query padding at every sibling level. When two items
/// share a PBC group, multiple passes are run — each pass itself padded.
#[allow(clippy::too_many_arguments)]
pub async fn verify_bucket_merkle_batch_dpf(
    conn0: &mut dyn PirTransport,
    conn1: &mut dyn PirTransport,
    items: &[BucketMerkleItem],
    index_bins: u32,
    chunk_bins: u32,
    index_k: usize,
    chunk_k: usize,
    db_id: u8,
    tree_tops: &[TreeTop],
) -> PirResult<Vec<bool>> {
    let mut querier = DpfSiblingQuerier::new(conn0, conn1);
    verify_bucket_merkle_batch_generic(
        &mut querier,
        items,
        index_bins,
        chunk_bins,
        index_k,
        chunk_k,
        db_id,
        tree_tops,
    )
    .await
}

/// Backend-agnostic per-bucket Merkle batch verifier.
///
/// Drives the shared sibling-walk via an arbitrary
/// [`BucketMerkleSiblingQuerier`]. Used directly by the HarmonyPIR client;
/// [`verify_bucket_merkle_batch_dpf`] wraps it with a DPF-specific querier.
///
/// # Parameters
///
/// * `querier` — per-pass sibling fetcher. See the trait docs.
/// * `items` — one per bin to verify (multiple per query for not-found proofs).
/// * `index_bins` — bins per table at the INDEX level (`DatabaseInfo::index_bins`).
/// * `chunk_bins` — bins per table at the CHUNK level.
/// * `index_k`, `chunk_k` — K and K_CHUNK from `DatabaseInfo`.
/// * `db_id` — active database id.
/// * `tree_tops` — parsed tree-tops blob (exactly `index_k + chunk_k` entries).
///
/// # Returns
///
/// `Vec<bool>` of length `items.len()`; `true` iff the item's Merkle path
/// reconstructs to the expected per-group root.
#[allow(clippy::too_many_arguments)]
pub async fn verify_bucket_merkle_batch_generic(
    querier: &mut dyn BucketMerkleSiblingQuerier,
    items: &[BucketMerkleItem],
    index_bins: u32,
    chunk_bins: u32,
    index_k: usize,
    chunk_k: usize,
    db_id: u8,
    tree_tops: &[TreeTop],
) -> PirResult<Vec<bool>> {
    if tree_tops.len() < index_k + chunk_k {
        // Catalog declared K_INDEX / K_CHUNK but the server's tree-tops
        // blob has fewer entries — client and server disagree on the
        // PBC group count. This is a version/feature skew, not a
        // transient wire corruption.
        return Err(PirError::ProtocolSkew {
            expected: format!(
                "at least {} tree-top entries (K_INDEX={}, K_CHUNK={})",
                index_k + chunk_k,
                index_k,
                chunk_k
            ),
            actual: format!("{} tree-top entries", tree_tops.len()),
        });
    }

    log::info!(
        "[PIR-AUDIT] Merkle verify: {} items (K_INDEX={}, K_CHUNK={}, arity={})",
        items.len(),
        index_k,
        chunk_k,
        BUCKET_MERKLE_ARITY
    );

    // ── Step 1: INDEX verification ─────────────────────────────────────
    let index_sub_items: Vec<SubItem> = items
        .iter()
        .map(|it| SubItem {
            pbc_group: it.index_pbc_group,
            bin_index: it.index_bin_index,
            bin_content: it.index_bin_content.clone(),
        })
        .collect();

    log::info!(
        "[PIR-AUDIT] Merkle INDEX: verifying {} bins across {} groups",
        index_sub_items.len(),
        index_k
    );

    let index_verified = verify_sibling_levels(
        querier,
        &index_sub_items,
        index_bins,
        index_k,
        /* table_type = */ 0,
        &tree_tops[..index_k],
        db_id,
    )
    .await?;

    // ── Step 2: CHUNK verification ─────────────────────────────────────
    let mut chunk_sub_items: Vec<SubItem> = Vec::new();
    // Map chunk_sub_items index → (outer item index, which chunk within).
    let mut chunk_item_map: Vec<(usize, usize)> = Vec::new();
    for (i, it) in items.iter().enumerate() {
        for c in 0..it.chunk_pbc_groups.len() {
            chunk_sub_items.push(SubItem {
                pbc_group: it.chunk_pbc_groups[c],
                bin_index: it.chunk_bin_indices[c],
                bin_content: it.chunk_bin_contents[c].clone(),
            });
            chunk_item_map.push((i, c));
        }
    }

    log::info!(
        "[PIR-AUDIT] Merkle CHUNK: verifying {} bins across {} groups",
        chunk_sub_items.len(),
        chunk_k
    );

    let chunk_verified = if chunk_sub_items.is_empty() {
        Vec::new()
    } else {
        verify_sibling_levels(
            querier,
            &chunk_sub_items,
            chunk_bins,
            chunk_k,
            /* table_type = */ 1,
            &tree_tops[index_k..index_k + chunk_k],
            db_id,
        )
        .await?
    };

    // ── Step 3: Combine results ────────────────────────────────────────
    let mut result = vec![true; items.len()];
    for (i, ok) in index_verified.iter().enumerate() {
        if !ok {
            result[i] = false;
        }
    }
    for (j, ok) in chunk_verified.iter().enumerate() {
        if !ok {
            let (i, _) = chunk_item_map[j];
            result[i] = false;
        }
    }

    let passed = result.iter().filter(|&&v| v).count();
    let failed = result.len() - passed;
    if failed == 0 {
        log::info!(
            "[PIR-AUDIT] Merkle verify: {}/{} PASSED",
            passed,
            result.len()
        );
    } else {
        log::warn!(
            "[PIR-AUDIT] Merkle verify: {}/{} passed, {} FAILED",
            passed,
            result.len(),
            failed
        );
    }

    Ok(result)
}

// ─── Per-table-type sibling walk ────────────────────────────────────────────

/// A flattened (pbc_group, bin_index, bin_content) triple used internally.
#[derive(Clone)]
struct SubItem {
    pbc_group: usize,
    bin_index: u32,
    bin_content: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
async fn verify_sibling_levels(
    querier: &mut dyn BucketMerkleSiblingQuerier,
    items: &[SubItem],
    bins: u32,
    table_k: usize,
    table_type: u8,
    tree_tops: &[TreeTop],
    db_id: u8,
) -> PirResult<Vec<bool>> {
    let arity = BUCKET_MERKLE_ARITY;
    let n_items = items.len();

    // Per-item running state.
    let mut current_hash: Vec<Hash256> = Vec::with_capacity(n_items);
    let mut node_idx: Vec<u32> = Vec::with_capacity(n_items);
    for it in items {
        current_hash.push(compute_bin_leaf_hash(it.bin_index, &it.bin_content));
        node_idx.push(it.bin_index);
    }

    // Group items by PBC group. Multiple items share a group only for the
    // INDEX-not-found case (both cuckoo positions); K-padding is still
    // preserved because each pass sends its own fully-padded batch.
    let mut items_by_group: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, it) in items.iter().enumerate() {
        items_by_group.entry(it.pbc_group).or_default().push(i);
    }
    let max_items_per_group = items_by_group
        .values()
        .map(|v| v.len())
        .max()
        .unwrap_or(1);

    // Compute per-level group count (bins_per_table at each Merkle level).
    // This MUST match the server's table layout exactly.
    let max_sib_levels = tree_tops
        .iter()
        .map(|t| t.cache_from_level)
        .max()
        .unwrap_or(0);
    let mut level_groups_count: Vec<u32> = Vec::with_capacity(max_sib_levels);
    {
        let mut nodes: u64 = bins as u64;
        for _ in 0..max_sib_levels {
            let groups = nodes.div_ceil(arity as u64);
            level_groups_count.push(groups as u32);
            nodes = groups;
        }
    }

    // For each sibling level, run `max_items_per_group` passes. Each pass is
    // itself K-padded: the querier sends one (real or dummy) sub-request per
    // group for every slot.
    for (level, &groups_at_level) in level_groups_count.iter().enumerate() {
        for pass in 0..max_items_per_group {
            // Select the item handled in this pass for each group.
            let mut pass_group_to_item: HashMap<usize, usize> = HashMap::new();
            for (&g, arr) in &items_by_group {
                if pass < arr.len() {
                    pass_group_to_item.insert(g, arr[pass]);
                }
            }

            // Build per-group targets: Some(target_child_idx) or None for padding.
            let pass_targets: Vec<Option<u32>> = (0..table_k)
                .map(|g| {
                    pass_group_to_item
                        .get(&g)
                        .map(|&item_idx| node_idx[item_idx] / arity as u32)
                })
                .collect();

            // Send one K-padded pass via the querier.
            let rows = querier
                .query_pass(table_type, level, groups_at_level, &pass_targets, db_id)
                .await?;

            // ── Update running hashes for this pass ────────────────────
            for (&g, &item_idx) in &pass_group_to_item {
                let row_opt = rows.get(g).and_then(|r| r.as_ref());
                let Some(row) = row_opt else {
                    log::warn!(
                        "[PIR-AUDIT] Merkle L{} pass {}: missing sibling row for group {} (item {})",
                        level, pass, g, item_idx
                    );
                    current_hash[item_idx] = ZERO_HASH;
                    continue;
                };
                if row.len() < BUCKET_MERKLE_SIB_ROW_SIZE {
                    log::warn!(
                        "[PIR-AUDIT] Merkle L{} group {}: sibling row too short ({} bytes, need {})",
                        level,
                        g,
                        row.len(),
                        BUCKET_MERKLE_SIB_ROW_SIZE
                    );
                    current_hash[item_idx] = ZERO_HASH;
                    continue;
                }

                let child_pos = (node_idx[item_idx] as usize) % arity;
                let mut children: Vec<Hash256> = Vec::with_capacity(arity);
                for c in 0..arity {
                    if c == child_pos {
                        children.push(current_hash[item_idx]);
                    } else {
                        let off = c * 32;
                        let mut h: Hash256 = ZERO_HASH;
                        h.copy_from_slice(&row[off..off + 32]);
                        children.push(h);
                    }
                }
                current_hash[item_idx] = compute_parent_n(&children);
                node_idx[item_idx] /= arity as u32;
            }
        }
    }

    // ── Walk tree-top cache to root for each item ──────────────────────
    let mut verified = Vec::with_capacity(n_items);
    for i in 0..n_items {
        let g = items[i].pbc_group;
        let Some(top) = tree_tops.get(g) else {
            log::warn!(
                "[PIR-AUDIT] Merkle: no tree-top for group {} (item {})",
                g,
                i
            );
            verified.push(false);
            continue;
        };

        let mut hash = current_hash[i];
        let mut idx = node_idx[i];

        if top.levels.is_empty() {
            log::warn!("[PIR-AUDIT] Merkle: tree-top for group {} is empty", g);
            verified.push(false);
            continue;
        }

        // Walk cached levels except the last (which IS the root).
        let cached_len = top.levels.len();
        for cl in 0..cached_len.saturating_sub(1) {
            let level_nodes = &top.levels[cl];
            let parent_start = (idx / arity as u32) * arity as u32;
            let child_pos = (idx as usize) % arity;
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
            idx /= arity as u32;
        }

        let expected_root = top.root().unwrap_or(ZERO_HASH);
        let ok = hash == expected_root;
        if !ok {
            log::warn!(
                "[PIR-AUDIT] Merkle: group {} item {} root MISMATCH (got {:02x}{:02x}{:02x}{:02x}..., expected {:02x}{:02x}{:02x}{:02x}...)",
                g,
                i,
                hash[0],
                hash[1],
                hash[2],
                hash[3],
                expected_root[0],
                expected_root[1],
                expected_root[2],
                expected_root[3],
            );
        }
        verified.push(ok);
    }

    Ok(verified)
}

// ─── Utilities ──────────────────────────────────────────────────────────────

pub(crate) fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// Same splitmix64-based PRNG as `dpf.rs::SimpleRng`.
/// Duplicated here to keep this module self-contained (it's tiny).
pub(crate) struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub(crate) fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self {
            state: pir_core::hash::splitmix64(seed.wrapping_add(0xbadc0ffee0ddf00d)),
        }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        pir_core::hash::splitmix64(self.state)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pir_core::merkle::{compute_bin_leaf_hash, MerkleTreeN};

    /// Build a small per-group Merkle tree, turn it into a `TreeTop` that
    /// caches the entire tree (so there are zero sibling levels to query),
    /// and verify that `walk_tree_top_to_root` (inlined here) matches.
    fn build_full_cache_top(tree: &MerkleTreeN) -> TreeTop {
        // Cache EVERY level so the sibling-query phase does nothing.
        TreeTop {
            cache_from_level: 0,
            levels: tree.levels.clone(),
        }
    }

    /// Walk a tree-top only (no sibling levels) from leaf to root, matching
    /// the logic in `verify_sibling_levels`. Used to exercise the top-walk.
    fn walk_top_only(
        leaf_hash: Hash256,
        mut idx: u32,
        top: &TreeTop,
    ) -> Hash256 {
        let arity = BUCKET_MERKLE_ARITY;
        let mut hash = leaf_hash;
        for cl in 0..top.levels.len().saturating_sub(1) {
            let level_nodes = &top.levels[cl];
            let parent_start = (idx / arity as u32) * arity as u32;
            let child_pos = (idx as usize) % arity;
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
            idx /= arity as u32;
        }
        hash
    }

    #[test]
    fn test_tree_tops_roundtrip_empty() {
        // Zero trees.
        let blob = 0u32.to_le_bytes().to_vec();
        let tops = parse_tree_tops(&blob).unwrap();
        assert!(tops.is_empty());
    }

    #[test]
    fn test_tree_tops_parse_truncated() {
        // Claims 1 tree but no bytes follow.
        let blob = 1u32.to_le_bytes().to_vec();
        assert!(parse_tree_tops(&blob).is_err());
    }

    #[test]
    fn test_encode_tree_tops_request_no_db() {
        let req = encode_tree_tops_request(0);
        assert_eq!(req, vec![1, 0, 0, 0, REQ_BUCKET_MERKLE_TREE_TOPS]);
    }

    #[test]
    fn test_encode_tree_tops_request_with_db() {
        let req = encode_tree_tops_request(7);
        assert_eq!(req, vec![2, 0, 0, 0, REQ_BUCKET_MERKLE_TREE_TOPS, 7]);
    }

    #[test]
    fn test_encode_sibling_batch_layout() {
        // One key per group, 2 groups.
        let keys = vec![vec![0xAAu8, 0xBB], vec![0xCCu8]];
        let req = encode_sibling_batch(/* db_id */ 0, /* round_id */ 3, &keys);
        // Payload: [0x33][3 0][2][1][2 0][AA BB][1 0][CC]
        // Expected total payload length = 1 + 2 + 1 + 1 + (2+2) + (2+1) = 12
        assert_eq!(&req[0..4], &[12, 0, 0, 0]);
        assert_eq!(req[4], REQ_BUCKET_MERKLE_SIB_BATCH);
        assert_eq!(&req[5..7], &[3, 0]); // round_id LE
        assert_eq!(req[7], 2); // num_groups
        assert_eq!(req[8], 1); // keys_per_group
        assert_eq!(&req[9..11], &[2, 0]); // key_len = 2
        assert_eq!(&req[11..13], &[0xAA, 0xBB]);
        assert_eq!(&req[13..15], &[1, 0]); // key_len = 1
        assert_eq!(req[15], 0xCC);
        // Total message = 4-byte length prefix + 12-byte payload
        assert_eq!(req.len(), 16);
    }

    #[test]
    fn test_decode_sibling_batch_roundtrip() {
        // Build a minimal valid response: 2 groups, 1 key each.
        let mut body = vec![RESP_BUCKET_MERKLE_SIB_BATCH];
        body.extend_from_slice(&0u16.to_le_bytes()); // round_id
        body.push(2); // num_groups
        body.push(1); // results_per_group
        for data in [&[1u8, 2, 3][..], &[0xAA, 0xBB, 0xCC, 0xDD][..]] {
            body.extend_from_slice(&(data.len() as u16).to_le_bytes());
            body.extend_from_slice(data);
        }
        let out = decode_sibling_batch(&body).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].len(), 1);
        assert_eq!(out[0][0], vec![1, 2, 3]);
        assert_eq!(out[1][0], vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_decode_sibling_batch_error_variant() {
        use pir_sdk::ErrorKind;
        let msg = b"not supported";
        let mut body = vec![0xFF];
        body.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        body.extend_from_slice(msg);
        let err = decode_sibling_batch(&body).unwrap_err();
        // Mid-Merkle-round server error ⇒ MerkleVerificationFailed so
        // callers can distinguish untrusted data from generic server
        // errors via `PirError::kind()`.
        assert!(matches!(err, PirError::MerkleVerificationFailed(_)));
        assert_eq!(err.kind(), ErrorKind::MerkleVerificationFailed);
    }

    #[test]
    fn test_bin_leaf_hash_matches_pir_core() {
        let content = vec![0u8; 68];
        let leaf = compute_bin_leaf_hash(42, &content);
        // Sanity: hashing again yields the same thing.
        assert_eq!(leaf, compute_bin_leaf_hash(42, &content));
        // And a different bin_index produces a different hash.
        assert_ne!(leaf, compute_bin_leaf_hash(43, &content));
    }

    /// End-to-end proof walk using only the tree-top cache (no sibling rounds).
    /// This exercises the top-walk logic directly, which is the same code path
    /// used after sibling rounds complete.
    #[test]
    fn test_verify_good_proof_top_only() {
        // 64 leaves, fully cached → 0 sibling levels required.
        let bin_contents: Vec<Vec<u8>> = (0..64u32).map(|i| vec![i as u8; 68]).collect();
        let leaves: Vec<Hash256> = bin_contents
            .iter()
            .enumerate()
            .map(|(i, c)| compute_bin_leaf_hash(i as u32, c))
            .collect();
        let tree = MerkleTreeN::build(&leaves, BUCKET_MERKLE_ARITY);
        let top = build_full_cache_top(&tree);

        for (i, c) in bin_contents.iter().enumerate() {
            let leaf = compute_bin_leaf_hash(i as u32, c);
            let computed_root = walk_top_only(leaf, i as u32, &top);
            assert_eq!(&computed_root, tree.root(), "leaf {} mismatch", i);
        }
    }

    /// Same tree, but walk with TAMPERED content — proof must fail.
    #[test]
    fn test_verify_bad_proof_tampered_content() {
        let bin_contents: Vec<Vec<u8>> = (0..64u32).map(|i| vec![i as u8; 68]).collect();
        let leaves: Vec<Hash256> = bin_contents
            .iter()
            .enumerate()
            .map(|(i, c)| compute_bin_leaf_hash(i as u32, c))
            .collect();
        let tree = MerkleTreeN::build(&leaves, BUCKET_MERKLE_ARITY);
        let top = build_full_cache_top(&tree);

        // Flip one byte of the content for leaf 7.
        let mut tampered = bin_contents[7].clone();
        tampered[0] ^= 0x01;
        let tampered_leaf = compute_bin_leaf_hash(7, &tampered);
        let computed_root = walk_top_only(tampered_leaf, 7, &top);
        assert_ne!(&computed_root, tree.root());
    }

    /// Walking the proof with a WRONG bin_index (tampering with position) fails.
    #[test]
    fn test_verify_bad_proof_wrong_index() {
        let bin_contents: Vec<Vec<u8>> = (0..64u32).map(|i| vec![i as u8; 68]).collect();
        let leaves: Vec<Hash256> = bin_contents
            .iter()
            .enumerate()
            .map(|(i, c)| compute_bin_leaf_hash(i as u32, c))
            .collect();
        let tree = MerkleTreeN::build(&leaves, BUCKET_MERKLE_ARITY);
        let top = build_full_cache_top(&tree);

        // Use content for leaf 3 but claim it's at index 4 — the leaf hash
        // itself will differ because bin_index is part of the hash.
        let wrong_leaf = compute_bin_leaf_hash(4, &bin_contents[3]);
        let computed_root = walk_top_only(wrong_leaf, 4, &top);
        assert_ne!(&computed_root, tree.root());
    }

    /// Partial cache walk: caches top 2 levels, leaves bottom levels to the
    /// caller to walk via simulated sibling hashes.
    #[test]
    fn test_partial_cache_walk_matches_pir_core_verify_proof_n() {
        let bin_contents: Vec<Vec<u8>> = (0..64u32).map(|i| vec![i as u8; 68]).collect();
        let leaves: Vec<Hash256> = bin_contents
            .iter()
            .enumerate()
            .map(|(i, c)| compute_bin_leaf_hash(i as u32, c))
            .collect();
        let tree = MerkleTreeN::build(&leaves, BUCKET_MERKLE_ARITY);

        // Build a partial top that only caches level 1 and root (level 2).
        // depth = log_8(64) = 2, so levels = [level0 (64 leaves), level1 (8 parents), level2 (root)].
        assert_eq!(tree.levels.len(), 3);
        let top = TreeTop {
            cache_from_level: 1,
            levels: tree.levels[1..].to_vec(),
        };

        for target_leaf in [0u32, 7, 13, 42, 63] {
            let leaf_hash = leaves[target_leaf as usize];
            // Simulate a single sibling round: reconstruct the parent at level 0
            // by using the known sibling hashes.
            let arity = BUCKET_MERKLE_ARITY as u32;
            let parent_start = (target_leaf / arity) * arity;
            let child_pos = (target_leaf % arity) as usize;
            let mut children: Vec<Hash256> = Vec::with_capacity(arity as usize);
            for c in 0..arity as usize {
                let leaf_i = (parent_start as usize) + c;
                if c == child_pos {
                    children.push(leaf_hash);
                } else {
                    children.push(leaves[leaf_i]);
                }
            }
            let parent_hash = compute_parent_n(&children);
            let parent_idx = target_leaf / arity;

            // Now walk the top cache from that parent.
            let root = walk_top_only(parent_hash, parent_idx, &top);
            assert_eq!(&root, tree.root());
        }
    }
}
