//! Sync planning and delta merging.
//!
//! This module provides:
//! - `compute_sync_plan()`: Find optimal path from current height to tip
//! - `merge_delta()`: Apply delta data to a snapshot result
//!
//! The sync algorithm uses BFS to find the shortest delta chain, with a
//! maximum chain length of 5 steps. Longer chains fall back to a full snapshot.

use crate::error::{PirError, PirResult};
use crate::types::{DatabaseCatalog, DatabaseInfo, DatabaseKind, QueryResult, UtxoEntry};
use std::collections::{HashMap, VecDeque};

/// Maximum number of delta steps in a chain before falling back to full snapshot.
pub const MAX_DELTA_CHAIN_LENGTH: usize = 5;

/// A single step in a sync plan.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyncStep {
    /// Database ID to query.
    pub db_id: u8,
    /// Database kind (full or delta).
    pub kind: DatabaseKind,
    /// Database name.
    pub name: String,
    /// Base height (0 for full snapshots).
    pub base_height: u32,
    /// Tip height after this step.
    pub tip_height: u32,
}

impl SyncStep {
    /// Create a step from a DatabaseInfo.
    pub fn from_db_info(db: &DatabaseInfo) -> Self {
        Self {
            db_id: db.db_id,
            kind: db.kind,
            name: db.name.clone(),
            base_height: db.base_height(),
            tip_height: db.height,
        }
    }

    /// Returns true if this is a full snapshot step.
    pub fn is_full(&self) -> bool {
        self.kind.is_full()
    }

    /// Returns true if this is a delta step.
    pub fn is_delta(&self) -> bool {
        self.kind.is_delta()
    }
}

/// A complete sync plan.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SyncPlan {
    /// Steps to execute (in order).
    pub steps: Vec<SyncStep>,
    /// Whether this is a fresh sync (starts from full snapshot).
    pub is_fresh_sync: bool,
    /// Target height after executing all steps.
    pub target_height: u32,
}

impl SyncPlan {
    /// Create an empty plan (already at tip).
    pub fn empty(current_height: u32) -> Self {
        Self {
            steps: Vec::new(),
            is_fresh_sync: false,
            target_height: current_height,
        }
    }

    /// Returns true if no steps are needed.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Number of steps in the plan.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Get a step by index.
    pub fn get(&self, index: usize) -> Option<&SyncStep> {
        self.steps.get(index)
    }

    /// Iterate over steps.
    pub fn iter(&self) -> impl Iterator<Item = &SyncStep> {
        self.steps.iter()
    }
}

/// Compute an optimal sync plan from `last_height` to the catalog tip.
///
/// # Algorithm
///
/// 1. **Fresh sync** (`last_height` is `None` or 0):
///    - Pick the highest full snapshot
///    - Chain deltas from that snapshot to the catalog tip
///
/// 2. **Incremental sync**:
///    - If `last_height` == catalog tip, return empty plan
///    - Try BFS to find delta chain from `last_height` to tip
///    - If chain is too long (> MAX_DELTA_CHAIN_LENGTH) or doesn't exist,
///      fall back to full snapshot + deltas
///
/// # Arguments
///
/// * `catalog` - Database catalog from server
/// * `last_height` - Last synced height, or `None` for fresh sync
///
/// # Returns
///
/// A sync plan with steps to execute.
pub fn compute_sync_plan(catalog: &DatabaseCatalog, last_height: Option<u32>) -> PirResult<SyncPlan> {
    let latest_tip = catalog
        .latest_tip()
        .ok_or_else(|| PirError::InvalidCatalog("empty catalog".into()))?;

    let last = last_height.unwrap_or(0);

    // Already at tip?
    if last > 0 && last >= latest_tip {
        return Ok(SyncPlan::empty(last));
    }

    // Fresh sync: start from best full snapshot
    if last == 0 {
        return compute_fresh_sync_plan(catalog, latest_tip);
    }

    // Incremental sync: try delta chain first
    if let Some(chain) = find_delta_chain(catalog, last, latest_tip) {
        if chain.len() <= MAX_DELTA_CHAIN_LENGTH {
            let steps: Vec<SyncStep> = chain.iter().map(|db| SyncStep::from_db_info(db)).collect();
            return Ok(SyncPlan {
                steps,
                is_fresh_sync: false,
                target_height: latest_tip,
            });
        }
    }

    // Fall back to fresh sync
    compute_fresh_sync_plan(catalog, latest_tip)
}

/// Compute a fresh sync plan starting from the best full snapshot.
fn compute_fresh_sync_plan(catalog: &DatabaseCatalog, latest_tip: u32) -> PirResult<SyncPlan> {
    let best_full = catalog
        .best_full_snapshot()
        .ok_or_else(|| PirError::NoSyncPath("no full snapshot available".into()))?;

    let mut steps = vec![SyncStep::from_db_info(best_full)];

    // Chain deltas from the snapshot to the tip
    if best_full.height < latest_tip {
        if let Some(chain) = find_delta_chain(catalog, best_full.height, latest_tip) {
            for db in &chain {
                steps.push(SyncStep::from_db_info(db));
            }
        }
        // Note: if no delta chain exists, we just return the snapshot
        // (the tip might be the snapshot height in this case)
    }

    let target_height = steps.last().map(|s| s.tip_height).unwrap_or(best_full.height);
    Ok(SyncPlan {
        steps,
        is_fresh_sync: true,
        target_height,
    })
}

/// Find a delta chain from `start_height` to `end_height` using BFS.
///
/// Returns `None` if no path exists.
fn find_delta_chain<'a>(
    catalog: &'a DatabaseCatalog,
    start_height: u32,
    end_height: u32,
) -> Option<Vec<&'a DatabaseInfo>> {
    if start_height >= end_height {
        return Some(Vec::new());
    }

    // Build adjacency map: base_height -> list of deltas starting at that height
    let mut by_base: HashMap<u32, Vec<&DatabaseInfo>> = HashMap::new();
    for db in catalog.deltas() {
        by_base.entry(db.base_height()).or_default().push(db);
    }

    // BFS to find shortest path
    let mut queue: VecDeque<(u32, Vec<&DatabaseInfo>)> = VecDeque::new();
    let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();

    queue.push_back((start_height, Vec::new()));
    visited.insert(start_height);

    while let Some((height, path)) = queue.pop_front() {
        if height >= end_height {
            return Some(path);
        }

        // Don't search too deep
        if path.len() >= MAX_DELTA_CHAIN_LENGTH + 1 {
            continue;
        }

        if let Some(deltas) = by_base.get(&height) {
            for delta in deltas {
                if !visited.contains(&delta.height) {
                    visited.insert(delta.height);
                    let mut new_path = path.clone();
                    new_path.push(*delta);
                    if delta.height >= end_height {
                        return Some(new_path);
                    }
                    queue.push_back((delta.height, new_path));
                }
            }
        }
    }

    None
}

// ─── Delta Merging ──────────────────────────────────────────────────────────

/// Decoded delta data from a delta query result.
#[derive(Clone, Debug, Default)]
pub struct DeltaData {
    /// Outpoints that were spent (txid || vout_le, 36 bytes each).
    pub spent: Vec<[u8; 36]>,
    /// New UTXOs added.
    pub new_utxos: Vec<UtxoEntry>,
}

/// Decode delta data from raw chunk bytes.
///
/// Delta format:
/// ```text
/// [varint num_spent]
/// [num_spent × 36B spent outpoints]
/// [varint num_new]
/// [num_new × (32B txid + 4B vout_le + 8B amount_le)]
/// ```
pub fn decode_delta_data(raw: &[u8]) -> PirResult<DeltaData> {
    let mut pos = 0;

    // Read num_spent as varint
    let (num_spent, consumed) = read_varint(&raw[pos..])?;
    pos += consumed;

    // Read spent outpoints
    let mut spent = Vec::with_capacity(num_spent as usize);
    for _ in 0..num_spent {
        if pos + 36 > raw.len() {
            return Err(PirError::Decode("truncated spent outpoint".into()));
        }
        let mut outpoint = [0u8; 36];
        outpoint.copy_from_slice(&raw[pos..pos + 36]);
        spent.push(outpoint);
        pos += 36;
    }

    // Read num_new as varint
    let (num_new, consumed) = read_varint(&raw[pos..])?;
    pos += consumed;

    // Read new UTXOs
    let mut new_utxos = Vec::with_capacity(num_new as usize);
    for _ in 0..num_new {
        if pos + 44 > raw.len() {
            return Err(PirError::Decode("truncated new UTXO".into()));
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&raw[pos..pos + 32]);
        pos += 32;

        let vout = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let amount_sats = u64::from_le_bytes(raw[pos..pos + 8].try_into().unwrap());
        pos += 8;

        new_utxos.push(UtxoEntry { txid, vout, amount_sats });
    }

    Ok(DeltaData { spent, new_utxos })
}

/// Read a varint from the buffer, returning (value, bytes_consumed).
fn read_varint(buf: &[u8]) -> PirResult<(u64, usize)> {
    if buf.is_empty() {
        return Err(PirError::Decode("empty varint".into()));
    }

    let mut value: u64 = 0;
    let mut shift = 0;
    let mut pos = 0;

    loop {
        if pos >= buf.len() {
            return Err(PirError::Decode("truncated varint".into()));
        }
        let byte = buf[pos];
        pos += 1;

        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(PirError::Decode("varint overflow".into()));
        }
    }

    Ok((value, pos))
}

/// Merge delta data into a snapshot result.
///
/// This applies the delta's spent/new UTXOs to produce an updated result:
/// 1. Remove any UTXOs whose outpoints are in `delta.spent`
/// 2. Append `delta.new_utxos` to the remaining entries
///
/// # Arguments
///
/// * `snapshot` - The snapshot result to update
/// * `delta_raw` - Raw delta chunk data from the delta query
///
/// # Returns
///
/// A new QueryResult with the delta applied.
pub fn merge_delta(snapshot: &QueryResult, delta_raw: &[u8]) -> PirResult<QueryResult> {
    if delta_raw.is_empty() {
        return Ok(snapshot.clone());
    }

    let delta = decode_delta_data(delta_raw)?;
    let merged = apply_delta_data(&snapshot.entries, &delta);

    Ok(QueryResult {
        entries: merged,
        is_whale: snapshot.is_whale,
        // Inherit the snapshot's verification status. Callers that have
        // separately verified the delta should AND in its `merkle_verified`
        // on the returned value; `merge_delta_batch` does this automatically.
        merkle_verified: snapshot.merkle_verified,
        raw_chunk_data: None,
        // Inspector fields stay empty after a merge — the Merkle-trace view
        // is per-query, not per-merged-history, and re-verifying a merged
        // result would require re-querying anyway.
        index_bins: Vec::new(),
        chunk_bins: Vec::new(),
        matched_index_idx: None,
    })
}

/// Apply delta data to an entry list (pure function).
fn apply_delta_data(entries: &[UtxoEntry], delta: &DeltaData) -> Vec<UtxoEntry> {
    // Build a set of spent outpoints for O(1) lookup
    let spent_set: std::collections::HashSet<[u8; 36]> = delta.spent.iter().copied().collect();

    // Filter out spent entries
    let mut result: Vec<UtxoEntry> = entries
        .iter()
        .filter(|e| !spent_set.contains(&e.outpoint()))
        .cloned()
        .collect();

    // Append new UTXOs
    result.extend(delta.new_utxos.iter().cloned());

    result
}

/// Merge delta batch results into snapshot batch results.
///
/// This is a batch variant of `merge_delta` that processes multiple script hashes.
///
/// # Arguments
///
/// * `snapshots` - Snapshot results (one per script hash)
/// * `delta_results` - Delta query results (one per script hash)
///
/// # Returns
///
/// Merged results for each script hash.
pub fn merge_delta_batch(
    snapshots: &[Option<QueryResult>],
    delta_results: &[Option<QueryResult>],
) -> PirResult<Vec<Option<QueryResult>>> {
    if snapshots.len() != delta_results.len() {
        return Err(PirError::MergeError(format!(
            "batch size mismatch: {} snapshots vs {} deltas",
            snapshots.len(),
            delta_results.len()
        )));
    }

    let mut merged = Vec::with_capacity(snapshots.len());

    for (snapshot, delta) in snapshots.iter().zip(delta_results.iter()) {
        let result = match (snapshot, delta) {
            (Some(snap), Some(del)) => {
                // A merged result is Merkle-verified iff BOTH inputs were.
                // One untrusted source taints the merge.
                let merkle_verified = snap.merkle_verified && del.merkle_verified;
                if let Some(raw) = &del.raw_chunk_data {
                    let mut m = merge_delta(snap, raw)?;
                    m.merkle_verified = merkle_verified;
                    Some(m)
                } else {
                    // No delta data means no changes for this script hash
                    let mut m = snap.clone();
                    m.merkle_verified = merkle_verified;
                    Some(m)
                }
            }
            (Some(snap), None) => {
                // No delta entry means no changes
                Some(snap.clone())
            }
            (None, Some(del)) => {
                // New entry from delta (script hash didn't exist in snapshot).
                // Verification state inherits from the delta query alone —
                // there is no snapshot side to AND against.
                if let Some(raw) = &del.raw_chunk_data {
                    let delta_data = decode_delta_data(raw)?;
                    Some(QueryResult {
                        entries: delta_data.new_utxos,
                        is_whale: false,
                        merkle_verified: del.merkle_verified,
                        raw_chunk_data: None,
                        index_bins: Vec::new(),
                        chunk_bins: Vec::new(),
                        matched_index_idx: None,
                    })
                } else {
                    None
                }
            }
            (None, None) => None,
        };
        merged.push(result);
    }

    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(txid_byte: u8, vout: u32, amount: u64) -> UtxoEntry {
        let mut txid = [0u8; 32];
        txid[0] = txid_byte;
        UtxoEntry { txid, vout, amount_sats: amount }
    }

    #[test]
    fn test_apply_delta_empty() {
        let entries = vec![make_entry(1, 0, 1000), make_entry(2, 1, 2000)];
        let delta = DeltaData::default();
        let result = apply_delta_data(&entries, &delta);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_apply_delta_spend() {
        let entries = vec![make_entry(1, 0, 1000), make_entry(2, 1, 2000)];
        let delta = DeltaData {
            spent: vec![entries[0].outpoint()],
            new_utxos: Vec::new(),
        };
        let result = apply_delta_data(&entries, &delta);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].txid[0], 2);
    }

    #[test]
    fn test_apply_delta_add() {
        let entries = vec![make_entry(1, 0, 1000)];
        let delta = DeltaData {
            spent: Vec::new(),
            new_utxos: vec![make_entry(3, 0, 3000)],
        };
        let result = apply_delta_data(&entries, &delta);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_apply_delta_both() {
        let entries = vec![make_entry(1, 0, 1000), make_entry(2, 1, 2000)];
        let delta = DeltaData {
            spent: vec![entries[0].outpoint()],
            new_utxos: vec![make_entry(3, 0, 3000)],
        };
        let result = apply_delta_data(&entries, &delta);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].txid[0], 2);
        assert_eq!(result[1].txid[0], 3);
    }

    #[test]
    fn test_read_varint() {
        // Single byte
        assert_eq!(read_varint(&[0x00]).unwrap(), (0, 1));
        assert_eq!(read_varint(&[0x01]).unwrap(), (1, 1));
        assert_eq!(read_varint(&[0x7F]).unwrap(), (127, 1));

        // Two bytes
        assert_eq!(read_varint(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(read_varint(&[0xFF, 0x01]).unwrap(), (255, 2));

        // Three bytes
        assert_eq!(read_varint(&[0x80, 0x80, 0x01]).unwrap(), (16384, 3));
    }

    #[test]
    fn test_compute_sync_plan_empty_catalog() {
        let catalog = DatabaseCatalog::new();
        let result = compute_sync_plan(&catalog, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_sync_plan_at_tip() {
        let mut catalog = DatabaseCatalog::new();
        catalog.databases.push(DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: "main".into(),
            height: 100,
            index_bins: 1000,
            chunk_bins: 2000,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 10,
            dpf_n_chunk: 11,
            has_bucket_merkle: false,
        });

        let plan = compute_sync_plan(&catalog, Some(100)).unwrap();
        assert!(plan.is_empty());
        assert_eq!(plan.target_height, 100);
    }

    #[test]
    fn test_compute_sync_plan_fresh() {
        let mut catalog = DatabaseCatalog::new();
        catalog.databases.push(DatabaseInfo {
            db_id: 0,
            kind: DatabaseKind::Full,
            name: "main".into(),
            height: 100,
            index_bins: 1000,
            chunk_bins: 2000,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0,
            dpf_n_index: 10,
            dpf_n_chunk: 11,
            has_bucket_merkle: false,
        });

        let plan = compute_sync_plan(&catalog, None).unwrap();
        assert!(plan.is_fresh_sync);
        assert_eq!(plan.steps.len(), 1);
        assert!(plan.steps[0].is_full());
    }

    // ─── merkle_verified propagation tests ───────────────────────────────

    /// Encode a delta payload containing no spends and a single new UTXO.
    /// Mirrors the on-wire format in `decode_delta_data`.
    fn encode_delta_one_new(new: &UtxoEntry) -> Vec<u8> {
        let mut out = Vec::new();
        // spent_count varint = 0
        out.push(0);
        // new_count varint = 1
        out.push(1);
        // 44 bytes per entry: txid(32) || vout_le(4) || amount_le(8)
        out.extend_from_slice(&new.txid);
        out.extend_from_slice(&new.vout.to_le_bytes());
        out.extend_from_slice(&new.amount_sats.to_le_bytes());
        out
    }

    #[test]
    fn test_merge_delta_inherits_verified_from_snapshot() {
        let snap_entry = make_entry(1, 0, 1000);
        let mut snap = QueryResult::with_entries(vec![snap_entry]);
        snap.merkle_verified = true;

        let raw = encode_delta_one_new(&make_entry(2, 0, 2000));
        let merged = merge_delta(&snap, &raw).unwrap();
        assert!(merged.merkle_verified, "verified snapshot stays verified");
        assert_eq!(merged.entries.len(), 2);
    }

    #[test]
    fn test_merge_delta_inherits_unverified_from_snapshot() {
        let mut snap = QueryResult::with_entries(vec![make_entry(1, 0, 1000)]);
        snap.merkle_verified = false;

        let raw = encode_delta_one_new(&make_entry(2, 0, 2000));
        let merged = merge_delta(&snap, &raw).unwrap();
        assert!(
            !merged.merkle_verified,
            "unverified snapshot taints the merge (merge_delta inherits from snapshot)"
        );
    }

    #[test]
    fn test_merge_delta_batch_ands_verified_flags() {
        let raw = encode_delta_one_new(&make_entry(2, 0, 2000));

        // Base case: both verified -> merged verified.
        {
            let mut snap = QueryResult::with_entries(vec![make_entry(1, 0, 1000)]);
            snap.merkle_verified = true;
            let mut del = QueryResult::with_entries(vec![]);
            del.merkle_verified = true;
            del.raw_chunk_data = Some(raw.clone());

            let out = merge_delta_batch(&[Some(snap)], &[Some(del)]).unwrap();
            assert!(out[0].as_ref().unwrap().merkle_verified);
        }

        // Unverified snapshot -> merged unverified.
        {
            let mut snap = QueryResult::with_entries(vec![make_entry(1, 0, 1000)]);
            snap.merkle_verified = false;
            let mut del = QueryResult::with_entries(vec![]);
            del.merkle_verified = true;
            del.raw_chunk_data = Some(raw.clone());

            let out = merge_delta_batch(&[Some(snap)], &[Some(del)]).unwrap();
            assert!(!out[0].as_ref().unwrap().merkle_verified);
        }

        // Unverified delta -> merged unverified.
        {
            let mut snap = QueryResult::with_entries(vec![make_entry(1, 0, 1000)]);
            snap.merkle_verified = true;
            let mut del = QueryResult::with_entries(vec![]);
            del.merkle_verified = false;
            del.raw_chunk_data = Some(raw.clone());

            let out = merge_delta_batch(&[Some(snap)], &[Some(del)]).unwrap();
            assert!(
                !out[0].as_ref().unwrap().merkle_verified,
                "unverified delta taints the merge"
            );
        }
    }

    #[test]
    fn test_merge_delta_batch_new_from_delta_only() {
        // (None, Some(del)) path: no snapshot entry, delta introduces a new
        // UTXO set. The merged verification flag should come from the delta.
        let raw = encode_delta_one_new(&make_entry(5, 0, 5000));

        let mut del = QueryResult::with_entries(vec![]);
        del.merkle_verified = false;
        del.raw_chunk_data = Some(raw);

        let out = merge_delta_batch(&[None], &[Some(del)]).unwrap();
        let merged = out[0].as_ref().unwrap();
        assert!(!merged.merkle_verified, "unverified delta propagates");
        assert_eq!(merged.entries.len(), 1);
    }

    #[test]
    fn test_query_result_merkle_failed() {
        let qr = QueryResult::merkle_failed();
        assert!(!qr.merkle_verified);
        assert!(qr.entries.is_empty());
        assert!(!qr.is_whale);
        assert!(qr.raw_chunk_data.is_none());
    }

    #[test]
    fn test_query_result_constructors_default_verified() {
        // empty() and with_entries() default to merkle_verified=true
        // ("no failure detected"). Callers that need the pessimistic
        // default must set the field explicitly.
        assert!(QueryResult::empty().merkle_verified);
        assert!(QueryResult::with_entries(vec![]).merkle_verified);
        assert!(QueryResult::default().merkle_verified);
    }
}
