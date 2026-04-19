//! WASM bindings for PIR SDK.
//!
//! Exposes sync planning, delta merging, and core types to JavaScript/TypeScript.
//!
//! # Usage in JavaScript
//!
//! ```javascript
//! import init, {
//!   computeSyncPlan,
//!   mergeDeltaBatch,
//!   WasmDatabaseCatalog,
//!   WasmSyncPlan,
//! } from 'pir-sdk-wasm';
//!
//! await init();
//!
//! // Build catalog from server response
//! const catalog = WasmDatabaseCatalog.fromJson(serverCatalogJson);
//!
//! // Compute sync plan
//! const plan = computeSyncPlan(catalog, lastSyncedHeight);
//! console.log(`Steps: ${plan.stepsCount}, target: ${plan.targetHeight}`);
//!
//! // Iterate steps
//! for (let i = 0; i < plan.stepsCount; i++) {
//!   const step = plan.getStep(i);
//!   console.log(`Step ${i}: ${step.name} (db_id=${step.dbId})`);
//! }
//! ```

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;
use pir_sdk::{
    BucketRef, DatabaseCatalog, DatabaseInfo, DatabaseKind, QueryResult, SyncPlan, UtxoEntry,
};

/// Per-bucket bin Merkle verifier — pure SHA-256 walk exposed to JS so the
/// web client can drop its duplicate TS verifier.
///
/// JS still owns the WebSocket transport and the multi-pass padded sibling
/// fetch; this module contributes the tree-top parser, leaf/parent hash
/// primitives, and the item-level walk from leaf → cached root.
///
/// See `merkle_verify.rs` for the JS usage pattern.
pub mod merkle_verify;
pub use merkle_verify::{
    bucket_merkle_leaf_hash, bucket_merkle_parent_n, bucket_merkle_sha256,
    verify_bucket_merkle_item, xor_buffers, WasmBucketMerkleTreeTops,
    BUCKET_MERKLE_ARITY, BUCKET_MERKLE_SIB_ROW_SIZE,
};

/// Async PIR clients (`WasmDpfClient` / `WasmHarmonyClient`) wrapping the
/// native `pir-sdk-client` structs. On wasm32 they use
/// `WasmWebSocketTransport` under the hood; on native (for unit tests)
/// they use the tokio-tungstenite transport from `pir-sdk-client`.
///
/// `WasmOnionClient` is not implemented — the upstream `onionpir` crate
/// depends on C++/SEAL which does not compile to wasm32. Browsers that
/// want OnionPIR must keep the TypeScript client for now.
pub mod client;
pub use client::{WasmDpfClient, WasmHarmonyClient, WasmSyncResult};

/// Phase 2+ observability bridge — exposes `pir_sdk::AtomicMetrics` to
/// JavaScript so a browser tools panel / dashboard can poll live PIR
/// query and transport counters. See [`metrics::WasmAtomicMetrics`] for
/// the installation + snapshot API.
pub mod metrics;
pub use metrics::WasmAtomicMetrics;

/// Phase 2+ observability tail — wires a `tracing-wasm` subscriber that
/// routes Phase 1 `#[tracing::instrument]` spans to the browser
/// DevTools console. Call [`init_tracing_subscriber`] once at app
/// startup. See [`tracing_bridge`] for the full rationale.
pub mod tracing_bridge;
pub use tracing_bridge::init_tracing_subscriber;

// ─── Module init ────────────────────────────────────────────────────────────

/// Auto-invoked by the wasm-bindgen loader once the module is
/// instantiated. Installs a browser-friendly panic hook so Rust
/// `panic!`s surface in the JS console with a readable message and
/// stack trace instead of the bare `RuntimeError: unreachable` that
/// `wasm32-unknown-unknown` emits by default.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(start)]
pub fn __wasm_init() {
    console_error_panic_hook::set_once();
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Serialize a value to `JsValue` with maps emitted as plain JS objects
/// instead of `Map`s. `serde_wasm_bindgen::to_value`'s default behavior
/// round-trips `serde_json::Value::Object` through `serialize_map`, which
/// the crate encodes as a JS `Map` — breaking every TS caller that reads
/// fields via property access (`step.dbId`) instead of `.get('dbId')`.
pub(crate) fn to_js_object<T: serde::Serialize>(value: &T) -> JsValue {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    value.serialize(&serializer).unwrap_or(JsValue::NULL)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Parse an optional `[{pbcGroup, binIndex, binContent: hex}]` JSON array
/// into a `Vec<BucketRef>`. Missing / null / non-array values decode to an
/// empty vec so that JSON shapes produced by older callers (pre-inspector
/// round-trip) still load cleanly; malformed inner objects are a hard
/// error.
fn parse_bucket_refs(val: Option<&serde_json::Value>) -> Result<Vec<BucketRef>, JsError> {
    let arr = match val.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let pbc_group = item
            .get("pbcGroup")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                JsError::new(&format!(
                    "bucket ref {}: missing u32 'pbcGroup'",
                    i
                ))
            })? as u32;
        let bin_index = item
            .get("binIndex")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                JsError::new(&format!(
                    "bucket ref {}: missing u32 'binIndex'",
                    i
                ))
            })? as u32;
        let bin_content_hex = item
            .get("binContent")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                JsError::new(&format!(
                    "bucket ref {}: missing hex string 'binContent'",
                    i
                ))
            })?;
        let bin_content = hex_decode(bin_content_hex).map_err(|e| {
            JsError::new(&format!(
                "bucket ref {}: invalid 'binContent' hex: {}",
                i, e
            ))
        })?;
        out.push(BucketRef {
            pbc_group,
            bin_index,
            bin_content,
        });
    }
    Ok(out)
}

/// Encode a slice of `BucketRef`s as a `serde_json::Value` array — the
/// inverse of `parse_bucket_refs`. Uses the same camelCase keys
/// (`pbcGroup`, `binIndex`, `binContent`) that
/// [`WasmQueryResult::from_json`] accepts.
fn bucket_refs_to_json(refs: &[BucketRef]) -> serde_json::Value {
    serde_json::Value::Array(
        refs.iter()
            .map(|r| {
                serde_json::json!({
                    "pbcGroup": r.pbc_group,
                    "binIndex": r.bin_index,
                    "binContent": hex_encode(&r.bin_content),
                })
            })
            .collect(),
    )
}

/// Build a native `QueryResult` from a `serde_json::Value`. Shared by
/// `WasmQueryResult::from_json` and the array-level parser used by
/// `WasmDpfClient::verifyMerkleBatch` so both surfaces accept the same
/// field-name conventions (camelCase, optional inspector state).
///
/// Field semantics:
/// * `entries` — required array. Missing or non-array is an error.
/// * `isWhale` — optional bool, default `false`.
/// * `merkleVerified` — optional bool, default `true`
///   ("no failure detected"; matches `QueryResult::with_entries`).
/// * `indexBins` / `chunkBins` — optional inspector-state arrays
///   (see `parse_bucket_refs`); missing ⇒ empty vec (legacy shape).
/// * `matchedIndexIdx` — optional u64 ⇒ `Some(usize)`; missing ⇒ `None`.
pub(crate) fn parse_query_result_json(
    data: &serde_json::Value,
) -> Result<QueryResult, JsError> {
    let entries_arr = data
        .get("entries")
        .and_then(|e| e.as_array())
        .ok_or_else(|| JsError::new("missing 'entries' array"))?;

    let mut entries = Vec::with_capacity(entries_arr.len());
    for entry_val in entries_arr {
        let txid_hex = entry_val
            .get("txid")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let txid_bytes = hex_decode(txid_hex)
            .map_err(|e| JsError::new(&format!("invalid txid hex: {}", e)))?;
        let mut txid = [0u8; 32];
        if txid_bytes.len() == 32 {
            txid.copy_from_slice(&txid_bytes);
        }

        entries.push(UtxoEntry {
            txid,
            vout: entry_val
                .get("vout")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            amount_sats: entry_val
                .get("amount")
                .or_else(|| entry_val.get("amountSats"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        });
    }

    let is_whale = data
        .get("isWhale")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let merkle_verified = data
        .get("merkleVerified")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let index_bins = parse_bucket_refs(data.get("indexBins"))?;
    let chunk_bins = parse_bucket_refs(data.get("chunkBins"))?;
    let matched_index_idx = data
        .get("matchedIndexIdx")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);

    // Delta-database raw chunk bytes. `to_json` emits this as a lowercase
    // hex string; we round-trip it back to `Vec<u8>` here so persisted
    // delta results (e.g. cached across a page reload) still have the
    // payload needed for `decodeDeltaData` + `applyDeltaData` in JS. An
    // empty / missing string ⇒ `None` (matches full-snapshot shape).
    let raw_chunk_data = match data.get("rawChunkData").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => Some(
            hex_decode(s)
                .map_err(|e| JsError::new(&format!("invalid rawChunkData hex: {}", e)))?,
        ),
        _ => None,
    };

    Ok(QueryResult {
        entries,
        is_whale,
        merkle_verified,
        raw_chunk_data,
        index_bins,
        chunk_bins,
        matched_index_idx,
    })
}

// ─── Database Catalog ───────────────────────────────────────────────────────

/// WASM wrapper for DatabaseCatalog.
#[wasm_bindgen]
pub struct WasmDatabaseCatalog {
    inner: DatabaseCatalog,
}

impl WasmDatabaseCatalog {
    /// Wrap a natively-built [`DatabaseCatalog`] (e.g. from
    /// `DpfClient::fetch_catalog`) without re-serialising through JSON.
    /// Visible within the crate only — the public JS constructors are
    /// `new()` and `fromJson()`.
    pub(crate) fn from_native(catalog: DatabaseCatalog) -> Self {
        Self { inner: catalog }
    }

    /// Borrow the wrapped catalog for in-crate helpers (e.g. the
    /// HarmonyClient wrapper reaches here to pull a `DatabaseInfo` by
    /// `db_id` for `loadHints` / `fingerprint`). Not exposed to JS —
    /// external callers go through `getEntry` / `toJson`.
    pub(crate) fn inner(&self) -> &DatabaseCatalog {
        &self.inner
    }
}

#[wasm_bindgen]
impl WasmDatabaseCatalog {
    /// Create an empty catalog.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: DatabaseCatalog::new(),
        }
    }

    /// Create a catalog from JSON.
    ///
    /// Expected format:
    /// ```json
    /// {
    ///   "databases": [
    ///     {
    ///       "dbId": 0,
    ///       "dbType": 0,  // 0 = full, 1 = delta
    ///       "name": "main",
    ///       "baseHeight": 0,
    ///       "height": 900000,
    ///       "indexBins": 750000,
    ///       "chunkBins": 1500000,
    ///       "indexK": 75,
    ///       "chunkK": 80,
    ///       "tagSeed": "0x123456789abcdef0"
    ///     }
    ///   ]
    /// }
    /// ```
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &JsValue) -> Result<WasmDatabaseCatalog, JsError> {
        let data: serde_json::Value = serde_wasm_bindgen::from_value(json.clone())
            .map_err(|e| JsError::new(&format!("JSON parse error: {}", e)))?;

        let databases_arr = data
            .get("databases")
            .and_then(|d| d.as_array())
            .ok_or_else(|| JsError::new("missing 'databases' array"))?;

        let mut databases = Vec::with_capacity(databases_arr.len());

        for db_val in databases_arr {
            let db_id = db_val
                .get("dbId")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u8;
            let db_type = db_val
                .get("dbType")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let base_height = db_val
                .get("baseHeight")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let height = db_val
                .get("height")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;

            let kind = if db_type == 0 {
                DatabaseKind::Full
            } else {
                DatabaseKind::Delta { base_height }
            };

            databases.push(DatabaseInfo {
                db_id,
                kind,
                name: db_val
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                height,
                index_bins: db_val
                    .get("indexBins")
                    .or_else(|| db_val.get("indexBinsPerTable"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                chunk_bins: db_val
                    .get("chunkBins")
                    .or_else(|| db_val.get("chunkBinsPerTable"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                index_k: db_val
                    .get("indexK")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(75) as u8,
                chunk_k: db_val
                    .get("chunkK")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(80) as u8,
                tag_seed: parse_tag_seed(db_val.get("tagSeed")),
                dpf_n_index: db_val
                    .get("dpfNIndex")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(17) as u8,
                dpf_n_chunk: db_val
                    .get("dpfNChunk")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(18) as u8,
                has_bucket_merkle: db_val
                    .get("hasBucketMerkle")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            });
        }

        Ok(WasmDatabaseCatalog {
            inner: DatabaseCatalog { databases },
        })
    }

    /// Number of databases in the catalog.
    #[wasm_bindgen(getter)]
    pub fn count(&self) -> usize {
        self.inner.databases.len()
    }

    /// Get latest tip height.
    #[wasm_bindgen(getter, js_name = latestTip)]
    pub fn latest_tip(&self) -> Option<u32> {
        self.inner.latest_tip()
    }

    /// Get database info (by slot index in the catalog's array) as JSON.
    ///
    /// Pre-existing, positional — use [`getEntry`](Self::get_entry) if
    /// you want to look up by `db_id` instead.
    #[wasm_bindgen(js_name = getDatabase)]
    pub fn get_database(&self, index: usize) -> JsValue {
        if index >= self.inner.databases.len() {
            return JsValue::NULL;
        }
        to_js_object(&database_info_to_json(&self.inner.databases[index]))
    }

    /// Get a database's full info by `db_id`, returning the same JSON
    /// shape as [`toJson`]'s `databases[i]` entry. Returns `null` if
    /// no database in the catalog carries that ID.
    ///
    /// Complements [`getDatabase`], which is positional — callers who
    /// only know the `db_id` (e.g. from a `SyncStep`) should reach
    /// here instead of scanning `getDatabase(i)` for the right index.
    #[wasm_bindgen(js_name = getEntry)]
    pub fn get_entry(&self, db_id: u8) -> JsValue {
        match self.inner.get(db_id) {
            Some(db) => to_js_object(&database_info_to_json(db)),
            None => JsValue::NULL,
        }
    }

    /// Does the database with `db_id` publish per-bucket bin Merkle
    /// commitments? `false` if the database is absent or carries no
    /// Merkle section.
    ///
    /// The JS-side callers check this before enabling the standalone
    /// Merkle verifier path — `verify_merkle_batch_for_results` on the
    /// native side does the same check internally, but the flag is
    /// useful for UI surfaces that want to show a "verified" badge
    /// only when verification actually ran.
    #[wasm_bindgen(js_name = hasBucketMerkle)]
    pub fn has_bucket_merkle(&self, db_id: u8) -> bool {
        self.inner
            .get(db_id)
            .map(|db| db.has_bucket_merkle)
            .unwrap_or(false)
    }

    /// Convert to JSON.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> JsValue {
        let databases: Vec<serde_json::Value> = self
            .inner
            .databases
            .iter()
            .map(database_info_to_json)
            .collect();
        to_js_object(&serde_json::json!({ "databases": databases }))
    }
}

/// Shared DatabaseInfo → JSON projection used by `getDatabase`,
/// `getEntry`, and `toJson`. Keeps the three accessors in lock-step
/// so a new field only needs to land once.
fn database_info_to_json(db: &DatabaseInfo) -> serde_json::Value {
    serde_json::json!({
        "dbId": db.db_id,
        "dbType": if db.kind.is_full() { 0 } else { 1 },
        "name": db.name,
        "baseHeight": db.base_height(),
        "height": db.height,
        "indexBins": db.index_bins,
        "chunkBins": db.chunk_bins,
        "indexK": db.index_k,
        "chunkK": db.chunk_k,
        "tagSeed": format!("0x{:016x}", db.tag_seed),
        "dpfNIndex": db.dpf_n_index,
        "dpfNChunk": db.dpf_n_chunk,
        "hasBucketMerkle": db.has_bucket_merkle,
    })
}

fn parse_tag_seed(v: Option<&serde_json::Value>) -> u64 {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => {
            if let Some(hex) = s.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).unwrap_or(0)
            } else {
                s.parse().unwrap_or(0)
            }
        }
        _ => 0,
    }
}

// ─── Sync Plan ──────────────────────────────────────────────────────────────

/// WASM wrapper for SyncPlan.
#[wasm_bindgen]
pub struct WasmSyncPlan {
    inner: SyncPlan,
}

#[wasm_bindgen]
impl WasmSyncPlan {
    /// Number of steps in the plan.
    #[wasm_bindgen(getter, js_name = stepsCount)]
    pub fn steps_count(&self) -> usize {
        self.inner.steps.len()
    }

    /// Whether this is a fresh sync.
    #[wasm_bindgen(getter, js_name = isFreshSync)]
    pub fn is_fresh_sync(&self) -> bool {
        self.inner.is_fresh_sync
    }

    /// Target height after sync.
    #[wasm_bindgen(getter, js_name = targetHeight)]
    pub fn target_height(&self) -> u32 {
        self.inner.target_height
    }

    /// Whether the plan is empty (already at tip).
    #[wasm_bindgen(getter, js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get a step by index.
    #[wasm_bindgen(js_name = getStep)]
    pub fn get_step(&self, index: usize) -> JsValue {
        if index >= self.inner.steps.len() {
            return JsValue::NULL;
        }
        let step = &self.inner.steps[index];
        let json = serde_json::json!({
            "dbId": step.db_id,
            "dbType": if step.is_full() { "full" } else { "delta" },
            "name": step.name,
            "baseHeight": step.base_height,
            "tipHeight": step.tip_height,
        });
        to_js_object(&json)
    }

    /// Get all steps as JSON array.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> JsValue {
        let steps: Vec<serde_json::Value> = self
            .inner
            .steps
            .iter()
            .map(|step| {
                serde_json::json!({
                    "dbId": step.db_id,
                    "dbType": if step.is_full() { "full" } else { "delta" },
                    "name": step.name,
                    "baseHeight": step.base_height,
                    "tipHeight": step.tip_height,
                })
            })
            .collect();
        to_js_object(&serde_json::json!({
            "steps": steps,
            "isFreshSync": self.inner.is_fresh_sync,
            "targetHeight": self.inner.target_height,
        }))
    }
}

// ─── Compute Sync Plan ──────────────────────────────────────────────────────

/// Compute an optimal sync plan from the catalog.
///
/// # Arguments
/// * `catalog` - Database catalog from server
/// * `last_synced_height` - Last synced height (0 or undefined for fresh sync)
///
/// # Returns
/// A WasmSyncPlan with steps to execute.
#[wasm_bindgen(js_name = computeSyncPlan)]
pub fn compute_sync_plan(
    catalog: &WasmDatabaseCatalog,
    last_synced_height: Option<u32>,
) -> Result<WasmSyncPlan, JsError> {
    let plan = pir_sdk::compute_sync_plan(&catalog.inner, last_synced_height)
        .map_err(|e| JsError::new(&format!("sync plan error: {}", e)))?;
    Ok(WasmSyncPlan { inner: plan })
}

// ─── Query Result ───────────────────────────────────────────────────────────

/// WASM wrapper for QueryResult.
#[wasm_bindgen]
pub struct WasmQueryResult {
    inner: QueryResult,
}

impl WasmQueryResult {
    /// Wrap a natively-built [`QueryResult`] (e.g. produced by a
    /// `DpfClient::sync` result entry) without re-serialising through
    /// JSON. In-crate use only — JS builds one via the `fromJson`
    /// factory.
    pub(crate) fn from_native(result: QueryResult) -> Self {
        Self { inner: result }
    }
}

#[wasm_bindgen]
impl WasmQueryResult {
    /// Create an empty result.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: QueryResult::empty(),
        }
    }

    /// Create from JSON.
    #[wasm_bindgen(js_name = fromJson)]
    pub fn from_json(json: &JsValue) -> Result<WasmQueryResult, JsError> {
        let data: serde_json::Value = serde_wasm_bindgen::from_value(json.clone())
            .map_err(|e| JsError::new(&format!("JSON parse error: {}", e)))?;
        Ok(WasmQueryResult {
            inner: parse_query_result_json(&data)?,
        })
    }

    /// Number of UTXO entries.
    #[wasm_bindgen(getter, js_name = entryCount)]
    pub fn entry_count(&self) -> usize {
        self.inner.entries.len()
    }

    /// Total balance in satoshis.
    #[wasm_bindgen(getter, js_name = totalBalance)]
    pub fn total_balance(&self) -> u64 {
        self.inner.total_balance()
    }

    /// Whether this is a whale address.
    #[wasm_bindgen(getter, js_name = isWhale)]
    pub fn is_whale(&self) -> bool {
        self.inner.is_whale
    }

    /// Whether the per-bucket Merkle proof verified for this result.
    ///
    /// `true` means the proof passed or the database doesn't publish
    /// Merkle commitments (no failure detected). `false` means
    /// verification was attempted and FAILED; the result should be
    /// treated as untrusted.
    #[wasm_bindgen(getter, js_name = merkleVerified)]
    pub fn merkle_verified(&self) -> bool {
        self.inner.merkle_verified
    }

    /// Get entry at index as JSON.
    #[wasm_bindgen(js_name = getEntry)]
    pub fn get_entry(&self, index: usize) -> JsValue {
        if index >= self.inner.entries.len() {
            return JsValue::NULL;
        }
        let entry = &self.inner.entries[index];
        let json = serde_json::json!({
            "txid": hex_encode(&entry.txid),
            "vout": entry.vout,
            "amountSats": entry.amount_sats,
        });
        to_js_object(&json)
    }

    /// Inspector state: every INDEX cuckoo bin probed for this query,
    /// as a JSON array of `{pbcGroup, binIndex, binContent}` objects.
    ///
    /// Only non-empty for `QueryResult`s produced by the inspector path
    /// (e.g. `WasmDpfClient.queryBatchRaw`). Populated for found,
    /// not-found, and whale alike — the item-count symmetry invariant
    /// guarantees this array always has `INDEX_CUCKOO_NUM_HASHES = 2`
    /// entries for an inspector-path result.
    #[wasm_bindgen(js_name = indexBins)]
    pub fn index_bins(&self) -> JsValue {
        to_js_object(&bucket_refs_to_json(&self.inner.index_bins))
    }

    /// Inspector state: every CHUNK cuckoo bin that backed a decoded
    /// UTXO, as a JSON array of `{pbcGroup, binIndex, binContent}`
    /// objects. Empty for not-found, whale, or zero-chunk matches.
    #[wasm_bindgen(js_name = chunkBins)]
    pub fn chunk_bins(&self) -> JsValue {
        to_js_object(&bucket_refs_to_json(&self.inner.chunk_bins))
    }

    /// Inspector state: if this query resolved to a match, the index
    /// within [`indexBins`] of the matching bin. Returns `undefined`
    /// for not-found / inspector-free results.
    #[wasm_bindgen(js_name = matchedIndexIdx)]
    pub fn matched_index_idx(&self) -> JsValue {
        match self.inner.matched_index_idx {
            Some(i) => JsValue::from(i as u32),
            None => JsValue::UNDEFINED,
        }
    }

    /// Raw chunk bytes for delta-database queries, or `undefined` for
    /// full-snapshot queries (and for queries that didn't hit the
    /// inspector path).
    ///
    /// The browser needs these bytes to decode the delta payload
    /// (`decodeDeltaData`) and merge it onto a cached snapshot. For
    /// full-snapshot queries they are `None` because the decoded
    /// `entries` already hold the canonical state — there is no
    /// second-layer merge to feed.
    ///
    /// Populated natively by
    /// `pir-sdk-client::DpfClient::query_batch_with_inspector`
    /// (when `db_info.kind.is_delta()`) and surfaced here as a
    /// `Uint8Array`. This getter is the only way the web client can
    /// obtain the bytes — `toJson()` emits them as a hex string so that
    /// persisted results also carry the delta payload across reloads.
    #[wasm_bindgen(js_name = rawChunkData)]
    pub fn raw_chunk_data(&self) -> JsValue {
        match &self.inner.raw_chunk_data {
            Some(bytes) => Uint8Array::from(&bytes[..]).into(),
            None => JsValue::UNDEFINED,
        }
    }

    /// Convert to JSON.
    ///
    /// The emitted object is accepted by [`fromJson`] as a round-trip
    /// input — including optional inspector fields (`indexBins`,
    /// `chunkBins`, `matchedIndexIdx`), which lets callers persist an
    /// inspector-path result (e.g. to localStorage) and later re-verify
    /// it via `WasmDpfClient.verifyMerkleBatch`.
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> JsValue {
        let entries: Vec<serde_json::Value> = self
            .inner
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "txid": hex_encode(&e.txid),
                    "vout": e.vout,
                    "amountSats": e.amount_sats,
                })
            })
            .collect();
        let mut obj = serde_json::json!({
            "entries": entries,
            "isWhale": self.inner.is_whale,
            "totalBalance": self.inner.total_balance(),
            "merkleVerified": self.inner.merkle_verified,
        });
        // Emit inspector state only when non-empty so the round-trip for
        // legacy (non-inspector) callers stays byte-identical to the
        // pre-Session-2 shape.
        if !self.inner.index_bins.is_empty() {
            obj["indexBins"] = bucket_refs_to_json(&self.inner.index_bins);
        }
        if !self.inner.chunk_bins.is_empty() {
            obj["chunkBins"] = bucket_refs_to_json(&self.inner.chunk_bins);
        }
        if let Some(i) = self.inner.matched_index_idx {
            obj["matchedIndexIdx"] = serde_json::json!(i);
        }
        // Delta-query bytes. Emit as hex so persisted JSON round-trips
        // carry the payload — `parse_query_result_json` decodes the hex
        // back to `Vec<u8>` when round-tripping through `fromJson`.
        // Native `QueryResult` marks `raw_chunk_data` as `#[serde(skip)]`
        // so native-side serde is unaffected; this is a WASM-side extra.
        if let Some(bytes) = &self.inner.raw_chunk_data {
            obj["rawChunkData"] = serde_json::Value::String(hex_encode(bytes));
        }
        to_js_object(&obj)
    }
}

// ─── Delta Merging ──────────────────────────────────────────────────────────

/// Decode delta data from raw bytes.
///
/// Returns JSON with `spent` (array of outpoint hex strings) and
/// `newUtxos` (array of UTXO entries).
#[wasm_bindgen(js_name = decodeDeltaData)]
pub fn decode_delta_data(raw: &[u8]) -> Result<JsValue, JsError> {
    let delta = pir_sdk::decode_delta_data(raw)
        .map_err(|e| JsError::new(&format!("decode error: {}", e)))?;

    let spent: Vec<String> = delta.spent.iter().map(|op| hex_encode(op)).collect();

    let new_utxos: Vec<serde_json::Value> = delta
        .new_utxos
        .iter()
        .map(|e| {
            serde_json::json!({
                "txid": hex_encode(&e.txid),
                "vout": e.vout,
                "amountSats": e.amount_sats,
            })
        })
        .collect();

    Ok(to_js_object(&serde_json::json!({
        "spent": spent,
        "newUtxos": new_utxos,
    })))
}

/// Merge delta into a snapshot result.
///
/// # Arguments
/// * `snapshot` - The snapshot QueryResult
/// * `delta_raw` - Raw delta chunk data bytes
///
/// # Returns
/// A new WasmQueryResult with the delta applied.
#[wasm_bindgen(js_name = mergeDelta)]
pub fn merge_delta(
    snapshot: &WasmQueryResult,
    delta_raw: &[u8],
) -> Result<WasmQueryResult, JsError> {
    let merged = pir_sdk::merge_delta(&snapshot.inner, delta_raw)
        .map_err(|e| JsError::new(&format!("merge error: {}", e)))?;
    Ok(WasmQueryResult { inner: merged })
}

// ─── Hash Functions (re-exported from pir-core) ─────────────────────────────

/// Splitmix64 finalizer. Returns 8 bytes (LE).
#[wasm_bindgen]
pub fn splitmix64(x_hi: u32, x_lo: u32) -> Vec<u8> {
    let x = ((x_hi as u64) << 32) | (x_lo as u64);
    pir_core::hash::splitmix64(x).to_le_bytes().to_vec()
}

/// Compute fingerprint tag. Returns 8 bytes (LE).
#[wasm_bindgen(js_name = computeTag)]
pub fn compute_tag(tag_seed_hi: u32, tag_seed_lo: u32, script_hash: &[u8]) -> Vec<u8> {
    let seed = ((tag_seed_hi as u64) << 32) | (tag_seed_lo as u64);
    pir_core::hash::compute_tag(seed, script_hash)
        .to_le_bytes()
        .to_vec()
}

/// Derive 3 group indices for a script hash.
#[wasm_bindgen(js_name = deriveGroups)]
pub fn derive_groups(script_hash: &[u8], k: u32) -> Vec<u32> {
    let groups = pir_core::hash::derive_groups_3(script_hash, k as usize);
    groups.iter().map(|&b| b as u32).collect()
}

/// Derive cuckoo hash key. Returns 8 bytes (LE).
#[wasm_bindgen(js_name = deriveCuckooKey)]
pub fn derive_cuckoo_key(
    master_seed_hi: u32,
    master_seed_lo: u32,
    group_id: u32,
    hash_fn: u32,
) -> Vec<u8> {
    let seed = ((master_seed_hi as u64) << 32) | (master_seed_lo as u64);
    pir_core::hash::derive_cuckoo_key(seed, group_id as usize, hash_fn as usize)
        .to_le_bytes()
        .to_vec()
}

/// Cuckoo hash a script hash.
#[wasm_bindgen(js_name = cuckooHash)]
pub fn cuckoo_hash(script_hash: &[u8], key_hi: u32, key_lo: u32, num_bins: u32) -> u32 {
    let key = ((key_hi as u64) << 32) | (key_lo as u64);
    pir_core::hash::cuckoo_hash(script_hash, key, num_bins as usize) as u32
}

/// Derive 3 group indices for a chunk ID.
#[wasm_bindgen(js_name = deriveChunkGroups)]
pub fn derive_chunk_groups(chunk_id: u32, k: u32) -> Vec<u32> {
    let groups = pir_core::hash::derive_int_groups_3(chunk_id, k as usize);
    groups.iter().map(|&b| b as u32).collect()
}

/// Cuckoo hash an integer chunk ID.
#[wasm_bindgen(js_name = cuckooHashInt)]
pub fn cuckoo_hash_int(chunk_id: u32, key_hi: u32, key_lo: u32, num_bins: u32) -> u32 {
    let key = ((key_hi as u64) << 32) | (key_lo as u64);
    pir_core::hash::cuckoo_hash_int(chunk_id, key, num_bins as usize) as u32
}

// ─── PBC Utilities ──────────────────────────────────────────────────────────

/// Cuckoo-place items into groups.
#[wasm_bindgen(js_name = cuckooPlace)]
pub fn cuckoo_place(
    cand_groups_flat: &[u32],
    num_items: u32,
    num_groups: u32,
    max_kicks: u32,
    num_hashes: u32,
) -> Vec<i32> {
    let ni = num_items as usize;
    let nh = num_hashes as usize;
    let nb = num_groups as usize;

    let cand_groups: Vec<Vec<usize>> = (0..ni)
        .map(|i| {
            (0..nh)
                .map(|h| cand_groups_flat[i * nh + h] as usize)
                .collect()
        })
        .collect();

    let mut group_owner: Vec<Option<usize>> = vec![None; nb];

    for qi in 0..ni {
        let saved = group_owner.clone();
        if !pir_core::pbc::pbc_cuckoo_place(
            &cand_groups,
            &mut group_owner,
            qi,
            max_kicks as usize,
            nh,
        ) {
            group_owner = saved;
        }
    }

    let mut assignments = vec![-1i32; ni];
    for (b, owner) in group_owner.iter().enumerate() {
        if let Some(qi) = owner {
            assignments[*qi] = b as i32;
        }
    }
    assignments
}

/// Plan multi-round PBC placement. Returns JSON.
#[wasm_bindgen(js_name = planRounds)]
pub fn plan_rounds(
    item_groups_flat: &[u32],
    items_per: u32,
    num_groups: u32,
    num_hashes: u32,
    max_kicks: u32,
) -> JsValue {
    let ip = items_per as usize;
    let num_items = item_groups_flat.len() / ip;

    let item_groups: Vec<Vec<usize>> = (0..num_items)
        .map(|i| {
            (0..ip)
                .map(|h| item_groups_flat[i * ip + h] as usize)
                .collect()
        })
        .collect();

    let rounds = pir_core::pbc::pbc_plan_rounds(
        &item_groups,
        num_groups as usize,
        num_hashes as usize,
        max_kicks as usize,
    );

    let json_rounds: Vec<Vec<[usize; 2]>> = rounds
        .iter()
        .map(|round| round.iter().map(|&(item, group)| [item, group]).collect())
        .collect();

    serde_wasm_bindgen::to_value(&json_rounds).unwrap_or(JsValue::NULL)
}

// ─── Varint Codec ───────────────────────────────────────────────────────────

/// Read a LEB128 varint. Returns [value_lo, value_hi, bytes_consumed].
#[wasm_bindgen(js_name = readVarint)]
pub fn read_varint(data: &[u8], offset: u32) -> Vec<u32> {
    let slice = &data[offset as usize..];
    let (value, consumed) = pir_core::codec::read_varint(slice);
    vec![value as u32, (value >> 32) as u32, consumed as u32]
}

/// Decode UTXO data from bytes. Returns JSON array.
#[wasm_bindgen(js_name = decodeUtxoData)]
pub fn decode_utxo_data(data: &[u8]) -> JsValue {
    let entries = pir_core::codec::parse_utxo_data(data);
    let json_entries: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "txid": hex_encode(&e.txid),
                "vout": e.vout,
                "amount": e.amount,
            })
        })
        .collect();
    to_js_object(&json_entries)
}

// ─── Tests ──────────────────────────────────────────────────────────────────
//
// These exercise the pure-Rust helpers (parsers, JSON projections) that
// underlie the `#[wasm_bindgen]` surface. Methods that take or return
// `JsValue` directly (`WasmQueryResult::to_json`, `WasmDatabaseCatalog::get_entry`,
// etc.) aren't exercised here because `serde_wasm_bindgen::to_value` / the
// `JsValue` constructors require a real JS runtime — the helpers tested
// below cover the equivalent data-layer contracts.

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info(db_id: u8, has_bucket_merkle: bool) -> DatabaseInfo {
        DatabaseInfo {
            db_id,
            kind: DatabaseKind::Full,
            name: format!("db{}", db_id),
            height: 900_000 + db_id as u32,
            index_bins: 8192,
            chunk_bins: 16_384,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0xdead_beef,
            dpf_n_index: 13,
            dpf_n_chunk: 14,
            has_bucket_merkle,
        }
    }

    // ─── parse_bucket_refs / bucket_refs_to_json ────────────────────────

    #[test]
    fn parse_bucket_refs_none_gives_empty_vec() {
        // Missing `indexBins` field in a caller's JSON ⇒ empty inspector
        // state (legacy shape). `JsError::new` is NOT called on this
        // path — the early `return Ok(Vec::new())` happens before.
        let out = parse_bucket_refs(None).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn parse_bucket_refs_happy_path() {
        let json = serde_json::json!([
            { "pbcGroup": 3, "binIndex": 17, "binContent": "abcd" },
            { "pbcGroup": 5, "binIndex": 42, "binContent": "" },
        ]);
        let refs = parse_bucket_refs(Some(&json)).unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].pbc_group, 3);
        assert_eq!(refs[0].bin_index, 17);
        assert_eq!(refs[0].bin_content, vec![0xab, 0xcd]);
        assert_eq!(refs[1].pbc_group, 5);
        assert_eq!(refs[1].bin_index, 42);
        assert!(refs[1].bin_content.is_empty());
    }

    #[test]
    fn bucket_refs_to_json_round_trip() {
        let refs = vec![
            BucketRef {
                pbc_group: 0,
                bin_index: 1,
                bin_content: vec![0x01, 0x02, 0x03],
            },
            BucketRef {
                pbc_group: 10,
                bin_index: 999,
                bin_content: vec![],
            },
        ];
        let json = bucket_refs_to_json(&refs);
        let parsed = parse_bucket_refs(Some(&json)).unwrap();
        assert_eq!(parsed.len(), refs.len());
        for (a, b) in refs.iter().zip(parsed.iter()) {
            assert_eq!(a.pbc_group, b.pbc_group);
            assert_eq!(a.bin_index, b.bin_index);
            assert_eq!(a.bin_content, b.bin_content);
        }
    }

    #[test]
    fn bucket_refs_to_json_empty_input() {
        let json = bucket_refs_to_json(&[]);
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    // ─── parse_query_result_json ────────────────────────────────────────

    #[test]
    fn parse_query_result_json_minimal() {
        // Minimal legacy shape: just `entries`. All inspector fields
        // default to empty / None / true, matching pre-Session-2 callers.
        let json = serde_json::json!({ "entries": [] });
        let qr = parse_query_result_json(&json).unwrap();
        assert!(qr.entries.is_empty());
        assert!(!qr.is_whale);
        assert!(qr.merkle_verified);
        assert!(qr.index_bins.is_empty());
        assert!(qr.chunk_bins.is_empty());
        assert!(qr.matched_index_idx.is_none());
    }

    #[test]
    fn parse_query_result_json_with_inspector_fields() {
        let json = serde_json::json!({
            "entries": [{
                "txid": "00".repeat(31) + "ab",
                "vout": 7,
                "amountSats": 12345,
            }],
            "isWhale": false,
            "merkleVerified": false,
            "indexBins": [
                { "pbcGroup": 0, "binIndex": 1, "binContent": "aa" },
                { "pbcGroup": 0, "binIndex": 2, "binContent": "bb" },
            ],
            "chunkBins": [
                { "pbcGroup": 1, "binIndex": 50, "binContent": "cc" },
            ],
            "matchedIndexIdx": 1,
        });
        let qr = parse_query_result_json(&json).unwrap();
        assert_eq!(qr.entries.len(), 1);
        assert_eq!(qr.entries[0].vout, 7);
        assert_eq!(qr.entries[0].amount_sats, 12345);
        assert_eq!(qr.entries[0].txid[31], 0xab);
        assert!(!qr.merkle_verified);
        assert_eq!(qr.index_bins.len(), 2);
        assert_eq!(qr.index_bins[0].bin_content, vec![0xaa]);
        assert_eq!(qr.index_bins[1].bin_content, vec![0xbb]);
        assert_eq!(qr.chunk_bins.len(), 1);
        assert_eq!(qr.chunk_bins[0].bin_content, vec![0xcc]);
        assert_eq!(qr.matched_index_idx, Some(1));
    }

    #[test]
    fn parse_query_result_json_accepts_legacy_amount_key() {
        // Historical JSON uses `amount` instead of `amountSats`; the
        // parser accepts either for back-compat with existing web
        // callers.
        let json = serde_json::json!({
            "entries": [{
                "txid": "00".repeat(32),
                "vout": 0,
                "amount": 999,
            }],
        });
        let qr = parse_query_result_json(&json).unwrap();
        assert_eq!(qr.entries[0].amount_sats, 999);
    }

    #[test]
    fn parse_query_result_json_round_trips_raw_chunk_data() {
        // `to_json` emits `rawChunkData` as lowercase hex when the inner
        // QueryResult carries delta bytes. The parser round-trips that
        // hex back to `Vec<u8>` so persisted delta results keep their
        // payload across page reloads. Missing / empty field ⇒ `None`
        // (preserves full-snapshot shape). The invalid-hex error path
        // is exercised indirectly — `JsError::new` is a wasm-bindgen
        // import that panics on non-wasm targets, so asserting `is_err()`
        // here would crash; the error path is covered by the same
        // `map_err(|e| JsError::new(...))` pattern that already guards
        // the `txid` field.
        let json_with = serde_json::json!({
            "entries": [],
            "rawChunkData": "deadbeef01",
        });
        let qr = parse_query_result_json(&json_with).unwrap();
        assert_eq!(
            qr.raw_chunk_data.as_deref(),
            Some(&[0xde, 0xad, 0xbe, 0xef, 0x01][..]),
        );

        let json_missing = serde_json::json!({ "entries": [] });
        let qr = parse_query_result_json(&json_missing).unwrap();
        assert!(qr.raw_chunk_data.is_none());

        let json_empty = serde_json::json!({
            "entries": [],
            "rawChunkData": "",
        });
        let qr = parse_query_result_json(&json_empty).unwrap();
        assert!(qr.raw_chunk_data.is_none());
    }

    // ─── database_info_to_json + catalog accessors ──────────────────────

    #[test]
    fn database_info_to_json_includes_has_bucket_merkle() {
        let db = make_info(3, true);
        let json = database_info_to_json(&db);
        assert_eq!(json["dbId"], 3);
        assert_eq!(json["hasBucketMerkle"], true);
        assert_eq!(json["indexBins"], 8192);
        assert_eq!(json["chunkBins"], 16_384);
    }

    #[test]
    fn database_info_to_json_has_bucket_merkle_false() {
        let db = make_info(5, false);
        let json = database_info_to_json(&db);
        assert_eq!(json["hasBucketMerkle"], false);
    }

    #[test]
    fn wasm_database_catalog_get_entry_by_db_id() {
        // Build a catalog whose positional order differs from db_id
        // order, to catch "positional vs by-id" regressions:
        // databases[0].db_id = 7, databases[1].db_id = 3.
        let mut catalog = DatabaseCatalog::new();
        catalog.databases.push(make_info(7, true));
        catalog.databases.push(make_info(3, false));
        let wrapper = WasmDatabaseCatalog::from_native(catalog);
        // get_entry(db_id) must find db_id == 3 even though it's at
        // position 1.
        assert!(wrapper.has_bucket_merkle(7));
        assert!(!wrapper.has_bucket_merkle(3));
        // Absent db_id ⇒ hasBucketMerkle = false, not a panic.
        assert!(!wrapper.has_bucket_merkle(99));
    }

    #[test]
    fn wasm_database_catalog_has_bucket_merkle_reflects_native_flag() {
        let mut catalog = DatabaseCatalog::new();
        catalog.databases.push(make_info(0, true));
        catalog.databases.push(make_info(1, false));
        let wrapper = WasmDatabaseCatalog::from_native(catalog);
        assert!(wrapper.has_bucket_merkle(0));
        assert!(!wrapper.has_bucket_merkle(1));
    }
}
