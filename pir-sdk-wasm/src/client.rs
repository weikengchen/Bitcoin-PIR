//! Async PIR clients exposed to JavaScript via `wasm-bindgen`.
//!
//! Wraps the native [`DpfClient`] and [`HarmonyClient`] from
//! `pir-sdk-client` so browser callers get the same query orchestration,
//! Merkle verification, and padding invariants the native clients provide
//! — with the only differences being:
//!
//! * **Transport**: the wrapped clients auto-select
//!   [`WasmWebSocketTransport`] at connect time on `wasm32-unknown-unknown`
//!   (via the `cfg(target_arch = "wasm32")` branch inside
//!   `pir-sdk-client::DpfClient::connect` / `HarmonyClient::connect`), so
//!   JS callers never touch the transport layer directly.
//! * **Types on the JS boundary**: `ScriptHash` (`[u8; 20]`) is passed as
//!   a packed `Uint8Array` whose `length` is a multiple of 20, and
//!   `QueryResult`/`SyncResult` are returned as plain JS objects
//!   (`JsValue` built via `serde_wasm_bindgen::to_value(...)`) rather
//!   than typed classes, because the TypeScript side of the web app
//!   already deals with the JSON-shape UTXO entries that match the
//!   native [`QueryResult::to_json`](crate::WasmQueryResult) output.
//!
//! 🔒 Padding invariants (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) are
//! enforced inside the native clients — this wrapper is a thin translation
//! layer and must not bypass them. See `CLAUDE.md` → "Query Padding".
//!
//! # Not wrapped: `OnionClient`
//!
//! `pir-sdk-client::OnionClient` is a pass-through to the upstream
//! `onionpir` crate, which depends on a C++ SEAL build. SEAL does not
//! compile to `wasm32-unknown-unknown`, so there is no `WasmOnionClient`
//! for now — browsers that need OnionPIR must keep the existing
//! TypeScript path (`web/src/onionpir_client.ts`) until a WASM-compatible
//! FHE backend is available.

use js_sys::{Array, Uint8Array};
use pir_sdk::{PirClient, QueryResult, ScriptHash, SyncResult};
use pir_sdk_client::{DpfClient, HarmonyClient, PRP_ALF, PRP_FASTPRP, PRP_HMR12};
#[cfg(target_arch = "wasm32")]
use pir_sdk_client::HintProgress;
use wasm_bindgen::prelude::*;

use crate::{
    parse_query_result_json, to_js_object, WasmAtomicMetrics, WasmDatabaseCatalog, WasmQueryResult,
};

// These symbols are only referenced from wasm32-gated bridges below, so
// keep their imports gated too — on native we only compile recorder-impl
// unit tests that use native types directly.
#[cfg(target_arch = "wasm32")]
use pir_sdk::{ConnectionState, StateListener, SyncProgress};
#[cfg(target_arch = "wasm32")]
use send_wrapper::SendWrapper;
#[cfg(target_arch = "wasm32")]
use std::sync::Arc;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// The input `Uint8Array` is a packed concatenation of 20-byte script
/// hashes; split it into `Vec<[u8; 20]>` with strict length validation so
/// a caller who forgot the padding (e.g. passed 19 bytes) gets a clear
/// error rather than a silently truncated query.
///
/// Returns a plain `String` on failure so the helper is callable from
/// native unit tests; the `#[wasm_bindgen]` methods wrap the error in
/// `JsError` at their boundary (`JsError::new` is a wasm-bindgen import
/// and panics when called on non-wasm targets).
fn unpack_script_hashes(packed: &[u8]) -> Result<Vec<ScriptHash>, String> {
    const SH_LEN: usize = 20;
    if packed.len() % SH_LEN != 0 {
        return Err(format!(
            "scriptHashes length must be a multiple of {} (got {})",
            SH_LEN,
            packed.len()
        ));
    }
    let n = packed.len() / SH_LEN;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut sh = [0u8; SH_LEN];
        sh.copy_from_slice(&packed[i * SH_LEN..(i + 1) * SH_LEN]);
        out.push(sh);
    }
    Ok(out)
}

/// Same one-byte PRP backend validation the `#[wasm_bindgen]` setters
/// use, factored out so unit tests can exercise it without constructing
/// a `JsError` (which panics on native).
fn validate_prp_backend(backend: u8) -> Result<(), String> {
    if backend != PRP_HMR12 && backend != PRP_FASTPRP && backend != PRP_ALF {
        return Err(format!(
            "unknown PRP backend: {} (use PRP_HMR12={}, PRP_FASTPRP={}, PRP_ALF={})",
            backend, PRP_HMR12, PRP_FASTPRP, PRP_ALF
        ));
    }
    Ok(())
}

/// Same 16-byte master-key validation the `#[wasm_bindgen]` setter
/// uses, factored out for native-side unit tests (see
/// `validate_prp_backend` for the `JsError`-panic rationale).
fn validate_master_key_len(len: usize) -> Result<(), String> {
    if len != 16 {
        return Err(format!("masterKey must be 16 bytes (got {})", len));
    }
    Ok(())
}

/// Pretty-print a `PirError` for the JS side. We stringify via
/// `Display` (the `thiserror` output) — callers can still distinguish
/// kinds downstream by inspecting the message prefix, matching the
/// error-taxonomy placeholder in the SDK roadmap.
fn err_to_js(e: pir_sdk::PirError) -> JsError {
    JsError::new(&e.to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Build the JS-facing JSON shape of a `SyncResult`. Mirrors
/// [`WasmQueryResult::to_json`](crate::WasmQueryResult) for the per-item
/// layout so the two consumers see identical entry objects.
fn sync_result_to_json(sync: &SyncResult) -> serde_json::Value {
    let results: Vec<serde_json::Value> = sync
        .results
        .iter()
        .map(|r| match r {
            None => serde_json::Value::Null,
            Some(qr) => {
                let entries: Vec<serde_json::Value> = qr
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
                serde_json::json!({
                    "entries": entries,
                    "isWhale": qr.is_whale,
                    "totalBalance": qr.total_balance(),
                    "merkleVerified": qr.merkle_verified,
                })
            }
        })
        .collect();

    serde_json::json!({
        "results": results,
        "syncedHeight": sync.synced_height,
        "wasFreshSync": sync.was_fresh_sync,
    })
}

// ─── JS callback bridges (wasm32-only) ─────────────────────────────────────
//
// These wrap a `js_sys::Function` so it can be handed to the native
// `DpfClient` through the `StateListener` / `SyncProgress` traits.
//
// `js_sys::Function` is `!Send + !Sync` — it's a handle into the browser's
// single-threaded event loop — but both traits require `Send + Sync`.
// `send_wrapper::SendWrapper<T>` lies about the bound (`unsafe impl Send +
// Sync`) and panics on cross-thread access. This is sound on wasm32 since
// `wasm-bindgen-futures` runs everything on the single JS event loop; on
// native the wrapper doesn't exist and these bridges aren't compiled.

/// `StateListener` adapter that forwards each transition to a JS
/// function as a single `string` argument matching
/// [`ConnectionState::as_str`].
#[cfg(target_arch = "wasm32")]
struct JsStateListener {
    cb: SendWrapper<js_sys::Function>,
}

#[cfg(target_arch = "wasm32")]
impl StateListener for JsStateListener {
    fn on_state_change(&self, state: ConnectionState) {
        // Best-effort — a throwing JS callback shouldn't take the client
        // down, so we drop the Result.
        let _ = (*self.cb).call1(&JsValue::NULL, &JsValue::from_str(state.as_str()));
    }
}

/// `SyncProgress` adapter that serialises each event as a plain JSON
/// object and invokes the JS function with one argument.
///
/// Event shapes (`type` discriminates):
/// * `{ type: "step_start", stepIndex, totalSteps, description }`
/// * `{ type: "step_progress", stepIndex, progress }`
/// * `{ type: "step_complete", stepIndex }`
/// * `{ type: "complete", syncedHeight }`
/// * `{ type: "error", message }`
#[cfg(target_arch = "wasm32")]
struct JsSyncProgress {
    cb: SendWrapper<js_sys::Function>,
}

#[cfg(target_arch = "wasm32")]
impl JsSyncProgress {
    fn emit(&self, event: serde_json::Value) {
        let val = to_js_object(&event);
        let _ = (*self.cb).call1(&JsValue::NULL, &val);
    }
}

#[cfg(target_arch = "wasm32")]
impl SyncProgress for JsSyncProgress {
    fn on_step_start(&self, step_index: usize, total_steps: usize, description: &str) {
        self.emit(serde_json::json!({
            "type": "step_start",
            "stepIndex": step_index,
            "totalSteps": total_steps,
            "description": description,
        }));
    }

    fn on_step_progress(&self, step_index: usize, progress: f32) {
        self.emit(serde_json::json!({
            "type": "step_progress",
            "stepIndex": step_index,
            "progress": progress,
        }));
    }

    fn on_step_complete(&self, step_index: usize) {
        self.emit(serde_json::json!({
            "type": "step_complete",
            "stepIndex": step_index,
        }));
    }

    fn on_complete(&self, synced_height: u32) {
        self.emit(serde_json::json!({
            "type": "complete",
            "syncedHeight": synced_height,
        }));
    }

    fn on_error(&self, error: &pir_sdk::PirError) {
        self.emit(serde_json::json!({
            "type": "error",
            "message": error.to_string(),
        }));
    }
}

/// `HintProgress` adapter that serialises each per-group event as a
/// plain JSON object and invokes the JS function with one argument.
///
/// Event shape: `{ done: number, total: number, phase: "index" | "chunk" }`.
/// `done` is the running count of groups whose hints have been loaded;
/// `total` is the constant `index_k + chunk_k` (typically 155 for the
/// production HarmonyPIR config). The callback fires once per main
/// group on a fresh fetch, or once with `done === total` on a cache
/// hit / already-loaded state.
#[cfg(target_arch = "wasm32")]
struct JsHintProgress {
    cb: SendWrapper<js_sys::Function>,
}

#[cfg(target_arch = "wasm32")]
impl HintProgress for JsHintProgress {
    fn on_group_complete(&self, done: u32, total: u32, phase: &str) {
        let event = serde_json::json!({
            "done": done,
            "total": total,
            "phase": phase,
        });
        let val = to_js_object(&event);
        // Best-effort — a throwing JS callback shouldn't take the hint
        // fetch down, so we drop the Result.
        let _ = (*self.cb).call1(&JsValue::NULL, &val);
    }
}

// ─── WasmSyncResult ─────────────────────────────────────────────────────────

/// WASM wrapper for [`SyncResult`].
///
/// Exposes the merged per-script-hash results plus sync metadata
/// (`syncedHeight`, `wasFreshSync`). Entries are surfaced both as
/// individual [`WasmQueryResult`] objects (so callers that already use
/// the typed class get the same API) and as a JSON blob (so callers that
/// just want to splat the result into a UI get a plain object).
#[wasm_bindgen]
pub struct WasmSyncResult {
    inner: SyncResult,
}

#[wasm_bindgen]
impl WasmSyncResult {
    /// Number of per-script-hash result slots (= length of the input
    /// `scriptHashes` array passed to `sync`).
    #[wasm_bindgen(getter, js_name = resultCount)]
    pub fn result_count(&self) -> usize {
        self.inner.results.len()
    }

    /// Synced height — the tip height the final merged result reflects.
    ///
    /// For servers that don't publish a height (legacy Harmony without
    /// `REQ_GET_DB_CATALOG`), this is `0`. See `CLAUDE.md` →
    /// "HarmonyClient REQ_GET_DB_CATALOG with legacy fallback" for the
    /// upgrade path.
    #[wasm_bindgen(getter, js_name = syncedHeight)]
    pub fn synced_height(&self) -> u32 {
        self.inner.synced_height
    }

    /// Whether the sync started from a fresh snapshot (vs an incremental
    /// delta chain from a previous height).
    #[wasm_bindgen(getter, js_name = wasFreshSync)]
    pub fn was_fresh_sync(&self) -> bool {
        self.inner.was_fresh_sync
    }

    /// Get the per-script-hash [`WasmQueryResult`] at `index`, or `null`
    /// if the script hash was not found (and Merkle-verified absent when
    /// the DB publishes commitments).
    ///
    /// Mirrors the `results: Vec<Option<QueryResult>>` shape of the
    /// underlying sync: `None` = verified absent, `Some(qr)` with
    /// `merkleVerified = false` = untrusted/tainted result.
    #[wasm_bindgen(js_name = getResult)]
    pub fn get_result(&self, index: usize) -> Option<WasmQueryResult> {
        self.inner
            .results
            .get(index)
            .and_then(|r| r.as_ref())
            .cloned()
            .map(WasmQueryResult::from_native)
    }

    /// Convert the full sync result to a plain JSON object.
    ///
    /// Shape:
    /// ```json
    /// {
    ///   "results": [
    ///     null,
    ///     { "entries": [...], "isWhale": false,
    ///       "totalBalance": 0, "merkleVerified": true }
    ///   ],
    ///   "syncedHeight": 900000,
    ///   "wasFreshSync": true
    /// }
    /// ```
    #[wasm_bindgen(js_name = toJson)]
    pub fn to_json(&self) -> JsValue {
        to_js_object(&sync_result_to_json(&self.inner))
    }
}

// ─── WasmDpfClient ──────────────────────────────────────────────────────────

/// Two-server DPF-PIR client exposed to JavaScript.
///
/// On the browser this is the recommended backend: stateless per query,
/// no FHE keys to register, and the fastest query round-trip of the
/// three backends. Construct with two `ws://` / `wss://` URLs, `connect`,
/// then call `sync` / `queryBatch`.
///
/// ```javascript
/// import init, { WasmDpfClient } from 'pir-sdk-wasm';
/// await init();
/// const client = new WasmDpfClient('wss://pir1...', 'wss://pir2...');
/// await client.connect();
/// const res = await client.sync(scriptHashesU8, null);
/// ```
#[wasm_bindgen]
pub struct WasmDpfClient {
    inner: DpfClient,
}

#[wasm_bindgen]
impl WasmDpfClient {
    /// Create a new DPF client. No network I/O happens until `connect` is
    /// called.
    #[wasm_bindgen(constructor)]
    pub fn new(server0_url: &str, server1_url: &str) -> Self {
        Self {
            inner: DpfClient::new(server0_url, server1_url),
        }
    }

    /// Open WebSocket connections to both servers and run the PIR
    /// handshake. Idempotent — calling twice is safe (the second call
    /// returns early via `PirClient::is_connected`).
    ///
    /// Rejects on malformed URL, CORS violation, or server refusal.
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(&mut self) -> Result<(), JsError> {
        self.inner.connect().await.map_err(err_to_js)
    }

    /// Close both WebSocket connections. After this the client returns
    /// `isConnected === false` and `connect` must be called before the
    /// next query.
    #[wasm_bindgen(js_name = disconnect)]
    pub async fn disconnect(&mut self) -> Result<(), JsError> {
        self.inner.disconnect().await.map_err(err_to_js)
    }

    /// True while both `conn0` and `conn1` are live.
    #[wasm_bindgen(getter, js_name = isConnected)]
    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    /// Fetch the database catalog from the server.
    ///
    /// Returns a [`WasmDatabaseCatalog`] wrapping the native catalog —
    /// the same class returned by
    /// `WasmDatabaseCatalog.fromJson(...)` for the TS fallback path, so
    /// downstream sync-planning code works on both surfaces.
    #[wasm_bindgen(js_name = fetchCatalog)]
    pub async fn fetch_catalog(&mut self) -> Result<WasmDatabaseCatalog, JsError> {
        let catalog = self.inner.fetch_catalog().await.map_err(err_to_js)?;
        Ok(WasmDatabaseCatalog::from_native(catalog))
    }

    /// End-to-end sync: fetch catalog, plan, execute all steps, merge
    /// deltas. Returns a [`WasmSyncResult`] whose `results[i]`
    /// corresponds to the i-th script hash in the packed input.
    ///
    /// # Arguments
    /// * `script_hashes` — packed `Uint8Array` of length `20 * N`
    /// * `last_height` — `null`/`undefined` for fresh sync, otherwise the
    ///   last-synced height to compute a delta chain from
    #[wasm_bindgen(js_name = sync)]
    pub async fn sync(
        &mut self,
        script_hashes: &Uint8Array,
        last_height: Option<u32>,
    ) -> Result<WasmSyncResult, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let result = self
            .inner
            .sync(&script_hashes, last_height)
            .await
            .map_err(err_to_js)?;
        Ok(WasmSyncResult { inner: result })
    }

    /// Low-level: query a single database by `db_id` without the
    /// catalog/plan orchestration. Matches
    /// `PirClient::query_batch`.
    ///
    /// Returns a JSON array of length `N`, each element either `null`
    /// (not found) or a `QueryResult` JSON object (see
    /// `WasmQueryResult.toJson()` for the shape).
    #[wasm_bindgen(js_name = queryBatch)]
    pub async fn query_batch(
        &mut self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let results = self
            .inner
            .query_batch(&script_hashes, db_id)
            .await
            .map_err(err_to_js)?;
        let json: Vec<serde_json::Value> = results
            .iter()
            .map(|r| match r {
                None => serde_json::Value::Null,
                Some(qr) => {
                    let entries: Vec<serde_json::Value> = qr
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
                    serde_json::json!({
                        "entries": entries,
                        "isWhale": qr.is_whale,
                        "totalBalance": qr.total_balance(),
                        "merkleVerified": qr.merkle_verified,
                    })
                }
            })
            .collect();
        Ok(to_js_object(&json))
    }

    /// Return the two server URLs this client is connected to as a
    /// `[string, string]` array (order matches the constructor:
    /// `[server0_url, server1_url]`).
    ///
    /// Safe to call at any time — no network I/O, no connection state
    /// needed.
    #[wasm_bindgen(js_name = serverUrls)]
    pub fn server_urls(&self) -> JsValue {
        let (a, b) = self.inner.server_urls();
        let arr = Array::new();
        arr.push(&JsValue::from_str(a));
        arr.push(&JsValue::from_str(b));
        arr.into()
    }

    /// Inspector-path batch query — like [`queryBatch`](Self::query_batch)
    /// but returns opaque [`WasmQueryResult`] handles whose
    /// `indexBins`/`chunkBins`/`matchedIndexIdx` accessors are populated,
    /// and whose per-query Merkle verification has been **skipped**.
    ///
    /// This is the pair-wise half of the split-verify flow: call this,
    /// persist or inspect the results, then later call
    /// [`verifyMerkleBatch`](Self::verify_merkle_batch) against the same
    /// `db_id` to obtain the per-query verdicts.
    ///
    /// Returns a JS `Array` of length `N` (the input scripthash count).
    /// Every slot is a non-null [`WasmQueryResult`] — not-found queries
    /// are synthesised as empty inspector-populated results so the
    /// absence-proof bins are preserved for verification.
    ///
    /// 🔒 Padding invariants are preserved (K=75 INDEX / K_CHUNK=80
    /// CHUNK groups), including when most queries are not-found — the
    /// wire-level batch is unchanged.
    #[wasm_bindgen(js_name = queryBatchRaw)]
    pub async fn query_batch_raw(
        &mut self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let results = self
            .inner
            .query_batch_with_inspector(&script_hashes, db_id)
            .await
            .map_err(err_to_js)?;
        let arr = Array::new();
        for r in results {
            match r {
                Some(qr) => {
                    arr.push(&JsValue::from(WasmQueryResult::from_native(qr)));
                }
                None => {
                    // `query_batch_with_inspector` synthesises `Some(empty)`
                    // for not-found, so we shouldn't land here in practice;
                    // forward `null` if the contract ever changes.
                    arr.push(&JsValue::NULL);
                }
            }
        }
        Ok(arr.into())
    }

    /// Standalone Merkle verifier — consumes inspector-populated
    /// QueryResults (as JSON, typically produced by
    /// [`queryBatchRaw`](Self::query_batch_raw) then
    /// `WasmQueryResult.toJson()` and possibly round-tripped through
    /// persistent storage) and returns one `bool` per input.
    ///
    /// # Arguments
    /// * `results_json` — JS `Array` where each element is either `null`
    ///   (caller had nothing to verify for that slot — always returns
    ///   `true`) or a `QueryResult` JSON object including `indexBins` /
    ///   `chunkBins` / `matchedIndexIdx`.
    /// * `db_id` — database to verify against.
    ///
    /// # Returns
    /// JS `Array` of `bool`:
    /// * `true`  — all attached Merkle items verified, or nothing to
    ///   verify at this slot.
    /// * `false` — at least one Merkle proof failed; callers should
    ///   treat the slot as untrusted.
    ///
    /// Databases that don't publish a bucket-Merkle tree are accepted
    /// trivially (every slot returns `true`).
    #[wasm_bindgen(js_name = verifyMerkleBatch)]
    pub async fn verify_merkle_batch(
        &mut self,
        results_json: &JsValue,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let data: serde_json::Value = serde_wasm_bindgen::from_value(results_json.clone())
            .map_err(|e| JsError::new(&format!("JSON parse error: {}", e)))?;
        let items = data
            .as_array()
            .ok_or_else(|| JsError::new("verifyMerkleBatch: results must be an array"))?;

        let mut parsed: Vec<Option<QueryResult>> = Vec::with_capacity(items.len());
        for v in items {
            if v.is_null() {
                parsed.push(None);
            } else {
                parsed.push(Some(parse_query_result_json(v)?));
            }
        }

        let verdicts = self
            .inner
            .verify_merkle_batch_for_results(&parsed, db_id)
            .await
            .map_err(err_to_js)?;

        let arr = Array::new();
        for ok in verdicts {
            arr.push(&JsValue::from_bool(ok));
        }
        Ok(arr.into())
    }

    /// Install a [`WasmAtomicMetrics`] recorder. All subsequent
    /// connect / disconnect / byte / query-lifecycle events are
    /// recorded on the shared atomic counters.
    ///
    /// Pre- and post-connect installs both work: if the client is
    /// already connected, the recorder is pushed to both transports
    /// immediately so it starts seeing byte traffic on the very next
    /// frame; otherwise the handle is held until `connect` wires up
    /// the fresh transports.
    ///
    /// The recorder is held behind an `Arc`, so installing the same
    /// [`WasmAtomicMetrics`] on multiple clients aggregates counters
    /// across all of them. Call [`clearMetricsRecorder`](Self::clear_metrics_recorder)
    /// to uninstall.
    ///
    /// 🔒 Padding invariants unaffected — the metrics surface is
    /// observational only and cannot influence the number or content
    /// of padding queries sent.
    #[wasm_bindgen(js_name = setMetricsRecorder)]
    pub fn set_metrics_recorder(&mut self, metrics: &WasmAtomicMetrics) {
        self.inner
            .set_metrics_recorder(Some(metrics.recorder_handle()));
    }

    /// Uninstall the currently-registered metrics recorder. Subsequent
    /// events are silenced on this client — any previously-shared
    /// [`WasmAtomicMetrics`] handle held by JS continues to reflect
    /// the last observed state and can still be installed on other
    /// clients.
    #[wasm_bindgen(js_name = clearMetricsRecorder)]
    pub fn clear_metrics_recorder(&mut self) {
        self.inner.set_metrics_recorder(None);
    }
}

/// wasm32-only: progress-aware sync and state-change observer.
///
/// These take `js_sys::Function` arguments and install wasm32-only
/// bridges ([`JsSyncProgress`] / [`JsStateListener`]) into the native
/// client. Both bridges rely on `send_wrapper::SendWrapper`, which is
/// sound only on single-threaded wasm32; that's why the whole block is
/// cfg-gated. Native callers use `DpfClient::set_state_listener` /
/// `DpfClient::sync_with_progress` directly.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl WasmDpfClient {
    /// Run an end-to-end sync, firing progress events to the given JS
    /// callback for every step transition.
    ///
    /// The callback receives a single argument — a plain JS object —
    /// whose `type` discriminates: `"step_start"`, `"step_progress"`,
    /// `"step_complete"`, `"complete"`, or `"error"`. See
    /// [`JsSyncProgress`] for the exact field set per event type.
    ///
    /// Argument semantics match [`sync`](Self::sync) otherwise.
    /// Callback exceptions are swallowed — a broken progress sink must
    /// not take the sync down.
    #[wasm_bindgen(js_name = syncWithProgress)]
    pub async fn sync_with_progress(
        &mut self,
        script_hashes: &Uint8Array,
        last_height: Option<u32>,
        progress: js_sys::Function,
    ) -> Result<WasmSyncResult, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let prog = JsSyncProgress {
            cb: SendWrapper::new(progress),
        };
        let result = self
            .inner
            .sync_with_progress(&script_hashes, last_height, &prog)
            .await
            .map_err(err_to_js)?;
        Ok(WasmSyncResult { inner: result })
    }

    /// Register a JS callback to be invoked on every
    /// [`ConnectionState`](pir_sdk::ConnectionState) transition.
    ///
    /// The callback receives a single `string` argument: one of
    /// `"connecting"`, `"connected"`, `"disconnected"` (see
    /// [`ConnectionState::as_str`](pir_sdk::ConnectionState::as_str)).
    /// Replaces any previously registered callback — only one listener
    /// per client. Pass-through behaviour matches the underlying
    /// [`DpfClient::set_state_listener`].
    ///
    /// Callback exceptions are swallowed.
    #[wasm_bindgen(js_name = onStateChange)]
    pub fn on_state_change(&mut self, cb: js_sys::Function) {
        let listener = Arc::new(JsStateListener {
            cb: SendWrapper::new(cb),
        });
        self.inner.set_state_listener(Some(listener));
    }
}

// ─── WasmHarmonyClient ──────────────────────────────────────────────────────

/// Two-server HarmonyPIR client (hint server + query server) exposed to
/// JavaScript.
///
/// HarmonyPIR has a stateful hint phase — hints are fetched from the
/// hint server once per `(db_id, level)` and replayed against the query
/// server for each query. The wrapper preserves this: a single
/// `WasmHarmonyClient` reuses hints across multiple `sync` calls on the
/// same database, so amortised cost drops after the first query.
///
/// ```javascript
/// import init, { WasmHarmonyClient } from 'pir-sdk-wasm';
/// await init();
/// const client = new WasmHarmonyClient('wss://hint...', 'wss://query...');
/// await client.connect();
/// const res = await client.sync(scriptHashesU8, null);
/// ```
#[wasm_bindgen]
pub struct WasmHarmonyClient {
    inner: HarmonyClient,
}

#[wasm_bindgen]
impl WasmHarmonyClient {
    /// Create a new HarmonyPIR client. Generates a random master PRP key
    /// from `performance.now()`-ish entropy (see `HarmonyClient::new`).
    /// Callers that want a stable key (e.g. to reuse cached hints across
    /// sessions) must call `setMasterKey`.
    #[wasm_bindgen(constructor)]
    pub fn new(hint_server_url: &str, query_server_url: &str) -> Self {
        Self {
            inner: HarmonyClient::new(hint_server_url, query_server_url),
        }
    }

    /// Override the 16-byte master PRP key. Invalidates any previously
    /// loaded hints — the next `sync`/`queryBatch` call will re-fetch.
    ///
    /// Rejects if `key` is not exactly 16 bytes.
    #[wasm_bindgen(js_name = setMasterKey)]
    pub fn set_master_key(&mut self, key: &[u8]) -> Result<(), JsError> {
        validate_master_key_len(key.len()).map_err(|e| JsError::new(&e))?;
        let mut arr = [0u8; 16];
        arr.copy_from_slice(key);
        self.inner.set_master_key(arr);
        Ok(())
    }

    /// Select the PRP backend.
    ///
    /// Accepts any of the [`PRP_HMR12`], [`PRP_FASTPRP`], [`PRP_ALF`]
    /// constants. [`PRP_HMR12`] is the reference backend (always
    /// available); the faster backends require the corresponding cargo
    /// features on the enclosing build.
    #[wasm_bindgen(js_name = setPrpBackend)]
    pub fn set_prp_backend(&mut self, backend: u8) -> Result<(), JsError> {
        validate_prp_backend(backend).map_err(|e| JsError::new(&e))?;
        self.inner.set_prp_backend(backend);
        Ok(())
    }

    /// Open WebSocket connections to both hint and query servers.
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(&mut self) -> Result<(), JsError> {
        self.inner.connect().await.map_err(err_to_js)
    }

    /// Close both WebSocket connections.
    #[wasm_bindgen(js_name = disconnect)]
    pub async fn disconnect(&mut self) -> Result<(), JsError> {
        self.inner.disconnect().await.map_err(err_to_js)
    }

    /// True while both connections are live.
    #[wasm_bindgen(getter, js_name = isConnected)]
    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    /// Fetch the database catalog from the hint server.
    #[wasm_bindgen(js_name = fetchCatalog)]
    pub async fn fetch_catalog(&mut self) -> Result<WasmDatabaseCatalog, JsError> {
        let catalog = self.inner.fetch_catalog().await.map_err(err_to_js)?;
        Ok(WasmDatabaseCatalog::from_native(catalog))
    }

    /// End-to-end sync. See [`WasmDpfClient::sync`] for argument
    /// semantics — the wire path differs but the JS-facing shape is
    /// identical.
    #[wasm_bindgen(js_name = sync)]
    pub async fn sync(
        &mut self,
        script_hashes: &Uint8Array,
        last_height: Option<u32>,
    ) -> Result<WasmSyncResult, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let result = self
            .inner
            .sync(&script_hashes, last_height)
            .await
            .map_err(err_to_js)?;
        Ok(WasmSyncResult { inner: result })
    }

    /// Low-level: query a single database by `db_id`. See
    /// [`WasmDpfClient::query_batch`].
    #[wasm_bindgen(js_name = queryBatch)]
    pub async fn query_batch(
        &mut self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let results = self
            .inner
            .query_batch(&script_hashes, db_id)
            .await
            .map_err(err_to_js)?;
        let json: Vec<serde_json::Value> = results
            .iter()
            .map(|r| match r {
                None => serde_json::Value::Null,
                Some(qr) => {
                    let entries: Vec<serde_json::Value> = qr
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
                    serde_json::json!({
                        "entries": entries,
                        "isWhale": qr.is_whale,
                        "totalBalance": qr.total_balance(),
                        "merkleVerified": qr.merkle_verified,
                    })
                }
            })
            .collect();
        Ok(to_js_object(&json))
    }

    // ─── Session 5: inspector / verify / DB-switch / hint-cache surface ─────

    /// Return the two server URLs this client is connected to as a
    /// `[string, string]` array (order matches the constructor:
    /// `[hint_server_url, query_server_url]`).
    ///
    /// Safe to call at any time — no network I/O, no connection state
    /// needed. Mirrors [`WasmDpfClient::server_urls`].
    #[wasm_bindgen(js_name = serverUrls)]
    pub fn server_urls(&self) -> JsValue {
        let (h, q) = self.inner.server_urls();
        let arr = Array::new();
        arr.push(&JsValue::from_str(h));
        arr.push(&JsValue::from_str(q));
        arr.into()
    }

    /// Inspector-path batch query — like [`queryBatch`](Self::query_batch)
    /// but returns opaque [`WasmQueryResult`] handles whose
    /// `indexBins`/`chunkBins`/`matchedIndexIdx` accessors are populated,
    /// and whose per-query Merkle verification has been **skipped**.
    ///
    /// See [`WasmDpfClient::query_batch_raw`] for the full split-verify
    /// flow description. The Harmony wrapper exposes the same JS-facing
    /// contract despite the different wire protocol underneath.
    ///
    /// 🔒 Padding invariants are preserved (K=75 INDEX / K_CHUNK=80
    /// CHUNK groups) — padding lives in the native `HarmonyClient` query
    /// path that this wrapper delegates to.
    #[wasm_bindgen(js_name = queryBatchRaw)]
    pub async fn query_batch_raw(
        &mut self,
        script_hashes: &Uint8Array,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let results = self
            .inner
            .query_batch_with_inspector(&script_hashes, db_id)
            .await
            .map_err(err_to_js)?;
        let arr = Array::new();
        for r in results {
            match r {
                Some(qr) => {
                    arr.push(&JsValue::from(WasmQueryResult::from_native(qr)));
                }
                None => {
                    // `query_batch_with_inspector` synthesises `Some(empty)`
                    // for not-found; fall through to null if the contract
                    // ever changes.
                    arr.push(&JsValue::NULL);
                }
            }
        }
        Ok(arr.into())
    }

    /// Standalone Merkle verifier over inspector-populated QueryResults.
    /// See [`WasmDpfClient::verify_merkle_batch`] for the full argument
    /// / return contract — the Harmony implementation uses the same
    /// per-bucket machinery via the `HarmonySiblingQuerier` transport
    /// path, so the JS-facing behaviour is identical.
    #[wasm_bindgen(js_name = verifyMerkleBatch)]
    pub async fn verify_merkle_batch(
        &mut self,
        results_json: &JsValue,
        db_id: u8,
    ) -> Result<JsValue, JsError> {
        let data: serde_json::Value = serde_wasm_bindgen::from_value(results_json.clone())
            .map_err(|e| JsError::new(&format!("JSON parse error: {}", e)))?;
        let items = data
            .as_array()
            .ok_or_else(|| JsError::new("verifyMerkleBatch: results must be an array"))?;

        let mut parsed: Vec<Option<QueryResult>> = Vec::with_capacity(items.len());
        for v in items {
            if v.is_null() {
                parsed.push(None);
            } else {
                parsed.push(Some(parse_query_result_json(v)?));
            }
        }

        let verdicts = self
            .inner
            .verify_merkle_batch_for_results(&parsed, db_id)
            .await
            .map_err(err_to_js)?;

        let arr = Array::new();
        for ok in verdicts {
            arr.push(&JsValue::from_bool(ok));
        }
        Ok(arr.into())
    }

    /// Get the currently-loaded `db_id`, or `null` if no hints are
    /// loaded. See [`HarmonyClient::db_id`] for semantics.
    #[wasm_bindgen(js_name = dbId)]
    pub fn db_id(&self) -> Option<u8> {
        self.inner.db_id()
    }

    /// Pin this client's hint state to `db_id`. If hints for a different
    /// db are currently loaded, invalidates them — the next
    /// `sync`/`queryBatch`/`queryBatchRaw` will re-fetch (or restore
    /// from the hint cache if configured).
    ///
    /// Idempotent when `db_id` already matches the loaded state.
    #[wasm_bindgen(js_name = setDbId)]
    pub fn set_db_id(&mut self, db_id: u8) {
        self.inner.set_db_id(db_id);
    }

    /// Minimum remaining per-group query budget across every loaded
    /// `HarmonyGroup`. Returns `null` when nothing is loaded — callers
    /// should treat that as "unknown, call `sync` or `queryBatch` first".
    ///
    /// UI surfaces use this to decide when to proactively refresh hints.
    #[wasm_bindgen(js_name = minQueriesRemaining)]
    pub fn min_queries_remaining(&self) -> Option<u32> {
        self.inner.min_queries_remaining()
    }

    /// Byte size the blob [`save_hints`](Self::save_hints) would produce
    /// right now. Returns `0` when no state is loaded or the client is
    /// in an inconsistent state (e.g. catalog missing).
    ///
    /// O(total hint bytes); fine for UI-polling cadence but not for
    /// the hot query path.
    #[wasm_bindgen(js_name = estimateHintSizeBytes)]
    pub fn estimate_hint_size_bytes(&self) -> u32 {
        // `usize` is 32-bit on wasm32; on native unit tests we truncate.
        // Hints are capped far below u32::MAX in practice so this is
        // always accurate in realistic deployments.
        self.inner.estimate_hint_size_bytes() as u32
    }

    /// 16-byte fingerprint of the cache key for the given catalog +
    /// `db_id`, under this client's current master key and PRP backend.
    /// Returns a fresh `Uint8Array` of length 16 on success.
    ///
    /// Rejects with `JsError` when the catalog doesn't carry `db_id`.
    /// The fingerprint matches the one embedded in the `saveHints` blob
    /// header and the on-disk cache filename stem, so the JS-side
    /// IndexedDB bridge can key cache entries on it directly.
    #[wasm_bindgen(js_name = fingerprint)]
    pub fn fingerprint(
        &self,
        catalog: &WasmDatabaseCatalog,
        db_id: u8,
    ) -> Result<Uint8Array, JsError> {
        let db_info = catalog
            .inner()
            .get(db_id)
            .ok_or_else(|| JsError::new(&format!("no database with db_id={}", db_id)))?;
        let fp = self.inner.cache_fingerprint(db_info);
        Ok(Uint8Array::from(&fp[..]))
    }

    /// Serialise the currently-loaded hint state to a self-describing
    /// binary blob. Returns a fresh `Uint8Array`, or `null` if no hints
    /// are loaded.
    ///
    /// The blob embeds a 16-byte fingerprint (see
    /// [`fingerprint`](Self::fingerprint)) so a later `loadHints` call
    /// against a mismatched database or master key fails cleanly
    /// instead of returning corrupted state. Safe to persist to
    /// IndexedDB as an opaque byte array.
    #[wasm_bindgen(js_name = saveHints)]
    pub fn save_hints(&self) -> Result<JsValue, JsError> {
        match self.inner.save_hints_bytes().map_err(err_to_js)? {
            Some(bytes) => Ok(Uint8Array::from(&bytes[..]).into()),
            None => Ok(JsValue::NULL),
        }
    }

    /// Restore hint state from a blob previously produced by
    /// [`saveHints`](Self::save_hints).
    ///
    /// The blob's embedded fingerprint is cross-checked against
    /// `(masterKey, prpBackend, catalog.get(db_id))`: a mismatch (wrong
    /// db shape, different master key, etc.) rejects with `JsError`
    /// rather than silently loading stale hints. Rejects with `JsError`
    /// when the catalog doesn't carry `db_id`.
    ///
    /// On success the client transitions into the same state it would
    /// be in after a fresh `sync` / `queryBatch` against `db_id` — i.e.
    /// `dbId() === db_id`, main `HarmonyGroup`s are populated, and the
    /// next query skips the hint-fetch network roundtrips.
    #[wasm_bindgen(js_name = loadHints)]
    pub fn load_hints(
        &mut self,
        bytes: &[u8],
        catalog: &WasmDatabaseCatalog,
        db_id: u8,
    ) -> Result<(), JsError> {
        let db_info = catalog
            .inner()
            .get(db_id)
            .ok_or_else(|| JsError::new(&format!("no database with db_id={}", db_id)))?;
        self.inner.load_hints_bytes(bytes, db_info).map_err(err_to_js)
    }

    /// Install a [`WasmAtomicMetrics`] recorder.
    ///
    /// See [`WasmDpfClient::set_metrics_recorder`] for the full
    /// install + aggregation contract — the Harmony implementation
    /// propagates the handle to both transports (hint + query) with
    /// the `"harmony"` backend label, so a single
    /// [`WasmAtomicMetrics`] installed on a DPF and a Harmony client
    /// simultaneously can aggregate counters across both backends.
    ///
    /// 🔒 Padding invariants unaffected.
    #[wasm_bindgen(js_name = setMetricsRecorder)]
    pub fn set_metrics_recorder(&mut self, metrics: &WasmAtomicMetrics) {
        self.inner
            .set_metrics_recorder(Some(metrics.recorder_handle()));
    }

    /// Uninstall the currently-registered metrics recorder. See
    /// [`WasmDpfClient::clear_metrics_recorder`].
    #[wasm_bindgen(js_name = clearMetricsRecorder)]
    pub fn clear_metrics_recorder(&mut self) {
        self.inner.set_metrics_recorder(None);
    }
}

/// wasm32-only: progress-aware sync and state-change observer for
/// HarmonyPIR. Mirrors [`WasmDpfClient`]'s wasm32 extension block —
/// same [`JsSyncProgress`] / [`JsStateListener`] bridges, same callback
/// contract. See the DPF version for the full event shape reference.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl WasmHarmonyClient {
    /// Run an end-to-end sync, firing progress events to the given JS
    /// callback for every step transition. See
    /// [`WasmDpfClient::sync_with_progress`] for the full argument +
    /// event-shape contract.
    #[wasm_bindgen(js_name = syncWithProgress)]
    pub async fn sync_with_progress(
        &mut self,
        script_hashes: &Uint8Array,
        last_height: Option<u32>,
        progress: js_sys::Function,
    ) -> Result<WasmSyncResult, JsError> {
        let packed = script_hashes.to_vec();
        let script_hashes = unpack_script_hashes(&packed).map_err(|e| JsError::new(&e))?;
        let prog = JsSyncProgress {
            cb: SendWrapper::new(progress),
        };
        let result = self
            .inner
            .sync_with_progress(&script_hashes, last_height, &prog)
            .await
            .map_err(err_to_js)?;
        Ok(WasmSyncResult { inner: result })
    }

    /// Register a JS callback to be invoked on every
    /// [`ConnectionState`](pir_sdk::ConnectionState) transition. See
    /// [`WasmDpfClient::on_state_change`].
    #[wasm_bindgen(js_name = onStateChange)]
    pub fn on_state_change(&mut self, cb: js_sys::Function) {
        let listener = Arc::new(JsStateListener {
            cb: SendWrapper::new(cb),
        });
        self.inner.set_state_listener(Some(listener));
    }

    /// Pre-fetch the main hint state for `dbId`, firing `progress` after
    /// each per-group response is loaded. Replaces the legacy "issue a
    /// dummy query to warm hints" pattern with a dedicated entry point
    /// that surfaces per-group progress directly.
    ///
    /// `progress` is invoked with one argument:
    /// `{ done, total, phase }` (see `JsHintProgress` for the contract).
    /// `total` equals `index_k + chunk_k` for the active database
    /// (typically 75 + 80 = 155). On a cache hit / already-loaded
    /// state, `progress` fires once with `done === total`.
    ///
    /// Rejects with `JsError` if the catalog doesn't carry `dbId` or
    /// the client isn't connected.
    ///
    /// 🔒 Padding invariants are unaffected — wire shape matches the
    /// no-progress hint-fetch path.
    #[wasm_bindgen(js_name = fetchHintsWithProgress)]
    pub async fn fetch_hints_with_progress(
        &mut self,
        catalog: &WasmDatabaseCatalog,
        db_id: u8,
        progress: js_sys::Function,
    ) -> Result<(), JsError> {
        let db_info = catalog
            .inner()
            .get(db_id)
            .ok_or_else(|| JsError::new(&format!("no database with db_id={}", db_id)))?
            .clone();
        let prog = JsHintProgress {
            cb: SendWrapper::new(progress),
        };
        self.inner
            .fetch_hints_with_progress(&db_info, &prog)
            .await
            .map_err(err_to_js)
    }
}

// ─── PRP backend constants (re-exported as JS number constants) ─────────────

/// PRP backend constant for the reference `HMR12` implementation.
/// Always available.
#[wasm_bindgen(js_name = PRP_HMR12)]
pub fn prp_hmr12() -> u8 {
    PRP_HMR12
}

/// PRP backend constant for `FastPRP`. Requires the `fastprp` cargo
/// feature on the enclosing build.
#[wasm_bindgen(js_name = PRP_FASTPRP)]
pub fn prp_fastprp() -> u8 {
    PRP_FASTPRP
}

/// PRP backend constant for `ALF`. Requires the `alf` cargo feature on
/// the enclosing build.
#[wasm_bindgen(js_name = PRP_ALF)]
pub fn prp_alf() -> u8 {
    PRP_ALF
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_script_hashes_empty_input_ok() {
        let out = unpack_script_hashes(&[]).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn unpack_script_hashes_multiple_of_20_ok() {
        let mut buf = Vec::new();
        for i in 0..3u8 {
            buf.extend(std::iter::repeat(i).take(20));
        }
        let out = unpack_script_hashes(&buf).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0], [0u8; 20]);
        assert_eq!(out[1], [1u8; 20]);
        assert_eq!(out[2], [2u8; 20]);
    }

    #[test]
    fn unpack_script_hashes_non_multiple_errors() {
        let buf = vec![0u8; 19];
        assert!(unpack_script_hashes(&buf).is_err());
        let buf = vec![0u8; 21];
        assert!(unpack_script_hashes(&buf).is_err());
        let buf = vec![0u8; 41];
        assert!(unpack_script_hashes(&buf).is_err());
    }

    #[test]
    fn wasm_dpf_client_construct_and_introspect() {
        let client = WasmDpfClient::new("ws://a:1", "ws://b:2");
        assert!(!client.is_connected());
    }

    #[test]
    fn wasm_harmony_client_construct_and_introspect() {
        let client = WasmHarmonyClient::new("ws://hint:1", "ws://query:2");
        assert!(!client.is_connected());
    }

    // ─── Session 5: WasmHarmonyClient surface tests (native-safe only) ──────
    //
    // Methods that return `JsValue` / `Uint8Array` / `JsError` can't run
    // on native because those wasm-bindgen imports panic outside wasm32.
    // The tests below cover the native-typed slice of the Session 5
    // surface (dbId / setDbId / minQueriesRemaining /
    // estimateHintSizeBytes + loadHints error paths where the error
    // comes from a `String`-returning helper before hitting `JsError`).

    /// Fresh `WasmHarmonyClient` reports `dbId() === None`, and
    /// `setDbId(0)` stays no-op when no hints are loaded.
    #[test]
    fn wasm_harmony_db_id_defaults_to_none() {
        let mut client = WasmHarmonyClient::new("ws://h:1", "ws://q:2");
        assert_eq!(client.db_id(), None);
        client.set_db_id(0);
        // `set_db_id` only invalidates if the id differs from
        // `loaded_db_id`; with nothing loaded the transition is inert.
        assert_eq!(client.db_id(), None);
    }

    /// `min_queries_remaining()` returns None before any hints are
    /// loaded — mirrors the native accessor.
    #[test]
    fn wasm_harmony_min_queries_remaining_none_when_empty() {
        let client = WasmHarmonyClient::new("ws://h:1", "ws://q:2");
        assert_eq!(client.min_queries_remaining(), None);
    }

    /// `estimate_hint_size_bytes()` is 0 before any hints are loaded.
    #[test]
    fn wasm_harmony_estimate_hint_size_zero_when_empty() {
        let client = WasmHarmonyClient::new("ws://h:1", "ws://q:2");
        assert_eq!(client.estimate_hint_size_bytes(), 0);
    }

    /// Sanity: `serverUrls` returns a 2-element JS array; we can't
    /// inspect the JS side natively but we can assert the native
    /// `inner.server_urls()` returns the constructor arguments
    /// verbatim (what `serverUrls` wraps).
    #[test]
    fn wasm_harmony_inner_server_urls_match_constructor() {
        let client = WasmHarmonyClient::new("wss://h.example", "wss://q.example");
        let (h, q) = client.inner.server_urls();
        assert_eq!(h, "wss://h.example");
        assert_eq!(q, "wss://q.example");
    }

    #[test]
    fn validate_master_key_len_accepts_only_16() {
        assert!(validate_master_key_len(15).is_err());
        assert!(validate_master_key_len(17).is_err());
        assert!(validate_master_key_len(0).is_err());
        assert!(validate_master_key_len(16).is_ok());
    }

    #[test]
    fn validate_prp_backend_matches_constants() {
        assert!(validate_prp_backend(PRP_HMR12).is_ok());
        assert!(validate_prp_backend(PRP_FASTPRP).is_ok());
        assert!(validate_prp_backend(PRP_ALF).is_ok());
        assert!(validate_prp_backend(99).is_err());
        assert!(validate_prp_backend(255).is_err());
    }

    #[test]
    fn prp_constants_reachable() {
        assert_eq!(prp_hmr12(), PRP_HMR12);
        assert_eq!(prp_fastprp(), PRP_FASTPRP);
        assert_eq!(prp_alf(), PRP_ALF);
        // Exercise the uniqueness invariant — the set_prp_backend guard
        // above relies on these three being distinct.
        assert_ne!(PRP_HMR12, PRP_FASTPRP);
        assert_ne!(PRP_FASTPRP, PRP_ALF);
        assert_ne!(PRP_HMR12, PRP_ALF);
    }

    #[test]
    fn sync_result_to_json_shape() {
        use pir_sdk::{QueryResult, SyncResult, UtxoEntry};

        let mut txid = [0u8; 32];
        txid[31] = 0xab;

        let sync = SyncResult {
            results: vec![
                None,
                Some(QueryResult::with_entries(vec![UtxoEntry {
                    txid,
                    vout: 7,
                    amount_sats: 12345,
                }])),
            ],
            synced_height: 900_000,
            was_fresh_sync: true,
        };

        let json = sync_result_to_json(&sync);
        assert_eq!(json["syncedHeight"], 900_000);
        assert_eq!(json["wasFreshSync"], true);
        let results = json["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_null());
        let entries = results[1]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["vout"], 7);
        assert_eq!(entries[0]["amountSats"], 12345);
        // `merkleVerified` defaults to `true` via `QueryResult::with_entries`.
        assert_eq!(results[1]["merkleVerified"], true);
    }

    #[test]
    fn sync_result_to_json_merkle_failed_propagates() {
        use pir_sdk::{QueryResult, SyncResult};

        let sync = SyncResult {
            results: vec![Some(QueryResult::merkle_failed())],
            synced_height: 0,
            was_fresh_sync: false,
        };

        let json = sync_result_to_json(&sync);
        assert_eq!(json["results"][0]["merkleVerified"], false);
        assert_eq!(
            json["results"][0]["entries"].as_array().unwrap().len(),
            0
        );
    }

    // Note: we deliberately don't have a unit test that calls `err_to_js`
    // directly — `JsError::new` is a wasm-bindgen imported function and
    // panics on non-wasm targets. The conversion's correctness is
    // verified at compile time (every `#[wasm_bindgen]` method using
    // `.map_err(err_to_js)` has to type-check).
}
