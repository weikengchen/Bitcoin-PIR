//! WASM bindings for the `pir_sdk::AtomicMetrics` observer.
//!
//! Phase 2+ observability tail: surfaces the native atomic-counter
//! recorder to JavaScript so a browser tools panel / dashboard can
//! poll live PIR query + transport counters.
//!
//! # Usage
//!
//! ```javascript
//! import init, { WasmDpfClient, WasmAtomicMetrics } from 'pir-sdk-wasm';
//! await init();
//!
//! const metrics = new WasmAtomicMetrics();
//! const client = new WasmDpfClient('wss://s0', 'wss://s1');
//! client.setMetricsRecorder(metrics);          // install before connect
//! await client.connect();
//! await client.sync(scriptHashes, null);
//!
//! const snap = metrics.snapshot();             // plain JS object
//! console.log(snap.bytesSent, snap.queriesStarted, snap.queryErrors);
//! //           ^ bigint       ^ bigint          ^ bigint
//!
//! // Latency: every successful or failed query records its duration in
//! // microseconds. `minQueryLatencyMicros` reads as `0xFFFF_FFFF_FFFF_FFFFn`
//! // (the BigInt form of u64::MAX) when no completions have been recorded.
//! const meanMicros =
//!   snap.queriesCompleted + snap.queryErrors === 0n
//!     ? 0n
//!     : snap.totalQueryLatencyMicros /
//!       (snap.queriesCompleted + snap.queryErrors);
//! console.log(snap.minQueryLatencyMicros, meanMicros, snap.maxQueryLatencyMicros);
//! ```
//!
//! The same recorder can be installed on multiple clients — counters
//! aggregate across every client that holds an `Arc` clone of the
//! underlying [`pir_sdk::AtomicMetrics`]. Uninstall with
//! `client.clearMetricsRecorder()`.
//!
//! # Numeric type choice
//!
//! Each counter is a `u64`. JavaScript `Number` is IEEE-754 double,
//! precise only up to 2^53. Byte counters in a long-running session
//! could in principle exceed that (~9 PB), so the snapshot returns
//! each counter as a JS **BigInt**. Callers that prefer `Number`
//! arithmetic can wrap with `Number(snap.bytesSent)` — lossless for
//! values under 2^53.
//!
//! # 🔒 Padding invariants
//!
//! The metrics layer is strictly observational: callbacks receive
//! scalar counters and `&'static str` labels only, never query
//! payloads, hint blobs, secret keys, or padding-critical state. It
//! sits *above* the query code that owns K=75 INDEX / K_CHUNK=80
//! CHUNK / 25-MERKLE padding, and there is no code path by which a
//! recorder can influence the number or content of padding queries
//! sent.

use std::sync::Arc;

use pir_sdk::{AtomicMetrics, AtomicMetricsSnapshot, PirMetrics};
use wasm_bindgen::prelude::*;

// ─── WasmAtomicMetrics ──────────────────────────────────────────────────────

/// Lock-free atomic metrics recorder exposed to JavaScript.
///
/// Wraps `Arc<pir_sdk::AtomicMetrics>`. The `Arc` is cloned once per
/// client install, so counters are shared between JS (via this
/// handle's `snapshot()`) and every client that has the recorder
/// installed via `setMetricsRecorder`. Dropping the JS handle does
/// *not* detach the recorder from installed clients — reinstall or
/// call `clearMetricsRecorder()` on the client if you want the
/// counters to stop.
#[wasm_bindgen]
pub struct WasmAtomicMetrics {
    inner: Arc<AtomicMetrics>,
}

impl Default for WasmAtomicMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl WasmAtomicMetrics {
    /// Construct a fresh recorder with every counter at zero.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicMetrics::new()),
        }
    }

    /// Take a snapshot of every counter at the current instant.
    ///
    /// Returns a plain JS object with sixteen `bigint` fields:
    ///
    /// ```text
    /// {
    ///   queriesStarted:               bigint,
    ///   queriesCompleted:             bigint,
    ///   queryErrors:                  bigint,
    ///   bytesSent:                    bigint,
    ///   bytesReceived:                bigint,
    ///   framesSent:                   bigint,
    ///   framesReceived:               bigint,
    ///   connects:                     bigint,
    ///   disconnects:                  bigint,
    ///   totalQueryLatencyMicros:      bigint,  // sum of every observed query duration
    ///   minQueryLatencyMicros:        bigint,  // u64::MAX before first completion
    ///   maxQueryLatencyMicros:        bigint,  // 0 before first completion
    ///   roundtripsObserved:           bigint,  // count of successful send+recv pairs
    ///   totalRoundtripLatencyMicros:  bigint,  // sum of every observed roundtrip duration
    ///   minRoundtripLatencyMicros:    bigint,  // u64::MAX before first roundtrip
    ///   maxRoundtripLatencyMicros:    bigint,  // 0 before first roundtrip
    /// }
    /// ```
    ///
    /// Individual counters are atomic, but the snapshot as a whole is
    /// NOT — two counters may be observed at slightly different
    /// instants. See [`pir_sdk::AtomicMetrics::snapshot`] for the
    /// consistency caveat.
    ///
    /// Latency-snapshot semantics (apply to both the per-query and
    /// per-roundtrip families):
    /// - `total*LatencyMicros` and `max*LatencyMicros` are 0 when no
    ///   measurements have been recorded.
    /// - `min*LatencyMicros` is `0xFFFF_FFFF_FFFF_FFFFn` (the BigInt
    ///   form of `u64::MAX`) when no measurements have been recorded —
    ///   callers should normalize via
    ///   `snap.minQueryLatencyMicros === 0xFFFF_FFFF_FFFF_FFFFn ? 0n : snap.minQueryLatencyMicros`
    ///   if a 0-when-empty value is preferable.
    ///
    /// `framesSent - roundtripsObserved` is the number of sends that
    /// succeeded but whose matching response failed (transient-network
    /// signal — see [`pir_sdk::PirMetrics::on_roundtrip_end`]).
    #[wasm_bindgen(js_name = snapshot)]
    pub fn snapshot(&self) -> JsValue {
        snapshot_to_js(&self.inner.snapshot())
    }
}

impl WasmAtomicMetrics {
    /// Return a `Send + Sync` trait-object handle suitable for passing
    /// to `DpfClient::set_metrics_recorder` /
    /// `HarmonyClient::set_metrics_recorder`. Clones the inner `Arc` —
    /// the counters are shared with the JS-side handle.
    ///
    /// Crate-visible so the `client.rs` wrappers can install the
    /// recorder without exposing the underlying `Arc<dyn PirMetrics>`
    /// to JavaScript.
    pub(crate) fn recorder_handle(&self) -> Arc<dyn PirMetrics> {
        self.inner.clone()
    }

    /// Raw snapshot as the native `AtomicMetricsSnapshot`. Used by
    /// native unit tests — the `snapshot()` wasm-bindgen method
    /// calls [`js_sys`] APIs that panic outside wasm32.
    #[cfg(test)]
    pub(crate) fn snapshot_raw(&self) -> AtomicMetricsSnapshot {
        self.inner.snapshot()
    }
}

// ─── JS-object builder ──────────────────────────────────────────────────────
//
// Building the JS object via `js_sys::Object::new` + `Reflect::set` keeps
// the u64 → BigInt conversion explicit and avoids any ambiguity in
// `serde_wasm_bindgen`'s number serialization. `js_sys::BigInt::from(u64)`
// is an unchecked cast to a real JS BigInt (see js-sys 0.3.91 line ~3024
// for the `bigint_from_big!(i64 u64 i128 u128)` macro expansion).
//
// These functions compile on native but will panic at runtime if
// called outside wasm32 — `js_sys::Object::new` is a wasm-bindgen extern.

fn snapshot_to_js(s: &AtomicMetricsSnapshot) -> JsValue {
    let obj = js_sys::Object::new();
    set_bigint_field(&obj, "queriesStarted", s.queries_started);
    set_bigint_field(&obj, "queriesCompleted", s.queries_completed);
    set_bigint_field(&obj, "queryErrors", s.query_errors);
    set_bigint_field(&obj, "bytesSent", s.bytes_sent);
    set_bigint_field(&obj, "bytesReceived", s.bytes_received);
    set_bigint_field(&obj, "framesSent", s.frames_sent);
    set_bigint_field(&obj, "framesReceived", s.frames_received);
    set_bigint_field(&obj, "connects", s.connects);
    set_bigint_field(&obj, "disconnects", s.disconnects);
    // Per-query latency fields (Phase 2+ tail, third item).
    // `min_query_latency_micros` is u64::MAX (sentinel) until the
    // first completion fires; callers can normalize with the
    // documented BigInt comparison.
    set_bigint_field(
        &obj,
        "totalQueryLatencyMicros",
        s.total_query_latency_micros,
    );
    set_bigint_field(&obj, "minQueryLatencyMicros", s.min_query_latency_micros);
    set_bigint_field(&obj, "maxQueryLatencyMicros", s.max_query_latency_micros);
    // Per-roundtrip latency fields (Phase 2+ tail, fourth item).
    // Same sentinel semantics as the per-query family above.
    // `roundtrips_observed` is the denominator for the running mean
    // and the partial-failure-detection signal noted in the docstring
    // on `snapshot()` above.
    set_bigint_field(&obj, "roundtripsObserved", s.roundtrips_observed);
    set_bigint_field(
        &obj,
        "totalRoundtripLatencyMicros",
        s.total_roundtrip_latency_micros,
    );
    set_bigint_field(
        &obj,
        "minRoundtripLatencyMicros",
        s.min_roundtrip_latency_micros,
    );
    set_bigint_field(
        &obj,
        "maxRoundtripLatencyMicros",
        s.max_roundtrip_latency_micros,
    );
    obj.into()
}

fn set_bigint_field(obj: &js_sys::Object, key: &str, value: u64) {
    let big = js_sys::BigInt::from(value);
    let _ = js_sys::Reflect::set(obj, &JsValue::from_str(key), &big);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pir_sdk::{Duration, PirMetrics};

    #[test]
    fn new_starts_at_zero() {
        let m = WasmAtomicMetrics::new();
        let s = m.snapshot_raw();
        assert_eq!(s.queries_started, 0);
        assert_eq!(s.bytes_sent, 0);
        assert_eq!(s.connects, 0);
        // Latency: untouched recorder reports the min sentinel so JS
        // callers can detect "no completions yet" rather than confusing
        // it with a real zero.
        assert_eq!(s.min_query_latency_micros, u64::MAX);
        assert_eq!(s.max_query_latency_micros, 0);
        assert_eq!(s.total_query_latency_micros, 0);
        // Roundtrip latency mirrors the per-query family.
        assert_eq!(s.roundtrips_observed, 0);
        assert_eq!(s.total_roundtrip_latency_micros, 0);
        assert_eq!(s.min_roundtrip_latency_micros, u64::MAX);
        assert_eq!(s.max_roundtrip_latency_micros, 0);
    }

    #[test]
    fn recorder_handle_is_shared_arc() {
        let m = WasmAtomicMetrics::new();
        let handle: Arc<dyn PirMetrics> = m.recorder_handle();
        // Fire a couple of callbacks through the dyn trait object and
        // observe them on the JS-side handle — proves the `Arc` clone
        // is aliased, not independently zeroed.
        handle.on_query_start("dpf", 0, 10);
        handle.on_bytes_sent("dpf", 1024);
        handle.on_connect("dpf", "wss://example");

        let s = m.snapshot_raw();
        assert_eq!(s.queries_started, 1);
        assert_eq!(s.bytes_sent, 1024);
        assert_eq!(s.frames_sent, 1);
        assert_eq!(s.connects, 1);
    }

    #[test]
    fn recorder_handle_installs_on_dpf_client() {
        use pir_sdk_client::DpfClient;

        let m = WasmAtomicMetrics::new();
        let mut client = DpfClient::new("wss://a", "wss://b");
        client.set_metrics_recorder(Some(m.recorder_handle()));
        // No connect here — we can't connect without a live WS. The
        // test simply proves installation compiles + doesn't panic;
        // the `MockTransport` integration tests in `pir-sdk-client`
        // cover end-to-end recorder behaviour for the native client.
        let _ = client;
    }

    #[test]
    fn recorder_handle_installs_on_harmony_client() {
        use pir_sdk_client::HarmonyClient;

        let m = WasmAtomicMetrics::new();
        let mut client = HarmonyClient::new("wss://h", "wss://q");
        client.set_metrics_recorder(Some(m.recorder_handle()));
        let _ = client;
    }

    #[test]
    fn multiple_clients_share_one_recorder() {
        use pir_sdk_client::{DpfClient, HarmonyClient};

        let m = WasmAtomicMetrics::new();
        let mut d = DpfClient::new("wss://a", "wss://b");
        let mut h = HarmonyClient::new("wss://h", "wss://q");
        d.set_metrics_recorder(Some(m.recorder_handle()));
        h.set_metrics_recorder(Some(m.recorder_handle()));

        // Fire directly on the `Arc<dyn PirMetrics>` that the JS
        // handle exposes — equivalent to both clients hitting the
        // same counter. Verifies the shared-state contract.
        let handle = m.recorder_handle();
        handle.on_bytes_sent("dpf", 100);
        handle.on_bytes_sent("harmony", 200);

        let s = m.snapshot_raw();
        assert_eq!(s.bytes_sent, 300);
        assert_eq!(s.frames_sent, 2);
    }

    #[test]
    fn default_equals_new() {
        let a = WasmAtomicMetrics::default();
        let b = WasmAtomicMetrics::new();
        // Both start at zero; the `Arc` identities differ (two
        // independent allocations), which is fine — `default` is a
        // convenience for callers that want `Default::default()`.
        assert_eq!(a.snapshot_raw(), b.snapshot_raw());
    }

    /// Uninstalling the recorder via `set_metrics_recorder(None)` on
    /// the native client should not invalidate the JS handle — the
    /// JS side can keep reading the last-observed counters.
    #[test]
    fn uninstall_preserves_js_handle() {
        use pir_sdk_client::DpfClient;

        let m = WasmAtomicMetrics::new();
        let mut client = DpfClient::new("wss://a", "wss://b");
        client.set_metrics_recorder(Some(m.recorder_handle()));

        // Fire a few events directly on the shared handle.
        let handle = m.recorder_handle();
        handle.on_connect("dpf", "wss://a");

        // Uninstall from the client. The JS-side handle still works.
        client.set_metrics_recorder(None);

        let s = m.snapshot_raw();
        assert_eq!(s.connects, 1);
    }

    /// Latency observations made through the `Arc<dyn PirMetrics>`
    /// trait object end up in the WASM-side snapshot. This is the
    /// shape any client wrapper actually exercises (the wrappers don't
    /// have direct access to the inner `AtomicMetrics`, only the
    /// `recorder_handle()` Arc clone).
    #[test]
    fn latency_through_recorder_handle_lands_in_snapshot() {
        let m = WasmAtomicMetrics::new();
        let handle: Arc<dyn PirMetrics> = m.recorder_handle();

        handle.on_query_end("dpf", 0, 10, true, Duration::from_millis(50));
        handle.on_query_end("dpf", 0, 10, true, Duration::from_millis(20));
        handle.on_query_end("dpf", 0, 10, false, Duration::from_millis(80));

        let s = m.snapshot_raw();
        assert_eq!(s.queries_completed, 2);
        assert_eq!(s.query_errors, 1);
        assert_eq!(s.total_query_latency_micros, 150_000);
        assert_eq!(s.min_query_latency_micros, 20_000);
        assert_eq!(s.max_query_latency_micros, 80_000);
    }

    /// Multiple clients sharing one recorder aggregate latency too —
    /// not just byte counters. This is the shape a real dashboard
    /// hits when DPF and Harmony both queue work on the same recorder.
    #[test]
    fn multiple_clients_aggregate_latency() {
        use pir_sdk_client::{DpfClient, HarmonyClient};

        let m = WasmAtomicMetrics::new();
        let mut d = DpfClient::new("wss://a", "wss://b");
        let mut h = HarmonyClient::new("wss://h", "wss://q");
        d.set_metrics_recorder(Some(m.recorder_handle()));
        h.set_metrics_recorder(Some(m.recorder_handle()));

        // Fire directly on the shared handle as both backends.
        let handle = m.recorder_handle();
        handle.on_query_end("dpf", 0, 10, true, Duration::from_millis(30));
        handle.on_query_end("harmony", 1, 5, true, Duration::from_millis(70));

        let s = m.snapshot_raw();
        assert_eq!(s.queries_completed, 2);
        assert_eq!(s.total_query_latency_micros, 100_000);
        assert_eq!(s.min_query_latency_micros, 30_000);
        assert_eq!(s.max_query_latency_micros, 70_000);
    }

    /// Per-roundtrip latency observations made through the
    /// `Arc<dyn PirMetrics>` trait object end up in the WASM-side
    /// snapshot. Mirrors `latency_through_recorder_handle_lands_in_snapshot`
    /// for the per-frame `on_roundtrip_end` callback that landed as the
    /// fourth Phase 2+ tail item — the shape any transport-level recorder
    /// actually exercises (the wrappers don't have direct access to the
    /// inner `AtomicMetrics`, only the `recorder_handle()` Arc clone).
    #[test]
    fn roundtrip_latency_through_recorder_handle_lands_in_snapshot() {
        let m = WasmAtomicMetrics::new();
        let handle: Arc<dyn PirMetrics> = m.recorder_handle();

        // Three roundtrips with varying durations and byte sizes.
        // `on_roundtrip_end` is called from the transport on
        // fully-successful roundtrips only — we simulate that here.
        handle.on_roundtrip_end("dpf", 100, 200, Duration::from_millis(50));
        handle.on_roundtrip_end("dpf", 80, 160, Duration::from_millis(20));
        handle.on_roundtrip_end("dpf", 120, 240, Duration::from_millis(80));

        let s = m.snapshot_raw();
        assert_eq!(s.roundtrips_observed, 3);
        assert_eq!(s.total_roundtrip_latency_micros, 150_000);
        assert_eq!(s.min_roundtrip_latency_micros, 20_000);
        assert_eq!(s.max_roundtrip_latency_micros, 80_000);
    }

    /// Multiple clients sharing one recorder aggregate roundtrip
    /// latency too — same shared-state contract as
    /// `multiple_clients_aggregate_latency` but for the
    /// per-roundtrip family.
    #[test]
    fn multiple_clients_aggregate_roundtrip_latency() {
        use pir_sdk_client::{DpfClient, HarmonyClient};

        let m = WasmAtomicMetrics::new();
        let mut d = DpfClient::new("wss://a", "wss://b");
        let mut h = HarmonyClient::new("wss://h", "wss://q");
        d.set_metrics_recorder(Some(m.recorder_handle()));
        h.set_metrics_recorder(Some(m.recorder_handle()));

        let handle = m.recorder_handle();
        handle.on_roundtrip_end("dpf", 50, 100, Duration::from_millis(40));
        handle.on_roundtrip_end("harmony", 60, 120, Duration::from_millis(60));

        let s = m.snapshot_raw();
        assert_eq!(s.roundtrips_observed, 2);
        assert_eq!(s.total_roundtrip_latency_micros, 100_000);
        assert_eq!(s.min_roundtrip_latency_micros, 40_000);
        assert_eq!(s.max_roundtrip_latency_micros, 60_000);
    }
}
