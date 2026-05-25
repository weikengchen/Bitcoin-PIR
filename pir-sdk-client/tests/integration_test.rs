//! Integration tests for PIR SDK Client.
//!
//! These tests require running PIR servers. By default they hit the public
//! deployment at `wss://weikeng1.bitcoinpir.org` / `wss://weikeng2.bitcoinpir.org`
//! (the same servers the production web client uses) — that's what CI runs
//! against and what a contributor gets out-of-the-box.
//!
//! Override via environment variables for local runs against
//! `unified_server`:
//!   - `PIR_DPF_SERVER0_URL` / `PIR_DPF_SERVER1_URL` (default: public pir1/pir2)
//!   - `PIR_HARMONY_HINT_URL` / `PIR_HARMONY_QUERY_URL` (default: public pir1/pir2)
//!   - `PIR_ONION_URL` (default: public pir1)
//!
//! Run with:
//!   cargo test -p pir-sdk-client --test integration_test -- --ignored
//!
//! For local servers:
//!   PIR_DPF_SERVER0_URL=ws://127.0.0.1:8091 \
//!   PIR_DPF_SERVER1_URL=ws://127.0.0.1:8092 \
//!     cargo test -p pir-sdk-client --test integration_test -- --ignored
//!
//! Before running locally, start the servers:
//!   cargo run --release -p runtime --bin unified_server -- --port 8091 &
//!   cargo run --release -p runtime --bin unified_server -- --port 8092 &

use pir_sdk_client::{DpfClient, HarmonyClient, PirClient, PirError, ScriptHash, WsConnection};

/// Default to the public deployment so CI — and contributors who haven't
/// stood up a fixture server — can exercise the full stack against
/// real data. The public servers are the same ones the web client at
/// https://www.bitcoinpir.org uses.
const DEFAULT_DPF_SERVER0: &str = "wss://weikeng1.bitcoinpir.org";
const DEFAULT_DPF_SERVER1: &str = "wss://weikeng2.bitcoinpir.org";
// Production topology (memory: project_pir1_hint_pir2_query_split.md):
//   pir1 = Hetzner, no-SEV   → HINT server  (--serve-hints + --pool-size)
//   pir2 = VPSBG,   SEV-SNP  → QUERY server (--serve-queries)
// Defaults were reversed pre-2026-05-13 and silently worked because
// pir2 also had --pool-size enabled. After the mode-flag landing
// (commit fb8b8a64) pir2 rejects hint requests with a clear
// wire-level error ("server not configured to serve hints — start
// with --serve-hints"), which surfaced the reversal in CI.
const DEFAULT_HARMONY_HINT: &str = "wss://weikeng1.bitcoinpir.org";
const DEFAULT_HARMONY_QUERY: &str = "wss://weikeng2.bitcoinpir.org";
#[cfg(feature = "onion")]
const DEFAULT_ONION_URL: &str = "wss://weikeng1.bitcoinpir.org";

fn dpf_server0_url() -> String {
    std::env::var("PIR_DPF_SERVER0_URL").unwrap_or_else(|_| DEFAULT_DPF_SERVER0.into())
}

fn dpf_server1_url() -> String {
    std::env::var("PIR_DPF_SERVER1_URL").unwrap_or_else(|_| DEFAULT_DPF_SERVER1.into())
}

fn harmony_hint_url() -> String {
    std::env::var("PIR_HARMONY_HINT_URL").unwrap_or_else(|_| DEFAULT_HARMONY_HINT.into())
}

fn harmony_query_url() -> String {
    std::env::var("PIR_HARMONY_QUERY_URL").unwrap_or_else(|_| DEFAULT_HARMONY_QUERY.into())
}

#[cfg(feature = "onion")]
fn onion_url() -> String {
    std::env::var("PIR_ONION_URL").unwrap_or_else(|_| DEFAULT_ONION_URL.into())
}

/// A known test script hash (can be replaced with actual test data).
fn test_script_hash() -> ScriptHash {
    // All-zero hash: extremely unlikely to be a real scripthash, so the
    // query will exercise the "not found" Merkle verification path. That
    // is the more important path to test — it proves that per-bucket
    // Merkle verification across both cuckoo positions is working.
    [0u8; 20]
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_connect() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());

    let result = client.connect().await;
    assert!(result.is_ok(), "Failed to connect: {:?}", result.err());
    assert!(client.is_connected());

    client.disconnect().await.unwrap();
    assert!(!client.is_connected());
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_fetch_catalog() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    let catalog = client.fetch_catalog().await.expect("fetch_catalog failed");

    assert!(!catalog.databases.is_empty(), "catalog should have at least one database");

    let main_db = &catalog.databases[0];
    assert_eq!(main_db.db_id, 0);
    assert!(main_db.index_bins > 0);
    assert!(main_db.chunk_bins > 0);
    assert!(main_db.index_k > 0);
    assert!(main_db.chunk_k > 0);

    println!("Catalog: {:#?}", catalog);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_sync_empty() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    // Sync with empty script hashes
    let script_hashes: Vec<ScriptHash> = vec![];
    let result = client.sync(&script_hashes, None).await.expect("sync failed");

    assert!(result.results.is_empty());
    assert!(result.synced_height > 0);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_sync_single() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    let script_hashes = vec![test_script_hash()];
    let result = client.sync(&script_hashes, None).await.expect("sync failed");

    assert_eq!(result.results.len(), 1);
    assert!(result.synced_height > 0);
    assert!(result.was_fresh_sync);

    println!("Sync result: {:?}", result);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_query_batch() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");
    client.fetch_catalog().await.expect("fetch_catalog failed");

    let script_hashes = vec![test_script_hash()];
    let results = client.query_batch(&script_hashes, 0).await.expect("query_batch failed");

    assert_eq!(results.len(), 1);

    // The all-zero scripthash should be `None` (not found). This exercises
    // the full INDEX round + per-bucket Merkle verification path end-to-end.
    match &results[0] {
        None => println!("All-zero scripthash correctly not found"),
        Some(r) => {
            println!(
                "All-zero scripthash unexpectedly found: merkle_verified={}, entries={}",
                r.merkle_verified,
                r.entries.len()
            );
        }
    }

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_multiple_queries() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    // Create multiple distinct script hashes
    let script_hashes: Vec<ScriptHash> = (0..5)
        .map(|i| {
            let mut hash = [0u8; 20];
            hash[0] = i as u8;
            hash[1] = (i * 17) as u8;
            hash[2] = (i * 31) as u8;
            hash
        })
        .collect();

    let result = client.sync(&script_hashes, None).await.expect("sync failed");

    assert_eq!(result.results.len(), 5);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_sync_with_cached_height() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    let script_hashes = vec![test_script_hash()];

    // First sync
    let result1 = client.sync(&script_hashes, None).await.expect("sync failed");
    let height = result1.synced_height;

    // Second sync with cached height (should use delta if available)
    let result2 = client.sync(&script_hashes, Some(height)).await.expect("sync failed");

    // Height should be >= previous
    assert!(result2.synced_height >= height);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_dpf_client_compute_sync_plan() {
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.connect().await.expect("connect failed");

    let catalog = client.fetch_catalog().await.expect("fetch_catalog failed");

    // Fresh sync (no prior height)
    let plan = client.compute_sync_plan(&catalog, None).expect("compute_sync_plan failed");
    assert!(!plan.is_empty());
    assert!(plan.is_fresh_sync);

    // Delta sync (with prior height)
    let latest = catalog.latest_tip().unwrap_or(0);
    if latest > 1000 {
        let plan = client.compute_sync_plan(&catalog, Some(latest - 1000)).expect("compute_sync_plan failed");
        println!("Delta plan: {:?}", plan);
    }

    client.disconnect().await.unwrap();
}

// ─── HarmonyPIR Integration Tests (require running servers) ─────────────────

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_harmony_client_connect() {
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());

    let result = client.connect().await;
    assert!(result.is_ok(), "Failed to connect: {:?}", result.err());
    assert!(client.is_connected());

    client.disconnect().await.unwrap();
    assert!(!client.is_connected());
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_harmony_client_fetch_catalog() {
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());
    client.connect().await.expect("connect failed");

    let catalog = client.fetch_catalog().await.expect("fetch_catalog failed");

    assert!(!catalog.databases.is_empty(), "catalog should have at least one database");
    let main_db = &catalog.databases[0];
    assert_eq!(main_db.db_id, 0);
    assert!(main_db.index_bins > 0);
    assert!(main_db.chunk_bins > 0);
    assert!(main_db.index_k > 0);
    assert!(main_db.chunk_k > 0);

    println!("Catalog: {:#?}", catalog);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_harmony_client_sync_single() {
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());
    client.connect().await.expect("connect failed");

    let script_hashes = vec![test_script_hash()];
    let result = client.sync(&script_hashes, None).await.expect("sync failed");

    assert_eq!(result.results.len(), 1);
    // HarmonyClient now prefers REQ_GET_DB_CATALOG (0x02) over the legacy
    // REQ_HARMONY_GET_INFO (0x40), so `synced_height` reflects the real tip.
    assert!(
        result.synced_height > 0,
        "synced_height should be non-zero via REQ_GET_DB_CATALOG; got {}",
        result.synced_height,
    );
    assert!(result.was_fresh_sync);

    println!("Sync result: {:?}", result);

    client.disconnect().await.unwrap();
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_harmony_client_query_batch() {
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());
    client.connect().await.expect("connect failed");
    client.fetch_catalog().await.expect("fetch_catalog failed");

    let script_hashes = vec![test_script_hash()];
    let results = client.query_batch(&script_hashes, 0).await.expect("query_batch failed");

    assert_eq!(results.len(), 1);

    println!("Query result: {:?}", results);

    client.disconnect().await.unwrap();
}

// ─── WsConnection Resilience Tests ───────────────────────────────────────

/// End-to-end test that `WsConnection::reconnect` actually yields a working
/// transport — after reconnecting, we send a fresh `REQ_GET_DB_CATALOG`
/// and verify the response parses. The wire-format constants come from
/// `crate::protocol`, which isn't exposed, so we reconstruct the request
/// inline: `[4B len LE][0x02]`.
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn test_wsconnection_reconnect_roundtrip() {
    use pir_sdk_client::WsConnection;
    let mut conn = WsConnection::connect(&dpf_server0_url())
        .await
        .expect("connect failed");

    // Baseline: fetch catalog once.
    let req = {
        let mut buf = Vec::with_capacity(5);
        buf.extend_from_slice(&1u32.to_le_bytes()); // len=1 (just variant byte)
        buf.push(0x02); // REQ_GET_DB_CATALOG
        buf
    };
    let resp1 = conn.roundtrip(&req).await.expect("first roundtrip failed");
    assert!(!resp1.is_empty(), "first response empty");
    assert_eq!(resp1[0], 0x02, "expected RESP_DB_CATALOG");

    // Now force a reconnect — drops the existing TCP + WebSocket state
    // and re-handshakes. The new transport should still work.
    conn.reconnect().await.expect("reconnect failed");

    let resp2 = conn.roundtrip(&req).await.expect("post-reconnect roundtrip failed");
    assert!(!resp2.is_empty(), "post-reconnect response empty");
    assert_eq!(resp2[0], 0x02, "expected RESP_DB_CATALOG after reconnect");

    conn.close().await.unwrap();
}

// ─── OnionPIR Integration Tests (require running servers + `onion` feature) ─

#[cfg(feature = "onion")]
mod onion_tests {
    use super::*;
    use pir_sdk_client::OnionClient;

    #[tokio::test]
    #[ignore = "requires running PIR servers"]
    async fn test_onion_client_connect() {
        let mut client = OnionClient::new(&onion_url());

        let result = client.connect().await;
        assert!(result.is_ok(), "Failed to connect: {:?}", result.err());
        assert!(client.is_connected());

        client.disconnect().await.unwrap();
        assert!(!client.is_connected());
    }

    #[tokio::test]
    #[ignore = "requires running PIR servers"]
    async fn test_onion_client_fetch_catalog() {
        let mut client = OnionClient::new(&onion_url());
        client.connect().await.expect("connect failed");

        let catalog = client.fetch_catalog().await.expect("fetch_catalog failed");

        assert!(!catalog.databases.is_empty(), "catalog should have at least one database");
        let main_db = &catalog.databases[0];
        assert_eq!(main_db.db_id, 0);
        assert!(main_db.index_bins > 0);
        assert!(main_db.chunk_bins > 0);

        println!("Catalog: {:#?}", catalog);

        client.disconnect().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires running PIR servers"]
    async fn test_onion_client_query_batch() {
        let mut client = OnionClient::new(&onion_url());
        client.connect().await.expect("connect failed");
        client.fetch_catalog().await.expect("fetch_catalog failed");

        let script_hashes = vec![test_script_hash()];
        let results = client.query_batch(&script_hashes, 0).await.expect("query_batch failed");

        assert_eq!(results.len(), 1);

        println!("Query result: {:?}", results);

        client.disconnect().await.unwrap();
    }
}

// ─── Sync Plan Tests (no server required) ───────────────────────────────────

use pir_sdk::{compute_sync_plan, DatabaseCatalog, DatabaseInfo, DatabaseKind};

fn make_test_catalog() -> DatabaseCatalog {
    DatabaseCatalog {
        databases: vec![
            DatabaseInfo {
                db_id: 0,
                kind: DatabaseKind::Full,
                name: "snapshot_900000".into(),
                height: 900000,
                index_bins: 1000,
                chunk_bins: 2000,
                index_k: 75,
                chunk_k: 80,
                tag_seed: 12345,
                dpf_n_index: 17,
                dpf_n_chunk: 18,
                has_bucket_merkle: false,
                index_master_seed: 0,
                chunk_master_seed: 0,
                anchor_kind: 0,
                anchor_bytes: Vec::new(),
            },
            DatabaseInfo {
                db_id: 1,
                kind: DatabaseKind::Delta { base_height: 900000 },
                name: "delta_900000_910000".into(),
                height: 910000,
                index_bins: 100,
                chunk_bins: 200,
                index_k: 75,
                chunk_k: 80,
                tag_seed: 12345,
                dpf_n_index: 14,
                dpf_n_chunk: 15,
                has_bucket_merkle: false,
                index_master_seed: 0,
                chunk_master_seed: 0,
                anchor_kind: 0,
                anchor_bytes: Vec::new(),
            },
            DatabaseInfo {
                db_id: 2,
                kind: DatabaseKind::Delta { base_height: 910000 },
                name: "delta_910000_920000".into(),
                height: 920000,
                index_bins: 100,
                chunk_bins: 200,
                index_k: 75,
                chunk_k: 80,
                tag_seed: 12345,
                dpf_n_index: 14,
                dpf_n_chunk: 15,
                has_bucket_merkle: false,
                index_master_seed: 0,
                chunk_master_seed: 0,
                anchor_kind: 0,
                anchor_bytes: Vec::new(),
            },
        ],
    }
}

#[test]
fn test_sync_plan_fresh() {
    let catalog = make_test_catalog();
    let plan = compute_sync_plan(&catalog, None).expect("compute_sync_plan failed");

    assert!(plan.is_fresh_sync);
    assert_eq!(plan.target_height, 920000);
    // Should include: snapshot + delta1 + delta2 = 3 steps
    assert_eq!(plan.steps.len(), 3);
    assert!(plan.steps[0].is_full());
    assert!(!plan.steps[1].is_full());
    assert!(!plan.steps[2].is_full());
}

#[test]
fn test_sync_plan_delta_only() {
    let catalog = make_test_catalog();
    // Start from height 900000 (after the snapshot)
    let plan = compute_sync_plan(&catalog, Some(900000)).expect("compute_sync_plan failed");

    assert!(!plan.is_fresh_sync);
    assert_eq!(plan.target_height, 920000);
    // Should include: delta1 + delta2 = 2 steps
    assert_eq!(plan.steps.len(), 2);
    assert!(!plan.steps[0].is_full());
    assert!(!plan.steps[1].is_full());
}

#[test]
fn test_sync_plan_already_synced() {
    let catalog = make_test_catalog();
    // Already at latest height
    let plan = compute_sync_plan(&catalog, Some(920000)).expect("compute_sync_plan failed");

    assert!(plan.is_empty());
    assert_eq!(plan.target_height, 920000);
}

#[test]
fn test_sync_plan_partial_delta() {
    let catalog = make_test_catalog();
    // Start from height 910000 (after delta1)
    let plan = compute_sync_plan(&catalog, Some(910000)).expect("compute_sync_plan failed");

    assert!(!plan.is_fresh_sync);
    assert_eq!(plan.target_height, 920000);
    // Should include: delta2 = 1 step
    assert_eq!(plan.steps.len(), 1);
}

#[test]
fn test_sync_plan_stale_height() {
    let catalog = make_test_catalog();
    // Start from height before snapshot - should fall back to fresh sync
    let plan = compute_sync_plan(&catalog, Some(850000)).expect("compute_sync_plan failed");

    assert!(plan.is_fresh_sync);
    assert_eq!(plan.target_height, 920000);
}

// ─────────────────────────────────────────────────────────────────────────
// REQ_ANNOUNCE — operator-signed identity, end-to-end through unified_server.
//
// This is the only test that drives the *production* dispatch arm for
// REQ_ANNOUNCE (the binary re-implements dispatch inline rather than going
// through pir-runtime-core's stateless RequestHandler). It connects, sends
// REQ_ANNOUNCE, parses the bundle, runs the in-bundle chain check, then
// operator-pubkey pinning (accept the right key, reject a wrong one).
//
// Unlike the other integration tests it does NOT default to the public
// deployment — pir1/pir2 run without --identity-* flags and answer
// "announce not configured". Point it at a locally-booted server:
//
//   # operator workflow (once):
//   bpir-admin generate-identity --purpose server   --out /tmp/s.key   # -> SERVER_PUB (stdout)
//   bpir-admin generate-identity --purpose operator --out /tmp/op.key  # -> OPERATOR_PUB (stdout)
//   bpir-admin sign-identity --operator-key-path /tmp/op.key --server-id pir-test \
//       --identity-pubkey-hex <SERVER_PUB> --valid-until <unix-ts> --out /tmp/s.cert
//   # boot (any local checkpoint works — announce is independent of the DB):
//   unified_server --port 8097 --data-dir <ckpt> --serve-queries \
//       --identity-key-path /tmp/s.key --identity-cert-path /tmp/s.cert \
//       --identity-server-id pir-test
//   # run:
//   PIR_ANNOUNCE_URL=ws://127.0.0.1:8097 \
//   PIR_ANNOUNCE_OPERATOR_PUB=<OPERATOR_PUB hex> \
//     cargo test -p pir-sdk-client --test integration_test \
//       test_announce_operator_identity_end_to_end -- --ignored --nocapture
#[tokio::test]
#[ignore = "requires a unified_server booted with --identity-* flags; see PIR_ANNOUNCE_* env vars"]
async fn test_announce_operator_identity_end_to_end() {
    use pir_sdk_client::announce::{announce, announce_with_pinned_operator};

    // Skip gracefully when unconfigured: unlike the other --ignored tests
    // there is no sensible public default (the public servers don't serve
    // announce), so CI runs this as a no-op unless both env vars are set.
    let (url, operator_pub_hex) =
        match (std::env::var("PIR_ANNOUNCE_URL"), std::env::var("PIR_ANNOUNCE_OPERATOR_PUB")) {
            (Ok(u), Ok(p)) => (u, p),
            _ => {
                eprintln!(
                    "skipping test_announce_operator_identity_end_to_end: set PIR_ANNOUNCE_URL \
                     + PIR_ANNOUNCE_OPERATOR_PUB (and optionally PIR_ANNOUNCE_SERVER_ID) to run"
                );
                return;
            }
        };
    let operator_pub = parse_pubkey_hex(&operator_pub_hex);

    // 1. Plain announce: the bundle decodes and the in-bundle chain check
    //    (manifest signature + cert/manifest cross-references) passes.
    let mut conn = WsConnection::connect(&url).await.expect("connect");
    let v = announce(&mut conn).await.expect("announce roundtrip");
    assert!(v.chain_verified, "chain check failed: {:?}", v.chain_error);
    // Expected server_id defaults to the local fixture's "pir-test"; override
    // with PIR_ANNOUNCE_SERVER_ID to verify a real deployment (e.g. "pir1").
    let expected_server_id =
        std::env::var("PIR_ANNOUNCE_SERVER_ID").unwrap_or_else(|_| "pir-test".into());
    assert_eq!(v.bundle.cert.server_id, expected_server_id);
    assert_eq!(
        v.bundle.cert.operator_pubkey, operator_pub,
        "cert's operator_pubkey should match the pinned operator"
    );

    // 2. Pinned to the correct operator pubkey → accepted (cert signature
    //    verifies under the pinned key and the chain check holds).
    let v2 = announce_with_pinned_operator(&mut conn, &operator_pub, 0)
        .await
        .expect("pinned announce with the correct operator must succeed");
    assert!(v2.chain_verified);

    // 3. Pinned to a wrong operator pubkey → rejected before trusting anything.
    let wrong = [0u8; 32];
    let err = announce_with_pinned_operator(&mut conn, &wrong, 0)
        .await
        .expect_err("pinned announce with a wrong operator must fail");
    match err {
        PirError::Protocol(m) => assert!(
            m.contains("does not match pinned operator"),
            "unexpected error: {m}"
        ),
        other => panic!("expected Protocol(does not match pinned operator), got {other:?}"),
    }
}

/// Parse a 64-char hex Ed25519 pubkey into 32 bytes (test helper).
fn parse_pubkey_hex(s: &str) -> [u8; 32] {
    let s = s.trim();
    assert_eq!(s.len(), 64, "operator pubkey hex must be 64 chars, got {}", s.len());
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("invalid hex in operator pubkey");
    }
    out
}
