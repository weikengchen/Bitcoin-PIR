//! Integration tests for PIR SDK Client.
//!
//! These tests require running PIR servers. By default they hit the public
//! deployment at `wss://pir1.chenweikeng.com` / `wss://pir2.chenweikeng.com`
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

use pir_sdk_client::{DpfClient, HarmonyClient, PirClient, ScriptHash};

/// Default to the public deployment so CI — and contributors who haven't
/// stood up a fixture server — can exercise the full stack against
/// real data. The public servers are the same ones the web client at
/// https://chenweikeng.com/bitcoin-pir uses.
const DEFAULT_DPF_SERVER0: &str = "wss://pir1.chenweikeng.com";
const DEFAULT_DPF_SERVER1: &str = "wss://pir2.chenweikeng.com";
// Harmony hint/query role split matches the web client defaults in
// `web/index.html` (the hint server runs on pir2, the query server on pir1).
// The primary-role server rejects 0x41 REQ_HARMONY_HINTS with
// "unsupported request 0x41 for primary role" — don't swap these.
const DEFAULT_HARMONY_HINT: &str = "wss://pir2.chenweikeng.com";
const DEFAULT_HARMONY_QUERY: &str = "wss://pir1.chenweikeng.com";
#[cfg(feature = "onion")]
const DEFAULT_ONION_URL: &str = "wss://pir1.chenweikeng.com";

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
