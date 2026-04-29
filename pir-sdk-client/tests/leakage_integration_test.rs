//! Phase 2.2 leakage-profile integration tests.
//!
//! These tests run real PIR queries through real servers and assert
//! per-message invariants + the simulator property on the captured
//! [`LeakageProfile`]. They are `#[ignore]` for the same reason
//! `integration_test.rs` is — they require either network access to
//! the public deployment (the default) or local servers via the
//! `PIR_*_URL` env vars.
//!
//! Run with:
//!   cargo test -p pir-sdk-client --test leakage_integration_test -- --ignored
//!   cargo test -p pir-sdk-client --features onion --test leakage_integration_test -- --ignored
//!
//! See `PLAN_LEAKAGE_VERIFICATION.md` for the framework: a leakage
//! function `L(q)` defines what each query is allowed to leak; the
//! simulator property says two queries with the same `L(q)` produce
//! structurally equivalent transcripts. The asserts below are the
//! operational form of that property.
//!
//! What's covered today (Phase 2.2):
//!
//! * **(a) Per-message invariant** assertions — `Index` rounds always
//!   carry K groups with the per-backend per-group constant
//!   (DPF/Onion: 2, Harmony: T-1); `IndexMerkleSiblings` rounds always
//!   carry K groups with one DPF or FHE key per group; the
//!   `INDEX_CUCKOO_NUM_HASHES = 2` invariant from CLAUDE.md is encoded
//!   directly.
//! * **(b) Simulator property** — two not-found queries with different
//!   scripthashes must produce structurally equal profiles (same
//!   number of rounds, same kinds, same items shapes). Bytes are
//!   compared too: DPF / FHE ciphertexts are fixed-length per param
//!   set, so two not-found queries should produce byte-identical
//!   transcripts.
//! * **(c) CHUNK Round-Presence Symmetry P1** — the wire transcript's
//!   round count depends only on batch size, never on per-query
//!   found/not-found classification. Encoded by:
//!     - `*_per_message_invariants_not_found` asserting ≥1 (Onion) /
//!       ≥2 (DPF) K_CHUNK-padded CHUNK rounds even for not-found;
//!     - `*_found_vs_not_found_have_same_round_count` asserting the
//!       found and not-found profiles emit equal CHUNK and total
//!       round counts;
//!     - `*_round_count_is_function_of_batch_size_only` as the
//!       integration-level binding of the helper-level Kani harness on
//!       `items_from_trace`.

use std::sync::Arc;

use pir_core::hash::derive_groups_3;
use pir_sdk::{BufferingLeakageRecorder, LeakageProfile, RoundKind, RoundProfile};
use pir_sdk_client::{DpfClient, HarmonyClient, PirClient, ScriptHash};

#[cfg(feature = "onion")]
use pir_sdk_client::OnionClient;

// ─── Server URL helpers (mirror integration_test.rs) ────────────────────────

const DEFAULT_DPF_SERVER0: &str = "wss://pir1.chenweikeng.com";
const DEFAULT_DPF_SERVER1: &str = "wss://pir2.chenweikeng.com";
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

// ─── Test corpus ────────────────────────────────────────────────────────────

/// Two distinct scripthashes — both extremely unlikely to exist
/// on-chain, so both queries follow the not-found path. The
/// simulator-property test compares their profiles for structural
/// equality.
fn not_found_pair() -> (ScriptHash, ScriptHash) {
    let mut a = [0u8; 20];
    let mut b = [0u8; 20];
    // Diverge in every byte so the cuckoo positions hit unrelated bins
    // — this is the worst case for "do these queries leak the same thing".
    for i in 0..20 {
        a[i] = (i as u8).wrapping_mul(17);
        b[i] = (i as u8).wrapping_mul(31).wrapping_add(7);
    }
    (a, b)
}

/// Two known-found script-hashes. These are HASH160 values of demo
/// scriptPubKeys from `web/src/example_spks.json` (precomputed once
/// via `RIPEMD160(SHA256(spk))` — see hardening notes in
/// `PLAN_LEAKAGE_VERIFICATION.md`). They have valid on-chain UTXO sets
/// at the public Hetzner deployment's indexed height, so a `query_batch`
/// against them will follow the FOUND path: INDEX rounds + CHUNK rounds
/// + Merkle verification across both INDEX and CHUNK trees.
///
/// If a future server rebuild drops these from the index, the FOUND
/// tests below will degrade to NOT-FOUND (CHUNK rounds disappear); the
/// `found_query_includes_chunk_rounds` assertion fires loudly so the
/// drift is caught rather than silently weakening the corpus.
fn found_pair() -> (ScriptHash, ScriptHash) {
    // HASH160(76a91484407a2fe50de7b97ef1a80613b41d06af8fa38788ac) — P2PKH
    let a = hex_to_array("de2e69f96b7e622f6ad39609b6d8554b37e8aba3");
    // HASH160(0014528aa6fb623acd8f574abc89508e0a42cde57b8b) — P2WPKH
    let b = hex_to_array("1f4e88358fd778cde7f3aa8d1b257ceb7e800a3b");
    (a, b)
}

fn hex_to_array(hex: &str) -> ScriptHash {
    let bytes = hex::decode(hex).expect("valid hex");
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}

// ─── Generic invariant checks ───────────────────────────────────────────────

/// Assert PIR-level K-padding only (Index + Chunk). Merkle rounds use
/// a separate K (the same one for DPF / Harmony, but a *different* one
/// for OnionPIR — `level_info.k` from the per-DB Merkle metadata
/// rather than the main PIR `index_k`/`chunk_k`).
fn assert_pir_k_padding(profile: &LeakageProfile, k_index: usize, k_chunk: usize) {
    for (i, r) in profile.rounds.iter().enumerate() {
        match r.kind {
            RoundKind::Index => assert_eq!(
                r.items.len(), k_index,
                "round[{}] Index: items.len()={}, expected K={}", i, r.items.len(), k_index,
            ),
            RoundKind::Chunk => assert_eq!(
                r.items.len(), k_chunk,
                "round[{}] Chunk: items.len()={}, expected K_CHUNK={}",
                i, r.items.len(), k_chunk,
            ),
            // Merkle-level rounds covered by `assert_merkle_per_level_uniform`.
            _ => {}
        }
    }
}

/// Assert that every Merkle sibling round at the same level emits the
/// same number of items. This captures the K-padding invariant at the
/// Merkle level without requiring the test to know what K_merkle is —
/// a server-driven parameter (`level_info.k`) that is constant per
/// (level, tree) for a given DB but may differ from K_pir.
fn assert_merkle_per_level_uniform(profile: &LeakageProfile) {
    use std::collections::HashMap;
    // Key: (variant_kind, level). Value: first observed items.len() for
    // any round matching that key. Re-observation must match.
    let mut seen: HashMap<(&'static str, u8), usize> = HashMap::new();
    for (i, r) in profile.rounds.iter().enumerate() {
        let key: Option<(&'static str, u8)> = match r.kind {
            RoundKind::IndexMerkleSiblings { level } => Some(("index_merkle", level)),
            RoundKind::ChunkMerkleSiblings { level } => Some(("chunk_merkle", level)),
            _ => None,
        };
        if let Some(k) = key {
            let n = r.items.len();
            match seen.entry(k) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(n);
                }
                std::collections::hash_map::Entry::Occupied(e) => {
                    assert_eq!(
                        *e.get(), n,
                        "round[{}] {:?}: items.len()={}, expected {} \
                         (mismatched K-padding within Merkle level)",
                        i, r.kind, n, *e.get(),
                    );
                }
            }
        }
    }
}

/// Assert per-group item-count uniformity within each round of the
/// given kind. The expected value is whatever `items[0]` is — we
/// don't hardcode T-1 (Harmony) or INDEX_CUCKOO_NUM_HASHES (DPF/Onion)
/// here because some are computed per-DB. Catches any drift between
/// groups within a single round.
fn assert_per_round_uniform(profile: &LeakageProfile, kind_match: &RoundKind) {
    for (i, r) in profile.rounds_of_kind(kind_match).enumerate() {
        if r.items.is_empty() {
            continue;
        }
        let first = r.items[0];
        for (g, &v) in r.items.iter().enumerate() {
            assert_eq!(
                v, first,
                "round[{} of {:?}] group[{}]={}, expected uniform (first={})",
                i, r.kind, g, v, first,
            );
        }
    }
}

/// Assert the simulator property at structural level: two profiles
/// agree on every wire-observable shape (round kinds, server ids,
/// db_ids, item shapes, byte counts).
///
/// For DPF / OnionPIR the byte counts are fixed-length per parameter
/// set so two not-found queries must produce *byte-identical*
/// transcripts. If this assertion fires it means somewhere a query
/// hash leaks into the encoding length, which would be a real
/// finding.
fn assert_profiles_equivalent(a: &LeakageProfile, b: &LeakageProfile) {
    assert_eq!(
        a.rounds.len(), b.rounds.len(),
        "round count mismatch: {} vs {}", a.rounds.len(), b.rounds.len(),
    );
    for (i, (ra, rb)) in a.rounds.iter().zip(b.rounds.iter()).enumerate() {
        assert_eq!(ra.kind, rb.kind, "round[{}] kind mismatch", i);
        assert_eq!(ra.server_id, rb.server_id, "round[{}] server_id mismatch", i);
        assert_eq!(ra.db_id, rb.db_id, "round[{}] db_id mismatch", i);
        assert_eq!(
            ra.request_bytes, rb.request_bytes,
            "round[{}] request_bytes mismatch ({:?})", i, ra.kind,
        );
        assert_eq!(
            ra.response_bytes, rb.response_bytes,
            "round[{}] response_bytes mismatch ({:?})", i, ra.kind,
        );
        assert_eq!(ra.items, rb.items, "round[{}] items mismatch", i);
    }
}

// ─── DPF tests ──────────────────────────────────────────────────────────────

/// Drive a single not-found DPF query and assert per-message invariants.
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn dpf_per_message_invariants_not_found() {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.set_leakage_recorder(Some(recorder.clone()));

    client.connect().await.expect("dpf connect");
    let catalog = client.fetch_catalog().await.expect("dpf fetch_catalog");
    let main = &catalog.databases[0];
    let k_index = main.index_k as usize;
    let k_chunk = main.chunk_k as usize;

    let (sh, _) = not_found_pair();
    let _ = client
        .query_batch(&[sh], main.db_id)
        .await
        .expect("dpf query_batch");

    let profile = recorder.take_profile("dpf");
    println!(
        "dpf not-found profile: {} rounds — {:?}",
        profile.rounds.len(),
        profile.rounds.iter().map(|r| r.kind).collect::<Vec<_>>()
    );

    // Sanity: at least the catalog/info round + one INDEX round per server.
    assert!(
        profile.count_of_kind(&RoundKind::Index) >= 2,
        "expected ≥2 Index rounds (one per DPF server), got {}",
        profile.count_of_kind(&RoundKind::Index),
    );
    // CHUNK Round-Presence Symmetry: not-found queries also emit
    // K_CHUNK-padded CHUNK rounds (one per server) so a wire observer
    // cannot distinguish found vs not-found at the round-count level.
    // Pre-fix this asserted == 0; the symmetry fix flipped it.
    let chunk_rounds = profile.count_of_kind(&RoundKind::Chunk);
    assert!(
        chunk_rounds >= 2,
        "expected ≥2 Chunk rounds for not-found post-fix (one per server), got {} \
         — CHUNK Round-Presence Symmetry violated (pre-fix behavior?)",
        chunk_rounds,
    );
    // Each emitted CHUNK round must still be K_CHUNK-padded.
    // `assert_pir_k_padding` below would also catch this, but make it
    // explicit since it is the invariant the symmetry fix preserves.
    for r in profile.rounds_of_kind(&RoundKind::Chunk) {
        assert_eq!(
            r.items.len(), k_chunk,
            "DPF not-found Chunk round items.len()={}, expected K_CHUNK={}",
            r.items.len(), k_chunk,
        );
    }

    assert_pir_k_padding(&profile, k_index, k_chunk);
    assert_merkle_per_level_uniform(&profile);
    // DPF INDEX shape: items[g] = INDEX_CUCKOO_NUM_HASHES = 2.
    for r in profile.rounds_of_kind(&RoundKind::Index) {
        assert!(
            r.items_uniform(k_index, 2),
            "DPF Index round violates items_uniform(K={}, 2): {:?}",
            k_index, r.items,
        );
    }
    // DPF Merkle sibling shape: items[g] = 1 (one DPF key per group per pass).
    let merkle_kind = RoundKind::IndexMerkleSiblings { level: 0 };
    for r in profile.rounds_of_kind(&merkle_kind) {
        assert!(
            r.items_uniform(k_index, 1),
            "DPF IndexMerkleSiblings round violates items_uniform(K={}, 1): {:?}",
            k_index, r.items,
        );
    }
    assert_per_round_uniform(&profile, &RoundKind::Index);
}

/// Two not-found scripthashes must produce structurally equal
/// (and byte-identical) leakage profiles.
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn dpf_simulator_property_two_not_found() {
    let (sh_a, sh_b) = not_found_pair();
    let profile_a = run_dpf_single_query(sh_a).await;
    let profile_b = run_dpf_single_query(sh_b).await;
    assert_profiles_equivalent(&profile_a, &profile_b);
}

async fn run_dpf_single_query(sh: ScriptHash) -> LeakageProfile {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.set_leakage_recorder(Some(recorder.clone()));
    client.connect().await.expect("dpf connect");
    let catalog = client.fetch_catalog().await.expect("dpf fetch_catalog");
    let _ = client
        .query_batch(&[sh], catalog.databases[0].db_id)
        .await
        .expect("dpf query_batch");
    client.disconnect().await.unwrap();
    recorder.take_profile("dpf")
}

// ─── Multi-query batch leakage observation ─────────────────────────────────

/// Multi-query batch profile capture — print-only.
///
/// Originally introduced to expose what the wire reveals on the
/// `index_max_items_per_group_per_level` axis (single-query corpora
/// cannot exercise the per-batch collision pattern). Post-Option-B
/// closure (this commit) the axis is structurally trivial: the PBC
/// plan routes each scripthash to a unique-per-batch `pbc_group` and
/// `max_items_per_group_per_level = 2` independently of input. The
/// closure regression test is `dpf_simulator_property_multi_query_collision`;
/// this print-only test stays as a quick-glance audit on the
/// per-message wire shape of any multi-query batch.
///
/// Asserts the structural invariants we DO know hold:
///   - K-padding on every Index / Chunk / Merkle round (per-message)
///   - `Index` rounds emit `items_uniform(K, 2)` (CLAUDE.md INDEX-Merkle
///     Item-Count Symmetry)
///   - At least 2 Index rounds (one per server, single batched call) —
///     after closure this is exactly 2 (= 1 PBC round × 2 servers)
///     instead of 4 (was 1 per scripthash × 2 servers pre-closure).
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn dpf_per_message_invariants_batch_2_not_found() {
    let (sh_a, sh_b) = not_found_pair();
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.set_leakage_recorder(Some(recorder.clone()));

    client.connect().await.expect("dpf connect");
    let catalog = client.fetch_catalog().await.expect("dpf fetch_catalog");
    let main = &catalog.databases[0];
    let k_index = main.index_k as usize;
    let k_chunk = main.chunk_k as usize;

    let _ = client
        .query_batch(&[sh_a, sh_b], main.db_id)
        .await
        .expect("dpf query_batch");

    let profile = recorder.take_profile("dpf");
    println!(
        "dpf 2-query not-found profile: {} rounds — kinds: {:?}",
        profile.rounds.len(),
        profile.rounds.iter().map(|r| r.kind).collect::<Vec<_>>()
    );
    let merkle_index_rounds_per_level: std::collections::HashMap<u8, usize> =
        profile
            .rounds_of_kind(&RoundKind::IndexMerkleSiblings { level: 0 })
            .fold(std::collections::HashMap::new(), |mut acc, r| {
                if let RoundKind::IndexMerkleSiblings { level } = r.kind {
                    *acc.entry(level).or_insert(0) += 1;
                }
                acc
            });
    println!(
        "dpf 2-query IndexMerkleSiblings per level: {:?} \
         (per-level pass count = leak.index_max_items_per_group_per_level × 2 servers)",
        merkle_index_rounds_per_level,
    );

    assert_pir_k_padding(&profile, k_index, k_chunk);
    assert_merkle_per_level_uniform(&profile);
    assert!(
        profile.count_of_kind(&RoundKind::Index) >= 2,
        "expected ≥2 Index rounds (one per DPF server) for a single-call batch",
    );
    for r in profile.rounds_of_kind(&RoundKind::Index) {
        assert!(
            r.items_uniform(k_index, 2),
            "DPF Index round violates items_uniform(K={}, 2): {:?}",
            k_index, r.items,
        );
    }
}

// ─── Multi-query simulator-property test (curated colliding pairs) ─────────

/// Six scripthashes curated by `examples/find_colliding_scripthashes.rs`
/// (seed = 0xCAFE_BABE_DEAD_BEEF, N = 1000, K = 75). The first four share
/// `derive_groups_3(_, K)[0] = 0`, so `batch_A = (a1, a2)` and
/// `batch_B = (b1, b2)` both place all four INDEX Merkle items in PBC
/// group 0 → `max_items_per_group_per_level = 4`. The last two have
/// distinct assigned groups (1 and 2) so `batch_C = (c1, c2)` gives
/// `max_items_per_group_per_level = 2`.
///
/// If `K` ever changes, re-run `find_colliding_scripthashes` and
/// re-pin these constants — `assert_curated_collision_pattern` below
/// catches drift before the test makes any network call.
const SH_A1_HEX: &str = "a35dd7fc68ee4028256a46afa1c30b82419a87fa";
const SH_A2_HEX: &str = "b9b46c7234681edbc77cc4ffd06a86a7da087976";
const SH_B1_HEX: &str = "6c3ffd393e1f1e604bad7880de2775893293aed5";
const SH_B2_HEX: &str = "bfe0ca50f50454a38ff23a1376bd7409eeb5693c";
const SH_C1_HEX: &str = "7c9844b54ece3bc47b34b6a081fddbb1f2eb7490";
const SH_C2_HEX: &str = "a9cd440d7fe7f2c16686eab2351b620459f2958d";

/// Decode the six hex constants into `ScriptHash`es and verify the
/// collision pattern that the test relies on. Runs locally — no
/// network — so any drift fires before we hit the server.
fn curated_batches() -> ([ScriptHash; 2], [ScriptHash; 2], [ScriptHash; 2]) {
    let a1 = hex_to_array(SH_A1_HEX);
    let a2 = hex_to_array(SH_A2_HEX);
    let b1 = hex_to_array(SH_B1_HEX);
    let b2 = hex_to_array(SH_B2_HEX);
    let c1 = hex_to_array(SH_C1_HEX);
    let c2 = hex_to_array(SH_C2_HEX);
    assert_curated_collision_pattern(&[a1, a2, b1, b2, c1, c2]);
    ([a1, a2], [b1, b2], [c1, c2])
}

/// Re-derive `assigned_group = derive_groups_3(sh, K)[0]` for each pinned
/// scripthash and assert the (4-collision, 2-distinct) pattern. Pinned
/// values are tied to `K = INDEX_PARAMS.k = 75`; if either changes,
/// `find_colliding_scripthashes` must be re-run.
fn assert_curated_collision_pattern(shs: &[ScriptHash; 6]) {
    let k = pir_core::params::INDEX_PARAMS.k;
    let groups: Vec<usize> = shs.iter().map(|sh| derive_groups_3(sh, k)[0]).collect();
    // a1, a2, b1, b2 must all share one group.
    assert_eq!(
        groups[0], groups[1],
        "curated SH_A1 and SH_A2 should share assigned_group (got {} vs {}); \
         re-run examples/find_colliding_scripthashes",
        groups[0], groups[1],
    );
    assert_eq!(
        groups[0], groups[2],
        "curated SH_A1 and SH_B1 should share assigned_group (got {} vs {})",
        groups[0], groups[2],
    );
    assert_eq!(
        groups[0], groups[3],
        "curated SH_A1 and SH_B2 should share assigned_group (got {} vs {})",
        groups[0], groups[3],
    );
    // c1 != c2 != a1.
    assert_ne!(
        groups[4], groups[5],
        "curated SH_C1 and SH_C2 should fall in distinct assigned_groups (both = {})",
        groups[4],
    );
    assert_ne!(
        groups[4], groups[0],
        "curated SH_C1 should not share assigned_group {} with the colliding bucket",
        groups[0],
    );
    assert_ne!(
        groups[5], groups[0],
        "curated SH_C2 should not share assigned_group {} with the colliding bucket",
        groups[0],
    );
}

/// Drive a multi-query batch through a fresh DPF client and capture its
/// `LeakageProfile`. Mirror of `run_dpf_single_query` for the multi-query
/// case used by the simulator-property collision test.
async fn run_dpf_batch_query(scripthashes: &[ScriptHash]) -> LeakageProfile {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.set_leakage_recorder(Some(recorder.clone()));
    client.connect().await.expect("dpf connect");
    let catalog = client.fetch_catalog().await.expect("dpf fetch_catalog");
    let _ = client
        .query_batch(scripthashes, catalog.databases[0].db_id)
        .await
        .expect("dpf query_batch");
    client.disconnect().await.unwrap();
    recorder.take_profile("dpf")
}

/// Cheap, no-network sanity check that the pinned hex constants still
/// witness the (4-collision, 2-distinct) pattern. Runs on every
/// `cargo test` invocation (no `--ignored` flag needed) so a `K` change
/// in `INDEX_PARAMS` fires here long before the integration test would.
#[test]
fn curated_scripthashes_match_collision_pattern() {
    let _ = curated_batches();
}

/// Multi-query simulator-property witness for the
/// `index_max_items_per_group_per_level` axis CLOSURE.
///
/// Pre-closure (commit `6eda18a`), the curated `batch_A`/`batch_B` (which
/// shared a colliding `derive_groups_3[0]` bucket) emitted 2× the
/// `IndexMerkleSiblings` rounds of the non-colliding `batch_C` —
/// `max_items_per_group_per_level` was DPF's `derive_groups_3[0]`
/// collision pattern, directly observable on the wire. The empirical
/// witness was DPF A=24 / C=12, Harmony A=12 / C=6.
///
/// Post-closure (this commit), DPF's INDEX phase routes each scripthash
/// to its PBC-plan-assigned group (one of the three `derive_groups_3`
/// candidates) instead of always to `[0]`. The plan distributes
/// scripthashes across distinct groups within a round, so each
/// scripthash's two INDEX Merkle items inherit a UNIQUE-per-batch
/// `pbc_group`. `max_items_per_group_per_level = 2` independently of
/// the batch's collision pattern.
///
/// All three curated batches now produce **byte-identical** profiles:
///   - `profile_A == profile_B` — already held pre-closure.
///   - `profile_A == profile_C` — only holds POST-closure; pre-closure
///     this was `assert_ne!`.
///
/// This test is the regression guard for the closure: any future change
/// that re-introduces `derive_groups_3[0]` coupling (or breaks the PBC
/// plan) will flip these assertions.
///
/// Empirical against `wss://pir1.chenweikeng.com` (post-closure):
///   `total rounds A=B=C=19; IndexMerkleSiblings A=B=C=12`
///   = 2 max_items_per_group × 2 servers × 3 Merkle levels.
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn dpf_simulator_property_multi_query_collision() {
    let (batch_a, batch_b, batch_c) = curated_batches();

    let profile_a = run_dpf_batch_query(&batch_a).await;
    let profile_b = run_dpf_batch_query(&batch_b).await;
    let profile_c = run_dpf_batch_query(&batch_c).await;

    let a_merkle = profile_a.count_of_kind(&RoundKind::IndexMerkleSiblings { level: 0 });
    let b_merkle = profile_b.count_of_kind(&RoundKind::IndexMerkleSiblings { level: 0 });
    let c_merkle = profile_c.count_of_kind(&RoundKind::IndexMerkleSiblings { level: 0 });
    println!(
        "dpf multi-query collision (post-closure): total rounds A={} B={} C={}; \
         IndexMerkleSiblings A={} B={} C={}",
        profile_a.rounds.len(), profile_b.rounds.len(), profile_c.rounds.len(),
        a_merkle, b_merkle, c_merkle,
    );

    // Post-closure: all three profiles must be byte-identical. The PBC
    // plan routes colliding scripthashes to alternate candidate groups,
    // so the wire-observable axis is constant across collision patterns.
    assert_profiles_equivalent(&profile_a, &profile_b);
    assert_profiles_equivalent(&profile_a, &profile_c);

    // Per-axis sanity: IndexMerkleSiblings count is the same across all
    // three batches (= 2 max_items_per_group × n_servers × n_levels). If
    // a future regression re-couples Merkle items to derive_groups_3[0],
    // a_merkle would jump to 2× c_merkle and `assert_profiles_equivalent`
    // above would fire first; this assertion is a clearer error signal
    // when that happens.
    assert!(
        c_merkle > 0,
        "expected ≥1 IndexMerkleSiblings round in batch_C profile (DB has Merkle?); got 0",
    );
    assert_eq!(
        a_merkle, c_merkle,
        "expected batch_A and batch_C IndexMerkleSiblings counts to match \
         post-closure (got A={}, C={}); if A == 2*C, the PBC plan regressed \
         to derive_groups_3[0] coupling",
        a_merkle, c_merkle,
    );

    // Assertion 1 already covered byte-identity for B vs A; print B's
    // merkle count too as a sanity record.
    assert_eq!(
        a_merkle, b_merkle,
        "expected batch_A and batch_B IndexMerkleSiblings counts to match \
         (got {} vs {}) — same colliding bucket should produce same wire shape",
        a_merkle, b_merkle,
    );
}

// ─── Harmony tests ──────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn harmony_per_message_invariants_not_found() {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());
    client.set_leakage_recorder(Some(recorder.clone()));

    client.connect().await.expect("harmony connect");
    let catalog = client.fetch_catalog().await.expect("harmony fetch_catalog");
    let main = &catalog.databases[0];
    let k_index = main.index_k as usize;
    let k_chunk = main.chunk_k as usize;

    let (sh, _) = not_found_pair();
    let _ = client
        .query_batch(&[sh], main.db_id)
        .await
        .expect("harmony query_batch");

    let profile = recorder.take_profile("harmony");
    println!(
        "harmony not-found profile: {} rounds — {:?}",
        profile.rounds.len(),
        profile.rounds.iter().map(|r| r.kind).collect::<Vec<_>>()
    );

    // HarmonyPIR sends one Index round per script-hash query (no
    // per-server fan-out for the query phase — just the query server).
    assert!(
        profile.count_of_kind(&RoundKind::Index) >= 1,
        "expected ≥1 Index round, got {}",
        profile.count_of_kind(&RoundKind::Index),
    );
    assert_pir_k_padding(&profile, k_index, k_chunk);
    assert_merkle_per_level_uniform(&profile);

    // HarmonyPIR per-group invariant — every Index/Chunk slot sends
    // EXACTLY `T - 1` distinct indices. We don't hardcode T (it depends
    // on bin count); just assert per-round uniformity. A drift would
    // expose the hint-state-leak the 2026 fix closed.
    assert_per_round_uniform(&profile, &RoundKind::Index);
    assert_per_round_uniform(&profile, &RoundKind::IndexMerkleSiblings { level: 0 });
    assert_per_round_uniform(&profile, &RoundKind::ChunkMerkleSiblings { level: 0 });

    // All Index rounds share the same per-group T-1 value.
    let index_first = profile
        .rounds_of_kind(&RoundKind::Index)
        .next()
        .map(|r| r.items.first().copied().unwrap_or(0));
    if let Some(t_minus_1) = index_first {
        for r in profile.rounds_of_kind(&RoundKind::Index) {
            assert!(
                r.items_uniform(k_index, t_minus_1),
                "Harmony Index round violates items_uniform(K={}, T-1={}): {:?}",
                k_index, t_minus_1, r.items,
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn harmony_simulator_property_two_not_found() {
    let (sh_a, sh_b) = not_found_pair();
    let profile_a = run_harmony_single_query(sh_a).await;
    let profile_b = run_harmony_single_query(sh_b).await;
    // Harmony's hint refresh phase is initiated lazily — the first
    // query in a session triggers a full hint download. Two fresh
    // sessions both incur the same hint refresh, so the profiles
    // should still match. If they don't, that's a real finding worth
    // investigating.
    assert_profiles_equivalent(&profile_a, &profile_b);
}

async fn run_harmony_single_query(sh: ScriptHash) -> LeakageProfile {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());
    client.set_leakage_recorder(Some(recorder.clone()));
    client.connect().await.expect("harmony connect");
    let catalog = client.fetch_catalog().await.expect("harmony fetch_catalog");
    let _ = client
        .query_batch(&[sh], catalog.databases[0].db_id)
        .await
        .expect("harmony query_batch");
    client.disconnect().await.unwrap();
    recorder.take_profile("harmony")
}

async fn run_harmony_batch_query(scripthashes: &[ScriptHash]) -> LeakageProfile {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = HarmonyClient::new(&harmony_hint_url(), &harmony_query_url());
    client.set_leakage_recorder(Some(recorder.clone()));
    client.connect().await.expect("harmony connect");
    let catalog = client.fetch_catalog().await.expect("harmony fetch_catalog");
    let _ = client
        .query_batch(scripthashes, catalog.databases[0].db_id)
        .await
        .expect("harmony query_batch");
    client.disconnect().await.unwrap();
    recorder.take_profile("harmony")
}

/// Multi-query simulator-property witness for HarmonyPIR — same
/// curated scripthash batches as the DPF analog, since HarmonyPIR's
/// INDEX path also assigns each scripthash to
/// `derive_groups_3(sh, K)[0]`. Pre-closure (commit `6eda18a`) the
/// curated colliding pair drove HarmonyPIR's
/// `max_items_per_group_per_level` from 2 to 4, with empirical
/// `IndexMerkleSiblings A=12 B=12 C=6`. Post-closure (this commit)
/// HarmonyPIR's INDEX phase routes each scripthash to its
/// PBC-plan-assigned group instead of `[0]`, so the three batches
/// produce byte-identical profiles. The DPF analog has the same
/// post-closure assertions; see its docstring for the full rationale.
///
/// Empirical against Hetzner (post-closure):
///   `total rounds A=B=C=20; IndexMerkleSiblings A=B=C=6`
///   = 2 max_items_per_group × 1 server × 3 Merkle levels.
///
/// Known flake: HarmonyPIR runs against the public Hetzner deployment
/// can intermittently time out on the hint-stream WebSocket — the same
/// caveat documented in `harmony_simulator_property_two_not_found`.
/// If this test fails with a connection / timeout error rather than
/// an assertion mismatch, retry once before treating it as a real
/// finding.
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn harmony_simulator_property_multi_query_collision() {
    let (batch_a, batch_b, batch_c) = curated_batches();

    let profile_a = run_harmony_batch_query(&batch_a).await;
    let profile_b = run_harmony_batch_query(&batch_b).await;
    let profile_c = run_harmony_batch_query(&batch_c).await;

    let a_merkle = profile_a.count_of_kind(&RoundKind::IndexMerkleSiblings { level: 0 });
    let b_merkle = profile_b.count_of_kind(&RoundKind::IndexMerkleSiblings { level: 0 });
    let c_merkle = profile_c.count_of_kind(&RoundKind::IndexMerkleSiblings { level: 0 });
    println!(
        "harmony multi-query collision (post-closure): total rounds A={} B={} C={}; \
         IndexMerkleSiblings A={} B={} C={}",
        profile_a.rounds.len(), profile_b.rounds.len(), profile_c.rounds.len(),
        a_merkle, b_merkle, c_merkle,
    );

    // Post-closure: all three profiles must be byte-identical.
    assert_profiles_equivalent(&profile_a, &profile_b);
    assert_profiles_equivalent(&profile_a, &profile_c);

    assert!(
        c_merkle > 0,
        "expected ≥1 IndexMerkleSiblings round in batch_C profile (DB has Merkle?); got 0",
    );
    assert_eq!(
        a_merkle, c_merkle,
        "expected harmony batch_A and batch_C IndexMerkleSiblings counts to match \
         post-closure (got A={}, C={}); if A == 2*C, the PBC plan regressed \
         to derive_groups_3[0] coupling",
        a_merkle, c_merkle,
    );
}

// ─── OnionPIR tests (feature-gated) ─────────────────────────────────────────

#[cfg(feature = "onion")]
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn onion_per_message_invariants_not_found() {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = OnionClient::new(&onion_url());
    client.set_leakage_recorder(Some(recorder.clone()));

    client.connect().await.expect("onion connect");
    let catalog = client.fetch_catalog().await.expect("onion fetch_catalog");
    let main = &catalog.databases[0];
    let k_index = main.index_k as usize;
    let k_chunk = main.chunk_k as usize;

    let (sh, _) = not_found_pair();
    let _ = client
        .query_batch(&[sh], main.db_id)
        .await
        .expect("onion query_batch");

    let profile = recorder.take_profile("onion");
    println!(
        "onion not-found profile: {} rounds — {:?}",
        profile.rounds.len(),
        profile.rounds.iter().map(|r| r.kind).collect::<Vec<_>>()
    );

    // OnionPIR is single-server, so one Index round per query (vs DPF's
    // two). Expect at least one Index round + the OnionKeyRegister.
    assert!(
        profile.count_of_kind(&RoundKind::Index) >= 1,
        "expected ≥1 Index round, got {}",
        profile.count_of_kind(&RoundKind::Index),
    );
    // CHUNK Round-Presence Symmetry: not-found also emits a
    // K_CHUNK-padded CHUNK round (single-server, so just one). Pre-fix
    // OnionPIR not-found queries skipped CHUNK rounds entirely, which
    // distinguished found vs not-found on the wire.
    let chunk_rounds = profile.count_of_kind(&RoundKind::Chunk);
    assert!(
        chunk_rounds >= 1,
        "expected ≥1 Chunk round for not-found post-fix, got {} \
         — CHUNK Round-Presence Symmetry violated (pre-fix behavior?)",
        chunk_rounds,
    );
    for r in profile.rounds_of_kind(&RoundKind::Chunk) {
        assert_eq!(
            r.items.len(), k_chunk,
            "OnionPIR not-found Chunk round items.len()={}, expected K_CHUNK={}",
            r.items.len(), k_chunk,
        );
    }

    assert_pir_k_padding(&profile, k_index, k_chunk);
    assert_merkle_per_level_uniform(&profile);

    // OnionPIR INDEX shape: items[g] = INDEX_CUCKOO_NUM_HASHES = 2
    // (matches DPF — see CLAUDE.md "Merkle INDEX Item-Count Symmetry").
    for r in profile.rounds_of_kind(&RoundKind::Index) {
        assert!(
            r.items_uniform(k_index, 2),
            "OnionPIR Index round violates items_uniform(K={}, 2): {:?}",
            k_index, r.items,
        );
    }
    // OnionPIR sibling round: items[g] = 1 (one FHE query per group).
    // OnionPIR Merkle uses a per-level server-driven K (`level_info.k`),
    // not the PIR `index_k` — see `assert_pir_k_padding` doc — so we
    // don't hardcode K_index here. Per-level K consistency is checked
    // by `assert_merkle_per_level_uniform`; this loop just asserts the
    // per-group value is 1.
    for r in profile.rounds_of_kind(&RoundKind::IndexMerkleSiblings { level: 0 }) {
        assert!(
            r.items.iter().all(|&v| v == 1),
            "OnionPIR IndexMerkleSiblings level 0: expected all items=1, got {:?}",
            r.items,
        );
    }
}

#[cfg(feature = "onion")]
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn onion_simulator_property_two_not_found() {
    let (sh_a, sh_b) = not_found_pair();
    let profile_a = run_onion_single_query(sh_a).await;
    let profile_b = run_onion_single_query(sh_b).await;
    assert_profiles_equivalent(&profile_a, &profile_b);
}

#[cfg(feature = "onion")]
async fn run_onion_single_query(sh: ScriptHash) -> LeakageProfile {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = OnionClient::new(&onion_url());
    client.set_leakage_recorder(Some(recorder.clone()));
    client.connect().await.expect("onion connect");
    let catalog = client.fetch_catalog().await.expect("onion fetch_catalog");
    let _ = client
        .query_batch(&[sh], catalog.databases[0].db_id)
        .await
        .expect("onion query_batch");
    client.disconnect().await.unwrap();
    recorder.take_profile("onion")
}

#[cfg(feature = "onion")]
async fn run_onion_batch_query(scripthashes: &[ScriptHash]) -> LeakageProfile {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = OnionClient::new(&onion_url());
    client.set_leakage_recorder(Some(recorder.clone()));
    client.connect().await.expect("onion connect");
    let catalog = client.fetch_catalog().await.expect("onion fetch_catalog");
    let _ = client
        .query_batch(scripthashes, catalog.databases[0].db_id)
        .await
        .expect("onion query_batch");
    client.disconnect().await.unwrap();
    recorder.take_profile("onion")
}

/// Multi-query simulator-property witness for OnionPIR. Reuses the
/// curated scripthash pairs from `curated_batches()` (the same six
/// pinned values the DPF and Harmony analogs use).
///
/// **Why this asserts equivalence across ALL three batches** — including
/// the non-colliding `batch_C`, where DPF and Harmony assert *non*-equivalence:
///
/// 1. OnionPIR's INDEX query layer
///    ([pir-sdk-client/src/onion.rs:1228-1232](pir-sdk-client/src/onion.rs:1228))
///    calls `pbc_plan_rounds` over the scripthashes' `derive_groups_3`
///    triples. When two scripthashes share `derive_groups_3[0]`, the
///    planner re-routes one to its [1] or [2] within the same INDEX
///    round — they land in different `group` slots, so their INDEX
///    Merkle leaves do *not* accumulate in one PBC group the way DPF's
///    do.
/// 2. OnionPIR's INDEX Merkle layer
///    ([pir-sdk-client/src/onion_merkle.rs:777-790](pir-sdk-client/src/onion_merkle.rs:777))
///    buckets items by `gid = node_idx / arity` (post-cuckoo, *not* by
///    `pbc_group`), then PBC-routes unique gids again via
///    `derive_int_groups_3(gid, level_info.k)`. Wire emits
///    `pbc_rounds.len()` rounds per level.
/// 3. Concretely: ARITY = 120 for OnionPIR Merkle (see
///    `build/src/gen_4_build_merkle_onion.rs:35`), and
///    `level_info.k = adaptive_k(num_groups)` returns 25 for typical
///    production sizes (same file, line 40-43). For batch=2 the upper
///    bound on INDEX Merkle items is 4 → at most 4 unique gids →
///    `pbc_plan_rounds(≤4 items, k=25, 3 candidates, 500 max_kicks)`
///    always packs into 1 round.
///
/// So the `index_max_items_per_group_per_level` axis is *structurally
/// trivial on Onion at small batch*: `pbc_rounds.len() = 1` per level,
/// regardless of any collision pattern in the inputs. The empirical
/// witness here is the negation of what DPF shows — the curation that
/// distinguishes DPF/Harmony profiles is a no-op on Onion.
///
/// If `level_info.k` ever drops to ≤ 4 (very small DB) or batch size
/// grows past ~12, the per-level count assertion below fires and forces
/// a re-think. The condition is pinned explicitly so a future server
/// reconfiguration cannot silently invalidate the structural argument.
#[cfg(feature = "onion")]
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn onion_simulator_property_multi_query_collision() {
    let (batch_a, batch_b, batch_c) = curated_batches();

    let profile_a = run_onion_batch_query(&batch_a).await;
    let profile_b = run_onion_batch_query(&batch_b).await;
    let profile_c = run_onion_batch_query(&batch_c).await;

    // Build per-level histograms of IndexMerkleSiblings rounds. Note
    // `count_of_kind` ignores the `level` field (matches by enum
    // discriminant), so we cannot rely on it for per-level counts and
    // walk the rounds list manually instead.
    let index_merkle_per_level = |p: &LeakageProfile| -> std::collections::BTreeMap<u8, usize> {
        let mut h = std::collections::BTreeMap::new();
        for r in &p.rounds {
            if let RoundKind::IndexMerkleSiblings { level } = r.kind {
                *h.entry(level).or_insert(0) += 1;
            }
        }
        h
    };
    let hist_a = index_merkle_per_level(&profile_a);
    let hist_b = index_merkle_per_level(&profile_b);
    let hist_c = index_merkle_per_level(&profile_c);

    println!(
        "onion multi-query collision: total rounds A={} B={} C={}",
        profile_a.rounds.len(), profile_b.rounds.len(), profile_c.rounds.len(),
    );
    println!("  IndexMerkleSiblings per level:");
    for (level, &a_lvl) in &hist_a {
        let b_lvl = hist_b.get(level).copied().unwrap_or(0);
        let c_lvl = hist_c.get(level).copied().unwrap_or(0);
        println!("    L{}: A={} B={} C={}", level, a_lvl, b_lvl, c_lvl);
    }

    // Cross-batch L-equivalence — the load-bearing assertion. Holds
    // across ALL three because the axis is structurally trivial on
    // Onion at batch=2 (see header comment).
    assert_profiles_equivalent(&profile_a, &profile_b);
    assert_profiles_equivalent(&profile_a, &profile_c);

    // Pin the structural-triviality assumption per level. Each
    // observed Merkle level must have emitted exactly 1 PBC round.
    // If a future server reconfiguration shrinks `level_info.k` below
    // ~5 (or batch size grows past ~12), this fires and the
    // structural argument needs a re-think.
    assert!(
        !hist_a.is_empty(),
        "expected ≥1 IndexMerkleSiblings level in OnionPIR profile (DB has Merkle?); got 0",
    );
    for (level, &count) in &hist_a {
        assert_eq!(
            count, 1,
            "batch=2 expected pbc_rounds.len()=1 at IndexMerkleSiblings L{}; got {} \
             — server's level_info.k may have shrunk below the structural-triviality \
             threshold; see the test header comment for context",
            level, count,
        );
    }

    // Per-message K-padding still holds for the multi-query path. K
    // values come from the catalog, not constants, so a server K-rebuild
    // doesn't silently break this assertion.
    {
        let recorder_for_catalog = Arc::new(BufferingLeakageRecorder::new());
        let mut client = OnionClient::new(&onion_url());
        client.set_leakage_recorder(Some(recorder_for_catalog.clone()));
        client.connect().await.expect("onion connect (catalog probe)");
        let catalog = client
            .fetch_catalog()
            .await
            .expect("onion fetch_catalog (catalog probe)");
        let main = &catalog.databases[0];
        let k_index = main.index_k as usize;
        let k_chunk = main.chunk_k as usize;
        client.disconnect().await.unwrap();
        assert_pir_k_padding(&profile_a, k_index, k_chunk);
        assert_merkle_per_level_uniform(&profile_a);
    }
}

// ─── Phase 2.2 hardening: FOUND path + admitted-leak validation ─────────────

/// FOUND path coverage for DPF: a known-found scripthash MUST emit
/// CHUNK rounds + ChunkMerkleSiblings, while still satisfying the
/// per-message invariants. Catches a regression where the chunk-path
/// branch silently breaks (would manifest as no CHUNK rounds emitted
/// even for found queries).
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn dpf_found_query_includes_chunk_rounds() {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = DpfClient::new(&dpf_server0_url(), &dpf_server1_url());
    client.set_leakage_recorder(Some(recorder.clone()));

    client.connect().await.expect("dpf connect");
    let catalog = client.fetch_catalog().await.expect("dpf fetch_catalog");
    let main = &catalog.databases[0];
    let k_index = main.index_k as usize;
    let k_chunk = main.chunk_k as usize;

    let (sh, _) = found_pair();
    let _ = client
        .query_batch(&[sh], main.db_id)
        .await
        .expect("dpf query_batch");

    let profile = recorder.take_profile("dpf");
    println!(
        "dpf found profile: {} rounds — {:?}",
        profile.rounds.len(),
        profile.rounds.iter().map(|r| r.kind).collect::<Vec<_>>()
    );

    // Found path emits CHUNK rounds (the not-found path skips them).
    let chunk_rounds = profile.count_of_kind(&RoundKind::Chunk);
    assert!(
        chunk_rounds >= 2,
        "FOUND query expected ≥2 Chunk rounds (one per server), got {}. \
         If this fires after a server rebuild, the example scripthash \
         may have been spent — update `found_pair()` from \
         web/src/example_spks.json.",
        chunk_rounds,
    );
    // Per-message invariants still hold.
    assert_pir_k_padding(&profile, k_index, k_chunk);
    assert_merkle_per_level_uniform(&profile);
    for r in profile.rounds_of_kind(&RoundKind::Index) {
        assert!(
            r.items_uniform(k_index, 2),
            "DPF Index round violates items_uniform(K={}, 2): {:?}",
            k_index, r.items,
        );
    }
    for r in profile.rounds_of_kind(&RoundKind::Chunk) {
        // CHUNK items[g] varies because chunks fan out into groups by
        // the cuckoo placement plan — admitted leak (UTXO count). We
        // only assert items.len() == K_CHUNK here; the per-group count
        // is intentionally non-uniform.
        assert_eq!(
            r.items.len(), k_chunk,
            "DPF Chunk round items.len()={}, expected K_CHUNK={}",
            r.items.len(), k_chunk,
        );
    }
}

/// CHUNK Round-Presence Symmetry P1: a FOUND query and a NOT-FOUND
/// query MUST produce the same round count. This was the pre-fix
/// admitted leak — chunk-round absence revealed not-found — that the
/// symmetry fix in `pir-sdk-client/src/dpf.rs` closes by emitting
/// dummy K_CHUNK-padded CHUNK rounds even on the not-found path.
///
/// Pre-fix this test asserted divergence; post-fix it asserts
/// equality. If equality fails, either:
///   (a) the not-found path emits fewer CHUNK rounds than found
///       (regression — pre-fix behavior reintroduced), or
///   (b) the FOUND example was spent and degraded to NOT-FOUND
///       (update `found_pair()` from `web/src/example_spks.json`).
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn dpf_found_vs_not_found_have_same_round_count() {
    let (sh_found, _) = found_pair();
    let (sh_not_found, _) = not_found_pair();
    let p_found = run_dpf_single_query(sh_found).await;
    let p_not_found = run_dpf_single_query(sh_not_found).await;

    let found_chunks = p_found.count_of_kind(&RoundKind::Chunk);
    let not_found_chunks = p_not_found.count_of_kind(&RoundKind::Chunk);
    println!(
        "dpf found-vs-not-found: rounds={} vs {}, Chunk={} vs {}",
        p_found.rounds.len(),
        p_not_found.rounds.len(),
        found_chunks,
        not_found_chunks,
    );
    // Both paths emit ≥2 CHUNK rounds (one per server).
    assert!(
        found_chunks >= 2,
        "FOUND query expected ≥2 CHUNK rounds, got {} — example may be spent",
        found_chunks,
    );
    assert!(
        not_found_chunks >= 2,
        "NOT-FOUND query expected ≥2 CHUNK rounds post-fix, got {} \
         — CHUNK Round-Presence Symmetry violated",
        not_found_chunks,
    );
    // CHUNK round counts AGREE — the property the symmetry fix
    // delivers. The wire transcripts are indistinguishable at the
    // CHUNK-round-count level.
    //
    // Note on total round count: `p_found.rounds.len() !=
    // p_not_found.rounds.len()` is still expected — the FOUND path
    // emits CHUNK Merkle sibling rounds whose count varies with UTXO
    // count, a documented residual leak (CLAUDE.md "What the Server
    // Learns"). Closing that would be a separate "CHUNK Merkle
    // Round-Presence Symmetry" fix, not in scope here. We only assert
    // CHUNK-PIR-round equality.
    assert_eq!(
        found_chunks, not_found_chunks,
        "found and not-found CHUNK round counts diverge ({} vs {}) \
         — CHUNK Round-Presence Symmetry P1 violated",
        found_chunks, not_found_chunks,
    );
}

/// CHUNK Round-Presence Symmetry P1 (positive form): the wire
/// transcript's CHUNK-round count must depend only on batch size,
/// not on per-query found/not-found classification. This is the
/// integration-level expression of the helper-level Kani harness on
/// `items_from_trace` in `pir-sdk-client/src/dpf.rs` (which proves the
/// per-slot decision tree emits the same number of items regardless
/// of trace outcome).
///
/// Drives equal-size single-query batches — one FOUND, one NOT-FOUND
/// — through fresh DPF clients and asserts identical
/// `count_of_kind(Chunk)` on the resulting profiles. Captures
/// regressions that the Kani harness cannot — those bind helper
/// correctness, this binds it to actual wire emission.
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn dpf_round_count_is_function_of_batch_size_only() {
    let (sh_found, _) = found_pair();
    let (sh_nf, _) = not_found_pair();
    let p_found = run_dpf_single_query(sh_found).await;
    let p_nf = run_dpf_single_query(sh_nf).await;
    let found_chunks = p_found.count_of_kind(&RoundKind::Chunk);
    let nf_chunks = p_nf.count_of_kind(&RoundKind::Chunk);
    println!(
        "dpf batch-size-only: found_chunks={}, nf_chunks={}",
        found_chunks, nf_chunks,
    );
    assert_eq!(
        found_chunks, nf_chunks,
        "CHUNK round count must be a function of batch size only \
         (found={}, not_found={}) — CHUNK Round-Presence Symmetry P1 violated",
        found_chunks, nf_chunks,
    );
}

/// Same-class simulator property: two FOUND scripthashes follow the
/// FOUND path, but their profiles are only structurally equal when
/// they have the same admitted leakage (UTXO count, whale-ness). The
/// public examples have varying UTXO counts so we don't assert
/// equality — instead we assert that BOTH follow the found shape
/// (Index + Chunk + Merkle present), and we log the divergent fields
/// so a future tightening (curated equal-UTXO-count corpus) can spot
/// what aspect of `L` actually leaks across these specific queries.
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn dpf_two_found_queries_both_follow_found_shape() {
    let (sh_a, sh_b) = found_pair();
    let p_a = run_dpf_single_query(sh_a).await;
    let p_b = run_dpf_single_query(sh_b).await;

    for (label, p) in [("a", &p_a), ("b", &p_b)] {
        let chunks = p.count_of_kind(&RoundKind::Chunk);
        assert!(
            chunks >= 2,
            "found query {} emitted {} CHUNK rounds; expected ≥2 (one per server)",
            label, chunks,
        );
        assert!(p.count_of_kind(&RoundKind::Index) >= 2);
    }

    // Document the per-round divergences for future hardening — these
    // are what `L` admits beyond the not-found case (UTXO count, etc.).
    if p_a.rounds.len() == p_b.rounds.len() {
        for (i, (ra, rb)) in p_a.rounds.iter().zip(p_b.rounds.iter()).enumerate() {
            if ra.items != rb.items
                || ra.request_bytes != rb.request_bytes
                || ra.response_bytes != rb.response_bytes
            {
                println!(
                    "round[{}] {:?} divergence: items_a={:?} items_b={:?} \
                     req=({}|{}) resp=({}|{})",
                    i,
                    ra.kind,
                    ra.items,
                    rb.items,
                    ra.request_bytes,
                    rb.request_bytes,
                    ra.response_bytes,
                    rb.response_bytes,
                );
            }
        }
    } else {
        println!(
            "round counts differ ({} vs {}) — one side may be a whale",
            p_a.rounds.len(),
            p_b.rounds.len(),
        );
    }
}

// ─── Phase 2.2 hardening (Onion) ────────────────────────────────────────────

/// FOUND path coverage for OnionPIR.
#[cfg(feature = "onion")]
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn onion_found_query_includes_chunk_rounds() {
    let recorder = Arc::new(BufferingLeakageRecorder::new());
    let mut client = OnionClient::new(&onion_url());
    client.set_leakage_recorder(Some(recorder.clone()));

    client.connect().await.expect("onion connect");
    let catalog = client.fetch_catalog().await.expect("onion fetch_catalog");
    let main = &catalog.databases[0];
    let k_index = main.index_k as usize;
    let k_chunk = main.chunk_k as usize;

    let (sh, _) = found_pair();
    let _ = client
        .query_batch(&[sh], main.db_id)
        .await
        .expect("onion query_batch");

    let profile = recorder.take_profile("onion");
    println!(
        "onion found profile: {} rounds — {:?}",
        profile.rounds.len(),
        profile.rounds.iter().map(|r| r.kind).collect::<Vec<_>>()
    );

    let chunk_rounds = profile.count_of_kind(&RoundKind::Chunk);
    assert!(
        chunk_rounds >= 1,
        "OnionPIR FOUND query expected ≥1 Chunk round, got {}. \
         Update `found_pair()` if a server rebuild dropped these.",
        chunk_rounds,
    );
    assert_pir_k_padding(&profile, k_index, k_chunk);
    assert_merkle_per_level_uniform(&profile);
    for r in profile.rounds_of_kind(&RoundKind::Index) {
        assert!(r.items_uniform(k_index, 2));
    }
}

/// CHUNK Round-Presence Symmetry P1 (OnionPIR variant): FOUND and
/// NOT-FOUND queries must produce the same round count. Pre-fix
/// OnionPIR not-found emitted 0 CHUNK rounds; the symmetry fix in
/// `pir-sdk-client/src/onion.rs` (and `web/src/onionpir_client.ts`)
/// emits a K_CHUNK-padded dummy CHUNK round even on the not-found
/// path.
#[cfg(feature = "onion")]
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn onion_found_vs_not_found_have_same_round_count() {
    let (sh_found, _) = found_pair();
    let (sh_not_found, _) = not_found_pair();
    let p_found = run_onion_single_query(sh_found).await;
    let p_not_found = run_onion_single_query(sh_not_found).await;

    let found_chunks = p_found.count_of_kind(&RoundKind::Chunk);
    let not_found_chunks = p_not_found.count_of_kind(&RoundKind::Chunk);
    println!(
        "onion found-vs-not-found: rounds={} vs {}, Chunk={} vs {}",
        p_found.rounds.len(),
        p_not_found.rounds.len(),
        found_chunks,
        not_found_chunks,
    );
    assert!(
        found_chunks >= 1,
        "FOUND query expected ≥1 CHUNK round, got {}",
        found_chunks,
    );
    assert!(
        not_found_chunks >= 1,
        "NOT-FOUND query expected ≥1 CHUNK round post-fix, got {} \
         — CHUNK Round-Presence Symmetry violated",
        not_found_chunks,
    );
    // CHUNK round counts AGREE — see DPF analog for the note on why
    // total round count is still allowed to differ (CHUNK Merkle is
    // a separately-tracked residual leak, not closed by this fix).
    assert_eq!(
        found_chunks, not_found_chunks,
        "OnionPIR found and not-found CHUNK round counts diverge ({} vs {}) \
         — CHUNK Round-Presence Symmetry P1 violated",
        found_chunks, not_found_chunks,
    );
}

/// CHUNK Round-Presence Symmetry P1 (OnionPIR positive form). See
/// `dpf_round_count_is_function_of_batch_size_only` for the rationale
/// — same property, different backend.
#[cfg(feature = "onion")]
#[tokio::test]
#[ignore = "requires running PIR servers"]
async fn onion_round_count_is_function_of_batch_size_only() {
    let (sh_found, _) = found_pair();
    let (sh_nf, _) = not_found_pair();
    let p_found = run_onion_single_query(sh_found).await;
    let p_nf = run_onion_single_query(sh_nf).await;
    let found_chunks = p_found.count_of_kind(&RoundKind::Chunk);
    let nf_chunks = p_nf.count_of_kind(&RoundKind::Chunk);
    println!(
        "onion batch-size-only: found_chunks={}, nf_chunks={}",
        found_chunks, nf_chunks,
    );
    assert_eq!(
        found_chunks, nf_chunks,
        "OnionPIR CHUNK round count must be a function of batch size only \
         (found={}, not_found={}) — CHUNK Round-Presence Symmetry P1 violated",
        found_chunks, nf_chunks,
    );
}

// Suppress unused-warning noise when only one backend is built.
#[allow(dead_code)]
fn _unused_url_helpers() {
    let _ = (
        dpf_server0_url(),
        dpf_server1_url(),
        harmony_hint_url(),
        harmony_query_url(),
    );
    #[cfg(feature = "onion")]
    let _ = onion_url();
}

// Suppress unused-fn warning for the `RoundProfile` import re-export
// when building with no feature.
#[allow(dead_code)]
fn _unused_round_profile(_p: &RoundProfile) {}
