//! Curation helper for `dpf_simulator_property_multi_query_collision`.
//!
//! Generates `N` candidate 20-byte scripthashes deterministically from
//! a fixed seed, buckets them by `derive_groups_3(sh, K)[0]` (the same
//! assigned-group function the DPF and Harmony INDEX query path uses
//! at `pir-sdk-client/src/dpf.rs::query_index_level` and
//! `pir-sdk-client/src/harmony.rs::query_single`), and prints six
//! scripthashes ready to paste into the integration test.
//!
//! Output is grouped into:
//!   - 4 scripthashes sharing one assigned_group `G_collide` — these
//!     supply `batch_A = (sh_a1, sh_a2)` and `batch_B = (sh_b1, sh_b2)`.
//!     Both batches have the same per-batch leakage record because each
//!     contributes 4 INDEX Merkle items to `G_collide`, so the verifier
//!     runs `max_items_per_group_per_level = 4` passes at every INDEX
//!     Merkle level.
//!   - 2 scripthashes in distinct other buckets — these supply
//!     `batch_C = (sh_c1, sh_c2)`, where each bucket holds 2 items, so
//!     `max_items_per_group_per_level = 2`.
//!
//! By construction `L_eq(batch_A, batch_B)` and `¬L_eq(batch_A, batch_C)`
//! at the `index_max_items_per_group_per_level` axis admitted in
//! `proofs/easycrypt/Leakage.ec`.
//!
//! Run: `cargo run -p pir-sdk-client --example find_colliding_scripthashes`
//!
//! The seed and N are fixed so re-running prints the same six values;
//! re-curate (and re-pin in the test) only when `K` changes.

use pir_core::hash::derive_groups_3;
use pir_core::params::INDEX_PARAMS;
use std::collections::HashMap;

/// Fixed seed — chosen once, frozen so the printed scripthashes match
/// what the integration test pins as constants.
const SEED: u64 = 0xCAFE_BABE_DEAD_BEEF;

/// Number of candidate scripthashes to generate. With K=75 the expected
/// bucket size is N/K ≈ 13, comfortably above the 4-per-bucket
/// requirement.
const N: u64 = 1000;

/// SplitMix64 — same constants the project uses internally
/// (`pir_core::hash::splitmix64`); duplicated here so the example does
/// not depend on a private function.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^ (x >> 31)
}

/// Generate the i-th candidate scripthash from `seed`. Deterministic.
fn random_scripthash(seed: u64, idx: u64) -> [u8; 20] {
    let mut out = [0u8; 20];
    let mut s = seed.wrapping_add(idx);
    for (chunk_idx, chunk) in out.chunks_mut(8).enumerate() {
        s = splitmix64(s.wrapping_add(chunk_idx as u64));
        let bytes = s.to_le_bytes();
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = bytes[i];
        }
    }
    out
}

fn main() {
    let k = INDEX_PARAMS.k;
    println!("# Curated scripthashes for `*_simulator_property_multi_query_collision`");
    println!("# K (INDEX) = {}, seed = {:#018x}, N = {}", k, SEED, N);
    println!();

    // Bucket N candidate scripthashes by their assigned_group[0].
    let mut buckets: HashMap<usize, Vec<[u8; 20]>> = HashMap::new();
    for i in 0..N {
        let sh = random_scripthash(SEED, i);
        let g = derive_groups_3(&sh, k)[0];
        buckets.entry(g).or_default().push(sh);
    }

    // Find the SMALLEST bucket-id with ≥4 scripthashes — using min instead
    // of arbitrary HashMap iteration order keeps the picked group stable
    // across `HashMap` randomisation seeds and Rust versions.
    let g_collide = buckets
        .iter()
        .filter(|(_, v)| v.len() >= 4)
        .map(|(&g, _)| g)
        .min()
        .expect("need >=4 candidate scripthashes in some bucket; increase N");
    let collide_hashes: Vec<[u8; 20]> = buckets[&g_collide].iter().take(4).copied().collect();

    // Pick two scripthashes from DIFFERENT buckets (and ≠ g_collide), again
    // ordered by bucket id for determinism.
    let mut other_buckets: Vec<(usize, [u8; 20])> = buckets
        .iter()
        .filter_map(|(&g, hashes)| {
            if g == g_collide {
                None
            } else {
                Some((g, hashes[0]))
            }
        })
        .collect();
    other_buckets.sort_by_key(|(g, _)| *g);
    let non_collide_pair: Vec<[u8; 20]> = other_buckets.iter().take(2).map(|(_, h)| *h).collect();
    assert_eq!(non_collide_pair.len(), 2, "need 2 distinct non-colliding buckets");
    let g_c1 = derive_groups_3(&non_collide_pair[0], k)[0];
    let g_c2 = derive_groups_3(&non_collide_pair[1], k)[0];

    println!("# === COLLIDING (batch_A, batch_B share assigned_group = {}) ===", g_collide);
    let labels_collide = ["sh_a1", "sh_a2", "sh_b1", "sh_b2"];
    for (i, sh) in collide_hashes.iter().enumerate() {
        let g = derive_groups_3(sh, k)[0];
        println!("const {}_HEX: &str = \"{}\"; // assigned_group = {}", labels_collide[i].to_uppercase(), hex::encode(sh), g);
    }
    println!();
    println!("# === NON-COLLIDING (batch_C: assigned_groups {} and {}) ===", g_c1, g_c2);
    let labels_nc = ["sh_c1", "sh_c2"];
    for (i, sh) in non_collide_pair.iter().enumerate() {
        let g = derive_groups_3(sh, k)[0];
        println!("const {}_HEX: &str = \"{}\"; // assigned_group = {}", labels_nc[i].to_uppercase(), hex::encode(sh), g);
    }

    // Self-verify the collision pattern. If any of these fire, the
    // hex constants printed above are stale and must not be pinned.
    let groups_collide: Vec<usize> = collide_hashes
        .iter()
        .map(|sh| derive_groups_3(sh, k)[0])
        .collect();
    assert!(
        groups_collide.iter().all(|&g| g == g_collide),
        "internal: collide_hashes do not all share assigned_group {}: {:?}",
        g_collide,
        groups_collide,
    );
    assert!(
        g_c1 != g_c2,
        "internal: non-colliding pair landed in same bucket {}",
        g_c1,
    );
    assert!(
        g_c1 != g_collide && g_c2 != g_collide,
        "internal: non-colliding pair overlaps g_collide={}",
        g_collide,
    );

    println!();
    println!("# Sanity-checked: groups[a1..b2] all = {}, c1 = {}, c2 = {}", g_collide, g_c1, g_c2);
    println!("# Distinct scripthashes in each batch:");
    for (label, sh) in labels_collide.iter().zip(collide_hashes.iter()) {
        println!("#   {}: {}", label, hex::encode(sh));
    }
    for (label, sh) in labels_nc.iter().zip(non_collide_pair.iter()) {
        println!("#   {}: {}", label, hex::encode(sh));
    }
}
