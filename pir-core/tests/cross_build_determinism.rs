//! Cross-build reproducibility fixture test.
//!
//! Guards the chain-derived-seed reproducibility guarantee from
//! [`docs/BUILD_REPRODUCIBILITY.md`](../../docs/BUILD_REPRODUCIBILITY.md):
//! two independent builds of the *same* UTXO set at the *same*
//! [`ChainAnchor`] must produce **byte-identical** cuckoo files. Any
//! source of non-determinism that creeps into the build math —
//! `HashMap` iteration order, a parallel-write race, a stray
//! wall-clock/RNG seed, or accidental seed drift — would change the
//! output bytes and trip the SHA-256 equality assertion here.
//!
//! These helpers mirror the INDEX and CHUNK serialization paths of the
//! production builder [`build/src/build_cuckoo_generic.rs`] over a small
//! synthetic in-memory fixture, build each path twice, and compare. The
//! build glue (group assignment → per-group cuckoo tables → sequential
//! slot serialization) is intentionally duplicated rather than imported
//! because the real builder lives in the heavyweight `build` crate (it
//! pulls SEAL via `onionpir`); `pir-core` is the lightweight home where
//! the genuinely at-risk primitives (`cuckoo_insert`, `cuckoo_hash`,
//! `derive_cuckoo_key`, `compute_tag`, `write_header_with_anchor`,
//! `SnapshotSeeds`/`DeltaSeeds`) actually live, so it is the right place
//! for a fast CI determinism gate.
//!
//! The suite also asserts **anchor sensitivity**: a different anchor must
//! produce a different file *body* (not merely a different embedded
//! header), proving the chain-derived seed actually drives cuckoo
//! placement. Without this, the seed could be silently ignored and the
//! "unpredictable until the anchor block is mined" property would be
//! vacuous.

use pir_core::cuckoo::{self, HeaderAnchor};
use pir_core::hash;
use pir_core::params::{
    CHUNK_PARAMS, CHUNK_SIZE, INDEX_PARAMS, INDEX_RECORD_SIZE, INDEX_SLOT_SIZE, SCRIPT_HASH_SIZE,
};
use pir_core::seeds::{ChainAnchor, DeltaAnchor, DeltaSeeds, SnapshotSeeds};
use sha2::{Digest, Sha256};

/// Number of synthetic entries. Large enough that the INDEX/CHUNK
/// builders span many bins per group (so a seed change reshuffles slot
/// positions rather than coincidentally landing identically), small
/// enough to build in milliseconds.
const FIXTURE_N: usize = 600;

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Bins-per-table for the synthetic fixture.
///
/// The production builder uses [`cuckoo::compute_bins_per_table`], which
/// targets a ~0.95 load factor. That is validated at mainnet scale (each
/// of the K tables holds hundreds of thousands of bins, so finite-size
/// effects are negligible and 2-hash / 4-slot cuckoo packs reliably even
/// near 0.95). At fixture scale (`bins_per_table` in the single digits) a
/// table sitting at ~0.94 load can fail to pack for an unlucky
/// chain-derived seed — purely a small-N artifact, not a property this
/// test should assert on. We therefore size the fixture's tables for a
/// relaxed ~0.6 load so insertion succeeds for *any* seed. Determinism —
/// the property under test — is independent of the exact bin count: the
/// build is a pure function of (entries, seed, bin count), and the bin
/// count itself is a pure function of `max_load`, so two builds of the
/// same fixture at the same anchor remain byte-identical regardless.
fn fixture_bins_per_table(max_load: usize, slots_per_bin: usize) -> usize {
    if max_load == 0 {
        return 1;
    }
    ((max_load as f64 / (slots_per_bin as f64 * 0.6)).ceil() as usize).max(2)
}

/// Deterministic synthetic INDEX records: `n` × `INDEX_RECORD_SIZE` bytes
/// (20-byte scripthash + 4-byte start_chunk_id + 1-byte num_chunks). Each
/// record is the first `INDEX_RECORD_SIZE` bytes of a counter-seeded
/// SHA-256, so the fixture itself is platform-independent and reproducible
/// (no `rand`). The payload bytes after the scripthash do not affect cuckoo
/// placement — they are copied verbatim into the slot — but we still derive
/// them deterministically so the serialized slots are reproducible.
fn synthetic_index_records(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n * INDEX_RECORD_SIZE);
    for i in 0..n {
        let mut h = Sha256::new();
        h.update(b"pir-core/fixture/index/v1/");
        h.update((i as u64).to_le_bytes());
        let digest = h.finalize();
        out.extend_from_slice(&digest[..INDEX_RECORD_SIZE]);
    }
    out
}

/// Deterministic synthetic CHUNK data: `n` × `CHUNK_SIZE` bytes. Chunk IDs
/// are the implicit positions `0..n`; placement depends only on the id and
/// the chunk master seed, so the data bytes are arbitrary-but-reproducible.
fn synthetic_chunks(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n * CHUNK_SIZE);
    for i in 0..n {
        let mut h = Sha256::new();
        h.update(b"pir-core/fixture/chunk/v1/");
        h.update((i as u64).to_le_bytes());
        // CHUNK_SIZE (40) > 32, so stretch with a second block.
        let d0 = h.finalize();
        out.extend_from_slice(&d0);
        let mut h2 = Sha256::new();
        h2.update(b"pir-core/fixture/chunk/v1/x");
        h2.update((i as u64).to_le_bytes());
        let d1 = h2.finalize();
        out.extend_from_slice(&d1[..CHUNK_SIZE - 32]);
    }
    out
}

/// Mirror of [`build_cuckoo_generic`]'s INDEX path: assign entries to PBC
/// groups, build per-group cuckoo tables, serialize header + tagged slots.
/// Sequential (no rayon) — the production builder collects rayon results
/// positionally into a `Vec<Vec<u32>>`, so the serialized bytes are
/// identical to a sequential build by construction.
fn build_index_cuckoo_bytes(records: &[u8], index_master: u64, index_tag: u64, anchor: &HeaderAnchor) -> Vec<u8> {
    let params = INDEX_PARAMS.with_master_seed(index_master);
    let params = &params;
    let n = records.len() / INDEX_RECORD_SIZE;

    let mut group_entries: Vec<Vec<usize>> = vec![Vec::new(); params.k];
    for i in 0..n {
        let off = i * INDEX_RECORD_SIZE;
        let script_hash = &records[off..off + SCRIPT_HASH_SIZE];
        for &b in &hash::derive_groups_3(script_hash, params.k) {
            group_entries[b].push(i);
        }
    }

    let max_load = group_entries.iter().map(|v| v.len()).max().unwrap_or(0);
    let bins_per_table = fixture_bins_per_table(max_load, params.slots_per_bin);

    let tables: Vec<Vec<u32>> = (0..params.k)
        .map(|group_id| {
            let script_hashes: Vec<&[u8]> = group_entries[group_id]
                .iter()
                .map(|&i| &records[i * INDEX_RECORD_SIZE..i * INDEX_RECORD_SIZE + SCRIPT_HASH_SIZE])
                .collect();
            cuckoo::build_byte_keyed_table(&script_hashes, group_id, params, bins_per_table)
        })
        .collect();

    let mut out = cuckoo::write_header_with_anchor(params, bins_per_table, index_tag, Some(anchor));
    for group_id in 0..params.k {
        let table = &tables[group_id];
        let entries = &group_entries[group_id];
        for &entry_local in table.iter().take(bins_per_table * params.slots_per_bin) {
            if entry_local == cuckoo::EMPTY {
                out.extend_from_slice(&[0u8; INDEX_SLOT_SIZE]);
            } else {
                let gi = entries[entry_local as usize];
                let off = gi * INDEX_RECORD_SIZE;
                let script_hash = &records[off..off + SCRIPT_HASH_SIZE];
                let tag = hash::compute_tag(index_tag, script_hash);
                out.extend_from_slice(&tag.to_le_bytes());
                out.extend_from_slice(&records[off + SCRIPT_HASH_SIZE..off + INDEX_RECORD_SIZE]);
            }
        }
    }
    out
}

/// Mirror of [`build_cuckoo_generic`]'s CHUNK path: assign chunk ids to PBC
/// groups, build per-group int-keyed cuckoo tables, serialize header +
/// inlined `[4B chunk_id][CHUNK_SIZE data]` slots.
fn build_chunk_cuckoo_bytes(chunks: &[u8], chunk_master: u64, anchor: &HeaderAnchor) -> Vec<u8> {
    let params = CHUNK_PARAMS.with_master_seed(chunk_master);
    let params = &params;
    let num_chunks = chunks.len() / CHUNK_SIZE;

    let mut group_chunks: Vec<Vec<u32>> = vec![Vec::new(); params.k];
    for chunk_id in 0..num_chunks as u32 {
        for &b in &hash::derive_int_groups_3(chunk_id, params.k) {
            group_chunks[b].push(chunk_id);
        }
    }

    let max_load = group_chunks.iter().map(|v| v.len()).max().unwrap_or(0);
    let bins_per_table = fixture_bins_per_table(max_load, params.slots_per_bin);

    let tables: Vec<Vec<u32>> = (0..params.k)
        .map(|group_id| cuckoo::build_int_keyed_table(&group_chunks[group_id], group_id, params, bins_per_table))
        .collect();

    let slot_size = 4 + CHUNK_SIZE;
    let zero_slot = vec![0u8; slot_size];

    let mut out = cuckoo::write_header_with_anchor(params, bins_per_table, 0, Some(anchor));
    for group_id in 0..params.k {
        let table = &tables[group_id];
        let ids = &group_chunks[group_id];
        for &entry_local in table.iter().take(bins_per_table * params.slots_per_bin) {
            if entry_local == cuckoo::EMPTY {
                out.extend_from_slice(&zero_slot);
            } else {
                let chunk_id = ids[entry_local as usize];
                let data_off = chunk_id as usize * CHUNK_SIZE;
                out.extend_from_slice(&chunk_id.to_le_bytes());
                out.extend_from_slice(&chunks[data_off..data_off + CHUNK_SIZE]);
            }
        }
    }
    out
}

fn anchor_a() -> ChainAnchor {
    ChainAnchor {
        block_hash: [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x6f, 0x3d, 0x91, 0xc4,
            0x55, 0x2e, 0x7b, 0x18, 0xd0, 0x4f, 0x21, 0x86, 0x9c, 0x33, 0xab, 0xcd, 0xef, 0x01,
            0x23, 0x45, 0x67, 0x89,
        ],
        block_height: 850_000,
    }
}

fn anchor_b() -> ChainAnchor {
    // Different block hash, same height — proves the hash participates.
    ChainAnchor {
        block_hash: [0x77; 32],
        block_height: 850_000,
    }
}

/// Header length for an INDEX snapshot-anchored v2 file: legacy header
/// (`header_size`) + 36-byte ChainAnchor trailer.
fn index_snapshot_header_len() -> usize {
    INDEX_PARAMS.header_size + pir_core::seeds::CHAIN_ANCHOR_BYTES
}

#[test]
fn index_snapshot_build_is_byte_reproducible() {
    let records = synthetic_index_records(FIXTURE_N);
    let s = SnapshotSeeds::derive(&anchor_a());
    let anchor = HeaderAnchor::Snapshot(anchor_a());

    let build1 = build_index_cuckoo_bytes(&records, s.index_master, s.index_tag, &anchor);
    let build2 = build_index_cuckoo_bytes(&records, s.index_master, s.index_tag, &anchor);

    assert_eq!(
        sha256_hex(&build1),
        sha256_hex(&build2),
        "two INDEX builds of the same fixture at the same anchor must be byte-identical"
    );
    assert_eq!(build1, build2);
    // Sanity: a non-trivial file (header + body), not an empty/degenerate build.
    assert!(build1.len() > index_snapshot_header_len() + INDEX_SLOT_SIZE * FIXTURE_N);
}

#[test]
fn chunk_snapshot_build_is_byte_reproducible() {
    let chunks = synthetic_chunks(FIXTURE_N);
    let s = SnapshotSeeds::derive(&anchor_a());
    let anchor = HeaderAnchor::Snapshot(anchor_a());

    let build1 = build_chunk_cuckoo_bytes(&chunks, s.chunk_master, &anchor);
    let build2 = build_chunk_cuckoo_bytes(&chunks, s.chunk_master, &anchor);

    assert_eq!(
        sha256_hex(&build1),
        sha256_hex(&build2),
        "two CHUNK builds of the same fixture at the same anchor must be byte-identical"
    );
    assert_eq!(build1, build2);
}

#[test]
fn index_delta_build_is_byte_reproducible() {
    // Exercise the delta-anchored header variant (72-byte trailer, delta
    // MAGIC) end-to-end through the same INDEX build path.
    let records = synthetic_index_records(FIXTURE_N);
    let danchor = DeltaAnchor { from: anchor_a(), to: anchor_b() };
    let s = DeltaSeeds::derive(&danchor);
    let anchor = HeaderAnchor::Delta(danchor);

    let build1 = build_index_cuckoo_bytes(&records, s.index_master, s.index_tag, &anchor);
    let build2 = build_index_cuckoo_bytes(&records, s.index_master, s.index_tag, &anchor);

    assert_eq!(sha256_hex(&build1), sha256_hex(&build2));
    assert_eq!(build1, build2);
}

#[test]
fn index_build_is_anchor_sensitive() {
    // Two snapshot anchors that differ only in block_hash. The group
    // assignment (and therefore bins_per_table and body length) is
    // seed-independent, so both bodies have identical length — but the
    // chain-derived master seed reshuffles slot placement, so the body
    // bytes MUST differ. A different fingerprint tag seed also changes
    // every populated slot's 8-byte tag.
    let records = synthetic_index_records(FIXTURE_N);

    let sa = SnapshotSeeds::derive(&anchor_a());
    let sb = SnapshotSeeds::derive(&anchor_b());
    assert_ne!(sa.index_master, sb.index_master, "anchors must derive distinct master seeds");
    assert_ne!(sa.index_tag, sb.index_tag, "anchors must derive distinct tag seeds");

    let build_a = build_index_cuckoo_bytes(&records, sa.index_master, sa.index_tag, &HeaderAnchor::Snapshot(anchor_a()));
    let build_b = build_index_cuckoo_bytes(&records, sb.index_master, sb.index_tag, &HeaderAnchor::Snapshot(anchor_b()));

    let hlen = index_snapshot_header_len();
    assert_eq!(build_a.len(), build_b.len(), "body length is seed-independent (depends only on group load)");
    assert_ne!(
        &build_a[hlen..],
        &build_b[hlen..],
        "different anchors must reshuffle the cuckoo body — otherwise the chain-derived seed is being ignored"
    );
}

#[test]
fn index_build_is_height_sensitive() {
    // Same block_hash, different height: height is part of the anchor and
    // must alter the derived seeds (and thus the body).
    let records = synthetic_index_records(FIXTURE_N);
    let a1 = anchor_a();
    let mut a2 = anchor_a();
    a2.block_height += 1;

    let s1 = SnapshotSeeds::derive(&a1);
    let s2 = SnapshotSeeds::derive(&a2);
    assert_ne!(s1.index_master, s2.index_master);

    let b1 = build_index_cuckoo_bytes(&records, s1.index_master, s1.index_tag, &HeaderAnchor::Snapshot(a1));
    let b2 = build_index_cuckoo_bytes(&records, s2.index_master, s2.index_tag, &HeaderAnchor::Snapshot(a2));

    let hlen = index_snapshot_header_len();
    assert_ne!(&b1[hlen..], &b2[hlen..], "block height must participate in the build");
}
