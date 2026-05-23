# Build reproducibility

This document captures BitcoinPIR's stance on **byte-deterministic database
builds across operators**, the threat that motivates it, and the staged
plan to make every PRG seed in the build pipeline derive verifiably from
the underlying Bitcoin chain.

## Status

The build pipeline is **byte-deterministic today, but only if every
operator runs the same release binary**:

- `bitcoind dumptxoutset` is byte-deterministic at a given block hash.
  The UTXO set has a fixed serialization order and Bitcoin Core's
  `muhash` is a public commitment to the snapshot contents.
- The build pipeline introduces **no system randomness**:
  no `OsRng`, no `thread_rng`, no `SystemTime` seeding anywhere in
  `build/src/` or `pir-core/src/`. All `Instant::now()` calls are
  timing logs only.
- All PRG seeds flow from three hardcoded constants in source:

  | Constant | Value | Purpose |
  | --- | --- | --- |
  | `INDEX_PARAMS.master_seed` | `0x71a2ef38b4c90d15` | INDEX cuckoo hash families |
  | `CHUNK_PARAMS.master_seed` | `0xa3f7c2d918e4b065` | CHUNK cuckoo hash families |
  | `TAG_SEED` | `0xd4e5f6a7b8c91023` | INDEX entry fingerprint tags |

  The constants are written into each cuckoo file header so a client
  can read them back at runtime — meaning the *bytes themselves* are
  not security-critical, only their *provenance* is, if the threat
  model includes adversarial seed selection.

## Threat model

The current design assumes the seed values are chosen honestly. A
build maintainer who could choose the seed values **before** the chain
state was fixed could mount adversarial seed-shopping attacks:

- Pick `INDEX_PARAMS.master_seed` so that a target set of
  surveillance scripthashes lands in pathological cuckoo configurations
  (e.g., all collide into the same INDEX bin), enabling timing or
  result-size side channels.
- Pick `TAG_SEED` so that fingerprint tags of two target scripthashes
  collide, defeating the tag's collision-check role.

Chain-derived seeds defeat this: a seed of the form

```
seed = derive_seed_u64(domain, ChainAnchor { block_hash, block_height })
```

cannot be biased toward an adversary's targets because the adversary
does not control `block_hash` — the chain produces it.

## Design

The centralized seed-derivation API lives in
[`pir-core/src/seeds.rs`](../pir-core/src/seeds.rs).

### Chain anchor types

```rust
pub struct ChainAnchor {
    pub block_hash: [u8; 32],   // bitcoin-cli dumptxoutset block hash
    pub block_height: u32,      // height at the snapshot anchor
}

pub struct DeltaAnchor {
    pub from: ChainAnchor,      // snapshot the delta applies to
    pub to: ChainAnchor,        // chain tip after applying the delta
}
```

Both `block_hash` **and** `block_height` participate in seed derivation,
so a build cannot be replayed with the same seeds under a mismatched
height even if an attacker fixed the hash.

### Tagged-hash derivation

Domain separation uses Bitcoin BIP-340-style tagged hashes:

```
tag_hash       = SHA256("BitcoinPIR/seed/v1/" || domain)
seed_bytes_32  = SHA256(tag_hash || tag_hash || ctx.absorb_bytes())
seed_u64       = LE-decode(seed_bytes_32[0..8])
```

Where `ctx.absorb_bytes()` is determined by the `SeedContext`
implementation:

- `ChainAnchor` absorbs `b"snapshot/" || height_le4 || block_hash`.
- `DeltaAnchor` absorbs
  `b"delta/" || from_height_le4 || from_hash || to_height_le4 || to_hash`.

The leading per-context tag (`b"snapshot/"` vs `b"delta/"`) means a
snapshot seed and a delta seed differ even when the chain hashes /
heights coincide.

### Canonical domain identifiers

```rust
pub mod domain {
    pub const INDEX_CUCKOO_MASTER: &str       = "index/cuckoo/master";
    pub const CHUNK_CUCKOO_MASTER: &str       = "chunk/cuckoo/master";
    pub const INDEX_TAG_FINGERPRINT: &str     = "index/tag/fingerprint";
    pub const MERKLE_DATA_CUCKOO_MASTER: &str = "merkle/data/cuckoo/master";
}
```

Per-protocol overrides (e.g., a hypothetical `onion/index/cuckoo/master`
with a different cuckoo layout) can be added without changing the
derivation rule — they just use a different domain string.

### Why u64 seeds, not 32-byte seeds

The existing PRG layer (`splitmix64`-based `derive_cuckoo_key`,
`compute_tag`) consumes 64-bit master seeds. Keeping that interface
unchanged means the rest of the codebase needs no surgery — the only
change is *how* the 64-bit seed is constructed at build time.

`derive_seed_32` is provided for future uses that genuinely need
more entropy (e.g., future FHE-layer pre-randomization).

## Implementation roadmap

### Phase A — landed

- [x] `pir-core/src/seeds.rs` with `ChainAnchor`, `DeltaAnchor`,
      `derive_seed_u64`, `derive_seed_32`, domain constants,
      `SnapshotSeeds` / `DeltaSeeds` derive helpers.
- [x] Unit tests covering determinism, domain separation, height
      sensitivity, hash sensitivity, snapshot-vs-delta separation.
- [x] This design document.

### Phase B — landed

- [x] **Seed I/O helpers** in `pir-core::seeds`:
      `ChainAnchor::{to_bytes, from_bytes, save, load, load_from_data_dir}`
      (36 bytes on disk: `block_hash || height_le4`),
      `DeltaAnchor::*` (72 bytes: `from || to`), and a polymorphic
      [`AnchorSeeds`] enum that loads either kind by length.
- [x] **`TableParams::with_master_seed`** const builder so build sites
      can overlay a chain-derived seed on top of the layout-only
      `INDEX_PARAMS` / `CHUNK_PARAMS` constants.
- [x] **`gen_0_utxo_set`** accepts `--anchor-height <H>`; writes
      `<data_dir>/chain_anchor.bin` using `dump.block_hash` + the
      operator-supplied height.
- [x] **`build_cuckoo_generic`** accepts `--anchor <path>` (snapshot
      or delta, length-discriminated). Falls back to legacy hardcoded
      seeds with a stderr warning when absent.
- [x] **`gen_2_onion` + `gen_3_onion`** accept `--anchor <path>` or
      auto-detect `<data_dir>/chain_anchor.bin` /
      `<data_dir>/delta_anchor.bin`. Seeds resolved via a
      `OnceLock<u64>` cell initialised once at the top of `main`.
- [x] **`delta_gen_0`** accepts `--to-block-hash <hex>`; writes
      `delta_anchor_<A>_<B>.bin` (72 bytes) when supplied.
- [x] **`scripts/build_full.sh` + `scripts/build_delta.sh`** pass the
      new flags through. Backward compatible — runs without the
      anchor still work, just with the legacy-fallback warning.

### Phase C — landed

- [x] **Header extension** *(backward-compatible wire-format change)*.
      [pir-core/src/cuckoo.rs](../pir-core/src/cuckoo.rs) gains
      `HeaderAnchor` enum, `write_header_with_anchor`,
      `read_cuckoo_header_with_anchor`, `verify_anchor_seeds`. v2
      MAGIC is the legacy MAGIC XOR'd with a 1-byte marker
      (`ANCHOR_MAGIC_SNAPSHOT_XOR = 0x0000_0001_0000_0000`,
      `ANCHOR_MAGIC_DELTA_XOR = 0x0000_0002_0000_0000`). Anchor bytes
      (36 snapshot / 72 delta) are appended after the legacy header.
- [x] **Build sites emit v2 MAGIC when `--anchor` is supplied.**
      [build/src/build_cuckoo_generic.rs](../build/src/build_cuckoo_generic.rs)
      switched to `write_header_with_anchor`. Anchor-less builds remain
      byte-identical to legacy.
- [x] **Readers accept both legacy and v2 MAGIC.**
      [build/src/common.rs](../build/src/common.rs)::`read_cuckoo_header`/`read_chunk_cuckoo_header`
      and [pir-runtime-core/src/table.rs](../pir-runtime-core/src/table.rs)
      delegate to `read_cuckoo_header_with_anchor`. Server can load
      both old and new databases without changes.
- [x] **6 unit tests in [pir-core::cuckoo::tests]**: snapshot + delta
      roundtrip, legacy passthrough (byte-identical), mismatched seed
      rejection, unknown magic rejection, truncated anchor rejection.
- [x] **Legacy seed wrappers in `pir-core::hash` deleted** —
      `derive_groups_legacy`, `derive_cuckoo_key_legacy`,
      `derive_chunk_groups_legacy`, `derive_chunk_cuckoo_key_legacy`
      and the `test_legacy_compat` test.
- [x] **`doc/DEPLOYMENT.md` updated** with the operator workflow
      ("Reproducible database builds (Phase B / C)" section).

### Phase C2 — landed

- **OnionPIR custom file headers carry the anchor.**
  [build/src/gen_2_onion.rs](../build/src/gen_2_onion.rs) (chunk cuckoo,
  `0xBA7C_0010_0000_0001`) and [build/src/gen_3_onion.rs](../build/src/gen_3_onion.rs)
  (index meta, `0xBA7C_0010_0000_0002`) XOR the same snapshot/delta
  marker into their bespoke magics and append the 36/72-byte anchor.
  [runtime/src/bin/unified_server.rs](../runtime/src/bin/unified_server.rs)
  `read_onion_chunk_header` / `read_onion_index_meta` accept legacy + v2
  via a shared `check_onion_magic` helper.
- **Diagnostic binaries migrated off const seeds.** `build/common.rs`
  legacy `derive_cuckoo_key` / `derive_chunk_cuckoo_key` wrappers
  deleted; the ~7 diagnostic binaries read `header.master_seed` via the
  new `read_cuckoo_header_full` / `read_chunk_cuckoo_header_full`.
  `INDEX_PARAMS.master_seed` / `CHUNK_PARAMS.master_seed` zeroed to a
  sentinel in `params.rs`.

### Phase C3 — landed

- **Server-side self-verification on load.**
  [pir-runtime-core/src/table.rs](../pir-runtime-core/src/table.rs)
  `MappedSubTable` now surfaces the header's `master_seed` + `anchor`;
  `MappedDatabase::load` calls `verify_anchor_consistency` on the INDEX
  and CHUNK tables — recomputing the seeds from the embedded anchor and
  **panicking (refusing to serve)** on mismatch — plus an INDEX/CHUNK
  anchor-equality guard. No-op for legacy (anchor-less) databases.
  This proves *internal consistency* (catches build bugs / corruption /
  tampering); it does **not** by itself defeat a malicious operator who
  fabricates a matching anchor+seed pair — that needs the client check
  below.

### Remaining

1. **Client-side verification wiring.** Clients (`pir-sdk-client`,
   `pir-sdk-wasm`, the standalone TS OnionPIR client) still trust the
   header seed. They should read the anchor from the v2 header (or the
   attest response) and `verify_anchor_seeds(&header, domain, tag_domain)`,
   refusing to query on mismatch. **Trust model (per project owner):**
   the seed is a deterministic function of the anchor block-header hash,
   so a client that can *see the block hash used* can recompute the seed
   and confirm it matches; how the client independently confirms that
   block hash is left open (Bitcoin light client, baked-in pin,
   attestation `REPORT_DATA`, or multi-operator quorum — many viable
   paths). The verifier code is trivial; the anchor-delivery channel is
   the remaining design choice.
2. **CI cross-build check.** GitHub Actions workflow that runs
   `./scripts/build_full.sh <snapshot> <height>` twice on clean
   checkouts at the same `<height>`, then `sha256sum`-compares the
   output cuckoo files. Deferred until first multi-operator deployment.
3. **HarmonyPIR keys not affected** — query-time, client-derived;
   no build-side seed.

## Merkle tables — exempt from chain-derivation (resolved)

The **active** Merkle schemes carry **no separate placement seed** to
chain-derive:

- **DPF / HarmonyPIR** use per-bucket bin Merkle
  (`gen_4_build_merkle_bucket` → `merkle_bucket_builder.rs`). Its output
  header writes `master_seed = 0`; it simply hashes the *already-placed*
  cuckoo bins, so it transparently inherits the chain-derived INDEX/CHUNK
  cuckoo seed. (`merkle_bucket_builder` was updated to read the v2
  cuckoo headers so per-bucket Merkle builds on chain-anchored DBs.)
- **OnionPIR** uses per-group Merkle (`gen_4_build_merkle_onion`),
  likewise content-addressed.

The only fixed Merkle seed (`0xBA7C_51B1_… + level`) lived in the
**legacy N-ary tree Merkle** (`merkle_builder.rs` / `gen_4_build_merkle_dpf`
/ `test_merkle_verify*`), which the active pipeline never built. Those
builders were **removed** rather than chain-derived. The inert
server/protocol/reference-client N-ary load+verify path (opcodes
`0x31`/`0x32`, the `MappedDatabase.merkle_*` fields) is slated for
removal in a focused follow-up; it is cleanly separated from the live
per-bucket path (opcodes `0x33`/`0x34`).

**Onion anchor coverage** is complete: `onion_index_meta.bin` +
`onion_chunk_cuckoo.bin` + `onion_index_all.bin` all embed the anchor,
and the server self-verifies the onion seeds against it on load.

## Wire format extension (Phase C)

For Phase C, each cuckoo file header gains the 36-byte chain anchor
at a stable offset *before* the master_seed. The proposed layout for
the INDEX header:

```
Offset  Size  Field             Old?  Notes
   0     8    magic              ✓    bump to ...0005 to gate format
   8     8    (header version)   ✓
  16     4    bins_per_table     ✓
  20     4    (reserved)         ✓
  24     8    (reserved)         ✓
  32     8    master_seed        ✓    now = derive_seed_u64(domain::INDEX_CUCKOO_MASTER, &anchor)
  40     8    tag_seed           ✓    now = derive_seed_u64(domain::INDEX_TAG_FINGERPRINT, &anchor)
  48    32    block_hash         NEW
  80     4    block_height       NEW
  84     0    -- header end                     (header_size: 40 → 84)
```

CHUNK header (header_size 32 → 76) gets `block_hash || block_height`
appended past `master_seed` similarly. Deltas use a 72-byte anchor
block (from + to) appended instead.

**Migration:**

- Every production database must be rebuilt at a clean anchor.
- Every deployed client must accept the new MAGIC and verify the
  derived seed against the header's `master_seed`.
- The build script bumps the on-disk MANIFEST version too.
- Schedule this with a maintenance window — coordinate the server
  + WASM client release simultaneously.

## Operator workflow (Phase B, today)

```
# Snapshot build
bitcoin-cli dumptxoutset /tmp/utxo_948454.dat
./scripts/build_full.sh /tmp/utxo_948454.dat 948454
# (gen_0 picks up --anchor-height 948454; chain_anchor.bin propagates
#  to every cuckoo-building stage)

# Delta build
./target/release/delta_gen_0 utxo_948454.dat /Volumes/Bitcoin/bitcoin \
    948454 950000 --to-block-hash $(bitcoin-cli getblockhash 950000)
./scripts/build_delta.sh 948454 950000
# (delta_anchor_948454_950000.bin auto-detected by build_delta.sh)
```

Without the `--anchor-height` / `--to-block-hash` flags the build
still succeeds, but each cuckoo binary prints a stderr warning
("WARNING: no --anchor supplied; using LEGACY hardcoded seeds") and
the resulting databases are not byte-reproducible across operators.

## Verification (post-Phase B)

A third party can verify that a server's database was honestly built
at a claimed `(block_hash, block_height)` anchor by:

1. Reading the chain anchor from each cuckoo file header.
2. Recomputing each `master_seed` / `tag_seed` via
   `pir_core::seeds::derive_seed_u64(domain::*, &anchor)`.
3. Asserting the recomputed seeds equal the seeds embedded in the
   file header.
4. (Optional) Re-running the full build at that anchor and
   byte-comparing the cuckoo files.

Steps 1–3 are cheap and can be done by every client on every
connection. Step 4 is expensive but the gold-standard check operators
should run periodically against peers.

## Open questions

- **Should anchor height come from the operator or from the chain?**
  Currently the `txoutset` crate exposes only per-UTXO heights, not
  the snapshot's anchor height. The operator must supply it via CLI.
  An alternative is to fetch the height from a local Bitcoin Core
  RPC given the block hash, but that adds a dependency on a running
  node *during the build* rather than just *before* it.
- **Should the chain anchor also commit to the dust filter threshold,
  PBC `K`, slots-per-bin, etc.?** These are also "build parameters"
  that affect on-disk layout. The pragmatic answer is to put them in
  a build manifest alongside the chain anchor, signed/hashed together,
  so a verifier checks the whole tuple. Out of scope for Phase A.
