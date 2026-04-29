# BitcoinPIR Project Memory

## Project Overview
Bitcoin Private Information Retrieval (PIR) system with three backends:
DPF-PIR, OnionPIR, HarmonyPIR. Supports full snapshots and delta
synchronization for incremental updates.

---

## CRITICAL SECURITY REQUIREMENTS

### Query Padding (MANDATORY for Privacy)

**NEVER OPTIMIZE AWAY PADDING. The padding is INTENTIONAL and REQUIRED for privacy.**

Within each PIR round, queries are padded to FIXED counts:
- **INDEX queries**: Always K=75 groups (regardless of how many real queries)
- **CHUNK queries**: Always K_CHUNK=80 groups (regardless of how many real chunks)
- **MERKLE queries**: Always 25 sibling queries (regardless of proof depth)

**Why:** If the server sees varying numbers of queries, it can infer information about which groups contain real queries vs padding. By always sending exactly K queries, the server cannot distinguish real queries from dummy queries.

**How padding works:**
1. Real queries are placed in their computed cuckoo positions
2. Remaining empty groups get random DPF keys (dummy queries)
3. Server processes ALL groups identically, cannot tell which are real

### Cuckoo Hashing and "Not Found" Verification

Each scripthash maps to INDEX_CUCKOO_NUM_HASHES=2 possible cuckoo positions. To prove a scripthash is "not found", ALL positions must be checked and verified:
- Client checks position h=0, then h=1
- If neither contains the scripthash, it's definitively not in the database
- Merkle verification must cover ALL checked bins to prove "not found"

### Merkle INDEX Item-Count Symmetry (MANDATORY for Privacy)

**All four implementations MUST emit exactly `INDEX_CUCKOO_NUM_HASHES = 2`
Merkle items per INDEX query, regardless of query outcome (found at h=0,
found at h=1, not-found, or whale):**

- `pir-sdk-client/src/dpf.rs` (Rust DPF — also drives `web/src/dpf-adapter.ts` via WASM)
- `pir-sdk-client/src/harmony.rs` (Rust HarmonyPIR — also drives `web/src/harmonypir-adapter.ts` via WASM)
- `pir-sdk-client/src/onion.rs` (Rust OnionPIR, feature-gated)
- `web/src/onionpir_client.ts` (standalone TS — SEAL doesn't compile to wasm32)

The per-level sibling **pass count** (`max_items_per_group`) is directly
observable on the wire. If a found query emits 1 INDEX Merkle item and a
not-found query emits 2, the server can infer found-vs-not-found from
the batched sibling request size for every INDEX Merkle level. That
defeats the "chunk rounds reveal found/not-found" trade-off at the INDEX
level and leaks cuckoo-position (h=0 vs h=1) as well.

**Invariants clients must preserve:**
1. Both cuckoo positions are probed for every INDEX query — no early exit
   on match. (In DPF and Onion the extra probe is tracking-only since
   both bins are XOR'd from the same batch response; in Harmony it costs
   one extra wire round per found@h=0 query.)
2. The Merkle item builder iterates the full `all_index_bins` list
   unconditionally, emitting one `BucketMerkleItem` per probed bin.
3. Whales emit INDEX Merkle items from their probed bins too — the
   whale's INDEX entry (`num_chunks=0`) is committed to the INDEX Merkle
   root, so whale-exclusion is a verifiable property.
4. Chunk-level Merkle items attach only to the matched INDEX bin.
   CHUNK Merkle item counts still vary with UTXO count — that is a
   separate, documented trade-off (see "What the Server Learns" below).

### CHUNK Round-Presence Symmetry (MANDATORY for Privacy)

**Every INDEX query — found, not-found, or whale — MUST trigger at least
one K_CHUNK-padded CHUNK PIR round.** Skipping CHUNK rounds when the
INDEX returned no match leaks found-vs-not-found per query at the wire
level (the server simply observes whether any CHUNK traffic followed
the INDEX phase).

This invariant is enforced in:
- `pir-sdk-client/src/dpf.rs::query_single` — calls `query_chunk_level(&[], …)`
  for the not-found and whale paths; `query_chunk_level` upgrades an empty
  `chunk_ids` list to a single empty-round plan so the existing per-group
  random-alpha padding code emits a fully synthetic K_CHUNK-padded batch.
- `pir-sdk-client/src/harmony.rs::query_single` — same shape; the dummy
  round is dispatched via `run_chunk_round(db_id, &[], …)` which already
  takes the `build_synthetic_dummy` branch for every group when
  `real_queries` is empty.
- `pir-sdk-client/src/onion.rs::query_chunk_level` — adds one uniformly
  random dummy `entry_id` to the unique-fetch list for each not-found /
  whale query, keeping CHUNK round count proportional to batch size.
- `web/src/onionpir_client.ts::queryBatch` — same per-query dummy
  injection as the Rust OnionPIR client (uses `crypto.getRandomValues`).

**Invariants implementations must preserve:**
1. The padded round is byte-identical in shape to a real round on the
   wire (K_CHUNK groups, real or `build_synthetic_dummy` per group;
   indistinguishable to the server).
2. Dummy responses are decrypted but their bin contents are never
   surfaced to the caller — there is no `IndexResult` pointing at a
   dummy entry_id, so result-assembly skips it naturally.
3. **No CHUNK Merkle items are synthesised for the dummy round.** The
   residual leak from CHUNK Merkle item counts (count varies with
   UTXO count) is a separately tracked decision — see "What the
   Server Learns" below.
4. The dummy entry_id / chunk_id is generated from a fresh CSPRNG for
   each query so the same not-found scripthash queried twice picks
   different dummies (no correlation oracle).

### HarmonyPIR Per-Group Request-Count Symmetry (MANDATORY for Privacy)

**Every HarmonyPIR per-group query slot (INDEX, CHUNK, or sibling) MUST
send exactly `T − 1` sorted distinct u32 indices drawn from
`[0, real_n)`, regardless of segment state, query count, or round.**

Filtering `EMPTY` cells and sending only the surviving non-empty
indices leaks the per-group count. The count drifts upward as hints
get consumed and as cells fill via relocation — a server can fit the
trajectory, distinguish the real-query slot from padding dummies
every round, estimate queries-since-last-rehint, and predict when a
fresh offline phase is imminent.

Do NOT add any code path that emits fewer than `T − 1` indices, and
do NOT add a "skip if empty" early-exit.

The fix is implemented in `HarmonyGroup::build_request` /
`build_synthetic_dummy` (see `PLAN_HARMONY_COUNT_LEAK_FIX.md`) by
padding the shortfall with random distinct indices drawn from
`[0, real_n) \ R` and XOR-cancelling those dummy response entries in
`process_response` / `process_response_xor_only`. No wire-format or
server-side change is required.

### INDEX Merkle Group-Symmetry (MANDATORY for Privacy)

**INDEX Merkle items in a multi-query batch MUST be distributed
across PBC groups via `pbc_plan_rounds(derive_groups_3, K, 3, 500)`,
not hard-coupled to `derive_groups_3(scripthash, K)[0]`.**

Two scripthashes whose `derive_groups_3[0]` collide would, under the
old fixed-`[0]` placement, accumulate all four INDEX Merkle items in
one PBC group → the per-Merkle-level pass count would jump from 2 to
4. The wire-observable pass count is therefore a function of the
batch's collision pattern at the assigned-group level — a side
channel the server can fit to candidate scripthash sets.

**Why:** The PBC plan distributes scripthashes across distinct PBC
slots within a round. Each scripthash's INDEX query (and its two
INDEX Merkle items) inherits the planner-assigned group, so
`max_items_per_group_per_level = 2` independently of input collision
pattern. Wire round count per level becomes `2 × n_servers × n_levels
× n_pbc_rounds`; for typical batches with `N ≤ K`, `n_pbc_rounds = 1`.

**How implementations preserve this:**

1. **DPF** ([pir-sdk-client/src/dpf.rs](pir-sdk-client/src/dpf.rs)):
   `query_index_phase_batched` runs one or more K-padded DPF INDEX
   wire rounds per PBC round. Real placements use the planner-assigned
   group's cuckoo positions; remaining groups send random dummies.
2. **HarmonyPIR** ([pir-sdk-client/src/harmony.rs](pir-sdk-client/src/harmony.rs)):
   `query_index_phase_batched` runs `INDEX_CUCKOO_NUM_HASHES = 2`
   wire rounds per PBC round (one per cuckoo position). Each placed
   group sends `build_request(target_bin)`; remaining groups send
   `build_synthetic_dummy()`.
3. **OnionPIR** ([pir-sdk-client/src/onion.rs](pir-sdk-client/src/onion.rs)):
   already uses `pbc_plan_rounds` over INDEX queries, plus a separate
   gid-level PBC plan at the Merkle layer with ARITY=120 — at batch=2
   the axis is structurally trivial regardless of placement (`pbc_plan_rounds`
   over ≤4 unique gids always packs into 1 round).

**Server-side compatibility:** the build script replicates each
scripthash's INDEX entry to all 3 candidate groups
([build/src/build_cuckoo_generic.rs:87-90](build/src/build_cuckoo_generic.rs:87)
and [build/src/gen_4_build_merkle.rs:236-239](build/src/gen_4_build_merkle.rs:236)),
so any candidate group can serve the query. No server changes were
required.

**Empirical witnesses (against `wss://pir1.chenweikeng.com`):**
- `dpf_simulator_property_multi_query_collision`: A=B=C=19 rounds,
  IndexMerkleSiblings A=B=C=12. Pre-closure: A=33 / C=21.
- `harmony_simulator_property_multi_query_collision`: A=B=C=20 rounds,
  IndexMerkleSiblings A=B=C=6. Pre-closure: A=28 / C=22.
- `onion_simulator_property_multi_query_collision`: A=B=C=7 rounds,
  IndexMerkleSiblings A=B=C=1 (structurally trivial pre- and post-).

### What the Server Learns (Documented Trade-offs)

The server **cannot** learn:
- Which specific groups contain real queries (due to padding)
- Which specific scripthash was queried
- Whether a query was found or not-found at the INDEX Merkle level
  (closed by the item-count symmetry invariant above)
- Whether a query was found or not-found from CHUNK round presence
  (closed by the CHUNK Round-Presence Symmetry invariant above)
- Which cuckoo position (h=0 vs h=1) a found query matched at
- The collision pattern of `derive_groups_3[0]` across a multi-query
  batch (closed by the INDEX Merkle Group-Symmetry invariant above)

The server **can** observe (known trade-offs):
- How many CHUNK Merkle items each query contributes (reveals
  approximate UTXO count for found queries; a not-found query
  contributes zero CHUNK Merkle items today). Closing this requires
  per-query item-count padding to a fixed `M`, separately tracked.
- Timing patterns across rounds.

To also hide approximate UTXO count, the client would need to pad
CHUNK Merkle item counts to a fixed `M` per query (forcing both
not-found queries and small-found queries to emit the same number
of items as a near-whale found query). This is a separate, more
expensive privacy/efficiency trade-off.

---

## SDK Layout

### Crates
- `pir-core` — shared primitives (Merkle N-ary, cuckoo, DPF, PBC, hashes).
- `pir-sdk` — high-level types, sync planning (`SyncPlanner`),
  `PirMetrics` observer trait + `AtomicMetrics` recorder, error taxonomy
  (`PirError` + `ErrorKind`).
- `pir-sdk-client` — native + wasm32 Rust client. Backends: `DpfClient`,
  `HarmonyClient`, `OnionClient` (feature-gated `onion`). Transport
  abstraction (`PirTransport` + `WsConnection` native /
  `WasmWebSocketTransport` wasm32 / `MockTransport` tests). Per-bucket
  Merkle verification + OnionPIR per-bin Merkle verification.
- `pir-sdk-server` — thin server wrapper over `pir-runtime-core`
  (`PirServerBuilder`, `PirServer`, `ServerConfig`, `DatabaseLoader`,
  `simple_server` binary). ~680 LOC, 0 lib tests.
- `pir-sdk-wasm` — WASM bindings (`WasmDpfClient`, `WasmHarmonyClient`,
  `WasmBucketMerkleTreeTops` verifier, `WasmAtomicMetrics`,
  `initTracingSubscriber()`). No `WasmOnionClient` — SEAL doesn't compile
  to wasm32.
- `pir-runtime-core` — shared server primitives (protocol, table, eval,
  handler). Extracted from `runtime/` as a publishable lib crate.
- `runtime/`, `build/`, `block_reader/`, `harmonypir-wasm/` — internal
  binary crates (`publish = false`).

### Web integration
- `web/src/sdk-bridge.ts` — JS/TS bridge to the wasm-pack output.
- `web/src/dpf-adapter.ts` — legacy-shape adapter over `WasmDpfClient`.
- `web/src/harmonypir_client.ts` — adapter over `WasmHarmonyClient`.
- `web/src/onionpir_client.ts` — hand-rolled TS (stays indefinitely;
  SEAL doesn't compile to wasm32).
- `web/src/sync-controller.ts` — drives sync via SDK.
- `web/src/types.ts` — neutral types shared across clients.

### Observability
- Phase 1 (`#[tracing::instrument]` spans with consistent `backend=` field).
- Phase 2 (`PirMetrics` trait, `AtomicMetrics` recorder, per-transport
  byte / connect / disconnect callbacks, per-client query start/end).
- Phase 2+ (per-client latency histograms, per-frame roundtrip latency,
  `WasmAtomicMetrics` JS bridge, `tracing-wasm` browser subscriber).

---

## Remaining open work

- **Publishing Blocker 1** ([PUBLISHING.md](PUBLISHING.md)): `libdpf` +
  `harmonypir` are git deps. They need to land on crates.io (with
  pinned revs) or be vendored into `pir-core` before the five
  publishable crates (`pir-core`, `pir-sdk`, `pir-runtime-core`,
  `pir-sdk-client`, `pir-sdk-server`) + the `pir-sdk-wasm` npm package
  can ship.
- **`pir-sdk-server` polish**: 0 lib tests today, no observability
  wiring (server-side `PirMetrics` parity), no rate limiting, no auth.

SDK_ROADMAP.md + PLAN_MERKLE_ARITY.md + PLAN_INDEX_BUCKET_SIZE_4.md +
YPIR_*_PLAN.md were deleted 2026-04-19 — all superseded or rejected.

---

## Key Files

- `pir-sdk/src/lib.rs`, `pir-sdk/src/error.rs`, `pir-sdk/src/metrics.rs`,
  `pir-sdk/src/sync.rs`.
- `pir-sdk-client/src/`: `dpf.rs`, `harmony.rs`, `onion.rs`,
  `transport.rs`, `connection.rs`, `wasm_transport.rs`,
  `merkle_verify.rs`, `onion_merkle.rs`, `hint_cache.rs`, `protocol.rs`.
- `pir-sdk-wasm/src/`: `lib.rs`, `client.rs`, `merkle_verify.rs`,
  `metrics.rs`, `tracing_bridge.rs`.
- `pir-sdk-server/src/`: `server.rs`, `loader.rs`, `config.rs`.
- `pir-runtime-core/src/`: `protocol.rs`, `table.rs`, `eval.rs`,
  `handler.rs`.
- `web/src/`: `sdk-bridge.ts`, `dpf-adapter.ts`, `types.ts`,
  `sync-controller.ts`.

## Build Commands
```bash
# Build SDK WASM
cd pir-sdk-wasm && wasm-pack build --target web --out-dir pkg

# Run web dev server
cd web && npm run dev

# Test SDK
cargo test -p pir-sdk --lib
cargo test -p pir-sdk-client --lib
cargo test -p pir-sdk-client --features onion --lib
cargo test -p pir-sdk-wasm --lib
```
