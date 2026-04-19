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

**All five clients (TS DPF/Onion/Harmony, Rust DPF/Harmony) MUST emit exactly
`INDEX_CUCKOO_NUM_HASHES = 2` Merkle items per INDEX query, regardless of
query outcome (found at h=0, found at h=1, not-found, or whale).**

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

### What the Server Learns (Documented Trade-offs)

The server **cannot** learn:
- Which specific groups contain real queries (due to padding)
- Which specific scripthash was queried
- Whether a query was found or not-found at the INDEX Merkle level
  (closed by the item-count symmetry invariant above)
- Which cuckoo position (h=0 vs h=1) a found query matched at

The server **can** observe (known trade-offs):
- Whether CHUNK rounds occur (reveals found vs not-found for non-whale
  queries — chunk rounds are skipped entirely when no INDEX match)
- Whether CHUNK Merkle rounds occur, and how many CHUNK Merkle items
  (reveals approximate UTXO count for found queries)
- Timing patterns across rounds

To fully hide found/not-found, the client would need to send dummy chunk
and chunk-Merkle rounds even when no results were found. This is a
documented privacy/efficiency trade-off that is distinct from — and
strictly weaker than — the INDEX-Merkle leak closed above.

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
