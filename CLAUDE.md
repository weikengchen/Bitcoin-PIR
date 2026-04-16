# BitcoinPIR Project Memory

## Project Overview
Bitcoin Private Information Retrieval (PIR) system with three backends: DPF-PIR, OnionPIR, HarmonyPIR. Supports full snapshots and delta synchronization for incremental updates.

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

### What the Server Learns (Documented Trade-offs)

The server **cannot** learn:
- Which specific groups contain real queries (due to padding)
- Which specific scripthash was queried

The server **can** observe (known trade-offs):
- Whether chunk/Merkle rounds occur (reveals found vs not-found)
- Roughly how many chunk rounds (reveals approximate UTXO count)
- Timing patterns across rounds

To fully hide found/not-found, the client would need to send dummy chunk and Merkle rounds even when no results were found. This is a documented privacy/efficiency trade-off.

---

## Recent Work: PIR SDK Implementation

### Completed
1. **pir-sdk/** - Core SDK crate with:
   - Database catalog types and sync planning (BFS delta chain, max 5 steps)
   - Delta merging logic
   - Hash function wrappers (splitmix64, cuckooHash, etc.)

2. **pir-sdk-wasm/** - WASM bindings for browser use:
   - `WasmDatabaseCatalog`, `WasmSyncPlan`, `WasmQueryResult` classes
   - `computeSyncPlan()`, `mergeDelta()`, `decodeDeltaData()` functions
   - Hash functions exposed to JS
   - Built with `wasm-pack build --target web`

3. **pir-sdk-client/** - Native Rust client. `DpfClient` is fully implemented
   (including per-bucket Merkle verification, see item 8 below). `HarmonyClient`
   and `OnionClient` are placeholders — see their module docs.

4. **pir-sdk-server/** - Server-side SDK placeholder

5. **Web SDK Integration**:
   - `web/src/sdk-bridge.ts` - Bridge with automatic fallback to TypeScript
   - `web/src/sync-controller.ts` - Now uses `computeSyncPlanSdk` from SDK
   - `web/index.html` - Calls `initSdkWasm()` at startup
   - `web/package.json` - Added `pir-sdk-wasm` dependency

6. **Merkle Verification for "Not Found" Results** (web TS clients, commit `60fe19c`):
   - All three **web TypeScript** PIR clients (DPF, OnionPIR, HarmonyPIR)
     track ALL bins checked.
   - For "not found", verifies ALL INDEX_CUCKOO_NUM_HASHES=2 positions.
   - Proves scripthash is truly absent from the database.
   - Enables Merkle verification of delta databases even when no activity.

7. **Human-Verifiable Audit Logging** (commit `9a693c5`):
   - `[PIR-AUDIT]` prefixed logs in web TS clients (DPF, OnionPIR, HarmonyPIR)
     and in the native Rust `DpfClient` (see item 8).
   - Logs show: query parameters, padding reminders, per-query FOUND/NOT FOUND
     status, bin indices, chunk IDs, Merkle verification details.
   - Enables humans to verify PIR operations are correct.

8. **Native Rust per-bucket Merkle verification (DPF + Harmony)**:
   - Module [`pir-sdk-client/src/merkle_verify.rs`](pir-sdk-client/src/merkle_verify.rs)
     implements the shared verifier: bin-leaf hash, K-padded sibling batches,
     tree-top parsing, full walk-to-root. 12 unit tests cover good proofs,
     tampered content, wrong bin index, encoding/decoding round-trips, and
     partial-cache walks against `pir-core::merkle`.
   - Backend-agnostic driver: a `BucketMerkleSiblingQuerier` trait abstracts
     one K-padded sibling-query round, with `DpfSiblingQuerier`
     (two-server DPF, `REQ_BUCKET_MERKLE_SIB_BATCH = 0x33`) and
     `HarmonySiblingQuerier` (single-server Harmony query,
     `REQ_HARMONY_BATCH_QUERY = 0x43` with `level = 10+L` INDEX or `20+L`
     CHUNK) both implementing it. `verify_bucket_merkle_batch_generic`
     drives the shared walk.
   - [`DpfClient`](pir-sdk-client/src/dpf.rs) and
     [`HarmonyClient`](pir-sdk-client/src/harmony.rs) now track every INDEX
     cuckoo bin they inspect (both `INDEX_CUCKOO_NUM_HASHES=2` positions for
     not-found, the matching position for found) and every CHUNK bin that
     returned a UTXO, then batch-verify them against the per-group root
     from the tree-top blob. Queries whose Merkle proof fails are coerced
     to `None`.
   - HarmonyPIR sibling groups and hints are lazily initialised per
     `(db_id, merkle_level)` — sibling-group count is derived from the
     server-supplied tree-tops (`cache_from_level`), and the sibling
     group's `derived_key` offset matches the server's
     `compute_hints_for_group` layout:
     * INDEX sib L, group g → `(k_index + k_chunk) + L*k_index + g`
     * CHUNK sib L, group g →
       `(k_index + k_chunk) + index_sib_levels*k_index + L*k_chunk + g`
   - Gated on `DatabaseInfo::has_bucket_merkle`. Padding (K=75 INDEX,
     K_CHUNK=80 CHUNK, 25 MERKLE) is preserved — see CLAUDE.md "Query Padding"
     section above.
   - Whales are deliberately not Merkle-verified (matches TS client behavior).
   - `OnionClient` Merkle verification is **not yet wired**. This is
     tracked as P0 work in [SDK_ROADMAP.md](SDK_ROADMAP.md). Until wired,
     OnionPIR results should be treated as unverified.

---

## SDK Roadmap

The full SDK work plan lives in [SDK_ROADMAP.md](SDK_ROADMAP.md) — P0
through P4 priorities, with in-progress items tracked at the bottom.
Consult it before starting new SDK work so nothing gets duplicated or
forgotten. Padding/privacy invariants (🔒 items in the roadmap) must
not be optimized away — see "Query Padding" above.

Short-term active work:
- **P0 #2 (next):** Merkle verification for `OnionClient`. Onion trace
  state already records both cuckoo positions; wiring is mechanical.
  Reference: web client's `web/src/onion-client.ts`.

### Completed milestones
- PIR SDK + WASM bindings + web integration (commit `19cbf5f`).
- Merkle verification for "not found" results in the web clients
  (commit `60fe19c`).
- `[PIR-AUDIT]` logging in web clients (commit `9a693c5`).
- Native Rust `HarmonyClient` + `OnionClient` un-stub (commit `f37db8f`).
- Native Rust `DpfClient` per-bucket Merkle verification (commit `8bd4b7b`).
- Native Rust `HarmonyClient` per-bucket Merkle verification via
  shared `BucketMerkleSiblingQuerier` trait (commit `6aee562`, P0 #1).

---

## Key Files
- `pir-sdk/src/lib.rs` - SDK entry point
- `pir-sdk-wasm/src/lib.rs` - WASM bindings
- `web/src/sdk-bridge.ts` - JS/TS bridge to WASM
- `web/src/sync-controller.ts` - Uses SDK for sync planning

## Build Commands
```bash
# Build SDK WASM
cd pir-sdk-wasm && wasm-pack build --target web --out-dir pkg

# Run web dev server
cd web && npm run dev

# Test SDK
cd pir-sdk && cargo test
```
