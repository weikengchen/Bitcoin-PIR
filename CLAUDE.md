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

8. **Native Rust per-bucket Merkle verification (DPF only)**:
   - New module [`pir-sdk-client/src/merkle_verify.rs`](pir-sdk-client/src/merkle_verify.rs)
     implements the shared verifier: bin-leaf hash, K-padded DPF sibling batches,
     tree-top parsing, full walk-to-root. 12 unit tests cover good proofs,
     tampered content, wrong bin index, encoding/decoding round-trips, and
     partial-cache walks against `pir-core::merkle`.
   - [`DpfClient`](pir-sdk-client/src/dpf.rs) now tracks every INDEX cuckoo bin
     it inspects (both `INDEX_CUCKOO_NUM_HASHES=2` positions for not-found,
     the matching position for found) and every CHUNK bin that returned a
     UTXO, then batch-verifies them via
     `run_merkle_verification` against the per-group root from the tree-top
     blob. Queries whose Merkle proof fails are coerced to `None`.
   - Gated on `DatabaseInfo::has_bucket_merkle`. Padding (K=75 INDEX,
     K_CHUNK=80 CHUNK, 25 MERKLE) is preserved — see CLAUDE.md "Query Padding"
     section above.
   - Whales are deliberately not Merkle-verified (matches TS client behavior).
   - `HarmonyClient` and `OnionClient` remain placeholders: since they issue
     no real PIR queries, there are no bins to Merkle-verify. Their module
     docs reference `DpfClient::run_merkle_verification` as the pattern to
     copy once queries land.

---

## Next TODOs

### If GitHub Actions SUCCEEDS:
1. **Test in browser**: Open the deployed web app, check DevTools console for `[PIR] SDK WASM loaded`
2. **Run a sync**: Connect to servers, enter a scriptPubKey, click Sync - verify sync planning works
3. **Migrate more functions to SDK**: 
   - Wire up SDK hash functions (`sdkComputeTag`, `sdkDeriveGroups`, etc.) in actual query flow
   - Move delta merging to SDK (`mergeDelta` WASM function)
4. **Rust client integration**: Have the Rust CLI client use `pir-sdk` for sync planning

### If GitHub Actions FAILS:
1. **Check build logs**: Look for WASM compilation errors in `pir-sdk-wasm`
2. **Common issues**:
   - Missing `wasm-pack` in CI - may need to add installation step
   - WASM target not installed - `rustup target add wasm32-unknown-unknown`
   - Cargo.toml workspace issues - ensure `pir-sdk-wasm` is in workspace members
3. **Web bundle issues**: Vite may fail if pir-sdk-wasm/pkg doesn't exist at build time
4. **Fix and re-push**: Address errors and push again

### Future Enhancements:
- [ ] Add SDK hash function verification tests (compare WASM vs TS outputs)
- [ ] Move PBC (cuckoo placement) logic to SDK for all backends
- [ ] Add Merkle verification to SDK
- [ ] Create SDK documentation with examples
- [ ] Publish pir-sdk-wasm to npm

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
