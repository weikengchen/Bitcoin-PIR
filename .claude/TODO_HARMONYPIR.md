# HarmonyPIR Integration — Status & TODOs

**Last updated**: 2026-03-26
**Latest commit**: `2d7e2a9` — Fix worker loading: inline JS code instead of fetching TS file

## What's Done ✅

### Core Protocol
- [x] `harmonypir-wasm/` — Full WASM client with 3 PRP backends (Hoang, FastPRP, ALF)
- [x] Sorted non-empty query optimization (~50% request size reduction)
- [x] `build_synthetic_dummy()` for privacy-preserving fake queries
- [x] Batch protocol: `HarmonyBatchQuery/Result` wire types with encode/decode
- [x] Server batch handler with rayon parallelism (`runtime/src/bin/server.rs`)
- [x] Hint server with streaming (`runtime/src/bin/harmonypir_hint_server.rs`)
- [x] Hint server uses `batch_forward()` (not sequential `locate()`) — 10-25× faster
- [x] PRP backend selection passed from client → hint server → correct PRP dispatch
- [x] `default = ["fastprp", "alf"]` in runtime Cargo.toml — always compiled in

### Web Client
- [x] Third tab "2-Server HarmonyPIR" in `web/index.html`
- [x] PRP backend selector (Hoang/FastPRP/ALF) with separate WASM builds
- [x] Offline hint download with unified 0-100% progress bar (155 buckets)
- [x] `queryBatch()` with always-2-rounds per hash function, fake queries for found entries
- [x] `planRounds()` + `cuckooPlace()` matching DPF-PIR batch structure
- [x] Varint-based UTXO decoder matching DPF-PIR format
- [x] Detailed timing logs: build/net/proc per round
- [x] Localhost/Remote toggle button for all 3 tabs
- [x] Double-connect prevention
- [x] Web Workers (4 workers, inlined JS blob, Transferable ArrayBuffers)
- [x] ALF WASM SIMD — rebuilt with `RUSTFLAGS='-C target-feature=+simd128'`

### E2E Tests (Rust)
- [x] `harmonypir_e2e_test` — synthetic DB, all 3 PRP backends
- [x] `harmonypir_real_test` — per-bucket narrative on real INDEX + CHUNK tables
- [x] `harmonypir_index_to_chunk_e2e` — full INDEX→CHUNK pipeline
- [x] `harmonypir_full_e2e` — all 75 INDEX + 80 CHUNK buckets
- [x] `harmonypir_batch_e2e` — batch wire protocol round-trip
- [x] `harmonypir_batch_trace` — verbose multi-address trace with ground truth
- [x] `harmonypir_hint_bench` — parallel hint generation benchmark (ALF/FastPRP/Hoang)

## TODOs / Known Issues 🔧

### High Priority
- [ ] **Test Web Workers end-to-end in browser** — Workers were just implemented, need real browser testing. Check:
  - Workers initialize correctly (WASM loads in each)
  - Hints are distributed to correct workers
  - `buildBatchRequests` / `processBatchResponses` return correct data
  - Timing improvement (~4× expected)
  - Fallback to single-threaded if Workers unavailable

- [ ] **FastPRP WASM SIMD** — Asked FastPRP agent to add `core::arch::wasm32` SIMD AES backend (like ALF did). When done:
  1. Rebuild: `RUSTFLAGS='-C target-feature=+simd128' wasm-pack build --target no-modules --release -- --features "fastprp"`
  2. Deploy to `web/public/wasm/harmonypir-fastprp/`
  3. Expected ~2-4× speedup for FastPRP in browser

### Medium Priority
- [ ] **Dummy query distribution matching** — `build_synthetic_dummy()` uses Binomial(T, 0.5) for count, which is statistically correct but needs formal privacy analysis. The user marked this as a TODO — need to verify the math matches the paper's distribution exactly.

- [ ] **Hint budget management** — When hints run out (`max_queries` per bucket exhausted), the client should prompt for re-download. Currently no UI for this.

- [ ] **State persistence** — HarmonyBucket supports `serialize()`/`deserialize()`. Could save state to IndexedDB so hints survive page refresh. Not implemented in web client yet.

- [ ] **Multi-chunk addresses** — Addresses with `num_chunks > 1` require multiple CHUNK queries. The batch logic handles this but hasn't been extensively tested with high-chunk-count addresses.

### Low Priority / Future
- [ ] **Hoang/FastPRP WASM SIMD** — The `aes` crate doesn't support WASM SIMD. Options: (a) recommend ALF for browser use, (b) switch to ALF's SIMD layer for AES, (c) fork `aes` crate.

- [ ] **Worker count auto-tuning** — Currently hardcoded to `min(hardwareConcurrency, 4)`. Could benchmark and pick optimal count.

- [ ] **Streaming batch responses** — Currently the entire batch response is one WebSocket message. Could chunk it for better perceived latency.

## Architecture Reference

```
Hint Server (port 8094)          Query Server (port 8095)
─────────────────────            ─────────────────────────
harmonypir_hint_server.rs        server.rs (shared with DPF)
  - Computes hints via            - handle_harmony_batch_query()
    batch_forward() + XOR         - Rayon parallel bucket lookup
  - Streams per-bucket            - Returns entries from mmap'd tables
  - PRP dispatch: Hoang/
    FastPRP/ALF

Web Client (harmonypir_client.ts)
───────────────────────────────────
  Main thread:
    - planRounds() + cuckooPlace()
    - WebSocket send/receive
    - encodeHarmonyBatchRequest / decodeHarmonyBatchResponse
    - findTagInBin / findChunkInBin / decodeUtxos

  Worker pool (4 workers):
    - Each worker: own WASM instance + ~39 HarmonyBucket instances
    - buildBatchRequests() → parallel build_request/build_dummy
    - processBatchResponses() → parallel process_response + relocation
```

## Key Files

| File | Purpose |
|------|---------|
| `harmonypir-wasm/src/lib.rs` | WASM client: HarmonyBucket, PRP dispatch, serialize |
| `harmonypir-wasm/src/state.rs` | State file format |
| `runtime/src/protocol.rs` | Wire protocol types + encode/decode |
| `runtime/src/bin/server.rs` | Query Server (DPF + HarmonyPIR) |
| `runtime/src/bin/harmonypir_hint_server.rs` | Hint Server |
| `web/src/harmonypir_client.ts` | Web client class |
| `web/src/harmonypir_worker.ts` | Worker entry (TS reference, inlined as JS) |
| `web/src/harmonypir_worker_pool.ts` | Worker pool manager |
| `web/index.html` | UI: tab, buttons, progress bars, JS wiring |
| `web/public/wasm/harmonypir*/` | 3 WASM builds (Hoang/FastPRP/ALF) |
| `scripts/start_pir_servers.sh` | Start all 5 servers |
| `build/src/common.rs` | Cuckoo table constants (K, K_CHUNK, slot sizes) |

## Benchmarks (from this session)

### Hint Generation (server-side, 24 threads, outer rayon)
| PRP | 75 INDEX | 80 CHUNK |
|-----|----------|----------|
| ALF | 711ms | ~2s |
| FastPRP | 1.05s | ~3s |
| Hoang | 7.24s | ~15s |

### Browser Query (50 addresses, FastPRP, pre-workers)
```
INDEX r0h0: build=1422ms net=642ms proc=1709ms
CHUNK r0h0: build=2265ms net=900ms proc=2554ms
Total: ~12.7s
```
Expected with workers: ~3-4s. With workers + ALF SIMD: ~1.5-2s.
