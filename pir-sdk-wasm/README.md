# pir-sdk-wasm

[![npm](https://img.shields.io/npm/v/pir-sdk-wasm.svg)](https://www.npmjs.com/package/pir-sdk-wasm)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

WASM / TypeScript bindings for [Bitcoin PIR](https://github.com/Bitcoin-PIR/Bitcoin-PIR).
Runs the full Rust PIR client in a browser — **no extension, no native helper**,
just a WASM module talking to a standard `WebSocket`.

- Same protocols and privacy guarantees as the native `pir-sdk-client`
  (K=75 / K_CHUNK=80 / 25-MERKLE padding enforced in the Rust core, not
  reimplemented in JS).
- Async `WasmDpfClient` and `WasmHarmonyClient` — full PIR query flow behind
  a `Promise`-returning API.
- Pure-crypto Merkle verifier primitives so the JS side can run a per-bucket
  Merkle proof against a published tree-top blob.
- Lock-free `WasmAtomicMetrics` counters bridged to JS — ideal for a
  browser tools panel or a wallet's diagnostics view.
- Browser `tracing` subscriber that surfaces Rust-side
  `#[tracing::instrument]` spans in DevTools console.
- Sync planning (`computeSyncPlan`), delta decoding (`decodeDeltaData`),
  delta merging (`mergeDelta`), and the low-level hash / cuckoo / codec
  primitives from `pir-core`.

> **No `WasmOnionClient`.** OnionPIR depends on Microsoft SEAL (C++), which
> does not build for `wasm32-unknown-unknown`. Browsers that need the
> single-server FHE backend continue to use a hand-written
> `onionpir_client.ts` in the reference web app.

## Installation

### npm (when published)

```bash
npm install pir-sdk-wasm
```

### Local build

```bash
# One-time install
cargo install wasm-pack

# Build into ./pkg/ (web target)
cd pir-sdk-wasm
wasm-pack build --target web --out-dir pkg

# Link into a consumer project
cd ../my-app
npm link ../pir-sdk-wasm/pkg
```

Targets supported by `wasm-pack build --target`:

| Target    | Use                                                  |
|-----------|------------------------------------------------------|
| `web`     | ES modules, directly consumable by Vite/Webpack/etc. |
| `bundler` | Emits a `package.json` with `sideEffects` set        |
| `nodejs`  | CommonJS for Node.js (tests, scripts)                |

## Quick start

```typescript
import init, {
  WasmDpfClient,
  sdkCreateAtomicMetrics,
  initTracingSubscriber,
} from 'pir-sdk-wasm';

// 1. Load the WASM module (once per page).
await init();

// 2. (optional) Route Rust tracing spans to DevTools console.
initTracingSubscriber();

// 3. (optional) Install a metrics recorder shared by every client.
const metrics = sdkCreateAtomicMetrics();

// 4. Build + connect a DPF client.
const client = new WasmDpfClient(
  'wss://weikeng1.bitcoinpir.org',
  'wss://weikeng2.bitcoinpir.org',
);
client.setMetricsRecorder(metrics);
await client.connect();

// 5. Sync a set of script hashes to tip. Input is a packed
//    Uint8Array of 20*N bytes (HASH160 per script hash).
const packed = new Uint8Array(scriptHashes.flat());
const syncResult = await client.sync(packed /* , lastHeight */);

for (let i = 0; i < syncResult.resultCount; i++) {
  const result = syncResult.getResult(i);
  if (result) {
    console.log(`${result.entryCount} UTXOs, merkleVerified=${result.merkleVerified}`);
  }
}

console.log(metrics.snapshot());
// { queriesStarted: 1n, queriesCompleted: 1n, bytesSent: ..., ... }
```

## API surface

### Async clients

| Class                | Description                                                      |
|----------------------|------------------------------------------------------------------|
| `WasmDpfClient`      | Two-server DPF client (recommended)                              |
| `WasmHarmonyClient`  | Two-server HarmonyPIR (hint + query) client                      |
| `WasmSyncResult`     | Return value from `sync()` — iterate with `getResult(i)`         |
| `WasmQueryResult`    | Per-hash result: `entries`, `merkleVerified`, `isWhale`, ...     |

Client methods (both `Dpf` and `Harmony`):

- `connect()` / `disconnect()` / `isConnected`
- `fetchCatalog(): Promise<WasmDatabaseCatalog>`
- `sync(scriptHashes, lastHeight?): Promise<WasmSyncResult>`
- `queryBatch(scriptHashes, dbId): Promise<WasmQueryResult[]>`
- `queryBatchRaw(scriptHashes, dbId)` — skip inline Merkle verify
- `verifyMerkleBatch(results, dbId)` — run the network Merkle verifier
- `serverUrls(): [string, string]`
- `onStateChange(cb)` — push `ConnectionState` transitions to JS
- `syncWithProgress(scriptHashes, lastHeight?, onEvent)` — progress events
- `setMetricsRecorder(metrics)` / `clearMetricsRecorder()`

`WasmHarmonyClient` additionally has:

- `setMasterKey(Uint8Array[16])` / `setPrpBackend(PRP_HMR12/PRP_FASTPRP/PRP_ALF)`
- `dbId()` / `setDbId(u8)` — switch databases (invalidates hints)
- `minQueriesRemaining()` / `estimateHintSizeBytes()`
- `fingerprint(catalog, dbId)` — 16-byte cache key
- `saveHints(): Uint8Array | null` / `loadHints(bytes, catalog, dbId)`

### Sync planning & delta merging

- `computeSyncPlan(catalog, lastHeight?): WasmSyncPlan`
- `decodeDeltaData(raw): { spent, newUtxos, entriesIter }`
- `mergeDelta(snapshot, deltaRaw): WasmQueryResult`
- `mergeDeltaBatch(snapshots[], deltas[])`

### Merkle verification (pure crypto)

- `WasmBucketMerkleTreeTops.fromBytes(bytes)` — parse a tree-top blob
- `verifyBucketMerkleItem(binIndex, content, pbcGroup, siblingRows, treeTops)`
- `bucketMerkleLeafHash(binIndex, content)` / `bucketMerkleParentN(children)` /
  `bucketMerkleSha256(bytes)` / `xorBuffers(a, b)`

The *network* half (K-padded sibling batches over DPF) is owned by the
client wrappers above; these primitives expose the leaf/parent/walk math
for callers that manage the wire loop themselves.

### Observability

- `WasmAtomicMetrics` — lock-free `bigint` counters:
  - `queriesStarted` / `queriesCompleted` / `queryErrors`
  - `bytesSent` / `bytesReceived` / `framesSent` / `framesReceived`
  - `connects` / `disconnects`
  - `totalQueryLatencyMicros` / `minQueryLatencyMicros` / `maxQueryLatencyMicros`
  - `sentinel = 0xFFFF_FFFF_FFFF_FFFFn` on min if no samples yet
- `initTracingSubscriber()` — installs a `tracing-wasm` subscriber that
  routes Rust-side spans to the browser DevTools console (idempotent).

### Hash / cuckoo / codec primitives

`splitmix64`, `computeTag`, `deriveGroups`, `deriveCuckooKey`, `cuckooHash`,
`deriveChunkGroups`, `cuckooHashInt`, `cuckooPlace`, `planRounds`,
`readVarint`, `decodeUtxoData`.

See the generated [`pir_sdk_wasm.d.ts`](./pir_sdk_wasm.d.ts) for the full
TypeScript type signatures.

## Input/output conventions

- **Script hashes** cross the JS↔WASM boundary as a packed `Uint8Array` of
  length `20 * N` (HASH160 = 20 bytes per address). Length not a multiple
  of 20 throws `Error`.
- **`WasmQueryResult` JSON** — `toJson()` returns a plain object with
  hex-encoded `txid` / `binContent` / `rawChunkData` fields; symmetric
  `fromJson(obj)` parses the round-trip shape for split-verify workflows.
- **All byte counts are `bigint`** (`u64` on the Rust side) to survive
  multi-PB session totals safely above `Number.MAX_SAFE_INTEGER`.

## Memory management

The wasm-bindgen classes own linear-memory handles that must be released
with `.free()` when you're done:

```typescript
const plan = computeSyncPlan(catalog, lastHeight);
// ... use plan ...
plan.free();
catalog.free();
```

Forgetting `.free()` leaks WASM memory — not a security issue, but the
browser tab will grow over time. A `FinalizationRegistry`-based wrapper
layer is a reasonable addition for consumer apps.

## Bundle size

Baseline (gzipped):

- WASM bundle: ~340 KB
- JS wrapper: ~7.5 KB

`initTracingSubscriber()` adds ~14 KB gzipped for the tracing subscriber
support code — opt-in, not loaded unless you call it.

For size-sensitive deployments, use `wasm-pack build --release` and
enable LTO via a workspace-level `[profile.wasm-release]`:

```toml
# Cargo.toml (workspace root)
[profile.wasm-release]
inherits = "release"
opt-level = "s"
lto = true
```

Then build with `wasm-pack build -- --profile wasm-release`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
