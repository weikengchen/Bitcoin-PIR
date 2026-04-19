# Feature Flags

This document lists every cargo / npm feature flag across the publishable
crates in the BitcoinPIR workspace, their default state, what they enable,
and the toolchain cost of turning them on.

## Summary table

| Crate             | Feature      | Default  | Compat    | What it enables                                                       |
|-------------------|--------------|:--------:|:---------:|-----------------------------------------------------------------------|
| `pir-sdk`         | `serde`      |   off    | all       | Derives `Serialize` / `Deserialize` on the public types.              |
| `pir-sdk-client`  | `onion`      |   off    | native    | OnionPIR backend via upstream `onionpir` crate (needs C++ SEAL).      |
| `pir-sdk-client`  | `fastprp`    |   off    | all       | FastPRP backend for HarmonyPIR — faster per-element.                  |
| `pir-sdk-client`  | `alf`        |   off    | all       | ALF PRP backend for HarmonyPIR — fastest per-element.                 |
| `pir-core`        | _(none)_     |   —      | all       | No feature flags; core primitives are always available.               |
| `pir-runtime-core`| _(none)_     |   —      | native    | No feature flags; shared server primitives are always available.      |
| `pir-sdk-wasm`    | _(none)_     |   —      | wasm32    | No cargo features; `wasm-pack --target` picks the JS module style.    |
| `pir-sdk-server`  | _(none)_     |   —      | native    | No feature flags currently; builder + loader always compiled.         |

"Compat" column:
- **all**: compiles on both native and `wasm32-unknown-unknown`.
- **native**: native targets only (tokio, std::fs, or a C toolchain).
- **wasm32**: `wasm32-unknown-unknown` only.

## `pir-sdk`

### `serde` — off by default

Derives `serde::Serialize` + `serde::Deserialize` on every public type
in the crate (`ScriptHash`, `UtxoEntry`, `QueryResult`, `SyncResult`,
`DatabaseCatalog`, `DatabaseInfo`, `SyncPlan`, `BucketRef`,
`PirError`, `ErrorKind`, `AtomicMetricsSnapshot`).

Use this when you want to persist PIR results to disk / IndexedDB /
a network message without hand-rolling an encoder. The sync-merge
delta protocol inside `pir-sdk` itself does not use serde — the
feature is purely for external callers.

```toml
pir-sdk = { version = "0.1", features = ["serde"] }
```

Cost: ~100 KB of additional compile time (typical `serde_derive`
macro expansion); adds `serde` as a transitive dep.

## `pir-sdk-client`

### `onion` — off by default, **native-only**

Pulls in the [`onionpir` crate](https://github.com/Bitcoin-PIR/OnionPIRv2-fork)
and enables the `OnionClient` single-server FHE backend. Without this
feature, `OnionClient` keeps a placeholder implementation (warns and
returns `None` on every query).

**Toolchain cost**:
- `cmake` (3.13+) and a C++17 toolchain on `PATH`.
- Cold `cargo build` adds ≈5–10 minutes (SEAL compiles from source).
- On macOS, Homebrew GCC is needed (the system Clang's libc++ headers
  cause SEAL compile errors on some releases).

**Platform compatibility**:
- ✅ Linux x86_64 / aarch64.
- ✅ macOS x86_64 / aarch64 (Homebrew GCC).
- ✅ Windows MSVC (untested in CI).
- ❌ `wasm32-unknown-unknown` — SEAL does not compile for WASM.
- ❌ `wasm32-wasi` — SEAL's `std::filesystem` / `std::thread` uses
  are not supported by the wasi-sdk's libc++.

```toml
pir-sdk-client = { version = "0.1", features = ["onion"] }
```

### `fastprp` — off by default

Enables the **FastPRP** backend for HarmonyPIR. Faster per-element than
the default HMR12 PRP but with a slightly larger setup cost. Call
`HarmonyClient::set_prp_backend(PRP_FASTPRP)` at runtime to select it.

```toml
pir-sdk-client = { version = "0.1", features = ["fastprp"] }
```

### `alf` — off by default

Enables the **ALF** PRP backend for HarmonyPIR — fastest per-element with
native per-group tweaks. Recommended for high-throughput native clients
when memory is not a concern. Call
`HarmonyClient::set_prp_backend(PRP_ALF)` at runtime to select it.

```toml
pir-sdk-client = { version = "0.1", features = ["alf"] }
```

The `fastprp` and `alf` features are mutually compatible — you can
enable both and switch backends at runtime — but enabling neither is
fine too; the default `PRP_HMR12` backend is always compiled in.

## `pir-core`

`pir-core` has no feature flags. Every primitive (hash, cuckoo, PBC,
Merkle, codec) is always compiled. The crate is `no_std`-eligible in
principle but currently pulls in `std` via `alloc`-heavy types; if you
need `no_std` in a downstream crate, open an issue.

## `pir-sdk-wasm`

`pir-sdk-wasm` has no cargo features. Build variants are selected at
`wasm-pack build --target` time:

| Target     | Output format                                                    |
|------------|------------------------------------------------------------------|
| `web`      | ES modules, directly consumable by Vite / Webpack / Rollup / etc.|
| `bundler`  | Emits a `package.json` with `sideEffects` set for tree-shakers.  |
| `nodejs`   | CommonJS for Node.js (tests, scripts).                           |
| `no-modules` | IIFE, for environments without ES module support.              |

`tracing-wasm` is pulled in unconditionally on `wasm32` targets (adds
~14 KB gzipped). If bundle size becomes a concern, gating behind a
`tracing-subscriber` feature is a follow-up tracked in
[`PUBLISHING.md`](PUBLISHING.md).

## `pir-sdk-server`

`pir-sdk-server` has no feature flags currently. The builder API
(`PirServerBuilder`, `PirServer`, `ServerConfig`) is always compiled.

## Combining features

Multiple features can be enabled simultaneously. The workspace-level
`Cargo.toml` pins compatible versions for every optional dep so
`cargo build --features onion,fastprp,alf -p pir-sdk-client` works out
of the box.

```bash
# Everything turned on (native only — requires C++ toolchain for onion).
cargo build -p pir-sdk-client --features "onion,fastprp,alf"

# All PRP backends without the C++ dependency.
cargo build -p pir-sdk-client --features "fastprp,alf"

# Default (DPF + Harmony with HMR12 PRP only — no C++ toolchain required).
cargo build -p pir-sdk-client
```

## Cross-target compatibility at a glance

| Target family               | `pir-sdk` | `pir-sdk-client`                    | `pir-sdk-wasm` | `pir-runtime-core` | `pir-sdk-server` | `pir-core` |
|-----------------------------|:---------:|-------------------------------------|:--------------:|:------------------:|:----------------:|:----------:|
| Linux / macOS / Windows     | ✅         | ✅ (any feature combo)               | ❌              | ✅                  | ✅                | ✅          |
| `wasm32-unknown-unknown`    | ✅         | ✅ without `onion`, ❌ with `onion`    | ✅              | ❌                  | ❌                | ✅          |
| `wasm32-wasi`               | ✅         | ❌ (tokio-tungstenite is tokio-only) | ❌              | ❌                  | ❌                | ✅          |

## Preserving PIR padding invariants

🔒 **None** of the feature flags above can disable the mandatory PIR
padding invariants (K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE) or the
INDEX-Merkle item-count symmetry. Those invariants live in the
`pir-sdk-client` query path and `pir-sdk-wasm` wrappers and are
enforced unconditionally — see the "CRITICAL SECURITY REQUIREMENTS"
section of the root `CLAUDE.md` for details.
