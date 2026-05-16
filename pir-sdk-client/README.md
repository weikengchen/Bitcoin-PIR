# pir-sdk-client

[![Crates.io](https://img.shields.io/crates/v/pir-sdk-client.svg)](https://crates.io/crates/pir-sdk-client)
[![Docs.rs](https://docs.rs/pir-sdk-client/badge.svg)](https://docs.rs/pir-sdk-client)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Native Rust async client for [Bitcoin PIR](https://github.com/Bitcoin-PIR/Bitcoin-PIR).
Look up Bitcoin UTXOs by script hash without revealing **which** script hash
you're looking up.

Three interchangeable backends are provided:

| Backend        | Type                       | Crypto basis                                    |
|----------------|----------------------------|-------------------------------------------------|
| `DpfClient`    | Two-server, stateless      | Distributed Point Functions (XOR of two shares) |
| `HarmonyClient`| Two-server, stateful hints | PBC codes + PRP-based hint server               |
| `OnionClient`  | Single-server, FHE         | Microsoft SEAL (BFV); `onion` cargo feature     |

All three implement the shared `PirClient` async trait from `pir-sdk`, so
switching backends is a one-line change at the call site. A reference deployment
of compatible servers runs at <https://www.bitcoinpir.org/>.

## Features at a glance

- **Async WebSocket transports** — tokio-tungstenite on native, optional
  `web_sys::WebSocket` on `wasm32-unknown-unknown` (via a `PirTransport`
  abstraction).
- **Automatic sync planning** — BFS delta-chain discovery (max 5 hops)
  between snapshot + delta databases; `sync(script_hashes, last_height)`
  is one call.
- **Per-bucket Merkle verification** — each UTXO lookup can be paired with a
  batched Merkle proof that ties results to a published root. DPF, Harmony, and
  Onion all implement verification; padding invariants (K=75 INDEX / K_CHUNK=80
  CHUNK / 25 MERKLE) are preserved to prevent side-channel leakage.
- **Connection resilience** — per-request deadlines
  (`DEFAULT_REQUEST_TIMEOUT = 90s`), connect-with-backoff
  (`RetryPolicy` up to 5 attempts, 250 ms → 5 s exponential backoff), and a
  `reconnect()` escape hatch.
- **Hint cache** (Harmony) — XDG-backed filesystem cache plus byte-blob
  `save_hints_bytes` / `load_hints_bytes` for browser IndexedDB bridges.
- **LRU-eviction retry** (Onion) — server evictions surface as
  `PirError::SessionEvicted` so callers can re-register and retry cleanly.
- **Observability** — Phase 1 `#[tracing::instrument]` spans on every
  public method, Phase 2 `PirMetrics` observer trait with per-query latency
  histograms.
- **Structured error taxonomy** — [`ErrorKind`] classifier with
  `TransientNetwork` / `SessionEvicted` / `ProtocolSkew` /
  `MerkleVerificationFailed` variants plus retry helpers.

## Installation

```toml
# Cargo.toml
[dependencies]
pir-sdk-client = "0.1"

# Opt in to the OnionPIR backend (requires a C++ toolchain + SEAL).
pir-sdk-client = { version = "0.1", features = ["onion"] }
```

## Quick start

### DPF (two-server, recommended)

```rust,ignore
use pir_sdk_client::{DpfClient, PirClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = DpfClient::new(
        "wss://weikeng1.bitcoinpir.org",
        "wss://weikeng2.bitcoinpir.org",
    );
    client.connect().await?;

    let script_hash: [u8; 20] = [0u8; 20]; // HASH160 of the script
    let result = client.sync(&[script_hash], None).await?;

    if let Some(Some(q)) = result.results.first() {
        println!(
            "{} UTXOs, {} sats, merkle_verified={}",
            q.entries.len(),
            q.total_balance(),
            q.merkle_verified,
        );
    }

    client.disconnect().await?;
    Ok(())
}
```

### HarmonyPIR (two-server, stateful hints)

```rust,ignore
use pir_sdk_client::{HarmonyClient, PirClient, PRP_HMR12};

let mut client = HarmonyClient::new(
    "wss://weikeng1.bitcoinpir.org", // query server
    "wss://weikeng2.bitcoinpir.org", // hint server
);
client.set_prp_backend(PRP_HMR12);
client.set_master_key(&[0u8; 16]); // 128-bit session key
client.connect().await?;

// First call downloads hints; subsequent calls reuse them until query budget
// is exhausted (see `min_queries_remaining()`).
let result = client.sync(&script_hashes, last_height).await?;
```

Enable `fastprp` or `alf` features for faster PRP backends:

```toml
pir-sdk-client = { version = "0.1", features = ["fastprp"] }
```

### OnionPIR (single-server, FHE)

```rust,ignore
# // requires `pir-sdk-client = { features = ["onion"] }`
use pir_sdk_client::{OnionClient, PirClient};

let mut client = OnionClient::new("wss://weikeng1.bitcoinpir.org");
client.connect().await?;                    // registers Galois + GSW keys
let result = client.sync(&hashes, None).await?;
```

OnionPIR requires the `onion` feature, which pulls in the
[`onionpir` crate](https://github.com/Bitcoin-PIR/OnionPIRv2-fork) and
Microsoft SEAL (C++). See [`FEATURES.md`](../FEATURES.md) for the toolchain
requirements — **not compatible with `wasm32` targets** because SEAL does not
build for `wasm32-unknown-unknown`.

## Delta sync

After an initial sync, pass the returned `synced_height` to skip work on
subsequent calls:

```rust,ignore
// First sync — full snapshot + any deltas.
let r0 = client.sync(&hashes, None).await?;

// Later — only query the delta chain since `r0.synced_height`.
let r1 = client.sync(&hashes, Some(r0.synced_height)).await?;
```

The `compute_sync_plan` BFS picks a shortest delta chain (≤5 hops) or falls
back to a fresh snapshot if the chain is too long.

## Hint cache (Harmony)

Harmony hints are several tens of MiB per level; caching avoids re-downloading
them across sessions.

```rust,ignore
// Filesystem cache (XDG-backed, $XDG_CACHE_HOME/pir-sdk/hints/ with
// ~/.cache/pir-sdk/hints/ fallback).
client.with_hint_cache_dir(None); // use default
// Or pick a custom dir:
client.with_hint_cache_dir(Some("/var/lib/my-app/pir-hints"));

// Byte-blob form (for browser IndexedDB bridges):
let bytes = client.save_hints_bytes()?; // Option<Vec<u8>>
client.load_hints_bytes(&bytes, &catalog_entry)?;
```

The cache key is a 16-byte SHA-256 fingerprint over
`(master_prp_key, prp_backend, db_id, height, index_bins, chunk_bins,
tag_seed, k_index, k_chunk)`; mismatched keys fail fast with
`PirError::InvalidState` rather than silently mis-using stale hints.

## Merkle verification

All three clients verify Merkle proofs inline during `sync`:

```rust,ignore
if let Some(Some(q)) = result.results.first() {
    if !q.merkle_verified {
        // untrusted result — treat as absent
    }
}
```

DPF and Harmony use per-PBC-bucket Merkle trees (INDEX + CHUNK roots per
group). OnionPIR uses two global flat trees (INDEX + DATA) with FHE-encrypted
sibling queries.

For split-verify workflows — run PIR now, verify later — use
`query_batch_with_inspector` / `verify_merkle_batch_for_results` on the
DPF and Harmony clients.

## Observability

### Tracing spans

Every public method on `DpfClient`, `HarmonyClient`, `OnionClient`, and
`WsConnection` carries a `#[tracing::instrument]` span with a consistent
`backend = "dpf" | "harmony" | "onion"` field. Install any
`tracing_subscriber::fmt` subscriber to get structured logs:

```rust,ignore
tracing_subscriber::fmt::init();
// spans now surface in stderr
```

### Metrics

Install a `PirMetrics` recorder to track queries, bytes, connect lifecycle,
and per-query latency:

```rust,ignore
use std::sync::Arc;
use pir_sdk_client::DpfClient;
use pir_sdk::AtomicMetrics;

let mut client  = DpfClient::new(/* ... */);
let recorder    = Arc::new(AtomicMetrics::new());
client.set_metrics_recorder(Some(recorder.clone()));
client.connect().await?;
// ... run queries ...

let snap = recorder.snapshot();
println!("{} queries, {} bytes, {} µs mean",
    snap.query_successes,
    snap.bytes_sent + snap.bytes_received,
    snap.mean_query_latency_micros().unwrap_or(0),
);
```

`AtomicMetrics` uses lock-free atomics — safe to share across threads.
Installing no recorder is zero-overhead.

## Examples

```bash
# Query a single address
cargo run -p pir-sdk-client --example simple_query -- <script_hash_hex>

# Delta sync flow
cargo run -p pir-sdk-client --example delta_sync
```

## Tests

```bash
# Unit tests (no server required)
cargo test -p pir-sdk-client --lib

# Integration tests against live public PIR servers
cargo test -p pir-sdk-client --test integration_test -- --ignored

# With the OnionPIR backend (requires a C++ toolchain + cmake)
cargo test -p pir-sdk-client --features onion --lib
```

## Feature flags

| Feature    | Default | What it enables                                              |
|------------|:-------:|--------------------------------------------------------------|
| `onion`    | off     | OnionPIR backend via the upstream `onionpir` crate (needs SEAL) |
| `fastprp`  | off     | FastPRP backend for HarmonyPIR (faster per-element)          |
| `alf`      | off     | ALF PRP backend for HarmonyPIR (fastest, native tweaks)      |

See [`FEATURES.md`](../FEATURES.md) at the workspace root for the
full matrix, build-time costs, and compatibility notes.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[`ErrorKind`]: https://docs.rs/pir-sdk/latest/pir_sdk/enum.ErrorKind.html
