# Bitcoin PIR - Private Information Retrieval for Bitcoin UTXOs

A privacy-preserving system for querying Bitcoin UTXO (Unspent Transaction Output) data using Private Information Retrieval (PIR). Supports three PIR protocols: two-server DPF, single-server OnionPIR (FHE-based), and HarmonyPIR (stateful single-server with offline hints).

## Overview

Bitcoin light wallets currently leak all queried addresses to their server, enabling surveillance. This project enables querying the Bitcoin UTXO set without revealing which addresses you're interested in, using PIR protocols where the server(s) learn nothing about your queries.

### Key Features

- **Three PIR Backends**: DPF (2-server), OnionPIR (1-server FHE), HarmonyPIR (1-server stateful)
- **Multi-Client Support**: Web (TypeScript/WASM), Rust CLI, Java (bitcoinj), Python (Electrum plugin)
- **Batch Queries**: Look up multiple addresses in a single round using PBC (probabilistic batch codes)
- **Two-Level Lookup**: Cuckoo index maps script hashes to chunk offsets; chunk database holds UTXO data
- **WebSocket Protocol**: Binary protocol over ws:// or wss:// for all client-server communication
- **High Performance**: Memory-mapped databases, placement optimization, dust/whale filtering

## PIR Protocols

### DPF (Distributed Point Function) - 2-Server

The original protocol. Client generates two DPF keys and sends one to each server. Each server evaluates its key and returns a result; the client XORs both responses to recover the entry. Privacy holds as long as the two servers don't collude.

- **Servers**: 2 (must be non-colluding)
- **Communication**: ~2 KB per query (both directions combined)
- **Latency**: ~50-150ms end-to-end (index + chunk)

### OnionPIR (OnionPIRv2) - 1-Server FHE

A single-server PIR protocol based on fully homomorphic encryption. The client encrypts the query index under a RLWE scheme; the server homomorphically evaluates the database lookup and returns the encrypted result. No trust assumptions between servers.

- **Server**: 1 (no collusion assumption needed)
- **Communication**: ~2.5 MB up, ~2.1 MB down per query (FHE ciphertexts + Galois/GSW keys)
- **Latency**: ~8.6s warm (6s server compute + 2.5s key registration)
- **Storage**: ~24 GB server-side (shared NTT-expanded database)
- **WASM**: 501 KB client (200 KB gzipped), key gen ~8ms, query gen ~1ms

### HarmonyPIR - 1-Server Stateful

A single-server stateful PIR protocol. In an offline phase, the client downloads hint parities from a hint server. Online queries are then fast: the client sends a set of indices, the server returns the corresponding entries, and the client uses its hints to recover the target entry. Hints are consumed per-query and must be refreshed periodically.

- **Servers**: 1 hint server (offline) + 1 query server (online)
- **Communication**: ~40 MB hint download (one-time), then ~few KB per query
- **Latency**: ~30s offline hint download, then ~100ms per online query
- **PRP Backends**: ALF (~198 ns/op), Hoang (~6 us/op), FastPRP (~36 us/op)
- **Max queries before re-hint**: 512 per bucket

## Architecture

```
                        ┌─────────────────────────────────────────┐
                        │               CLIENTS                    │
                        │                                         │
                        │  Web Browser    Rust CLI    Electrum     │
                        │  (TypeScript)   (client)   (Python)     │
                        │                                         │
                        │  bitcoinj       PIR Explorer             │
                        │  (Java/JNI)     (bitcoinjs)             │
                        └────────────┬────────────────────────────┘
                                     │
                           WebSocket (ws:// or wss://)
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         │                           │                           │
         ▼                           ▼                           ▼
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│   DPF Server 1  │      │  OnionPIR Server│      │ HarmonyPIR Hint │
│   (port 8091)   │      │  (port 8093)    │      │  (port 8094)    │
│                 │      │                 │      │                 │
│  DPF Server 2   │      │  FHE evaluation │      │ HarmonyPIR Query│
│  (port 8092)    │      │  Shared NTT DB  │      │  (port 8095)    │
└─────────────────┘      └─────────────────┘      └─────────────────┘

PIR Security: Privacy guaranteed if servers don't learn the query.
  DPF: requires non-collusion.  OnionPIR/HarmonyPIR: single-server privacy.
```

## Project Structure

```
BitcoinPIR/
├── runtime/                        # PIR servers & clients (Rust)
│   └── src/bin/
│       ├── server.rs               # DPF WebSocket server
│       ├── client.rs               # DPF CLI client
│       ├── onionpir2_server.rs     # OnionPIR server (shared NTT)
│       ├── onionpir2_client.rs     # OnionPIR CLI client
│       ├── harmonypir_hint_server.rs  # HarmonyPIR hint server
│       └── harmonypir_*            # HarmonyPIR benchmarks & e2e tests
│
├── build/                          # Database generation pipeline (Rust)
│   └── src/
│       ├── gen_0_utxo_set.rs       # Extract UTXOs from dumptxoutset snapshot
│       ├── build_utxo_chunks.rs    # Build chunks + index (gen_1)
│       ├── build_chunk_cuckoo.rs   # Build chunk cuckoo tables (gen_2)
│       ├── main.rs                 # Build index cuckoo tables (gen_3)
│       ├── gen_1_onion.rs          # Pack OnionPIR entries + build index
│       ├── gen_2_onion.rs          # Build shared NTT store + chunk cuckoo
│       ├── gen_3_onion.rs          # Build index OnionPIR databases
│       └── (stamp_flags, append_whale_sentinels, stats, verify, ...)
│
├── web/                            # Browser client (TypeScript + WASM)
│   └── src/
│       ├── client.ts               # DPF WebSocket PIR client
│       ├── onionpir_client.ts      # OnionPIR client (WASM FHE)
│       ├── harmonypir_client.ts    # HarmonyPIR client + worker pool
│       ├── dpf.ts, hash.ts         # DPF key gen, HASH160/cuckoo hashing
│       ├── pbc.ts                  # Probabilistic batch code planning
│       ├── constants.ts            # Database IDs and parameters
│       └── protocol.ts, codec.ts   # Binary protocol codec
│
├── explorer/                       # bitcoinjs ecosystem adapter
│   └── src/
│       ├── explorer.ts             # PirExplorer (@bitcoinerlab/explorer)
│       ├── utxo-provider.ts        # PirUtxoProvider (standalone)
│       └── esplora-fallback.ts     # Non-sensitive ops via Esplora HTTP
│
├── bitcoinj-pir/                   # Java PIR client library
│   └── src/main/java/com/bitcoinpir/
│       ├── PirUtxoProvider.java    # High-level UTXO lookup
│       ├── dpf/                    # DPF client (DpfKeyGen, DpfPirClient)
│       ├── harmony/                # HarmonyPIR client (JNI-backed)
│       └── codec/                  # Protocol codec, UTXO decoder
│
├── electrum_plugin/                # Electrum wallet plugin (Python)
│   └── pir_privacy/
│       ├── __init__.py             # Plugin entry point (PyQt6)
│       ├── pir_dpf.py              # DPF protocol client
│       ├── pir_onionpir_client.py  # OnionPIR protocol client
│       ├── pir_harmony_client.py   # HarmonyPIR protocol client
│       └── pir_synchronizer.py     # Wallet sync (address → PIR → UTXOs)
│
├── harmonypir-wasm/                # HarmonyPIR WASM bindings
├── block_reader/                   # Blockchain data analysis tools (Rust)
├── scripts/                        # Server startup & test scripts
├── doc/                            # Documentation
│   ├── DEPLOYMENT.md               # Production deployment guide
│   ├── WEB.md                      # WebSocket protocol details
│   └── WALLET_INTEGRATION_ANALYSIS.md  # Wallet ecosystem analysis
├── docs/                           # Design documents
│   └── onionpir_plan.md            # OnionPIR integration design
└── pdf/                            # Research paper (LaTeX)
    └── main.tex                    # 7-part paper (data, batching, 2-server,
                                    #   HarmonyPIR, OnionPIR, comparison, deployment)
```

## Live Demo

A public demo is available at **https://pir.chenweikeng.com/** — you can test all three PIR protocols directly in the browser. Note: the servers are running on a home computer and load data into memory on-demand, so they may be intermittently unavailable or slow on first query. Please be patient!

## Quick Start

### 1. Build the Project

```bash
git clone https://github.com/Bitcoin-PIR/Bitcoin-PIR.git
cd Bitcoin-PIR

# Build all Rust components
cargo build --release
```

### 2. Generate Database Files

The build pipeline transforms a Bitcoin Core UTXO snapshot into PIR-queryable databases:

```bash
# Step 0: Extract UTXOs from dumptxoutset snapshot
cargo run --release -p build --bin gen_0_extract_utxo_set -- /path/to/utxo_snapshot.dat

# DPF / HarmonyPIR databases:
cargo run --release -p build --bin gen_1_build_utxo_chunks     # Build chunks + index
cargo run --release -p build --bin append_whale_sentinels      # Add whale sentinel entries
cargo run --release -p build --bin gen_2_build_chunk_cuckoo    # Build chunk cuckoo tables
cargo run --release -p build --bin gen_2b_stamp_flags          # Stamp placement bits
cargo run --release -p build --bin gen_3_build_index_cuckoo    # Build index cuckoo tables

# OnionPIR databases (additional):
cargo run --release -p build --bin gen_1_onion    # Pack entries + index
cargo run --release -p build --bin gen_2_onion    # Build NTT store + chunk cuckoo
cargo run --release -p build --bin gen_3_onion    # Build index PIR databases
```

### 3. Start PIR Servers

**DPF (2-server):**
```bash
./target/release/server --port 8091   # Server 1
./target/release/server --port 8092   # Server 2 (separate terminal)
```

**OnionPIR (1-server):**
```bash
./target/release/onionpir2_server --port 8093
```

**HarmonyPIR (hint + query servers):**
```bash
./target/release/harmonypir_hint_server --port 8094   # Hint server (offline phase)
# Query server uses port 8095
```

### 4. Query UTXOs

**Using the Rust CLI (DPF):**
```bash
./target/release/client \
    --server0 ws://127.0.0.1:8091 \
    --server1 ws://127.0.0.1:8092 \
    --hash <40-char-hex-script-hash>
```

**Using the Web Client:**
```bash
cd web
npm install
npx vite --port 8080
# Open http://localhost:8080 — supports DPF, OnionPIR, and HarmonyPIR tabs
```

**Using the Java Client (bitcoinj-pir):**
```bash
cd bitcoinj-pir
./gradlew build
# See bitcoinj-pir/USAGE.md for API documentation
```

**Using the Electrum Plugin:**
```bash
cd electrum_plugin
# Build the plugin zip (see electrum_plugin/ for full instructions)
# Install via Electrum: Tools → Plugins → Add Plugin → select zip
```

## Databases

The system uses a two-level lookup: a cuckoo index maps script hashes to chunk locations, then chunks hold the actual UTXO data.

### Cuckoo Index

- **Purpose**: Maps HASH160(scriptPubKey) to chunk offset
- **Entry size**: 26 bytes (20B hash + 4B chunk_id + 1B num_chunks + 1B flags)
- **Hashing**: 2-hash cuckoo, bucket size 3
- **Flags byte**: Encodes first-chunk cuckoo placement (5 bits + 1 valid bit) — allows 1 DPF key instead of 3 when placement is known (93.9% of addresses)
- **DPF domain**: 2^20

### UTXO Chunks

- **Purpose**: Serialized UTXO data in fixed-size blocks
- **Entry size**: 40 bytes per block
- **Hashing**: 3-hash cuckoo, bucket size 2
- **DPF domain**: 2^21

### Chunk Data Format

Each script hash's UTXOs are serialized as:
```
[varint entry_count]
[32B TXID][varint vout][varint amount]  x entry_count
```

### Filtering

- **Dust threshold**: 576 sats (UTXOs below this are excluded)
- **Whale threshold**: >100 UTXOs per scriptPubKey (handled via sentinel entries)

## Query Flow

1. **Compute HASH160**: RIPEMD160(SHA256(scriptPubKey)) — 20 bytes
2. **Calculate cuckoo locations**: Two bucket indices from the HASH160
3. **Phase 1 — Index query**: PIR retrieves the cuckoo index entry (chunk_id, num_chunks, flags)
4. **Phase 2 — Chunk query**: PIR retrieves the chunk(s) containing UTXO data
5. **Parse results**: Decode varint-encoded entries to get TXIDs, vouts, and amounts

For batch queries, PBC (probabilistic batch codes) assigns multiple addresses across K buckets (K=75 index, K=80 chunk) so all queries can execute in parallel.

## Client Integrations

### Web Client (TypeScript/WASM)

Browser-based client supporting all three PIR backends. HarmonyPIR uses a Web Worker pool for PRP computation. OnionPIR uses a WASM module (501 KB) for FHE operations.

### PIR Explorer (bitcoinjs Adapter)

Drop-in replacement for `@bitcoinerlab/explorer` (Esplora/Electrum). Privacy-sensitive operations (address lookup, UTXO fetch) go through PIR; non-sensitive operations (fee estimates, tx broadcast) fall back to Esplora HTTP.

```typescript
import { PirExplorer } from 'pir-explorer';
const explorer = new PirExplorer({ backend: { type: 'dpf', server0: '...', server1: '...' } });
const utxos = await explorer.fetchAddress('bc1q...');
```

### bitcoinj-pir (Java)

Java client library with DPF and HarmonyPIR support. HarmonyPIR uses JNI bindings to the Rust core library for PRP and relocation. Implements `PirUtxoProvider` for easy wallet integration.

### Electrum Plugin (Python)

Plugin for Electrum 4.7.1 supporting all three PIR backends. Installed as a zip via Tools > Plugins > Add Plugin. Uses vendored `websockets` for the frozen PyInstaller app. Settings dialog for protocol/server selection.

## WebSocket Protocol

Binary protocol over WebSocket:

| Message Type | Code | Description |
|--------------|------|-------------|
| Ping / Pong | `0x01` / `0x02` | Keep-alive |
| List Databases | `0x03` / `0x04` | Enumerate available databases |
| Get Database Info | `0x05` / `0x06` | Query database parameters |
| DPF Query | `0x07` / `0x08` | DPF PIR query and response |
| HarmonyPIR GetInfo | `0x40` | Get server parameters (n, w, bins) |
| HarmonyPIR Hint | `0x41` | Download hint parities |
| HarmonyPIR Batch Query | `0x43` | Batch query with bucket requests |
| Error | `0xFF` | Error message |

## TLS/SSL Support

For production, use secure WebSocket (wss://):

```bash
./target/release/server --port 8091 \
    --tls-cert /path/to/cert.pem \
    --tls-key /path/to/key.pem
```

See [`doc/DEPLOYMENT.md`](doc/DEPLOYMENT.md) for Cloudflare Tunnel and nginx reverse proxy setups.

## Development

```bash
# Build all Rust components
cargo build --release

# Run Rust tests
cargo test

# Build web client
cd web && npm run build-web

# Run web dev server
cd web && npx vite --port 8080

# Build Java client
cd bitcoinj-pir && ./gradlew build
```

## Security Model

### Privacy Guarantees

- **DPF (2-server)**: Privacy guaranteed if the two servers don't collude
- **OnionPIR (1-server)**: Computational privacy from RLWE hardness — single server learns nothing
- **HarmonyPIR (1-server)**: Information-theoretic privacy for online queries; hint server sees PRP key but not which entries are queried

### Deployment Requirements

- DPF servers MUST NOT collude — use different hosting providers
- Enable TLS (wss://) in production
- Keep database files synchronized across servers
- For HarmonyPIR, hint and query servers can be the same machine (different security domains)

## Performance

| Protocol | Index Query | Chunk Query | Full Lookup | Communication |
|----------|------------|-------------|-------------|---------------|
| DPF | ~10-50ms | ~10-50ms | ~50-150ms | ~2 KB |
| OnionPIR | ~0.9s | ~5.1s | ~8.6s (warm) | ~4.6 MB |
| HarmonyPIR | ~50ms | ~50ms | ~100ms (online) | ~40 MB hints + ~few KB/query |

## Documentation

- [`doc/DEPLOYMENT.md`](doc/DEPLOYMENT.md) — Production deployment guide
- [`doc/WEB.md`](doc/WEB.md) — WebSocket protocol details
- [`doc/WALLET_INTEGRATION_ANALYSIS.md`](doc/WALLET_INTEGRATION_ANALYSIS.md) — Wallet ecosystem analysis
- [`bitcoinj-pir/USAGE.md`](bitcoinj-pir/USAGE.md) — Java client API and HarmonyPIR JNI guide
- [`docs/onionpir_plan.md`](docs/onionpir_plan.md) — OnionPIR integration design
- [`pdf/main.pdf`](pdf/main.pdf) — Research paper

## Dependencies

### Rust
- `tokio` — Async runtime
- `tokio-tungstenite` — WebSocket support
- `tokio-rustls` — TLS support
- `memmap2` — Memory-mapped files
- `libdpf` — DPF implementation
- `bitcoin` — Bitcoin data structures
- `onionpir` — OnionPIR FHE library
- `harmonypir` — HarmonyPIR core (PRP, relocation, protocol)

### Web Client
- TypeScript 5+
- Vite (build tool)
- `libdpf` — TypeScript DPF implementation
- OnionPIR WASM module (Emscripten)
- HarmonyPIR WASM + Web Workers
- `hash.js` — RIPEMD160 and SHA256

### Java (bitcoinj-pir)
- Java 21+
- Gradle
- HarmonyPIR JNI native library

### Python (Electrum Plugin)
- Python 3.12+ (PyQt6)
- `websockets` (vendored)
- OnionPIR / HarmonyPIR Python bindings (PyO3)

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## References

- [Private Information Retrieval](https://en.wikipedia.org/wiki/Private_information_retrieval)
- [Distributed Point Functions](https://eprint.iacr.org/2013/679.pdf)
- [OnionPIR](https://eprint.iacr.org/2021/1081.pdf)
- [HarmonyPIR](https://eprint.iacr.org/2024/XXX)
- [Bitcoin UTXO Model](https://developer.bitcoin.org/devguide/transactions.html)
- [Cuckoo Hashing](https://en.wikipedia.org/wiki/Cuckoo_hashing)
