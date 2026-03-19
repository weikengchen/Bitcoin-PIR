# Bitcoin PIR - Private Information Retrieval for Bitcoin UTXOs

A privacy-preserving system for querying Bitcoin UTXO (Unspent Transaction Output) data using Distributed Point Function (DPF) based Private Information Retrieval (PIR).

## Overview

This project enables querying the Bitcoin UTXO set without revealing which addresses you're interested in. Using a two-server PIR architecture with DPF, the servers learn nothing about your queries as long as they don't collude.

### Key Features

- **Privacy-Preserving**: Servers cannot determine which addresses are being queried
- **DPF-Based**: Uses Distributed Point Functions for efficient PIR
- **Web Compatible**: Browser and Node.js clients via WebSocket
- **TLS Support**: Secure WebSocket (wss://) for production deployments
- **High Performance**: Memory-mapped databases for fast queries

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         CLIENT                                    │
│  ┌────────────────────┐    ┌────────────────────┐               │
│  │   Web Browser      │    │   Rust CLI         │               │
│  │   (TypeScript)     │    │   (lookup_pir)     │               │
│  └─────────┬──────────┘    └─────────┬──────────┘               │
│            │                         │                           │
│            └───────────┬─────────────┘                           │
│                        │                                         │
│              WebSocket Connections                                │
│           (ws:// or wss://)                                       │
└────────────────────────┼─────────────────────────────────────────┘
                         │
           ┌─────────────┴─────────────┐
           ▼                           ▼
┌──────────────────────┐    ┌──────────────────────┐
│      SERVER 1        │    │      SERVER 2        │
│   (port 8091)        │    │   (port 8092)        │
│                      │    │                      │
│  ┌────────────────┐  │    │  ┌────────────────┐  │
│  │  2 Databases   │  │    │  │  2 Databases   │  │
│  │  (identical)   │  │    │  │  (identical)   │  │
│  └────────────────┘  │    │  └────────────────┘  │
└──────────────────────┘    └──────────────────────┘

PIR Security Model: Privacy guaranteed if at least one server doesn't learn queries.
```

## Project Structure

```
BitcoinPIR/
├── runtime/                    # PIR server & client (Rust)
│   ├── src/
│   │   ├── lib.rs              # Library exports
│   │   ├── eval.rs             # DPF evaluation engine
│   │   ├── protocol.rs         # Binary protocol codec
│   │   └── bin/
│   │       ├── server.rs       # WebSocket server binary
│   │       └── client.rs       # CLI PIR client
│   └── Cargo.toml
│
├── build/                      # Database generation pipeline (Rust)
│   ├── src/
│   │   ├── gen_0_utxo_set.rs     # Extract UTXOs from dumptxoutset snapshot
│   │   ├── common.rs             # Shared constants & hash functions
│   │   ├── main.rs               # Build index cuckoo tables
│   │   ├── build_utxo_chunks.rs  # Build UTXO chunks (with dust filter)
│   │   ├── build_chunk_cuckoo.rs # Build chunk cuckoo tables
│   │   └── (test/verify/stats binaries)
│   └── Cargo.toml
│
├── web/                        # Browser/Node.js client (TypeScript)
│   ├── src/
│   │   ├── index.ts            # Main entry point & exports
│   │   ├── client.ts           # WebSocket PIR client
│   │   ├── dpf.ts              # DPF key generation wrapper
│   │   ├── hash.ts             # HASH160, cuckoo hash functions
│   │   ├── constants.ts        # Database IDs and parameters
│   │   └── protocol.ts         # Binary protocol codec
│   ├── index.html              # Demo web interface
│   ├── vite.config.js          # Vite build configuration
│   └── package.json
│
├── scripts/                    # Helper scripts
│   ├── start_pir_servers.sh    # Start both PIR servers
│   ├── test_batch_pir_client.sh # Test PIR client
│   └── get_random_hash.sh      # Sample random cuckoo entries
│
├── doc/                        # Documentation
│   ├── DEPLOYMENT.md           # Production deployment guide
│   └── WEB.md                  # WebSocket protocol details
│
└── pdf/                        # Research paper (LaTeX)
    ├── main.tex
    └── main.pdf
```

## Quick Start

### 1. Build the Project

```bash
git clone https://github.com/weikengchen/Bitcoin-PIR.git
cd Bitcoin-PIR

# Build all components
cargo build --release
```

### 2. Generate Database Files

The database pipeline transforms a Bitcoin Core UTXO snapshot into PIR-queryable format:

```bash
# Step 0: Extract UTXOs from dumptxoutset snapshot
#   Input:  Bitcoin Core UTXO snapshot (dumptxoutset)
#   Output: utxo_set.bin (68 bytes per UTXO)
cargo run --release -p build --bin gen_0_extract_utxo_set -- /path/to/utxo_snapshot.dat

# Step 1+: Build batch PIR databases
#   Builds UTXO chunks, index cuckoo tables, and chunk cuckoo tables
cargo run --release -p build --bin gen_1_build_utxo_chunks
cargo run --release -p build --bin gen_2_build_index_cuckoo
cargo run --release -p build --bin gen_7_build_chunk_cuckoo
```

### 3. Start PIR Servers

```bash
# Start both servers (ports 8093 and 8094)
./scripts/start_pir_servers.sh
```

Or manually:
```bash
./target/release/server --port 8093
./target/release/server --port 8094  # in another terminal
```

### 4. Query UTXOs

**Using CLI:**
```bash
# Query by script hash hex
./target/release/client \
    --server0 ws://127.0.0.1:8093 \
    --server1 ws://127.0.0.1:8094 \
    --hash <40-char-hex-script-hash>
```

**Using Web Client:**
```bash
cd web
npm install
npx vite --port 8080
# Open http://localhost:8080 in your browser
```

## Databases

The system uses two databases for PIR queries:

### 1. Cuckoo Index (`utxo_cuckoo_index`)
- **Purpose**: Maps HASH160(scriptPubKey) to byte offset in chunks file
- **Hash**: Bucketed cuckoo hashing with 2 locations (FNV-1a style)
- **Entry size**: 24 bytes (20-byte HASH160 key + 4-byte offset)
- **Bucket size**: 4 entries per bucket
- **Buckets**: ~15.4 million

### 2. UTXO Chunks Data (`utxo_chunks_data`)
- **Purpose**: Contains serialized UTXO data in 32KB chunks
- **Format**: Direct index lookup (chunk_index = byte_offset / 32768)
- **Entry size**: 32,768 bytes (32KB per chunk)
- **Entries**: ~182K (normal) / ~65K (small)

#### Chunk Data Format

Each script hash's UTXOs are serialized as:
```
[varint entry_count]
[32B TXID][varint vout][varint amount]  × entry_count
```

Full 32-byte TXIDs are stored directly (no compression or mapping needed).

#### Offset Encoding

Byte offsets into the chunks file are stored as `offset / 2` in the cuckoo index (u32), with 2-byte alignment padding. This allows addressing up to ~8.6GB with a 4-byte field. Clients multiply the stored offset by 2 to recover the actual byte offset.

## Query Flow

1. **Compute HASH160**: RIPEMD160(SHA256(scriptPubKey)) — 20 bytes
2. **Calculate cuckoo locations**: Two bucket indices from the HASH160
3. **Phase 1 — Query cuckoo index**: PIR query retrieves the index entry, revealing the chunk offset
4. **Phase 2 — Query chunks**: PIR query retrieves the 32KB chunk containing the UTXO data
5. **Parse results**: Decode varint-encoded entries to get TXIDs, vouts, and amounts

Each phase sends DPF keys to both servers; responses are XOR'd to recover the plaintext.

## WebSocket Protocol

The server uses a Simple Binary Protocol over WebSocket:

| Message Type | Format |
|--------------|--------|
| Ping | `[0x01]` |
| Pong | `[0x02]` |
| List Databases | `[0x03]` |
| Database List | `[0x04][count:u32][entries...]` |
| Get Database Info | `[0x05][db_id_len:u16][db_id:bytes]` |
| Database Info | `[0x06][info_data...]` |
| Query | `[0x07][query_data...]` |
| Query Response | `[0x08][response_data...]` |
| Error | `[0xFF][error_message]` |

## TLS/SSL Support

For production deployments, use secure WebSocket (wss://):

```bash
# Generate self-signed certificate (testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Run server with TLS
./target/release/server --port 8091 \
    --tls-cert /path/to/cert.pem \
    --tls-key /path/to/key.pem
```

See [`doc/DEPLOYMENT.md`](doc/DEPLOYMENT.md) for complete deployment instructions including Cloudflare Tunnel and nginx reverse proxy setups.

## Development

```bash
# Build all Rust components
cargo build --release

# Run Rust tests
cargo test

# Build web client for production
cd web && npm run build-web

# Run web client dev server
cd web && npx vite --port 8080
```

## Dependencies

### Rust
- `tokio` — Async runtime
- `tokio-tungstenite` — WebSocket support
- `tokio-rustls` — TLS support
- `memmap2` — Memory-mapped files
- `libdpf` — DPF implementation
- `bitcoin` — Bitcoin data structures

### Web Client
- TypeScript 5+
- Vite (build tool)
- `libdpf` — TypeScript DPF implementation
- `hash.js` — RIPEMD160 and SHA256

## Security Model

### Privacy Guarantees
- **Two-server model**: Privacy is guaranteed if at least one server is honest
- **DPF-based queries**: Each server receives a different DPF key; neither can reconstruct the query alone
- **No query logging**: The library does not log query details

### Requirements
- Servers MUST NOT collude — use different hosting providers
- Enable TLS in production
- Keep database files synchronized between servers

## Performance

| Operation | Latency | Notes |
|-----------|---------|-------|
| Cuckoo Index Query | ~10–50ms | Memory-mapped access |
| Chunk Query | ~10–50ms | Direct index lookup |
| Full UTXO Lookup | ~50–150ms | Both queries combined |

## Documentation

- [`doc/DEPLOYMENT.md`](doc/DEPLOYMENT.md) — Production deployment guide
- [`doc/WEB.md`](doc/WEB.md) — WebSocket protocol and web client details
- [`web/`](web/) — Web client

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## References

- [Private Information Retrieval](https://en.wikipedia.org/wiki/Private_information_retrieval)
- [Distributed Point Functions](https://eprint.iacr.org/2013/679.pdf)
- [Bitcoin UTXO Model](https://developer.bitcoin.org/devguide/transactions.html)
- [Cuckoo Hashing](https://en.wikipedia.org/wiki/Cuckoo_hashing)
