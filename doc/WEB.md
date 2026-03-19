# Web Client & WebSocket Protocol

## Overview

The PIR system uses WebSocket for all client-server communication. This enables direct browser connections without any intermediary.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PIR Server                               │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              WebSocket Listener (Port 8091/8092)         │   │
│  │                                                          │   │
│  │  For Browser/JS Clients and Rust Clients                │   │
│  │  - Persistent connection                                │   │
│  │  - Multiple queries per conn                            │   │
│  │  - Simple Binary Protocol                               │   │
│  └───────────────────────────┬─────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│           ┌─────────────────────────────────┐                  │
│           │      Query Handler              │                  │
│           │  - Parse Request                │                  │
│           │  - Evaluate DPF                 │                  │
│           │  - XOR buckets                  │                  │
│           │  - Return Response              │                  │
│           └─────────────────────────────────┘                  │
│                              │                                  │
│                              ▼                                  │
│           ┌─────────────────────────────────┐                  │
│           │      Database Registry          │                  │
│           │  - utxo_cuckoo_index            │                  │
│           │  - utxo_chunks_data             │                  │
│           └─────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

## File Structure

```
runtime/src/
├── bin/
│   ├── server.rs          # WebSocket server
│   └── client.rs          # WebSocket CLI client
├── eval.rs                # DPF evaluation engine
├── protocol.rs            # Binary protocol codec
└── lib.rs                 # Module exports

web/src/
├── client.ts              # Browser WebSocket PIR client
├── dpf.ts                 # DPF key generation
├── hash.ts                # HASH160, cuckoo hash functions
├── constants.ts           # Database IDs and parameters
├── bincode.ts             # Binary serialization
├── sbp.ts                 # Simple Binary Protocol codec
└── index.ts               # Main entry point
```

## Running the System

### Start Servers

```bash
./scripts/start_pir_servers.sh
```

This starts two WebSocket servers:
- Server 1: `ws://localhost:8091`
- Server 2: `ws://localhost:8092`

### Web Client (Development)

```bash
cd web
npm install
npx vite --port 8080
```

### Web Client (Production Build)

```bash
cd web
npm run build-web
# Output in dist-web/, deploy to static hosting
```

## WebSocket Protocol

### Message Format

All messages use the Simple Binary Protocol (SBP) — a compact binary format:

**Request Types:**
- `Ping` — `[0x01]`
- `ListDatabases` — `[0x03]`
- `GetDatabaseInfo` — `[0x05][db_id_len:u16][db_id:bytes]`
- `QueryDatabaseSingle` — `[0x07][query_data...]`
- `QueryDatabase` — `[0x07][query_data...]` (two DPF keys)

**Response Types:**
- `Pong` — `[0x02]`
- `DatabaseList` — `[0x04][count:u32][entries...]`
- `DatabaseInfo` — `[0x06][info_data...]`
- `QueryResult` — `[0x08][response_data...]`
- `Error` — `[0xFF][error_message]`

### Connection Lifecycle

```
Client                          Server
  │                               │
  │──── WebSocket Handshake ────▶│
  │                               │
  │──── Ping ────────────────────▶│
  │◀─── Pong ─────────────────────│
  │                               │
  │──── Query (DPF key) ────────▶│
  │◀─── QueryResult ──────────────│
  │         ...                   │
  │                               │
  │──── Close Frame ─────────────▶│
  │◀─── Close Frame ──────────────│
```

### Heartbeat

The web client sends periodic Ping messages to keep connections alive. Pong responses are handled by a central message dispatcher that routes them separately from query responses, preventing race conditions.

## Two-Phase PIR Query

### Phase 1: Cuckoo Index Lookup

1. Client computes HASH160 = RIPEMD160(SHA256(scriptPubKey))
2. Client computes two cuckoo bucket locations from the HASH160
3. Client generates DPF keys targeting both locations
4. Each server evaluates its DPF key across all buckets and XORs matching entries
5. Client XORs both server responses to recover the bucket contents
6. Client searches the bucket for the matching 20-byte HASH160 key
7. The associated 4-byte value is the chunk offset (stored as byte_offset / 2)

### Phase 2: Chunk Data Retrieval

1. Client computes chunk_index = (offset * 2) / 32768
2. Client generates DPF keys for the chunk index
3. Servers evaluate and return XOR'd chunk data
4. Client XORs responses to recover the 32KB chunk
5. Client seeks to local_offset = (offset * 2) % 32768 within the chunk
6. Client reads varint-encoded UTXO entries: [count][32B TXID + varint vout + varint amount] × count

### Whale Address Detection

If `entry_count == 0` (varint 0), the address is a "whale" excluded from the `--small` database variant. The client displays a notification instead of UTXO data.

## Key Constants

```typescript
// Database IDs
CUCKOO_DB_ID = "utxo_cuckoo_index"
CHUNKS_DB_ID = "utxo_chunks_data"

// Database parameters
CUCKOO_NUM_BUCKETS = 15_385_139
CUCKOO_ENTRY_SIZE = 24        // 20B key + 4B offset
CUCKOO_BUCKET_SIZE = 4
CHUNK_SIZE = 32_768            // 32KB
CHUNKS_NUM_ENTRIES = 181_833   // normal (65_294 for small)
```

## Implementation Checklist

- [x] WebSocket server (`server.rs`)
- [x] WebSocket CLI client (`lookup_pir.rs`)
- [x] WebSocket protocol handler (`websocket.rs`)
- [x] Server startup script (`start_pir_servers.sh`)
- [x] Test script (`test_lookup_pir.sh`)
- [x] TypeScript web client library
- [x] Browser demo page with Vite bundling
- [x] GitHub Pages deployment via GitHub Actions
- [x] TLS support (native + Cloudflare Tunnel)
- [x] Heartbeat with race-condition-safe message dispatch
