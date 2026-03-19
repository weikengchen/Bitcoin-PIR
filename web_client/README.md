# Bitcoin PIR Web Client

A TypeScript client library for querying the Bitcoin UTXO set using Private Information Retrieval (PIR) via WebSocket.

## Features

- **Web-compatible**: Works in browsers and Node.js
- **Privacy-preserving**: Server learns nothing about which addresses you're querying
- **DPF-based**: Uses Distributed Point Functions for privacy
- **Real-time**: WebSocket protocol for efficient communication
- **TypeScript**: Full TypeScript support with type definitions

## Installation

```bash
cd web_client
npm install
```

## Development

```bash
# Start Vite dev server (browser, with hot-reload)
npx vite --port 8080

# Build TypeScript for Node.js
npm run build

# Build for production deployment (outputs to dist-web/)
npm run build-web
```

## Usage

### Browser Demo

1. Start PIR servers: `./scripts/start_pir_servers.sh` (from repo root)
2. Start dev server: `npx vite --port 8080`
3. Open `http://localhost:8080` in your browser
4. Enter server URLs and connect
5. Enter a Bitcoin scriptPubKey hex to query

### Programmatic Usage

```typescript
import {
  createPirClient,
  hexToBytes,
  cuckooHash1,
  cuckooHash2,
  CUCKOO_NUM_BUCKETS,
  CUCKOO_DB_ID,
  CHUNKS_DB_ID
} from './src/index.ts';

// Create and connect client
const client = createPirClient('ws://localhost:8091', 'ws://localhost:8092');
await client.connect();

// Test connection
const { pong1, pong2 } = await client.ping();

// List available databases
const dbList = await client.listDatabases(1);
console.log('Databases:', dbList);

// Disconnect when done
client.disconnect();
```

## API Reference

### PirClient

#### `createPirClient(server1Url, server2Url): PirClient`
Creates a new PIR client.

#### Methods

- `connect(): Promise<void>` — Connect to both servers
- `disconnect(): void` — Disconnect from both servers
- `isConnected(): boolean` — Check connection status
- `ping(): Promise<{ pong1, pong2 }>` — Test connectivity
- `listDatabases(serverNum: 1 | 2): Promise<Response>` — List databases
- `getDatabaseInfo(serverNum, databaseId): Promise<Response>` — Get database info
- `queryDatabase(databaseId, index1, index2, n?): Promise<{ response1, response2 }>` — Two-location PIR query
- `queryDatabaseSingle(databaseId, index, n?): Promise<{ response1, response2 }>` — Single-location PIR query

### Hash Functions

```typescript
import {
  scriptHash,      // HASH160 = RIPEMD160(SHA256(script))
  ripemd160,       // RIPEMD160
  sha256,          // SHA256
  cuckooHash1,     // Cuckoo hash function 1
  cuckooHash2,     // Cuckoo hash function 2
  cuckooLocations, // Both cuckoo locations
  hexToBytes,
  bytesToHex,
  reverseBytes
} from './src/index.ts';
```

### Constants

```typescript
import {
  CUCKOO_DB_ID,        // "utxo_cuckoo_index"
  CHUNKS_DB_ID,        // "utxo_chunks_data"
  CUCKOO_NUM_BUCKETS,  // 15,385,139
  CHUNKS_NUM_ENTRIES,  // 181,833
  CHUNK_SIZE,          // 32,768
  WS_SERVER1_PORT,     // 8091
  WS_SERVER2_PORT      // 8092
} from './src/constants.ts';
```

## Two-Phase Query Flow

1. **Compute HASH160**: RIPEMD160(SHA256(scriptPubKey))
2. **Cuckoo hash**: Compute two bucket locations
3. **Phase 1 — Query cuckoo index**: PIR query to get chunk byte offset
4. **Phase 2 — Query chunks**: PIR query to retrieve 32KB chunk with UTXO data
5. **Parse results**: Full 32-byte TXIDs displayed as clickable mempool.space links

## Project Structure

```
web_client/
├── src/
│   ├── index.ts        # Main exports
│   ├── client.ts       # WebSocket PIR client
│   ├── dpf.ts          # DPF key generation wrapper
│   ├── hash.ts         # HASH160, cuckoo hash functions
│   ├── constants.ts    # Database IDs and parameters
│   ├── bincode.ts      # Binary serialization
│   ├── sbp.ts          # Simple Binary Protocol codec
│   └── polyfills.ts    # Browser compatibility
├── dist/               # Compiled JS (Node.js)
├── dist-web/           # Bundled for production
├── index.html          # Demo page
├── vite.config.js      # Vite build configuration
├── tsconfig.json
└── package.json
```

## Dependencies

- **libdpf** — TypeScript DPF implementation
- **hash.js** — RIPEMD160 and SHA256
- **buffer** — Browser Buffer polyfill
- **Vite** — Build tool and dev server
- **TypeScript** — Type safety

## License

MIT
