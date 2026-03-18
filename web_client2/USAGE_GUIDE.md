# Bitcoin PIR Web Client - Usage Guide

## Overview

This is a JavaScript/TypeScript implementation of a client for the Bitcoin PIR (Private Information Retrieval) system. It allows browsers and Node.js applications to query the Bitcoin UTXO set privately.

## Setup

### Installation

```bash
cd web_client
npm install
```

### Build for Node.js

```bash
npm run build
```

This compiles TypeScript to JavaScript in the `dist/` directory for Node.js usage.

### Development Server (Browser)

```bash
npm run dev
```

This starts Vite dev server at `http://localhost:3000` with hot-reload enabled.

### Production Build (Browser)

```bash
npm run build-web
```

This creates an optimized build in `dist-web/` for deployment.

## Running the Demo

### 1. Start PIR Servers

In the root directory:

```bash
./scripts/start_pir_servers.sh
```

This starts two WebSocket servers:
- Server 1: `ws://localhost:8091`
- Server 2: `ws://localhost:8092`

### 2. Start the Web Demo

In the `web_client` directory:

```bash
npm run dev
```

### 3. Open Browser

Navigate to `http://localhost:3000`

## Usage Examples

### Browser (ES Modules)

```javascript
import { createPirClient, hexToBytes, cuckooHash1, cuckooHash2, CUCKOO_NUM_BUCKETS } from './src/index.js';

// Create client
const client = createPirClient('ws://localhost:8091', 'ws://localhost:8092');

// Connect
await client.connect();

// Test connection
const { pong1, pong2 } = await client.ping();

// Query by script hash
const scriptHashHex = '76a914...88ac';
const scriptHash = hexToBytes(scriptHashHex);

// Compute cuckoo locations
const loc1 = cuckooHash1(scriptHash, CUCKOO_NUM_BUCKETS);
const loc2 = cuckooHash2(scriptHash, CUCKOO_NUM_BUCKETS);

// ... perform PIR query with DPF keys
```

### Node.js

```javascript
import { createPirClient, hexToBytes } from './dist/index.js';

// Same API as browser
const client = createPirClient('ws://localhost:8091', 'ws://localhost:8092');
await client.connect();
```

## API Reference

### PirClient

#### Constructor

```typescript
createPirClient(server1Url: string, server2Url: string): PirClient
```

Creates a new PIR client connected to two servers.

#### Methods

- `connect(): Promise<void>` - Connect to both servers
- `disconnect(): void` - Disconnect from servers
- `ping(): Promise<{pong1: Pong, pong2: Pong}>` - Test connectivity
- `listDatabases(server: 1 | 2): Promise<DatabaseInfo[]>` - List available databases
- `sendRequest(server: 1 | 2, request: Request): Promise<Response>` - Send custom request

### Constants

- `CUCKOO_DB_ID` - Cuckoo index database ID
- `CHUNKS_DB_ID` - Chunks database ID
- `TXID_MAPPING_DB_ID` - TXID mapping database ID
- `CUCKOO_NUM_BUCKETS` - Number of cuckoo buckets (15,385,139)
- `CHUNK_SIZE` - Size of each chunk (32 KB)

### Hash Functions

- `cuckooHash1(key: Uint8Array, numBuckets: number): number`
- `cuckooHash2(key: Uint8Array, numBuckets: number): number`
- `cuckooLocations(key: Uint8Array, numBuckets: number): [number, number]`
- `txidMappingHash1(key: Uint8Array, numBuckets: number): number`
- `txidMappingHash2(key: Uint8Array, numBuckets: number): number`
- `hexToBytes(hex: string): Uint8Array`
- `bytesToHex(bytes: Uint8Array): string`

## PIR Query Flow

1. **Compute Script Hash**: Convert Bitcoin address to script hash
2. **Cuckoo Hash**: Compute two possible bucket locations
3. **Generate DPF Keys**: Create keys for each location
4. **Query Cuckoo Index**: Get location in chunks database
5. **Query Chunks**: Get UTXO data
6. **Query TXID Mapping**: Get full transaction data

## Troubleshooting

### Connection Issues

- Ensure PIR servers are running: `./scripts/start_pir_servers.sh`
- Check WebSocket URLs (default: `ws://localhost:8091` and `ws://localhost:8092`)
- Check browser console for errors

### Import Errors in Browser

- Use Vite dev server: `npm run dev`
- Don't open `index.html` directly (file:// protocol)
- Vite handles module resolution and bundling

### TypeScript Compilation Errors

```bash
npm run build
```

Check for type errors and fix as needed.

## Project Structure

```
web_client/
├── src/
│   ├── bincode.ts       # Binary serialization
│   ├── client.ts        # WebSocket client
│   ├── constants.ts     # Configuration
│   ├── dpf.ts          # DPF wrapper
│   ├── hash.ts         # Hash functions
│   └── index.ts        # Main exports
├── dist/              # Compiled JS (Node.js)
├── dist-web/          # Bundled for production
├── index.html         # Demo page
├── package.json
├── tsconfig.json
└── vite.config.js
```

## Dependencies

- **libdpf** - TypeScript DPF implementation
- **TypeScript** - Type safety
- **Vite** - Build tool for browser

## License

MIT