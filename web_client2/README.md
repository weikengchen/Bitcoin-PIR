# Bitcoin PIR Web Client

A JavaScript/TypeScript client library for querying the Bitcoin UTXO set using Private Information Retrieval (PIR) via WebSocket.

## Features

- 🌐 **Web-compatible**: Works in browsers and Node.js
- 🔒 **Privacy-preserving**: Server learns nothing about which addresses you're querying
- 🔐 **DPF-based**: Uses Distributed Point Functions for privacy
- ⚡ **Real-time**: WebSocket protocol for efficient communication
- 📦 **TypeScript**: Full TypeScript support with type definitions

## Installation

```bash
# Clone the repository
git clone https://github.com/weikengchen/Bitcoin-PIR.git
cd Bitcoin-PIR/web_client

# Install dependencies
npm install

# If npm install fails with libdpf, try:
npm install https://github.com/weikengchen/libdpf.git

# Or install libdpf separately first:
npm install weikengchen/libdpf
npm install

# Build the library
npm run build
```

**Note**: The `libdpf` library is installed from GitHub. If you encounter issues, make sure you have Git installed and can access GitHub.

## Usage

### Basic Example

```typescript
import { createPirClient } from './dist/index.js';

// Create client with default server URLs
const client = createPirClient(
  'ws://localhost:8091',  // Server 1
  'ws://localhost:8092'   // Server 2
);

// Connect to both servers
await client.connect();

// Send a ping to test connection
const { pong1, pong2 } = await client.ping();
console.log('Server 1:', pong1);
console.log('Server 2:', pong2);

// List available databases
const dbList = await client.listDatabases(1);
console.log('Databases:', dbList);

// Disconnect when done
client.disconnect();
```

### Query by Script Hash

```typescript
import { 
  createPirClient, 
  hexToBytes, 
  cuckooHash1, 
  cuckooHash2,
  CUCKOO_NUM_BUCKETS 
} from './dist/index.js';

const client = createPirClient();
await client.connect();

// Convert hex script hash to bytes
const scriptHash = hexToBytes('76a914...88ac');

// Compute cuckoo hash locations
const loc1 = cuckooHash1(scriptHash, CUCKOO_NUM_BUCKETS);
const loc2 = cuckooHash2(scriptHash, CUCKOO_NUM_BUCKETS);

console.log(`Locations: ${loc1}, ${loc2}`);

// Query the cuckoo database
const result = await client.queryDatabase(
  'utxo_cuckoo_index',
  loc1,
  loc2,
  24  // DPF parameter n
);

console.log('Query result:', result);
```

### Browser Demo

Open `example.html` in a web browser (requires a local web server due to CORS):

```bash
# Using Python 3
python -m http.server 8000

# Or using Node.js
npx serve .
```

Then navigate to `http://localhost:8000/example.html`

## API Reference

### `PirClient`

The main client class for interacting with PIR servers.

#### Constructor

```typescript
const client = new PirClient({
  server1Url: string,  // WebSocket URL for server 1
  server2Url: string   // WebSocket URL for server 2
});
```

#### Methods

##### `connect(): Promise<void>`
Connect to both PIR servers.

##### `disconnect(): void`
Disconnect from both servers.

##### `isConnected(): boolean`
Check if connected to both servers.

##### `ping(): Promise<{ pong1: Response; pong2: Response }>`
Send a ping to both servers.

##### `listDatabases(serverNum: 1 | 2): Promise<Response>`
List available databases on a specific server.

##### `getDatabaseInfo(serverNum: 1 | 2, databaseId: string): Promise<Response>`
Get information about a specific database.

##### `queryDatabase(databaseId: string, index1: number, index2: number, n?: number): Promise<{ response1: Response; response2: Response }>`
Query a database on both servers using DPF keys.

##### `queryDatabaseSingle(databaseId: string, index: number, n?: number): Promise<{ response1: Response; response2: Response }>`
Query a single-location database on both servers.

### Hash Functions

```typescript
import { 
  cuckooHash1, 
  cuckooHash2, 
  cuckooLocations,
  txidMappingHash1,
  txidMappingHash2,
  txidMappingLocations 
} from './dist/index.js';

// Compute cuckoo hash locations
const loc1 = cuckooHash1(key, numBuckets);
const loc2 = cuckooHash2(key, numBuckets);
const [loc1, loc2] = cuckooLocations(key, numBuckets);

// Compute TXID mapping locations
const [loc1, loc2] = txidMappingLocations(key, numBuckets);
```

### Utility Functions

```typescript
import { 
  hexToBytes, 
  bytesToHex, 
  reverseBytes,
  ripemd160,
  scriptHash 
} from './dist/index.js';

// Convert hex to bytes
const bytes = hexToBytes('deadbeef');

// Convert bytes to hex
const hex = bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));

// Reverse byte array (for Bitcoin TXIDs)
const reversed = reverseBytes(bytes);

// Compute RIPEMD160 hash
const hash = await ripemd160(data);

// Compute script hash from scriptPubkey
const hash = await scriptHash(scriptPubkey);
```

### Constants

```typescript
import {
  CUCKOO_DB_ID,
  CHUNKS_DB_ID,
  TXID_MAPPING_DB_ID,
  CUCKOO_NUM_BUCKETS,
  CHUNKS_NUM_ENTRIES,
  TXID_MAPPING_NUM_BUCKETS,
  CHUNK_SIZE,
  WS_SERVER1_PORT,
  WS_SERVER2_PORT
} from './dist/index.js';
```

## Architecture

The Bitcoin PIR system consists of three main databases:

1. **UTXO Cuckoo Index** (`utxo_cuckoo_index`)
   - Maps script hashes to UTXO chunk indices
   - Uses cuckoo hashing with 2 locations
   - 15,385,139 buckets

2. **UTXO Chunks Data** (`utxo_chunks_data`)
   - Contains UTXO data in 32KB chunks
   - Direct index lookup
   - 33,032 entries

3. **TXID Mapping** (`utxo_4b_to_32b`)
   - Maps 4-byte TXID prefixes to full 32-byte TXIDs
   - Uses cuckoo hashing with 4 entries per bucket
   - 30,097,234 buckets

## Query Flow

1. **Hash scriptPubkey** → Compute RIPEMD160 hash
2. **Compute cuckoo locations** → Get 2 bucket indices
3. **Query cuckoo index** → Get chunk indices using PIR
4. **Query chunks** → Get UTXO data using PIR
5. **Combine results** → XOR responses from both servers
6. **Query TXID mapping** (if needed) → Get full TXID

## Development

```bash
# Build TypeScript
npm run build

# Watch mode for development
npm run dev

# Run tests
npm test
```

## Security Considerations

- **Privacy**: DPF ensures the server cannot determine which indices you're querying
- **Integrity**: Responses from both servers are XOR'd, preventing tampering by a single server
- **No logging**: The library does not log query details

## Requirements

- Node.js 18+ or modern browser
- WebSocket support
- TypeScript 5+ (for development)

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Related Projects

- [Bitcoin PIR Server](https://github.com/weikengchen/Bitcoin-PIR) - Rust implementation of the PIR server
- [libdpf](https://github.com/weikengchen/libdpf) - DPF library for privacy-preserving queries