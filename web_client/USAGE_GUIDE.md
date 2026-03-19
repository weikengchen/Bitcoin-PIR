# Bitcoin PIR Web Client — Usage Guide

## Setup

### Installation

```bash
cd web_client
npm install
```

### Development Server (Browser)

```bash
npx vite --port 8080
```

Opens a dev server at `http://localhost:8080` with hot-reload.

### Production Build (Browser)

```bash
npm run build-web
```

Creates an optimized build in `dist-web/` for deployment (e.g., GitHub Pages).

### Build for Node.js

```bash
npm run build
```

Compiles TypeScript to JavaScript in `dist/`.

## Running the Demo

### 1. Start PIR Servers

From the repository root:

```bash
./scripts/start_pir_servers.sh
```

This starts two WebSocket servers:
- Server 1: `ws://localhost:8091`
- Server 2: `ws://localhost:8092`

### 2. Start the Web Client

```bash
cd web_client
npx vite --port 8080
```

### 3. Open Browser

Navigate to `http://localhost:8080`

1. Enter server URLs (defaults: `ws://localhost:8091` and `ws://localhost:8092`)
2. Click **Connect**
3. Enter a Bitcoin scriptPubKey hex string (e.g., `76a914...88ac`)
4. Click **Lookup**

## Query Flow

1. **HASH160**: Computes RIPEMD160(SHA256(scriptPubKey)) — 20 bytes
2. **Cuckoo locations**: Two bucket indices from the HASH160
3. **Phase 1**: PIR query to cuckoo index → byte offset in chunks file
4. **Phase 2**: PIR query to chunks database → 32KB chunk containing UTXO data
5. **Results**: Full 32-byte TXIDs displayed as clickable mempool.space links

## Troubleshooting

### Connection Issues

- Ensure PIR servers are running: `./scripts/start_pir_servers.sh`
- Check WebSocket URLs (default: `ws://localhost:8091` and `ws://localhost:8092`)
- Open browser console (F12) for detailed connection logs

### Import Errors in Browser

- Always use the Vite dev server (`npx vite`), not `file://` or a plain HTTP server
- Vite handles TypeScript compilation and module bundling

### "Unexpected response type" Errors

- This was a known race condition with heartbeat pongs — fixed in the current codebase
- If you see this, ensure you're running the latest version of `client.ts`

### Production Deployment

- Build with `npm run build-web` and deploy `dist-web/`
- For HTTPS pages, WebSocket servers must use `wss://` (see [DEPLOYMENT.md](../doc/DEPLOYMENT.md))
