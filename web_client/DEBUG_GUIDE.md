# Debugging Connection Issues

## Where to Find Logs

### 1. Browser Console (Primary)

All detailed connection logs from `client.ts` appear here.

**How to open:**
- **Chrome/Edge**: `F12` or `Ctrl+Shift+I` / `Cmd+Option+I`, then "Console" tab
- **Firefox**: `F12` or `Ctrl+Shift+K` / `Cmd+Option+K`
- **Safari**: Enable Developer menu in Preferences, then `Cmd+Option+C`

### 2. On-Page Log (Secondary)

High-level status messages appear in the black log box on the webpage.

## Expected Log Flow (Successful Connection)

```
Browser Console:
  [DEBUG] Main connect(): Starting parallel connection to both servers
  [DEBUG] [SERVER 1] Step 1: Starting connection to ws://localhost:8091
  [DEBUG] [SERVER 1] Step 2: WebSocket object created successfully
  [DEBUG] [SERVER 1] Step 5: onopen event fired! Connection successful!
  [DEBUG] [SERVER 2] Step 5: onopen event fired! Connection successful!
  [DEBUG] Main connect(): Both connections completed successfully
```

## Troubleshooting

### No logs appear at all
- JavaScript error preventing code execution — check for red errors in console
- Make sure you're using Vite dev server, not opening `index.html` directly

### Connection hangs (logs stop at "waiting")
- Server not running — start with `./scripts/start_pir_servers.sh`
- Wrong port or URL
- Firewall blocking connection

### "Unexpected response type" from query
- Fixed in current codebase (was a heartbeat/query race condition)
- Ensure you're running the latest `client.ts`

### Mixed content errors
- HTTPS page requires `wss://` WebSocket URLs, not `ws://`
- See [DEPLOYMENT.md](../doc/DEPLOYMENT.md) for TLS setup options

### Server crashes on query
- Check server logs: `/tmp/pir_server1.log` and `/tmp/pir_server2.log`
- Verify database files exist and paths match `server_config.rs`
- Ensure sufficient RAM (databases load into memory)
