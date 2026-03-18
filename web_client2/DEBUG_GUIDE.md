# Debugging Connection Issues - Log Location Guide

## Where to Find Logs

### 1. Browser Console (Primary Debug Location)
**All detailed connection logs from `client.ts` appear here**

**How to open:**
- **Chrome/Edge**: Press `F12` or `Ctrl+Shift+I` (Windows) / `Cmd+Option+I` (Mac), then click "Console" tab
- **Firefox**: Press `F12` or `Ctrl+Shift+K` (Windows) / `Cmd+Option+K` (Mac)
- **Safari**: Enable Developer menu in Preferences, then press `Cmd+Option+C`

**What you'll see:**
```
[DEBUG] Main connect(): Starting parallel connection to both servers
[DEBUG] [SERVER 1] Step 1: Starting connection to ws://localhost:8091
[DEBUG] [SERVER 1] Step 2: WebSocket object created successfully
[DEBUG] [SERVER 1] Step 3: Creating event handlers
[DEBUG] [SERVER 1] Step 4: Event handlers registered, waiting for connection...
[DEBUG] [SERVER 2] Step 1: Starting connection to ws://localhost:8092
...
```

### 2. On-Page Log (Secondary Location)
**Logs from `index.html` appear in the black log box on the webpage**

**What you'll see:**
```
[DEBUG] Starting connection process...
[DEBUG] Creating PIR client with URLs:
[DEBUG] Connection failed with error:
```

## Why Logs Might Not Appear

### Possible Reasons:

1. **Looking at wrong place**
   - If you only see on-page logs but not console logs, you need to open the browser console
   - `client.ts` uses `console.log()` → Browser Console
   - `index.html` uses custom `log()` function → On-page log box

2. **Critical error before logging**
   - If JavaScript fails to load or there's a syntax error, logs won't execute
   - Check for any red error messages in the console

3. **Async/await timing**
   - While async/await itself doesn't block console.log(), errors might occur before logs complete
   - Added try-catch blocks to ensure errors are logged

4. **WebSocket constructor fails immediately**
   - Invalid URL format
   - Browser doesn't support WebSocket
   - Network restrictions
   - These would show up in Step 1 or Step 2 logs

## Expected Log Flow (Successful Connection)

```
1. Browser Console:
   [DEBUG] Main connect(): Starting parallel connection to both servers
   [DEBUG] [SERVER 1] Step 1: Starting connection to ws://localhost:8091
   [DEBUG] [SERVER 1] Step 2: WebSocket object created successfully
   [DEBUG] [SERVER 1] Step 3: Creating event handlers
   [DEBUG] [SERVER 1] Step 4: Event handlers registered, waiting for connection...
   [DEBUG] [SERVER 2] Step 1: Starting connection to ws://localhost:8092
   [DEBUG] [SERVER 2] Step 2: WebSocket object created successfully
   [DEBUG] [SERVER 2] Step 3: Creating event handlers
   [DEBUG] [SERVER 2] Step 4: Event handlers registered, waiting for connection...
   [DEBUG] [SERVER 1] Step 5: onopen event fired! Connection successful!
   [DEBUG] [SERVER 1] Step 6: Resolving connection promise
   [DEBUG] [SERVER 2] Step 5: onopen event fired! Connection successful!
   [DEBUG] [SERVER 2] Step 6: Resolving connection promise
   [DEBUG] Main connect(): Both connections completed successfully

2. On-Page Log:
   [DEBUG] Starting connection process...
   [DEBUG] Creating PIR client with URLs:
   [DEBUG]   Server 1: ws://localhost:8091
   [DEBUG]   Server 2: ws://localhost:8092
   [DEBUG] Client object created, initiating connect() call...
   [DEBUG] client.connect() completed successfully!
   Successfully connected to both servers!
```

## Expected Log Flow (Connection Failed)

```
1. Browser Console:
   [DEBUG] Main connect(): Starting parallel connection to both servers
   [DEBUG] [SERVER 1] Step 1: Starting connection to ws://localhost:8091
   [DEBUG] [SERVER 1] Step 2: WebSocket object created successfully
   ...
   [DEBUG] [SERVER 1] Step ERROR: onerror fired! Connection failed.
   [DEBUG] [SERVER 1] Error details: {type: 'error', url: 'ws://localhost:8091', ...}
   [DEBUG] Main connect(): Connection failed with error: Error: ...

2. On-Page Log:
   [DEBUG] Starting connection process...
   [DEBUG] Connection failed with error:
   [DEBUG] Error type: Error
   [DEBUG] Error message: Failed to connect to server 1...
   Connection failed: Failed to connect to server 1...
```

## Troubleshooting Steps

1. **Open browser console first** - This is where the real debug information is
2. **Click "Connect" button** - Watch logs appear in real-time
3. **Note where logs stop** - This tells you exactly where the failure occurred
4. **Check error details** - Look for:
   - WebSocket readyState (should be 0=CONNECTING initially)
   - Error messages
   - Close codes (if connection was rejected)

## Common Error Scenarios

### No logs appear at all:
- JavaScript error preventing code execution
- Browser doesn't support WebSocket
- Network security settings blocking connections

### Logs stop at Step 1/2:
- Invalid URL format
- WebSocket constructor failing
- Network restrictions

### Logs stop at Step 4 (waiting):
- Server not running
- Wrong port
- Firewall blocking connection
- Server rejecting connection

### Logs show Step ERROR:
- Server refused connection
- Network error
- Protocol mismatch
- Check error details for specific cause