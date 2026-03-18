/**
 * WebSocket client for Bitcoin PIR system
 *
 * Handles communication with PIR servers via WebSocket protocol
 */

import { encodeRequest, decodeResponse, Request, Response } from './sbp.js';
import { createDpf } from './dpf.js';
import {
  CUCKOO_NUM_BUCKETS,
  CHUNKS_NUM_ENTRIES,
  CHUNK_SIZE,
  KEY_SIZE,
} from './constants.js';

// Re-export Request and Response types
export type { Request, Response } from './sbp.js';

/**
 * A parsed UTXO entry
 */
export interface UtxoEntry {
  txid: Uint8Array;  // 32-byte raw TXID
  vout: number;
  amount: bigint;
}

/**
 * UTXO pagination state
 */
export interface UtxoPaginationState {
  scriptHash: Uint8Array;
  startOffset: number;       // Starting offset in chunks file
  totalEntries: bigint;      // Total number of UTXOs
  entries: UtxoEntry[];      // Cached entries
  currentChunkIndex: number; // Current chunk being read
  localOffset: number;       // Current position within the chunk
  entriesRead: number;       // Number of entries read so far
  chunksData: Map<number, Uint8Array>;  // Cached chunk data
  isWhale: boolean;          // True if address has too many UTXOs for lightweight DB
}

/**
 * Connection state enum
 */
export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting';

/**
 * Reconnection configuration
 */
export interface ReconnectConfig {
  enabled: boolean;           // Enable auto-reconnection
  maxAttempts: number;        // Max reconnection attempts (0 = infinite)
  initialDelay: number;       // Initial delay in ms
  maxDelay: number;           // Max delay in ms
  backoffFactor: number;      // Backoff multiplier
  heartbeatInterval: number;  // Heartbeat ping interval in ms (0 = disabled)
  heartbeatTimeout: number;   // Time to wait for pong response in ms
}

/**
 * PIR client configuration
 */
export interface PirClientConfig {
  server1Url: string;
  server2Url: string;
  reconnect?: Partial<ReconnectConfig>;
  onConnectionStateChange?: (state: ConnectionState, message?: string) => void;
}

/**
 * Default reconnection configuration
 */
const DEFAULT_RECONNECT_CONFIG: ReconnectConfig = {
  enabled: true,
  maxAttempts: 0,           // 0 = infinite
  initialDelay: 1000,       // 1 second
  maxDelay: 30000,          // 30 seconds
  backoffFactor: 2,         // Double the delay each time
  heartbeatInterval: 30000, // 30 seconds
  heartbeatTimeout: 10000,  // 10 seconds
};

/**
 * PIR WebSocket client
 */
export class PirClient {
  private ws1: WebSocket | null = null;
  private ws2: WebSocket | null = null;
  private config: PirClientConfig;
  private reconnectConfig: ReconnectConfig;
  private dpf = createDpf();
  private pendingResponses: Map<1 | 2, Array<(response: Response) => void>> = new Map();
  private requestCounter = 0;

  // Reconnection state
  private connectionState: ConnectionState = 'disconnected';
  private reconnectAttempts = 0;
  private reconnectTimers: Map<1 | 2, ReturnType<typeof setTimeout>> = new Map();
  private isIntentionalDisconnect = false;

  // Heartbeat state
  private heartbeatTimers: Map<1 | 2, ReturnType<typeof setInterval>> = new Map();
  private heartbeatTimeoutTimers: Map<1 | 2, ReturnType<typeof setTimeout>> = new Map();
  private lastPongTime: Map<1 | 2, number> = new Map();

  constructor(config: PirClientConfig) {
    this.config = config;
    this.reconnectConfig = { ...DEFAULT_RECONNECT_CONFIG, ...config.reconnect };
    this.pendingResponses.set(1, []);
    this.pendingResponses.set(2, []);
  }

  /**
   * Central message handler for a server's WebSocket.
   * Routes responses to pending request callbacks in FIFO order.
   * Pong responses from heartbeats are handled inline without consuming a pending callback.
   */
  private handleMessage(serverNum: 1 | 2, event: MessageEvent): void {
    try {
      const response = decodeResponse(new Uint8Array(event.data));

      // Handle heartbeat pongs without consuming a pending request callback
      if ('Pong' in response) {
        clearTimeout(this.heartbeatTimeoutTimers.get(serverNum));
        this.heartbeatTimeoutTimers.delete(serverNum);
        this.lastPongTime.set(serverNum, Date.now());
        console.log(`[HEARTBEAT] Server ${serverNum} pong received`);
        return;
      }

      // Route to the next pending request callback (FIFO)
      const queue = this.pendingResponses.get(serverNum)!;
      const callback = queue.shift();
      if (callback) {
        callback(response);
      } else {
        console.warn(`[PIR] Received unexpected response from server ${serverNum} with no pending request`);
      }
    } catch (error) {
      console.error(`[PIR] Failed to decode response from server ${serverNum}:`, error);
      // Reject the oldest pending request
      const queue = this.pendingResponses.get(serverNum)!;
      const callback = queue.shift();
      if (callback) {
        // Can't reject a resolve callback, but at least clear it
        // The timeout will handle rejection
      }
    }
  }

  /**
   * Get current connection state
   */
  getConnectionState(): ConnectionState {
    return this.connectionState;
  }

  /**
   * Update connection state and notify callback
   */
  private setConnectionState(state: ConnectionState, message?: string): void {
    this.connectionState = state;
    if (this.config.onConnectionStateChange) {
      this.config.onConnectionStateChange(state, message);
    }
  }

  /**
   * Connect to both servers
   */
  async connect(): Promise<void> {
    this.isIntentionalDisconnect = false;
    this.setConnectionState('connecting', 'Connecting to servers...');

    console.log(`[DEBUG] Main connect(): Starting parallel connection to both servers`);
    try {
      await Promise.all([
        this.connectToServer(1),
        this.connectToServer(2),
      ]);
      console.log(`[DEBUG] Main connect(): Both connections completed successfully`);

      // Reset reconnect attempts on successful connection
      this.reconnectAttempts = 0;
      this.setConnectionState('connected', 'Connected to both servers');

      // Start heartbeat if enabled
      if (this.reconnectConfig.heartbeatInterval > 0) {
        this.startHeartbeat(1);
        this.startHeartbeat(2);
      }
    } catch (error) {
      console.log(`[DEBUG] Main connect(): Connection failed with error:`, error);
      this.setConnectionState('disconnected', `Connection failed: ${error}`);
      throw error;
    }
  }

  /**
   * Connect to a specific server
   */
  private async connectToServer(serverNum: 1 | 2): Promise<void> {
    const url = serverNum === 1 ? this.config.server1Url : this.config.server2Url;
    console.log(`[DEBUG] [SERVER ${serverNum}] Step 1: Starting connection to ${url}`);
    console.log(`[DEBUG] [SERVER ${serverNum}] Timestamp: ${new Date().toISOString()}`);
    console.log(`[DEBUG] [SERVER ${serverNum}] Browser WebSocket support: ${typeof WebSocket !== 'undefined'}`);

    try {
      const ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
      console.log(`[DEBUG] [SERVER ${serverNum}] Step 2: WebSocket object created successfully`);
      console.log(`[DEBUG] [SERVER ${serverNum}] WebSocket readyState: ${ws.readyState} (${['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'][ws.readyState]})`);
      console.log(`[DEBUG] [SERVER ${serverNum}] WebSocket URL: ${ws.url}`);
      console.log(`[DEBUG] [SERVER ${serverNum}] WebSocket protocol: ${ws.protocol || 'none'}`);

      return new Promise((resolve, reject) => {
        console.log(`[DEBUG] [SERVER ${serverNum}] Step 3: Creating event handlers`);

        ws.onopen = () => {
          console.log(`[DEBUG] [SERVER ${serverNum}] Step 5: onopen event fired! Connection successful!`);
          console.log(`[DEBUG] [SERVER ${serverNum}] WebSocket readyState: ${ws.readyState}`);
          if (serverNum === 1) {
            this.ws1 = ws;
          } else {
            this.ws2 = ws;
          }
          // Install permanent central message handler
          ws.onmessage = (event) => this.handleMessage(serverNum, event);
          // Reset the pending response queue for this server
          this.pendingResponses.set(serverNum, []);
          // Record the time of last pong (connection established)
          this.lastPongTime.set(serverNum, Date.now());
          console.log(`[DEBUG] [SERVER ${serverNum}] Step 6: Resolving connection promise`);
          resolve();
        };

        ws.onerror = (event: Event) => {
          console.log(`[DEBUG] [SERVER ${serverNum}] Step ERROR: onerror fired! Connection failed.`);
          const errorEvent = event as ErrorEvent;
          console.error(`[DEBUG] [SERVER ${serverNum}] Error details:`, {
            type: event.type,
            url: url,
            readyState: ws.readyState,
            readyStateText: ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'][ws.readyState],
            message: errorEvent?.message || 'No message',
            error: errorEvent?.error || 'Unknown error',
            timestamp: new Date().toISOString(),
          });
          console.error(`[DEBUG] [SERVER ${serverNum}] Full error object:`, event);
          reject(new Error(`Failed to connect to server ${serverNum}: ${errorEvent?.message || 'Unknown error'}`));
        };

        ws.onclose = (event: CloseEvent) => {
          console.log(`[DEBUG] [SERVER ${serverNum}] Step CLOSE: onclose fired (connection closed)`);
          console.log(`[DEBUG] [SERVER ${serverNum}] Close code: ${event.code}, reason: ${event.reason || 'none'}, wasClean: ${event.wasClean}`);

          if (serverNum === 1) {
            this.ws1 = null;
          } else {
            this.ws2 = null;
          }

          // Stop heartbeat for this server
          this.stopHeartbeat(serverNum);

          // Attempt reconnection if enabled and not intentional disconnect
          if (this.reconnectConfig.enabled && !this.isIntentionalDisconnect) {
            this.attemptReconnect(serverNum);
          } else if (!this.isIntentionalDisconnect) {
            // Update state if connection was lost unexpectedly and reconnection is disabled
            this.setConnectionState('disconnected', `Server ${serverNum} disconnected`);
          }
        };

        console.log(`[DEBUG] [SERVER ${serverNum}] Step 4: Event handlers registered, waiting for connection...`);
      });
    } catch (error) {
      console.log(`[DEBUG] [SERVER ${serverNum}] CRITICAL ERROR during WebSocket creation:`, error);
      throw error;
    }
  }

  /**
   * Attempt to reconnect to a specific server with exponential backoff
   */
  private attemptReconnect(serverNum: 1 | 2): void {
    // Clear any existing reconnect timer
    const existingTimer = this.reconnectTimers.get(serverNum);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Check if we've exceeded max attempts (0 means infinite)
    if (this.reconnectConfig.maxAttempts > 0 && this.reconnectAttempts >= this.reconnectConfig.maxAttempts) {
      console.log(`[RECONNECT] Max reconnection attempts (${this.reconnectConfig.maxAttempts}) reached for server ${serverNum}`);
      this.setConnectionState('disconnected', `Max reconnection attempts reached for server ${serverNum}`);
      return;
    }

    // Calculate delay with exponential backoff
    const delay = Math.min(
      this.reconnectConfig.initialDelay * Math.pow(this.reconnectConfig.backoffFactor, this.reconnectAttempts),
      this.reconnectConfig.maxDelay
    );

    this.reconnectAttempts++;
    this.setConnectionState('reconnecting', `Reconnecting to server ${serverNum} (attempt ${this.reconnectAttempts})...`);

    console.log(`[RECONNECT] Scheduling reconnection to server ${serverNum} in ${delay}ms (attempt ${this.reconnectAttempts})`);

    const timer = setTimeout(async () => {
      console.log(`[RECONNECT] Attempting to reconnect to server ${serverNum}...`);

      try {
        await this.connectToServer(serverNum);
        console.log(`[RECONNECT] Successfully reconnected to server ${serverNum}`);

        // Check if both servers are now connected
        if (this.isConnected()) {
          this.reconnectAttempts = 0;
          this.setConnectionState('connected', 'Reconnected to both servers');

          // Restart heartbeats
          if (this.reconnectConfig.heartbeatInterval > 0) {
            this.startHeartbeat(1);
            this.startHeartbeat(2);
          }
        }
      } catch (error) {
        console.log(`[RECONNECT] Reconnection to server ${serverNum} failed:`, error);
        // Schedule another attempt
        this.attemptReconnect(serverNum);
      }
    }, delay);

    this.reconnectTimers.set(serverNum, timer);
  }

  /**
   * Start heartbeat for a specific server
   */
  private startHeartbeat(serverNum: 1 | 2): void {
    // Clear any existing heartbeat
    this.stopHeartbeat(serverNum);

    if (this.reconnectConfig.heartbeatInterval <= 0) {
      return;
    }

    console.log(`[HEARTBEAT] Starting heartbeat for server ${serverNum} (interval: ${this.reconnectConfig.heartbeatInterval}ms)`);

    const timer = setInterval(async () => {
      const ws = serverNum === 1 ? this.ws1 : this.ws2;

      if (!ws || ws.readyState !== WebSocket.OPEN) {
        return;
      }

      try {
        // Send a ping request
        const request: Request = { Ping: {} };
        const encoded = encodeRequest(request);

        // Set up timeout for pong response
        const timeoutTimer = setTimeout(() => {
          console.log(`[HEARTBEAT] Server ${serverNum} pong timeout - connection may be stale`);
          // Close the connection to trigger reconnection
          const wsToClose = serverNum === 1 ? this.ws1 : this.ws2;
          if (wsToClose) {
            wsToClose.close();
          }
        }, this.reconnectConfig.heartbeatTimeout);

        this.heartbeatTimeoutTimers.set(serverNum, timeoutTimer);

        // Send ping — pong response is handled by the central handleMessage()
        ws.send(encoded);
      } catch (error) {
        console.error(`[HEARTBEAT] Error sending ping to server ${serverNum}:`, error);
      }
    }, this.reconnectConfig.heartbeatInterval);

    this.heartbeatTimers.set(serverNum, timer);
  }

  /**
   * Stop heartbeat for a specific server
   */
  private stopHeartbeat(serverNum: 1 | 2): void {
    const timer = this.heartbeatTimers.get(serverNum);
    if (timer) {
      clearInterval(timer);
      this.heartbeatTimers.delete(serverNum);
    }

    const timeoutTimer = this.heartbeatTimeoutTimers.get(serverNum);
    if (timeoutTimer) {
      clearTimeout(timeoutTimer);
      this.heartbeatTimeoutTimers.delete(serverNum);
    }
  }

  /**
   * Disconnect from servers
   */
  disconnect(): void {
    this.isIntentionalDisconnect = true;

    // Clear all timers
    for (const serverNum of [1, 2] as const) {
      this.stopHeartbeat(serverNum);
      const reconnectTimer = this.reconnectTimers.get(serverNum);
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        this.reconnectTimers.delete(serverNum);
      }
    }

    // Close connections
    this.ws1?.close();
    this.ws2?.close();
    this.ws1 = null;
    this.ws2 = null;

    // Reset state
    this.reconnectAttempts = 0;
    this.setConnectionState('disconnected', 'Disconnected');
  }

  /**
   * Check if connected to both servers
   */
  isConnected(): boolean {
    return (
      this.ws1 !== null &&
      this.ws2 !== null &&
      this.ws1.readyState === WebSocket.OPEN &&
      this.ws2.readyState === WebSocket.OPEN
    );
  }

  /**
   * Send a request to a specific server
   */
  private async sendRequest(
    serverNum: 1 | 2,
    request: Request,
  ): Promise<Response> {
    const ws = serverNum === 1 ? this.ws1 : this.ws2;

    if (!ws || ws.readyState !== WebSocket.OPEN) {
      throw new Error(`Not connected to server ${serverNum}`);
    }

    const encoded = encodeRequest(request);
    const queue = this.pendingResponses.get(serverNum)!;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        // Remove this callback from the queue on timeout
        const idx = queue.indexOf(callback);
        if (idx !== -1) queue.splice(idx, 1);
        reject(new Error(`Request to server ${serverNum} timed out`));
      }, 30000); // 30 second timeout

      const callback = (response: Response) => {
        clearTimeout(timeout);
        resolve(response);
      };

      queue.push(callback);
      ws.send(encoded);
    });
  }

  /**
   * Send ping to both servers
   */
  async ping(): Promise<{ pong1: Response; pong2: Response }> {
    const request: Request = { Ping: {} };
    const [pong1, pong2] = await Promise.all([
      this.sendRequest(1, request),
      this.sendRequest(2, request),
    ]);
    return { pong1, pong2 };
  }

  /**
   * List databases on a server
   */
  async listDatabases(serverNum: 1 | 2): Promise<Response> {
    const request: Request = { ListDatabases: {} };
    return await this.sendRequest(serverNum, request);
  }

  /**
   * Get database info
   */
  async getDatabaseInfo(
    serverNum: 1 | 2,
    databaseId: string,
  ): Promise<Response> {
    const request: Request = { GetDatabaseInfo: { database_id: databaseId } };
    return await this.sendRequest(serverNum, request);
  }

  /**
   * Query a database on both servers
   */
  async queryDatabase(
    databaseId: string,
    index1: number,
    index2: number,
    n: number = 24,
  ): Promise<{ response1: Response; response2: Response }> {
    // Generate DPF keys for both indices (async)
    const keys1 = await this.dpf.genKeys(index1, n);
    const keys2 = await this.dpf.genKeys(index2, n);

    const request: Request = {
      QueryDatabase: {
        database_id: databaseId,
        dpf_key1: keys1.key1,
        dpf_key2: keys1.key2,
      },
    };

    // Send to both servers
    const [response1, response2] = await Promise.all([
      this.sendRequest(1, request),
      this.sendRequest(2, request),
    ]);

    return { response1, response2 };
  }


  /**
   * Query the cuckoo database for a script hash
   * Uses proper cuckoo hash functions to compute locations
   *
   * This performs a multi-step PIR lookup:
   * Step 1-3: Query cuckoo index to find the chunk offset
   * Step 4: Fetch the chunk and read the UTXO count
   */
  async queryCuckooIndex(
    scriptHash: Uint8Array,
    numBuckets: number = CUCKOO_NUM_BUCKETS,
  ): Promise<{
    response1: Response;
    response2: Response;
    loc1: number;
    loc2: number;
    // Step 4 results
    offset?: number;
    chunkIndex?: number;
    localOffset?: number;
    utxoCount?: bigint;
  }> {
    // Import the cuckoo hash functions
    const { cuckooHash1, cuckooHash2 } = await import('./hash.js');

    // Step 1: Compute cuckoo locations
    const loc1 = cuckooHash1(scriptHash, numBuckets);
    const loc2 = cuckooHash2(scriptHash, numBuckets);

    console.log(`[PIR] Step 1: Cuckoo locations computed: loc1=${loc1}, loc2=${loc2}`);

    // Compute n (domain size) from numBuckets
    const n = Math.ceil(Math.log2(numBuckets));

    // Step 2: Generate DPF keys for both locations (async)
    const keys1 = await this.dpf.genKeys(loc1, n);
    const keys2 = await this.dpf.genKeys(loc2, n);

    console.log(`[PIR] Step 2: DPF keys generated (domain=2^${n})`);

    // Create request for both locations
    const request1: Request = {
      QueryDatabase: {
        database_id: 'gen2_utxo_cuckoo_index',
        dpf_key1: keys1.key1,
        dpf_key2: keys2.key1,  // Server 1 gets key1 for both locations
      },
    };

    const request2: Request = {
      QueryDatabase: {
        database_id: 'gen2_utxo_cuckoo_index',
        dpf_key1: keys1.key2,  // Server 2 gets key2 for both locations
        dpf_key2: keys2.key2,
      },
    };

    // Step 3: Send to both servers
    console.log(`[PIR] Step 3: Querying cuckoo index...`);
    const [response1, response2] = await Promise.all([
      this.sendRequest(1, request1),
      this.sendRequest(2, request2),
    ]);
    console.log(`[PIR] Step 3: Cuckoo index query completed`);

    // Extract data from responses
    if (!('QueryTwoResults' in response1) || !('QueryTwoResults' in response2)) {
      console.log(`[PIR] Step 3: Unexpected response type from cuckoo index query`);
      return { response1, response2, loc1, loc2 };
    }

    const data1_loc1 = response1.QueryTwoResults.data1;
    const data1_loc2 = response1.QueryTwoResults.data2;
    const data2_loc1 = response2.QueryTwoResults.data1;
    const data2_loc2 = response2.QueryTwoResults.data2;

    // XOR the results from both servers
    const combined_loc1 = this.xorBuffers(data1_loc1, data2_loc1);
    const combined_loc2 = this.xorBuffers(data1_loc2, data2_loc2);

    console.log(`[PIR] Step 3: Combined results: loc1=${combined_loc1.length} bytes, loc2=${combined_loc2.length} bytes`);

    // Entry size in cuckoo index: 20-byte key + 4-byte offset = 24 bytes
    const CUCKOO_ENTRY_SIZE = 24;
    const CUCKOO_BUCKET_SIZE = 4;

    // Search in both locations to find the offset
    let foundOffset: number | undefined;

    for (const [bucketData, locName] of [[combined_loc1, 'loc1'], [combined_loc2, 'loc2']] as const) {
      for (let i = 0; i < CUCKOO_BUCKET_SIZE; i++) {
        const entryOffset = i * CUCKOO_ENTRY_SIZE;
        if (entryOffset + CUCKOO_ENTRY_SIZE > bucketData.length) {
          continue;
        }

        // Read the key (first 20 bytes)
        const key = bucketData.slice(entryOffset, entryOffset + KEY_SIZE);

        // Check if this slot is empty (all zeros)
        if (key.every(b => b === 0)) {
          continue;
        }

        // Check if the key matches
        if (this.bytesEqual(key, scriptHash)) {
          // Read the offset (4 bytes after the key, little-endian u32)
          const offsetBytes = bucketData.slice(entryOffset + KEY_SIZE, entryOffset + KEY_SIZE + 4);
          foundOffset = new DataView(offsetBytes.buffer, offsetBytes.byteOffset, 4).getUint32(0, true);
          console.log(`[PIR] Step 3: Found matching key at ${locName} bucket ${i} with offset ${foundOffset}`);
          break;
        }
      }
      if (foundOffset !== undefined) break;
    }

    if (foundOffset === undefined) {
      console.log(`[PIR] Step 3: Script hash not found in cuckoo index`);
      return { response1, response2, loc1, loc2 };
    }

    // Step 4: Calculate chunk index and local offset, then fetch UTXO count
    // The stored offset is byte_offset/2 (to fit >4GB files in u32)
    const byteOffset = foundOffset * 2;
    const chunkIndex = Math.floor(byteOffset / CHUNK_SIZE);
    const localOffset = byteOffset % CHUNK_SIZE;

    console.log(`[PIR] Step 4: Stored offset ${foundOffset} -> byte offset ${byteOffset} -> chunk_index=${chunkIndex}, local_offset=${localOffset}`);

    // Query the chunk
    console.log(`[PIR] Step 4: Fetching chunk ${chunkIndex}...`);
    const chunkData = await this.queryChunk(chunkIndex);

    // Read the varint (UTXO count) at the local offset
    const { value: utxoCount, bytesConsumed } = this.readVarint(chunkData, localOffset);

    console.log(`[PIR] Step 4: UTXO count = ${utxoCount} (read ${bytesConsumed} bytes at local offset ${localOffset})`);
    console.log(`[PIR] ========================================`);
    console.log(`[PIR] RESULT: Number of UTXOs for this script: ${utxoCount}`);
    console.log(`[PIR] ========================================`);

    return {
      response1,
      response2,
      loc1,
      loc2,
      offset: byteOffset,
      chunkIndex,
      localOffset,
      utxoCount,
    };
  }

  /**
   * XOR two buffers
   */
  private xorBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(Math.max(a.length, b.length));
    for (let i = 0; i < result.length; i++) {
      result[i] = (a[i] || 0) ^ (b[i] || 0);
    }
    return result;
  }

  /**
   * Query the cuckoo index to find the offset for a script hash
   * Returns the offset in the chunks database, or null if not found
   */
  async findScriptOffset(
    scriptHash: Uint8Array,
    numBuckets: number = CUCKOO_NUM_BUCKETS,
  ): Promise<{ offset: number; loc1: number; loc2: number } | null> {
    const { cuckooHash1, cuckooHash2 } = await import('./hash.js');

    // Compute cuckoo locations
    const loc1 = cuckooHash1(scriptHash, numBuckets);
    const loc2 = cuckooHash2(scriptHash, numBuckets);

    console.log(`[PIR] Cuckoo locations: loc1=${loc1}, loc2=${loc2}`);

    // Compute n (domain size) from numBuckets
    const n = Math.ceil(Math.log2(numBuckets));

    // Generate DPF keys for both locations
    const keys1 = await this.dpf.genKeys(loc1, n);
    const keys2 = await this.dpf.genKeys(loc2, n);

    // Create requests for both servers
    // Server 1 gets key1 for both locations
    const request1: Request = {
      QueryDatabase: {
        database_id: 'gen2_utxo_cuckoo_index',
        dpf_key1: keys1.key1,
        dpf_key2: keys2.key1,
      },
    };

    // Server 2 gets key2 for both locations
    const request2: Request = {
      QueryDatabase: {
        database_id: 'gen2_utxo_cuckoo_index',
        dpf_key1: keys1.key2,
        dpf_key2: keys2.key2,
      },
    };

    // Send to both servers
    const [response1, response2] = await Promise.all([
      this.sendRequest(1, request1),
      this.sendRequest(2, request2),
    ]);

    // Extract data from responses
    if (!('QueryTwoResults' in response1) || !('QueryTwoResults' in response2)) {
      throw new Error('Unexpected response type from cuckoo index query');
    }

    const data1_loc1 = response1.QueryTwoResults.data1;
    const data1_loc2 = response1.QueryTwoResults.data2;
    const data2_loc1 = response2.QueryTwoResults.data1;
    const data2_loc2 = response2.QueryTwoResults.data2;

    // XOR the results from both servers
    const combined_loc1 = this.xorBuffers(data1_loc1, data2_loc1);
    const combined_loc2 = this.xorBuffers(data1_loc2, data2_loc2);

    console.log(`[PIR] Combined results: loc1=${combined_loc1.length} bytes, loc2=${combined_loc2.length} bytes`);

    // Entry size in cuckoo index: 20-byte key + 4-byte offset = 24 bytes
    const CUCKOO_ENTRY_SIZE = 24;
    const CUCKOO_BUCKET_SIZE = 4;

    // Search in both locations
    for (const [bucketData, locName] of [[combined_loc1, 'loc1'], [combined_loc2, 'loc2']] as const) {
      for (let i = 0; i < CUCKOO_BUCKET_SIZE; i++) {
        const offset = i * CUCKOO_ENTRY_SIZE;
        if (offset + CUCKOO_ENTRY_SIZE > bucketData.length) {
          continue;
        }

        // Read the key (first 20 bytes)
        const key = bucketData.slice(offset, offset + KEY_SIZE);

        // Check if this slot is empty (all zeros)
        if (key.every(b => b === 0)) {
          continue;
        }

        // Check if the key matches
        if (this.bytesEqual(key, scriptHash)) {
          // Read the offset (4 bytes after the key, little-endian u32)
          const offsetBytes = bucketData.slice(offset + KEY_SIZE, offset + KEY_SIZE + 4);
          const chunkOffset = new DataView(offsetBytes.buffer, offsetBytes.byteOffset, 4).getUint32(0, true);
          console.log(`[PIR] Found matching key at ${locName} bucket ${i} with offset ${chunkOffset}`);
          return { offset: chunkOffset, loc1, loc2 };
        }
      }
    }

    console.log(`[PIR] Script hash not found in cuckoo index`);
    return null;
  }

  /**
   * Compare two byte arrays for equality
   */
  private bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  /**
   * Query a single chunk from the chunks database
   * Returns the raw chunk data
   *
   * Uses DPF with two keys - one for each server
   */
  async queryChunk(chunkIndex: number): Promise<Uint8Array> {
    const n = Math.ceil(Math.log2(CHUNKS_NUM_ENTRIES));

    // Generate DPF keys for the chunk index
    // key1 goes to server 1, key2 goes to server 2
    const keys = await this.dpf.genKeys(chunkIndex, n);

    // Create different requests for each server
    const request1: Request = {
      QueryDatabase: {
        database_id: 'gen2_utxo_chunks_data',
        dpf_key1: keys.key1,  // Server 1 gets key1
        dpf_key2: keys.key1,  // Same key for both slots (only querying one location)
      },
    };

    const request2: Request = {
      QueryDatabase: {
        database_id: 'gen2_utxo_chunks_data',
        dpf_key1: keys.key2,  // Server 2 gets key2
        dpf_key2: keys.key2,  // Same key for both slots (only querying one location)
      },
    };

    // Send to both servers
    const [response1, response2] = await Promise.all([
      this.sendRequest(1, request1),
      this.sendRequest(2, request2),
    ]);

    // Extract data from responses
    if (!('QueryTwoResults' in response1) || !('QueryTwoResults' in response2)) {
      throw new Error('Unexpected response type from chunk query');
    }

    // XOR the results from both servers
    // Since we're querying the same location with both keys, data1 and data2 should be the same
    // We only need to XOR one of them
    const combined = this.xorBuffers(response1.QueryTwoResults.data1, response2.QueryTwoResults.data1);
    console.log(`[PIR] Chunk ${chunkIndex} retrieved: ${combined.length} bytes`);

    return combined;
  }

  /**
   * Read a varint (LEB128 encoded) from a Uint8Array at the given offset
   * Returns the value and the number of bytes consumed
   */
  readVarint(data: Uint8Array, offset: number): { value: bigint; bytesConsumed: number } {
    let result: bigint = 0n;
    let shift = 0;
    let bytesConsumed = 0;

    while (true) {
      if (offset + bytesConsumed >= data.length) {
        throw new Error('Unexpected end of data while reading varint');
      }

      const byte = data[offset + bytesConsumed];
      bytesConsumed++;

      result |= BigInt(byte & 0x7F) << BigInt(shift);

      if ((byte & 0x80) === 0) {
        break;
      }
      shift += 7;

      if (shift >= 64) {
        throw new Error('VarInt too large');
      }
    }

    return { value: result, bytesConsumed };
  }

  /**
   * Look up UTXO count for a script hash
   * This performs the full PIR lookup:
   * 1. Query cuckoo index to get the chunk offset
   * 2. Calculate chunk index and local offset
   * 3. Query the chunk
   * 4. Read the varint (UTXO count) at the local offset
   */
  async lookupUtxoCount(
    scriptHash: Uint8Array,
    numBuckets: number = CUCKOO_NUM_BUCKETS,
  ): Promise<{
    found: boolean;
    offset?: number;
    chunkIndex?: number;
    localOffset?: number;
    utxoCount?: bigint;
    chunkData?: Uint8Array;
  }> {
    console.log(`[PIR] Starting UTXO count lookup for script hash: ${this.bytesToHex(scriptHash)}`);

    // Step 1: Query cuckoo index to get the offset
    const cuckooResult = await this.findScriptOffset(scriptHash, numBuckets);

    if (!cuckooResult) {
      console.log(`[PIR] Script hash not found in database`);
      return { found: false };
    }

    const { offset: storedOffset } = cuckooResult;

    // Step 2: Calculate chunk index and local offset
    // The stored offset is byte_offset/2 (to fit >4GB files in u32)
    const byteOffset = storedOffset * 2;
    const chunkIndex = Math.floor(byteOffset / CHUNK_SIZE);
    const localOffset = byteOffset % CHUNK_SIZE;

    console.log(`[PIR] Stored offset: ${storedOffset}, byte offset: ${byteOffset}`);
    console.log(`[PIR] Chunk index: ${chunkIndex}`);
    console.log(`[PIR] Local offset: ${localOffset}`);

    // Step 3: Query the chunk
    const chunkData = await this.queryChunk(chunkIndex);

    // Step 4: Read the varint (UTXO count) at the local offset
    const { value: utxoCount, bytesConsumed } = this.readVarint(chunkData, localOffset);

    console.log(`[PIR] UTXO count at offset ${localOffset}: ${utxoCount} (varint: ${bytesConsumed} bytes)`);

    return {
      found: true,
      offset: byteOffset,
      chunkIndex,
      localOffset,
      utxoCount,
      chunkData,
    };
  }

  /**
   * Convert bytes to hex string
   */
  private bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Read 4 bytes as little-endian u32
   */
  private readU32LE(data: Uint8Array, offset: number): number {
    if (offset + 4 > data.length) {
      throw new Error('Unexpected end of data while reading u32');
    }
    return new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(0, true);
  }

  /**
   * Initialize pagination state for a script hash
   * This fetches the first chunk and reads the entry count
   */
  async initUtxoPagination(
    scriptHash: Uint8Array,
    numBuckets: number = CUCKOO_NUM_BUCKETS,
  ): Promise<UtxoPaginationState | null> {
    // Find the offset in the chunks database
    const cuckooResult = await this.findScriptOffset(scriptHash, numBuckets);
    if (!cuckooResult) {
      return null;
    }

    // The stored offset is byte_offset/2 (to fit >4GB files in u32)
    const startOffset = cuckooResult.offset * 2;
    const chunkIndex = Math.floor(startOffset / CHUNK_SIZE);
    const localOffset = startOffset % CHUNK_SIZE;

    // Fetch the first chunk
    const chunkData = await this.queryChunk(chunkIndex);

    // Read the entry count (varint at local offset)
    const { value: totalEntries, bytesConsumed } = this.readVarint(chunkData, localOffset);

    // Whale detection: if totalEntries === 0, this is a whale address
    const isWhale = totalEntries === 0n;

    // Store chunk data
    const chunksData = new Map<number, Uint8Array>();
    chunksData.set(chunkIndex, chunkData);

    console.log(`[PIR] Initialized pagination: ${totalEntries} total entries, starting at chunk ${chunkIndex}, offset ${localOffset + bytesConsumed}${isWhale ? ' (WHALE DETECTED)' : ''}`);

    return {
      scriptHash,
      startOffset,
      totalEntries,
      entries: [],
      currentChunkIndex: chunkIndex,
      localOffset: localOffset + bytesConsumed, // Move past the count varint
      entriesRead: 0,
      chunksData,
      isWhale,
    };
  }

  /**
   * Read a single byte from chunk data, fetching next chunk if needed
   */
  private async readByteFromChunks(
    state: UtxoPaginationState
  ): Promise<number> {
    // Check if we need to fetch the next chunk
    if (state.localOffset >= CHUNK_SIZE) {
      state.currentChunkIndex++;
      state.localOffset = 0;

      // Check if we have this chunk cached
      if (!state.chunksData.has(state.currentChunkIndex)) {
        console.log(`[PIR] Fetching chunk ${state.currentChunkIndex}...`);
        const chunkData = await this.queryChunk(state.currentChunkIndex);
        state.chunksData.set(state.currentChunkIndex, chunkData);
      }
    }

    const chunkData = state.chunksData.get(state.currentChunkIndex)!;
    if (state.localOffset >= chunkData.length) {
      throw new Error('End of chunk data reached');
    }

    const byte = chunkData[state.localOffset];
    state.localOffset++;
    return byte;
  }

  /**
   * Read a varint from the pagination state
   */
  private async readVarintFromChunks(state: UtxoPaginationState): Promise<bigint> {
    let result: bigint = 0n;
    let shift = 0;

    while (true) {
      const byte = await this.readByteFromChunks(state);
      result |= BigInt(byte & 0x7F) << BigInt(shift);

      if ((byte & 0x80) === 0) {
        break;
      }
      shift += 7;

      if (shift >= 64) {
        throw new Error('VarInt too large');
      }
    }

    return result;
  }

  /**
   * Fetch more UTXO entries
   * Returns the entries fetched (may be less than requested if end of data)
   *
   * Every entry: read 32 raw bytes for TXID (no delta, no special first entry)
   */
  async fetchUtxoEntries(
    state: UtxoPaginationState,
    count: number
  ): Promise<UtxoEntry[]> {
    const totalToRead = Math.min(count, Number(state.totalEntries) - state.entriesRead);

    if (totalToRead <= 0) {
      return [];
    }

    const newEntries: UtxoEntry[] = [];

    for (let i = 0; i < totalToRead; i++) {
      try {
        // Every entry: read 32 raw bytes for TXID (no delta, no special first entry)
        const txid = new Uint8Array(32);
        for (let j = 0; j < 32; j++) {
          txid[j] = await this.readByteFromChunks(state);
        }

        // Read vout as varint
        const vout = await this.readVarintFromChunks(state);

        // Read amount as varint
        const amount = await this.readVarintFromChunks(state);

        const entry: UtxoEntry = {
          txid,
          vout: Number(vout),
          amount,
        };

        newEntries.push(entry);
        state.entries.push(entry);
        state.entriesRead++;
      } catch (error) {
        console.error(`[PIR] Error reading entry ${state.entriesRead + i}:`, error);
        break;
      }
    }

    console.log(`[PIR] Fetched ${newEntries.length} entries, total cached: ${state.entries.length}`);
    return newEntries;
  }

  /**
   * Get a page of UTXO entries
   * If not enough entries are cached, fetches more from the server
   */
  async getUtxoPage(
    state: UtxoPaginationState,
    page: number,
    pageSize: number = 20
  ): Promise<UtxoEntry[]> {
    const startIndex = page * pageSize;
    const endIndex = startIndex + pageSize;

    // Fetch more entries if needed
    while (state.entries.length < endIndex && state.entriesRead < Number(state.totalEntries)) {
      const needed = endIndex - state.entries.length;
      await this.fetchUtxoEntries(state, Math.max(needed, pageSize));
    }

    // Return the requested page
    return state.entries.slice(startIndex, Math.min(endIndex, state.entries.length));
  }

  /**
   * Get pagination info
   */
  getPaginationInfo(state: UtxoPaginationState, pageSize: number = 20): {
    totalPages: number;
    currentPage: number;
    totalEntries: bigint;
    cachedEntries: number;
  } {
    const totalPages = Math.ceil(Number(state.totalEntries) / pageSize);
    const cachedEntries = state.entries.length;
    return {
      totalPages,
      currentPage: 0, // Caller should track this
      totalEntries: state.totalEntries,
      cachedEntries,
    };
  }
}

/**
 * Create a PIR client with default configuration
 */
export function createPirClient(
  server1Url: string = 'ws://localhost:8091',
  server2Url: string = 'ws://localhost:8092',
): PirClient {
  return new PirClient({ server1Url, server2Url });
}
