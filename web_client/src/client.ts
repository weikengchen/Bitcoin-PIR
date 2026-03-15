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
  TXID_MAPPING_NUM_BUCKETS,
  TXID_MAPPING_BUCKET_SIZE,
  TXID_MAPPING_ENTRY_SIZE,
  KEY_SIZE,
} from './constants.js';

// Re-export Request and Response types
export type { Request, Response } from './sbp.js';

/**
 * A parsed UTXO entry
 */
export interface UtxoEntry {
  txid: number;  // 4-byte mapped TXID
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
}

/**
 * PIR client configuration
 */
export interface PirClientConfig {
  server1Url: string;
  server2Url: string;
}

/**
 * PIR WebSocket client
 */
export class PirClient {
  private ws1: WebSocket | null = null;
  private ws2: WebSocket | null = null;
  private config: PirClientConfig;
  private dpf = createDpf();
  private pendingRequests: Map<number, (response: Response) => void> =
    new Map();
  private requestCounter = 0;

  constructor(config: PirClientConfig) {
    this.config = config;
  }

  /**
   * Connect to both servers
   */
  async connect(): Promise<void> {
    console.log(`[DEBUG] Main connect(): Starting parallel connection to both servers`);
    try {
      await Promise.all([
        this.connectToServer(1),
        this.connectToServer(2),
      ]);
      console.log(`[DEBUG] Main connect(): Both connections completed successfully`);
    } catch (error) {
      console.log(`[DEBUG] Main connect(): Connection failed with error:`, error);
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
        };

        console.log(`[DEBUG] [SERVER ${serverNum}] Step 4: Event handlers registered, waiting for connection...`);
      });
    } catch (error) {
      console.log(`[DEBUG] [SERVER ${serverNum}] CRITICAL ERROR during WebSocket creation:`, error);
      throw error;
    }
  }

  /**
   * Disconnect from servers
   */
  disconnect(): void {
    this.ws1?.close();
    this.ws2?.close();
    this.ws1 = null;
    this.ws2 = null;
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

    const requestId = this.requestCounter++;
    const encoded = encodeRequest(request);

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        reject(new Error(`Request to server ${serverNum} timed out`));
      }, 30000); // 30 second timeout

      this.pendingRequests.set(requestId, (response: Response) => {
        clearTimeout(timeout);
        resolve(response);
      });

      ws.onmessage = (event) => {
        try {
          const response = decodeResponse(new Uint8Array(event.data));
          const callback = this.pendingRequests.get(requestId);
          if (callback) {
            this.pendingRequests.delete(requestId);
            callback(response);
          }
        } catch (error) {
          console.error('Failed to decode response:', error);
          reject(error);
        }
      };

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
        database_id: 'utxo_cuckoo_index',
        dpf_key1: keys1.key1,
        dpf_key2: keys2.key1,  // Server 1 gets key1 for both locations
      },
    };
    
    const request2: Request = {
      QueryDatabase: {
        database_id: 'utxo_cuckoo_index',
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
    const chunkIndex = Math.floor(foundOffset / CHUNK_SIZE);
    const localOffset = foundOffset % CHUNK_SIZE;
    
    console.log(`[PIR] Step 4: Offset ${foundOffset} -> chunk_index=${chunkIndex}, local_offset=${localOffset}`);
    
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
      offset: foundOffset,
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
        database_id: 'utxo_cuckoo_index',
        dpf_key1: keys1.key1,
        dpf_key2: keys2.key1,
      },
    };
    
    // Server 2 gets key2 for both locations
    const request2: Request = {
      QueryDatabase: {
        database_id: 'utxo_cuckoo_index',
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
        database_id: 'utxo_chunks_data',
        dpf_key1: keys.key1,  // Server 1 gets key1
        dpf_key2: keys.key1,  // Same key for both slots (only querying one location)
      },
    };
    
    const request2: Request = {
      QueryDatabase: {
        database_id: 'utxo_chunks_data',
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
    
    const { offset } = cuckooResult;
    
    // Step 2: Calculate chunk index and local offset
    const chunkIndex = Math.floor(offset / CHUNK_SIZE);
    const localOffset = offset % CHUNK_SIZE;
    
    console.log(`[PIR] Offset: ${offset}`);
    console.log(`[PIR] Chunk index: ${chunkIndex}`);
    console.log(`[PIR] Local offset: ${localOffset}`);
    
    // Step 3: Query the chunk
    const chunkData = await this.queryChunk(chunkIndex);
    
    // Step 4: Read the varint (UTXO count) at the local offset
    const { value: utxoCount, bytesConsumed } = this.readVarint(chunkData, localOffset);
    
    console.log(`[PIR] UTXO count at offset ${localOffset}: ${utxoCount} (varint: ${bytesConsumed} bytes)`);
    
    return {
      found: true,
      offset,
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

    const startOffset = cuckooResult.offset;
    const chunkIndex = Math.floor(startOffset / CHUNK_SIZE);
    const localOffset = startOffset % CHUNK_SIZE;

    // Fetch the first chunk
    const chunkData = await this.queryChunk(chunkIndex);

    // Read the entry count (varint at local offset)
    const { value: totalEntries, bytesConsumed } = this.readVarint(chunkData, localOffset);

    // Store chunk data
    const chunksData = new Map<number, Uint8Array>();
    chunksData.set(chunkIndex, chunkData);

    console.log(`[PIR] Initialized pagination: ${totalEntries} total entries, starting at chunk ${chunkIndex}, offset ${localOffset + bytesConsumed}`);

    return {
      scriptHash,
      startOffset,
      totalEntries,
      entries: [],
      currentChunkIndex: chunkIndex,
      localOffset: localOffset + bytesConsumed, // Move past the count varint
      entriesRead: 0,
      chunksData,
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
   * Read 4 bytes as u32 from the pagination state
   */
  private async readU32FromChunks(state: UtxoPaginationState): Promise<number> {
    const b0 = await this.readByteFromChunks(state);
    const b1 = await this.readByteFromChunks(state);
    const b2 = await this.readByteFromChunks(state);
    const b3 = await this.readByteFromChunks(state);
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
  }

  /**
   * Fetch more UTXO entries
   * Returns the entries fetched (may be less than requested if end of data)
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
        let txid: number;
        let vout: bigint;
        let amount: bigint;

        if (state.entriesRead + i === 0) {
          // First entry: read raw 4-byte TXID
          txid = await this.readU32FromChunks(state);
        } else {
          // Subsequent entries: read varint delta
          const delta = await this.readVarintFromChunks(state);
          const prevTxid = state.entries.length > 0 
            ? state.entries[state.entries.length - 1].txid 
            : newEntries[newEntries.length - 1].txid;
          txid = (prevTxid - Number(delta)) >>> 0; // wrapping subtraction
        }

        // Read vout as varint
        vout = await this.readVarintFromChunks(state);

        // Read amount as varint
        amount = await this.readVarintFromChunks(state);

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

  /**
   * Query TXID mapping database to convert 4-byte TXID to 32-byte TXID
   * 
   * Uses cuckoo-style hash lookup:
   * 1. Compute two hash locations for the 4-byte TXID
   * 2. Query both locations via PIR
   * 3. Find matching 4-byte key and extract 32-byte TXID
   * 
   * @param txid4b - The 4-byte mapped TXID
   * @returns The 32-byte TXID (reversed for display), or null if not found
   */
  async queryTxidMapping(txid4b: number): Promise<Uint8Array | null> {
    const { txidMappingLocations } = await import('./hash.js');
    
    console.log(`[PIR] Querying TXID mapping for 4B TXID: ${txid4b}`);
    
    // Compute hash locations
    const [loc1, loc2] = txidMappingLocations(
      new Uint8Array([
        txid4b & 0xff,
        (txid4b >> 8) & 0xff,
        (txid4b >> 16) & 0xff,
        (txid4b >> 24) & 0xff,
      ]),
      TXID_MAPPING_NUM_BUCKETS
    );
    
    console.log(`[PIR] TXID mapping locations: loc1=${loc1}, loc2=${loc2}`);
    
    // Compute n (domain size) from numBuckets
    const n = Math.ceil(Math.log2(TXID_MAPPING_NUM_BUCKETS));
    
    // Generate DPF keys for both locations
    const keys1 = await this.dpf.genKeys(loc1, n);
    const keys2 = await this.dpf.genKeys(loc2, n);

    // Create requests for both servers
    const request1: Request = {
      QueryDatabase: {
        database_id: 'utxo_4b_to_32b',
        dpf_key1: keys1.key1,
        dpf_key2: keys2.key1,  // Server 1 gets key1 for both locations
      },
    };
    
    const request2: Request = {
      QueryDatabase: {
        database_id: 'utxo_4b_to_32b',
        dpf_key1: keys1.key2,  // Server 2 gets key2 for both locations
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
      throw new Error('Unexpected response type from TXID mapping query');
    }

    // XOR the results from both servers
    const combined_loc1 = this.xorBuffers(response1.QueryTwoResults.data1, response2.QueryTwoResults.data1);
    const combined_loc2 = this.xorBuffers(response1.QueryTwoResults.data2, response2.QueryTwoResults.data2);

    console.log(`[PIR] TXID mapping combined results: loc1=${combined_loc1.length} bytes, loc2=${combined_loc2.length} bytes`);

    // The 4-byte key we're looking for
    const txid4bBytes = new Uint8Array([
      txid4b & 0xff,
      (txid4b >> 8) & 0xff,
      (txid4b >> 16) & 0xff,
      (txid4b >> 24) & 0xff,
    ]);

    // Search in both locations
    for (const [bucketData, locName] of [[combined_loc1, 'loc1'], [combined_loc2, 'loc2']] as const) {
      for (let i = 0; i < TXID_MAPPING_BUCKET_SIZE; i++) {
        const offset = i * TXID_MAPPING_ENTRY_SIZE;
        if (offset + TXID_MAPPING_ENTRY_SIZE > bucketData.length) {
          continue;
        }
        
        // Read the key (first 4 bytes)
        const key = bucketData.slice(offset, offset + 4);
        
        // Check if this slot is empty (all zeros)
        if (key.every(b => b === 0)) {
          continue;
        }
        
        // Check if the key matches
        if (this.bytesEqual(key, txid4bBytes)) {
          // Read the 32-byte TXID
          const txid32b = bucketData.slice(offset + 4, offset + 36);
          console.log(`[PIR] Found matching key at ${locName} bucket ${i}`);
          return txid32b;
        }
      }
    }

    console.log(`[PIR] 4B TXID not found in TXID mapping`);
    return null;
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
