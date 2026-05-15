/**
 * Shared WebSocket management for all PIR backends.
 *
 * Provides a managed WebSocket with:
 * - FIFO request/response queue
 * - Pong response filtering (prevents pongs from stealing query callbacks)
 * - Periodic heartbeat pings (30s default)
 * - Request timeout (120s default)
 * - Connection state tracking
 */

export interface ManagedWsConfig {
  url: string;
  label?: string;
  onLog?: (msg: string, level: 'info' | 'success' | 'error') => void;
  onClose?: () => void;
  heartbeatIntervalMs?: number;
  requestTimeoutMs?: number;
}

type PendingCallback = {
  resolve: (data: Uint8Array) => void;
  reject: (err: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
};

/** Standard ping message: [4B len=1 LE][1B variant=0x00] */
const PING_MSG = new Uint8Array([1, 0, 0, 0, 0x00]);

// ─── Transport-level message chunking (Cloudflare large-message workaround) ──
//
// Cloudflare's WebSocket proxy silently corrupts single messages above
// ~1 MB (a 3.1 MB OnionPIR RegisterKeys upload arrives truncated — see
// docs/PIR1_REGISTER_KEYS_TRUNCATION.md). Messages over CHUNK_SIZE are
// split into `[4B len][CHUNK_MAGIC][seq:u16 LE][total:u16 LE][piece]`
// frames; the peer reassembles. Must stay in sync with
// pir-sdk-client/src/connection.rs and runtime/src/bin/unified_server.rs.
const CHUNK_MAGIC = 0xc7;
const CHUNK_SIZE = 256 * 1024;
const CHUNK_HDR = 5; // 1 magic + 2 seq + 2 total
const MAX_REASSEMBLED = 64 * 1024 * 1024;

export class ManagedWebSocket {
  private ws: WebSocket | null = null;
  private pending: PendingCallback[] = [];
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  // Transport-level chunk reassembly state (see CHUNK_MAGIC above).
  private chunkAcc: Uint8Array[] = [];
  private chunkExpected = 0;
  private chunkTotal = 0;

  private config: Required<Pick<ManagedWsConfig, 'url'>> & ManagedWsConfig;

  private get heartbeatMs() { return this.config.heartbeatIntervalMs ?? 30_000; }
  private get timeoutMs() { return this.config.requestTimeoutMs ?? 120_000; }

  constructor(config: ManagedWsConfig) {
    this.config = config;
  }

  private log(msg: string, level: 'info' | 'success' | 'error' = 'info') {
    this.config.onLog?.(msg, level);
  }

  /** Connect and resolve when the WebSocket is open. */
  connect(): Promise<void> {
    const label = this.config.label ?? this.config.url;
    this.log(`Connecting to ${label}`);

    return new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(this.config.url);
      ws.binaryType = 'arraybuffer';

      ws.onopen = () => {
        this.ws = ws;
        this.pending = [];
        this.chunkAcc = [];
        this.chunkExpected = 0;
        this.chunkTotal = 0;
        this.startHeartbeat();
        resolve();
      };

      ws.onerror = () => {
        reject(new Error(`Failed to connect to ${label}`));
      };

      ws.onmessage = (event) => {
        const data = new Uint8Array(event.data as ArrayBuffer);

        // Chunk frame: [4B len][CHUNK_MAGIC][seq:u16 LE][total:u16 LE][piece].
        // A normal message never carries CHUNK_MAGIC at offset 4.
        if (data.length >= 4 + CHUNK_HDR && data[4] === CHUNK_MAGIC) {
          this.handleChunkFrame(data);
          return;
        }

        this.deliver(data);
      };

      ws.onclose = () => {
        this.ws = null;
        this.stopHeartbeat();
        this.config.onClose?.();
      };
    });
  }

  /** Send raw bytes and wait for the next response (FIFO). */
  sendRaw(msg: Uint8Array): Promise<Uint8Array> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error(`Not connected (${this.config.label ?? this.config.url})`);
    }

    return new Promise<Uint8Array>((resolve, reject) => {
      const timeout = setTimeout(() => {
        const idx = this.pending.findIndex(p => p.resolve === resolve);
        if (idx !== -1) this.pending.splice(idx, 1);
        reject(new Error(`Request timed out (${this.config.label ?? this.config.url})`));
      }, this.timeoutMs);

      this.pending.push({ resolve, reject, timeout });
      try {
        this.sendChunked(msg);
      } catch (err) {
        clearTimeout(timeout);
        const idx = this.pending.findIndex(p => p.resolve === resolve);
        if (idx !== -1) this.pending.splice(idx, 1);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  /** Check if the WebSocket is open. */
  isOpen(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  /** Gracefully close the connection. */
  disconnect(): void {
    this.stopHeartbeat();
    // Reject all pending
    for (const cb of this.pending) {
      clearTimeout(cb.timeout);
      cb.reject(new Error('Disconnected'));
    }
    this.pending = [];
    this.ws?.close();
    this.ws = null;
  }

  /** Pong-filter, then resolve the next pending request (FIFO). */
  private deliver(data: Uint8Array): void {
    // Filter pong responses: [4B len LE][1B variant]. Pong: len=1, variant=0x00.
    if (data.length >= 5) {
      const len = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
      if (len === 1 && data[4] === 0x00) {
        return; // Silently discard pong
      }
    }

    const cb = this.pending.shift();
    if (cb) {
      clearTimeout(cb.timeout);
      cb.resolve(data);
    }
  }

  /**
   * Accumulate one chunk frame; deliver the reassembled message once the
   * final chunk arrives. Frame layout must match `send_chunked` in
   * pir-sdk-client/src/connection.rs and `send_resp_chunked` in
   * runtime/src/bin/unified_server.rs.
   */
  private handleChunkFrame(data: Uint8Array): void {
    const seq = data[5] | (data[6] << 8);
    const total = data[7] | (data[8] << 8);

    if (total === 0 || seq !== this.chunkExpected) {
      this.log(`Bad chunk frame (seq=${seq} total=${total} expected=${this.chunkExpected})`, 'error');
      this.chunkAcc = [];
      this.chunkExpected = 0;
      return;
    }
    if (seq === 0) {
      this.chunkTotal = total;
      this.chunkAcc = [];
    } else if (total !== this.chunkTotal) {
      this.log('Chunk total changed mid-stream', 'error');
      this.chunkAcc = [];
      this.chunkExpected = 0;
      return;
    }

    const piece = data.subarray(4 + CHUNK_HDR);
    let accLen = piece.length;
    for (const p of this.chunkAcc) accLen += p.length;
    if (accLen > MAX_REASSEMBLED) {
      this.log('Reassembled message exceeds cap', 'error');
      this.chunkAcc = [];
      this.chunkExpected = 0;
      return;
    }

    this.chunkAcc.push(piece);
    this.chunkExpected += 1;
    if (this.chunkExpected < this.chunkTotal) {
      return; // wait for the next chunk frame
    }

    const out = new Uint8Array(accLen);
    let off = 0;
    for (const p of this.chunkAcc) {
      out.set(p, off);
      off += p.length;
    }
    this.chunkAcc = [];
    this.chunkExpected = 0;
    this.deliver(out);
  }

  /**
   * Send `msg`, splitting it into chunk frames if it exceeds CHUNK_SIZE.
   * Cloudflare's WebSocket proxy corrupts single multi-MB messages; the
   * peer reassembles the frames transparently.
   */
  private sendChunked(msg: Uint8Array): void {
    if (msg.length <= CHUNK_SIZE) {
      this.ws!.send(msg);
      return;
    }
    const total = Math.ceil(msg.length / CHUNK_SIZE);
    if (total > 0xffff) {
      throw new Error(`Message too large to chunk: ${msg.length} bytes`);
    }
    for (let seq = 0; seq < total; seq++) {
      const start = seq * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, msg.length);
      const piece = msg.subarray(start, end);
      const bodyLen = CHUNK_HDR + piece.length;
      const frame = new Uint8Array(4 + bodyLen);
      frame[0] = bodyLen & 0xff;
      frame[1] = (bodyLen >>> 8) & 0xff;
      frame[2] = (bodyLen >>> 16) & 0xff;
      frame[3] = (bodyLen >>> 24) & 0xff;
      frame[4] = CHUNK_MAGIC;
      frame[5] = seq & 0xff;
      frame[6] = (seq >>> 8) & 0xff;
      frame[7] = total & 0xff;
      frame[8] = (total >>> 8) & 0xff;
      frame.set(piece, 4 + CHUNK_HDR);
      this.ws!.send(frame);
    }
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(PING_MSG);
      }
    }, this.heartbeatMs);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
}
