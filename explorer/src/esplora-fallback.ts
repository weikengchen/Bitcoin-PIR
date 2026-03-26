/**
 * Built-in Esplora HTTP client for non-privacy-sensitive operations.
 *
 * Handles: fetchTx, fetchFeeEstimates, fetchBlockStatus, fetchBlockHeight, push.
 * These operations don't reveal address ownership, so they can safely go
 * through a standard Esplora REST API without PIR.
 */

import type { BlockStatus } from './types.js';

const DEFAULT_ESPLORA_URL = 'https://blockstream.info/api';

export class EsploraFallback {
  private readonly baseUrl: string;
  private readonly onLog?: (msg: string) => void;

  constructor(baseUrl?: string, onLog?: (msg: string) => void) {
    this.baseUrl = (baseUrl ?? DEFAULT_ESPLORA_URL).replace(/\/+$/, '');
    this.onLog = onLog;
  }

  private log(msg: string): void {
    this.onLog?.(`[Esplora] ${msg}`);
  }

  private async fetchJson<T>(path: string): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`Esplora ${path}: HTTP ${resp.status}`);
    }
    return resp.json() as Promise<T>;
  }

  private async fetchText(path: string): Promise<string> {
    const url = `${this.baseUrl}${path}`;
    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`Esplora ${path}: HTTP ${resp.status}`);
    }
    return resp.text();
  }

  /** Fetch raw transaction hex by txid. */
  async fetchTx(txId: string): Promise<string> {
    this.log(`fetchTx ${txId.slice(0, 12)}...`);
    return this.fetchText(`/tx/${txId}/hex`);
  }

  /** Fetch fee estimates (target confirmations → sat/vB). */
  async fetchFeeEstimates(): Promise<Record<string, number>> {
    this.log('fetchFeeEstimates');
    return this.fetchJson<Record<string, number>>('/fee-estimates');
  }

  /** Fetch block status for a given height. */
  async fetchBlockStatus(blockHeight: number): Promise<BlockStatus | undefined> {
    this.log(`fetchBlockStatus ${blockHeight}`);
    // Step 1: get block hash at height
    let blockHash: string;
    try {
      blockHash = await this.fetchText(`/block-height/${blockHeight}`);
    } catch {
      return undefined;
    }

    // Step 2: get block header info
    const info = await this.fetchJson<{
      id: string;
      height: number;
      timestamp: number;
    }>(`/block/${blockHash}`);

    // Step 3: determine irreversibility (3+ confirmations)
    const tipHeight = await this.fetchBlockHeight();
    const confirmations = tipHeight - blockHeight + 1;

    return {
      blockHeight: info.height,
      blockHash: info.id,
      blockTime: info.timestamp,
      irreversible: confirmations >= 3,
    };
  }

  /** Fetch current block tip height. */
  async fetchBlockHeight(): Promise<number> {
    this.log('fetchBlockHeight');
    const text = await this.fetchText('/blocks/tip/height');
    return parseInt(text, 10);
  }

  /** Broadcast a raw transaction hex, returns txid. */
  async push(txHex: string): Promise<string> {
    this.log('push tx');
    const url = `${this.baseUrl}/tx`;
    const resp = await fetch(url, {
      method: 'POST',
      body: txHex,
      headers: { 'Content-Type': 'text/plain' },
    });
    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`Esplora push failed: HTTP ${resp.status} — ${body}`);
    }
    return resp.text();
  }

  /** Quick connectivity check. */
  async ping(): Promise<boolean> {
    try {
      await this.fetchBlockHeight();
      return true;
    } catch {
      return false;
    }
  }
}
