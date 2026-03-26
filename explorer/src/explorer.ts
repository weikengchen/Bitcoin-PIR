/**
 * PirExplorer — implements the @bitcoinerlab/explorer Explorer interface
 * backed by PIR for privacy-sensitive operations.
 *
 * Privacy-sensitive operations (address/UTXO lookups) go through PIR.
 * Non-sensitive operations (fetchTx, fee estimates, block info, broadcast)
 * delegate to a built-in Esplora HTTP fallback.
 *
 * Usage with @bitcoinerlab/discovery:
 *   const explorer = new PirExplorer({ backend: { type: 'dpf', ... } });
 *   await explorer.connect();
 *   const discovery = DiscoveryFactory(explorer, networks.bitcoin);
 */

import type {
  Explorer,
  PirExplorerConfig,
  BlockStatus,
  AddressInfo,
  TxHistoryEntry,
  Utxo,
  ScriptQuery,
} from './types.js';

import { PirUtxoProvider } from './utxo-provider.js';
import { EsploraFallback } from './esplora-fallback.js';
import { addressToElectrumScriptHash, queryKey } from './address.js';

// ─── Cache entry ────────────────────────────────────────────────────────────

interface CacheEntry {
  utxos: Utxo[];
  timestamp: number;
}

// ─── PirExplorer ────────────────────────────────────────────────────────────

export class PirExplorer implements Explorer {
  private provider: PirUtxoProvider;
  private esplora: EsploraFallback;
  private closed = true;
  private cacheTtlMs: number;
  private cache = new Map<string, CacheEntry>();
  private onLog?: (msg: string) => void;

  constructor(config: PirExplorerConfig) {
    this.onLog = config.onLog;
    this.cacheTtlMs = config.cacheTtlMs ?? 60_000;
    this.provider = new PirUtxoProvider({
      backend: config.backend,
      onLog: config.onLog,
    });
    this.esplora = new EsploraFallback(config.esploraUrl, config.onLog);
  }

  private log(msg: string): void {
    this.onLog?.(`[PirExplorer] ${msg}`);
  }

  // ─── Lifecycle ──────────────────────────────────────────────────────────

  async connect(): Promise<void> {
    await this.provider.connect();
    this.closed = false;
    this.log('Connected');
  }

  async isConnected(): Promise<boolean> {
    if (this.closed) return false;
    return this.provider.isConnected();
  }

  isClosed(): boolean {
    return this.closed;
  }

  close(): void {
    this.provider.disconnect();
    this.cache.clear();
    this.closed = true;
    this.log('Closed');
  }

  // ─── Cache helpers ──────────────────────────────────────────────────────

  private getCached(address: string): Utxo[] | null {
    const entry = this.cache.get(address);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > this.cacheTtlMs) {
      this.cache.delete(address);
      return null;
    }
    return entry.utxos;
  }

  private setCache(address: string, utxos: Utxo[]): void {
    this.cache.set(address, { utxos, timestamp: Date.now() });
  }

  /** Internal: get UTXOs for a query target, using cache. */
  private async getUtxos(query: ScriptQuery): Promise<Utxo[]> {
    const key = queryKey(query);
    const cached = this.getCached(key);
    if (cached) return cached;

    const utxos = await this.provider.fetchUtxos(query);
    this.setCache(key, utxos);
    return utxos;
  }

  /** Internal: batch-get UTXOs for multiple targets, using cache. */
  private async getUtxosBatch(queries: ScriptQuery[]): Promise<Map<string, Utxo[]>> {
    const result = new Map<string, Utxo[]>();
    const uncached: ScriptQuery[] = [];

    for (const q of queries) {
      const key = queryKey(q);
      const cached = this.getCached(key);
      if (cached) {
        result.set(key, cached);
      } else {
        uncached.push(q);
      }
    }

    if (uncached.length > 0) {
      const fetched = await this.provider.fetchUtxosBatch(uncached);
      for (const [key, utxos] of fetched) {
        this.setCache(key, utxos);
        result.set(key, utxos);
      }
    }

    return result;
  }

  // ─── Privacy-sensitive methods (PIR-backed) ─────────────────────────────

  /**
   * Fetch address info. Accepts an address string or raw scriptPubKey:
   *   explorer.fetchAddress('bc1q...')
   *   explorer.fetchAddress({ scriptPubKey: '5221...ae' })
   */
  async fetchAddress(query: ScriptQuery): Promise<AddressInfo> {
    const utxos = await this.getUtxos(query);
    return utxosToAddressInfo(utxos);
  }

  async fetchScriptHash(scriptHash: string): Promise<AddressInfo> {
    // The Electrum scriptHash format (reversed SHA256 of scriptPubKey) cannot
    // be converted back to an address or PIR HASH160. This method requires
    // the caller to have previously called fetchAddress for the same address.
    //
    // In practice, @bitcoinerlab/discovery calls fetchTxHistory (not
    // fetchScriptHash), so this limitation rarely matters.
    this.log(`fetchScriptHash called — PIR cannot reverse Electrum scriptHash. Returning empty.`);
    return { balance: 0, txCount: 0, unconfirmedBalance: 0, unconfirmedTxCount: 0 };
  }

  /**
   * Fetch tx history for a single target.
   * Accepts address string or raw scriptPubKey via `scriptPubKey` field.
   */
  async fetchTxHistory(params: {
    address?: string;
    scriptHash?: string;
    scriptPubKey?: string;
  }): Promise<TxHistoryEntry[]> {
    const query: ScriptQuery | null = params.address
      ? params.address
      : params.scriptPubKey
        ? { scriptPubKey: params.scriptPubKey }
        : null;

    if (!query) {
      this.log('fetchTxHistory: no address or scriptPubKey provided, returning empty');
      return [];
    }

    return utxosToTxHistory(await this.getUtxos(query));
  }

  /**
   * Batch-fetch tx history for multiple targets in a single PIR batch.
   * Accepts any mix of address strings and raw scriptPubKey objects.
   *
   * Returns Map keyed by canonical form (address or "spk:<hex>").
   */
  async fetchTxHistoryBatch(queries: ScriptQuery[]): Promise<Map<string, TxHistoryEntry[]>> {
    const batchUtxos = await this.getUtxosBatch(queries);
    const result = new Map<string, TxHistoryEntry[]>();
    for (const [key, utxos] of batchUtxos) {
      result.set(key, utxosToTxHistory(utxos));
    }
    return result;
  }

  // ─── Non-sensitive methods (Esplora fallback) ───────────────────────────

  async fetchTx(txId: string): Promise<string> {
    return this.esplora.fetchTx(txId);
  }

  async fetchFeeEstimates(): Promise<Record<string, number>> {
    return this.esplora.fetchFeeEstimates();
  }

  async fetchBlockStatus(blockHeight: number): Promise<BlockStatus | undefined> {
    return this.esplora.fetchBlockStatus(blockHeight);
  }

  async fetchBlockHeight(): Promise<number> {
    return this.esplora.fetchBlockHeight();
  }

  async push(txHex: string): Promise<string> {
    return this.esplora.push(txHex);
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function utxosToAddressInfo(utxos: Utxo[]): AddressInfo {
  let balance = 0;
  const txids = new Set<string>();
  for (const u of utxos) {
    balance += u.value;
    txids.add(u.txid);
  }
  return {
    balance,
    txCount: txids.size,
    unconfirmedBalance: 0,
    unconfirmedTxCount: 0,
  };
}

function utxosToTxHistory(utxos: Utxo[]): TxHistoryEntry[] {
  const seen = new Set<string>();
  const entries: TxHistoryEntry[] = [];
  for (const u of utxos) {
    if (!seen.has(u.txid)) {
      seen.add(u.txid);
      entries.push({
        txId: u.txid,
        blockHeight: 0,      // Unknown from PIR; consumer calls fetchTx to learn more
        irreversible: true,   // In the confirmed UTXO set
      });
    }
  }
  return entries;
}
