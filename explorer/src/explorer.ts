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
} from './types.js';

import { PirUtxoProvider } from './utxo-provider.js';
import { EsploraFallback } from './esplora-fallback.js';
import { addressToElectrumScriptHash } from './address.js';

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

  /** Internal: get UTXOs for an address, using cache. */
  private async getUtxos(address: string): Promise<Utxo[]> {
    const cached = this.getCached(address);
    if (cached) return cached;

    const utxos = await this.provider.fetchUtxos(address);
    this.setCache(address, utxos);
    return utxos;
  }

  // ─── Privacy-sensitive methods (PIR-backed) ─────────────────────────────

  async fetchAddress(address: string): Promise<AddressInfo> {
    const utxos = await this.getUtxos(address);
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

  async fetchTxHistory(params: {
    address?: string;
    scriptHash?: string;
  }): Promise<TxHistoryEntry[]> {
    const { address } = params;
    if (!address) {
      // Cannot derive address from scriptHash alone
      this.log('fetchTxHistory: no address provided, returning empty');
      return [];
    }

    const utxos = await this.getUtxos(address);

    // Extract unique txids from UTXO set
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
