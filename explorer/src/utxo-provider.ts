/**
 * PirUtxoProvider — standalone PIR-backed UTXO fetcher.
 *
 * High-level API that any bitcoinjs-lib wallet can use directly:
 *   const utxos = await provider.fetchUtxos('bc1q...');
 *   // → [{ txid, vout, value }]  ready for psbt.addInput()
 *
 * Supports all three PIR backends (DPF, HarmonyPIR, OnionPIR).
 */

import {
  BatchPirClient,
  type UtxoEntry as DpfUtxoEntry,
  type QueryResult,
  HarmonyPirClient,
  type HarmonyUtxoEntry,
  type HarmonyQueryResult,
  OnionPirWebClient,
  bytesToHex,
  reverseBytes,
} from 'bitcoin-batch-pir-web-client';

import { addressToPirScriptHash, addressToSpk } from './address.js';
import type { Utxo, PirBackend } from './types.js';

// ─── Unified client wrapper ────────────────────────────────────────────────

/**
 * Wraps the three PIR backends behind a uniform interface.
 * Handles address → scriptHash conversion and result normalization.
 */
class PirClientWrapper {
  private backend: PirBackend;
  private dpfClient?: BatchPirClient;
  private harmonyClient?: HarmonyPirClient;
  private onionpirClient?: OnionPirWebClient;
  private onLog?: (msg: string) => void;

  constructor(backend: PirBackend, onLog?: (msg: string) => void) {
    this.backend = backend;
    this.onLog = onLog;
  }

  async connect(): Promise<void> {
    switch (this.backend.type) {
      case 'dpf': {
        this.dpfClient = new BatchPirClient({
          server0Url: this.backend.server0Url,
          server1Url: this.backend.server1Url,
          onLog: this.onLog ? (msg) => this.onLog!(msg) : undefined,
        });
        await this.dpfClient.connect();
        break;
      }
      case 'harmony': {
        this.harmonyClient = new HarmonyPirClient({
          hintServerUrl: this.backend.hintServerUrl,
          queryServerUrl: this.backend.queryServerUrl,
          prpBackend: this.backend.prpBackend,
          onProgress: this.onLog,
        });
        await this.harmonyClient.connectQueryServer();
        await this.harmonyClient.fetchHints();
        break;
      }
      case 'onionpir': {
        this.onionpirClient = new OnionPirWebClient({
          serverUrl: this.backend.serverUrl,
          onLog: this.onLog ? (msg) => this.onLog!(msg) : undefined,
        });
        await this.onionpirClient.connect();
        break;
      }
    }
  }

  disconnect(): void {
    this.dpfClient?.disconnect();
    this.harmonyClient?.disconnect();
    this.onionpirClient?.disconnect();
  }

  isConnected(): boolean {
    switch (this.backend.type) {
      case 'dpf': return this.dpfClient?.isConnected() ?? false;
      case 'harmony': return this.harmonyClient !== undefined;
      case 'onionpir': return this.onionpirClient?.isConnected() ?? false;
    }
  }

  /**
   * Query multiple addresses in a single PIR batch.
   * Returns a Map from address → Utxo[].
   */
  async queryBatch(addresses: string[]): Promise<Map<string, Utxo[]>> {
    const result = new Map<string, Utxo[]>();

    switch (this.backend.type) {
      case 'dpf': {
        const scriptHashes = addresses.map(a => addressToPirScriptHash(a));
        const results = await this.dpfClient!.queryBatch(scriptHashes);
        for (let i = 0; i < addresses.length; i++) {
          result.set(addresses[i], results[i] ? normalizeQueryResult(results[i]!) : []);
        }
        break;
      }
      case 'harmony': {
        const harmonyResults = await this.harmonyClient!.queryBatch(addresses);
        for (let i = 0; i < addresses.length; i++) {
          const hr = harmonyResults.get(i);
          result.set(addresses[i], hr ? normalizeHarmonyResult(hr) : []);
        }
        break;
      }
      case 'onionpir': {
        const scriptHashes = addresses.map(a => addressToPirScriptHash(a));
        const results = await this.onionpirClient!.queryBatch(scriptHashes);
        for (let i = 0; i < addresses.length; i++) {
          result.set(addresses[i], results[i] ? normalizeQueryResult(results[i]!) : []);
        }
        break;
      }
    }

    return result;
  }
}

/** Convert DPF/OnionPIR QueryResult entries to Utxo[]. */
function normalizeQueryResult(qr: QueryResult): Utxo[] {
  return qr.entries.map(e => ({
    txid: bytesToHex(reverseBytes(e.txid)),
    vout: e.vout,
    value: Number(e.amount),
  }));
}

/** Convert HarmonyPIR result to Utxo[]. */
function normalizeHarmonyResult(hr: HarmonyQueryResult): Utxo[] {
  if (hr.whale) return [];
  return hr.utxos.map(e => ({
    txid: e.txid,
    vout: e.vout,
    value: e.value,
  }));
}

// ─── Public PirUtxoProvider class ──────────────────────────────────────────

export class PirUtxoProvider {
  private client: PirClientWrapper;
  private onLog?: (msg: string) => void;

  constructor(config: { backend: PirBackend; onLog?: (msg: string) => void }) {
    this.onLog = config.onLog;
    this.client = new PirClientWrapper(config.backend, config.onLog);
  }

  async connect(): Promise<void> {
    await this.client.connect();
  }

  disconnect(): void {
    this.client.disconnect();
  }

  isConnected(): boolean {
    return this.client.isConnected();
  }

  /**
   * Fetch UTXOs for a single Bitcoin address via PIR.
   *
   * Returns UTXOs in a format ready for bitcoinjs-lib PSBT:
   *   psbt.addInput({
   *     hash: utxo.txid,
   *     index: utxo.vout,
   *     witnessUtxo: { script: scriptPubKeyBuffer, value: utxo.value }
   *   });
   */
  async fetchUtxos(address: string): Promise<Utxo[]> {
    const results = await this.client.queryBatch([address]);
    return results.get(address) ?? [];
  }

  /**
   * Fetch UTXOs for multiple addresses in a single PIR batch.
   * Efficient: all addresses share the same PBC rounds.
   */
  async fetchUtxosBatch(addresses: string[]): Promise<Map<string, Utxo[]>> {
    return this.client.queryBatch(addresses);
  }

  /** Get scriptPubKey hex for an address (for witnessUtxo construction). */
  scriptPubKey(address: string): string {
    return addressToSpk(address);
  }
}
