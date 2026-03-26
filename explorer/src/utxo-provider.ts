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

import { resolveToHash160, queryKey, queryToSpk } from './address.js';
import type { Utxo, PirBackend, ScriptQuery } from './types.js';

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
   * Query multiple targets in a single PIR batch.
   * Each target can be an address string or a { scriptPubKey } object.
   * Returns a Map from canonical key → Utxo[].
   */
  async queryBatch(queries: ScriptQuery[]): Promise<Map<string, Utxo[]>> {
    const keys = queries.map(q => queryKey(q));
    const result = new Map<string, Utxo[]>();

    switch (this.backend.type) {
      case 'dpf': {
        const scriptHashes = queries.map(q => resolveToHash160(q));
        const results = await this.dpfClient!.queryBatch(scriptHashes);
        for (let i = 0; i < queries.length; i++) {
          result.set(keys[i], results[i] ? normalizeQueryResult(results[i]!) : []);
        }
        break;
      }
      case 'harmony': {
        // HarmonyPIR client takes address strings; for raw SPK queries,
        // pass the HASH160 hex as the lookup key.
        const harmonyKeys = queries.map(q =>
          typeof q === 'string' ? q : bytesToHex(resolveToHash160(q))
        );
        const harmonyResults = await this.harmonyClient!.queryBatch(harmonyKeys);
        for (let i = 0; i < queries.length; i++) {
          const hr = harmonyResults.get(i);
          result.set(keys[i], hr ? normalizeHarmonyResult(hr) : []);
        }
        break;
      }
      case 'onionpir': {
        const scriptHashes = queries.map(q => resolveToHash160(q));
        const results = await this.onionpirClient!.queryBatch(scriptHashes);
        for (let i = 0; i < queries.length; i++) {
          result.set(keys[i], results[i] ? normalizeQueryResult(results[i]!) : []);
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
   * Fetch UTXOs for a single target via PIR.
   *
   * Accepts a Bitcoin address string or a raw scriptPubKey hex:
   *   provider.fetchUtxos('bc1q...')
   *   provider.fetchUtxos({ scriptPubKey: '5221...ae' })  // bare multisig
   *
   * Returns UTXOs ready for bitcoinjs-lib PSBT:
   *   psbt.addInput({
   *     hash: utxo.txid,
   *     index: utxo.vout,
   *     witnessUtxo: { script: scriptPubKeyBuffer, value: utxo.value }
   *   });
   */
  async fetchUtxos(query: ScriptQuery): Promise<Utxo[]> {
    const key = queryKey(query);
    const results = await this.client.queryBatch([query]);
    return results.get(key) ?? [];
  }

  /**
   * Fetch UTXOs for multiple targets in a single PIR batch.
   * Efficient: all queries share the same PBC rounds.
   *
   * Accepts any mix of address strings and raw scriptPubKey objects:
   *   provider.fetchUtxosBatch([
   *     'bc1q...',                             // segwit address
   *     { scriptPubKey: '5221...ae' },          // bare 2-of-3 multisig
   *     'bc1p...',                              // taproot
   *   ])
   *
   * Returns Map keyed by the canonical form: address string as-is,
   * or "spk:<hex>" for raw scriptPubKey queries.
   */
  async fetchUtxosBatch(queries: ScriptQuery[]): Promise<Map<string, Utxo[]>> {
    return this.client.queryBatch(queries);
  }

  /**
   * Get scriptPubKey hex for a query target (for witnessUtxo construction).
   * For addresses, derives it. For raw SPK queries, returns it directly.
   */
  scriptPubKey(query: ScriptQuery): string {
    return queryToSpk(query);
  }
}
