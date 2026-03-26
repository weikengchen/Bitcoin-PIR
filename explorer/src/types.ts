/**
 * Shared types for the PIR Explorer adapter.
 *
 * The Explorer interface mirrors @bitcoinerlab/explorer so that PirExplorer
 * can be used as a drop-in replacement without adding that package as a
 * runtime dependency.
 */

// ─── Query input types ──────────────────────────────────────────────────────

/**
 * A query target: either a standard Bitcoin address string, or a raw
 * scriptPubKey hex for scripts that have no address encoding (e.g. bare
 * multisig: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG).
 *
 * Both paths converge to HASH160(scriptPubKey) internally.
 */
export type ScriptQuery = string | { scriptPubKey: string };

// ─── UTXO type ──────────────────────────────────────────────────────────────

/** A confirmed UTXO returned by PIR. */
export interface Utxo {
  txid: string;       // hex, display byte order (reversed)
  vout: number;
  value: number;      // satoshis
}

// ─── PIR backend configuration ──────────────────────────────────────────────

export type PirBackend =
  | { type: 'dpf'; server0Url: string; server1Url: string }
  | { type: 'harmony'; hintServerUrl: string; queryServerUrl: string; prpBackend?: number }
  | { type: 'onionpir'; serverUrl: string };

// ─── Explorer configuration ─────────────────────────────────────────────────

export interface PirExplorerConfig {
  backend: PirBackend;
  /** Esplora REST API base URL for non-privacy-sensitive operations.
   *  Default: "https://blockstream.info/api" */
  esploraUrl?: string;
  /** How long (ms) to cache PIR results per scriptHash. Default: 60000 */
  cacheTtlMs?: number;
  /** Optional logging callback */
  onLog?: (message: string) => void;
}

// ─── Explorer interface (mirrors @bitcoinerlab/explorer) ────────────────────

export interface BlockStatus {
  blockHeight: number;
  blockHash: string;
  blockTime: number;
  irreversible: boolean;
}

export interface AddressInfo {
  balance: number;
  txCount: number;
  unconfirmedBalance: number;
  unconfirmedTxCount: number;
}

export interface TxHistoryEntry {
  txId: string;
  blockHeight: number;
  irreversible: boolean;
}

/**
 * Explorer interface compatible with @bitcoinerlab/explorer.
 *
 * Privacy-sensitive methods (fetchAddress, fetchScriptHash, fetchTxHistory)
 * are backed by PIR. Non-sensitive methods delegate to Esplora.
 */
export interface Explorer {
  connect(): Promise<void>;
  isConnected(): Promise<boolean>;
  isClosed(): boolean;
  close(): void;

  fetchAddress(address: string): Promise<AddressInfo>;
  fetchScriptHash(scriptHash: string): Promise<AddressInfo>;

  fetchTxHistory(params: {
    address?: string;
    scriptHash?: string;
  }): Promise<TxHistoryEntry[]>;

  fetchTx(txId: string): Promise<string>;
  fetchFeeEstimates(): Promise<Record<string, number>>;
  fetchBlockStatus(blockHeight: number): Promise<BlockStatus | undefined>;
  fetchBlockHeight(): Promise<number>;
  push(txHex: string): Promise<string>;
}
