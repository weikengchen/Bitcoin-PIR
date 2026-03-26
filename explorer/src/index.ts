/**
 * bitcoin-pir-explorer
 *
 * PIR-backed Explorer adapter for the bitcoinjs ecosystem.
 *
 * Two entry points:
 *
 * 1. PirExplorer — implements the @bitcoinerlab/explorer Explorer interface.
 *    Drop-in replacement for EsploraExplorer / ElectrumExplorer.
 *    Works with @bitcoinerlab/discovery for HD wallet UTXO discovery.
 *
 * 2. PirUtxoProvider — standalone high-level UTXO fetcher.
 *    Simpler API for wallets using bitcoinjs-lib directly.
 */

export { PirExplorer } from './explorer.js';
export { PirUtxoProvider } from './utxo-provider.js';
export { EsploraFallback } from './esplora-fallback.js';

export {
  addressToSpk,
  addressToPirScriptHash,
  addressToElectrumScriptHash,
} from './address.js';

export type {
  Explorer,
  BlockStatus,
  AddressInfo,
  TxHistoryEntry,
  Utxo,
  PirBackend,
  PirExplorerConfig,
} from './types.js';
