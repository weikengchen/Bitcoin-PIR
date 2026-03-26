/**
 * Address conversion utilities for the PIR Explorer adapter.
 *
 * Bridges between Bitcoin address formats and the hash formats used by
 * different systems (PIR, Electrum, Esplora).
 */

import {
  addressToScriptPubKey,
  scriptHash as hash160,
  sha256,
  hexToBytes,
  bytesToHex,
  reverseBytes,
} from 'bitcoin-batch-pir-web-client';

/**
 * Convert a Bitcoin address to its scriptPubKey hex.
 * Supports P2PKH, P2SH, P2WPKH, P2WSH, P2TR.
 */
export function addressToSpk(address: string): string {
  const spk = addressToScriptPubKey(address);
  if (!spk) throw new Error(`Unsupported address format: ${address}`);
  return spk;
}

/**
 * Convert a Bitcoin address to the 20-byte PIR scriptHash (HASH160 of scriptPubKey).
 * This is the format the PIR database is indexed by.
 */
export function addressToPirScriptHash(address: string): Uint8Array {
  const spkHex = addressToSpk(address);
  const spkBytes = hexToBytes(spkHex);
  return hash160(spkBytes);
}

/**
 * Convert a Bitcoin address to the Electrum-style scriptHash.
 * SHA256(scriptPubKey), byte-reversed, hex-encoded.
 * This is what @bitcoinerlab/explorer uses for fetchScriptHash.
 */
export function addressToElectrumScriptHash(address: string): string {
  const spkHex = addressToSpk(address);
  const spkBytes = hexToBytes(spkHex);
  const hash = sha256(spkBytes);
  return bytesToHex(reverseBytes(hash));
}

/**
 * Convert an Electrum-style scriptHash (reversed SHA256 hex) to a
 * scriptPubKey hex. This is a one-way hash — we cannot reverse it.
 * Returns null (the Electrum scriptHash alone is not enough to derive
 * the scriptPubKey or the PIR HASH160).
 *
 * For PirExplorer, callers should prefer using address-based methods.
 */
export function electrumScriptHashToSpk(_scriptHash: string): null {
  return null;
}

export { hexToBytes, bytesToHex, reverseBytes };
