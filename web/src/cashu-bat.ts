/**
 * Cashu Blind Auth Token (BAT) client-side integration.
 *
 * Batches of single-use BATs are obtained from the payment service after
 * paying a Lightning invoice. Each BAT is presented once per PIR query
 * batch and then consumed.
 *
 * ## Usage
 *
 * ```typescript
 * import { CashuBatPool } from './cashu-bat';
 *
 * // After paying: POST /auth/blind/mint → { blind_signatures, keyset_id }
 * const pool = new CashuBatPool(keysetId, secrets, blindSigs, mintPubkey);
 *
 * // Before each PIR query batch:
 * const batBytes = pool.popAndSerialize();
 * // Send batBytes in REQ_CASHU_BAT_PRESENT to the server
 * console.log(`Remaining: ${pool.remaining}`);
 * ```
 */

import { REQ_CASHU_BAT_PRESENT } from './constants';
import { bytesToHex } from './hash.js';
import { initSdkWasm, requireSdkWasm } from './sdk-bridge.js';
import {
  getCashuKeyset,
  mintCashuBats,
  CASHU_POINT_BYTES,
} from './payment-client.js';

/**
 * A single unspent Blind Auth Token.
 */
export interface Bat {
  /** Keyset ID this BAT belongs to. */
  keysetId: string;
  /** The secret (revealed at spend time). */
  secret: string;
  /** The unblinded BDHKE signature C (compressed secp256k1 point, hex). */
  signature: string;
}

/**
 * Manages a pool of single-use Cashu BATs.
 */
export class CashuBatPool {
  private bats: Bat[];

  constructor(bats: Bat[]) {
    this.bats = [...bats];
  }

  /** How many BATs remain unspent. */
  get remaining(): number {
    return this.bats.length;
  }

  /** Whether the pool is exhausted. */
  get exhausted(): boolean {
    return this.bats.length === 0;
  }

  /**
   * Pop one BAT and serialize it for the wire.
   *
   * Format: `authA` + base64url(JSON({id, secret, C}))
   *
   * @returns UTF-8 bytes of the authA token string.
   */
  popAndSerialize(): Uint8Array {
    const bat = this.bats.pop();
    if (!bat) throw new Error('No BATs remaining');

    const payload = JSON.stringify({
      id: bat.keysetId,
      secret: bat.secret,
      C: bat.signature,
    });

    // Base64url encode (no padding)
    const b64 = btoa(payload)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const token = `authA${b64}`;
    return new TextEncoder().encode(token);
  }

  /**
   * Build the full REQ_CASHU_BAT_PRESENT wire frame.
   *
   * Format: [4B len LE][1B variant=0x09][bat_token UTF-8 bytes]
   */
  buildPresentFrame(): Uint8Array {
    const batBytes = this.popAndSerialize();
    const payload = new Uint8Array(1 + batBytes.length);
    payload[0] = REQ_CASHU_BAT_PRESENT;
    payload.set(batBytes, 1);

    const frame = new Uint8Array(4 + payload.length);
    const view = new DataView(frame.buffer);
    view.setUint32(0, payload.length, true);
    frame.set(payload, 4);
    return frame;
  }
}

/**
 * Mint a pool of `count` single-use BATs from a Cashu mint (the "obtain" leg).
 *
 * Runs the full BDHKE flow: for each BAT, blind a fresh secret in WASM
 * (`WasmCashuBlind`), batch the blinded messages to the mint, then unblind
 * each returned signature into a `Bat`. The blinding factors never leave
 * WASM.
 *
 * Requires the SDK WASM module (initialised here, idempotently). In the demo
 * `issuerUrl` is the `dev-issuer`; in production it would be the
 * Lightning-backed mint after a paid invoice.
 *
 * @throws if `count` is not a positive integer, the mint is unreachable, or
 *   the response is malformed (errors surface from `payment-client`).
 */
export async function mintBatPool(
  issuerUrl: string,
  count: number,
): Promise<CashuBatPool> {
  if (!Number.isInteger(count) || count <= 0) {
    throw new Error(`mintBatPool: count must be a positive integer, got ${count}`);
  }

  await initSdkWasm();
  const sdk = requireSdkWasm();

  const keyset = await getCashuKeyset(issuerUrl);

  // One blind per BAT; concatenate the 33-byte blinded messages.
  const blinds = Array.from({ length: count }, () => new sdk.WasmCashuBlind());
  const blinded = new Uint8Array(count * CASHU_POINT_BYTES);
  blinds.forEach((b, i) => blinded.set(b.blinded_message(), i * CASHU_POINT_BYTES));

  // Mint → N blind signatures C', in the same order.
  const sigs = await mintCashuBats(issuerUrl, blinded);

  // Unblind each into a BAT, then release the WASM handle.
  const bats: Bat[] = blinds.map((b, i) => {
    const sig = sigs.slice(i * CASHU_POINT_BYTES, (i + 1) * CASHU_POINT_BYTES);
    const c = b.unblind(keyset.pubkey, sig);
    const bat: Bat = {
      keysetId: keyset.id,
      secret: b.secret_string(),
      signature: bytesToHex(c),
    };
    b.free();
    return bat;
  });

  return new CashuBatPool(bats);
}
