/**
 * HTTP client for the credential issuer (the "obtain" leg of anonymous
 * rate-limiting).
 *
 * In the demo this talks to `dev-issuer` — a DEV-ONLY free issuer with no
 * payment. In production the same endpoints would be served by the
 * Lightning-backed payment service after a paid invoice. Either way the wire
 * shapes are identical: raw binary bodies, no JSON.
 *
 * Typical ARC obtain flow (pairs with the `WasmArcCredentialRequest` WASM
 * binding and `ArcCredentialManager`):
 *
 *   import { WasmArcCredentialRequest } from '<wasm pkg>';
 *   import { getArcPubkey, issueArcCredential } from './payment-client';
 *   import { ArcCredentialManager } from './credential-manager';
 *
 *   const req = new WasmArcCredentialRequest(REQUEST_CONTEXT);   // 1. build request
 *   const pubkey   = await getArcPubkey(issuerUrl);              // 2. issuer pubkey
 *   const response = await issueArcCredential(issuerUrl,
 *                                             req.request_bytes()); // 3. issue
 *   const credBytes = req.finalize(pubkey, response);            // 4. finalize → 131B
 *   const mgr = new ArcCredentialManager(credBytes, presCtx, limit);
 *
 * (Cashu mint method added in Phase 2.)
 */

import { hexToBytes } from './hash.js';

/** Byte sizes pinned to the arc crate's wire formats (P-256, NE=33, NS=32). */
export const ARC_PUBKEY_BYTES = 99;
export const ARC_REQUEST_BYTES = 226;
export const ARC_RESPONSE_BYTES = 454;

/** Compressed secp256k1 point size (Cashu blinded messages / signatures). */
export const CASHU_POINT_BYTES = 33;

/** Trim a trailing slash so `${base}/dev/...` never doubles up. */
function normalizeBase(url: string): string {
  return url.replace(/\/+$/, '');
}

async function readBytes(resp: Response): Promise<Uint8Array> {
  const buf = await resp.arrayBuffer();
  return new Uint8Array(buf);
}

/**
 * Fetch the issuer's ARC public key (99-byte `ServerPublicKey`).
 *
 * Pass this to `WasmArcCredentialRequest.finalize(pubkey, response)`.
 * @throws if the issuer is unreachable, errors, or returns the wrong length.
 */
export async function getArcPubkey(issuerUrl: string): Promise<Uint8Array> {
  const url = `${normalizeBase(issuerUrl)}/dev/arc/pubkey`;
  let resp: Response;
  try {
    resp = await fetch(url, { method: 'GET' });
  } catch (e) {
    throw new Error(`issuer unreachable at ${url}: ${(e as Error).message}`);
  }
  if (!resp.ok) {
    throw new Error(`GET ${url} failed: HTTP ${resp.status}`);
  }
  const bytes = await readBytes(resp);
  if (bytes.length !== ARC_PUBKEY_BYTES) {
    throw new Error(
      `ARC pubkey: expected ${ARC_PUBKEY_BYTES} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

/**
 * Submit a blinded 226-byte `CredentialRequest` and receive the issuer's
 * 454-byte `CredentialResponse`.
 *
 * `requestBytes` comes from `WasmArcCredentialRequest.request_bytes()`; feed
 * the returned bytes to `.finalize(pubkey, response)`.
 * @throws if the request length is wrong, the issuer rejects it (HTTP 4xx),
 *   or the response length is unexpected.
 */
export async function issueArcCredential(
  issuerUrl: string,
  requestBytes: Uint8Array,
): Promise<Uint8Array> {
  if (requestBytes.length !== ARC_REQUEST_BYTES) {
    throw new Error(
      `ARC request: expected ${ARC_REQUEST_BYTES} bytes, got ${requestBytes.length}`,
    );
  }
  const url = `${normalizeBase(issuerUrl)}/dev/arc/issue`;
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      // Copy into a fresh ArrayBuffer so a Uint8Array view with a non-zero
      // byteOffset (e.g. a subarray) is sent correctly.
      body: requestBytes.slice(),
    });
  } catch (e) {
    throw new Error(`issuer unreachable at ${url}: ${(e as Error).message}`);
  }
  if (!resp.ok) {
    const detail = await resp.text().catch(() => '');
    throw new Error(
      `POST ${url} failed: HTTP ${resp.status}${detail ? ` — ${detail.trim()}` : ''}`,
    );
  }
  const bytes = await readBytes(resp);
  if (bytes.length !== ARC_RESPONSE_BYTES) {
    throw new Error(
      `ARC response: expected ${ARC_RESPONSE_BYTES} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

// ─── Cashu Blind Auth (NUT-22) ────────────────────────────────────────────

/** A Cashu keyset as published by the mint. */
export interface CashuKeyset {
  /** Keyset id string (e.g. `02ab…-auth`); goes in the authA token's `id`. */
  id: string;
  /** Mint public key `K = k·G` (33-byte compressed point), for unblinding. */
  pubkey: Uint8Array;
}

/**
 * Fetch the mint's Cashu keyset (`{id, pubkey}`).
 *
 * Pass `pubkey` to `WasmCashuBlind.unblind(pubkey, signature)` and `id` into
 * each minted `Bat`.
 * @throws if unreachable, errors, or the pubkey isn't a 33-byte point.
 */
export async function getCashuKeyset(issuerUrl: string): Promise<CashuKeyset> {
  const url = `${normalizeBase(issuerUrl)}/dev/cashu/keyset`;
  let resp: Response;
  try {
    resp = await fetch(url, { method: 'GET' });
  } catch (e) {
    throw new Error(`issuer unreachable at ${url}: ${(e as Error).message}`);
  }
  if (!resp.ok) {
    throw new Error(`GET ${url} failed: HTTP ${resp.status}`);
  }
  let json: { id?: unknown; pubkey?: unknown };
  try {
    json = (await resp.json()) as { id?: unknown; pubkey?: unknown };
  } catch (e) {
    throw new Error(`Cashu keyset: invalid JSON: ${(e as Error).message}`);
  }
  if (typeof json.id !== 'string' || typeof json.pubkey !== 'string') {
    throw new Error('Cashu keyset: response missing string id/pubkey');
  }
  const pubkey = hexToBytes(json.pubkey);
  if (pubkey.length !== CASHU_POINT_BYTES) {
    throw new Error(
      `Cashu keyset pubkey: expected ${CASHU_POINT_BYTES} bytes, got ${pubkey.length}`,
    );
  }
  return { id: json.id, pubkey };
}

/**
 * Blind-sign a batch of blinded messages.
 *
 * `blindedMessages` is `N × 33` concatenated compressed points (each from
 * `WasmCashuBlind.blinded_message()`); the response is `N × 33` blind
 * signatures `C'` in the same order.
 * @throws if the input isn't a non-empty multiple of 33 bytes, the mint
 *   rejects it, or the response length doesn't match the request.
 */
export async function mintCashuBats(
  issuerUrl: string,
  blindedMessages: Uint8Array,
): Promise<Uint8Array> {
  if (
    blindedMessages.length === 0 ||
    blindedMessages.length % CASHU_POINT_BYTES !== 0
  ) {
    throw new Error(
      `Cashu mint: blinded messages must be a non-empty multiple of ${CASHU_POINT_BYTES} bytes, got ${blindedMessages.length}`,
    );
  }
  const url = `${normalizeBase(issuerUrl)}/dev/cashu/mint`;
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: blindedMessages.slice(),
    });
  } catch (e) {
    throw new Error(`issuer unreachable at ${url}: ${(e as Error).message}`);
  }
  if (!resp.ok) {
    const detail = await resp.text().catch(() => '');
    throw new Error(
      `POST ${url} failed: HTTP ${resp.status}${detail ? ` — ${detail.trim()}` : ''}`,
    );
  }
  const bytes = await readBytes(resp);
  if (bytes.length !== blindedMessages.length) {
    throw new Error(
      `Cashu mint: expected ${blindedMessages.length} bytes back (one signature per blinded message), got ${bytes.length}`,
    );
  }
  return bytes;
}

// ─── Credential presentation (the "verify" leg) ───────────────────────────

/** Outcome of presenting a credential to the gate. */
export interface PresentResult {
  /** True if the gate accepted the credential. */
  ok: boolean;
  /** Rejection reason (e.g. "BAT already spent") when `ok` is false. */
  reason?: string;
}

/**
 * Present an ARC credential to the verify gate.
 *
 * `presentFrame` is the full frame from `ArcCredentialManager.buildPresentFrame`
 * (`[4B len][0x08]…`). In the demo this POSTs to the dev-issuer's co-located
 * gate; in production the identical `[0x08]…` payload is sent over WebSocket to
 * the PIR server (`sendArcPresentation`). Rejection (exhausted / duplicate /
 * bad proof) returns `{ok:false}` rather than throwing.
 */
export async function presentArc(
  issuerUrl: string,
  presentFrame: Uint8Array,
): Promise<PresentResult> {
  return presentPayload(`${normalizeBase(issuerUrl)}/dev/arc/verify`, presentFrame);
}

/**
 * Present a Cashu BAT to the verify gate. `presentFrame` is the full frame
 * from `CashuBatPool.buildPresentFrame` (`[4B len][0x09]…`).
 */
export async function presentCashu(
  issuerUrl: string,
  presentFrame: Uint8Array,
): Promise<PresentResult> {
  return presentPayload(`${normalizeBase(issuerUrl)}/dev/cashu/verify`, presentFrame);
}

async function presentPayload(url: string, presentFrame: Uint8Array): Promise<PresentResult> {
  // Strip the 4-byte WS length prefix → the [variant][body] payload the gate
  // parses (byte-identical to the PIR server's WS frame payload).
  const payload = presentFrame.length >= 4 ? presentFrame.slice(4) : presentFrame.slice();
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: payload,
    });
  } catch (e) {
    throw new Error(`issuer unreachable at ${url}: ${(e as Error).message}`);
  }
  if (resp.ok) {
    return { ok: true };
  }
  const reason = (await resp.text().catch(() => '')).trim();
  return { ok: false, reason: reason || `HTTP ${resp.status}` };
}
