/**
 * Standalone demo of anonymous rate-limiting credentials (ARC + Cashu),
 * end-to-end: mint → obtain → present → verify, with quota + exhaustion.
 *
 * This page is intentionally separate from the main PIR client and the wire
 * explorer. It talks only to the `dev-issuer` (one process, free issuance, no
 * Lightning, no PIR database):
 *
 *   cargo run -p dev-issuer            # http://127.0.0.1:5601
 *   cd web && npm run dev              # open /ratelimit-demo.html
 *
 * The dev-issuer co-locates the credential *verify* gate (same crypto as the
 * PIR server's `unified_server` gate) so the demo needs no PIR database. In
 * production the identical present frames go over WebSocket to the PIR
 * server's gate; here they go over HTTP to the dev-issuer verify endpoints.
 */

import { initSdkWasm, requireSdkWasm } from './sdk-bridge.js';
import { ArcCredentialManager } from './credential-manager.js';
import { CashuBatPool, mintBatPool } from './cashu-bat.js';
import { getArcPubkey, issueArcCredential, presentArc, presentCashu } from './payment-client.js';

/** Must match the verifier's DEFAULT_REQUEST_CONTEXT and the dev-issuer. */
const REQUEST_CONTEXT = new TextEncoder().encode('bitcoin-pir-v1');

type Col = 'arc' | 'cashu';
type Kind = 'info' | 'ok' | 'err';

const el = (id: string) => document.getElementById(id) as HTMLElement;
const input = (id: string) => document.getElementById(id) as HTMLInputElement;
const button = (id: string) => document.getElementById(id) as HTMLButtonElement;

function issuerUrl(): string {
  return input('issuer').value.trim().replace(/\/+$/, '');
}

function log(col: Col, msg: string, kind: Kind = 'info') {
  const pre = el(`${col}-log`);
  const line = document.createElement('div');
  line.className = `line ${kind}`;
  line.textContent = `${new Date().toLocaleTimeString()}  ${msg}`;
  pre.appendChild(line);
  pre.scrollTop = pre.scrollHeight;
}

function setStatus(col: Col, msg: string) {
  el(`${col}-status`).textContent = msg;
}

/** Render an N-of-M quota meter (used boxes filled). */
function setMeter(col: Col, remaining: number, total: number) {
  const meter = el(`${col}-meter`);
  meter.innerHTML = '';
  for (let i = 0; i < total; i++) {
    const cell = document.createElement('span');
    cell.className = 'cell ' + (i < remaining ? 'full' : 'spent');
    meter.appendChild(cell);
  }
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

// ─── ARC (multi-show: one credential, N presentations) ────────────────────

let credMgr: ArcCredentialManager | null = null;
let lastArcFrame: Uint8Array | null = null;

async function arcMint() {
  button('arc-mint').disabled = true;
  try {
    const limit = Math.max(1, parseInt(input('arc-limit').value, 10) || 8);
    log('arc', `Minting ARC credential (limit ${limit})…`);

    await initSdkWasm();
    const sdk = requireSdkWasm();

    const req = new sdk.WasmArcCredentialRequest(REQUEST_CONTEXT);
    log('arc', `Built blinded credential request (${req.request_bytes().length} B).`);

    const pubkey = await getArcPubkey(issuerUrl());
    const response = await issueArcCredential(issuerUrl(), req.request_bytes());
    log('arc', `Issuer signed it (response ${response.length} B).`);

    const credBytes = req.finalize(pubkey, response);
    log('arc', `Finalized → ${credBytes.length}-byte credential.`, 'ok');

    const presCtx = randomBytes(32);
    credMgr = new ArcCredentialManager(credBytes, presCtx, limit);

    setStatus('arc', `Credential ready — ${credMgr.remaining}/${limit} presentations left`);
    setMeter('arc', credMgr.remaining, limit);
    button('arc-present').disabled = false;
  } catch (e) {
    log('arc', `Mint failed: ${(e as Error).message}`, 'err');
  } finally {
    button('arc-mint').disabled = false;
  }
}

async function arcPresent() {
  if (!credMgr) return;
  button('arc-present').disabled = true;
  try {
    if (credMgr.exhausted) {
      log('arc', 'Credential exhausted — mint a new one.', 'err');
      return;
    }
    // buildPresentFrame() advances the nonce (throws once exhausted).
    const frame = await credMgr.buildPresentFrame(REQUEST_CONTEXT);
    lastArcFrame = frame;
    const result = await presentArc(issuerUrl(), frame);

    if (result.ok) {
      log('arc', `Presented #${credMgr.used} → accepted ✓`, 'ok');
    } else {
      log('arc', `Presented → rejected: ${result.reason}`, 'err');
    }
    setStatus('arc', `${credMgr.remaining}/${credMgr.limit} presentations left`);
    setMeter('arc', credMgr.remaining, credMgr.limit);
    button('arc-replay').disabled = false;
  } catch (e) {
    log('arc', `Exhausted client-side: ${(e as Error).message}`, 'err');
    setStatus('arc', `0/${credMgr.limit} — exhausted`);
  } finally {
    button('arc-present').disabled = credMgr.exhausted;
  }
}

// ─── Cashu (single-show: a pool of one-time BATs) ─────────────────────────

let pool: CashuBatPool | null = null;
let lastBatFrame: Uint8Array | null = null;
let cashuTotal = 0;

async function cashuMint() {
  button('cashu-mint').disabled = true;
  try {
    const count = Math.max(1, parseInt(input('cashu-count').value, 10) || 5);
    log('cashu', `Minting a pool of ${count} BATs…`);
    pool = await mintBatPool(issuerUrl(), count);
    cashuTotal = count;
    lastBatFrame = null;
    setStatus('cashu', `Pool ready — ${pool.remaining} BATs`);
    setMeter('cashu', pool.remaining, cashuTotal);
    button('cashu-present').disabled = false;
    button('cashu-replay').disabled = true;
    log('cashu', `Pool minted (${pool.remaining} single-use BATs).`, 'ok');
  } catch (e) {
    log('cashu', `Mint failed: ${(e as Error).message}`, 'err');
  } finally {
    button('cashu-mint').disabled = false;
  }
}

async function cashuPresent() {
  if (!pool) return;
  button('cashu-present').disabled = true;
  try {
    if (pool.exhausted) {
      log('cashu', 'Pool empty — mint more BATs.', 'err');
      return;
    }
    const frame = pool.buildPresentFrame(); // pops one BAT
    lastBatFrame = frame;
    const result = await presentCashu(issuerUrl(), frame);
    if (result.ok) {
      log('cashu', `Spent a BAT → accepted ✓ (${pool.remaining} left)`, 'ok');
    } else {
      log('cashu', `Rejected: ${result.reason}`, 'err');
    }
    setStatus('cashu', `${pool.remaining} BATs left`);
    setMeter('cashu', pool.remaining, cashuTotal);
    button('cashu-replay').disabled = false;
  } catch (e) {
    log('cashu', `Present failed: ${(e as Error).message}`, 'err');
  } finally {
    button('cashu-present').disabled = pool.exhausted;
  }
}

async function cashuReplay() {
  if (!lastBatFrame) return;
  log('cashu', 'Re-presenting the last (already-spent) BAT…');
  try {
    const result = await presentCashu(issuerUrl(), lastBatFrame);
    if (result.ok) {
      log('cashu', 'Accepted again?! (unexpected — double-spend not caught)', 'err');
    } else {
      log('cashu', `Rejected as expected: ${result.reason} ✓`, 'ok');
    }
  } catch (e) {
    log('cashu', `Replay failed: ${(e as Error).message}`, 'err');
  }
}

/** Re-send the last ARC presentation → the gate rejects it (duplicate tag).
 *  Demonstrates ARC's server-side anti-replay (each nonce is single-use even
 *  though the credential is multi-show). */
async function arcReplay() {
  if (!lastArcFrame) return;
  log('arc', 'Re-presenting the last (already-used) presentation…');
  try {
    const result = await presentArc(issuerUrl(), lastArcFrame);
    if (result.ok) {
      log('arc', 'Accepted again?! (unexpected — replay not caught)', 'err');
    } else {
      log('arc', `Rejected as expected: ${result.reason} ✓`, 'ok');
    }
  } catch (e) {
    log('arc', `Replay failed: ${(e as Error).message}`, 'err');
  }
}

// ─── Auto-run (mint, then present to exhaustion) ──────────────────────────

async function arcRunAll() {
  button('arc-run').disabled = true;
  try {
    await arcMint();
    if (!credMgr) return;
    while (!credMgr.exhausted) await arcPresent();
    log('arc', 'Auto-run complete — credential exhausted.', 'ok');
  } finally {
    button('arc-run').disabled = false;
  }
}

async function cashuRunAll() {
  button('cashu-run').disabled = true;
  try {
    await cashuMint();
    if (!pool) return;
    while (!pool.exhausted) await cashuPresent();
    log('cashu', 'Auto-run complete — pool empty.', 'ok');
  } finally {
    button('cashu-run').disabled = false;
  }
}

// ─── Issuer reachability banner ───────────────────────────────────────────

async function checkIssuer() {
  const banner = el('issuer-banner');
  banner.className = 'banner checking';
  banner.textContent = 'Checking issuer…';
  try {
    const resp = await fetch(`${issuerUrl()}/health`);
    if (resp.ok) {
      banner.className = 'banner ok';
      banner.textContent = `✓ Issuer reachable at ${issuerUrl()}`;
    } else {
      banner.className = 'banner err';
      banner.textContent = `Issuer responded HTTP ${resp.status} — is this the dev-issuer?`;
    }
  } catch {
    banner.className = 'banner err';
    banner.textContent = `✗ Issuer unreachable at ${issuerUrl()} — start it with:  cargo run -p dev-issuer`;
  }
}

// ─── Wire up ──────────────────────────────────────────────────────────────

button('arc-mint').onclick = arcMint;
button('arc-present').onclick = arcPresent;
button('arc-replay').onclick = arcReplay;
button('arc-run').onclick = arcRunAll;
button('cashu-mint').onclick = cashuMint;
button('cashu-present').onclick = cashuPresent;
button('cashu-replay').onclick = cashuReplay;
button('cashu-run').onclick = cashuRunAll;
button('issuer-check').onclick = checkIssuer;

log('arc', 'Ready. Start the dev-issuer, then click "Mint credential".');
log('cashu', 'Ready. Start the dev-issuer, then click "Mint BAT pool".');
void checkIssuer();
