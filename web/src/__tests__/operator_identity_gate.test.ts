import { describe, it, expect } from 'vitest';
import { gateOperatorIdentity } from '../dpf-adapter.js';
import type { WasmAnnounceVerification } from '../sdk-bridge.js';

/**
 * Minimal fake of the WASM bundle handle. Only `checkPinnedOperator` /
 * `checkChannelBinding` behaviour matters — they throw (as the real
 * wasm-bindgen methods do) when `throwOn` selects them. The getters
 * stand in for a parsed bundle so we can assert the surfaced fields.
 */
function fakeBundle(throwOn?: 'operator' | 'channel'): WasmAnnounceVerification {
  return {
    serverId: 'pir1',
    operatorPubkeyHex: '47d98cb6'.padEnd(64, '0'),
    identityPubkeyHex: 'dbefff8b'.padEnd(64, '0'),
    channelPub: new Uint8Array(32),
    channelPubHex: '0'.repeat(64),
    binarySha256Hex: '0'.repeat(64),
    gitRev: 'test-rev',
    validFrom: 0n,
    validUntil: 1811051894n,
    issuedAt: 1779515936n,
    chainVerified: true,
    chainError: '',
    checkPinnedOperator() {
      if (throwOn === 'operator') {
        throw new Error(
          'announce: cert.operator_pubkey (aa…) does not match pinned operator (bb…)',
        );
      }
    },
    checkChannelBinding() {
      if (throwOn === 'channel') {
        throw new Error(
          'announce: bundle channel_pub (aa…) does not match the handshake key (bb…)',
        );
      }
    },
    free() {},
  } as unknown as WasmAnnounceVerification;
}

const PIN = new Uint8Array(32);
const CHANNEL = new Uint8Array(32);

describe('gateOperatorIdentity', () => {
  it("returns 'verified' with bundle fields when both checks pass", () => {
    const r = gateOperatorIdentity(fakeBundle(), PIN, CHANNEL, 0n);
    expect(r.state).toBe('verified');
    expect(r.serverId).toBe('pir1');
    expect(r.gitRev).toBe('test-rev');
    expect(r.validUntil).toBe(1811051894); // bigint → number
    expect(r.error).toBeUndefined();
  });

  it("returns 'unverified' when the operator-pin check throws", () => {
    const r = gateOperatorIdentity(fakeBundle('operator'), PIN, CHANNEL, 0n);
    expect(r.state).toBe('unverified');
    expect(r.error).toMatch(/does not match pinned operator/);
    // best-effort identifying fields still surfaced for diagnostics
    expect(r.serverId).toBe('pir1');
  });

  it("returns 'unverified' when the channel-binding check throws", () => {
    const r = gateOperatorIdentity(fakeBundle('channel'), PIN, CHANNEL, 0n);
    expect(r.state).toBe('unverified');
    expect(r.error).toMatch(/does not match the handshake key/);
  });
});
