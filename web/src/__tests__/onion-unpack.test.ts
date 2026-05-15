/**
 * Vitest cross-language harness for `web/src/onion-unpack.ts` mirroring
 * the 8 Rust unit tests at `pir-core/src/onion_unpack.rs`. Failure
 * modes the suite covers:
 *
 *   - bits_per_coeff math (default + edge cases)
 *   - pack/unpack round-trip on full + short payloads
 *   - pack truncates oversize input silently
 *   - unpack rejects truncated / N-mismatch inputs
 *   - a second non-default config (N=4096) to catch hardcoded 13-bit
 *     assumptions
 *
 * Keeping the Rust tests and TS tests aligned is what lets the web
 * client decode plaintexts byte-for-byte the same as `pir-sdk-client`
 * — a prerequisite for the cross-language wire-leakage diff that
 * `web/src/__tests__/onion_leakage_diff.test.ts` runs against the
 * Rust reference.
 */

import { describe, it, expect } from 'vitest';
import {
  bitsPerCoeff,
  packBytesIntoCoefficients,
  unpackOnionPlaintext,
} from '../onion-unpack.js';

/** Default OnionPIRv2 `CONFIG_N2048_K1` post-port shape. */
const N = 2048;
const ENTRY_SIZE = 3328;

function synthesizeWireBytes(coeffs: BigUint64Array): Uint8Array {
  const out = new Uint8Array(4 + 8 * coeffs.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, coeffs.length, true);
  for (let i = 0; i < coeffs.length; i++) {
    dv.setBigUint64(4 + i * 8, coeffs[i], true);
  }
  return out;
}

describe('onion-unpack', () => {
  it('bitsPerCoeff(default config) === 13', () => {
    expect(bitsPerCoeff(ENTRY_SIZE, N)).toBe(13);
  });

  it('bitsPerCoeff returns null on inconsistent params', () => {
    // 3329 * 8 = 26632 not divisible by 2048 → null.
    expect(bitsPerCoeff(3329, N)).toBeNull();
    expect(bitsPerCoeff(ENTRY_SIZE, 0)).toBeNull();
  });

  it('round-trips a full-length payload', () => {
    const payload = new Uint8Array(ENTRY_SIZE);
    for (let i = 0; i < ENTRY_SIZE; i++) payload[i] = i % 251;

    const coeffs = packBytesIntoCoefficients(payload, ENTRY_SIZE, N);
    expect(coeffs.length).toBe(N);
    // Every coefficient fits within 13 bits.
    const max13 = (1n << 13n) - 1n;
    for (let i = 0; i < coeffs.length; i++) {
      expect(coeffs[i] <= max13).toBe(true);
    }

    const wire = synthesizeWireBytes(coeffs);
    const recovered = unpackOnionPlaintext(wire, N, ENTRY_SIZE);
    expect(recovered).not.toBeNull();
    expect(recovered!.length).toBe(ENTRY_SIZE);
    expect(Array.from(recovered!)).toEqual(Array.from(payload));
  });

  it('round-trips a short payload (zero-pads the tail)', () => {
    const payload = new Uint8Array(100);
    for (let i = 0; i < 100; i++) payload[i] = i;

    const coeffs = packBytesIntoCoefficients(payload, ENTRY_SIZE, N);
    const wire = synthesizeWireBytes(coeffs);
    const recovered = unpackOnionPlaintext(wire, N, ENTRY_SIZE);
    expect(recovered).not.toBeNull();
    expect(recovered!.length).toBe(ENTRY_SIZE);
    expect(Array.from(recovered!.slice(0, 100))).toEqual(Array.from(payload));
    for (let i = 100; i < ENTRY_SIZE; i++) {
      expect(recovered![i]).toBe(0);
    }
  });

  it('unpack rejects short input', () => {
    const short = new Uint8Array(4 + 8 * N - 1);
    expect(unpackOnionPlaintext(short, N, ENTRY_SIZE)).toBeNull();
  });

  it('unpack rejects N mismatch', () => {
    const wire = new Uint8Array(4 + 8 * N);
    const dv = new DataView(wire.buffer);
    dv.setUint32(0, 4096, true); // claim N=4096
    expect(unpackOnionPlaintext(wire, N, ENTRY_SIZE)).toBeNull();
  });

  it('pack truncates oversize input silently', () => {
    const oversize = new Uint8Array(ENTRY_SIZE + 100).fill(0xab);
    const coeffs = packBytesIntoCoefficients(oversize, ENTRY_SIZE, N);
    const wire = synthesizeWireBytes(coeffs);
    const recovered = unpackOnionPlaintext(wire, N, ENTRY_SIZE);
    expect(recovered).not.toBeNull();
    expect(recovered!.length).toBe(ENTRY_SIZE);
    for (let i = 0; i < ENTRY_SIZE; i++) {
      expect(recovered![i]).toBe(0xab);
    }
  });

  it('round-trips at N=4096, entry_size=19968 (CONFIG_N4096_K2_MP)', () => {
    const N4096 = 4096;
    const ENTRY_19968 = 19968;
    expect(bitsPerCoeff(ENTRY_19968, N4096)).toBe(39);

    const payload = new Uint8Array(ENTRY_19968);
    for (let i = 0; i < ENTRY_19968; i++) payload[i] = i & 0xff;

    const coeffs = packBytesIntoCoefficients(payload, ENTRY_19968, N4096);
    expect(coeffs.length).toBe(N4096);
    const wire = synthesizeWireBytes(coeffs);
    const recovered = unpackOnionPlaintext(wire, N4096, ENTRY_19968);
    expect(recovered).not.toBeNull();
    expect(Array.from(recovered!)).toEqual(Array.from(payload));
  });
});
