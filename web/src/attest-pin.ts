/**
 * Operator-pinned 32-byte SHA-256 fingerprint of the AMD ARK (Root
 * Key) certificate.
 *
 * This is the trust anchor for browser-side AMD VCEK chain validation
 * (Slice D). When the adapter calls `verifyVcekChain`, it computes
 * SHA-256(ARK_DER) and compares to this constant; mismatch = the
 * server's bundled cert chain doesn't actually root at AMD's ARK.
 *
 * Pinned 2026-05-03 by the operator from the Turin family ARK at
 * https://kdsintf.amd.com/vcek/v1/Turin/cert_chain (second PEM block).
 *
 * To rotate (very rare — AMD ARKs have ~25-year validity):
 *   1. Re-fetch cert_chain.pem from AMD KDS.
 *   2. Run on the operator's laptop:
 *        # Split, then SHA-256 the ARK DER:
 *        csplit -z -f cert_ -b "%d.pem" cert_chain.pem '/-----BEGIN CERT/' '{*}'
 *        openssl x509 -in cert_1.pem -outform DER | sha256sum
 *   3. Replace the hex below + rebuild + redeploy the web bundle.
 *
 * Same fingerprint applies to all Turin-family chips. (Genoa, Milan,
 * etc. would have different ARKs and need their own pins; we only
 * deploy on Turin so far.)
 */
export const AMD_TURIN_ARK_FINGERPRINT_HEX =
  '1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a';

/** Same as `AMD_TURIN_ARK_FINGERPRINT_HEX` but as Uint8Array — the
 *  shape `WasmAttestVerification.verifyVcekChain` expects. */
export const AMD_TURIN_ARK_FINGERPRINT: Uint8Array = (() => {
  const hex = AMD_TURIN_ARK_FINGERPRINT_HEX;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
})();

/**
 * Per-server build-time pins for values the SEV-SNP report surfaces.
 * Defense in depth on top of the ARK chain validation: even with a
 * verified chain, mismatches on these self-reported (but in Tier 3
 * MEASUREMENT-covered) values trip state to `'mismatch'` and the
 * adapter refuses to upgrade to the encrypted channel.
 *
 * - `measurementHex`: 96-char hex (48 bytes) — the launch
 *   MEASUREMENT AMD's PSP signs into every report. For Tier 3 this
 *   covers OVMF + UKI bytes (kernel + initramfs + cmdline) and
 *   therefore the unified_server binary itself, since it lives
 *   inside the initramfs. Any binary substitution flips this value.
 * - `binarySha256Hex`: 64-char hex — SHA-256 of the running
 *   unified_server binary, server-self-reported. Cross-checkable
 *   against MEASUREMENT (transitively, for Tier 3) and against
 *   the cmdline pin (for Slice 2 with bpir-verify hook).
 *
 * Operator publishes both in `docs/PHASE3_ROADMAP.md::Attested
 * values published`. Update here whenever you re-bake + republish
 * the UKI on pir2 (every binary change).
 */
export interface ServerAttestPin {
  measurementHex?: string;
  binarySha256Hex?: string;
  /** Human-readable description shown in the badge tooltip. */
  description?: string;
}

/**
 * pir2.chenweikeng.com — VPSBG Tier 3 (Slice 3 lockdown), v4. Same
 * reproducibility flags as v3 (sub-tasks 1 + 2 + 3(b) + 4) but rebuilt
 * with the upstream OnionPIR CMake-4.x compatibility fix landed (rev
 * 0c84595f), so the build no longer needs the in-place cargo-cache
 * patch hack we used for v3.
 * Pinned 2026-05-04 from the v4 deploy (UKI sha `e835a516…f8396da0`).
 */
export const PIR2_TIER3_PIN: ServerAttestPin = {
  // Tier 3 UKI v5 — 2026-05-04. Includes V2 hint pool, hardened SEV module validation.
  measurementHex:
    'ac03dde40f5496051a580d062934d879e132e8ba7db7b18670ccc457f6655dad8d7111565b25ccfaa154167faf626304',
  binarySha256Hex:
    '5877e304ee1447fa3747073f5f8f2783abe24c1d459c123d39e30860829ed256',
  description: 'pir2.chenweikeng.com (VPSBG, SEV-SNP, Tier 3 UKI v5)',
};

/**
 * pir1.chenweikeng.com — Hetzner i7-8700, Intel chip, NO SEV-SNP.
 * No MEASUREMENT to pin (no SEV report). binary_sha256 IS pinnable —
 * the value isn't hardware-backed without SEV, but pinning still
 * detects accidental drift between what the operator claims is
 * deployed and what's actually running.
 */
export const PIR1_PIN: ServerAttestPin = {
  // No measurementHex — Hetzner has no SEV.
  binarySha256Hex:
    '11f0860bee3c00da478ecddb43a9431393b27c78952a0bd69f0561d7d509452d',
  description: 'pir1.chenweikeng.com (Hetzner i7-8700, no SEV)',
};
