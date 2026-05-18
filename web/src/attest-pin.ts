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
 * weikeng2.bitcoinpir.org — VPSBG Tier 3 UKI v16, pinned 2026-05-16.
 * Deterministic build (scripts/build_unified_server.sh +
 * build_uki_tier3.sh) on the Hetzner build host with VPSBG kernel
 * 7.0.0-15 + dracut 110.
 */
export const PIR2_TIER3_PIN: ServerAttestPin = {
  // Tier 3 UKI v16 — 2026-05-16. Rebuilt to ship the transport-level
  // WebSocket chunking fix (commit 49db31da) so OnionPIR's large
  // RegisterKeys upload survives Cloudflare. pir2 runs `--serve-queries`
  // only — no hint pool. The embedded binary (`f63b3535…`) comes from
  // the deterministic wrapper `scripts/build_unified_server.sh`.
  // NOTE (2026-05-18): pir2 is now one version BEHIND pir1 — pir1 was
  // redeployed to the Phase-3b per-group OnionPIR Merkle server
  // (`0cc87a8c…`, commit 121ea5c3) while pir2 still runs this pre-3b
  // `f63b3535…` build, so PIR1_PIN and PIR2_TIER3_PIN no longer share
  // a `binarySha256Hex`. A pir2 UKI v17 rebuild will realign them
  // (pir2 does not serve OnionPIR, so this is a hygiene gap, not a
  // functional one). MEASUREMENT captured from the v16 deploy via
  // `bpir-admin attest wss://weikeng2.bitcoinpir.org`.
  measurementHex:
    '59e276f34881fec46f68f07582b863d46944868206db14402e32000e49ab568e3d41a9df9155991345ed578c31a7ab4a',
  binarySha256Hex:
    'f63b35354c3f02037d5063a25696c3a919d14cccbcf4946f98cf6c5e75117ecd',
  description: 'weikeng2.bitcoinpir.org (VPSBG, SEV-SNP, Tier 3 UKI v16)',
};

/**
 * weikeng1.bitcoinpir.org — Hetzner i7-8700, Intel chip, NO SEV-SNP.
 * No MEASUREMENT to pin (no SEV report). binary_sha256 IS pinnable —
 * the value isn't hardware-backed without SEV, but pinning still
 * detects accidental drift between what the operator claims is
 * deployed and what's actually running.
 */
export const PIR1_PIN: ServerAttestPin = {
  // No measurementHex — Hetzner has no SEV.
  // Bumped 2026-05-18: pir1 was redeployed to the Phase-3b per-group
  // OnionPIR Merkle server (commit 121ea5c3). The binary below was
  // verified on Hetzner against BOTH the on-disk artifact
  // (`target/release/unified_server`) AND the live pir-primary /
  // pir-secondary process images (`/proc/<pid>/exe`) — all three
  // agree. pir2 is NOT on this binary yet (it still runs the pre-3b
  // `f63b3535…` build), so PIR1_PIN and PIR2_TIER3_PIN no longer
  // share a `binarySha256Hex`.
  binarySha256Hex:
    '0cc87a8c8530a7830e78ed172af2c5c666c62ccde5d00dbca36321c577dcdeba',
  description: 'weikeng1.bitcoinpir.org (Hetzner i7-8700, no SEV)',
};
