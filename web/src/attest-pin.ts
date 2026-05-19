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
 * weikeng2.bitcoinpir.org — VPSBG Tier 3 UKI v17, pinned 2026-05-19.
 * Built by the `packages.tier3-uki` flake derivation
 * (`nix build --impure .#tier3-uki`) on the Hetzner build host: VPSBG
 * kernel 7.0.0-15 + the reproducible `nix build .#unified-server`
 * binary, embedded via the full Nix closure.
 */
export const PIR2_TIER3_PIN: ServerAttestPin = {
  // Tier 3 UKI v17 — 2026-05-19. The flake-built UKI (PR #3) embeds the
  // reproducible Nix `unified_server` (`3925cc4d…`), so pir2 now runs
  // the BYTE-IDENTICAL binary to pir1 — PIR1_PIN and PIR2_TIER3_PIN
  // share `binarySha256Hex` again (the v16 `f63b3535…` drift is closed).
  // pir2 runs `--serve-queries` only (no hint pool) and does not serve
  // OnionPIR. MEASUREMENT captured from the v17 deploy via
  // `bpir-admin attest wss://weikeng2.bitcoinpir.org` (SEV-SNP report
  // Status: ReportDataMatch — attestation verified on real hardware).
  measurementHex:
    '6dcbfa45baa345ce5fabdddbc7386d43c31b3dbf1fd75402a112d303299c2428b2c0d0bf6a01325da87292ae69f2aa2a',
  binarySha256Hex:
    '3925cc4d5c4e45d8d3c8d798afb471905f909751d5c15ad5cccb22eb2631d2d5',
  description: 'weikeng2.bitcoinpir.org (VPSBG, SEV-SNP, Tier 3 UKI v17)',
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
  // Bumped 2026-05-19: pir1 redeployed to the HEXL-accelerated server
  // (commit 0845b060) — the reproducible Nix build `nix build
  // .#unified-server`, with Intel HEXL linked into OnionPIR's C++
  // engine. Verified on Hetzner against the on-disk artifact
  // (`target/release/unified_server`) and the live pir-primary process
  // image (`/proc/<pid>/exe`). As of the 2026-05-19 Tier-3 v17 deploy
  // (flake-built UKI, PR #3) pir2 runs this same binary, so PIR1_PIN
  // and PIR2_TIER3_PIN now share `binarySha256Hex`.
  binarySha256Hex:
    '3925cc4d5c4e45d8d3c8d798afb471905f909751d5c15ad5cccb22eb2631d2d5',
  description: 'weikeng1.bitcoinpir.org (Hetzner i7-8700, no SEV)',
};
