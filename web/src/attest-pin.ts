import { requireSdkWasm } from './sdk-bridge.js';

/**
 * Operator-pinned 32-byte SHA-256 fingerprint of the AMD ARK (Root
 * Key) certificate, as a human-readable hex string.
 *
 * This constant is **documentation** — the live runtime value used by
 * the verifier comes from the WASM module (`turinArkFingerprint()`,
 * exported from `pir-attest-verify::TURIN_ARK_FINGERPRINT_SHA256`).
 * Keeping the hex here gives operators a searchable, auditable copy
 * of the pinned value AND a build-time cross-check (see
 * [`getAmdTurinArkFingerprint`] below) that catches drift if anyone
 * ever rotates one without the other.
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
 *   3. Replace the hex below AND the Rust constant
 *      `pir-attest-verify::TURIN_ARK_FINGERPRINT_SHA256`, then rebuild
 *      the WASM bundle.
 *
 * Same fingerprint applies to all Turin-family chips. (Genoa, Milan,
 * etc. would have different ARKs and need their own pins; we only
 * deploy on Turin so far.)
 */
export const AMD_TURIN_ARK_FINGERPRINT_HEX =
  '1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a';

/** Decode the hex constant once at module load. Used as the
 *  authoritative *human-readable* source — the runtime value comes
 *  from WASM and is checked against this at [`getAmdTurinArkFingerprint`]
 *  call time. */
const HEX_AS_BYTES: Uint8Array = (() => {
  const hex = AMD_TURIN_ARK_FINGERPRINT_HEX;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
})();

/**
 * Return the 32-byte ARK fingerprint sourced from the WASM module
 * (which mirrors the Rust constant
 * `pir-attest-verify::TURIN_ARK_FINGERPRINT_SHA256`).
 *
 * Throws if [`initSdkWasm`] hasn't resolved yet — the WASM module is
 * the single source of truth, so this function intentionally has no
 * pure-TS fallback. Callers that need the value before WASM init can
 * use [`AMD_TURIN_ARK_FINGERPRINT_HEX`] for display purposes only
 * (never as the value passed to `verifyVcekChain` / `verifyFull` —
 * that would defeat the cross-check).
 *
 * On first call after WASM init, cross-checks the WASM-exported bytes
 * against the hex constant and throws on mismatch (build-time drift
 * between Rust + TS). Subsequent calls return the cached Uint8Array.
 */
let cachedArkFingerprint: Uint8Array | null = null;
export function getAmdTurinArkFingerprint(): Uint8Array {
  if (cachedArkFingerprint) return cachedArkFingerprint;
  const sdk = requireSdkWasm();
  const fromWasm = sdk.turinArkFingerprint();
  if (fromWasm.length !== 32) {
    throw new Error(
      `attest-pin: WASM turinArkFingerprint returned ${fromWasm.length} bytes (expected 32)`,
    );
  }
  for (let i = 0; i < 32; i++) {
    if (fromWasm[i] !== HEX_AS_BYTES[i]) {
      throw new Error(
        `attest-pin: ARK fingerprint mismatch between WASM (${bytesToHex(fromWasm)}) ` +
          `and AMD_TURIN_ARK_FINGERPRINT_HEX (${AMD_TURIN_ARK_FINGERPRINT_HEX}). ` +
          `One was rotated without the other — fix and rebuild.`,
      );
    }
  }
  cachedArkFingerprint = fromWasm;
  return fromWasm;
}

/**
 * @deprecated Use [`getAmdTurinArkFingerprint`] instead. This eager
 * Uint8Array is kept for back-compat with pre-Slice-D.4 callers; new
 * code should source from WASM so the cross-check fires. Will be
 * removed once `dpf-adapter.ts` / `harmonypir-adapter.ts` migrate.
 */
export const AMD_TURIN_ARK_FINGERPRINT: Uint8Array = HEX_AS_BYTES;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

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
 * weikeng2.bitcoinpir.org — VPSBG Tier 3 UKI v18, pinned 2026-05-20.
 * Built by the `packages.tier3-uki` flake derivation
 * (`nix build --impure .#tier3-uki`) on the Hetzner build host: VPSBG
 * kernel 7.0.0-15 + the reproducible `nix build .#unified-server`
 * binary, embedded via the full Nix closure.
 */
export const PIR2_TIER3_PIN: ServerAttestPin = {
  // Tier 3 UKI v18 — 2026-05-20. Rebaked from main @ 90bcaef4 to ship
  // PRs #5/#6/#7 (web vendor cleanup, harmony_decode_counts wasm
  // binding, Harmony hint coalescing). The flake-built UKI embeds the
  // reproducible Nix `unified_server` (`2ba6e79c…`), and pir1 was
  // installed with the SAME Nix-built binary so PIR1_PIN and
  // PIR2_TIER3_PIN share `binarySha256Hex` again.
  // pir2 runs `--serve-queries` only (no hint pool) and does not serve
  // OnionPIR. MEASUREMENT captured from the v18 deploy via
  // `bpir-admin attest wss://weikeng2.bitcoinpir.org` (SEV-SNP report
  // Status: ReportDataMatch — attestation verified on real hardware).
  measurementHex:
    '53eb00331081ed7ee27df20a40c7d8d9be4c0a6a93cf043e876508a0f1fc74658987c03cceced379b5bf23e715a9435b',
  binarySha256Hex:
    '2ba6e79c388f54867988885785512f42864d5ceb3b88d1e1d5b8d24459d2f46c',
  description: 'weikeng2.bitcoinpir.org (VPSBG, SEV-SNP, Tier 3 UKI v18)',
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
  // Bumped 2026-05-20: pir1 redeployed from main @ 90bcaef4 to ship
  // PRs #5/#6/#7 (web vendor cleanup, harmony_decode_counts wasm
  // binding, Harmony hint coalescing). Binary is the reproducible
  // `nix build .#unified-server` output (same Nix-built binary
  // embedded in the v18 Tier-3 UKI for pir2, so once pir2 boots
  // v18, PIR1_PIN and PIR2_TIER3_PIN share `binarySha256Hex`
  // again — the shared-binary invariant from v17 is preserved).
  binarySha256Hex:
    '2ba6e79c388f54867988885785512f42864d5ceb3b88d1e1d5b8d24459d2f46c',
  description: 'weikeng1.bitcoinpir.org (Hetzner i7-8700, no SEV)',
};
