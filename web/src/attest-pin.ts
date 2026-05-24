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
 * weikeng2.bitcoinpir.org — VPSBG Tier 3 UKI v20, pinned 2026-05-24.
 * Built by the `packages.tier3-uki` flake derivation
 * (`nix build --impure .#tier3-uki`) on the Hetzner build host: VPSBG
 * kernel 7.0.0-15 + the reproducible `nix build .#unified-server`
 * binary, embedded via the full Nix closure.
 */
export const PIR2_TIER3_PIN: ServerAttestPin = {
  // Tier 3 UKI v20 — 2026-05-24. Rebaked from main @ ea4ee8c8: the v19
  // chain-anchored deploy (`b07a00d2…`) had an OnionPIR query-path SEGV
  // (onion_chunk_cuckoo read its tables at a hardcoded offset 36, which on
  // a v2 file is the chain-anchor bytes → out-of-range entry-ids → NTT
  // OOB). ea4ee8c8 fixes the reader (offset = 36 + anchor_len) and
  // rebuilds the reproducible Nix `unified_server` (`71a041ae…`). pir1
  // runs the SAME Nix binary so PIR1_PIN and PIR2_TIER3_PIN share
  // `binarySha256Hex`. pir2 runs `--serve-queries` only (no hint pool)
  // and does not serve OnionPIR. MEASUREMENT captured from the v20 deploy via
  // `bpir-admin attest wss://weikeng2.bitcoinpir.org` (SEV-SNP report
  // Status: ReportDataMatch — attestation verified on real hardware).
  measurementHex:
    '1573de58b181b06d913ac536be8fd36da4bb8c79e0a6c2ccde5564198e87190d3b8fd5bc741ba208158e83cda33cfa4b',
  binarySha256Hex:
    '71a041ae1931b81563f460c6e028c96706ea1c2f66545ee700479c0e5c5a93b6',
  description: 'weikeng2.bitcoinpir.org (VPSBG, SEV-SNP, Tier 3 UKI v20)',
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
  // Bumped 2026-05-24 (v20): pir1 redeployed from main @ ea4ee8c8 (the
  // OnionPIR onion_chunk_cuckoo v2-anchor offset SEGV fix). Binary is the
  // reproducible `nix build .#unified-server` output (`71a041ae…`) — the
  // same Nix binary embedded in the v20 Tier-3 UKI for pir2, so PIR1_PIN
  // and PIR2_TIER3_PIN share `binarySha256Hex` (shared-binary invariant
  // preserved).
  binarySha256Hex:
    '71a041ae1931b81563f460c6e028c96706ea1c2f66545ee700479c0e5c5a93b6',
  description: 'weikeng1.bitcoinpir.org (Hetzner i7-8700, no SEV)',
};

/**
 * Operator identity pin (Tier-1) for the REQ_ANNOUNCE operator-signed
 * identity flow.
 *
 * The operator's long-term Ed25519 key (generated OFFLINE via
 * `bpir-admin generate-identity --purpose operator`, secret never on a
 * server) signs each server's `IdentityCert`. A client pins the
 * operator's *public* key here and rejects any announce bundle whose
 * cert isn't signed by it. One operator key signs the whole fleet; the
 * per-server `IdentityCert.server_id` (pir1 / pir2) distinguishes them,
 * so this single pin covers both.
 *
 * Pass the decoded bytes to `WasmAnnounceVerification.checkPinnedOperator`
 * (operator pubkey match + cert signature + validity + chain check) —
 * NOT a bare `operatorPubkeyHex` string-compare, which would miss the
 * cert's operator signature.
 *
 * ⚠️ DEV STAND-IN — NOT FOR PRODUCTION. The value below is the
 * throwaway keypair used by the announce end-to-end test
 * (`test_announce_operator_identity_end_to_end`), pinned so the path is
 * exercisable in dev. Before any deployment relies on operator identity:
 *   1. generate the real operator key offline,
 *   2. publish its pubkey out-of-band (build-time pin here is the MVP;
 *      DNSSEC/Nostr can layer on later), and
 *   3. replace the hex below + record provenance like the pins above.
 * Until then, callers should treat a passing operator-pin check as
 * dev-only and gate any "verified operator" UI on a real pin landing.
 *
 * Full operator runbook + client trust model: docs/OPERATOR_IDENTITY.md.
 */
export const PIR_OPERATOR_PUBKEY_HEX =
  '47d98cb6483b2b027e4b08e516e26ce414ebb719421a591f66272f9c97bad562';

/** Decoded 32-byte operator pubkey for
 *  `WasmAnnounceVerification.checkPinnedOperator`. See the loud
 *  DEV-STAND-IN warning on [`PIR_OPERATOR_PUBKEY_HEX`]. */
export const PIR_OPERATOR_PUBKEY: Uint8Array = (() => {
  const hex = PIR_OPERATOR_PUBKEY_HEX;
  if (hex.length !== 64) {
    throw new Error(
      `attest-pin: PIR_OPERATOR_PUBKEY_HEX must be 64 hex chars, got ${hex.length}`,
    );
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
})();
