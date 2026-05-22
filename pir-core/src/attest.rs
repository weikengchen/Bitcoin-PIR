//! Attestation helpers shared by server and client.
//!
//! The pure-crypto pieces of the BPIR attestation flow live here so both
//! the server (which fetches the SEV-SNP report) and the client (which
//! verifies it) compute the same canonical REPORT_DATA preimage. Anything
//! platform-specific (the `/dev/sev-guest` ioctl, AMD VCEK chain
//! verification) lives in the consuming crates.
//!
//! ## REPORT_DATA layout (V2)
//!
//! SEV-SNP attestation reports include 64 bytes of attester-supplied
//! "user data". BPIR uses the first 32 bytes for a SHA-256 commitment,
//! leaving the trailing 32 bytes zero so the layout can be extended
//! later without re-keying the verifier:
//!
//! ```text
//! report_data[ 0..32] = sha256(BPIR-ATTEST-V2
//!                              || nonce                (32 B)
//!                              || combined_root        (32 B)  // sha256(root_0 || root_1 || ...)
//!                              || binary_sha256        (32 B)
//!                              || server_static_pub    (32 B)  // X25519 channel pubkey
//!                              || git_rev_utf8)
//! report_data[32..64] = 0x00 * 32
//! ```
//!
//! The domain tag `BPIR-ATTEST-V2` ensures collisions with V1 (or any
//! unrelated protocol that may want its own REPORT_DATA derivation)
//! cannot be confused for valid attestations.
//!
//! ## Why server_static_pub is in the preimage
//!
//! The V2 layout binds a long-lived X25519 public key — generated
//! inside the SEV-SNP guest at boot — into the chip-signed report.
//! That lets browser clients establish an encrypted+authenticated
//! channel directly to `unified_server` without trusting cloudflared
//! (which sits between the browser and the guest, terminating TLS at
//! the tunnel edge and seeing plaintext PIR traffic today).
//!
//! Concretely: client sends an ephemeral X25519 pubkey + nonce,
//! server's ECDH peer is its long-lived `server_static_pub` (so the
//! handshake derives a key that depends on the attested-once static
//! key + a fresh per-session ephemeral pair → forward secrecy + chip-
//! attested identity).
//!
//! ## V1 → V2 migration
//!
//! V1 (no pubkey, tag `BPIR-ATTEST-V1`) is gone. There is no
//! coexistence path: a V1 verifier checking a V2 report's
//! REPORT_DATA fails loudly (mismatch), which is the correct
//! behaviour — silently mis-validating an unbound pubkey would let
//! cloudflared substitute its own key.

use crate::merkle::{sha256, Hash256};

/// Length of an X25519 public key (RFC 7748 §6.1).
pub const X25519_PUBKEY_LEN: usize = 32;

/// Domain-separation tag prefixed to the REPORT_DATA preimage.
///
/// Bumped from `V1` to `V2` when `server_static_pub` was added to the
/// preimage — see module docs for the migration story.
pub const REPORT_DATA_DOMAIN_TAG: &[u8] = b"BPIR-ATTEST-V2";

/// Domain-separation tag for the *attest nonce* derivation that binds
/// the client's handshake ephemeral pubkey into the chip-signed
/// REPORT_DATA. Distinct from [`REPORT_DATA_DOMAIN_TAG`] so a verifier
/// cannot confuse a nonce preimage with a REPORT_DATA preimage.
pub const ATTEST_NONCE_DOMAIN_TAG: &[u8] = b"BPIR-ATTEST-NONCE-V1";

/// Derive the 32-byte attest nonce so the SEV-SNP report's REPORT_DATA
/// commits to *this specific* client handshake ephemeral pubkey:
///
/// ```text
/// attest_nonce = sha256(BPIR-ATTEST-NONCE-V1 || client_eph_pub || random_32)
/// ```
///
/// The bound nonce is what gets passed to [`build_report_data`] as the
/// `nonce` argument (and ultimately to the server's REQ_ATTEST). On the
/// verifier side, the client recomputes this value from the same
/// `client_eph_pub` (which it controls — it's the public half of the
/// X25519 ephemeral the client will use in REQ_HANDSHAKE) plus the
/// `random_32` it generated; if the chip-signed REPORT_DATA matches the
/// reconstructed preimage, the attestation provably covers this
/// handshake — not a stale or replayed one.
///
/// `random_32` MUST come from a CSPRNG. Production callers feed it
/// from `OsRng` / `getrandom`. Tests can pass a fixed value for
/// reproducibility.
pub fn derive_attest_nonce(
    client_eph_pub: [u8; X25519_PUBKEY_LEN],
    random_32: [u8; 32],
) -> [u8; 32] {
    let mut preimage =
        Vec::with_capacity(ATTEST_NONCE_DOMAIN_TAG.len() + X25519_PUBKEY_LEN + 32);
    preimage.extend_from_slice(ATTEST_NONCE_DOMAIN_TAG);
    preimage.extend_from_slice(&client_eph_pub);
    preimage.extend_from_slice(&random_32);
    sha256(&preimage)
}

/// Concatenate per-DB manifest roots and hash, producing the single
/// "combined manifest root" that goes into REPORT_DATA. Empty input
/// returns the all-zero hash so a server with no manifests still has
/// a deterministic value.
///
/// Order matters: this hashes `roots[0] || roots[1] || ...`. Callers
/// must agree on iteration order (BPIR uses db_id order).
pub fn combine_manifest_roots(roots: &[Hash256]) -> Hash256 {
    if roots.is_empty() {
        return [0u8; 32];
    }
    let mut concat = Vec::with_capacity(roots.len() * 32);
    for r in roots {
        concat.extend_from_slice(r);
    }
    sha256(&concat)
}

/// Build the 64-byte REPORT_DATA payload that gets passed into
/// `/dev/sev-guest`'s SNP_GET_REPORT ioctl.
///
/// See module docs for the exact V2 layout. The high 32 bytes are zero
/// today; clients verify the low 32 bytes match a fresh recomputation.
///
/// `server_static_pub` is the X25519 public half of the long-lived
/// channel key the server generates inside the SEV-SNP guest at boot.
/// Binding it here means a verifier with the chip-signed report can
/// trust that subsequent encrypted-channel handshakes terminate inside
/// the same attested guest (cloudflared can't substitute its own key).
/// Pass `[0u8; 32]` if the server has no channel key yet (transitional;
/// any production server should have one).
pub fn build_report_data(
    nonce: [u8; 32],
    manifest_roots: &[Hash256],
    binary_sha256: Hash256,
    server_static_pub: [u8; X25519_PUBKEY_LEN],
    git_rev: &str,
) -> [u8; 64] {
    let combined_root = combine_manifest_roots(manifest_roots);

    let mut preimage = Vec::with_capacity(
        REPORT_DATA_DOMAIN_TAG.len() + 32 + 32 + 32 + 32 + git_rev.len(),
    );
    preimage.extend_from_slice(REPORT_DATA_DOMAIN_TAG);
    preimage.extend_from_slice(&nonce);
    preimage.extend_from_slice(&combined_root);
    preimage.extend_from_slice(&binary_sha256);
    preimage.extend_from_slice(&server_static_pub);
    preimage.extend_from_slice(git_rev.as_bytes());

    let h = sha256(&preimage);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h);
    out
}

/// Offset of the REPORT_DATA field inside an SEV-SNP attestation
/// report (version 2 / version 5; the field's position is stable
/// across both). Use this to extract the 64-byte field from a raw
/// report blob for verification.
pub const SEV_SNP_REPORT_DATA_OFFSET: usize = 0x50;

/// Length of REPORT_DATA in the SEV-SNP report.
pub const SEV_SNP_REPORT_DATA_LEN: usize = 64;

/// Extract the REPORT_DATA field from a raw SEV-SNP report.
/// Returns `None` if the report is too short to contain the field.
pub fn extract_report_data(report: &[u8]) -> Option<&[u8]> {
    let end = SEV_SNP_REPORT_DATA_OFFSET + SEV_SNP_REPORT_DATA_LEN;
    if report.len() < end {
        return None;
    }
    Some(&report[SEV_SNP_REPORT_DATA_OFFSET..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_manifest_roots_empty_is_zero() {
        assert_eq!(combine_manifest_roots(&[]), [0u8; 32]);
    }

    #[test]
    fn combine_manifest_roots_single_is_sha256_of_root() {
        let root = [7u8; 32];
        assert_eq!(combine_manifest_roots(&[root]), sha256(&root));
    }

    #[test]
    fn combine_manifest_roots_order_matters() {
        let a = combine_manifest_roots(&[[1u8; 32], [2u8; 32]]);
        let b = combine_manifest_roots(&[[2u8; 32], [1u8; 32]]);
        assert_ne!(a, b);
    }

    #[test]
    fn build_report_data_changes_with_nonce() {
        let h1 = build_report_data([1u8; 32], &[], [2u8; 32], [0u8; 32], "abc");
        let h2 = build_report_data([3u8; 32], &[], [2u8; 32], [0u8; 32], "abc");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_report_data_changes_with_manifest_roots() {
        let h1 = build_report_data([1u8; 32], &[[7u8; 32]], [2u8; 32], [0u8; 32], "abc");
        let h2 = build_report_data([1u8; 32], &[[8u8; 32]], [2u8; 32], [0u8; 32], "abc");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_report_data_changes_with_binary_hash() {
        let h1 = build_report_data([1u8; 32], &[], [2u8; 32], [0u8; 32], "abc");
        let h2 = build_report_data([1u8; 32], &[], [3u8; 32], [0u8; 32], "abc");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_report_data_changes_with_server_static_pub() {
        // The whole point of V2 — substituting a different pubkey
        // (e.g. cloudflared inserting its own key) must produce a
        // different REPORT_DATA so the verifier rejects the binding.
        let h1 = build_report_data([1u8; 32], &[], [2u8; 32], [0xAAu8; 32], "abc");
        let h2 = build_report_data([1u8; 32], &[], [2u8; 32], [0xBBu8; 32], "abc");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_report_data_changes_with_git_rev() {
        let h1 = build_report_data([1u8; 32], &[], [2u8; 32], [0u8; 32], "abc");
        let h2 = build_report_data([1u8; 32], &[], [2u8; 32], [0u8; 32], "xyz");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_report_data_high_32_bytes_zero() {
        let h = build_report_data([1u8; 32], &[], [2u8; 32], [0u8; 32], "abc");
        assert_eq!(&h[32..], &[0u8; 32]);
    }

    #[test]
    fn build_report_data_low_32_bytes_match_manual_sha256() {
        // Recompute the preimage by hand and check it matches the V2
        // layout exactly (catches accidental field-order regressions).
        let nonce = [0xAAu8; 32];
        let root = [0xBBu8; 32];
        let binary = [0xCCu8; 32];
        let server_pub = [0xDDu8; 32];
        let git = "deadbeef";
        let combined = combine_manifest_roots(&[root]);

        let mut p = Vec::new();
        p.extend_from_slice(b"BPIR-ATTEST-V2");
        p.extend_from_slice(&nonce);
        p.extend_from_slice(&combined);
        p.extend_from_slice(&binary);
        p.extend_from_slice(&server_pub);
        p.extend_from_slice(git.as_bytes());
        let manual = sha256(&p);

        let out = build_report_data(nonce, &[root], binary, server_pub, git);
        assert_eq!(&out[..32], &manual);
    }

    #[test]
    fn derive_attest_nonce_changes_with_client_eph_pub() {
        let n1 = derive_attest_nonce([0xAAu8; 32], [0x11u8; 32]);
        let n2 = derive_attest_nonce([0xBBu8; 32], [0x11u8; 32]);
        assert_ne!(n1, n2);
    }

    #[test]
    fn derive_attest_nonce_changes_with_random_32() {
        let n1 = derive_attest_nonce([0xAAu8; 32], [0x11u8; 32]);
        let n2 = derive_attest_nonce([0xAAu8; 32], [0x22u8; 32]);
        assert_ne!(n1, n2);
    }

    #[test]
    fn derive_attest_nonce_is_deterministic() {
        let eph = [0xCCu8; 32];
        let rnd = [0xDDu8; 32];
        assert_eq!(
            derive_attest_nonce(eph, rnd),
            derive_attest_nonce(eph, rnd)
        );
    }

    #[test]
    fn derive_attest_nonce_domain_tag_distinct_from_report_data_tag() {
        // A nonce preimage and a REPORT_DATA preimage with the same
        // trailing bytes must not collide — distinct domain tags
        // prevent cross-protocol confusion.
        assert_ne!(ATTEST_NONCE_DOMAIN_TAG, REPORT_DATA_DOMAIN_TAG);
    }

    #[test]
    fn derive_attest_nonce_matches_manual_sha256() {
        // Catch accidental field-order or domain-tag regressions.
        let eph = [0x12u8; 32];
        let rnd = [0x34u8; 32];
        let mut p = Vec::new();
        p.extend_from_slice(b"BPIR-ATTEST-NONCE-V1");
        p.extend_from_slice(&eph);
        p.extend_from_slice(&rnd);
        let manual = sha256(&p);
        assert_eq!(derive_attest_nonce(eph, rnd), manual);
    }

    #[test]
    fn extract_report_data_short_returns_none() {
        assert!(extract_report_data(&[0u8; 100]).is_none());
    }

    #[test]
    fn extract_report_data_full_report_returns_64b_at_offset() {
        let mut report = vec![0u8; 1184];
        for (i, b) in report
            .iter_mut()
            .enumerate()
            .skip(SEV_SNP_REPORT_DATA_OFFSET)
            .take(64)
        {
            *b = ((i - SEV_SNP_REPORT_DATA_OFFSET) as u8).wrapping_add(1);
        }
        let extracted = extract_report_data(&report).unwrap();
        assert_eq!(extracted.len(), 64);
        assert_eq!(extracted[0], 1);
        assert_eq!(extracted[63], 64);
    }
}
