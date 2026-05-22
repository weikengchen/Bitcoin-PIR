//! Server-side identity-key + operator-cert loader, plus the per-boot
//! [`ChannelManifest`] builder that REQ_ANNOUNCE serves.
//!
//! ## Two-tier signing recap
//!
//! - **Operator key** (Tier 1) lives OFFLINE on the operator's
//!   workstation. It signs an [`IdentityCert`] for each server once per
//!   identity rotation. The operator publishes the operator pubkey
//!   out-of-band (eventually via Nostr).
//! - **Identity key** (Tier 2) is held on the server's filesystem
//!   (`--identity-key-path`). At boot, the server signs a per-boot
//!   [`ChannelManifest`] that commits the current `channel_pub` plus
//!   build metadata.
//!
//! Either file missing at startup is non-fatal: the server simply runs
//! in "unannounced" mode — REQ_ANNOUNCE returns a RESP_ERROR. The
//! existing attest / handshake / query paths are unaffected. This
//! matches the project's [HUMAN-decided] boot policy: "Serve without
//! announce, log warning."
//!
//! ## Filesystem layout (operator policy, not protocol)
//!
//! The server takes paths for the key + cert via CLI flags or env vars;
//! contents are byte-blobs only (no JSON / TOML wrapping). The
//! identity-key file holds the raw 32-byte Ed25519 seed; the cert file
//! holds the bytes of [`IdentityCert::encode`]. Both files SHOULD be
//! mode `0600` and owned by the unified_server user.
//!
//! ## Threat model
//!
//! - **Cloudflared / passive middlebox**: can't forge the bundle
//!   (operator key is offline). Can drop/delay/replay — for replay,
//!   the per-boot ChannelManifest's `issued_at` lets clients apply a
//!   freshness policy.
//! - **Compromise of the on-disk identity key**: attacker can sign
//!   forged ChannelManifests with that server's identity_pubkey, but
//!   they can't move to a different `server_id` or substitute the
//!   `identity_pubkey` (those are bound in the IdentityCert signed by
//!   the offline operator key). Mitigation: operator re-signs an
//!   IdentityCert with a new identity_pubkey (rotation).
//! - **Compromise of the offline operator key**: attacker can mint
//!   IdentityCerts for any server_id, including ones the operator
//!   never set up. Mitigation: operator publishes a new operator
//!   pubkey via the out-of-band channel; clients pin the new one.

use ed25519_dalek::SigningKey;
use pir_core::merkle::Hash256;
use pir_identity::{
    sign_channel_manifest, AnnouncementBundle, ChannelManifest, IdentityCert, IdentityError,
};
use std::fs;
use std::io;
use std::path::Path;

/// Errors loading identity material at server startup.
#[derive(Debug)]
pub enum IdentityLoadError {
    /// File read failed (missing, no permission, etc.).
    Io { path: String, source: io::Error },
    /// Identity-key file's byte length is wrong (must be 32 bytes).
    KeyLength { path: String, got: usize },
    /// Cert file failed to parse as an [`IdentityCert`].
    CertParse { path: String, source: IdentityError },
    /// Cert's `identity_pubkey` doesn't match the loaded identity key's
    /// public half. Almost certainly a deploy-time mismatch (operator
    /// signed against a different identity key than the one on disk).
    PubkeyMismatch {
        expected_from_key_file: [u8; 32],
        cert_says: [u8; 32],
    },
    /// Cert's signature failed verification (operator's own key
    /// disagrees with the signature). Indicates a corrupt cert file
    /// or a deploy mishap.
    CertSignatureInvalid(IdentityError),
}

impl std::fmt::Display for IdentityLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read {}: {}", path, source)
            }
            Self::KeyLength { path, got } => write!(
                f,
                "identity-key file {} is {} bytes (must be 32)",
                path, got
            ),
            Self::CertParse { path, source } => {
                write!(f, "failed to parse {}: {}", path, source)
            }
            Self::PubkeyMismatch {
                expected_from_key_file,
                cert_says,
            } => write!(
                f,
                "cert.identity_pubkey ({}) ≠ pubkey derived from key file ({})",
                hex_8(cert_says),
                hex_8(expected_from_key_file)
            ),
            Self::CertSignatureInvalid(e) => {
                write!(f, "cert signature does not verify: {}", e)
            }
        }
    }
}

impl std::error::Error for IdentityLoadError {}

fn hex_8(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(18);
    for b in &bytes[..8] {
        s.push_str(&format!("{:02x}", b));
    }
    s.push('…');
    s
}

/// In-memory bundle the unified_server holds for the duration of its
/// boot. Built once at startup from the on-disk key + cert plus the
/// boot-fresh `channel_pub`, and served verbatim on REQ_ANNOUNCE.
#[derive(Debug)]
pub struct ServerIdentity {
    /// Pre-encoded `AnnouncementBundle::encode()` bytes. Cached so
    /// REQ_ANNOUNCE is a zero-cost copy.
    pub encoded_bundle: Vec<u8>,
    /// Decoded cert — used internally for diagnostics / logging.
    pub cert: IdentityCert,
    /// Decoded manifest — same. Includes the issued_at timestamp.
    pub manifest: ChannelManifest,
}

/// Load the identity Ed25519 keypair from disk. Returns the parsed
/// [`SigningKey`]. The file must hold exactly 32 raw seed bytes (this
/// matches `bpir-admin generate-identity --raw` output).
pub fn load_identity_key(path: &Path) -> Result<SigningKey, IdentityLoadError> {
    let bytes = fs::read(path).map_err(|e| IdentityLoadError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    if bytes.len() != 32 {
        return Err(IdentityLoadError::KeyLength {
            path: path.display().to_string(),
            got: bytes.len(),
        });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

/// Load the operator-signed [`IdentityCert`] from disk. Verifies the
/// signature against `cert.operator_pubkey`. Does NOT compare
/// `cert.operator_pubkey` against any pinned operator pubkey — that's
/// a client-side check (the server has no policy on which operator
/// signed it; it just serves what the operator deployed).
pub fn load_identity_cert(path: &Path) -> Result<IdentityCert, IdentityLoadError> {
    let bytes = fs::read(path).map_err(|e| IdentityLoadError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let cert = IdentityCert::decode(&bytes).map_err(|e| IdentityLoadError::CertParse {
        path: path.display().to_string(),
        source: e,
    })?;
    cert.verify()
        .map_err(IdentityLoadError::CertSignatureInvalid)?;
    Ok(cert)
}

/// Build the per-boot announcement bundle.
///
/// Cross-checks that `identity_key`'s public half matches
/// `cert.identity_pubkey` — a mismatch means the deploy is broken
/// (operator signed against a key the server doesn't hold) and we
/// MUST refuse to ship the bundle rather than silently produce one
/// the client will reject. Per the project's boot policy, the caller
/// (unified_server startup) downgrades this error to "log warning,
/// serve without announce".
///
/// `binary_sha256` and `git_rev` are the same values that go into
/// REPORT_DATA; passing them in (rather than recomputing) keeps the
/// announcement bundle in sync with the chip-signed attestation on
/// SEV hosts.
///
/// `issued_at` is unix-seconds. Production callers pass
/// `SystemTime::now()`'s unix epoch; tests can pin it for
/// reproducibility.
#[allow(clippy::too_many_arguments)]
pub fn build_announcement_bundle(
    identity_key: &SigningKey,
    cert: IdentityCert,
    server_id: &str,
    channel_pub: [u8; 32],
    binary_sha256: Hash256,
    git_rev: &str,
    manifest_roots: Vec<Hash256>,
    issued_at: i64,
) -> Result<ServerIdentity, IdentityLoadError> {
    let identity_pubkey = identity_key.verifying_key().to_bytes();
    if identity_pubkey != cert.identity_pubkey {
        return Err(IdentityLoadError::PubkeyMismatch {
            expected_from_key_file: identity_pubkey,
            cert_says: cert.identity_pubkey,
        });
    }
    // server_id consistency: the manifest commits to the same server_id
    // that the cert was issued for. If the operator changes the cert's
    // server_id but the unified_server is started with a different
    // identity, the bundle would be incoherent — fail loudly.
    if cert.server_id != server_id {
        return Err(IdentityLoadError::PubkeyMismatch {
            // Re-use the variant — we don't have a dedicated one and the
            // payload still tells the operator what went wrong. Encode
            // the server_id mismatch as two distinct "pubkeys" so the
            // Display impl is still useful.
            expected_from_key_file: blake_from_str(server_id),
            cert_says: blake_from_str(&cert.server_id),
        });
    }
    let manifest = sign_channel_manifest(
        identity_key,
        server_id,
        channel_pub,
        binary_sha256,
        git_rev,
        manifest_roots,
        issued_at,
    );
    let bundle = AnnouncementBundle {
        cert: cert.clone(),
        manifest: manifest.clone(),
    };
    let encoded_bundle = bundle.encode();
    Ok(ServerIdentity {
        encoded_bundle,
        cert,
        manifest,
    })
}

/// Cheap derive-a-hash-from-a-string for the server_id mismatch
/// Display message. Not cryptographic — diagnostic only.
fn blake_from_str(s: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_identity::sign_identity_cert;
    use tempfile::tempdir;

    fn fake_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn load_identity_key_round_trips_raw_32_byte_seed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let original = fake_sk(0x77);
        fs::write(&path, original.to_bytes()).unwrap();
        let loaded = load_identity_key(&path).unwrap();
        assert_eq!(loaded.to_bytes(), original.to_bytes());
        // And the pubkey matches — sanity for the deploy invariant.
        assert_eq!(
            loaded.verifying_key().to_bytes(),
            original.verifying_key().to_bytes()
        );
    }

    #[test]
    fn load_identity_key_wrong_length_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.key");
        fs::write(&path, b"too short").unwrap();
        let err = load_identity_key(&path).unwrap_err();
        assert!(matches!(err, IdentityLoadError::KeyLength { got: 9, .. }));
    }

    #[test]
    fn load_identity_key_missing_file_returns_io_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("absent.key");
        let err = load_identity_key(&path).unwrap_err();
        assert!(matches!(err, IdentityLoadError::Io { .. }));
    }

    #[test]
    fn load_identity_cert_verifies_signature() {
        let dir = tempdir().unwrap();
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        let path = dir.path().join("identity.cert");
        fs::write(&path, cert.encode()).unwrap();
        let loaded = load_identity_cert(&path).unwrap();
        assert_eq!(loaded.operator_pubkey, op_sk.verifying_key().to_bytes());
        assert_eq!(loaded.server_id, "pir1");
    }

    #[test]
    fn load_identity_cert_rejects_tampered_blob() {
        let dir = tempdir().unwrap();
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        let path = dir.path().join("identity.cert");
        let mut bytes = cert.encode();
        // Flip a byte in the server_id field — preimage diverges.
        let server_id_start = 2 + 32 + 2; // version + type + operator_pub + len
        bytes[server_id_start] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        let err = load_identity_cert(&path).unwrap_err();
        assert!(matches!(err, IdentityLoadError::CertSignatureInvalid(_)));
    }

    #[test]
    fn build_bundle_with_matching_key_and_cert_succeeds() {
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        let identity = build_announcement_bundle(
            &id_sk,
            cert,
            "pir1",
            [0xCCu8; 32],
            [0xAAu8; 32],
            "abc",
            vec![],
            1_700_000_000,
        )
        .unwrap();
        // Encoded bundle round-trips and verifies end-to-end.
        let parsed =
            pir_identity::AnnouncementBundle::decode(&identity.encoded_bundle).unwrap();
        parsed.cert.verify().unwrap();
        parsed.verify_chain().unwrap();
        assert_eq!(parsed.cert.server_id, "pir1");
        assert_eq!(parsed.manifest.channel_pub, [0xCCu8; 32]);
        assert_eq!(parsed.manifest.binary_sha256, [0xAAu8; 32]);
        assert_eq!(parsed.manifest.issued_at, 1_700_000_000);
    }

    #[test]
    fn build_bundle_rejects_mismatched_identity_key() {
        let op_sk = fake_sk(0x11);
        let id_sk_on_disk = fake_sk(0x22);
        let id_sk_in_cert = fake_sk(0x33); // different!
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk_in_cert.verifying_key().to_bytes(),
            0,
            0,
        );
        let err = build_announcement_bundle(
            &id_sk_on_disk,
            cert,
            "pir1",
            [0u8; 32],
            [0u8; 32],
            "v",
            vec![],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, IdentityLoadError::PubkeyMismatch { .. }));
    }

    #[test]
    fn build_bundle_rejects_server_id_mismatch() {
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        // Server is started with server_id = "pir2" but cert says "pir1".
        let err = build_announcement_bundle(
            &id_sk,
            cert,
            "pir2",
            [0u8; 32],
            [0u8; 32],
            "v",
            vec![],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, IdentityLoadError::PubkeyMismatch { .. }));
    }
}
