//! Server-side ARC (Anonymous Rate-limited Credentials) presentation verification.
//!
//! Holds the long-lived issuer keypair, verifies ARC presentations, and tracks
//! seen tags in a per-`presentation_context` double-spend set to enforce the
//! per-credential rate limit.

use arc::group::{deserialize_scalar, serialize_element, serialize_scalar};
use arc::{
    verify_presentation, Presentation, ServerPrivateKey, ServerPublicKey,
};
use std::collections::HashMap;

/// Serialized size of an ARC private key: 4 × 32-byte scalars
/// (`x0 || x1 || x2 || x0_blinding`). Must match the layout the issuer
/// (`dev-issuer` / payment service `ArcIssuer`) writes to `arc_key.bin`.
pub const ARC_PRIVKEY_SIZE: usize = 128;

/// The fixed `request_context` that the payment service and the PIR server agree
/// on. The client receives this value from the payment service alongside the
/// issued credential and MUST pass it verbatim in every `REQ_CREDENTIAL_PRESENT`.
pub const DEFAULT_REQUEST_CONTEXT: &[u8] = b"bitcoin-pir-v1";

/// Errors that can occur during ARC presentation verification.
#[derive(Debug, Clone)]
pub enum ArcVerifyError {
    /// The presentation failed cryptographic verification (bad proof, wrong
    /// context, expired credential, etc.).
    InvalidProof(String),
    /// The presentation's tag was already seen in this presentation context
    /// — the client is trying to reuse a nonce.
    DuplicateTag,
    /// The wire format is malformed (wrong length, invalid encoding).
    Malformed(String),
}

impl std::fmt::Display for ArcVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProof(msg) => write!(f, "ARC proof invalid: {}", msg),
            Self::DuplicateTag => write!(f, "duplicate ARC tag — nonce reused"),
            Self::Malformed(msg) => write!(f, "malformed ARC presentation: {}", msg),
        }
    }
}

/// Holds state for verifying ARC credential presentations.
///
/// The verifier owns the server's long-lived MAC keypair and a per-context
/// set of seen tags. Tags are pruned when the context is removed (typically
/// on connection close).
pub struct ArcVerifier {
    /// Long-lived server keypair loaded at startup.
    pub secret_key: ServerPrivateKey,
    pub public_key: ServerPublicKey,

    /// Per-`presentation_context` set of seen tags (serialized as 33-byte
    /// compressed SEC1 elements). When a connection closes, the caller
    /// should call `remove_context` to free the set.
    seen_tags: HashMap<Vec<u8>, Vec<Vec<u8>>>,
}

impl ArcVerifier {
    /// Load a verifier from a serialized 128-byte ARC private key
    /// (`x0 || x1 || x2 || x0_blinding`, each a 32-byte big-endian scalar).
    /// The public key is *derived* from the private key, so issuer and
    /// verifier sharing the same `arc_key.bin` are guaranteed to agree.
    ///
    /// This is the layout written by the `dev-issuer` and the payment
    /// service's `ArcIssuer::load_or_generate`.
    pub fn from_secret_key_bytes(secret_key_bytes: &[u8]) -> Result<Self, String> {
        if secret_key_bytes.len() != ARC_PRIVKEY_SIZE {
            return Err(format!(
                "ARC private key must be {ARC_PRIVKEY_SIZE} bytes, got {}",
                secret_key_bytes.len()
            ));
        }
        let x0 = deserialize_scalar(&secret_key_bytes[0..32])
            .map_err(|e| format!("bad x0 scalar: {e}"))?;
        let x1 = deserialize_scalar(&secret_key_bytes[32..64])
            .map_err(|e| format!("bad x1 scalar: {e}"))?;
        let x2 = deserialize_scalar(&secret_key_bytes[64..96])
            .map_err(|e| format!("bad x2 scalar: {e}"))?;
        let x0_blinding = deserialize_scalar(&secret_key_bytes[96..128])
            .map_err(|e| format!("bad x0_blinding scalar: {e}"))?;
        let sk = ServerPrivateKey { x0, x1, x2, x0_blinding };
        let pk = sk.public_key();
        Ok(Self {
            secret_key: sk,
            public_key: pk,
            seen_tags: HashMap::new(),
        })
    }

    /// Load a verifier from an `arc_key.bin` file written by the issuer.
    pub fn from_secret_key_file(path: &std::path::Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("failed to read ARC key file {}: {e}", path.display()))?;
        Self::from_secret_key_bytes(&bytes)
    }

    /// Generate a fresh keypair. Used for testing or first-run setup.
    ///
    /// NOTE: a verifier created this way holds a random key, so credentials
    /// issued by any *other* party will not verify. Production / demo
    /// deployments must instead load a shared key via
    /// [`Self::from_secret_key_file`].
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        let (sk, pk) = arc::setup_server(&mut rng);
        Self {
            secret_key: sk,
            public_key: pk,
            seen_tags: HashMap::new(),
        }
    }

    /// Serialize the private key to the canonical 128-byte
    /// `x0 || x1 || x2 || x0_blinding` layout (so the issuer can persist a
    /// freshly generated key and the verifier can reload it).
    pub fn secret_key_bytes(&self) -> [u8; ARC_PRIVKEY_SIZE] {
        let mut out = [0u8; ARC_PRIVKEY_SIZE];
        out[0..32].copy_from_slice(&serialize_scalar(&self.secret_key.x0));
        out[32..64].copy_from_slice(&serialize_scalar(&self.secret_key.x1));
        out[64..96].copy_from_slice(&serialize_scalar(&self.secret_key.x2));
        out[96..128].copy_from_slice(&serialize_scalar(&self.secret_key.x0_blinding));
        out
    }

    /// Serialize the public key for distribution to clients / payment service.
    pub fn public_key_bytes(&self) -> [u8; 99] {
        self.public_key.to_bytes()
    }

    /// Verify an ARC presentation.
    ///
    /// Returns `Ok(())` if the presentation is cryptographically valid and
    /// has not been seen before in this `presentation_context`. Returns
    /// `Err(ArcVerifyError)` otherwise.
    ///
    /// The caller must call `remove_context` when the session ends to free
    /// the accumulated tag set.
    pub fn verify(
        &mut self,
        request_context: &[u8],
        presentation_context: &[u8],
        presentation_bytes: &[u8],
        presentation_limit: u64,
    ) -> Result<(), ArcVerifyError> {
        let presentation = Presentation::from_bytes(presentation_bytes, presentation_limit)
            .map_err(|e| ArcVerifyError::Malformed(format!("{}", e)))?;

        let tag = verify_presentation(
            &self.secret_key,
            &self.public_key,
            request_context,
            presentation_context,
            &presentation,
            presentation_limit,
        )
        .map_err(|e| ArcVerifyError::InvalidProof(format!("{}", e)))?;

        // Check for duplicate tag in this presentation context.
        let tag_bytes = serialize_element(&tag).to_vec();
        let tags = self
            .seen_tags
            .entry(presentation_context.to_vec())
            .or_default();

        if tags.contains(&tag_bytes) {
            return Err(ArcVerifyError::DuplicateTag);
        }

        tags.push(tag_bytes);
        Ok(())
    }

    /// Remove the tag set for a presentation context (e.g., on connection close).
    pub fn remove_context(&mut self, presentation_context: &[u8]) {
        self.seen_tags.remove(presentation_context);
    }

    /// Return the number of active presentation contexts being tracked.
    pub fn context_count(&self) -> usize {
        self.seen_tags.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let verifier = ArcVerifier::generate();
        let pk_bytes = verifier.public_key_bytes();
        assert_eq!(pk_bytes.len(), 99);
    }

    #[test]
    fn test_reject_empty_presentation() {
        let mut verifier = ArcVerifier::generate();
        let result = verifier.verify(b"ctx", b"pres_ctx", &[], 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_context() {
        let mut verifier = ArcVerifier::generate();
        verifier.remove_context(b"test");
        assert_eq!(verifier.context_count(), 0);
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let v1 = ArcVerifier::generate();
        let kb = v1.secret_key_bytes();
        assert_eq!(kb.len(), ARC_PRIVKEY_SIZE);
        // A verifier reloaded from the serialized key derives the same pubkey.
        let v2 = ArcVerifier::from_secret_key_bytes(&kb).unwrap();
        assert_eq!(v1.public_key_bytes(), v2.public_key_bytes());
    }

    #[test]
    fn test_from_secret_key_bytes_rejects_wrong_size() {
        assert!(ArcVerifier::from_secret_key_bytes(&[0u8; 64]).is_err());
    }

    /// The core de-risk: a credential issued under key K must present-and-verify
    /// against a verifier that loaded the SAME key K from bytes. This exercises
    /// the entire ARC path the demo depends on
    /// (create_request → create_response → finalize → present → verify).
    #[test]
    fn test_full_issue_present_verify_loop_shared_key() {
        let mut rng = rand_core::OsRng;

        // Issuer generates a key and serializes it the way `arc_key.bin` is stored.
        let (sk, _pk) = arc::setup_server(&mut rng);
        let mut key_bytes = [0u8; ARC_PRIVKEY_SIZE];
        key_bytes[0..32].copy_from_slice(&serialize_scalar(&sk.x0));
        key_bytes[32..64].copy_from_slice(&serialize_scalar(&sk.x1));
        key_bytes[64..96].copy_from_slice(&serialize_scalar(&sk.x2));
        key_bytes[96..128].copy_from_slice(&serialize_scalar(&sk.x0_blinding));

        // Verifier loads the SAME key from bytes (the from_secret_key_bytes fix).
        let mut verifier = ArcVerifier::from_secret_key_bytes(&key_bytes).unwrap();

        let limit = 50u64;
        let request_context = DEFAULT_REQUEST_CONTEXT;
        let presentation_context = b"demo-session-001";

        // 1. Client builds a blinded credential request.
        let (secrets, request) =
            arc::create_credential_request(request_context, &mut rng).unwrap();

        // 2. Issuer signs it with the shared key.
        let response = arc::create_credential_response(
            &verifier.secret_key,
            &verifier.public_key,
            &request,
            &mut rng,
        )
        .unwrap();

        // 3. Client finalizes into a 4-tuple credential.
        let credential =
            arc::finalize_credential(&secrets, &verifier.public_key, &request, &response).unwrap();

        // 4. Client produces a presentation.
        let state = arc::make_presentation_state(credential, presentation_context, limit);
        let (_next_state, _nonce, presentation) = arc::present(&state, &mut rng).unwrap();

        // 5. Server verifies — must succeed because it holds the same key.
        let ok = verifier.verify(
            request_context,
            presentation_context,
            &presentation.to_bytes(),
            limit,
        );
        assert!(ok.is_ok(), "verify under shared key failed: {:?}", ok.err());

        // 6. Replaying the exact same presentation is a duplicate tag.
        let dup = verifier.verify(
            request_context,
            presentation_context,
            &presentation.to_bytes(),
            limit,
        );
        assert!(
            matches!(dup, Err(ArcVerifyError::DuplicateTag)),
            "expected DuplicateTag on replay, got {dup:?}"
        );
    }

    /// Negative: a presentation issued under key A must NOT verify under a
    /// different key B. Guards against the old `generate()`-on-startup bug
    /// silently "passing" by checking against an unrelated random key.
    #[test]
    fn test_presentation_rejected_under_wrong_key() {
        let mut rng = rand_core::OsRng;
        let request_context = DEFAULT_REQUEST_CONTEXT;

        // Issue + present under key A.
        let (sk_a, pk_a) = arc::setup_server(&mut rng);
        let (secrets, request) =
            arc::create_credential_request(request_context, &mut rng).unwrap();
        let response =
            arc::create_credential_response(&sk_a, &pk_a, &request, &mut rng).unwrap();
        let credential =
            arc::finalize_credential(&secrets, &pk_a, &request, &response).unwrap();
        let state = arc::make_presentation_state(credential, b"ctx", 50);
        let (_s, _n, presentation) = arc::present(&state, &mut rng).unwrap();

        // Verify under an unrelated key B.
        let mut verifier_b = ArcVerifier::generate();
        let result =
            verifier_b.verify(request_context, b"ctx", &presentation.to_bytes(), 50);
        assert!(result.is_err(), "presentation verified under the wrong key!");
    }
}
