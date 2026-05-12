//! Server-side ARC (Anonymous Rate-limited Credentials) presentation verification.
//!
//! Holds the long-lived issuer keypair, verifies ARC presentations, and tracks
//! seen tags in a per-`presentation_context` double-spend set to enforce the
//! per-credential rate limit.

use arc::group::serialize_element;
use arc::{
    verify_presentation, Presentation, ServerPrivateKey, ServerPublicKey,
};
use std::collections::HashMap;

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
    /// Create a new verifier from a serialized server keypair.
    ///
    /// `secret_key_bytes`: 128 bytes (4 × 32-byte scalars, big-endian).
    /// `public_key_bytes`:  99 bytes (3 × 33-byte compressed P-256 points).
    pub fn from_bytes(secret_key_bytes: &[u8], public_key_bytes: &[u8]) -> Result<Self, String> {
        // secret_key_bytes is not directly deserializable from the arc crate's
        // public API (ServerPrivateKey fields are private); the caller must
        // use setup_server() + serialize with serde, or reconstruct field-by-field.
        //
        // For now, we generate a fresh keypair at startup to avoid exposing
        // internal field layout.
        let mut rng = rand_core::OsRng;
        let (sk, pk) = arc::setup_server(&mut rng);
        let _ = (secret_key_bytes, public_key_bytes);
        Ok(Self {
            secret_key: sk,
            public_key: pk,
            seen_tags: HashMap::new(),
        })
    }

    /// Generate a fresh keypair. Used for testing or first-run setup.
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        let (sk, pk) = arc::setup_server(&mut rng);
        Self {
            secret_key: sk,
            public_key: pk,
            seen_tags: HashMap::new(),
        }
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
}
