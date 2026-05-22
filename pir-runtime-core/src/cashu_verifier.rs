//! Server-side Cashu Blind Auth (NUT-22) BAT verification.
//!
//! Verifies Blind Authentication Tokens using BDHKE over secp256k1.
//! Each BAT is single-use: the secret is revealed at presentation time
//! and added to a spent-set to prevent reuse.
//!
//! Reference: NUT-00 (Cryptography and Models), NUT-22 (Blind Authentication).

use k256::{
    elliptic_curve::{
        group::prime::PrimeCurveAffine,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    AffinePoint, ProjectivePoint, Scalar,
};
use k256::elliptic_curve::ff::PrimeField;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Errors during BAT verification.
#[derive(Debug, Clone)]
pub enum CashuVerifyError {
    InvalidFormat(String),
    InvalidSignature,
    AlreadySpent,
    UnknownKeyset(String),
}

impl std::fmt::Display for CashuVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "invalid BAT format: {}", msg),
            Self::InvalidSignature => write!(f, "BAT signature verification failed"),
            Self::AlreadySpent => write!(f, "BAT already spent"),
            Self::UnknownKeyset(id) => write!(f, "unknown keyset: {}", id),
        }
    }
}

/// A parsed Blind Auth Token from the wire.
struct BatToken {
    keyset_id: String,
    secret: Vec<u8>,
    /// The unblinded signature C = k * hash_to_curve(secret), as a
    /// compressed secp256k1 point (33 bytes).
    signature_bytes: [u8; 33],
}

/// Holds the mint's authorized keysets and the spent-secret set.
pub struct CashuVerifier {
    /// Known keysets: keyset_id → (secret_scalar, full_public_key_point).
    keysets: Vec<(String, Scalar)>,
    /// Hashes of spent secrets (SHA-256).
    spent_secrets: HashSet<[u8; 32]>,
}

impl CashuVerifier {
    /// Create a verifier from a list of (keyset_id, secret_key_hex) pairs.
    ///
    /// `keys`: slice of `(keyset_id, hex_encoded_32_byte_secret_scalar)`.
    pub fn from_keys(keys: &[(String, String)]) -> Result<Self, String> {
        let mut keysets = Vec::new();
        for (id, sk_hex) in keys {
            let sk_bytes = hex::decode(sk_hex)
                .map_err(|_| format!("invalid hex for keyset {}", id))?;
            if sk_bytes.len() != 32 {
                return Err(format!("keyset {}: secret key must be 32 bytes", id));
            }
            let sk_arr: [u8; 32] = sk_bytes.try_into().unwrap();
            let scalar = <Scalar as PrimeField>::from_repr(sk_arr.into())
                .into_option()
                .ok_or_else(|| format!("keyset {}: invalid scalar", id))?;
            keysets.push((id.clone(), scalar));
        }
        Ok(Self {
            keysets,
            spent_secrets: HashSet::new(),
        })
    }

    /// Verify a BAT presented by a client.
    ///
    /// `bat_json`: the `authA`-prefixed base64url-encoded AuthProof JSON.
    /// Expected format: `authAeyJpZCI6...` (base64url of `{"id":"...","secret":"...","C":"..."}`)
    ///
    /// Returns `Ok(())` if the BAT is valid and has not been spent.
    pub fn verify(&mut self, bat_base64url: &str) -> Result<(), CashuVerifyError> {
        let token = self.decode_bat(bat_base64url)?;
        let secret_scalar = self
            .keysets
            .iter()
            .find(|(id, _)| id == &token.keyset_id)
            .map(|(_, sk)| sk)
            .ok_or_else(|| CashuVerifyError::UnknownKeyset(token.keyset_id.clone()))?;

        // BDHKE verification: C == k * hash_to_curve(secret)
        let y = hash_to_curve_cashu(&token.secret);
        let expected_c = y * secret_scalar;

        let expected_bytes = expected_c.to_encoded_point(true);
        if expected_bytes.as_ref() != token.signature_bytes.as_slice() {
            return Err(CashuVerifyError::InvalidSignature);
        }

        // Check spent
        let secret_hash: [u8; 32] = Sha256::digest(&token.secret).into();
        if !self.spent_secrets.insert(secret_hash) {
            return Err(CashuVerifyError::AlreadySpent);
        }

        Ok(())
    }

    /// Decode an authA token from the wire format.
    fn decode_bat(&self, bat: &str) -> Result<BatToken, CashuVerifyError> {
        // Strip authA prefix
        let payload = bat
            .strip_prefix("authA")
            .ok_or_else(|| CashuVerifyError::InvalidFormat("missing authA prefix".into()))?;

        // Base64url decode (no padding, URL-safe alphabet)
        let json_bytes = base64url_decode(payload)
            .ok_or_else(|| CashuVerifyError::InvalidFormat("base64url decode failed".into()))?;

        // Parse JSON: { "id": "...", "secret": "...", "C": "..." }
        #[derive(serde::Deserialize)]
        struct AuthProofRaw {
            id: String,
            secret: String,
            #[serde(rename = "C")]
            c: String,
        }
        let raw: AuthProofRaw = serde_json::from_slice(&json_bytes)
            .map_err(|e| CashuVerifyError::InvalidFormat(format!("json: {}", e)))?;

        let c_bytes = hex::decode(&raw.c)
            .map_err(|e| CashuVerifyError::InvalidFormat(format!("C hex: {}", e)))?;
        if c_bytes.len() != 33 {
            return Err(CashuVerifyError::InvalidFormat(format!(
                "C must be 33 bytes, got {}",
                c_bytes.len()
            )));
        }
        let mut sig_bytes = [0u8; 33];
        sig_bytes.copy_from_slice(&c_bytes);

        Ok(BatToken {
            keyset_id: raw.id,
            secret: raw.secret.into_bytes(),
            signature_bytes: sig_bytes,
        })
    }

    /// Number of spent secrets tracked.
    pub fn spent_count(&self) -> usize {
        self.spent_secrets.len()
    }

    /// Number of known keysets.
    pub fn keyset_count(&self) -> usize {
        self.keysets.len()
    }
}

/// Cashu NUT-00 hash-to-curve: domain-separated SHA-256 with counter-based
/// point lifting on secp256k1.
///
/// ```text
/// msg_hash = SHA256(b"Secp256k1_HashToCurve_Cashu_" || secret)
/// for counter in 0..:
///   x = SHA256(msg_hash || u32_le(counter))
///   point = lift_x(0x02 || x)
///   if point is on curve: return point
/// ```
fn hash_to_curve_cashu(secret: &[u8]) -> ProjectivePoint {
    let domain = b"Secp256k1_HashToCurve_Cashu_";
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(secret);
    let msg_hash = hasher.finalize();

    for counter in 0u32.. {
        let mut h = Sha256::new();
        h.update(msg_hash);
        h.update(counter.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();

        // Try to lift x = digest as an x-coordinate with even y (0x02 prefix).
        let mut point_bytes = [0u8; 33];
        point_bytes[0] = 0x02;
        point_bytes[1..].copy_from_slice(&digest);

        if let Some(point) =
            AffinePoint::from_encoded_point(&k256::EncodedPoint::from_bytes(point_bytes).unwrap())
                .into_option()
        {
            if !bool::from(point.is_identity()) {
                return point.into();
            }
        }
    }

    // Unreachable: secp256k1 has ~2^256 points, counters run to 2^32.
    unreachable!()
}

/// Minimal base64url decoder (no padding), returns None on invalid input.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() % 4 == 1 {
        return None;
    }
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut buf = 0u32;
    let mut bits = 0u8;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for &c in input.as_bytes() {
        let val = alphabet.iter().position(|&a| a == c)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Brings the `is_identity` trait method into scope for ProjectivePoint
    // in tests. Production code in this module uses it through a different
    // path; only the test path needed the explicit import.
    use k256::elliptic_curve::Group;

    #[test]
    fn test_hash_to_curve_round_trip() {
        let secret = b"test-secret-12345";
        let point = hash_to_curve_cashu(secret);
        // Must not be identity
        assert!(!bool::from(point.is_identity()));
        // Same secret → same point
        let point2 = hash_to_curve_cashu(secret);
        assert_eq!(point, point2);
    }

    #[test]
    fn test_keyset_loading() {
        let keys = vec![(
            "test-keyset-auth".to_string(),
            "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        )];
        let v = CashuVerifier::from_keys(&keys).unwrap();
        assert_eq!(v.keyset_count(), 1);
    }

    #[test]
    fn test_decode_bat_invalid_prefix() {
        let v = CashuVerifier::from_keys(&[]).unwrap();
        assert!(v.decode_bat("not-authA-xxx").is_err());
        assert!(v.decode_bat("authA!!!not-base64").is_err());
    }
}
