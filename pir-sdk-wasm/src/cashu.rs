//! WASM bindings for the Cashu Blind Auth (NUT-22) "obtain" leg.
//!
//! BDHKE over secp256k1: the client blinds a fresh secret, the mint
//! blind-signs it, and the client unblinds the result into a single-use
//! Blind Auth Token (BAT). The unblinded `(secret, C)` pair is then wrapped
//! by `web/src/cashu-bat.ts`'s `CashuBatPool` into the `authA` wire token the
//! PIR server's `CashuVerifier` checks.
//!
//! `hash_to_curve` here is byte-identical to
//! `pir_runtime_core::cashu_verifier::hash_to_curve_cashu`; the native
//! cross-check test presents a WASM-blinded BAT to the real `CashuVerifier`
//! and asserts it verifies (the same WASM-mirror+cross-check pattern as
//! `harmony_wire`).

use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// One in-flight Cashu blind/unblind. Holds the blinding scalar `r` and the
/// secret **inside WASM** so neither crosses into JS until the BAT is
/// assembled. Create one per BAT you want to mint.
///
/// Flow (one BAT):
/// 1. `new()` — pick a fresh secret + `r`, compute `B' = Y + r·G`.
/// 2. `blinded_message()` — 33-byte `B'` to POST to the mint.
/// 3. `unblind(keyset_pubkey, signature)` — combine the mint's 33-byte `C'`
///    into the unblinded 33-byte `C`.
/// 4. wrap `{ secret_string(), hex(C) }` (+ keyset id) into a `Bat`.
#[wasm_bindgen]
pub struct WasmCashuBlind {
    /// The Cashu "secret" as a 64-char hex string. `hash_to_curve` is taken
    /// over its UTF-8 bytes (matching the verifier's `secret.into_bytes()`).
    secret_hex: String,
    /// Blinding factor, retained for unblinding.
    r: Scalar,
    /// Precomputed `B' = hash_to_curve(secret) + r·G`.
    b_prime: [u8; 33],
}

#[wasm_bindgen]
impl WasmCashuBlind {
    /// Pick a fresh random secret + blinding factor and compute `B'`.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> WasmCashuBlind {
        let mut rng = OsRng;
        let mut secret_raw = [0u8; 32];
        rng.fill_bytes(&mut secret_raw);
        let secret_hex = hex::encode(secret_raw);
        let r = Scalar::generate_vartime(&mut rng);

        let y = hash_to_curve_cashu(secret_hex.as_bytes());
        let b_prime_point = y + ProjectivePoint::GENERATOR * r;

        WasmCashuBlind {
            secret_hex,
            r,
            b_prime: compress(&b_prime_point),
        }
    }

    /// The Cashu "secret" string (64-char hex) for the `authA` token.
    pub fn secret_string(&self) -> String {
        self.secret_hex.clone()
    }

    /// The 33-byte blinded message `B'` to POST to the mint
    /// (`/dev/cashu/mint`).
    pub fn blinded_message(&self) -> Vec<u8> {
        self.b_prime.to_vec()
    }

    /// Unblind the mint's 33-byte `C'` with the keyset public key `K`
    /// (33 bytes): `C = C' − r·K`. Returns the 33-byte unblinded signature
    /// `C` (hex-encode it for the token's `C` field).
    ///
    /// Throws on a malformed point. (`C` verifies as `C == k·hash_to_curve
    /// (secret)` on the server.)
    pub fn unblind(&self, keyset_pubkey: &[u8], signature: &[u8]) -> Result<Vec<u8>, JsError> {
        let k_point =
            parse_point(keyset_pubkey).ok_or_else(|| JsError::new("invalid keyset pubkey (want 33-byte compressed point)"))?;
        let c_prime =
            parse_point(signature).ok_or_else(|| JsError::new("invalid blind signature (want 33-byte compressed point)"))?;
        let c = c_prime - k_point * self.r;
        Ok(compress(&c).to_vec())
    }
}

/// Cashu NUT-00 hash-to-curve. Byte-identical to
/// `pir_runtime_core::cashu_verifier::hash_to_curve_cashu`:
/// `msg = SHA256("Secp256k1_HashToCurve_Cashu_" || secret)`, then for
/// `counter = 0,1,…` lift `0x02 || SHA256(msg || u32_le(counter))` until a
/// valid non-identity point is found.
fn hash_to_curve_cashu(secret: &[u8]) -> ProjectivePoint {
    let mut hasher = Sha256::new();
    hasher.update(b"Secp256k1_HashToCurve_Cashu_");
    hasher.update(secret);
    let msg_hash = hasher.finalize();

    for counter in 0u32.. {
        let mut h = Sha256::new();
        h.update(msg_hash);
        h.update(counter.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();

        let mut point_bytes = [0u8; 33];
        point_bytes[0] = 0x02;
        point_bytes[1..].copy_from_slice(&digest);

        if let Some(point) =
            Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(&point_bytes.into()))
        {
            if !bool::from(point.is_identity()) {
                return point;
            }
        }
    }
    unreachable!("secp256k1 has ~2^256 points; a valid lift is found well within 2^32 counters")
}

/// Parse a 33-byte compressed point.
fn parse_point(bytes: &[u8]) -> Option<ProjectivePoint> {
    let arr: [u8; 33] = bytes.try_into().ok()?;
    Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(&arr.into()))
}

/// Compress a point to 33 bytes (SEC1).
fn compress(p: &ProjectivePoint) -> [u8; 33] {
    let enc = p.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(enc.as_bytes());
    out
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    /// URL-safe base64 without padding (matches `cashu_verifier::base64url_decode`).
    fn base64url_nopad(data: &[u8]) -> String {
        const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = *chunk.get(1).unwrap_or(&0);
            let b2 = *chunk.get(2).unwrap_or(&0);
            out.push(ALPHA[(b0 >> 2) as usize] as char);
            out.push(ALPHA[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHA[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
            }
            if chunk.len() > 2 {
                out.push(ALPHA[(b2 & 0x3f) as usize] as char);
            }
        }
        out
    }

    /// The ultimate cross-check: a BAT blinded+unblinded entirely via
    /// `WasmCashuBlind`, blind-signed by a k256 mint key, must verify under
    /// the REAL `pir_runtime_core::cashu_verifier::CashuVerifier`. If this
    /// module's hash_to_curve or the BDHKE math drifted from the server, the
    /// verify would fail.
    #[test]
    fn wasm_blinded_bat_verifies_under_real_cashu_verifier() {
        let mut rng = OsRng;

        // Mint keyset.
        let k = Scalar::generate_vartime(&mut rng);
        let keyset_pubkey = compress(&(ProjectivePoint::GENERATOR * k));
        let keyset_id = format!("{}-auth", &hex::encode(keyset_pubkey)[..16]);
        let k_hex = hex::encode(k.to_bytes());

        // Client blinds via the WASM binding.
        let blind = WasmCashuBlind::new();
        let secret = blind.secret_string();
        let b_prime = blind.blinded_message();
        assert_eq!(b_prime.len(), 33);

        // Mint: C' = k · B'.
        let b_point = parse_point(&b_prime).expect("B' point");
        let c_prime = compress(&(b_point * k));

        // Client unblinds via the WASM binding.
        let c = blind.unblind(&keyset_pubkey, &c_prime).ok().expect("unblind");
        let c_hex = hex::encode(&c);

        // Assemble the authA token exactly as cashu-bat.ts does.
        let json = format!(
            "{{\"id\":\"{}\",\"secret\":\"{}\",\"C\":\"{}\"}}",
            keyset_id, secret, c_hex
        );
        let token = format!("authA{}", base64url_nopad(json.as_bytes()));

        // Verify under the real server verifier.
        let mut verifier = pir_runtime_core::cashu_verifier::CashuVerifier::from_keys(&[(
            keyset_id.clone(),
            k_hex,
        )])
        .expect("verifier");
        assert!(
            verifier.verify(&token).is_ok(),
            "WASM-blinded BAT failed verification under the real CashuVerifier"
        );

        // Single-use: replay must be rejected as already spent.
        assert!(
            verifier.verify(&token).is_err(),
            "replaying the same BAT should fail (double-spend)"
        );
    }

    #[test]
    fn distinct_blinds_have_distinct_secrets() {
        let a = WasmCashuBlind::new();
        let b = WasmCashuBlind::new();
        assert_ne!(a.secret_string(), b.secret_string());
        assert_ne!(a.blinded_message(), b.blinded_message());
        assert_eq!(a.secret_string().len(), 64);
    }
}
