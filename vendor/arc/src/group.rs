//! Thin wrapper over the P-256 arithmetic provided by `p256` / `elliptic-curve`.
//!
//! Exposes the five primitives the ARC spec talks about as if `Group` were
//! a concrete type:
//!
//! * `SerializeElement` / `DeserializeElement`
//! * `SerializeScalar`  / `DeserializeScalar`
//! * `HashToGroup`      / `HashToScalar`
//! * `ScalarInverse`
//! * `generatorG`       / `generatorH`
//!
//! Spec: draft-ietf-privacypass-arc-crypto-01 §6.1 (ARCV1-P256 ciphersuite).

use std::sync::OnceLock;

use elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use elliptic_curve::{Field, Group, PrimeField};
use p256::{EncodedPoint, NistP256};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::ciphersuite::{hash_to_group_dst, hash_to_scalar_dst, INFO_GENERATOR_H, NE, NS};
use crate::error::{Error, Result};

// ---- Type aliases -----------------------------------------------------------
//
// We alias rather than newtype: the compiler scaffolding and the issuance
// modules do a lot of arithmetic (`a * G + b * H` etc.) and the `p256` types
// already implement the required operator traits. A newtype layer would add
// a large pile of boilerplate trait impls without changing behaviour.

/// Element of the prime-order subgroup of P-256 (never the identity when
/// handled by the spec; `DeserializeElement` rejects the identity encoding).
pub type Element = p256::ProjectivePoint;

/// Scalar mod the group order `n`.
pub type Scalar = p256::Scalar;

// ---- Generators -------------------------------------------------------------

/// `generatorG`: the standard P-256 base point.
pub fn generator_g() -> Element {
    Element::generator()
}

/// `generatorH = HashToGroup(SerializeElement(G.Generator()), "generatorH")`
/// (Section 6.1).
///
/// The compressed 33-byte encoding of the standard generator is the hash
/// input — **not** the 65-byte uncompressed form. Test-vector debugging
/// hinges on this detail (cf. the "subtle footgun" note in the design memo).
pub fn generator_h() -> Element {
    static H: OnceLock<Element> = OnceLock::new();
    *H.get_or_init(|| {
        let g_bytes = serialize_element(&generator_g());
        hash_to_group(&g_bytes, INFO_GENERATOR_H.as_bytes())
    })
}

// ---- Serialization ----------------------------------------------------------

/// `SerializeElement` — compressed SEC1 encoding, 33 bytes.
pub fn serialize_element(e: &Element) -> [u8; NE] {
    let affine = p256::AffinePoint::from(*e);
    let encoded = affine.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    debug_assert_eq!(bytes.len(), NE, "compressed P-256 point must be 33 bytes");
    let mut out = [0u8; NE];
    out.copy_from_slice(bytes);
    out
}

/// `DeserializeElement` — 33-byte compressed SEC1 point. Rejects the identity.
pub fn deserialize_element(bytes: &[u8]) -> Result<Element> {
    if bytes.len() != NE {
        return Err(Error::InvalidLength { expected: NE, got: bytes.len() });
    }
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidEncoding)?;
    let affine = Option::<p256::AffinePoint>::from(p256::AffinePoint::from_encoded_point(&encoded))
        .ok_or(Error::InvalidEncoding)?;
    let point = Element::from(affine);
    if bool::from(point.is_identity()) {
        return Err(Error::InvalidEncoding);
    }
    Ok(point)
}

/// `SerializeScalar` — big-endian 32-byte encoding.
pub fn serialize_scalar(s: &Scalar) -> [u8; NS] {
    s.to_bytes().into()
}

/// `DeserializeScalar` — rejects encodings of `0` and of values `>= n`.
pub fn deserialize_scalar(bytes: &[u8]) -> Result<Scalar> {
    if bytes.len() != NS {
        return Err(Error::InvalidLength { expected: NS, got: bytes.len() });
    }
    let array = <[u8; NS]>::try_from(bytes).map_err(|_| Error::InvalidEncoding)?;
    let repr: elliptic_curve::FieldBytes<NistP256> = array.into();
    let s = Option::<Scalar>::from(Scalar::from_repr(repr)).ok_or(Error::InvalidEncoding)?;
    if bool::from(s.ct_eq(&Scalar::ZERO)) {
        return Err(Error::ZeroScalar);
    }
    Ok(s)
}

// ---- Hash-to-X --------------------------------------------------------------

/// `HashToGroup(msg, info)`.
///
/// Uses RFC 9380 `P256_XMD:SHA-256_SSWU_RO_` with
/// `DST = "HashToGroup-" || "ARCV1-P256" || info`.
pub fn hash_to_group(msg: &[u8], info: &[u8]) -> Element {
    let dst = hash_to_group_dst(info);
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[&dst])
        .expect("hash_from_bytes is infallible for DSTs <= 255 bytes")
}

/// `HashToScalar(msg, info)`.
///
/// Implements RFC 9380 `hash_to_field(..., count=1)` targeting the **scalar**
/// field of P-256 (modulus `n`, not `p`):
///
/// 1. `uniform = expand_message_xmd_SHA256(msg, DST, L=48)`
/// 2. Interpret `uniform` as big-endian integer (via `FromOkm`).
/// 3. Reduce mod `n`.
///
/// DST: `"HashToScalar-" || "ARCV1-P256" || info`.
pub fn hash_to_scalar(msg: &[u8], info: &[u8]) -> Scalar {
    let dst = hash_to_scalar_dst(info);
    <NistP256 as GroupDigest>::hash_to_scalar::<ExpandMsgXmd<Sha256>>(&[msg], &[&dst])
        .expect("hash_to_scalar is infallible for DSTs <= 255 bytes")
}

// ---- Scalar arithmetic ------------------------------------------------------

/// `ScalarInverse(s)` — multiplicative inverse modulo the group order.
/// Errors on `s = 0` rather than panicking.
pub fn scalar_inverse(s: &Scalar) -> Result<Scalar> {
    Option::<Scalar>::from(s.invert()).ok_or(Error::ZeroScalar)
}

/// Sample a uniformly-random nonzero scalar. Retries on the
/// (cryptographically negligible) event of hitting zero.
pub(crate) fn nonzero_random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let s = Scalar::random(&mut *rng);
        if !bool::from(<Scalar as Field>::is_zero(&s)) {
            return s;
        }
    }
}
