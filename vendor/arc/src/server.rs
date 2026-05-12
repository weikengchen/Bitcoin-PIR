//! Server key material and setup.
//!
//! Spec: draft-ietf-privacypass-arc-crypto-01 §4.1, §4.2.2.
//!
//! The credential is an *algebraic MAC* of the GGM family ("MAC_GGM"). The
//! tag and verification operations are not exposed as a standalone object in
//! draft-01; they are inlined in `CreateCredentialResponse` and
//! `VerifyPresentation`. This module therefore only holds the keys.

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::NE;
use crate::error::{Error, Result};
use crate::group::{
    deserialize_element, generator_g, generator_h, nonzero_random_scalar, serialize_element,
    Element, Scalar,
};

/// Secret scalars held by the issuer / verifier.
///
/// Layout matches draft-01 §4.1 exactly: `x0`, `x1`, `x2` are the MAC key
/// components; `x0Blinding` is used only in the blinding commitment `X0` so
/// that the issuer's public key does not leak `x0` in the clear.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ServerPrivateKey {
    pub x0: Scalar,
    pub x1: Scalar,
    pub x2: Scalar,
    pub x0_blinding: Scalar,
}

impl ServerPrivateKey {
    /// Derive the matching [`ServerPublicKey`].
    ///
    /// Per draft-01 §4.1:
    ///
    /// ```text
    /// X0 = x0 * generatorG + x0Blinding * generatorH
    /// X1 = x1 * generatorH
    /// X2 = x2 * generatorH
    /// ```
    pub fn public_key(&self) -> ServerPublicKey {
        let g = generator_g();
        let h = generator_h();
        ServerPublicKey {
            x0: g * self.x0 + h * self.x0_blinding,
            x1: h * self.x1,
            x2: h * self.x2,
        }
    }
}

/// Three commitments `X0`, `X1`, `X2` published by the issuer.
///
/// Stored as deserialized [`Element`]s. The wire format is three concatenated
/// 33-byte compressed SEC1 encodings (see [`ServerPublicKey::to_bytes`]).
#[derive(Clone, Copy, Debug)]
pub struct ServerPublicKey {
    pub x0: Element,
    pub x1: Element,
    pub x2: Element,
}

impl ServerPublicKey {
    /// Serialized length: `3 * Ne = 99` bytes.
    pub const SIZE: usize = 3 * NE;

    /// Encode as `SerializeElement(X0) || SerializeElement(X1) || SerializeElement(X2)`.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..NE].copy_from_slice(&serialize_element(&self.x0));
        out[NE..2 * NE].copy_from_slice(&serialize_element(&self.x1));
        out[2 * NE..].copy_from_slice(&serialize_element(&self.x2));
        out
    }

    /// Decode three compressed SEC1 points. Rejects the identity for each.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidLength { expected: Self::SIZE, got: bytes.len() });
        }
        Ok(Self {
            x0: deserialize_element(&bytes[..NE])?,
            x1: deserialize_element(&bytes[NE..2 * NE])?,
            x2: deserialize_element(&bytes[2 * NE..])?,
        })
    }
}

/// `SetupServer()` — generate a fresh `(privateKey, publicKey)` pair.
///
/// All four secret scalars are sampled uniformly from `[1, n-1]`.
/// (The spec permits any uniform sampling method in §4.1; we use the RNG the
/// caller provides.)
pub fn setup_server<R: RngCore + CryptoRng>(rng: &mut R) -> (ServerPrivateKey, ServerPublicKey) {
    let sk = ServerPrivateKey {
        x0: nonzero_random_scalar(rng),
        x1: nonzero_random_scalar(rng),
        x2: nonzero_random_scalar(rng),
        x0_blinding: nonzero_random_scalar(rng),
    };
    let pk = sk.public_key();
    (sk, pk)
}

