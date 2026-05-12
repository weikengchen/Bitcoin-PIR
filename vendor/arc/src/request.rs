//! Client-side credential request and matching proof.
//!
//! Spec: draft-ietf-privacypass-arc-crypto-01 §4.2.1, §5.1.

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ciphersuite::{proof_session, INFO_REQUEST_CONTEXT, NE, NS, PROOF_NAME_CREDENTIAL_REQUEST};
use crate::error::{Error, Result};
use crate::group::{
    deserialize_element, deserialize_scalar, generator_g, generator_h, hash_to_scalar,
    nonzero_random_scalar, serialize_element, serialize_scalar, Element, Scalar,
};
use crate::schnorr::{LinearRelation, NISchnorrProofShake128P256, Proof};

/// Per-request secrets kept by the client until `FinalizeCredential`.
///
/// Per draft-01 §4.2.1:
/// - `m1` is a **fresh random scalar** — the long-term, client-only attribute
///   used to derive per-presentation tags (rate-limiting fingerprint).
/// - `m2` is **derived from `requestContext`** via `HashToScalar`; the server
///   re-derives it at presentation time (`m2 = HashToScalar(requestContext,
///   "requestContext")`).
/// - `r1`, `r2` are Pedersen blindings on the ElGamal-style commitments.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClientSecrets {
    pub m1: Scalar,
    pub m2: Scalar,
    pub r1: Scalar,
    pub r2: Scalar,
}

/// Wire-format credential request.
///
/// Byte layout (§4.2.1):
///
/// ```text
/// m1Enc           : Ne
/// m2Enc           : Ne
/// requestProof    : 5 * Ns        // challenge + 4 responses
/// ```
#[derive(Clone, Debug)]
pub struct CredentialRequest {
    pub m1_enc: Element,
    pub m2_enc: Element,
    pub request_proof: Proof,
}

impl CredentialRequest {
    /// `Nrequest = 2 * Ne + 5 * Ns`.
    pub const SIZE: usize = 2 * NE + 5 * NS;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..NE].copy_from_slice(&serialize_element(&self.m1_enc));
        out[NE..2 * NE].copy_from_slice(&serialize_element(&self.m2_enc));
        let proof_off = 2 * NE;
        out[proof_off..proof_off + NS]
            .copy_from_slice(&serialize_scalar(&self.request_proof.challenge));
        for (i, r) in self.request_proof.responses.iter().enumerate() {
            let off = proof_off + NS + i * NS;
            out[off..off + NS].copy_from_slice(&serialize_scalar(r));
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidLength { expected: Self::SIZE, got: bytes.len() });
        }
        let m1_enc = deserialize_element(&bytes[..NE])?;
        let m2_enc = deserialize_element(&bytes[NE..2 * NE])?;
        let proof_off = 2 * NE;
        let challenge = deserialize_scalar(&bytes[proof_off..proof_off + NS])?;
        let mut responses = Vec::with_capacity(4);
        for i in 0..4 {
            let off = proof_off + NS + i * NS;
            responses.push(deserialize_scalar(&bytes[off..off + NS])?);
        }
        Ok(Self {
            m1_enc,
            m2_enc,
            request_proof: Proof { challenge, responses },
        })
    }
}

/// `CreateCredentialRequest(requestContext, rng)` — §4.2.1.
///
/// Per draft-01 (verified against the WG JSON test vectors):
///
/// - `m1 = G.RandomScalar()`                                  — fresh random.
/// - `m2 = G.HashToScalar(requestContext, "requestContext")`  — deterministic.
/// - `r1 = G.RandomScalar()`, `r2 = G.RandomScalar()`         — fresh blindings.
/// - `m1Enc = m1·G + r1·H`
/// - `m2Enc = m2·G + r2·H`
/// - `requestProof = MakeCredentialRequestProof(...)`.
pub fn create_credential_request<R: RngCore + CryptoRng>(
    request_context: &[u8],
    rng: &mut R,
) -> Result<(ClientSecrets, CredentialRequest)> {
    let m1 = nonzero_random_scalar(rng);
    let m2 = hash_to_scalar(request_context, INFO_REQUEST_CONTEXT.as_bytes());
    let r1 = nonzero_random_scalar(rng);
    let r2 = nonzero_random_scalar(rng);
    let g = generator_g();
    let h = generator_h();
    let m1_enc = g * m1 + h * r1;
    let m2_enc = g * m2 + h * r2;
    let request_proof = make_credential_request_proof(&m1, &m2, &r1, &r2, &m1_enc, &m2_enc, rng)?;
    Ok((
        ClientSecrets { m1, m2, r1, r2 },
        CredentialRequest { m1_enc, m2_enc, request_proof },
    ))
}

// ---- CredentialRequest proof (§5.1) -----------------------------------------
//
// Scalar witnesses : [m1, m2, r1, r2]
// Equations        :
//     m1Enc = m1 * generatorG + r1 * generatorH
//     m2Enc = m2 * generatorG + r2 * generatorH
//
// Wire proof       : challenge, response0..response3     (= 5 * Ns bytes)
//
// Session/transcript label for Fiat-Shamir:
//   "ARCV1-P256CredentialRequest"

/// Build the [`LinearRelation`] that defines the request proof. Called by
/// both `make_credential_request_proof` and `verify_credential_request_proof`
/// so the two sides agree on variable allocation order (which is part of the
/// Fiat-Shamir transcript).
fn credential_request_statement(m1_enc: Element, m2_enc: Element) -> LinearRelation {
    let mut st = LinearRelation::new();
    let sv = st.allocate_scalars(4); // [m1, m2, r1, r2]
    let ev = st.allocate_elements(4); // [g, h, m1_enc, m2_enc]
    st.set_elements(&[
        (ev[0], generator_g()),
        (ev[1], generator_h()),
        (ev[2], m1_enc),
        (ev[3], m2_enc),
    ])
    .expect("variables were just allocated");
    // m1Enc = m1·G + r1·H
    st.append_equation(ev[2], &[(sv[0], ev[0]), (sv[2], ev[1])])
        .expect("variables were just allocated");
    // m2Enc = m2·G + r2·H
    st.append_equation(ev[3], &[(sv[1], ev[0]), (sv[3], ev[1])])
        .expect("variables were just allocated");
    st
}

/// Build the zero-knowledge proof that accompanies a `CredentialRequest`.
pub fn make_credential_request_proof<R: RngCore + CryptoRng>(
    m1: &Scalar,
    m2: &Scalar,
    r1: &Scalar,
    r2: &Scalar,
    m1_enc: &Element,
    m2_enc: &Element,
    rng: &mut R,
) -> Result<Proof> {
    let st = credential_request_statement(*m1_enc, *m2_enc);
    let session = proof_session(PROOF_NAME_CREDENTIAL_REQUEST);
    NISchnorrProofShake128P256::new(&session, &st).prove(&[*m1, *m2, *r1, *r2], rng)
}

/// Verify the proof attached to a `CredentialRequest`. (§5.1.2)
pub fn verify_credential_request_proof(request: &CredentialRequest) -> Result<()> {
    let st = credential_request_statement(request.m1_enc, request.m2_enc);
    let session = proof_session(PROOF_NAME_CREDENTIAL_REQUEST);
    NISchnorrProofShake128P256::new(&session, &st).verify(&request.request_proof)
}
