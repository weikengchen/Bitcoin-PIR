//! Server-side credential response and matching proof.
//!
//! Spec: draft-ietf-privacypass-arc-crypto-01 §4.2.2, §5.2.

use rand_core::{CryptoRng, RngCore};

use crate::ciphersuite::{proof_session, NE, NS, PROOF_NAME_CREDENTIAL_RESPONSE};
use crate::error::{Error, Result};
use crate::group::{
    deserialize_element, deserialize_scalar, generator_g, generator_h, nonzero_random_scalar,
    serialize_element, serialize_scalar, Element, Scalar,
};
use crate::request::{verify_credential_request_proof, CredentialRequest};
use crate::schnorr::{LinearRelation, NISchnorrProofShake128P256, Proof};
use crate::server::{ServerPrivateKey, ServerPublicKey};

/// Wire-format credential response.
///
/// Byte layout (§4.2.2):
///
/// ```text
/// U, encUPrime, X0Aux, X1Aux, X2Aux, HAux  : 6 * Ne
/// responseProof                            : 8 * Ns  (challenge + 7 responses)
/// ```
#[derive(Clone, Debug)]
pub struct CredentialResponse {
    pub u: Element,
    pub enc_u_prime: Element,
    pub x0_aux: Element,
    pub x1_aux: Element,
    pub x2_aux: Element,
    pub h_aux: Element,
    pub response_proof: Proof,
}

impl CredentialResponse {
    /// `Nresponse = 6 * Ne + 8 * Ns`.
    pub const SIZE: usize = 6 * NE + 8 * NS;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        let elems = [
            &self.u,
            &self.enc_u_prime,
            &self.x0_aux,
            &self.x1_aux,
            &self.x2_aux,
            &self.h_aux,
        ];
        for (i, e) in elems.iter().enumerate() {
            out[i * NE..(i + 1) * NE].copy_from_slice(&serialize_element(e));
        }
        let proof_off = 6 * NE;
        out[proof_off..proof_off + NS]
            .copy_from_slice(&serialize_scalar(&self.response_proof.challenge));
        for (i, r) in self.response_proof.responses.iter().enumerate() {
            let off = proof_off + NS + i * NS;
            out[off..off + NS].copy_from_slice(&serialize_scalar(r));
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(Error::InvalidLength { expected: Self::SIZE, got: bytes.len() });
        }
        let u = deserialize_element(&bytes[..NE])?;
        let enc_u_prime = deserialize_element(&bytes[NE..2 * NE])?;
        let x0_aux = deserialize_element(&bytes[2 * NE..3 * NE])?;
        let x1_aux = deserialize_element(&bytes[3 * NE..4 * NE])?;
        let x2_aux = deserialize_element(&bytes[4 * NE..5 * NE])?;
        let h_aux = deserialize_element(&bytes[5 * NE..6 * NE])?;
        let proof_off = 6 * NE;
        let challenge = deserialize_scalar(&bytes[proof_off..proof_off + NS])?;
        let mut responses = Vec::with_capacity(7);
        for i in 0..7 {
            let off = proof_off + NS + i * NS;
            responses.push(deserialize_scalar(&bytes[off..off + NS])?);
        }
        Ok(Self {
            u,
            enc_u_prime,
            x0_aux,
            x1_aux,
            x2_aux,
            h_aux,
            response_proof: Proof { challenge, responses },
        })
    }
}

/// `CreateCredentialResponse(sk, pk, request, rng)`.
///
/// Throws `Error::Verify` if `VerifyCredentialRequestProof(request)` fails.
///
/// Construction (§4.2.2):
/// 1. Verify the request proof.
/// 2. Sample a fresh nonzero blinding scalar `b`.
/// 3. Compute the six response elements:
///    - `U         = b · generatorG`
///    - `HAux      = b · generatorH`
///    - `X0Aux     = (b · x0Blinding) · generatorH`
///    - `X1Aux     = b · X1`                      (= (b · x1) · H)
///    - `X2Aux     = b · X2`                      (= (b · x2) · H)
///    - `encUPrime = b · (X0 + x1 · m1Enc + x2 · m2Enc)`,
///      equivalently `b · X0 + t1 · m1Enc + t2 · m2Enc` with `t_i = b · x_i`.
/// 4. Build and attach the 11-equation response proof (§5.2).
pub fn create_credential_response<R: RngCore + CryptoRng>(
    sk: &ServerPrivateKey,
    pk: &ServerPublicKey,
    request: &CredentialRequest,
    rng: &mut R,
) -> Result<CredentialResponse> {
    verify_credential_request_proof(request)?;

    let b = nonzero_random_scalar(rng);
    let t1 = b * sk.x1;
    let t2 = b * sk.x2;
    let g = generator_g();
    let h = generator_h();

    let u = g * b;
    let h_aux = h * b;
    let x0_aux = h * (b * sk.x0_blinding);
    let x1_aux = pk.x1 * b;
    let x2_aux = pk.x2 * b;
    let enc_u_prime = pk.x0 * b + request.m1_enc * t1 + request.m2_enc * t2;

    let response_proof = make_credential_response_proof(
        sk,
        pk,
        request,
        &b,
        &t1,
        &t2,
        &u,
        &enc_u_prime,
        &x0_aux,
        &x1_aux,
        &x2_aux,
        &h_aux,
        rng,
    )?;
    Ok(CredentialResponse {
        u,
        enc_u_prime,
        x0_aux,
        x1_aux,
        x2_aux,
        h_aux,
        response_proof,
    })
}

// ---- CredentialResponse proof (§5.2) ----------------------------------------
//
// Scalar witnesses (7) : [x0, x1, x2, x0Blinding, b, t1, t2]
//                        with side-conditions t1 = b*x1, t2 = b*x2.
//
// Element variables (13, in allocation order):
//     [generatorG, generatorH, m1Enc, m2Enc, U, encUPrime,
//      X0, X1, X2, X0Aux, X1Aux, X2Aux, HAux]
//
// Equations (11, in insertion order — this order is part of the Fiat-Shamir
// transcript, don't reshuffle):
//     1.  X0        = x0 * generatorG + x0Blinding * generatorH
//     2.  X1        = x1 * generatorH
//     3.  X2        = x2 * generatorH
//     4.  HAux      = b  * generatorH
//     5.  X0Aux     = x0Blinding * HAux
//     6.  X1Aux     = t1 * generatorH
//     7.  X1Aux     = b  * X1
//     8.  X2Aux     = b  * X2
//     9.  X2Aux     = t2 * generatorH
//    10.  U         = b  * generatorG
//    11.  encUPrime = b  * X0  +  t1 * m1Enc  +  t2 * m2Enc
//
// Wire proof : challenge, response0..response6       (= 8 * Ns bytes)
// Transcript label: "ARCV1-P256CredentialResponse"
//
// Equations (6)+(7) together prove `t1 = b * x1` (likewise (8)+(9) for t2).
// The linear-relation framework cannot express a bilinear equation directly;
// binding `X1Aux = t1·H = b·X1` with two independent equations lets the
// linear system pin down `t1` modulo the group order even though each
// equation alone is underdetermined.

/// Build the [`LinearRelation`] that defines the response proof. Shared by
/// prover and verifier so the variable-allocation and equation-insertion
/// order (both transcript-affecting) are defined in exactly one place.
#[allow(clippy::too_many_arguments)]
fn credential_response_statement(
    pk: &ServerPublicKey,
    m1_enc: Element,
    m2_enc: Element,
    u: Element,
    enc_u_prime: Element,
    x0_aux: Element,
    x1_aux: Element,
    x2_aux: Element,
    h_aux: Element,
) -> LinearRelation {
    let mut st = LinearRelation::new();

    // 7 scalar vars: [x0, x1, x2, xb, b, t1, t2]
    let sv = st.allocate_scalars(7);
    let x0_var = sv[0];
    let x1_var = sv[1];
    let x2_var = sv[2];
    let xb_var = sv[3];
    let b_var = sv[4];
    let t1_var = sv[5];
    let t2_var = sv[6];

    // 13 element vars in the order below — matches `arc_proofs.sage` exactly.
    let ev = st.allocate_elements(13);
    let gen_g_var = ev[0];
    let gen_h_var = ev[1];
    let m1_enc_var = ev[2];
    let m2_enc_var = ev[3];
    let u_var = ev[4];
    let enc_u_prime_var = ev[5];
    let cap_x0_var = ev[6];
    let cap_x1_var = ev[7];
    let cap_x2_var = ev[8];
    let x0_aux_var = ev[9];
    let x1_aux_var = ev[10];
    let x2_aux_var = ev[11];
    let h_aux_var = ev[12];

    st.set_elements(&[
        (gen_g_var, generator_g()),
        (gen_h_var, generator_h()),
        (m1_enc_var, m1_enc),
        (m2_enc_var, m2_enc),
        (u_var, u),
        (enc_u_prime_var, enc_u_prime),
        (cap_x0_var, pk.x0),
        (cap_x1_var, pk.x1),
        (cap_x2_var, pk.x2),
        (x0_aux_var, x0_aux),
        (x1_aux_var, x1_aux),
        (x2_aux_var, x2_aux),
        (h_aux_var, h_aux),
    ])
    .expect("variables were just allocated");

    // 1. X0 = x0·G + xb·H
    st.append_equation(cap_x0_var, &[(x0_var, gen_g_var), (xb_var, gen_h_var)])
        .expect("vars allocated");
    // 2. X1 = x1·H
    st.append_equation(cap_x1_var, &[(x1_var, gen_h_var)]).expect("vars allocated");
    // 3. X2 = x2·H
    st.append_equation(cap_x2_var, &[(x2_var, gen_h_var)]).expect("vars allocated");
    // 4. HAux = b·H
    st.append_equation(h_aux_var, &[(b_var, gen_h_var)]).expect("vars allocated");
    // 5. X0Aux = xb·HAux
    st.append_equation(x0_aux_var, &[(xb_var, h_aux_var)]).expect("vars allocated");
    // 6. X1Aux = t1·H
    st.append_equation(x1_aux_var, &[(t1_var, gen_h_var)]).expect("vars allocated");
    // 7. X1Aux = b·X1
    st.append_equation(x1_aux_var, &[(b_var, cap_x1_var)]).expect("vars allocated");
    // 8. X2Aux = b·X2
    st.append_equation(x2_aux_var, &[(b_var, cap_x2_var)]).expect("vars allocated");
    // 9. X2Aux = t2·H
    st.append_equation(x2_aux_var, &[(t2_var, gen_h_var)]).expect("vars allocated");
    // 10. U = b·G
    st.append_equation(u_var, &[(b_var, gen_g_var)]).expect("vars allocated");
    // 11. encUPrime = b·X0 + t1·m1Enc + t2·m2Enc
    st.append_equation(
        enc_u_prime_var,
        &[(b_var, cap_x0_var), (t1_var, m1_enc_var), (t2_var, m2_enc_var)],
    )
    .expect("vars allocated");

    st
}

/// `MakeCredentialResponseProof(sk, pk, request, b, t1, t2, U, encUPrime, X0Aux, X1Aux, X2Aux, HAux, rng)`.
///
/// `t1` and `t2` must equal `b * sk.x1` and `b * sk.x2` respectively — the
/// linear-relation framework does not enforce the bilinear side-condition at
/// prove time, but the verifier would reject a proof where it doesn't hold.
#[allow(clippy::too_many_arguments)]
pub fn make_credential_response_proof<R: RngCore + CryptoRng>(
    sk: &ServerPrivateKey,
    pk: &ServerPublicKey,
    request: &CredentialRequest,
    b: &Scalar,
    t1: &Scalar,
    t2: &Scalar,
    u: &Element,
    enc_u_prime: &Element,
    x0_aux: &Element,
    x1_aux: &Element,
    x2_aux: &Element,
    h_aux: &Element,
    rng: &mut R,
) -> Result<Proof> {
    let st = credential_response_statement(
        pk,
        request.m1_enc,
        request.m2_enc,
        *u,
        *enc_u_prime,
        *x0_aux,
        *x1_aux,
        *x2_aux,
        *h_aux,
    );
    let session = proof_session(PROOF_NAME_CREDENTIAL_RESPONSE);
    let witness = [sk.x0, sk.x1, sk.x2, sk.x0_blinding, *b, *t1, *t2];
    NISchnorrProofShake128P256::new(&session, &st).prove(&witness, rng)
}

/// `VerifyCredentialResponseProof(pk, response, request)` (§5.2.2).
pub fn verify_credential_response_proof(
    pk: &ServerPublicKey,
    response: &CredentialResponse,
    request: &CredentialRequest,
) -> Result<()> {
    let st = credential_response_statement(
        pk,
        request.m1_enc,
        request.m2_enc,
        response.u,
        response.enc_u_prime,
        response.x0_aux,
        response.x1_aux,
        response.x2_aux,
        response.h_aux,
    );
    let session = proof_session(PROOF_NAME_CREDENTIAL_RESPONSE);
    NISchnorrProofShake128P256::new(&session, &st).verify(&response.response_proof)
}
