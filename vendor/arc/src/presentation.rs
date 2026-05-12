//! Credential presentation and verification.
//!
//! Spec: draft-ietf-privacypass-arc-crypto-01 §4.3, §5.3.
//!
//! The client proves possession of a valid credential, commits to a fresh
//! `nonce` in the range `[0, presentationLimit)`, and derives a deterministic
//! `tag = 1/(m1 + nonce) · generatorT` that lets the server detect replays
//! without learning `nonce` or `m1`.

use rand_core::{CryptoRng, RngCore};

use crate::ciphersuite::{
    proof_session, INFO_REQUEST_CONTEXT, INFO_TAG, NE, NS, PROOF_NAME_CREDENTIAL_PRESENTATION,
};
use crate::error::{Error, Result};
use crate::finalize::Credential;
use crate::group::{
    deserialize_element, deserialize_scalar, generator_g, generator_h, hash_to_group,
    hash_to_scalar, nonzero_random_scalar, scalar_inverse, serialize_element, serialize_scalar,
    Element, Scalar,
};
use crate::range_proof::{compute_bases, make_range_proof_helper, verify_range_proof_helper};
use crate::schnorr::{ElementVar, LinearRelation, NISchnorrProofShake128P256, Proof};
use crate::server::{ServerPrivateKey, ServerPublicKey};

// ---- State ------------------------------------------------------------------

/// Client-side state between successive `Present` calls (§4.3.1).
///
/// The `next_nonce` counter enforces the `presentation_limit`. The state is
/// destructive-update style: `Present` returns a *new* state with the counter
/// bumped, so a caller can persist it atomically.
#[derive(Clone, Debug)]
pub struct PresentationState {
    pub credential: Credential,
    pub presentation_context: Vec<u8>,
    pub next_nonce: u64,
    pub presentation_limit: u64,
}

/// `MakePresentationState(credential, presentationContext, presentationLimit)`.
pub fn make_presentation_state(
    credential: Credential,
    presentation_context: &[u8],
    presentation_limit: u64,
) -> PresentationState {
    PresentationState {
        credential,
        presentation_context: presentation_context.to_vec(),
        next_nonce: 0,
        presentation_limit,
    }
}

// ---- Wire format ------------------------------------------------------------

/// Non-interactive proof body carried inside a [`Presentation`].
///
/// Dimensions depend on `k = ceil(log2(presentation_limit))`:
///
/// ```text
/// D          : k   elements      (k * Ne  bytes)
/// challenge  : 1   scalar        (     Ns bytes)
/// responses  : (5 + 3*k) scalars ((5+3k)*Ns bytes)
/// ```
#[derive(Clone, Debug)]
pub struct PresentationProof {
    /// Range-proof bit commitments `D[0..k]`.
    pub d: Vec<Element>,
    /// Underlying Schnorr proof (challenge + responses).
    pub schnorr: Proof,
}

impl PresentationProof {
    /// `Npresentationproof = k*Ne + (6 + 3*k)*Ns`
    /// (challenge counts in the `+6`, not `+5`).
    pub fn size(k: usize) -> usize {
        k * NE + (6 + 3 * k) * NS
    }

    /// Number of response scalars (excludes the challenge).
    fn num_responses(k: usize) -> usize {
        5 + 3 * k
    }
}

/// Wire-format presentation (§4.3.2).
///
/// ```text
/// U, UPrimeCommit, m1Commit, tag, nonceCommit  : 5 * Ne
/// presentationProof                            : Npresentationproof
/// ```
#[derive(Clone, Debug)]
pub struct Presentation {
    pub u: Element,
    pub u_prime_commit: Element,
    pub m1_commit: Element,
    pub tag: Element,
    pub nonce_commit: Element,
    pub presentation_proof: PresentationProof,
}

impl Presentation {
    /// `Npresentation = 5 * Ne + Npresentationproof`.
    pub fn size(k: usize) -> usize {
        5 * NE + PresentationProof::size(k)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let k = self.presentation_proof.d.len();
        let mut out = Vec::with_capacity(Self::size(k));
        for e in [
            &self.u,
            &self.u_prime_commit,
            &self.m1_commit,
            &self.tag,
            &self.nonce_commit,
        ] {
            out.extend_from_slice(&serialize_element(e));
        }
        for di in &self.presentation_proof.d {
            out.extend_from_slice(&serialize_element(di));
        }
        out.extend_from_slice(&serialize_scalar(&self.presentation_proof.schnorr.challenge));
        for r in &self.presentation_proof.schnorr.responses {
            out.extend_from_slice(&serialize_scalar(r));
        }
        debug_assert_eq!(out.len(), Self::size(k));
        out
    }

    pub fn from_bytes(bytes: &[u8], presentation_limit: u64) -> Result<Self> {
        let k = compute_bases(presentation_limit).len();
        let expected = Self::size(k);
        if bytes.len() != expected {
            return Err(Error::InvalidLength { expected, got: bytes.len() });
        }
        let u = deserialize_element(&bytes[..NE])?;
        let u_prime_commit = deserialize_element(&bytes[NE..2 * NE])?;
        let m1_commit = deserialize_element(&bytes[2 * NE..3 * NE])?;
        let tag = deserialize_element(&bytes[3 * NE..4 * NE])?;
        let nonce_commit = deserialize_element(&bytes[4 * NE..5 * NE])?;
        let mut off = 5 * NE;
        let mut d = Vec::with_capacity(k);
        for _ in 0..k {
            d.push(deserialize_element(&bytes[off..off + NE])?);
            off += NE;
        }
        let challenge = deserialize_scalar(&bytes[off..off + NS])?;
        off += NS;
        let num_resp = PresentationProof::num_responses(k);
        let mut responses = Vec::with_capacity(num_resp);
        for _ in 0..num_resp {
            responses.push(deserialize_scalar(&bytes[off..off + NS])?);
            off += NS;
        }
        Ok(Presentation {
            u,
            u_prime_commit,
            m1_commit,
            tag,
            nonce_commit,
            presentation_proof: PresentationProof {
                d,
                schnorr: Proof { challenge, responses },
            },
        })
    }
}

// ---- Present (§4.3.2) -------------------------------------------------------

/// `Present(state, rng)` — produce the next unlinkable presentation.
///
/// Returns `(new_state, nonce, presentation)`. The `nonce` is also embedded
/// (committed, not plaintext) inside the returned `presentation`; it is
/// surfaced separately because callers frequently want to log it locally.
pub fn present<R: RngCore + CryptoRng>(
    state: &PresentationState,
    rng: &mut R,
) -> Result<(PresentationState, u64, Presentation)> {
    if state.next_nonce >= state.presentation_limit {
        return Err(Error::LimitExceeded);
    }
    let nonce = state.next_nonce;

    let a = nonzero_random_scalar(rng);
    let r = nonzero_random_scalar(rng);
    let z = nonzero_random_scalar(rng);
    let nonce_blinding = nonzero_random_scalar(rng);

    let g = generator_g();
    let h = generator_h();
    let nonce_scalar = Scalar::from(nonce);

    // Randomized credential and the blinded MAC.
    let cap_u = state.credential.u * a;
    let u_prime_commit = state.credential.u_prime * a + g * r;
    // m1Commit is a Pedersen commitment to m1 with the randomized U as base.
    let m1_commit = cap_u * state.credential.m1 + h * z;
    let nonce_commit = g * nonce_scalar + h * nonce_blinding;

    let generator_t = hash_to_group(&state.presentation_context, INFO_TAG.as_bytes());
    let tag_denom_inv = scalar_inverse(&(state.credential.m1 + nonce_scalar))?;
    let tag = generator_t * tag_denom_inv;

    // V is the auxiliary element used as target of presentation equation 2.
    // The prover computes V = z·X1 − r·G; the verifier reconstructs the
    // same element from the server's secret key (see verify_presentation_proof).
    let v = state.credential.x1 * z - g * r;

    let presentation_proof = make_presentation_proof(
        &cap_u,
        &u_prime_commit,
        &m1_commit,
        &tag,
        &generator_t,
        &state.credential,
        &v,
        &r,
        &z,
        nonce,
        &nonce_blinding,
        &nonce_commit,
        state.presentation_limit,
        rng,
    )?;

    let new_state = PresentationState {
        credential: state.credential.clone(),
        presentation_context: state.presentation_context.clone(),
        next_nonce: state.next_nonce + 1,
        presentation_limit: state.presentation_limit,
    };
    let presentation = Presentation {
        u: cap_u,
        u_prime_commit,
        m1_commit,
        tag,
        nonce_commit,
        presentation_proof,
    };
    Ok((new_state, nonce, presentation))
}

// ---- VerifyPresentation (§4.3.3) -------------------------------------------

/// `VerifyPresentation(sk, pk, requestContext, presentationContext, presentation, presentationLimit)`.
///
/// Returns the `tag` on success. The caller is responsible for storing it
/// in a per-`(requestContext, presentationContext)` double-spend set.
pub fn verify_presentation(
    sk: &ServerPrivateKey,
    pk: &ServerPublicKey,
    request_context: &[u8],
    presentation_context: &[u8],
    presentation: &Presentation,
    presentation_limit: u64,
) -> Result<Element> {
    verify_presentation_proof(
        sk,
        pk,
        request_context,
        presentation_context,
        presentation,
        presentation_limit,
    )?;
    Ok(presentation.tag)
}

// ---- Presentation proof (§5.3) ---------------------------------------------
//
// Base proof scalar witnesses (5) :
//   [m1, z, rNeg, nonce, nonceBlinding]
// where rNeg = -r so that equation 2 can be expressed as an all-positive
// linear combination (the NISchnorr compiler does not support subtraction
// directly; negation happens on the witness, not on the equation).
//
// Element variables (10, in allocation order):
//   [G, H, U, UPrimeCommit, m1Commit, V, X1, tag, generatorT, nonceCommit]
//
// Range-proof scalar witnesses (3*k):
//   all b's, then all s's, then all s2's (k each, in RangeWitness order).
//
// Base equations (4):
//     1.  m1Commit    = m1    · U            +  z     · generatorH
//     2.  V           = z     · X1           +  rNeg  · generatorG
//     3.  nonceCommit = nonce · generatorG   +  nonceBlinding · generatorH
//     4.  generatorT  = m1    · tag          +  nonce · tag
//
// Range equations (2*k): see range_proof.rs.
//
// Sum check (verified outside the Schnorr proof):
//     nonceCommit  == Σ_i  bases[i] · D[i]
//                where bases = ComputeBases(presentation_limit).
//
// **k = 1 special case** (presentation_limit == 2, draft §5.4.1): the range
// helper reuses `nonce_commit_var` for D[0] (see range_proof.rs for details).
// The wire format still emits D[0] unconditionally.
//
// Wire proof     : D[0..k] || challenge || responses
// Transcript lbl : "ARCV1-P256CredentialPresentation"

/// Bundle of element-variable handles that `make_presentation_proof` and
/// `verify_presentation_proof` need to hand off to the range-proof helper.
struct PresentationBaseHandles {
    gen_g_var: ElementVar,
    gen_h_var: ElementVar,
    nonce_commit_var: ElementVar,
}

/// Build the 5-scalar / 10-element linear relation and append the 4 base
/// equations. Shared by prover and verifier so the allocation and equation
/// insertion order (both Fiat-Shamir-affecting) live in exactly one place.
#[allow(clippy::too_many_arguments)]
fn presentation_base_statement(
    u: Element,
    u_prime_commit: Element,
    m1_commit: Element,
    v: Element,
    x1: Element,
    tag: Element,
    generator_t: Element,
    nonce_commit: Element,
) -> (LinearRelation, PresentationBaseHandles) {
    let mut st = LinearRelation::new();

    // 5 scalar vars: [m1, z, rNeg, nonce, nonceBlinding].
    let sv = st.allocate_scalars(5);
    let m1_var = sv[0];
    let z_var = sv[1];
    let r_neg_var = sv[2];
    let nonce_var = sv[3];
    let nonce_blinding_var = sv[4];

    // 10 element vars — order matches arc_proofs.sage exactly.
    let ev = st.allocate_elements(10);
    let gen_g_var = ev[0];
    let gen_h_var = ev[1];
    let u_var = ev[2];
    let _u_prime_commit_var = ev[3];
    let m1_commit_var = ev[4];
    let v_var = ev[5];
    let x1_var = ev[6];
    let tag_var = ev[7];
    let gen_t_var = ev[8];
    let nonce_commit_var = ev[9];

    st.set_elements(&[
        (gen_g_var, generator_g()),
        (gen_h_var, generator_h()),
        (u_var, u),
        (_u_prime_commit_var, u_prime_commit),
        (m1_commit_var, m1_commit),
        (v_var, v),
        (x1_var, x1),
        (tag_var, tag),
        (gen_t_var, generator_t),
        (nonce_commit_var, nonce_commit),
    ])
    .expect("variables were just allocated");

    // 1. m1Commit = m1·U + z·H
    st.append_equation(m1_commit_var, &[(m1_var, u_var), (z_var, gen_h_var)])
        .expect("vars allocated");
    // 2. V = z·X1 + rNeg·G
    st.append_equation(v_var, &[(z_var, x1_var), (r_neg_var, gen_g_var)])
        .expect("vars allocated");
    // 3. nonceCommit = nonce·G + nonceBlinding·H
    st.append_equation(
        nonce_commit_var,
        &[(nonce_var, gen_g_var), (nonce_blinding_var, gen_h_var)],
    )
    .expect("vars allocated");
    // 4. generatorT = m1·tag + nonce·tag  (pins down tag = (m1+nonce)^{-1}·genT)
    st.append_equation(gen_t_var, &[(m1_var, tag_var), (nonce_var, tag_var)])
        .expect("vars allocated");

    (
        st,
        PresentationBaseHandles { gen_g_var, gen_h_var, nonce_commit_var },
    )
}

/// `MakePresentationProof` (§5.3.1).
///
/// Builds the composed base + range statement, runs the Schnorr prover over
/// the concatenated witness `[m1, z, −r, nonce, nonceBlinding, b…, s…, s2…]`,
/// and returns the wire proof together with the range-proof `D[]`
/// commitments (which appear in the wire format but are not part of the
/// Schnorr challenge derivation beyond the Fiat-Shamir instance label).
#[allow(clippy::too_many_arguments)]
pub fn make_presentation_proof<R: RngCore + CryptoRng>(
    u: &Element,
    u_prime_commit: &Element,
    m1_commit: &Element,
    tag: &Element,
    generator_t: &Element,
    credential: &Credential,
    v: &Element,
    r: &Scalar,
    z: &Scalar,
    nonce: u64,
    nonce_blinding: &Scalar,
    nonce_commit: &Element,
    presentation_limit: u64,
    rng: &mut R,
) -> Result<PresentationProof> {
    let (mut st, handles) = presentation_base_statement(
        *u,
        *u_prime_commit,
        *m1_commit,
        *v,
        credential.x1,
        *tag,
        *generator_t,
        *nonce_commit,
    );

    let (d, range_witness, _range_vars) = make_range_proof_helper(
        &mut st,
        nonce,
        nonce_blinding,
        presentation_limit,
        handles.gen_g_var,
        handles.gen_h_var,
        *nonce_commit,
        handles.nonce_commit_var,
        rng,
    )?;

    // Base witness : [m1, z, rNeg, nonce, nonceBlinding]
    // rNeg = -r so that equation 2 (V = z·X1 + rNeg·G) is consistent with
    // the prover's V = z·X1 − r·G.
    let mut witness: Vec<Scalar> = Vec::with_capacity(5 + range_witness.b.len() * 3);
    witness.push(credential.m1);
    witness.push(*z);
    witness.push(-*r);
    witness.push(Scalar::from(nonce));
    witness.push(*nonce_blinding);
    witness.extend(range_witness.to_witness_vec());

    let session = proof_session(PROOF_NAME_CREDENTIAL_PRESENTATION);
    let schnorr = NISchnorrProofShake128P256::new(&session, &st).prove(&witness, rng)?;
    Ok(PresentationProof { d, schnorr })
}

/// `VerifyPresentationProof` (§5.3.2).
///
/// Reconstructs the auxiliary element `V` from the server's long-term secret
/// (`V = x0·U + x1·m1Commit + (x2·m2)·U − UPrimeCommit`, where
/// `m2 = HashToScalar(requestContext, "requestContext")`), rebuilds the same
/// statement as the prover, runs the Schnorr verifier, and performs the
/// range-proof linear sum check.
pub fn verify_presentation_proof(
    sk: &ServerPrivateKey,
    pk: &ServerPublicKey,
    request_context: &[u8],
    presentation_context: &[u8],
    presentation: &Presentation,
    presentation_limit: u64,
) -> Result<()> {
    let generator_t = hash_to_group(presentation_context, INFO_TAG.as_bytes());
    let m2 = hash_to_scalar(request_context, INFO_REQUEST_CONTEXT.as_bytes());

    // Reconstruct V from server secrets. Derivation (matching arc_proofs.sage):
    //   For a valid credential, U_prime_commit = a·(x0·u + x1·m1·u + x2·m2·u) + r·G
    //   Substituting m1·U = m1Commit − z·H (with U = a·u) gives
    //     U_prime_commit = x0·U + x1·(m1Commit − z·H) + x2·m2·U + r·G
    //                    = x0·U + x1·m1Commit − x1·z·H + x2·m2·U + r·G
    //   So  x1·z·H − r·G = x0·U + x1·m1Commit + x2·m2·U − U_prime_commit.
    //   And V = z·X1 − r·G = x1·z·H − r·G = (above).
    let v = presentation.u * sk.x0
        + presentation.m1_commit * sk.x1
        + presentation.u * (sk.x2 * m2)
        - presentation.u_prime_commit;

    let (mut st, handles) = presentation_base_statement(
        presentation.u,
        presentation.u_prime_commit,
        presentation.m1_commit,
        v,
        pk.x1,
        presentation.tag,
        generator_t,
        presentation.nonce_commit,
    );

    // Range proof: appends equations + returns sum-check validity.
    let range_ok = verify_range_proof_helper(
        &mut st,
        &presentation.presentation_proof.d,
        presentation.nonce_commit,
        presentation_limit,
        handles.gen_g_var,
        handles.gen_h_var,
        handles.nonce_commit_var,
    )?;
    if !range_ok {
        return Err(Error::Verify);
    }

    let session = proof_session(PROOF_NAME_CREDENTIAL_PRESENTATION);
    NISchnorrProofShake128P256::new(&session, &st)
        .verify(&presentation.presentation_proof.schnorr)
}
