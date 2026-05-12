//! Client-side credential finalization: decrypt `encUPrime` into `UPrime`
//! and package the result into a [`Credential`].
//!
//! Spec: draft-ietf-privacypass-arc-crypto-01 §4.2.3.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Result;
use crate::group::{Element, Scalar};
use crate::request::{ClientSecrets, CredentialRequest};
use crate::response::{verify_credential_response_proof, CredentialResponse};
use crate::server::ServerPublicKey;

/// A finalized credential. The secret `m1` stays with the client; the three
/// elements are revealed (in committed form) during each `Present` call.
///
/// `X1` is carried inside the credential because it appears in the
/// presentation proof (equation 2: `V = z·X1 − r·generatorG`).
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Credential {
    pub m1: Scalar,
    pub u: Element,
    pub u_prime: Element,
    pub x1: Element,
}

/// `FinalizeCredential(clientSecrets, serverPublicKey, request, response)`.
///
/// Steps (§4.2.3):
/// 1. `VerifyCredentialResponseProof(serverPublicKey, response, request)`.
/// 2. `UPrime = encUPrime − X0Aux − r1·X1Aux − r2·X2Aux`.
///    The `r·H` blinding terms cancel with the response's auxiliary
///    commitments: `encUPrime` carries a `b·(x1·r1 + x2·r2)·H` term from
///    the ElGamal-style encryption, and `X1Aux = b·x1·H`, `X2Aux = b·x2·H`,
///    so subtracting `r1·X1Aux + r2·X2Aux` exactly removes it. `X0Aux`
///    removes the `b·x0Blinding·H` term that `X0` contributed.
/// 3. Return `Credential { m1 = clientSecrets.m1, U, UPrime, X1 = pk.X1 }`.
pub fn finalize_credential(
    secrets: &ClientSecrets,
    pk: &ServerPublicKey,
    request: &CredentialRequest,
    response: &CredentialResponse,
) -> Result<Credential> {
    verify_credential_response_proof(pk, response, request)?;
    let u_prime = response.enc_u_prime
        - response.x0_aux
        - response.x1_aux * secrets.r1
        - response.x2_aux * secrets.r2;
    Ok(Credential {
        m1: secrets.m1,
        u: response.u,
        u_prime,
        x1: pk.x1,
    })
}
