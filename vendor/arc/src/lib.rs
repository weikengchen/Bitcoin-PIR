//! Anonymous Rate-limited Credentials (ARC) over P-256.
//!
//! Implementation of `draft-ietf-privacypass-arc-crypto-01`, ciphersuite
//! `ARCV1-P256` (§6.1 of the draft).
//!
//! All wire-format outputs are byte-exact against the WG PoC
//! `allVectors.json` (staged locally at `test-vectors-draft-01.json`); the
//! `tests/test_vectors.rs` harness asserts this for every element and every
//! Schnorr proof response.
//!
//! # Reference implementations
//!
//! - **Authoritative PoC:** `ietf-wg-privacypass/draft-arc/poc` (Sage) —
//!   matches draft-01 byte-for-byte; `allVectors.json` in that repo is the
//!   canonical test vector file.
//! - **Apple swift-crypto (`Sources/CryptoExtras/{ARC,ZKPs}/`)** — tracks an
//!   earlier ARC revision (`draft-yun-cfrg-arc-00`). Useful as a reference
//!   for the codec, variable-allocation style, and constraint-equation
//!   ordering, but **diverges from draft-01** in several places:
//!     * **Schnorr challenge**: Apple uses SHA-256 + `expand_message_xmd`
//!       directly over a self-describing transcript; draft-01 uses a
//!       SHAKE128 duplex sponge seeded with the SIGMA protocol IV
//!       (`sigma-proofs_Shake128_P256`). See [`schnorr`] for the exact layout.
//!     * **Response sign**: Apple emits `r = k − c · w` (subtractive); the
//!       SIGMA reference and draft-01 both use `r = k + c · w`
//!       (additive). The verifier reconstruction changes accordingly to
//!       `T = Σ r · B − c · Y`.
//!     * **Range proof**: Apple has none — nonce bound is enforced by
//!       loop subtraction on the server. Draft-01 has a per-bit Pedersen
//!       range proof (§5.4) composed into the presentation Schnorr proof.
//!     * **Per-proof Fiat-Shamir labels**: Apple doubles the domain string
//!       (`"ARCV1-P256ARCV1-P256CredentialRequest"`), almost certainly a
//!       bug; draft-01 / the WG PoC pass the label through the helper
//!       session-ID sponge exactly once.
//!     * **Test vectors**: Apple's `ARCTestVectors.json` uses a different
//!       seed and a different transcript, so outputs do not match even
//!       when the math is equivalent.
//!       Do **not** rely on Apple's vectors to validate a draft-01 port.
//!
//! # Protocol layers (draft §4)
//!
//! | Layer          | Module             | Key operations                                          |
//! |----------------|--------------------|---------------------------------------------------------|
//! | Ciphersuite    | [`ciphersuite`]    | Constants, DST construction                             |
//! | Group wrapper  | [`group`]          | `HashToGroup`, `HashToScalar`, `Serialize{Element,Scalar}` |
//! | Schnorr        | [`schnorr`]        | `LinearRelation`, `NISchnorrProofShake128P256`          |
//! | Server keys    | [`server`]         | `SetupServer`, `ServerPrivateKey`, `ServerPublicKey`    |
//! | Issuance       | [`request`], [`response`], [`finalize`] | `CreateCredentialRequest`, `CreateCredentialResponse`, `FinalizeCredential` |
//! | Presentation   | [`presentation`]   | `MakePresentationState`, `Present`, `VerifyPresentation` |
//! | Range proof    | [`range_proof`]    | `ComputeBases`, `MakeRangeProofHelper`, `VerifyRangeProofHelper` |

#![forbid(unsafe_code)]

pub mod ciphersuite;
pub mod error;
pub mod finalize;
pub mod group;
pub mod presentation;
pub mod range_proof;
pub mod request;
pub mod response;
pub mod schnorr;
pub mod server;

// ---- Convenience re-exports at the crate root -----------------------------
//
// Callers of the public protocol API shouldn't need to care about the
// internal module structure; they use the crate root as a flat namespace
// that mirrors draft-01's data-type vocabulary.

pub use error::{Error, Result};
pub use finalize::{finalize_credential, Credential};
pub use group::{Element, Scalar};
pub use presentation::{
    make_presentation_state, present, verify_presentation, Presentation, PresentationProof,
    PresentationState,
};
pub use request::{create_credential_request, ClientSecrets, CredentialRequest};
pub use response::{create_credential_response, CredentialResponse};
pub use server::{setup_server, ServerPrivateKey, ServerPublicKey};
