//! ARCV1-P256 ciphersuite constants.
//!
//! Spec: draft-ietf-privacypass-arc-crypto-01, Section 6.1.

/// Ciphersuite identifier used in wire formats that need to disambiguate.
pub const CIPHERSUITE_ID: &str = "P256";

/// Context string prepended to every domain-separation tag.
pub const CONTEXT_STRING: &str = "ARCV1-P256";

/// Serialized element length in bytes (compressed SEC1).
pub const NE: usize = 33;

/// Serialized scalar length in bytes (big-endian).
pub const NS: usize = 32;

// ---------- Domain-separation tag prefixes ----------
//
// Per Section 6.1:
//   HashToGroup DST  = "HashToGroup-"  || CONTEXT_STRING || info
//   HashToScalar DST = "HashToScalar-" || CONTEXT_STRING || info
//
// The `info` string varies per call site and is passed by the caller.

pub const HASH_TO_GROUP_PREFIX: &str = "HashToGroup-";
pub const HASH_TO_SCALAR_PREFIX: &str = "HashToScalar-";

// ---------- Per-call-site `info` strings ----------
//
// These strings appear verbatim throughout draft-01. Centralizing them here
// lets the higher-level modules refer to named constants rather than string
// literals that are easy to typo.

/// Info for `generatorH = HashToGroup(SerializeElement(G.Generator()), "generatorH")`.
pub const INFO_GENERATOR_H: &str = "generatorH";

/// Info for the per-presentation tag generator
/// `generatorT = HashToGroup(presentationContext, "Tag")`.
pub const INFO_TAG: &str = "Tag";

/// `info` for `m2 = HashToScalar(requestContext, "requestContext")` (§4.2.1).
pub const INFO_REQUEST_CONTEXT: &str = "requestContext";

// ---------- Schnorr session strings (per-proof) ----------
//
// The WG PoC (`arc_proofs.sage`) constructs `session = context_string || name`
// with NO separator:
//   session_id = b"ARCV1-P256" + b"CredentialRequest"       (27 bytes)
//   session_id = b"ARCV1-P256" + b"CredentialResponse"      (28 bytes)
//   session_id = b"ARCV1-P256" + b"CredentialPresentation"  (32 bytes)
//
// These are the `session` bytes passed into `NISchnorrProofShake128P256::new`.
// They are absorbed into the main sponge as
//   I2OSP(len(session), 4) || session
// per pre-`41b316a348f9` SIGMA `codec.init` (the format the WG ARC test
// vectors were generated against). See `schnorr.rs` for the full layout.

pub const PROOF_NAME_CREDENTIAL_REQUEST: &str = "CredentialRequest";
pub const PROOF_NAME_CREDENTIAL_RESPONSE: &str = "CredentialResponse";
pub const PROOF_NAME_CREDENTIAL_PRESENTATION: &str = "CredentialPresentation";

/// Concatenate `CONTEXT_STRING || name` to build the `session` bytes that
/// identify a particular ARC proof instance to the Schnorr compiler.
pub fn proof_session(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(CONTEXT_STRING.len() + name.len());
    out.extend_from_slice(CONTEXT_STRING.as_bytes());
    out.extend_from_slice(name.as_bytes());
    out
}

// ---------- Schnorr / SIGMA sponge constants ----------
//
// Fetched from the SIGMA protocols PoC (`mmaker/draft-irtf-cfrg-sigma-protocols`
// submodule under `ietf-wg-privacypass/draft-arc/poc/sigma/`). These two
// strings seed the duplex-sponge IVs used by `NISchnorrProofShake128P256`.

/// Identifier absorbed as the 64-byte IV of the main Fiat-Shamir sponge.
/// Must be NUL-padded to 64 bytes before being fed into SHAKE128's first block.
/// Raw value: `"sigma-proofs_Shake128_P256"`.
pub const SCHNORR_PROTOCOL_ID_RAW: &[u8] = b"sigma-proofs_Shake128_P256";

/// Build the full DST for `HashToGroup` from a per-call-site `info` string.
///
/// Returned bytes: `"HashToGroup-" || "ARCV1-P256" || info`.
pub fn hash_to_group_dst(info: &[u8]) -> Vec<u8> {
    let mut dst = Vec::with_capacity(HASH_TO_GROUP_PREFIX.len() + CONTEXT_STRING.len() + info.len());
    dst.extend_from_slice(HASH_TO_GROUP_PREFIX.as_bytes());
    dst.extend_from_slice(CONTEXT_STRING.as_bytes());
    dst.extend_from_slice(info);
    dst
}

/// Build the full DST for `HashToScalar` from a per-call-site `info` string.
///
/// Returned bytes: `"HashToScalar-" || "ARCV1-P256" || info`.
pub fn hash_to_scalar_dst(info: &[u8]) -> Vec<u8> {
    let mut dst =
        Vec::with_capacity(HASH_TO_SCALAR_PREFIX.len() + CONTEXT_STRING.len() + info.len());
    dst.extend_from_slice(HASH_TO_SCALAR_PREFIX.as_bytes());
    dst.extend_from_slice(CONTEXT_STRING.as_bytes());
    dst.extend_from_slice(info);
    dst
}
