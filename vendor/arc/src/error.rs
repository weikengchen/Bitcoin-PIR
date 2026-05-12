//! Error types for the ARC protocol.
//!
//! Spec references:
//! - `VerifyError` — raised when proof verification fails
//!   (see [draft-ietf-privacypass-arc-crypto-01] Sections 4.2.2, 4.2.3, 4.3.3).
//! - `LimitExceededError` — raised when `Present` is called more than
//!   `presentationLimit` times on a single credential (Section 4.3.2).
//! - `DeserializeError` — raised when byte inputs fail length or range checks
//!   (Section 6.1, `DeserializeElement` / `DeserializeScalar`).

use core::fmt;

/// All public-API errors produced by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A zero-knowledge proof or MAC check did not verify.
    Verify,
    /// A `Present` call would exceed `presentationLimit` for this credential.
    LimitExceeded,
    /// Byte input had the wrong length.
    InvalidLength { expected: usize, got: usize },
    /// Byte input encoded a value outside the permitted range
    /// (e.g. the identity point, or a scalar ≥ group order).
    InvalidEncoding,
    /// A scalar was zero where a nonzero value was required.
    ZeroScalar,
    /// A linear-relation equation referenced a variable that was not allocated.
    UnknownVariable,
    /// A Schnorr proof was shorter or longer than the statement expects.
    MalformedProof,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Verify => f.write_str("ARC proof or MAC verification failed"),
            Error::LimitExceeded => f.write_str("presentation limit exceeded"),
            Error::InvalidLength { expected, got } => {
                write!(f, "invalid length: expected {expected}, got {got}")
            }
            Error::InvalidEncoding => f.write_str("invalid element or scalar encoding"),
            Error::ZeroScalar => f.write_str("scalar was zero"),
            Error::UnknownVariable => f.write_str("unknown variable in linear relation"),
            Error::MalformedProof => f.write_str("malformed Schnorr proof"),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;
