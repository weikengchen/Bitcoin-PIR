//! Error types for PIR SDK.
//!
//! # Error taxonomy
//!
//! `PirError` has many specific variants, but for retry and UI decisions
//! callers usually only care about the **cause category**. The [`ErrorKind`]
//! enum provides exactly that categorical view:
//!
//! | `ErrorKind`                | What it means                                   | Recommended action                           |
//! |----------------------------|-------------------------------------------------|----------------------------------------------|
//! | `TransientNetwork`         | Timeout / connection drop / transient blip     | Retry with exponential backoff               |
//! | `SessionEvicted`           | Server lost our session (LRU, stale hint)       | Reconnect then retry once                    |
//! | `ProtocolSkew`             | Client/server version or feature mismatch       | Bail; caller must upgrade one side           |
//! | `MerkleVerificationFailed` | Merkle proof rejected at the batch level        | Bail; surface data as untrusted              |
//! | `ServerError`              | Server returned an error payload                | Bail (usually caller-side config bug)        |
//! | `ClientError`              | Not connected, bad input, invalid state         | Fix caller state, do not retry automatically |
//! | `DataError`                | Payload shape / encoding / merge failure        | Bail; surface to caller                      |
//! | `Other`                    | I/O error or internal bug                       | Surface to user, log                         |
//!
//! The three most common helpers (`is_transient_network`,
//! `is_session_lost`, `is_verification_failure`) are what you want inside
//! a retry loop. For anything more nuanced, match on [`PirError::kind`]
//! directly.
//!
//! # Per-query Merkle failures vs batch-level Merkle failures
//!
//! The native clients **do not** raise `MerkleVerificationFailed` when a
//! single query's Merkle proof is rejected — instead they coerce that
//! query to [`QueryResult::merkle_failed()`](crate::types::QueryResult::merkle_failed)
//! so the caller sees "this specific result is untrusted" without
//! aborting the rest of the batch. `MerkleVerificationFailed` is for
//! pipeline-level failures (e.g. the server refuses to serve tree-tops
//! despite advertising `has_bucket_merkle = true`).

use std::io;
use thiserror::Error;

/// Result type alias for PIR operations.
pub type PirResult<T> = Result<T, PirError>;

/// Categorical classification of an error's cause.
///
/// Obtained via [`PirError::kind`]. Callers that need finer-grained
/// detail should match on `PirError` directly — `ErrorKind` is meant for
/// retry-strategy decisions and UI taxonomy, not for precise recovery.
///
/// See the module-level docs for the mapping table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Network transport failure that may succeed on retry (timeout,
    /// connection drop, DNS blip). Retry with exponential backoff.
    TransientNetwork,
    /// Server lost our session (OnionPIR LRU eviction after in-session
    /// retry failed; Harmony hint session expired; etc.). Retry
    /// requires a reconnect that re-establishes per-session state.
    SessionEvicted,
    /// Client and server disagree on protocol version or feature
    /// support. Not retryable — one side must be upgraded.
    ProtocolSkew,
    /// Merkle verification failed at the pipeline level (not
    /// per-query). The server is either serving bad data or proofs
    /// genuinely don't match. Not retryable.
    MerkleVerificationFailed,
    /// Server returned an error payload (database not found
    /// server-side, unsupported query, etc.). Not retryable.
    ServerError,
    /// Client-side misuse: not connected, invalid state, missing
    /// config, bad input. Not retryable without a caller-side change.
    ClientError,
    /// Data parsing, encoding, or merge error. Not retryable — the
    /// payload shape is wrong.
    DataError,
    /// I/O error, `from_str`, or unclassified internal error.
    Other,
}

/// Unified error type for all PIR operations.
#[derive(Error, Debug)]
pub enum PirError {
    // ─── Connection errors ──────────────────────────────────────────────────

    /// Failed to connect to a PIR server.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection was closed unexpectedly.
    #[error("connection closed: {0}")]
    ConnectionClosed(String),

    /// Timeout waiting for server response.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Not connected to server.
    #[error("not connected")]
    NotConnected,

    /// Transient failure surfaced from a background path (retry layer,
    /// keep-alive, etc.). Classified as [`ErrorKind::TransientNetwork`];
    /// prefer this over `ConnectionClosed` / `Timeout` when the cause
    /// is a general "transient blip" rather than a specific wire event.
    ///
    /// The field is named `origin` (not `source`) so that
    /// `#[derive(thiserror::Error)]` does not try to treat it as a
    /// [`std::error::Error`] source chain — `&'static str` does not
    /// implement `Error`.
    #[error("transient ({origin}): {context}")]
    Transient {
        /// Short label for the origin of the transient failure
        /// (e.g. `"reconnect"`, `"keepalive"`, `"retry"`).
        origin: &'static str,
        /// Human-readable detail.
        context: String,
    },

    // ─── Protocol errors ────────────────────────────────────────────────────

    /// Invalid protocol message received. Use for wire-format violations
    /// within the agreed protocol — if the mismatch is a version or
    /// feature gap, prefer [`PirError::ProtocolSkew`].
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Server returned an error response. For LRU-eviction specifically,
    /// prefer [`PirError::SessionEvicted`] so callers can reconnect
    /// cleanly.
    #[error("server error: {0}")]
    ServerError(String),

    /// Unexpected response variant.
    #[error("unexpected response: expected {expected}, got {actual}")]
    UnexpectedResponse {
        /// Human description of the expected variant
        /// (e.g. `"RESP_BUCKET_MERKLE_TREE_TOPS (0x34)"`).
        expected: &'static str,
        /// String form of what was actually received.
        actual: String,
    },

    /// Client and server disagree on protocol version or feature
    /// support. Distinct from [`PirError::Protocol`], which is for
    /// malformed wire data *within* the agreed protocol. `ProtocolSkew`
    /// means the caller cannot recover without a software upgrade.
    #[error("protocol skew: expected {expected}, got {actual}")]
    ProtocolSkew {
        /// Short description of the expected protocol feature or
        /// version (e.g. `"bucket_merkle support"`, `"catalog v2"`).
        expected: String,
        /// Short description of what the server actually advertised or
        /// returned.
        actual: String,
    },

    /// Server session state was lost (e.g. OnionPIR LRU eviction, stale
    /// Harmony hint session) and the internal in-session retry also
    /// failed. Callers should reconnect before retrying; the dedicated
    /// variant (instead of `ServerError`) lets retry logic target this
    /// cause specifically.
    #[error("session evicted: {0}")]
    SessionEvicted(String),

    // ─── Database errors ────────────────────────────────────────────────────

    /// Database not found.
    #[error("database not found: db_id={0}")]
    DatabaseNotFound(u8),

    /// Invalid database catalog.
    #[error("invalid catalog: {0}")]
    InvalidCatalog(String),

    /// No valid sync path found.
    #[error("no sync path: {0}")]
    NoSyncPath(String),

    // ─── Query errors ───────────────────────────────────────────────────────

    /// Invalid script hash.
    #[error("invalid script hash: {0}")]
    InvalidScriptHash(String),

    /// Query failed.
    #[error("query failed: {0}")]
    QueryFailed(String),

    /// Generic verification failure (legacy). Prefer the more specific
    /// [`PirError::MerkleVerificationFailed`] for Merkle-proof failures
    /// — it's the variant that pipeline-level retry logic expects to
    /// match on.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// Merkle verification failed at the batch/pipeline level.
    ///
    /// Per-query Merkle failures are coerced to
    /// [`crate::types::QueryResult::merkle_failed`] and do **not**
    /// raise this error. This variant fires only when the pipeline
    /// itself fails — e.g. the server advertised `has_bucket_merkle =
    /// true` in the catalog but its tree-tops response came back as
    /// `RESP_ERROR`, or the caller explicitly asked for a batch-level
    /// verification verdict and one item rejected.
    #[error("merkle verification failed: {0}")]
    MerkleVerificationFailed(String),

    // ─── State errors ───────────────────────────────────────────────────────

    /// Client is in invalid state for this operation.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Backend-specific state error (e.g., HarmonyPIR hints not computed).
    #[error("backend state error: {0}")]
    BackendState(String),

    // ─── Configuration errors ───────────────────────────────────────────────

    /// Invalid configuration.
    #[error("configuration error: {0}")]
    Config(String),

    /// Missing required server URL.
    #[error("missing server: {0}")]
    MissingServer(String),

    // ─── I/O errors ─────────────────────────────────────────────────────────

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    // ─── Codec errors ───────────────────────────────────────────────────────

    /// Failed to decode data.
    #[error("decode error: {0}")]
    Decode(String),

    /// Failed to encode data.
    #[error("encode error: {0}")]
    Encode(String),

    // ─── Delta merge errors ─────────────────────────────────────────────────

    /// Failed to merge delta into snapshot.
    #[error("merge error: {0}")]
    MergeError(String),

    // ─── Internal errors ────────────────────────────────────────────────────

    /// Internal error (bug).
    #[error("internal error: {0}")]
    Internal(String),
}

impl PirError {
    /// Classify this error into a categorical [`ErrorKind`].
    ///
    /// This is the primary entry point for retry logic and UI decisions
    /// — see the module-level docs for the full mapping table.
    pub fn kind(&self) -> ErrorKind {
        match self {
            // Transport / transient
            PirError::Timeout(_)
            | PirError::ConnectionClosed(_)
            | PirError::ConnectionFailed(_)
            | PirError::Transient { .. } => ErrorKind::TransientNetwork,

            // Session loss
            PirError::SessionEvicted(_) => ErrorKind::SessionEvicted,

            // Version / feature skew
            PirError::ProtocolSkew { .. } | PirError::UnexpectedResponse { .. } => {
                ErrorKind::ProtocolSkew
            }

            // Merkle verification
            PirError::MerkleVerificationFailed(_) | PirError::VerificationFailed(_) => {
                ErrorKind::MerkleVerificationFailed
            }

            // Server-side generic errors (non-eviction)
            PirError::Protocol(_) | PirError::ServerError(_) => ErrorKind::ServerError,

            // Client-side misuse
            PirError::NotConnected
            | PirError::InvalidState(_)
            | PirError::BackendState(_)
            | PirError::Config(_)
            | PirError::MissingServer(_)
            | PirError::InvalidScriptHash(_) => ErrorKind::ClientError,

            // Data/payload errors
            PirError::DatabaseNotFound(_)
            | PirError::InvalidCatalog(_)
            | PirError::NoSyncPath(_)
            | PirError::QueryFailed(_)
            | PirError::Decode(_)
            | PirError::Encode(_)
            | PirError::MergeError(_) => ErrorKind::DataError,

            // Everything else
            PirError::Io(_) | PirError::Internal(_) => ErrorKind::Other,
        }
    }

    /// Returns true if this is a connection-related error (transport
    /// failure, timeout, or not-connected). Retained for backwards
    /// compatibility with [`crate::error::PirError`] callers in
    /// `pir-sdk-client`'s reconnect loop.
    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            PirError::ConnectionFailed(_)
                | PirError::ConnectionClosed(_)
                | PirError::Timeout(_)
                | PirError::NotConnected
                | PirError::Transient { .. }
        )
    }

    /// Returns true if this is a protocol-related error (malformed
    /// wire data, server-error frame, unexpected response, or
    /// protocol skew).
    pub fn is_protocol_error(&self) -> bool {
        matches!(
            self,
            PirError::Protocol(_)
                | PirError::ServerError(_)
                | PirError::UnexpectedResponse { .. }
                | PirError::ProtocolSkew { .. }
        )
    }

    /// Returns true if retrying the same operation (possibly after
    /// transparent reconnect) might succeed. Covers both
    /// [`ErrorKind::TransientNetwork`] and [`ErrorKind::SessionEvicted`]
    /// — the latter requires reconnecting before the retry, which the
    /// caller is expected to handle (e.g. via
    /// `WsConnection::reconnect` + re-registration).
    ///
    /// Callers that want to distinguish "retry in place" from "retry
    /// after reconnect" should use [`is_transient_network`] and
    /// [`is_session_lost`] instead.
    ///
    /// [`is_transient_network`]: PirError::is_transient_network
    /// [`is_session_lost`]: PirError::is_session_lost
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            ErrorKind::TransientNetwork | ErrorKind::SessionEvicted,
        )
    }

    /// Returns true if this is a transient network failure that should
    /// be retried with exponential backoff, without needing to
    /// reconnect first.
    pub fn is_transient_network(&self) -> bool {
        matches!(self.kind(), ErrorKind::TransientNetwork)
    }

    /// Returns true if the server lost our session (LRU eviction,
    /// expired hint session) — the caller should reconnect and retry.
    /// Also true for [`ErrorKind::TransientNetwork`] since a dropped
    /// connection also destroys session state; callers that want to
    /// handle those two cases differently should use [`kind`] directly.
    ///
    /// [`kind`]: PirError::kind
    pub fn is_session_lost(&self) -> bool {
        matches!(
            self.kind(),
            ErrorKind::SessionEvicted | ErrorKind::TransientNetwork,
        )
    }

    /// Returns true if Merkle verification failed at the pipeline
    /// level. Per-query Merkle failures are **not** surfaced this way
    /// — they coerce the result to
    /// [`QueryResult::merkle_failed`](crate::types::QueryResult::merkle_failed)
    /// so the rest of the batch can succeed.
    pub fn is_verification_failure(&self) -> bool {
        matches!(self.kind(), ErrorKind::MerkleVerificationFailed)
    }

    /// Returns true if this is a protocol-version or feature-support
    /// mismatch. Not retryable — one side must be upgraded.
    pub fn is_protocol_skew(&self) -> bool {
        matches!(self.kind(), ErrorKind::ProtocolSkew)
    }
}

// ─── Conversion helpers ─────────────────────────────────────────────────────

impl From<&str> for PirError {
    fn from(s: &str) -> Self {
        PirError::Internal(s.to_string())
    }
}

impl From<String> for PirError {
    fn from(s: String) -> Self {
        PirError::Internal(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_classifies_transient_network() {
        assert_eq!(
            PirError::Timeout("slow".into()).kind(),
            ErrorKind::TransientNetwork
        );
        assert_eq!(
            PirError::ConnectionClosed("eof".into()).kind(),
            ErrorKind::TransientNetwork
        );
        assert_eq!(
            PirError::ConnectionFailed("dns".into()).kind(),
            ErrorKind::TransientNetwork
        );
        assert_eq!(
            PirError::Transient {
                origin: "keepalive",
                context: "blip".into(),
            }
            .kind(),
            ErrorKind::TransientNetwork
        );
    }

    #[test]
    fn kind_classifies_session_evicted() {
        assert_eq!(
            PirError::SessionEvicted("LRU".into()).kind(),
            ErrorKind::SessionEvicted
        );
    }

    #[test]
    fn kind_classifies_protocol_skew() {
        assert_eq!(
            PirError::ProtocolSkew {
                expected: "catalog v2".into(),
                actual: "catalog v1".into(),
            }
            .kind(),
            ErrorKind::ProtocolSkew
        );
        assert_eq!(
            PirError::UnexpectedResponse {
                expected: "RESP_X",
                actual: "0xff".into(),
            }
            .kind(),
            ErrorKind::ProtocolSkew
        );
    }

    #[test]
    fn kind_classifies_merkle_verification() {
        assert_eq!(
            PirError::MerkleVerificationFailed("tampered".into()).kind(),
            ErrorKind::MerkleVerificationFailed
        );
        // Legacy alias still classifies correctly.
        assert_eq!(
            PirError::VerificationFailed("legacy".into()).kind(),
            ErrorKind::MerkleVerificationFailed
        );
    }

    #[test]
    fn kind_classifies_server_errors() {
        assert_eq!(
            PirError::Protocol("bad frame".into()).kind(),
            ErrorKind::ServerError
        );
        assert_eq!(
            PirError::ServerError("db not found".into()).kind(),
            ErrorKind::ServerError
        );
    }

    #[test]
    fn kind_classifies_client_errors() {
        assert_eq!(PirError::NotConnected.kind(), ErrorKind::ClientError);
        assert_eq!(
            PirError::InvalidState("x".into()).kind(),
            ErrorKind::ClientError
        );
        assert_eq!(
            PirError::BackendState("hints".into()).kind(),
            ErrorKind::ClientError
        );
        assert_eq!(
            PirError::Config("bad".into()).kind(),
            ErrorKind::ClientError
        );
        assert_eq!(
            PirError::MissingServer("hint".into()).kind(),
            ErrorKind::ClientError
        );
        assert_eq!(
            PirError::InvalidScriptHash("short".into()).kind(),
            ErrorKind::ClientError
        );
    }

    #[test]
    fn kind_classifies_data_errors() {
        assert_eq!(PirError::DatabaseNotFound(7).kind(), ErrorKind::DataError);
        assert_eq!(
            PirError::InvalidCatalog("bad".into()).kind(),
            ErrorKind::DataError
        );
        assert_eq!(
            PirError::NoSyncPath("gap".into()).kind(),
            ErrorKind::DataError
        );
        assert_eq!(
            PirError::QueryFailed("boom".into()).kind(),
            ErrorKind::DataError
        );
        assert_eq!(
            PirError::Decode("short".into()).kind(),
            ErrorKind::DataError
        );
        assert_eq!(
            PirError::Encode("huh".into()).kind(),
            ErrorKind::DataError
        );
        assert_eq!(
            PirError::MergeError("conflict".into()).kind(),
            ErrorKind::DataError
        );
    }

    #[test]
    fn kind_classifies_other() {
        let io_err = io::Error::new(io::ErrorKind::Other, "oops");
        assert_eq!(PirError::Io(io_err).kind(), ErrorKind::Other);
        assert_eq!(
            PirError::Internal("bug".into()).kind(),
            ErrorKind::Other
        );
    }

    #[test]
    fn is_transient_network_matches_kind() {
        assert!(PirError::Timeout("t".into()).is_transient_network());
        assert!(PirError::ConnectionClosed("c".into()).is_transient_network());
        assert!(PirError::ConnectionFailed("c".into()).is_transient_network());
        assert!(PirError::Transient {
            origin: "x",
            context: "y".into(),
        }
        .is_transient_network());
        assert!(!PirError::SessionEvicted("e".into()).is_transient_network());
        assert!(!PirError::NotConnected.is_transient_network());
    }

    #[test]
    fn is_session_lost_covers_transient_and_evicted() {
        assert!(PirError::Timeout("t".into()).is_session_lost());
        assert!(PirError::ConnectionClosed("c".into()).is_session_lost());
        assert!(PirError::SessionEvicted("e".into()).is_session_lost());
        // Not session-lost:
        assert!(!PirError::NotConnected.is_session_lost());
        assert!(!PirError::Protocol("x".into()).is_session_lost());
        assert!(!PirError::MerkleVerificationFailed("m".into()).is_session_lost());
    }

    #[test]
    fn is_verification_failure_matches_merkle_variants() {
        assert!(PirError::MerkleVerificationFailed("m".into()).is_verification_failure());
        assert!(PirError::VerificationFailed("legacy".into()).is_verification_failure());
        assert!(!PirError::ServerError("s".into()).is_verification_failure());
        assert!(!PirError::Timeout("t".into()).is_verification_failure());
    }

    #[test]
    fn is_protocol_skew_matches_skew_variants() {
        assert!(PirError::ProtocolSkew {
            expected: "a".into(),
            actual: "b".into(),
        }
        .is_protocol_skew());
        assert!(PirError::UnexpectedResponse {
            expected: "x",
            actual: "y".into(),
        }
        .is_protocol_skew());
        assert!(!PirError::Protocol("p".into()).is_protocol_skew());
        assert!(!PirError::ServerError("s".into()).is_protocol_skew());
    }

    #[test]
    fn is_retryable_covers_transient_and_session_evicted() {
        assert!(PirError::Timeout("t".into()).is_retryable());
        assert!(PirError::ConnectionClosed("c".into()).is_retryable());
        assert!(PirError::ConnectionFailed("f".into()).is_retryable());
        assert!(PirError::Transient {
            origin: "r",
            context: "b".into()
        }
        .is_retryable());
        assert!(PirError::SessionEvicted("e".into()).is_retryable());
        // Non-retryable:
        assert!(!PirError::NotConnected.is_retryable());
        assert!(!PirError::Protocol("p".into()).is_retryable());
        assert!(!PirError::ServerError("s".into()).is_retryable());
        assert!(!PirError::MerkleVerificationFailed("m".into()).is_retryable());
        assert!(!PirError::ProtocolSkew {
            expected: "a".into(),
            actual: "b".into()
        }
        .is_retryable());
        assert!(!PirError::InvalidState("s".into()).is_retryable());
    }

    #[test]
    fn is_connection_error_back_compat() {
        // Original behaviour: Timeout / ConnectionClosed / ConnectionFailed / NotConnected.
        assert!(PirError::Timeout("t".into()).is_connection_error());
        assert!(PirError::ConnectionClosed("c".into()).is_connection_error());
        assert!(PirError::ConnectionFailed("f".into()).is_connection_error());
        assert!(PirError::NotConnected.is_connection_error());
        // New: Transient also counts as a connection error.
        assert!(PirError::Transient {
            origin: "r",
            context: "b".into(),
        }
        .is_connection_error());
        // Non-connection errors still aren't.
        assert!(!PirError::Protocol("p".into()).is_connection_error());
        assert!(!PirError::SessionEvicted("e".into()).is_connection_error());
    }

    #[test]
    fn is_protocol_error_covers_skew_and_unexpected() {
        assert!(PirError::Protocol("p".into()).is_protocol_error());
        assert!(PirError::ServerError("s".into()).is_protocol_error());
        assert!(PirError::UnexpectedResponse {
            expected: "x",
            actual: "y".into(),
        }
        .is_protocol_error());
        assert!(PirError::ProtocolSkew {
            expected: "a".into(),
            actual: "b".into(),
        }
        .is_protocol_error());
        // Non-protocol errors.
        assert!(!PirError::Timeout("t".into()).is_protocol_error());
        assert!(!PirError::SessionEvicted("e".into()).is_protocol_error());
    }

    #[test]
    fn error_kind_is_copy() {
        let k = ErrorKind::SessionEvicted;
        let k2 = k;
        assert_eq!(k, k2);
    }

    #[test]
    fn new_variants_format_properly() {
        let e = PirError::Transient {
            origin: "reconnect",
            context: "peer reset".into(),
        };
        assert_eq!(e.to_string(), "transient (reconnect): peer reset");

        let e = PirError::SessionEvicted("LRU".into());
        assert_eq!(e.to_string(), "session evicted: LRU");

        let e = PirError::MerkleVerificationFailed("tampered".into());
        assert_eq!(e.to_string(), "merkle verification failed: tampered");

        let e = PirError::ProtocolSkew {
            expected: "v2".into(),
            actual: "v1".into(),
        };
        assert_eq!(e.to_string(), "protocol skew: expected v2, got v1");
    }
}
