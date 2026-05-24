//! Client-side REQ_ANNOUNCE caller — fetches the operator-signed
//! identity bundle from a connected server.
//!
//! ## What this does
//!
//! - Sends REQ_ANNOUNCE (opcode 0x07, empty body) over any
//!   [`PirTransport`].
//! - Decodes RESP_ANNOUNCE → a `pir_identity::AnnouncementBundle`.
//! - Runs the [chain check](pir_identity::AnnouncementBundle::verify_chain):
//!   the `ChannelManifest`'s signature must verify against the
//!   `IdentityCert`'s `identity_pubkey`, and the `server_id` /
//!   `identity_pubkey` cross-references must match.
//!
//! ## What this does NOT do
//!
//! - **Verify the IdentityCert against a pinned operator pubkey.**
//!   The publishing mechanism for the operator pubkey is being
//!   designed (eventually Nostr). Until pinning lands, the
//!   `cert.operator_pubkey` is just what the server claims; clients
//!   must NOT rely on it for trust. Callers that want full
//!   authentication should pass an `operator_pubkey` to
//!   [`announce_with_pinned_operator`] once the publishing path is in
//!   place — that variant runs the missing check.
//! - **Know the expected channel key on its own.** This crate doesn't
//!   track handshake state, so the caller must supply the X25519 key
//!   the channel actually handshook against (the attested
//!   `AttestVerification::response.server_static_pub`). Given that key,
//!   [`AnnounceVerification::check_channel_binding`] performs the
//!   cross-check against `bundle.manifest.channel_pub`, and the
//!   all-in-one [`announce_bound`] folds it together with operator
//!   pinning + validity in one call.
//! - **Validate `cert.valid_from` / `cert.valid_until`.** That's a
//!   caller wall-clock policy. See
//!   [`IdentityCert::check_validity`](pir_identity::IdentityCert::check_validity).
//! - **Bound replay via `manifest.issued_at`.** Caller policy.

use crate::protocol::encode_request;
use crate::transport::PirTransport;
use pir_identity::{AnnouncementBundle, IdentityError};
use pir_sdk::{PirError, PirResult};

/// REQ_ANNOUNCE opcode (mirrors `pir_runtime_core::protocol::REQ_ANNOUNCE`).
pub(crate) const REQ_ANNOUNCE: u8 = 0x07;
/// RESP_ANNOUNCE opcode.
pub(crate) const RESP_ANNOUNCE: u8 = 0x07;
/// Generic server-side error envelope.
const RESP_ERROR: u8 = 0xff;

/// What [`announce`] returns: the parsed bundle plus its chain-check
/// verdict. The bundle is always returned (decode succeeded), but
/// callers should consult `chain_verified` before trusting any of its
/// fields. A `false` value here means the server returned a
/// well-formed but inconsistent bundle — almost certainly a deploy
/// bug, but also the shape a MITM with a misconfigured rig would
/// produce.
#[derive(Clone, Debug)]
pub struct AnnounceVerification {
    pub bundle: AnnouncementBundle,
    /// Result of the in-bundle cross-check: manifest signature valid,
    /// `cert.identity_pubkey == manifest.identity_pubkey`, and
    /// `cert.server_id == manifest.server_id`. Operator-pubkey pinning
    /// is a separate, caller-driven step.
    pub chain_verified: bool,
    /// `Some(e)` if `chain_verified` is `false`, for diagnostics.
    pub chain_error: Option<IdentityError>,
}

impl AnnounceVerification {
    /// Bind the bundle to the encrypted session: check that the
    /// operator-signed `manifest.channel_pub` equals the X25519 public
    /// key the channel actually handshook against.
    ///
    /// Pass the *attested* `server_static_pub` — i.e. the value the
    /// client verified via the SEV-SNP report / VCEK chain (V2 layout
    /// commits the channel key to `REPORT_DATA`) and then ran
    /// `REQ_HANDSHAKE` against. Equality closes the loop: the chip
    /// vouches for the channel key, the operator vouches for the same
    /// key, and the client confirms they agree. A mismatch means the
    /// bundle describes a *different* channel than the one in use —
    /// either a deploy bug or a relay splicing one server's bundle onto
    /// another server's session — so trust nothing in the bundle.
    ///
    /// This is orthogonal to operator-pubkey pinning ([`announce_with_pinned_operator`])
    /// and the in-bundle chain check ([`AnnounceVerification::chain_verified`]);
    /// the full-trust path wants all three, which [`announce_bound`] runs
    /// in one call.
    pub fn check_channel_binding(&self, expected_channel_pub: &[u8; 32]) -> PirResult<()> {
        if &self.bundle.manifest.channel_pub != expected_channel_pub {
            return Err(PirError::Protocol(format!(
                "announce: bundle channel_pub ({}) does not match the handshake key ({})",
                short_hex(&self.bundle.manifest.channel_pub),
                short_hex(expected_channel_pub),
            )));
        }
        Ok(())
    }
}

/// Send REQ_ANNOUNCE and parse the response.
///
/// Returns:
/// - `Ok(v)` — the server returned a well-formed bundle. `v.chain_verified`
///   indicates whether the manifest-vs-cert chain check passed. Either
///   way, the caller still owes (a) operator-pubkey pinning and
///   (b) cross-check of `bundle.manifest.channel_pub` against the
///   handshake pubkey.
/// - `Err(PirError::ServerError(_))` — the server explicitly returned
///   `RESP_ERROR`, typically meaning "announce is not configured on
///   this server" (no `--identity-key-path` / `--identity-cert-path`).
///   Production clients should treat this as a soft state — the
///   server's other endpoints (attest, handshake, query) are still
///   usable; just no operator-signed identity is available.
/// - `Err(PirError::Protocol(_))` — wire-format violation.
pub async fn announce<T: PirTransport + ?Sized>(
    transport: &mut T,
) -> PirResult<AnnounceVerification> {
    let request = encode_request(REQ_ANNOUNCE, &[]);
    let response = transport.roundtrip(&request).await?;

    if response.is_empty() {
        return Err(PirError::Protocol("empty announce response".into()));
    }
    match response[0] {
        RESP_ANNOUNCE => { /* fall through */ }
        RESP_ERROR => {
            // Server-side error envelope. Decoder is shared with the
            // existing attest path — wire layout is
            // [RESP_ERROR][u32 len LE][utf-8 msg]. Older servers (pre-
            // REQ_ANNOUNCE) reject the opcode at the request decoder,
            // surfacing the same envelope, so this branch covers both.
            let msg = if response.len() >= 5 {
                let len = u32::from_le_bytes(response[1..5].try_into().unwrap()) as usize;
                if 5 + len <= response.len() {
                    String::from_utf8_lossy(&response[5..5 + len]).to_string()
                } else {
                    "<truncated error message>".into()
                }
            } else {
                String::from_utf8_lossy(&response[1..]).to_string()
            };
            return Err(PirError::ServerError(msg));
        }
        v => {
            return Err(PirError::Protocol(format!(
                "unexpected response variant 0x{:02x} for announce",
                v
            )));
        }
    }

    // Layout (after the variant byte): [u32 LE bundle_len][bundle_bytes]
    if response.len() < 1 + 4 {
        return Err(PirError::Protocol(
            "announce response missing 4-byte bundle length".into(),
        ));
    }
    let blen = u32::from_le_bytes(response[1..5].try_into().unwrap()) as usize;
    if 5 + blen > response.len() {
        return Err(PirError::Protocol(
            "announce response: declared bundle length exceeds payload".into(),
        ));
    }
    let bundle_bytes = &response[5..5 + blen];
    let bundle = AnnouncementBundle::decode(bundle_bytes)
        .map_err(|e| PirError::Protocol(format!("decode AnnouncementBundle: {}", e)))?;

    // Run the chain check. Verifying the operator's signature on the
    // cert is a SEPARATE step (caller policy) — see
    // `announce_with_pinned_operator`.
    let chain_result = bundle.verify_chain();
    let (chain_verified, chain_error) = match chain_result {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e)),
    };

    Ok(AnnounceVerification {
        bundle,
        chain_verified,
        chain_error,
    })
}

/// Same as [`announce`] but ALSO verifies the IdentityCert against a
/// pinned operator pubkey. Use this once you have a trustworthy way
/// to know the operator's pubkey (build-time pin, DNSSEC TXT, Nostr,
/// etc.). Fails if the cert's signature doesn't validate under
/// `pinned_operator_pubkey`, OR if the cert was signed by a different
/// operator key than expected.
///
/// `now_unix_seconds` is the wall clock the caller wants to apply for
/// the `valid_from` / `valid_until` window check. Pass `0` to skip
/// the time check.
pub async fn announce_with_pinned_operator<T: PirTransport + ?Sized>(
    transport: &mut T,
    pinned_operator_pubkey: &[u8; 32],
    now_unix_seconds: i64,
) -> PirResult<AnnounceVerification> {
    let v = announce(transport).await?;
    if &v.bundle.cert.operator_pubkey != pinned_operator_pubkey {
        return Err(PirError::Protocol(format!(
            "announce: cert.operator_pubkey ({}) does not match pinned operator ({})",
            short_hex(&v.bundle.cert.operator_pubkey),
            short_hex(pinned_operator_pubkey),
        )));
    }
    v.bundle
        .cert
        .verify()
        .map_err(|e| PirError::Protocol(format!("announce: cert.verify failed: {}", e)))?;
    if now_unix_seconds != 0 {
        v.bundle
            .cert
            .check_validity(now_unix_seconds)
            .map_err(|e| PirError::Protocol(format!("announce: cert outside validity: {}", e)))?;
    }
    if !v.chain_verified {
        return Err(PirError::Protocol(format!(
            "announce: chain check failed: {}",
            v.chain_error
                .as_ref()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown".into())
        )));
    }
    Ok(v)
}

/// Full-trust announce: [`announce_with_pinned_operator`] **plus** the
/// channel-binding cross-check ([`AnnounceVerification::check_channel_binding`]).
///
/// This is the call a production client should use once it has both a
/// pinned operator pubkey and the attested channel key in hand. It
/// fails unless ALL of the following hold:
/// - the cert is signed by `pinned_operator_pubkey` and (if
///   `now_unix_seconds != 0`) is inside its validity window,
/// - the in-bundle chain check passes (manifest signed by the cert's
///   identity key, server_id / identity_pubkey cross-refs match),
/// - `bundle.manifest.channel_pub == expected_channel_pub` (the
///   attested `server_static_pub` the channel handshook against).
///
/// `expected_channel_pub` is the X25519 key the caller verified through
/// attestation and ran `REQ_HANDSHAKE` against. `now_unix_seconds` is
/// the wall clock for the validity check; pass `0` to skip it.
pub async fn announce_bound<T: PirTransport + ?Sized>(
    transport: &mut T,
    pinned_operator_pubkey: &[u8; 32],
    expected_channel_pub: &[u8; 32],
    now_unix_seconds: i64,
) -> PirResult<AnnounceVerification> {
    let v =
        announce_with_pinned_operator(transport, pinned_operator_pubkey, now_unix_seconds).await?;
    v.check_channel_binding(expected_channel_pub)?;
    Ok(v)
}

fn short_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(18);
    for b in &bytes[..8] {
        s.push_str(&format!("{:02x}", b));
    }
    s.push('…');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use pir_identity::{sign_channel_manifest, sign_identity_cert, AnnouncementBundle};
    use std::sync::Mutex;

    struct MockTransport {
        reply: Vec<u8>,
        last_request: Mutex<Vec<u8>>,
    }

    #[async_trait]
    impl PirTransport for MockTransport {
        async fn send(&mut self, _data: Vec<u8>) -> PirResult<()> {
            Ok(())
        }
        async fn recv(&mut self) -> PirResult<Vec<u8>> {
            Ok(self.reply.clone())
        }
        async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
            *self.last_request.lock().unwrap() = request.to_vec();
            Ok(self.reply.clone())
        }
        async fn close(&mut self) -> PirResult<()> {
            Ok(())
        }
        fn url(&self) -> &str {
            "mock://test"
        }
    }

    fn fake_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn build_resp_announce(bundle: &AnnouncementBundle) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(RESP_ANNOUNCE);
        let b = bundle.encode();
        payload.extend_from_slice(&(b.len() as u32).to_le_bytes());
        payload.extend_from_slice(&b);
        payload
    }

    fn build_bundle() -> AnnouncementBundle {
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        let manifest = sign_channel_manifest(
            &id_sk,
            "pir1",
            [0xCCu8; 32],
            [0xAAu8; 32],
            "abc",
            vec![],
            1_700_000_000,
        );
        AnnouncementBundle { cert, manifest }
    }

    #[tokio::test]
    async fn announce_returns_parsed_bundle_with_chain_verified() {
        let bundle = build_bundle();
        let mut mock = MockTransport {
            reply: build_resp_announce(&bundle),
            last_request: Mutex::new(Vec::new()),
        };
        let v = announce(&mut mock).await.unwrap();
        assert!(v.chain_verified);
        assert!(v.chain_error.is_none());
        assert_eq!(v.bundle.cert.server_id, "pir1");
        assert_eq!(v.bundle.manifest.channel_pub, [0xCCu8; 32]);

        // Wire-sanity: REQ_ANNOUNCE has empty body.
        let req = mock.last_request.lock().unwrap().clone();
        assert_eq!(req.len(), 4 + 1);
        assert_eq!(req[4], REQ_ANNOUNCE);
    }

    #[tokio::test]
    async fn announce_chain_mismatch_surfaces_as_chain_verified_false() {
        // Bundle that decodes fine but whose chain check fails.
        let op_sk = fake_sk(0x11);
        let id_sk_a = fake_sk(0x22);
        let id_sk_b = fake_sk(0x33);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk_a.verifying_key().to_bytes(),
            0,
            0,
        );
        // Manifest signed by a different identity key than the cert
        // endorses → chain check fails. (Each signature in isolation
        // still verifies, but the cross-check catches it.)
        let manifest = sign_channel_manifest(
            &id_sk_b,
            "pir1",
            [0u8; 32],
            [0u8; 32],
            "v",
            vec![],
            0,
        );
        let bundle = AnnouncementBundle { cert, manifest };

        let mut mock = MockTransport {
            reply: build_resp_announce(&bundle),
            last_request: Mutex::new(Vec::new()),
        };
        let v = announce(&mut mock).await.unwrap();
        assert!(!v.chain_verified);
        assert!(v.chain_error.is_some());
    }

    #[tokio::test]
    async fn announce_server_error_envelope_propagates() {
        // Server returns RESP_ERROR (e.g. "announce not configured").
        let mut reply = vec![RESP_ERROR];
        let msg = b"announce not configured";
        reply.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        reply.extend_from_slice(msg);
        let mut mock = MockTransport {
            reply,
            last_request: Mutex::new(Vec::new()),
        };
        let err = announce(&mut mock).await.unwrap_err();
        match err {
            PirError::ServerError(m) => assert!(m.contains("not configured")),
            other => panic!("expected ServerError, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn announce_unknown_response_variant_is_decode_error() {
        let mut mock = MockTransport {
            reply: vec![0x42, 0x00, 0x00, 0x00, 0x00],
            last_request: Mutex::new(Vec::new()),
        };
        let err = announce(&mut mock).await.unwrap_err();
        assert!(matches!(err, PirError::Protocol(_)));
    }

    #[tokio::test]
    async fn announce_with_pinned_operator_happy_path() {
        let bundle = build_bundle();
        let pinned = bundle.cert.operator_pubkey;
        let mut mock = MockTransport {
            reply: build_resp_announce(&bundle),
            last_request: Mutex::new(Vec::new()),
        };
        let v = announce_with_pinned_operator(&mut mock, &pinned, 0)
            .await
            .unwrap();
        assert!(v.chain_verified);
    }

    #[tokio::test]
    async fn announce_with_pinned_operator_rejects_wrong_pin() {
        let bundle = build_bundle();
        let wrong_pin = [0u8; 32];
        let mut mock = MockTransport {
            reply: build_resp_announce(&bundle),
            last_request: Mutex::new(Vec::new()),
        };
        let err = announce_with_pinned_operator(&mut mock, &wrong_pin, 0)
            .await
            .unwrap_err();
        match err {
            PirError::Protocol(m) => assert!(m.contains("does not match pinned operator")),
            other => panic!("expected Protocol, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn announce_with_pinned_operator_rejects_expired_cert() {
        // Cert with a tight validity window — query at a time outside
        // the window must fail.
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            100,
            200,
        );
        let manifest = sign_channel_manifest(
            &id_sk,
            "pir1",
            [0u8; 32],
            [0u8; 32],
            "v",
            vec![],
            150,
        );
        let bundle = AnnouncementBundle { cert, manifest };
        let pinned = bundle.cert.operator_pubkey;
        let mut mock = MockTransport {
            reply: build_resp_announce(&bundle),
            last_request: Mutex::new(Vec::new()),
        };
        let err = announce_with_pinned_operator(&mut mock, &pinned, 999).await;
        match err {
            Err(PirError::Protocol(m)) => assert!(m.contains("outside validity")),
            other => panic!("expected Protocol(outside validity), got {:?}", other),
        }
    }

    #[test]
    fn check_channel_binding_accepts_matching_key() {
        // build_bundle()'s manifest commits channel_pub = [0xCC; 32].
        let v = AnnounceVerification {
            bundle: build_bundle(),
            chain_verified: true,
            chain_error: None,
        };
        v.check_channel_binding(&[0xCCu8; 32])
            .expect("matching channel_pub must pass");
    }

    #[test]
    fn check_channel_binding_rejects_mismatched_key() {
        let v = AnnounceVerification {
            bundle: build_bundle(),
            chain_verified: true,
            chain_error: None,
        };
        let err = v.check_channel_binding(&[0u8; 32]).unwrap_err();
        match err {
            PirError::Protocol(m) => assert!(m.contains("does not match the handshake key")),
            other => panic!("expected Protocol(channel mismatch), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn announce_bound_happy_path() {
        let bundle = build_bundle();
        let pinned = bundle.cert.operator_pubkey;
        let mut mock = MockTransport {
            reply: build_resp_announce(&bundle),
            last_request: Mutex::new(Vec::new()),
        };
        let v = announce_bound(&mut mock, &pinned, &[0xCCu8; 32], 0)
            .await
            .expect("correct operator + channel key must pass");
        assert!(v.chain_verified);
    }

    #[tokio::test]
    async fn announce_bound_rejects_wrong_channel_pub() {
        // Operator pin is correct, but the bundle's channel_pub does not
        // match the key the channel handshook against → reject.
        let bundle = build_bundle();
        let pinned = bundle.cert.operator_pubkey;
        let mut mock = MockTransport {
            reply: build_resp_announce(&bundle),
            last_request: Mutex::new(Vec::new()),
        };
        let err = announce_bound(&mut mock, &pinned, &[0x99u8; 32], 0)
            .await
            .unwrap_err();
        match err {
            PirError::Protocol(m) => assert!(m.contains("does not match the handshake key")),
            other => panic!("expected Protocol(channel mismatch), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn announce_bound_rejects_wrong_operator_even_with_right_channel() {
        // A wrong operator pin must fail before the channel key is even
        // considered (operator pinning is checked first).
        let bundle = build_bundle();
        let mut mock = MockTransport {
            reply: build_resp_announce(&bundle),
            last_request: Mutex::new(Vec::new()),
        };
        let err = announce_bound(&mut mock, &[0u8; 32], &[0xCCu8; 32], 0)
            .await
            .unwrap_err();
        match err {
            PirError::Protocol(m) => assert!(m.contains("does not match pinned operator")),
            other => panic!("expected Protocol(operator mismatch), got {:?}", other),
        }
    }
}
