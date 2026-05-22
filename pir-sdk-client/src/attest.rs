//! Client-side attestation: send REQ_ATTEST, decode RESP_ATTEST, and
//! recompute the REPORT_DATA preimage to verify the server's response.
//!
//! ## What this module does
//!
//! - Frames a 32-byte client nonce as a REQ_ATTEST message and sends it
//!   over any [`PirTransport`].
//! - Decodes the response into a typed [`AttestResponse`] (the wire
//!   format mirrors `pir_runtime_core::protocol::AttestResult`).
//! - Recomputes `sha256("BPIR-ATTEST-V2" || nonce || combined_root ||
//!   binary_sha256 || server_static_pub || git_rev)` and checks that
//!   the SEV-SNP report's REPORT_DATA field (if present) carries that
//!   value.
//!
//! The V2 preimage adds `server_static_pub` — the long-lived X25519
//! public key the server generated inside its SEV-SNP guest at boot.
//! Binding the pubkey here is the foundation of the
//! browser↔unified_server encrypted channel: with this check passing,
//! the client knows the X25519 key it'll handshake against was
//! generated inside the same attested guest cloudflared can't see into.
//!
//! ## What this module does NOT do
//!
//! - **AMD VCEK chain verification.** The cert chain (ARK → ASK → VCEK
//!   → report) needs the AMD KDS endpoint and a TLS-validated PEM chain;
//!   the `bpir-admin attest` CLI tool (Slice 4) is the right place for
//!   that since it can shell out to `snpguest verify` or use the `sev`
//!   crate. This module returns the raw SEV bytes; callers are
//!   responsible for cert-chain validation.
//! - **Cross-checking binary_sha256 / git_rev / manifest_roots against
//!   operator-published expected values.** That comparison is operator-
//!   policy, not a wire-protocol concern.

use crate::protocol::encode_request;
use crate::transport::PirTransport;
use pir_core::attest::{build_report_data, derive_attest_nonce, extract_report_data};
use pir_core::merkle::Hash256;
use pir_sdk::{PirError, PirResult};

/// REQ_ATTEST opcode (mirrors `pir_runtime_core::protocol::REQ_ATTEST`).
pub(crate) const REQ_ATTEST: u8 = 0x05;
/// RESP_ATTEST opcode.
pub(crate) const RESP_ATTEST: u8 = 0x05;
/// Generic server-side error envelope.
const RESP_ERROR: u8 = 0xff;

/// Decoded body of a `RESP_ATTEST` message.
#[derive(Clone, Debug)]
pub struct AttestResponse {
    /// Raw signed SEV-SNP attestation report bytes (~1184 for v5).
    /// Empty if the server isn't running on a SEV-SNP guest.
    pub sev_snp_report: Vec<u8>,
    /// Per-DB manifest roots in db_id order. The all-zero hash means
    /// that DB has no `MANIFEST.toml` (legacy / un-verified state).
    pub manifest_roots: Vec<Hash256>,
    /// SHA-256 of the running binary (cached at server startup).
    pub binary_sha256: Hash256,
    /// X25519 public key the server uses for encrypted-channel
    /// handshakes. All-zero on servers that don't yet have a channel
    /// key (transitional). Bound into REPORT_DATA via the V2 layout
    /// so the chip-signed attestation authenticates this exact key.
    pub server_static_pub: [u8; 32],
    /// Git commit baked into the running binary. May be suffixed with
    /// `-dirty` if the working tree had local changes at build time, or
    /// be the literal `"unknown"` for non-git builds.
    pub git_rev: String,
    /// PEM-encoded AMD ARK certificate, when the server has the cert
    /// chain loaded. Empty on servers without `--vcek-dir` configured.
    /// Together with `ask_pem` + `vcek_pem`, the browser-side
    /// `pir-attest-verify` can chain-validate the SNP report's
    /// signature back to AMD's known root.
    pub ark_pem: Vec<u8>,
    /// PEM-encoded AMD ASK certificate (per SoC family). Empty when
    /// not loaded server-side.
    pub ask_pem: Vec<u8>,
    /// PEM-encoded per-chip + per-TCB VCEK certificate. Empty when
    /// not loaded server-side.
    pub vcek_pem: Vec<u8>,
}

/// Outcome of an attest call: server response + locally-recomputed
/// expected REPORT_DATA + status of the SEV-SNP report binding check.
#[derive(Clone, Debug)]
pub struct AttestVerification {
    /// The 32-byte nonce the caller supplied — echoed for convenience
    /// so callers can correlate concurrent attest calls.
    pub nonce: [u8; 32],
    /// Decoded server response.
    pub response: AttestResponse,
    /// REPORT_DATA preimage hash the client recomputed locally. For
    /// the binding to be valid, the SEV report's REPORT_DATA[0..32]
    /// must equal this value.
    pub expected_report_data_hash: Hash256,
    /// Status of the REPORT_DATA binding check.
    pub sev_status: SevStatus,
}

/// SEV-SNP report binding status. `ReportDataMatch` is the only state
/// where the operator's claims (binary_sha256, manifest_roots, git_rev)
/// have *any* hardware backing — anything else is unsigned data the
/// server self-reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SevStatus {
    /// Server isn't on a SEV-SNP host (e.g. Hetzner i7-8700, dev laptop).
    /// `binary_sha256` / `manifest_roots` / `git_rev` are self-reported,
    /// not hardware-backed.
    NoSevHost,
    /// SEV-SNP report present, its REPORT_DATA matches our recomputation.
    /// Caller still needs to validate the AMD VCEK chain to anchor the
    /// signature in real silicon.
    ReportDataMatch,
    /// SEV-SNP report present but REPORT_DATA doesn't match. Either the
    /// server is lying about its manifest_roots / binary / git_rev, or
    /// there's a wire format bug. **Do not trust the self-reported
    /// fields in this case.**
    ReportDataMismatch,
    /// SEV-SNP report bytes present but too short to contain REPORT_DATA.
    /// Almost certainly a wire bug or a malformed report.
    MalformedReport,
}

/// Send REQ_ATTEST and verify the REPORT_DATA binding.
///
/// `transport` can be a [`crate::WsConnection`], a
/// [`crate::WasmWebSocketTransport`], or any test mock — the trait
/// abstracts over native and wasm32 sockets. The trait method
/// `roundtrip` already strips the outer 4-byte length prefix.
pub async fn attest<T: PirTransport + ?Sized>(
    transport: &mut T,
    nonce: [u8; 32],
) -> PirResult<AttestVerification> {
    let request = encode_request(REQ_ATTEST, &nonce);
    let response = transport.roundtrip(&request).await?;

    if response.is_empty() {
        return Err(PirError::Protocol("empty attest response".into()));
    }
    match response[0] {
        RESP_ATTEST => { /* fall through */ }
        RESP_ERROR => {
            let msg = String::from_utf8_lossy(&response[1..]).to_string();
            return Err(PirError::ServerError(msg));
        }
        v => {
            return Err(PirError::Protocol(format!(
                "unexpected response variant 0x{:02x} for attest",
                v
            )));
        }
    }

    let parsed = decode_attest_response(&response[1..])?;
    let expected = build_report_data(
        nonce,
        &parsed.manifest_roots,
        parsed.binary_sha256,
        parsed.server_static_pub,
        &parsed.git_rev,
    );
    let mut expected_low = [0u8; 32];
    expected_low.copy_from_slice(&expected[..32]);

    let sev_status = if parsed.sev_snp_report.is_empty() {
        SevStatus::NoSevHost
    } else {
        match extract_report_data(&parsed.sev_snp_report) {
            None => SevStatus::MalformedReport,
            Some(actual) if actual == expected.as_slice() => SevStatus::ReportDataMatch,
            Some(_) => SevStatus::ReportDataMismatch,
        }
    };

    Ok(AttestVerification {
        nonce,
        response: parsed,
        expected_report_data_hash: expected_low,
        sev_status,
    })
}

/// Send REQ_ATTEST with the nonce *bound* to the client's handshake
/// ephemeral pubkey, so the chip-signed REPORT_DATA commits to *this*
/// handshake — not a stale or replayed attestation.
///
/// Concretely: `nonce = derive_attest_nonce(eph_pub_from_seed(eph_seed),
/// random_32)`. The same `eph_seed` MUST be threaded into the
/// subsequent [`crate::channel::establish`] call so the eph pubkey
/// committed-to in REPORT_DATA equals the eph pubkey sent in
/// REQ_HANDSHAKE.
///
/// `random_32` MUST be a fresh CSPRNG draw per call (Os entropy in
/// production; deterministic in tests for reproducibility).
///
/// The returned [`AttestVerification`] is the same shape as
/// [`attest`]'s — its `expected_report_data_hash` was computed using
/// the derived nonce, so the existing `sev_status` semantics apply
/// (e.g. `ReportDataMatch` proves the SEV report covers both the
/// server's static pubkey AND this handshake's client ephemeral).
pub async fn attest_with_eph_binding<T: PirTransport + ?Sized>(
    transport: &mut T,
    eph_seed: [u8; 32],
    random_32: [u8; 32],
) -> PirResult<AttestVerification> {
    let client_eph_pub = pir_channel::eph_pub_from_seed(eph_seed);
    let nonce = derive_attest_nonce(client_eph_pub, random_32);
    attest(transport, nonce).await
}

/// Recompute the bound attest nonce from an `eph_seed` + `random_32`.
/// Useful for tests / inspectors that want to compare a captured
/// `AttestVerification::nonce` against the binding it should encode.
pub fn bound_nonce_for(eph_seed: [u8; 32], random_32: [u8; 32]) -> [u8; 32] {
    let client_eph_pub = pir_channel::eph_pub_from_seed(eph_seed);
    derive_attest_nonce(client_eph_pub, random_32)
}

/// Mirror of `pir_runtime_core::protocol::decode_attest_result`. Kept
/// here so pir-sdk-client doesn't need to depend on pir-runtime-core
/// (which pulls in libdpf, memmap2, and other server-side deps).
fn decode_attest_response(data: &[u8]) -> PirResult<AttestResponse> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(PirError::Protocol(
            "attest response missing sev_report length".into(),
        ));
    }
    let sev_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if pos + sev_len > data.len() {
        return Err(PirError::Protocol("truncated sev_snp_report".into()));
    }
    let sev_snp_report = data[pos..pos + sev_len].to_vec();
    pos += sev_len;

    if pos >= data.len() {
        return Err(PirError::Protocol(
            "attest response missing manifest count".into(),
        ));
    }
    let n_roots = data[pos] as usize;
    pos += 1;
    if pos + n_roots * 32 > data.len() {
        return Err(PirError::Protocol("truncated manifest roots".into()));
    }
    let mut manifest_roots = Vec::with_capacity(n_roots);
    for _ in 0..n_roots {
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[pos..pos + 32]);
        manifest_roots.push(root);
        pos += 32;
    }

    if pos + 32 > data.len() {
        return Err(PirError::Protocol("truncated binary_sha256".into()));
    }
    let mut binary_sha256 = [0u8; 32];
    binary_sha256.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // V2 wire layout: server_static_pub right after binary_sha256.
    if pos + 32 > data.len() {
        return Err(PirError::Protocol(
            "truncated server_static_pub (V2 wire layout)".into(),
        ));
    }
    let mut server_static_pub = [0u8; 32];
    server_static_pub.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    if pos + 2 > data.len() {
        return Err(PirError::Protocol("truncated git_rev length".into()));
    }
    let git_len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    if pos + git_len > data.len() {
        return Err(PirError::Protocol("truncated git_rev bytes".into()));
    }
    let git_rev = String::from_utf8_lossy(&data[pos..pos + git_len]).to_string();
    pos += git_len;

    // V3 cert chain extension. Trailing empty for back-compat with
    // pre-Slice-D.2 servers.
    let ark_pem = decode_lp_bytes_u32_or_empty(data, &mut pos)
        .map_err(|e| PirError::Protocol(format!("ark_pem: {}", e)))?;
    let ask_pem = decode_lp_bytes_u32_or_empty(data, &mut pos)
        .map_err(|e| PirError::Protocol(format!("ask_pem: {}", e)))?;
    let vcek_pem = decode_lp_bytes_u32_or_empty(data, &mut pos)
        .map_err(|e| PirError::Protocol(format!("vcek_pem: {}", e)))?;

    Ok(AttestResponse {
        sev_snp_report,
        manifest_roots,
        binary_sha256,
        server_static_pub,
        git_rev,
        ark_pem,
        ask_pem,
        vcek_pem,
    })
}

/// Read a length-prefixed binary blob from `data` at `pos`, advancing
/// `pos`. Returns empty if `pos` is at end-of-buffer (back-compat with
/// pre-Slice-D.2 servers that don't emit cert fields).
fn decode_lp_bytes_u32_or_empty(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
    if *pos == data.len() {
        return Ok(Vec::new());
    }
    if *pos + 4 > data.len() {
        return Err(format!(
            "truncated u32 length prefix at pos {} (len={})",
            *pos,
            data.len()
        ));
    }
    let n = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + n > data.len() {
        return Err(format!(
            "body truncated: claimed {} bytes, have {}",
            n,
            data.len() - *pos
        ));
    }
    let body = data[*pos..*pos + n].to_vec();
    *pos += n;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use pir_core::attest::SEV_SNP_REPORT_DATA_OFFSET;
    use std::sync::Mutex;

    /// Test transport that returns a canned reply and records the request.
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
            // Strip the outer length prefix (server's reply doesn't include it
            // by the time we reach the trait method — see the doc on
            // PirTransport::roundtrip).
            Ok(self.reply.clone())
        }
        async fn close(&mut self) -> PirResult<()> {
            Ok(())
        }
        fn url(&self) -> &str {
            "mock://test"
        }
    }

    /// Build the wire bytes of a RESP_ATTEST message body (after the
    /// 4-byte outer length prefix would be stripped by transport.roundtrip).
    /// Mirrors `pir_runtime_core::protocol::encode_attest_result` (V3 —
    /// V2 layout + trailing ark_pem/ask_pem/vcek_pem extension).
    fn build_response_payload(r: &AttestResponse) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(RESP_ATTEST);
        payload.extend_from_slice(&(r.sev_snp_report.len() as u32).to_le_bytes());
        payload.extend_from_slice(&r.sev_snp_report);
        payload.push(r.manifest_roots.len() as u8);
        for root in &r.manifest_roots {
            payload.extend_from_slice(root);
        }
        payload.extend_from_slice(&r.binary_sha256);
        payload.extend_from_slice(&r.server_static_pub);
        let g = r.git_rev.as_bytes();
        payload.extend_from_slice(&(g.len() as u16).to_le_bytes());
        payload.extend_from_slice(g);
        for blob in [&r.ark_pem, &r.ask_pem, &r.vcek_pem] {
            payload.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            payload.extend_from_slice(blob);
        }
        payload
    }

    #[tokio::test]
    async fn no_sev_host_returns_no_sev_status() {
        let nonce = [0x42u8; 32];
        let resp = AttestResponse {
            sev_snp_report: Vec::new(), // empty → NoSevHost
            manifest_roots: vec![[0xAAu8; 32]],
            binary_sha256: [0xBBu8; 32],
            server_static_pub: [0u8; 32],
            git_rev: "abc".into(),
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: Vec::new(),
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest(&mut mock, nonce).await.unwrap();
        assert_eq!(v.sev_status, SevStatus::NoSevHost);
        assert_eq!(v.nonce, nonce);
        assert_eq!(v.response.git_rev, "abc");
        // Sanity-check the request is REQ_ATTEST + 32-byte nonce
        let req = mock.last_request.lock().unwrap().clone();
        assert_eq!(req.len(), 4 + 1 + 32);
        assert_eq!(req[4], REQ_ATTEST);
        assert_eq!(&req[5..37], &nonce);
    }

    #[tokio::test]
    async fn matching_sev_report_returns_match() {
        let nonce = [0x10u8; 32];
        let manifest_roots = vec![[0xAAu8; 32], [0xBBu8; 32]];
        let binary_sha256 = [0xCCu8; 32];
        let server_static_pub = [0xEEu8; 32];
        let git_rev = "deadbeef".to_string();

        // Construct a SEV report blob whose REPORT_DATA field at offset 0x50
        // contains the expected V2 preimage hash.
        let expected = build_report_data(
            nonce,
            &manifest_roots,
            binary_sha256,
            server_static_pub,
            &git_rev,
        );
        let mut sev_blob = vec![0xFFu8; 1184];
        sev_blob[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&expected);

        let resp = AttestResponse {
            sev_snp_report: sev_blob,
            manifest_roots,
            binary_sha256,
            server_static_pub,
            git_rev,
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: Vec::new(),
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest(&mut mock, nonce).await.unwrap();
        assert_eq!(v.sev_status, SevStatus::ReportDataMatch);
    }

    #[tokio::test]
    async fn lying_server_returns_mismatch() {
        let nonce = [0x10u8; 32];

        // Report claims binary_sha256 = [0xCCu8; 32] but the embedded
        // REPORT_DATA was computed with a different binary hash — server
        // is lying.
        let claimed_binary = [0xCCu8; 32];
        let actual_binary = [0xDDu8; 32];
        let manifest_roots = vec![[0xAAu8; 32]];
        let server_static_pub = [0u8; 32];
        let git_rev = "v1".to_string();
        let dishonest_preimage = build_report_data(
            nonce,
            &manifest_roots,
            actual_binary,
            server_static_pub,
            &git_rev,
        );

        let mut sev_blob = vec![0u8; 1184];
        sev_blob[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&dishonest_preimage);

        let resp = AttestResponse {
            sev_snp_report: sev_blob,
            manifest_roots,
            binary_sha256: claimed_binary, // ≠ actual_binary used in REPORT_DATA
            server_static_pub,
            git_rev,
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: Vec::new(),
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest(&mut mock, nonce).await.unwrap();
        assert_eq!(v.sev_status, SevStatus::ReportDataMismatch);
    }

    #[tokio::test]
    async fn substituted_pubkey_returns_mismatch() {
        // The whole point of binding server_static_pub: a MITM (e.g.
        // cloudflared) that replaces the pubkey but echoes everything
        // else faithfully must trip the binding check.
        let nonce = [0x10u8; 32];
        let manifest_roots = vec![[0xAAu8; 32]];
        let binary_sha256 = [0xCCu8; 32];
        let real_pubkey = [0x11u8; 32];
        let attacker_pubkey = [0x22u8; 32];
        let git_rev = "v1".to_string();

        // Server's chip-signed REPORT_DATA was computed against the
        // real pubkey (this is the only thing the chip can sign — the
        // server can't lie to the chip about its own boot-time key).
        let real_preimage = build_report_data(
            nonce,
            &manifest_roots,
            binary_sha256,
            real_pubkey,
            &git_rev,
        );
        let mut sev_blob = vec![0u8; 1184];
        sev_blob[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&real_preimage);

        // But the wire response carries the attacker's pubkey (e.g.
        // cloudflared swapped it). Recomputed preimage diverges.
        let resp = AttestResponse {
            sev_snp_report: sev_blob,
            manifest_roots,
            binary_sha256,
            server_static_pub: attacker_pubkey,
            git_rev,
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: Vec::new(),
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest(&mut mock, nonce).await.unwrap();
        assert_eq!(v.sev_status, SevStatus::ReportDataMismatch);
    }

    #[tokio::test]
    async fn truncated_sev_report_returns_malformed() {
        let nonce = [0x10u8; 32];
        let resp = AttestResponse {
            sev_snp_report: vec![0u8; 50], // < 0x50 + 64
            manifest_roots: vec![],
            binary_sha256: [0u8; 32],
            server_static_pub: [0u8; 32],
            git_rev: "x".into(),
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: Vec::new(),
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest(&mut mock, nonce).await.unwrap();
        assert_eq!(v.sev_status, SevStatus::MalformedReport);
    }

    #[tokio::test]
    async fn server_error_envelope_propagates_as_pirerror_server() {
        // Server replied with RESP_ERROR (0xff) + msg
        let mut reply = vec![RESP_ERROR];
        reply.extend_from_slice(b"attest unsupported");
        let mut mock = MockTransport {
            reply,
            last_request: Mutex::new(Vec::new()),
        };
        let err = attest(&mut mock, [0u8; 32]).await.unwrap_err();
        match err {
            PirError::ServerError(msg) => assert!(msg.contains("attest unsupported")),
            _ => panic!("expected PirError::ServerError, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn unknown_response_variant_is_decode_error() {
        let mock_reply = vec![0x99]; // not RESP_ATTEST or RESP_ERROR
        let mut mock = MockTransport {
            reply: mock_reply,
            last_request: Mutex::new(Vec::new()),
        };
        let err = attest(&mut mock, [0u8; 32]).await.unwrap_err();
        assert!(matches!(err, PirError::Protocol(_)), "got {:?}", err);
    }

    #[tokio::test]
    async fn attest_with_eph_binding_sends_bound_nonce_on_the_wire() {
        // The function must derive the nonce from (eph_seed, random_32)
        // and put exactly those bytes into REQ_ATTEST. Recompute the
        // expected nonce independently and compare to the wire bytes.
        let eph_seed = [0x77u8; 32];
        let random_32 = [0x88u8; 32];
        let expected_nonce = bound_nonce_for(eph_seed, random_32);

        let resp = AttestResponse {
            sev_snp_report: Vec::new(),
            manifest_roots: vec![],
            binary_sha256: [0u8; 32],
            server_static_pub: [0u8; 32],
            git_rev: "x".into(),
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: Vec::new(),
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest_with_eph_binding(&mut mock, eph_seed, random_32)
            .await
            .unwrap();
        assert_eq!(v.nonce, expected_nonce);

        let req = mock.last_request.lock().unwrap().clone();
        assert_eq!(req.len(), 4 + 1 + 32);
        assert_eq!(req[4], REQ_ATTEST);
        assert_eq!(&req[5..37], &expected_nonce);
    }

    #[tokio::test]
    async fn stale_report_against_different_eph_pub_is_rejected() {
        // Threat model: an attacker captured a real SEV report from a
        // prior session bound to eph_seed_A's nonce. They replay it
        // against a client running eph_seed_B. The client's recomputed
        // REPORT_DATA preimage uses nonce_B (committing to client_eph_pub_B);
        // the captured report's REPORT_DATA was computed from nonce_A
        // (committing to client_eph_pub_A) → mismatch.
        let eph_seed_a = [0xAAu8; 32];
        let eph_seed_b = [0xBBu8; 32];
        let random_32 = [0x99u8; 32]; // same random, different eph_seeds
        let nonce_a = bound_nonce_for(eph_seed_a, random_32);
        let nonce_b = bound_nonce_for(eph_seed_b, random_32);
        assert_ne!(nonce_a, nonce_b);

        let manifest_roots = vec![[0u8; 32]];
        let binary_sha256 = [0u8; 32];
        let server_static_pub = [0xEEu8; 32];
        let git_rev = "v1".to_string();

        // The captured report's REPORT_DATA was computed against nonce_A.
        let captured_preimage = build_report_data(
            nonce_a,
            &manifest_roots,
            binary_sha256,
            server_static_pub,
            &git_rev,
        );
        let mut sev_blob = vec![0u8; 1184];
        sev_blob[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&captured_preimage);

        // Attacker re-serves the captured report verbatim (same SEV
        // bytes + same self-reported fields) — what changes is which
        // eph_seed the *current* client is using.
        let resp = AttestResponse {
            sev_snp_report: sev_blob,
            manifest_roots,
            binary_sha256,
            server_static_pub,
            git_rev,
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: Vec::new(),
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        // Current client runs with eph_seed_B → expects REPORT_DATA
        // bound to nonce_B; gets one bound to nonce_A → mismatch.
        let v = attest_with_eph_binding(&mut mock, eph_seed_b, random_32)
            .await
            .unwrap();
        assert_eq!(v.sev_status, SevStatus::ReportDataMismatch);
    }

    #[tokio::test]
    async fn bound_nonce_matches_against_honest_server() {
        // Sanity: honest server signs against the SAME nonce the client
        // derived → ReportDataMatch.
        let eph_seed = [0x55u8; 32];
        let random_32 = [0x66u8; 32];
        let nonce = bound_nonce_for(eph_seed, random_32);

        let manifest_roots = vec![[0x33u8; 32]];
        let binary_sha256 = [0x44u8; 32];
        let server_static_pub = [0xEEu8; 32];
        let git_rev = "main".to_string();
        let preimage = build_report_data(
            nonce,
            &manifest_roots,
            binary_sha256,
            server_static_pub,
            &git_rev,
        );
        let mut sev_blob = vec![0u8; 1184];
        sev_blob[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&preimage);

        let resp = AttestResponse {
            sev_snp_report: sev_blob,
            manifest_roots,
            binary_sha256,
            server_static_pub,
            git_rev,
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: Vec::new(),
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest_with_eph_binding(&mut mock, eph_seed, random_32)
            .await
            .unwrap();
        assert_eq!(v.sev_status, SevStatus::ReportDataMatch);
    }
}
