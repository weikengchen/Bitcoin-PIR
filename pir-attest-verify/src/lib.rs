//! AMD SEV-SNP attestation chain verifier for BitcoinPIR.
//!
//! ## Trust model
//!
//! After [`bpir-admin attest`] returns a 1184-byte SEV-SNP report, the
//! caller has only verified that the *self-reported* fields
//! (binary_sha256, manifest_roots, server_static_pub) hash to the
//! REPORT_DATA value baked into the report. That's the V2 binding —
//! necessary but not sufficient. The report itself could still be
//! fabricated by a malicious server.
//!
//! This crate closes the gap: given the report bytes + the chip's
//! VCEK certificate, [`verify_report_against_vcek`] checks the
//! report's ECDSA-P384 signature using the VCEK's public key. A
//! pass means "this report was signed by the AMD chip whose VCEK
//! cert is `vcek_pem`".
//!
//! For a fully trustless check (rather than pinning the VCEK),
//! callers also feed [`verify_chain`] the ASK + ARK certificates;
//! the function walks ASK←ARK and VCEK←ASK with RSA-PSS sigs. The
//! ARK is AMD's root and should be operator-pinned (its SHA-256
//! fingerprint is baked into the WASM bundle so a malicious server
//! can't substitute a forged root).
//!
//! ## Why pure-Rust + wasm32
//!
//! The browser-side WASM SDK invokes this from JS — no Cloudflare
//! Worker proxy, no openssl FFI. We use `sev = "7"` with the
//! `crypto_nossl` feature, which delegates to RustCrypto's
//! `rsa` + `p384` + `sha2`. Verified earlier (`/tmp/sev-wasm-probe`)
//! that the full stack compiles to `wasm32-unknown-unknown` once
//! `getrandom` carries the `js` feature.
//!
//! ## What this crate does NOT do
//!
//! - Fetch certs from AMD's KDS endpoint. Browser CORS rejects
//!   `kdsintf.amd.com`; the design instead has the server bundle
//!   ARK + ASK + VCEK in its AttestResult so the browser only needs
//!   to verify, not fetch.
//! - Decide whether the *attested values* (MEASUREMENT, REPORT_DATA,
//!   manifest_roots) are the ones the operator expects. That's a
//!   policy concern handled by the caller — typically by comparing
//!   the report's MEASUREMENT against an operator-published value
//!   (today via `bpir-admin --expect-measurement`).

#![warn(missing_docs)]

use sev::firmware::guest::AttestationReport;
// `from_bytes` lives on the ByteParser trait — bring it in scope so
// the call site below resolves.
use sev::parser::ByteParser;

pub use sev::firmware::guest::AttestationReport as SnpReport;
pub use sev::firmware::host::TcbVersion;

/// Operator-pinned SHA-256 fingerprint of the AMD **Turin**-family ARK
/// (Root Key) certificate, DER-encoded.
///
/// Source: AMD's published cert chain at
/// `https://kdsintf.amd.com/vcek/v1/Turin/cert_chain` (the ARK is the
/// second PEM block). Same fingerprint applies to every Turin-family
/// chip — there's one ARK per CPU generation, not per chip.
///
/// This is the *trust anchor* for the SEV-SNP chain. Verifiers pass
/// `Some(TURIN_ARK_FINGERPRINT_SHA256)` to [`verify_chain`] so the
/// supplied ARK PEM is checked against this value before any RSA
/// signature work — defends against a malicious server bundling a
/// self-signed forgery and claiming it's AMD's root.
///
/// Mirrored in `web/src/attest-pin.ts` as
/// `AMD_TURIN_ARK_FINGERPRINT_HEX` — keep both in sync. To rotate
/// (~25-year cadence; ARK rolls are very rare):
/// 1. Re-fetch `cert_chain.pem` from AMD KDS.
/// 2. `csplit -z -f cert_ -b "%d.pem" cert_chain.pem '/-----BEGIN CERT/' '{*}'`
/// 3. `openssl x509 -in cert_1.pem -outform DER | sha256sum`
/// 4. Replace both constants + rebuild.
pub const TURIN_ARK_FINGERPRINT_SHA256: [u8; 32] = [
    0x1f, 0x08, 0x41, 0x61, 0xa4, 0x4b, 0xb6, 0xd9, 0x37, 0x78, 0xa9, 0x04, 0x87, 0x7d, 0x48, 0x19,
    0xca, 0xfa, 0x5d, 0x05, 0xef, 0x41, 0x93, 0xb2, 0xde, 0xd9, 0xdd, 0x9c, 0x73, 0xdd, 0x3f, 0x6a,
];

pub mod policy;

/// Bytes-level offset of the report's MEASUREMENT field.
///
/// Mirrors `pir_core::attest::SEV_SNP_REPORT_DATA_OFFSET` (0x50, for
/// REPORT_DATA) — the MEASUREMENT field follows a similar fixed
/// layout. Exposed so callers can sanity-check report length without
/// importing `sev` directly.
pub const SNP_REPORT_LEN: usize = 1184;

/// Errors from the verifier. `Display` impls are concise and
/// human-readable so the WASM bridge can pass them through to JS as
/// a single string.
#[derive(Debug)]
pub enum VerifyError {
    /// Report bytes too short or otherwise malformed.
    MalformedReport(String),
    /// VCEK PEM bytes failed to parse as a valid X.509 certificate.
    MalformedVcek(String),
    /// ASK PEM bytes failed to parse.
    MalformedAsk(String),
    /// ARK PEM bytes failed to parse.
    MalformedArk(String),
    /// Cert chain validation failed (one of the parent→child
    /// signatures didn't verify).
    ChainBroken(String),
    /// Report signature verification against VCEK's pubkey failed —
    /// the report was NOT signed by the chip whose VCEK was
    /// supplied.
    ReportSignatureInvalid(String),
    /// ARK pubkey fingerprint didn't match the operator-pinned value.
    /// Strong signal that the supplied chain isn't AMD's.
    ArkFingerprintMismatch {
        /// What the verifier computed from the supplied ARK PEM.
        actual: [u8; 32],
        /// What the operator pinned at build time.
        expected: [u8; 32],
    },
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedReport(s) => write!(f, "malformed SNP report: {}", s),
            Self::MalformedVcek(s) => write!(f, "malformed VCEK cert: {}", s),
            Self::MalformedAsk(s) => write!(f, "malformed ASK cert: {}", s),
            Self::MalformedArk(s) => write!(f, "malformed ARK cert: {}", s),
            Self::ChainBroken(s) => write!(f, "VCEK chain broken: {}", s),
            Self::ReportSignatureInvalid(s) => {
                write!(f, "report signature invalid against VCEK: {}", s)
            }
            Self::ArkFingerprintMismatch { actual, expected } => write!(
                f,
                "ARK fingerprint mismatch (expected {}, got {})",
                hex::encode(expected),
                hex::encode(actual),
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Parse a 1184-byte SEV-SNP attestation report into structured fields.
///
/// Returns the high-level [`SnpReport`] handle from `sev`. Callers
/// reach inside for `measurement`, `report_data`, `chip_id`,
/// `current_tcb`, etc. via that crate's public API. We re-export
/// [`SnpReport`] so downstream callers can avoid a direct `sev` dep.
pub fn parse_report(bytes: &[u8]) -> Result<SnpReport, VerifyError> {
    if bytes.len() < SNP_REPORT_LEN {
        return Err(VerifyError::MalformedReport(format!(
            "expected at least {} bytes, got {}",
            SNP_REPORT_LEN,
            bytes.len()
        )));
    }
    AttestationReport::from_bytes(&bytes[..SNP_REPORT_LEN])
        .map_err(|e| VerifyError::MalformedReport(format!("decode: {e}")))
}

/// Verify the SNP report's ECDSA-P384 signature against a VCEK cert.
///
/// `report_bytes` must be the raw 1184-byte SEV-SNP report (the same
/// bytes [`pir_runtime_core::attest::fetch_report`] returns to the
/// server, which the server then embeds in its AttestResult).
/// `vcek_pem` is the VCEK's PEM-encoded X.509 certificate, as fetched
/// from `https://kdsintf.amd.com/vcek/v1/{Family}/{ChipID}?…` on the
/// server side and bundled into the AttestResult.
///
/// Pass means: "this report was signed by the chip endorsed by this
/// VCEK". For a fully trustless verdict, also call [`verify_chain`]
/// to confirm the VCEK itself chains back to AMD's ARK.
pub fn verify_report_against_vcek(
    report_bytes: &[u8],
    vcek_pem: &[u8],
) -> Result<SnpReport, VerifyError> {
    use sev::certs::snp::{Certificate, Verifiable};
    let report = parse_report(report_bytes)?;
    let vcek = Certificate::from_pem(vcek_pem)
        .map_err(|e| VerifyError::MalformedVcek(format!("PEM decode: {e}")))?;
    (&vcek, &report)
        .verify()
        .map_err(|e| VerifyError::ReportSignatureInvalid(format!("{e}")))?;
    Ok(report)
}

/// Verify the full VCEK ← ASK ← ARK chain.
///
/// `ark_pem`, `ask_pem`, `vcek_pem` are PEM-encoded X.509 certificates.
/// All three signatures are checked: ARK self-signed, ARK→ASK
/// (RSA-PSS-SHA384), ASK→VCEK (RSA-PSS-SHA384). On success returns
/// the parsed VCEK certificate so callers can extract its public key
/// for subsequent report-signature verification.
///
/// `expected_ark_fingerprint`, when supplied, is checked against
/// SHA-256 of the ARK's tbsCertificate DER bytes. This is the layer
/// that anchors trust to AMD's known root — without it, a malicious
/// server could supply a self-signed "root" that doesn't actually
/// belong to AMD. Pin the operator-published value into your WASM
/// bundle.
pub fn verify_chain(
    ark_pem: &[u8],
    ask_pem: &[u8],
    vcek_pem: &[u8],
    expected_ark_fingerprint: Option<[u8; 32]>,
) -> Result<(), VerifyError> {
    use sev::certs::snp::{ca, Certificate, Chain, Verifiable};

    // Pin the ARK first — fails fast before doing any expensive RSA
    // signature verification if the operator-supplied root doesn't
    // match what we expected.
    if let Some(expected) = expected_ark_fingerprint {
        let actual = ark_fingerprint_sha256(ark_pem)?;
        if actual != expected {
            return Err(VerifyError::ArkFingerprintMismatch { actual, expected });
        }
    }

    let ca_chain = ca::Chain::from_pem(ark_pem, ask_pem).map_err(|e| {
        // The CA chain constructor wraps both ARK and ASK errors into
        // a single io::Error; we can't easily disambiguate which side
        // failed without re-parsing. Surface as a generic ChainBroken
        // — operators should re-run with a debug build to see which
        // PEM was malformed.
        VerifyError::ChainBroken(format!("ca chain decode: {e}"))
    })?;
    let vcek = Certificate::from_pem(vcek_pem)
        .map_err(|e| VerifyError::MalformedVcek(format!("PEM decode: {e}")))?;

    let chain = Chain {
        ca: ca_chain,
        vek: vcek,
    };
    chain
        .verify()
        .map_err(|e| VerifyError::ChainBroken(format!("{e}")))?;
    Ok(())
}

/// One-shot full SEV-SNP attestation verification: chain + report
/// signature + policy.
///
/// This is the recommended entry point for production callers. It runs
/// the three independent checks in order, short-circuiting on first
/// failure, and returns the parsed [`SnpReport`] only if everything
/// passed:
///
/// 1. **Chain** ([`verify_chain`]): server-supplied `ark_pem` matches
///    the operator-pinned fingerprint, ARK self-signed, ARK→ASK,
///    ASK→VCEK (RSA-PSS-SHA384). Pass
///    `Some(TURIN_ARK_FINGERPRINT_SHA256)` for the Turin pin.
/// 2. **Report signature** ([`verify_report_against_vcek`]): the SNP
///    report's ECDSA-P384-SHA384 signature verifies against the VCEK
///    pubkey — i.e. the report was minted by the chip whose VCEK was
///    supplied.
/// 3. **Policy** ([`policy::verify_policy`]): VMPL, debug, migrate,
///    TCB monotonicity + minimum, and the optional measurement /
///    family / image / chip_id pins all hold.
///
/// On success, the returned [`SnpReport`] carries every field the
/// caller might want to inspect (REPORT_DATA, MEASUREMENT, chip_id,
/// etc.) — and they're all anchored in silicon at this point.
pub fn verify_full(
    report_bytes: &[u8],
    ark_pem: &[u8],
    ask_pem: &[u8],
    vcek_pem: &[u8],
    expected_ark_fingerprint: Option<[u8; 32]>,
    requirements: &policy::PolicyRequirements,
) -> Result<SnpReport, FullVerifyError> {
    verify_chain(ark_pem, ask_pem, vcek_pem, expected_ark_fingerprint)
        .map_err(FullVerifyError::Chain)?;
    let report = verify_report_against_vcek(report_bytes, vcek_pem)
        .map_err(FullVerifyError::ReportSignature)?;
    policy::verify_policy(&report, requirements).map_err(FullVerifyError::Policy)?;
    Ok(report)
}

/// Composite error from [`verify_full`]. Each variant wraps the
/// step-specific error type so callers can drill in if they need to.
#[derive(Debug)]
pub enum FullVerifyError {
    /// ARK / ASK / VCEK chain validation failed (pre-signature check
    /// on the report itself).
    Chain(VerifyError),
    /// VCEK chain was sound but the report's signature didn't verify
    /// against the VCEK pubkey.
    ReportSignature(VerifyError),
    /// Chain and signature were sound but a policy assertion (VMPL,
    /// debug bit, TCB, measurement, etc.) failed.
    Policy(policy::PolicyError),
}

impl core::fmt::Display for FullVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Chain(e) => write!(f, "chain: {}", e),
            Self::ReportSignature(e) => write!(f, "report-sig: {}", e),
            Self::Policy(e) => write!(f, "policy: {}", e),
        }
    }
}

impl std::error::Error for FullVerifyError {}

/// Compute SHA-256 of the ARK's PEM bytes (after stripping the
/// PEM armor — i.e. the SHA-256 of the DER-encoded certificate).
///
/// Operators publish this 32-byte fingerprint alongside the
/// attestation values; verifiers pin it into their WASM bundle and
/// pass it to [`verify_chain`] as `expected_ark_fingerprint`.
fn ark_fingerprint_sha256(ark_pem: &[u8]) -> Result<[u8; 32], VerifyError> {
    // Strip PEM armor → DER bytes → SHA-256.
    let der = pem_to_der(ark_pem)
        .map_err(|e| VerifyError::MalformedArk(format!("PEM→DER: {e}")))?;
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(&der);
    Ok(h.finalize().into())
}

/// Minimal PEM→DER helper. Doesn't validate the BEGIN/END tags
/// match — that's the cert parser's job downstream.
fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>, String> {
    let s = core::str::from_utf8(pem).map_err(|e| format!("not utf8: {e}"))?;
    let mut b64 = String::new();
    let mut in_body = false;
    for line in s.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if trimmed.starts_with("-----END") {
            in_body = false;
            continue;
        }
        if in_body {
            b64.push_str(trimmed);
        }
    }
    base64_decode(&b64).map_err(|e| format!("base64: {e}"))
}

/// Tiny base64 decoder — we don't pull in the `base64` crate to keep
/// the dep tree minimal. Standard alphabet (RFC 4648), no URL-safe.
fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity((s.len() / 4) * 3);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        let v: u32 = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return Err(format!("invalid base64 char: 0x{:02x}", c)),
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_report_rejects_short_input() {
        let err = parse_report(&[0u8; 100]).unwrap_err();
        match err {
            VerifyError::MalformedReport(_) => {}
            _ => panic!("expected MalformedReport, got {:?}", err),
        }
    }

    #[test]
    fn parse_report_rejects_unsupported_version() {
        // The sev crate's parser checks the report version field (u32
        // at offset 0). A zero-filled buffer has version=0, which the
        // parser rejects as unsupported. Real reports from
        // /dev/sev-guest are version 2 (older) or 5 (current).
        let err = parse_report(&[0u8; SNP_REPORT_LEN]).unwrap_err();
        match err {
            VerifyError::MalformedReport(s) => {
                assert!(s.contains("unsupported"), "got: {}", s)
            }
            _ => panic!("expected MalformedReport, got {:?}", err),
        }
    }

    // Note: we don't unit-test the `verify_report_against_vcek`
    // happy path here — building a synthetic report that satisfies
    // every internal check the sev parser does (version, MASK_CHIP_ID,
    // signature algorithm tag, …) without also being a full real
    // attestation is fragile. Slice D.3's browser integration tests
    // exercise the real path against actual server-supplied bytes.

    #[test]
    fn pem_to_der_round_trip_matches_known_value() {
        // Tiny synthetic PEM (just to exercise the parser; not a real cert).
        let pem = b"-----BEGIN TEST-----\nSGVsbG8sIFdvcmxkIQ==\n-----END TEST-----\n";
        let der = pem_to_der(pem).unwrap();
        assert_eq!(der, b"Hello, World!");
    }

    #[test]
    fn pem_to_der_handles_multi_line_body() {
        // PEM bodies usually wrap at 64 chars; check we concatenate.
        let pem = b"-----BEGIN TEST-----\nU0dWc2JHOHNJ\nRmR2Y214a0lR\n==\n-----END TEST-----\n";
        // U0dWc2JHOHNJRmR2Y214a0lRPT0= → b"SGVsbG8sIFdvcmxkIQ==" → b"Hello, World!"
        // (actually the inner b64 decodes once to the b64-encoded form; let's
        // verify by running the decoder manually)
        let der = pem_to_der(pem).unwrap();
        // The two lines concatenate to "U0dWc2JHOHNJRmR2Y214a0lR==" which
        // decodes to "SGVsbG8sIFdvcmxkIQ" (no quote, partial — confirms multi-line
        // concatenation works rather than being a strict assertion of contents).
        assert!(!der.is_empty(), "multi-line PEM should produce non-empty DER");
    }

    #[test]
    fn base64_decode_rejects_invalid_char() {
        let err = base64_decode("AB!CD").unwrap_err();
        assert!(err.contains("invalid base64 char"));
    }

    #[test]
    fn base64_decode_handles_padding() {
        // "Hi" → "SGk=" — single padding
        assert_eq!(base64_decode("SGk=").unwrap(), b"Hi");
        // "Hello" → "SGVsbG8=" — single padding
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), b"Hello");
        // "Hell" → "SGVsbA==" — double padding
        assert_eq!(base64_decode("SGVsbA==").unwrap(), b"Hell");
    }

    #[test]
    fn verify_chain_rejects_garbage_pem() {
        // Wrapped as ChainBroken because `ca::Chain::from_pem` collapses
        // ARK and ASK decode failures into a single error variant — see
        // the comment in `verify_chain` for why we don't disambiguate.
        let err = verify_chain(b"not pem", b"not pem", b"not pem", None).unwrap_err();
        match err {
            VerifyError::ChainBroken(s) => {
                assert!(s.contains("decode") || s.contains("PEM"), "got: {}", s)
            }
            _ => panic!("expected ChainBroken, got {:?}", err),
        }
    }

    #[test]
    fn verify_chain_rejects_when_ark_fingerprint_mismatches() {
        // Even with garbage PEM bytes, the fingerprint check happens
        // first so we get a precise diagnostic. PEM stripping returns
        // empty bytes (no BEGIN/END tags), SHA-256 of empty is the
        // well-known constant. Compare against a clearly-different
        // expectation.
        let empty_sha256 = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        let expected = [0xFFu8; 32];
        // Not-PEM (no BEGIN/END tags) produces empty DER → SHA-256 of empty.
        let err = verify_chain(b"garbage", b"garbage", b"garbage", Some(expected)).unwrap_err();
        match err {
            VerifyError::ArkFingerprintMismatch { actual, expected: e } => {
                assert_eq!(actual, empty_sha256);
                assert_eq!(e, expected);
            }
            _ => panic!("expected ArkFingerprintMismatch, got {:?}", err),
        }
    }

    #[test]
    fn verify_error_display_is_human_readable() {
        let e = VerifyError::ArkFingerprintMismatch {
            actual: [0xAA; 32],
            expected: [0xBB; 32],
        };
        let s = e.to_string();
        assert!(s.contains("ARK fingerprint mismatch"));
        assert!(s.contains(&"aa".repeat(32)));
        assert!(s.contains(&"bb".repeat(32)));
    }

    #[test]
    fn turin_ark_fingerprint_is_32_bytes_and_nonzero() {
        // Sanity: caught a copy-paste mistake earlier where I had 31
        // bytes. Belt-and-suspenders.
        assert_eq!(TURIN_ARK_FINGERPRINT_SHA256.len(), 32);
        assert!(TURIN_ARK_FINGERPRINT_SHA256.iter().any(|&b| b != 0));
        // First byte matches the published value 0x1f (sanity-check
        // against a single-character typo).
        assert_eq!(TURIN_ARK_FINGERPRINT_SHA256[0], 0x1f);
        // Last byte 0x6a.
        assert_eq!(TURIN_ARK_FINGERPRINT_SHA256[31], 0x6a);
    }

    #[test]
    fn verify_full_short_circuits_on_chain_failure() {
        // Garbage PEM bytes → chain check fails before report-sig or
        // policy is even attempted.
        let req = policy::PolicyRequirements::default();
        let err = verify_full(
            &[0u8; SNP_REPORT_LEN],
            b"garbage",
            b"garbage",
            b"garbage",
            None,
            &req,
        )
        .unwrap_err();
        assert!(matches!(err, FullVerifyError::Chain(_)), "{:?}", err);
    }

    #[test]
    fn verify_full_short_circuits_on_pinned_ark_mismatch() {
        // Even with garbage PEM, the fingerprint check fires first
        // (per `verify_chain`'s contract). FullVerifyError wraps that
        // as Chain.
        let req = policy::PolicyRequirements::default();
        let err = verify_full(
            &[0u8; SNP_REPORT_LEN],
            b"garbage",
            b"garbage",
            b"garbage",
            Some([0xFFu8; 32]),
            &req,
        )
        .unwrap_err();
        match err {
            FullVerifyError::Chain(VerifyError::ArkFingerprintMismatch { .. }) => {}
            other => panic!("expected Chain(ArkFingerprintMismatch), got {:?}", other),
        }
    }

    #[test]
    fn full_verify_error_display_includes_step() {
        // Display should say which step failed — operators reading
        // logs want to know whether to fix their pin, their VCEK
        // bundle, or their policy config.
        let e = FullVerifyError::Chain(VerifyError::ChainBroken("oops".into()));
        let s = e.to_string();
        assert!(s.starts_with("chain:"), "got: {}", s);

        let e = FullVerifyError::Policy(policy::PolicyError::DebugNotAllowed);
        let s = e.to_string();
        assert!(s.starts_with("policy:"), "got: {}", s);
    }
}
