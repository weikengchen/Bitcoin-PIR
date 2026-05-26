//! DEV-ONLY free credential issuer for the ARC / Cashu rate-limiting demo.
//!
//! This binary stands in for the real (Lightning-backed) payment service so
//! the end-to-end demo can run without money, an LDK node, or any network
//! deploy. It issues credentials **for free** to anyone who asks — there is
//! deliberately no payment check. DO NOT DEPLOY THIS TO PRODUCTION.
//!
//! It is intentionally dependency-light: only `arc` (already vendored) and
//! `rand_core`. The HTTP/1.1 handling is hand-rolled over `std::net` so the
//! offline `vendor/` tree is not perturbed by a web framework.
//!
//! ## Endpoints (CORS-open for browser `fetch`)
//!
//! | Method | Path               | Body (in)                 | Body (out)                 |
//! |--------|--------------------|---------------------------|----------------------------|
//! | GET    | `/dev/arc/pubkey`  | —                         | 99-byte `ServerPublicKey`  |
//! | POST   | `/dev/arc/issue`   | 226-byte `CredentialRequest` | 454-byte `CredentialResponse` |
//! | OPTIONS| *                  | —                         | 204 (CORS preflight)       |
//!
//! The ARC private key is loaded from / generated to `--arc-key <path>` using
//! the canonical 128-byte `x0 || x1 || x2 || x0_blinding` layout, byte-exact
//! with `pir_runtime_core::arc_verifier::ArcVerifier`, so the demo PIR server
//! can be launched with `--require-arc --arc-key <same path>` and will verify
//! credentials this issuer mints.
//!
//! (Cashu `/dev/cashu/*` endpoints are added in Phase 2.)

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use arc::group::{deserialize_scalar, serialize_element, serialize_scalar};
use arc::{
    create_credential_response, setup_server, verify_presentation, CredentialRequest,
    Presentation, ServerPrivateKey, ServerPublicKey,
};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::{Group, PrimeField};
use k256::{ProjectivePoint, Scalar};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

/// Canonical ARC private-key file size: 4 × 32-byte scalars.
const ARC_PRIVKEY_SIZE: usize = 128;

/// A Cashu Blind Auth keyset: a single secp256k1 scalar `k`. Matches the
/// payment service's `CashuAuthKeyset` (32-byte `k` file, id =
/// `hex(pubkey)[..16] + "-auth"`) so the demo PIR server can be launched with
/// `--require-cashu --cashu-keyset <id>:<k_hex>`.
struct CashuKeyset {
    k: Scalar,
    keyset_id: String,
    pubkey_hex: String,
    secret_hex: String,
}

struct IssuerState {
    sk: ServerPrivateKey,
    pk: ServerPublicKey,
    cashu: CashuKeyset,
    /// ARC seen-tags per presentation_context (reject nonce reuse), mirroring
    /// `pir_runtime_core::arc_verifier::ArcVerifier`.
    arc_tags: Mutex<HashMap<Vec<u8>, HashSet<Vec<u8>>>>,
    /// Cashu spent secrets (SHA-256), mirroring `CashuVerifier` (single-use).
    cashu_spent: Mutex<HashSet<[u8; 32]>>,
}

fn main() {
    let mut arc_key_path = PathBuf::from("arc_key.bin");
    let mut cashu_key_path = PathBuf::from("cashu_key.bin");
    let mut port: u16 = 5601;

    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--arc-key" => {
                if let Some(p) = argv.get(i + 1) {
                    arc_key_path = PathBuf::from(p);
                }
                i += 1;
            }
            "--cashu-key" => {
                if let Some(p) = argv.get(i + 1) {
                    cashu_key_path = PathBuf::from(p);
                }
                i += 1;
            }
            "--port" => {
                if let Some(p) = argv.get(i + 1) {
                    port = p.parse().unwrap_or_else(|_| {
                        eprintln!("invalid --port '{p}', using 5601");
                        5601
                    });
                }
                i += 1;
            }
            "-h" | "--help" => {
                println!("dev-issuer — DEV-ONLY free ARC/Cashu credential issuer");
                println!(
                    "usage: dev-issuer [--arc-key <path>] [--cashu-key <path>] [--port <n>]"
                );
                return;
            }
            other => eprintln!("ignoring unknown arg: {other}"),
        }
        i += 1;
    }

    let (sk, pk) = load_or_generate_key(&arc_key_path);
    let cashu = load_or_generate_cashu_key(&cashu_key_path);
    let cashu_keyset_arg = format!("{}:{}", cashu.keyset_id, cashu.secret_hex);
    let state = Arc::new(IssuerState {
        sk,
        pk,
        cashu,
        arc_tags: Mutex::new(HashMap::new()),
        cashu_spent: Mutex::new(HashSet::new()),
    });

    let listener = TcpListener::bind(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("failed to bind 127.0.0.1:{port}: {e}"));

    println!("┌─────────────────────────────────────────────────────────────");
    println!("│ dev-issuer  (DEV ONLY — no payment, free issuance)");
    println!("│ listening   http://127.0.0.1:{port}");
    println!("│ ARC key     {}", arc_key_path.display());
    println!("│ ARC pubkey  {} (99 bytes)", hex99(&pk.to_bytes()));
    println!("│ Cashu key   {}", cashu_key_path.display());
    println!("│ Cashu id    {}", state.cashu.keyset_id);
    println!("│ endpoints   GET /dev/arc/pubkey    POST /dev/arc/issue    POST /dev/arc/verify");
    println!("│             GET /dev/cashu/keyset  POST /dev/cashu/mint   POST /dev/cashu/verify");
    println!("│ NOTE        verify endpoints co-locate the credential gate (same logic as");
    println!("│             unified_server) so the demo needs no PIR database.");
    println!("│ server      unified_server --require-arc --arc-key {} \\", arc_key_path.display());
    println!("│                 --require-cashu --cashu-keyset {}", cashu_keyset_arg);
    println!("└─────────────────────────────────────────────────────────────");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st = Arc::clone(&state);
                thread::spawn(move || handle(s, st));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}

/// Load the ARC keypair from `path`, or generate + persist a fresh one.
/// Layout matches `ArcVerifier::secret_key_bytes` exactly.
fn load_or_generate_key(path: &Path) -> (ServerPrivateKey, ServerPublicKey) {
    if path.exists() {
        let bytes = std::fs::read(path)
            .unwrap_or_else(|e| panic!("failed to read ARC key {}: {e}", path.display()));
        assert_eq!(
            bytes.len(),
            ARC_PRIVKEY_SIZE,
            "ARC key file {} has wrong size",
            path.display()
        );
        let x0 = deserialize_scalar(&bytes[0..32]).expect("bad x0 scalar in key file");
        let x1 = deserialize_scalar(&bytes[32..64]).expect("bad x1 scalar in key file");
        let x2 = deserialize_scalar(&bytes[64..96]).expect("bad x2 scalar in key file");
        let x0_blinding =
            deserialize_scalar(&bytes[96..128]).expect("bad x0_blinding scalar in key file");
        let sk = ServerPrivateKey { x0, x1, x2, x0_blinding };
        let pk = sk.public_key();
        (sk, pk)
    } else {
        let (sk, pk) = setup_server(&mut OsRng);
        let mut out = [0u8; ARC_PRIVKEY_SIZE];
        out[0..32].copy_from_slice(&serialize_scalar(&sk.x0));
        out[32..64].copy_from_slice(&serialize_scalar(&sk.x1));
        out[64..96].copy_from_slice(&serialize_scalar(&sk.x2));
        out[96..128].copy_from_slice(&serialize_scalar(&sk.x0_blinding));
        std::fs::write(path, out)
            .unwrap_or_else(|e| panic!("failed to write ARC key {}: {e}", path.display()));
        println!("generated new ARC key → {}", path.display());
        (sk, pk)
    }
}

/// Handle one HTTP/1.1 connection. Never panics on client input (panic =
/// 'abort' is workspace-wide, so a panic here would kill the whole process).
fn handle(mut stream: TcpStream, state: Arc<IssuerState>) {
    let read_half = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(read_half);

    // Request line: "METHOD PATH HTTP/1.1"
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    // Headers — we only care about Content-Length.
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    // Body (exactly Content-Length bytes; BufReader holds any already-read).
    let mut body = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }

    match (method.as_str(), path.as_str()) {
        ("OPTIONS", _) => write_response(&mut stream, 204, "No Content", b"", "text/plain"),
        ("GET", "/dev/arc/pubkey") => {
            write_response(&mut stream, 200, "OK", &state.pk.to_bytes(), "application/octet-stream")
        }
        ("POST", "/dev/arc/issue") => match issue_arc(&state, &body) {
            Ok(resp) => {
                write_response(&mut stream, 200, "OK", &resp, "application/octet-stream")
            }
            Err(e) => {
                eprintln!("/dev/arc/issue rejected: {e}");
                write_response(&mut stream, 400, "Bad Request", e.as_bytes(), "text/plain")
            }
        },
        ("GET", "/dev/cashu/keyset") => {
            let json = format!(
                "{{\"id\":\"{}\",\"pubkey\":\"{}\"}}",
                state.cashu.keyset_id, state.cashu.pubkey_hex
            );
            write_response(&mut stream, 200, "OK", json.as_bytes(), "application/json")
        }
        ("POST", "/dev/cashu/mint") => match mint_cashu(&state, &body) {
            Ok(sigs) => {
                write_response(&mut stream, 200, "OK", &sigs, "application/octet-stream")
            }
            Err(e) => {
                eprintln!("/dev/cashu/mint rejected: {e}");
                write_response(&mut stream, 400, "Bad Request", e.as_bytes(), "text/plain")
            }
        },
        ("POST", "/dev/arc/verify") => match verify_arc(&state, &body) {
            Ok(()) => write_response(&mut stream, 200, "OK", b"ok\n", "text/plain"),
            Err(e) => write_response(&mut stream, 400, "Bad Request", e.as_bytes(), "text/plain"),
        },
        ("POST", "/dev/cashu/verify") => match verify_cashu(&state, &body) {
            Ok(()) => write_response(&mut stream, 200, "OK", b"ok\n", "text/plain"),
            Err(e) => write_response(&mut stream, 400, "Bad Request", e.as_bytes(), "text/plain"),
        },
        ("GET", "/") | ("GET", "/health") => {
            write_response(&mut stream, 200, "OK", b"dev-issuer ok\n", "text/plain")
        }
        _ => write_response(&mut stream, 404, "Not Found", b"not found\n", "text/plain"),
    }
}

/// Sign a blinded credential request → serialized `CredentialResponse`.
fn issue_arc(state: &IssuerState, request_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let request = CredentialRequest::from_bytes(request_bytes)
        .map_err(|e| format!("invalid CredentialRequest ({} bytes): {e}", request_bytes.len()))?;
    let response = create_credential_response(&state.sk, &state.pk, &request, &mut OsRng)
        .map_err(|e| format!("issuance failed: {e}"))?;
    Ok(response.to_bytes().to_vec())
}

/// Load the Cashu auth keyset from `path`, or generate + persist a fresh
/// 32-byte secp256k1 scalar. Layout matches the payment service's
/// `CashuAuthKeyset` (`scalar.to_bytes()`), and the keyset id is derived the
/// same way (`hex(compressed_pubkey)[..16] + "-auth"`).
fn load_or_generate_cashu_key(path: &Path) -> CashuKeyset {
    let scalar_bytes: [u8; 32] = if path.exists() {
        let bytes = std::fs::read(path)
            .unwrap_or_else(|e| panic!("failed to read Cashu key {}: {e}", path.display()));
        assert_eq!(bytes.len(), 32, "Cashu key file {} has wrong size", path.display());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        let k = Scalar::generate_vartime(&mut OsRng);
        let bytes: [u8; 32] = k.to_bytes().into();
        std::fs::write(path, bytes)
            .unwrap_or_else(|e| panic!("failed to write Cashu key {}: {e}", path.display()));
        println!("generated new Cashu key → {}", path.display());
        bytes
    };

    let k = Option::<Scalar>::from(Scalar::from_repr(scalar_bytes.into()))
        .unwrap_or_else(|| panic!("invalid Cashu key scalar in {}", path.display()));
    let pubkey = (ProjectivePoint::GENERATOR * k).to_affine().to_encoded_point(true);
    let pubkey_hex = hex::encode(pubkey.as_bytes());
    let keyset_id = format!("{}-auth", &pubkey_hex[..16]);
    let secret_hex = hex::encode(scalar_bytes);

    CashuKeyset { k, keyset_id, pubkey_hex, secret_hex }
}

/// Blind-sign one or more 33-byte blinded points: `C'_i = k · B'_i`.
/// Body is `N × 33` concatenated compressed points; response is `N × 33`.
fn mint_cashu(state: &IssuerState, body: &[u8]) -> Result<Vec<u8>, String> {
    if body.is_empty() || body.len() % 33 != 0 {
        return Err(format!(
            "blinded messages must be a non-empty multiple of 33 bytes, got {}",
            body.len()
        ));
    }
    let mut out = Vec::with_capacity(body.len());
    for chunk in body.chunks_exact(33) {
        out.extend_from_slice(&cashu_blind_sign(&state.cashu.k, chunk)?);
    }
    Ok(out)
}

/// `C' = k · B'` for a single 33-byte compressed blinded point.
fn cashu_blind_sign(k: &Scalar, blinded: &[u8]) -> Result<[u8; 33], String> {
    let arr: [u8; 33] = blinded
        .try_into()
        .map_err(|_| "blinded message must be 33 bytes".to_string())?;
    let point = Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(&arr.into()))
        .ok_or("invalid blinded point encoding")?;
    if bool::from(point.is_identity()) {
        return Err("blinded message is the identity point".into());
    }
    let signed = (point * k).to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(signed.as_bytes());
    Ok(out)
}

// ─── Verify gate (co-located so the demo needs no PIR server) ──────────────
//
// These mirror `pir_runtime_core::arc_verifier::ArcVerifier` and
// `cashu_verifier::CashuVerifier` exactly (same `arc::verify_presentation`
// call; same Cashu `C == k·hash_to_curve(secret)` relation + spent-set). The
// payload bytes are byte-identical to the WS `REQ_CREDENTIAL_PRESENT` (0x08) /
// `REQ_CASHU_BAT_PRESENT` (0x09) frames the PIR server receives — only the
// transport (HTTP here vs WS in production) differs.

/// Verify an ARC presentation payload `[0x08][req_ctx_len][req_ctx]
/// [pres_ctx_len][pres_ctx][8B limit LE][pres_bytes]` (same layout as
/// unified_server). Rejects nonce reuse via a per-pres_ctx tag set.
fn verify_arc(state: &IssuerState, payload: &[u8]) -> Result<(), String> {
    if payload.first() != Some(&0x08) {
        return Err("expected REQ_CREDENTIAL_PRESENT (0x08) variant byte".into());
    }
    let body = &payload[1..];
    if body.len() < 11 {
        return Err("malformed ARC present: too short".into());
    }
    let req_ctx_len = body[0] as usize;
    if body.len() < 1 + req_ctx_len + 1 {
        return Err("malformed ARC present: truncated request_context".into());
    }
    let req_ctx = &body[1..1 + req_ctx_len];
    let off = 1 + req_ctx_len;
    let pres_ctx_len = body[off] as usize;
    if body.len() < off + 1 + pres_ctx_len + 8 {
        return Err("malformed ARC present: truncated presentation_context".into());
    }
    let pres_ctx = &body[off + 1..off + 1 + pres_ctx_len];
    let limit_off = off + 1 + pres_ctx_len;
    let limit = u64::from_le_bytes(body[limit_off..limit_off + 8].try_into().unwrap());
    let pres_bytes = &body[limit_off + 8..];

    let presentation = Presentation::from_bytes(pres_bytes, limit)
        .map_err(|e| format!("malformed presentation: {e}"))?;
    let tag = verify_presentation(&state.sk, &state.pk, req_ctx, pres_ctx, &presentation, limit)
        .map_err(|e| format!("ARC proof invalid: {e}"))?;

    let tag_bytes = serialize_element(&tag).to_vec();
    let mut tags = state.arc_tags.lock().unwrap();
    let set = tags.entry(pres_ctx.to_vec()).or_default();
    if !set.insert(tag_bytes) {
        return Err("duplicate ARC tag — nonce reused".into());
    }
    Ok(())
}

/// Verify a Cashu BAT payload `[0x09][authA…]`. Rejects double-spends via the
/// spent-secret set.
fn verify_cashu(state: &IssuerState, payload: &[u8]) -> Result<(), String> {
    if payload.first() != Some(&0x09) {
        return Err("expected REQ_CASHU_BAT_PRESENT (0x09) variant byte".into());
    }
    let bat = std::str::from_utf8(&payload[1..]).map_err(|_| "invalid UTF-8 in BAT".to_string())?;
    let b64 = bat.strip_prefix("authA").ok_or("missing authA prefix")?;
    let json_bytes = base64url_decode(b64).ok_or("base64url decode failed")?;
    let json = std::str::from_utf8(&json_bytes).map_err(|_| "BAT JSON not UTF-8".to_string())?;

    let id = extract_json_str(json, "id").ok_or("BAT missing id")?;
    let secret = extract_json_str(json, "secret").ok_or("BAT missing secret")?;
    let c_hex = extract_json_str(json, "C").ok_or("BAT missing C")?;

    if id != state.cashu.keyset_id {
        return Err(format!("unknown keyset: {id}"));
    }
    let c_bytes: [u8; 33] = hex::decode(&c_hex)
        .map_err(|e| format!("C hex: {e}"))?
        .try_into()
        .map_err(|_| "C must be 33 bytes".to_string())?;
    let c = Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(&c_bytes.into()))
        .ok_or("invalid C point encoding")?;

    let expected = cashu_hash_to_curve(secret.as_bytes()) * state.cashu.k;
    if c != expected {
        return Err("BAT signature verification failed".into());
    }

    let secret_hash: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
    let mut spent = state.cashu_spent.lock().unwrap();
    if !spent.insert(secret_hash) {
        return Err("BAT already spent".into());
    }
    Ok(())
}

/// Cashu NUT-00 hash-to-curve (matches `cashu_verifier::hash_to_curve_cashu`).
fn cashu_hash_to_curve(secret: &[u8]) -> ProjectivePoint {
    let mut hasher = Sha256::new();
    hasher.update(b"Secp256k1_HashToCurve_Cashu_");
    hasher.update(secret);
    let msg_hash = hasher.finalize();
    for counter in 0u32.. {
        let mut h = Sha256::new();
        h.update(msg_hash);
        h.update(counter.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let mut pt = [0u8; 33];
        pt[0] = 0x02;
        pt[1..].copy_from_slice(&digest);
        if let Some(point) =
            Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(&pt.into()))
        {
            if !bool::from(point.is_identity()) {
                return point;
            }
        }
    }
    unreachable!()
}

/// Minimal URL-safe base64 decode, no padding (matches the verifier's).
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() || input.len() % 4 == 1 {
        return None;
    }
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut buf = 0u32;
    let mut bits = 0u8;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for &c in input.as_bytes() {
        let val = alphabet.iter().position(|&a| a == c)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Extract a string field `"key":"value"` from flat JSON (no nesting).
fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Write an HTTP/1.1 response with permissive (dev-only) CORS headers.
fn write_response(stream: &mut TcpStream, code: u16, status: &str, body: &[u8], content_type: &str) {
    let header = format!(
        "HTTP/1.1 {code} {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: *\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    if !body.is_empty() {
        let _ = stream.write_all(body);
    }
    let _ = stream.flush();
}

/// Lowercase hex for the 99-byte pubkey banner.
fn hex99(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
