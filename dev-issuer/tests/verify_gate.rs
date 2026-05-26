//! End-to-end test of the dev-issuer's co-located verify gate (the demo's "D"
//! leg). Builds the *real* `REQ_CREDENTIAL_PRESENT` (0x08) and
//! `REQ_CASHU_BAT_PRESENT` (0x09) payloads — byte-identical to what the PIR
//! server's WS gate receives — and POSTs them to `/dev/arc/verify` and
//! `/dev/cashu/verify`. Asserts accept, then rejection on replay
//! (ARC duplicate tag / Cashu double-spend).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::Duration;

use arc::{
    create_credential_request, finalize_credential, make_presentation_state, present,
    CredentialResponse, ServerPublicKey,
};
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::Group;
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

const PORT: u16 = 5733;
const REQUEST_CONTEXT: &[u8] = b"bitcoin-pir-v1";

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn http(method: &str, path: &str, body: Option<&[u8]>) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", PORT)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let body = body.unwrap_or(&[]);
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(req.as_bytes()).expect("write");
    if !body.is_empty() {
        stream.write_all(body).expect("write body");
    }
    stream.flush().ok();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read");
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("sep");
    let head = &raw[..sep];
    let resp_body = raw[sep + 4..].to_vec();
    let line_end = head.windows(2).position(|w| w == b"\r\n").unwrap_or(head.len());
    let first = String::from_utf8_lossy(&head[..line_end]);
    let code = first.split_whitespace().nth(1).and_then(|c| c.parse().ok()).expect("code");
    (code, resp_body)
}

fn wait_ready() {
    for _ in 0..60 {
        if TcpStream::connect(("127.0.0.1", PORT)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("dev-issuer not ready on {PORT}");
}

fn h2c(secret: &[u8]) -> ProjectivePoint {
    let mut hasher = Sha256::new();
    hasher.update(b"Secp256k1_HashToCurve_Cashu_");
    hasher.update(secret);
    let msg = hasher.finalize();
    for counter in 0u32.. {
        let mut h = Sha256::new();
        h.update(msg);
        h.update(counter.to_le_bytes());
        let d: [u8; 32] = h.finalize().into();
        let mut pt = [0u8; 33];
        pt[0] = 0x02;
        pt[1..].copy_from_slice(&d);
        if let Some(p) = Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(&pt.into())) {
            if !bool::from(p.is_identity()) {
                return p;
            }
        }
    }
    unreachable!()
}

fn compress(p: &ProjectivePoint) -> [u8; 33] {
    let e = p.to_affine().to_encoded_point(true);
    let mut o = [0u8; 33];
    o.copy_from_slice(e.as_bytes());
    o
}

fn base64url_nopad(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(A[(b0 >> 2) as usize] as char);
        out.push(A[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(A[(b2 & 0x3f) as usize] as char);
        }
    }
    out
}

fn extract(json: &str, key: &str) -> String {
    let needle = format!("\"{key}\":\"");
    let start = json.find(&needle).unwrap() + needle.len();
    let rest = &json[start..];
    rest[..rest.find('"').unwrap()].to_string()
}

#[test]
fn verify_gate_accepts_then_rejects_replays_for_both_schemes() {
    let pid = std::process::id();
    let arc_key = std::env::temp_dir().join(format!("vg_arc_{pid}.bin"));
    let cashu_key = std::env::temp_dir().join(format!("vg_cashu_{pid}.bin"));
    let _ = std::fs::remove_file(&arc_key);
    let _ = std::fs::remove_file(&cashu_key);

    let child = Command::new(env!("CARGO_BIN_EXE_dev-issuer"))
        .args(["--arc-key"])
        .arg(&arc_key)
        .args(["--cashu-key"])
        .arg(&cashu_key)
        .args(["--port", &PORT.to_string()])
        .spawn()
        .expect("spawn");
    let _guard = ServerGuard(child);
    wait_ready();

    let mut rng = rand_core::OsRng;

    // ─── ARC: obtain → present payload → verify → replay ───
    let (_, pk_bytes) = http("GET", "/dev/arc/pubkey", None);
    let pk = ServerPublicKey::from_bytes(&pk_bytes).unwrap();
    let (secrets, request) = create_credential_request(REQUEST_CONTEXT, &mut rng).unwrap();
    let (_, resp) = http("POST", "/dev/arc/issue", Some(&request.to_bytes()));
    let response = CredentialResponse::from_bytes(&resp).unwrap();
    let credential = finalize_credential(&secrets, &pk, &request, &response).unwrap();

    let limit = 8u64;
    let pres_ctx: &[u8] = b"verify-gate-session";
    let state = make_presentation_state(credential, pres_ctx, limit);
    let (_s, _n, presentation) = present(&state, &mut rng).unwrap();

    // Build the real REQ_CREDENTIAL_PRESENT payload (no 4B WS length prefix).
    let mut arc_payload = vec![0x08u8];
    arc_payload.push(REQUEST_CONTEXT.len() as u8);
    arc_payload.extend_from_slice(REQUEST_CONTEXT);
    arc_payload.push(pres_ctx.len() as u8);
    arc_payload.extend_from_slice(pres_ctx);
    arc_payload.extend_from_slice(&limit.to_le_bytes());
    arc_payload.extend_from_slice(&presentation.to_bytes());

    let (code, _) = http("POST", "/dev/arc/verify", Some(&arc_payload));
    assert_eq!(code, 200, "ARC present should verify");
    let (code, body) = http("POST", "/dev/arc/verify", Some(&arc_payload));
    assert_eq!(code, 400, "ARC replay should be rejected");
    assert!(
        String::from_utf8_lossy(&body).contains("duplicate"),
        "expected duplicate-tag rejection, got {}",
        String::from_utf8_lossy(&body)
    );

    // ─── Cashu: mint → unblind → authA → verify → replay ───
    let (_, keyset_json) = http("GET", "/dev/cashu/keyset", None);
    let keyset_json = String::from_utf8(keyset_json).unwrap();
    let id = extract(&keyset_json, "id");
    let pubkey_hex = extract(&keyset_json, "pubkey");
    let k_point = {
        let b: [u8; 33] = hex::decode(&pubkey_hex).unwrap().try_into().unwrap();
        Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(&b.into())).unwrap()
    };

    let secret = format!("vg-secret-{pid}");
    let r = Scalar::generate_vartime(&mut rng);
    let b_prime = compress(&(h2c(secret.as_bytes()) + ProjectivePoint::GENERATOR * r));
    let (_, sig) = http("POST", "/dev/cashu/mint", Some(&b_prime));
    let c_prime = Option::<ProjectivePoint>::from(
        ProjectivePoint::from_bytes(&<[u8; 33]>::try_from(sig.as_slice()).unwrap().into()),
    )
    .unwrap();
    let c = c_prime - k_point * r;
    let c_hex = hex::encode(compress(&c));

    let json = format!("{{\"id\":\"{}\",\"secret\":\"{}\",\"C\":\"{}\"}}", id, secret, c_hex);
    let token = format!("authA{}", base64url_nopad(json.as_bytes()));
    let mut cashu_payload = vec![0x09u8];
    cashu_payload.extend_from_slice(token.as_bytes());

    let (code, _) = http("POST", "/dev/cashu/verify", Some(&cashu_payload));
    assert_eq!(code, 200, "Cashu BAT should verify");
    let (code, body) = http("POST", "/dev/cashu/verify", Some(&cashu_payload));
    assert_eq!(code, 400, "Cashu replay should be rejected");
    assert!(
        String::from_utf8_lossy(&body).contains("spent"),
        "expected already-spent rejection, got {}",
        String::from_utf8_lossy(&body)
    );

    let _ = std::fs::remove_file(&arc_key);
    let _ = std::fs::remove_file(&cashu_key);
}
