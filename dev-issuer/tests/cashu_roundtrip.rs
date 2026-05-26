//! End-to-end HTTP test for the Cashu BDHKE mint: spawn `dev-issuer`, blind a
//! secret, get it blind-signed over the wire, unblind, and verify the
//! resulting BAT against the issuer's actual secret key (read from the key
//! file). Proves the demo's Cashu "obtain" leg works across real HTTP.
//!
//! The client-side crypto here (hash_to_curve / blind / unblind) is the same
//! math the WASM `WasmCashuBlind` binding implements; this test pins the mint
//! and the BDHKE relation `C == k · hash_to_curve(secret)` with only k256.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::Duration;

use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::{Group, PrimeField};
use k256::{ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

const PORT: u16 = 5732;

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
    stream.write_all(req.as_bytes()).expect("write headers");
    if !body.is_empty() {
        stream.write_all(body).expect("write body");
    }
    stream.flush().ok();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("no separator");
    let head = &raw[..sep];
    let resp_body = raw[sep + 4..].to_vec();
    let line_end = head.windows(2).position(|w| w == b"\r\n").unwrap_or(head.len());
    let first = String::from_utf8_lossy(&head[..line_end]);
    let code: u16 = first.split_whitespace().nth(1).and_then(|c| c.parse().ok()).expect("code");
    (code, resp_body)
}

fn wait_until_ready() {
    for _ in 0..60 {
        if TcpStream::connect(("127.0.0.1", PORT)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("dev-issuer did not become ready on port {PORT}");
}

/// Cashu NUT-00 hash-to-curve (must match `cashu_verifier::hash_to_curve_cashu`
/// and the dev-issuer's WASM binding byte-for-byte).
fn hash_to_curve(secret: &[u8]) -> ProjectivePoint {
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
        if let Some(point) = Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(&pt.into())) {
            if !bool::from(point.is_identity()) {
                return point;
            }
        }
    }
    unreachable!()
}

fn compress(p: &ProjectivePoint) -> [u8; 33] {
    let enc = p.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(enc.as_bytes());
    out
}

/// Pull the `pubkey` hex out of `{"id":"...","pubkey":"..."}` without a JSON dep.
fn extract_field(json: &str, key: &str) -> String {
    let needle = format!("\"{key}\":\"");
    let start = json.find(&needle).expect("key present") + needle.len();
    let rest = &json[start..];
    let end = rest.find('"').expect("closing quote");
    rest[..end].to_string()
}

#[test]
fn dev_issuer_cashu_mint_unblind_verify_over_http() {
    let pid = std::process::id();
    let arc_key = std::env::temp_dir().join(format!("cashu_test_arc_{pid}.bin"));
    let cashu_key = std::env::temp_dir().join(format!("cashu_test_k_{pid}.bin"));
    let _ = std::fs::remove_file(&arc_key);
    let _ = std::fs::remove_file(&cashu_key);

    let child = Command::new(env!("CARGO_BIN_EXE_dev-issuer"))
        .args(["--arc-key"])
        .arg(&arc_key)
        .args(["--cashu-key"])
        .arg(&cashu_key)
        .args(["--port", &PORT.to_string()])
        .spawn()
        .expect("spawn dev-issuer");
    let _guard = ServerGuard(child);
    wait_until_ready();

    // 1. Fetch the keyset → mint pubkey K (33 bytes).
    let (code, body) = http("GET", "/dev/cashu/keyset", None);
    assert_eq!(code, 200, "keyset status");
    let json = String::from_utf8(body).unwrap();
    let pubkey_hex = extract_field(&json, "pubkey");
    let id = extract_field(&json, "id");
    assert!(id.ends_with("-auth"), "keyset id format: {id}");
    let k_point = {
        let bytes: [u8; 33] = hex::decode(&pubkey_hex).unwrap().try_into().unwrap();
        Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(&bytes.into())).unwrap()
    };

    // 2. Client blinds a batch of 3 secrets: B'_i = hash_to_curve(secret_i) + r_i·G.
    let secrets: Vec<String> = (0..3).map(|i| format!("demo-secret-{pid}-{i}")).collect();
    let mut rng = rand_core::OsRng;
    let blindings: Vec<Scalar> = (0..3).map(|_| Scalar::generate_vartime(&mut rng)).collect();
    let mut blinded = Vec::new();
    for (secret, r) in secrets.iter().zip(&blindings) {
        let b_prime = hash_to_curve(secret.as_bytes()) + ProjectivePoint::GENERATOR * r;
        blinded.extend_from_slice(&compress(&b_prime));
    }

    // 3. Mint over HTTP → 3 blind signatures (3 × 33 bytes).
    let (code, sigs) = http("POST", "/dev/cashu/mint", Some(&blinded));
    assert_eq!(code, 200, "mint status");
    assert_eq!(sigs.len(), 3 * 33, "expected 3 blind sigs");

    // 4. Read the issuer's actual secret scalar k from the key file (to verify).
    let k = {
        let bytes: [u8; 32] = std::fs::read(&cashu_key).unwrap().try_into().unwrap();
        Option::<Scalar>::from(Scalar::from_repr(bytes.into())).unwrap()
    };
    // Sanity: the served pubkey is k·G.
    assert_eq!(compress(&(ProjectivePoint::GENERATOR * k)), compress(&k_point));

    // 5. Unblind each (C = C' - r·K) and verify the BDHKE relation C == k·Y.
    for (i, (secret, r)) in secrets.iter().zip(&blindings).enumerate() {
        let c_prime = {
            let chunk: [u8; 33] = sigs[i * 33..(i + 1) * 33].try_into().unwrap();
            Option::<ProjectivePoint>::from(ProjectivePoint::from_bytes(&chunk.into())).unwrap()
        };
        let c = c_prime - k_point * r;
        let expected = hash_to_curve(secret.as_bytes()) * k;
        assert_eq!(compress(&c), compress(&expected), "BAT {i} failed BDHKE verify");
    }

    let _ = std::fs::remove_file(&arc_key);
    let _ = std::fs::remove_file(&cashu_key);
}
