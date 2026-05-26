//! End-to-end HTTP test: spawn the `dev-issuer` binary, obtain an ARC
//! credential over the wire, present it, and verify the presentation against
//! the same key the issuer persisted. Proves the demo's "obtain" leg works
//! across the real HTTP boundary (not just the in-process crypto of
//! `pir_runtime_core::arc_verifier`'s native loop test).
//!
//! Uses only `arc` + std — no WASM, no Node. The browser-side glue
//! (`payment-client.ts` + WASM bindings) is exercised by the demo page in its
//! real environment.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::Duration;

use arc::group::deserialize_scalar;
use arc::{
    create_credential_request, finalize_credential, make_presentation_state, present,
    verify_presentation, CredentialResponse, ServerPrivateKey, ServerPublicKey,
};

const REQUEST_CONTEXT: &[u8] = b"bitcoin-pir-v1";
const PORT: u16 = 5731;

/// Kill the child on drop so a panicking assert never leaks the process.
struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Minimal HTTP/1.1 client: returns (status_code, body_bytes). Reads to EOF
/// (the server sends `Connection: close`).
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

    // Split headers / body on the first CRLFCRLF.
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header/body separator");
    let head = &raw[..sep];
    let resp_body = raw[sep + 4..].to_vec();

    // Status code from the first line: "HTTP/1.1 <code> <reason>".
    let first_line_end = head.windows(2).position(|w| w == b"\r\n").unwrap_or(head.len());
    let first_line = String::from_utf8_lossy(&head[..first_line_end]);
    let code: u16 = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .expect("status code");

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

/// Reconstruct the issuer keypair from the persisted `arc_key.bin` so we can
/// verify the presentation with the *same* key the server issued under.
fn load_key(path: &std::path::Path) -> (ServerPrivateKey, ServerPublicKey) {
    let bytes = std::fs::read(path).expect("read key file");
    assert_eq!(bytes.len(), 128, "key file size");
    let x0 = deserialize_scalar(&bytes[0..32]).unwrap();
    let x1 = deserialize_scalar(&bytes[32..64]).unwrap();
    let x2 = deserialize_scalar(&bytes[64..96]).unwrap();
    let x0_blinding = deserialize_scalar(&bytes[96..128]).unwrap();
    let sk = ServerPrivateKey { x0, x1, x2, x0_blinding };
    let pk = sk.public_key();
    (sk, pk)
}

#[test]
fn dev_issuer_full_obtain_present_verify_over_http() {
    // Fresh key file per run.
    let key_path = std::env::temp_dir().join(format!("dev_issuer_test_key_{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&key_path);

    let child = Command::new(env!("CARGO_BIN_EXE_dev-issuer"))
        .arg("--arc-key")
        .arg(&key_path)
        .arg("--port")
        .arg(PORT.to_string())
        .spawn()
        .expect("spawn dev-issuer");
    let _guard = ServerGuard(child);
    wait_until_ready();

    // 1. Fetch the issuer pubkey (99 bytes) and parse it.
    let (code, pk_bytes) = http("GET", "/dev/arc/pubkey", None);
    assert_eq!(code, 200, "pubkey status");
    assert_eq!(pk_bytes.len(), 99, "pubkey length");
    let pk = ServerPublicKey::from_bytes(&pk_bytes).expect("parse served pubkey");

    // 2. Client builds a blinded credential request.
    let mut rng = rand_core::OsRng;
    let (secrets, request) = create_credential_request(REQUEST_CONTEXT, &mut rng).unwrap();
    let request_bytes = request.to_bytes();
    assert_eq!(request_bytes.len(), 226, "request length");

    // 3. POST it to the issuer → 454-byte CredentialResponse.
    let (code, resp_bytes) = http("POST", "/dev/arc/issue", Some(&request_bytes));
    assert_eq!(code, 200, "issue status");
    assert_eq!(resp_bytes.len(), 454, "response length");
    let response = CredentialResponse::from_bytes(&resp_bytes).expect("parse response");

    // 4. Finalize into a credential, using the served pubkey.
    let credential = finalize_credential(&secrets, &pk, &request, &response).expect("finalize");

    // 5. Produce a presentation.
    let limit = 16u64;
    let pres_ctx = b"http-test-session";
    let state = make_presentation_state(credential, pres_ctx, limit);
    let (_next, _nonce, presentation) = present(&state, &mut rng).expect("present");

    // 6. Verify it against the key the issuer persisted to disk.
    let (sk_file, pk_file) = load_key(&key_path);
    // The served pubkey must equal the one derived from the persisted key.
    assert_eq!(pk.to_bytes(), pk_file.to_bytes(), "served pubkey vs file-derived");
    let tag = verify_presentation(
        &sk_file,
        &pk_file,
        REQUEST_CONTEXT,
        pres_ctx,
        &presentation,
        limit,
    );
    assert!(tag.is_ok(), "verify failed: {:?}", tag.err());

    let _ = std::fs::remove_file(&key_path);
}
