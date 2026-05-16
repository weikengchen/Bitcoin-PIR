//! `bpir-admin channel-test` — end-to-end smoke test of the encrypted
//! channel against a running unified_server.
//!
//! Sequence:
//!   1. Connect raw WSS to the server.
//!   2. REQ_ATTEST → recover `server_static_pub` + verify the SEV-SNP
//!      REPORT_DATA binding (V2 layout). Fail if the binding is broken
//!      or the server reports no channel pubkey.
//!   3. Wrap the connection with `pir_sdk_client::channel::establish`
//!      — this runs REQ_HANDSHAKE and derives the session key.
//!   4. Send a REQ_PING through the now-encrypted channel and confirm
//!      the response decrypts to RESP_PONG (0x00).
//!   5. Send a REQ_GET_INFO through the channel and confirm the
//!      response decrypts to a valid RESP_INFO frame.
//!
//! The test exits 0 on success, non-zero with a diagnostic on failure.
//!
//! ## What this proves (after Slice E deploys)
//!
//! - The handshake protocol works against the production server.
//! - The session key derivation agrees on both sides.
//! - Per-frame AEAD seal/open work bidirectionally.
//! - cloudflared between us and unified_server saw only ciphertext for
//!   frames 2+ — the only cleartext frames were the attest, the
//!   handshake itself, and the response to handshake. (Verifying
//!   cloudflared blindness from outside requires packet capture; this
//!   test verifies the protocol.)
//!
//! ## What this does NOT prove
//!
//! - That the AMD VCEK chain validates the SEV-SNP report (Slice D).
//! - That the browser-side wiring works (Slice C.2).
//! - That cloudflared can't be exploited to MITM (out of scope —
//!   that's the AMD-attested chip's job).

use clap::Args;
use pir_sdk_client::attest::{attest, SevStatus};
use pir_sdk_client::channel::establish;
// `roundtrip` is a trait method on PirTransport — bring it into scope
// so we can call it on the SecureChannelTransport returned by `establish`.
use pir_sdk_client::PirTransport;
use pir_sdk_client::WsConnection;

#[derive(Args, Debug)]
pub struct ChannelTestArgs {
    /// Server WebSocket URL (e.g. `wss://weikeng2.bitcoinpir.org`).
    pub server_url: String,
    /// Operator-pinned 64-hex-char SHA-256 fingerprint of the AMD ARK
    /// (Root Key) certificate. When set + the server bundles a VCEK
    /// chain, runs full Slice D chain validation
    /// (ARK→ASK→VCEK + report-sig). Skip to test only V2 binding.
    #[arg(long = "expect-ark-fingerprint", value_name = "HEX64")]
    pub expect_ark_fingerprint: Option<String>,
}

pub async fn run(args: ChannelTestArgs) -> Result<(), i32> {
    let url = &args.server_url;
    println!("Server URL:     {}", url);

    // ── Step 1: connect raw ─────────────────────────────────────────
    let mut conn = match WsConnection::connect(url).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect: {}", e);
            return Err(1);
        }
    };

    // ── Step 2: attest + extract server_static_pub ──────────────────
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("OS RNG must work");
    let v = match attest(&mut conn, nonce).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("attest: {}", e);
            return Err(2);
        }
    };
    println!("attest:         {:?}", v.sev_status);
    if v.sev_status != SevStatus::ReportDataMatch && v.sev_status != SevStatus::NoSevHost {
        eprintln!("attest binding broken: {:?}", v.sev_status);
        return Err(3);
    }
    let server_static_pub = v.response.server_static_pub;
    if server_static_pub == [0u8; 32] {
        eprintln!(
            "server has no X25519 channel key (server_static_pub is all-zero) — \
             upgrade unified_server to enable the encrypted channel"
        );
        return Err(4);
    }
    println!(
        "server channel pubkey: {}",
        hex::encode(server_static_pub)
    );

    // ── Optional Slice D chain validation ──────────────────────────
    let chain_present = !v.response.ark_pem.is_empty()
        && !v.response.ask_pem.is_empty()
        && !v.response.vcek_pem.is_empty();
    match (&args.expect_ark_fingerprint, chain_present) {
        (None, false) => {
            println!("vcek chain:     <none> (skipped, no --expect-ark-fingerprint)");
        }
        (None, true) => {
            println!(
                "vcek chain:     bundled but UNVERIFIED (pass --expect-ark-fingerprint to validate)"
            );
        }
        (Some(_), false) => {
            eprintln!(
                "--expect-ark-fingerprint set but server didn't bundle a chain — \
                 deploy `--vcek-dir` on the server first"
            );
            return Err(10);
        }
        (Some(hex_str), true) => {
            let pin: [u8; 32] = match hex::decode(hex_str.trim()) {
                Ok(b) if b.len() == 32 => b.try_into().unwrap(),
                _ => {
                    eprintln!("--expect-ark-fingerprint must be 64 hex chars (32 bytes)");
                    return Err(11);
                }
            };
            match pir_attest_verify::verify_chain(
                &v.response.ark_pem,
                &v.response.ask_pem,
                &v.response.vcek_pem,
                Some(pin),
            ) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("chain validation failed: {}", e);
                    return Err(12);
                }
            }
            match pir_attest_verify::verify_report_against_vcek(
                &v.response.sev_snp_report,
                &v.response.vcek_pem,
            ) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("report-sig validation failed: {}", e);
                    return Err(13);
                }
            }
            println!(
                "vcek chain:     ✓ verified (ARK→ASK→VCEK + report sig validate; ARK fingerprint matches pin)"
            );
        }
    }

    // ── Step 3: handshake ───────────────────────────────────────────
    let mut eph_seed = [0u8; 32];
    getrandom::getrandom(&mut eph_seed).expect("OS RNG must work");
    let mut hs_nonce = [0u8; 32];
    getrandom::getrandom(&mut hs_nonce).expect("OS RNG must work");

    let mut secure = match establish(conn, server_static_pub, eph_seed, hs_nonce).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("handshake: {}", e);
            return Err(5);
        }
    };
    println!("handshake:      ok (channel established)");

    // ── Step 4: encrypted REQ_PING → RESP_PONG ──────────────────────
    // REQ_PING = 0x00, no body.
    // Wire: [4B len=1][REQ_PING=0x00]
    let ping_req = {
        let mut r = Vec::with_capacity(5);
        r.extend_from_slice(&1u32.to_le_bytes());
        r.push(0x00);
        r
    };
    let pong = match secure.roundtrip(&ping_req).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ping (encrypted): {}", e);
            return Err(6);
        }
    };
    if pong.is_empty() || pong[0] != 0x00 {
        eprintln!(
            "expected RESP_PONG (0x00) inside encrypted reply, got {:02x?}",
            pong.first()
        );
        return Err(7);
    }
    println!("ping/pong:      ok (encrypted roundtrip)");

    // ── Step 5: encrypted REQ_GET_INFO → RESP_INFO ──────────────────
    // REQ_GET_INFO = 0x01, no body.
    let info_req = {
        let mut r = Vec::with_capacity(5);
        r.extend_from_slice(&1u32.to_le_bytes());
        r.push(0x01);
        r
    };
    let info_resp = match secure.roundtrip(&info_req).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("get_info (encrypted): {}", e);
            return Err(8);
        }
    };
    if info_resp.is_empty() || info_resp[0] != 0x01 {
        eprintln!(
            "expected RESP_INFO (0x01) inside encrypted reply, got {:02x?}",
            info_resp.first()
        );
        return Err(9);
    }
    println!(
        "get_info:       ok (encrypted, payload {} bytes after variant)",
        info_resp.len() - 1
    );

    println!();
    println!("✓ end-to-end encrypted channel works against {}", url);
    Ok(())
}
