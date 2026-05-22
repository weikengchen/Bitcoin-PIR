//! `bpir-admin sign-identity` — operator signs an IdentityCert.
//!
//! Runs OFFLINE on the operator's workstation. Reads the operator's
//! long-term Ed25519 secret key from disk, takes the server's
//! identity_pubkey (hex) + server_id + validity window as inputs, and
//! produces a canonically-encoded [`pir_identity::IdentityCert`] blob.
//!
//! The blob is then deployed to the server (path passed to
//! unified_server via `--identity-cert-path`) alongside the matching
//! server-identity key file (`--identity-key-path`).
//!
//! Verifying the signature after generation is mandatory — catches
//! the case where the operator typo'd the hex pubkey, since the cert
//! signing wouldn't catch that (it just bakes whatever bytes you gave
//! it into the preimage).
//!
//! [HUMAN-decided 2026-05-21] No default validity window: the operator
//! MUST pass `--valid-until` explicitly. Pass `0` for an indefinite
//! upper bound if you actually want that.

use clap::Args;
use ed25519_dalek::SigningKey;
use pir_identity::{sign_identity_cert, IdentityCert, ED25519_PUBKEY_LEN};
use std::fs;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct SignIdentityArgs {
    /// Path to the operator's Ed25519 secret key (raw 32-byte seed,
    /// from `bpir-admin generate-identity --purpose operator`).
    #[arg(long)]
    pub operator_key_path: PathBuf,

    /// Server identifier this cert is endorsed for, e.g. "pir1" or
    /// "pir2". MUST match the value the server will start with via
    /// `--identity-server-id`.
    #[arg(long)]
    pub server_id: String,

    /// Hex-encoded (64 chars / 32 bytes) Ed25519 public key of the
    /// server's identity keypair (from `bpir-admin generate-identity
    /// --purpose server`'s stdout).
    #[arg(long)]
    pub identity_pubkey_hex: String,

    /// Earliest unix-seconds timestamp at which the cert is valid.
    /// Default 0 (no lower bound).
    #[arg(long, default_value_t = 0)]
    pub valid_from: i64,

    /// Latest unix-seconds timestamp at which the cert is valid.
    /// REQUIRED — the operator MUST think about cert expiry. Pass
    /// 0 for "no upper bound" (indefinite), but that's a deliberate
    /// choice, not a default.
    #[arg(long)]
    pub valid_until: i64,

    /// Write the encoded cert to this path. Default:
    /// `./<server_id>.cert`.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Overwrite an existing cert file.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: SignIdentityArgs) -> Result<(), String> {
    if args.valid_from < 0 {
        return Err("--valid-from must be non-negative".into());
    }
    if args.valid_until < 0 {
        return Err("--valid-until must be non-negative".into());
    }
    if args.valid_until != 0 && args.valid_until <= args.valid_from {
        return Err(format!(
            "--valid-until ({}) must be 0 (indefinite) or strictly greater than --valid-from ({})",
            args.valid_until, args.valid_from
        ));
    }

    let operator_sk = crate::keygen::read_secret_key(&args.operator_key_path)?;

    let identity_pubkey = parse_pubkey_hex(&args.identity_pubkey_hex)?;
    // Reject the all-zero key — that's the sentinel for "no channel
    // key yet" elsewhere in the protocol, never a legitimate pubkey.
    if identity_pubkey.iter().all(|b| *b == 0) {
        return Err("identity_pubkey is all-zero — refusing to sign".into());
    }

    let cert = sign_identity_cert(
        &operator_sk,
        &args.server_id,
        identity_pubkey,
        args.valid_from,
        args.valid_until,
    );

    // Sanity-verify what we just signed. Catches a typo'd
    // `--identity-pubkey-hex` if it accidentally bakes the wrong
    // operator pubkey into the preimage — Ed25519 signing wouldn't
    // catch it (any bytes can be a "preimage"), but this round-trip
    // through `verify()` exercises the same path the server / clients
    // will run.
    cert.verify()
        .map_err(|e| format!("internal: signed cert fails to verify: {}", e))?;

    let encoded = cert.encode();
    // And decode roundtrips — catches future encode/decode drift.
    let decoded = IdentityCert::decode(&encoded)
        .map_err(|e| format!("internal: signed cert fails to decode: {}", e))?;
    if decoded != cert {
        return Err("internal: cert decode roundtrip diverged".into());
    }

    let out = args
        .out
        .unwrap_or_else(|| PathBuf::from(format!("{}.cert", args.server_id)));
    if out.exists() && !args.force {
        return Err(format!(
            "{} already exists; rerun with --force to overwrite",
            out.display()
        ));
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create dir {}: {}", parent.display(), e))?;
        }
    }
    fs::write(&out, &encoded).map_err(|e| format!("write {}: {}", out.display(), e))?;

    let op_pk = operator_sk.verifying_key().to_bytes();
    eprintln!("wrote IdentityCert ({} bytes) to {}", encoded.len(), out.display());
    eprintln!("  server_id:        {}", args.server_id);
    eprintln!("  identity_pubkey:  {}", hex::encode(identity_pubkey));
    eprintln!("  operator_pubkey:  {}", hex::encode(op_pk));
    eprintln!("  valid_from:       {}", args.valid_from);
    eprintln!(
        "  valid_until:      {}{}",
        args.valid_until,
        if args.valid_until == 0 {
            " (indefinite)"
        } else {
            ""
        }
    );
    Ok(())
}

fn parse_pubkey_hex(hex: &str) -> Result<[u8; ED25519_PUBKEY_LEN], String> {
    let trimmed = hex.trim();
    if trimmed.len() != ED25519_PUBKEY_LEN * 2 {
        return Err(format!(
            "identity-pubkey-hex must be {} hex chars ({} bytes), got {}",
            ED25519_PUBKEY_LEN * 2,
            ED25519_PUBKEY_LEN,
            trimmed.len()
        ));
    }
    let mut out = [0u8; ED25519_PUBKEY_LEN];
    ::hex::decode_to_slice(trimmed, &mut out)
        .map_err(|e| format!("identity-pubkey-hex not valid hex: {}", e))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    fn write_op_key(dir: &std::path::Path) -> (PathBuf, SigningKey) {
        let path = dir.join("op.key");
        keygen::run(keygen::KeygenArgs {
            out: Some(path.clone()),
            force: false,
        })
        .unwrap();
        let sk = keygen::read_secret_key(&path).unwrap();
        (path, sk)
    }

    fn id_pubkey_hex(seed: u8) -> ([u8; 32], String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (pk, hex::encode(pk))
    }

    #[test]
    fn sign_identity_produces_verifiable_cert() {
        let dir = tempdir().unwrap();
        let (op_key_path, op_sk) = write_op_key(dir.path());
        let (_id_pk, id_pk_hex) = id_pubkey_hex(0x42);
        let cert_path = dir.path().join("pir1.cert");

        run(SignIdentityArgs {
            operator_key_path: op_key_path,
            server_id: "pir1".into(),
            identity_pubkey_hex: id_pk_hex,
            valid_from: 0,
            valid_until: 1_900_000_000,
            out: Some(cert_path.clone()),
            force: false,
        })
        .unwrap();

        let bytes = fs::read(&cert_path).unwrap();
        let cert = IdentityCert::decode(&bytes).unwrap();
        cert.verify().unwrap();
        assert_eq!(
            cert.operator_pubkey,
            op_sk.verifying_key().to_bytes()
        );
        assert_eq!(cert.server_id, "pir1");
        assert_eq!(cert.valid_until, 1_900_000_000);
    }

    #[test]
    fn sign_identity_rejects_short_hex() {
        let dir = tempdir().unwrap();
        let (op_key_path, _) = write_op_key(dir.path());
        let err = run(SignIdentityArgs {
            operator_key_path: op_key_path,
            server_id: "pir1".into(),
            identity_pubkey_hex: "abc123".into(),
            valid_from: 0,
            valid_until: 100,
            out: Some(dir.path().join("c")),
            force: false,
        })
        .unwrap_err();
        assert!(err.contains("must be 64 hex chars"));
    }

    #[test]
    fn sign_identity_rejects_all_zero_pubkey() {
        let dir = tempdir().unwrap();
        let (op_key_path, _) = write_op_key(dir.path());
        let zero_hex = "0".repeat(64);
        let err = run(SignIdentityArgs {
            operator_key_path: op_key_path,
            server_id: "pir1".into(),
            identity_pubkey_hex: zero_hex,
            valid_from: 0,
            valid_until: 100,
            out: Some(dir.path().join("c")),
            force: false,
        })
        .unwrap_err();
        assert!(err.contains("all-zero"));
    }

    #[test]
    fn sign_identity_rejects_invalid_validity_window() {
        let dir = tempdir().unwrap();
        let (op_key_path, _) = write_op_key(dir.path());
        let (_, id_hex) = id_pubkey_hex(0x42);
        // valid_until < valid_from (and != 0)
        let err = run(SignIdentityArgs {
            operator_key_path: op_key_path,
            server_id: "pir1".into(),
            identity_pubkey_hex: id_hex,
            valid_from: 200,
            valid_until: 100,
            out: Some(dir.path().join("c")),
            force: false,
        })
        .unwrap_err();
        assert!(err.contains("must be 0 (indefinite)"));
    }
}
