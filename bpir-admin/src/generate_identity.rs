//! `bpir-admin generate-identity` — generate an Ed25519 keypair for
//! the BitcoinPIR operator-signed identity flow.
//!
//! Generates the same shape of Ed25519 key as `keygen` (the admin-auth
//! keypair) but with messaging tuned for two distinct purposes:
//!
//! 1. **Server identity key** (Tier 2) — lives on the server's
//!    filesystem and signs the per-boot ChannelManifest. Generated
//!    on the server host with `--purpose server`.
//! 2. **Operator key** (Tier 1) — lives ONLY on the operator's
//!    workstation (never the server) and signs IdentityCerts.
//!    Generated with `--purpose operator`.
//!
//! Output is interchangeable — the file format is identical (raw
//! 32-byte seed). The `--purpose` flag only changes the help text
//! and the "where does this go" hint printed to stderr, so it's harder
//! for an operator to accidentally deploy an operator key onto a
//! server.

use clap::{Args, ValueEnum};
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum IdentityPurpose {
    /// Server-side identity key. Signs per-boot ChannelManifests.
    /// Lives on disk inside the SEV guest (pir2) or on the server's
    /// filesystem (pir1). Pass to unified_server via
    /// `--identity-key-path`.
    Server,
    /// Operator's long-term Ed25519 key. Signs IdentityCerts via
    /// `bpir-admin sign-identity`. MUST NEVER touch a server host —
    /// generate on the workstation; pubkey gets published out-of-band
    /// (e.g. Nostr) so clients can pin it.
    Operator,
}

#[derive(Args, Debug)]
pub struct GenerateIdentityArgs {
    /// Write the secret key to this path. Defaults vary by purpose
    /// (see `--purpose`).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Overwrite an existing key file. Without this, refuses to
    /// clobber an existing key.
    #[arg(long)]
    pub force: bool,
    /// What this key is for. Affects help messaging only; the file
    /// format is purpose-independent.
    #[arg(long, value_enum, default_value_t = IdentityPurpose::Server)]
    pub purpose: IdentityPurpose,
}

pub fn run(args: GenerateIdentityArgs) -> Result<(), String> {
    let out = args
        .out
        .unwrap_or_else(|| default_path_for(args.purpose));

    if out.exists() && !args.force {
        return Err(format!(
            "{} already exists; rerun with --force to overwrite (you'll lose the existing privkey)",
            out.display()
        ));
    }

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create dir {}: {}", parent.display(), e))?;
    }

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("getrandom: {}", e))?;
    let sk = SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key();
    let pk_hex = hex::encode(pk.to_bytes());

    crate::keygen::write_secret_key_unix(&out, &seed)?;

    eprintln!("wrote secret key (32 bytes, mode 0600) to {}", out.display());
    eprintln!();
    match args.purpose {
        IdentityPurpose::Server => {
            eprintln!("Server identity pubkey (give this hex to the operator so they");
            eprintln!("can sign an IdentityCert with `bpir-admin sign-identity`):");
            println!("{}", pk_hex);
            eprintln!();
            eprintln!(
                "Then deploy: place the key file at the path you'll pass to unified_server's"
            );
            eprintln!(
                "  --identity-key-path, and the operator-signed cert at --identity-cert-path."
            );
        }
        IdentityPurpose::Operator => {
            eprintln!("Operator pubkey — KEEP THE SECRET KEY OFFLINE. Publish this hex");
            eprintln!("via the agreed out-of-band channel (e.g. Nostr) so clients can pin it:");
            println!("{}", pk_hex);
            eprintln!();
            eprintln!("To sign a server's identity_pubkey:");
            eprintln!(
                "  bpir-admin sign-identity --operator-key-path {} \\",
                out.display()
            );
            eprintln!("    --server-id <e.g. pir1> --identity-pubkey-hex <hex from server>  \\");
            eprintln!("    --valid-until <unix-seconds> --out <cert path>");
        }
    }
    Ok(())
}

fn default_path_for(purpose: IdentityPurpose) -> PathBuf {
    let base = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("bpir-admin")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config/bpir-admin")
    } else {
        PathBuf::from(".")
    };
    match purpose {
        IdentityPurpose::Server => base.join("server-identity.key"),
        IdentityPurpose::Operator => base.join("operator.key"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_identity_writes_32_byte_seed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id.key");
        run(GenerateIdentityArgs {
            out: Some(path.clone()),
            force: false,
            purpose: IdentityPurpose::Server,
        })
        .unwrap();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32);
        // And the pubkey loads cleanly.
        let sk = SigningKey::from_bytes(&bytes.try_into().unwrap());
        assert_eq!(sk.verifying_key().to_bytes().len(), 32);
    }

    #[test]
    fn generate_identity_refuses_overwrite_without_force() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id.key");
        run(GenerateIdentityArgs {
            out: Some(path.clone()),
            force: false,
            purpose: IdentityPurpose::Server,
        })
        .unwrap();
        let err = run(GenerateIdentityArgs {
            out: Some(path.clone()),
            force: false,
            purpose: IdentityPurpose::Server,
        })
        .unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[test]
    fn generate_identity_with_force_replaces() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("id.key");
        run(GenerateIdentityArgs {
            out: Some(path.clone()),
            force: false,
            purpose: IdentityPurpose::Operator,
        })
        .unwrap();
        let bytes1 = fs::read(&path).unwrap();
        run(GenerateIdentityArgs {
            out: Some(path.clone()),
            force: true,
            purpose: IdentityPurpose::Operator,
        })
        .unwrap();
        let bytes2 = fs::read(&path).unwrap();
        assert_ne!(bytes1, bytes2);
    }
}
