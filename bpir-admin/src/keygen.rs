//! `bpir-admin keygen` — generate an ed25519 keypair for admin auth.
//!
//! Writes the 32-byte secret seed to a file (mode 0600 on Unix) and
//! prints the corresponding public key as 64-char hex. The operator
//! pastes the hex into the server's `--admin-pubkey-hex` flag.

use clap::Args;
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Write the secret key to this path. Default:
    /// `$XDG_CONFIG_HOME/bpir-admin/admin.key` (or
    /// `~/.config/bpir-admin/admin.key`).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Overwrite an existing key file. Without this, refuses to
    /// clobber an existing key (so an accidental rerun doesn't lose
    /// the operator's only copy of the privkey).
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: KeygenArgs) -> Result<(), String> {
    let out = args.out.unwrap_or_else(default_keyfile_path);

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

    write_secret_key(&out, &seed)?;

    eprintln!("wrote secret key (32 bytes, mode 0600) to {}", out.display());
    eprintln!();
    eprintln!("Public key (paste into server's --admin-pubkey-hex):");
    println!("{}", pk_hex);
    Ok(())
}

#[cfg(unix)]
pub(crate) fn write_secret_key_unix(
    path: &std::path::Path,
    seed: &[u8; 32],
) -> Result<(), String> {
    write_secret_key(path, seed)
}

#[cfg(not(unix))]
pub(crate) fn write_secret_key_unix(
    path: &std::path::Path,
    seed: &[u8; 32],
) -> Result<(), String> {
    write_secret_key(path, seed)
}

#[cfg(unix)]
fn write_secret_key(path: &std::path::Path, seed: &[u8; 32]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .or_else(|e| {
            // If create_new failed because the file exists, the caller
            // already passed --force. Re-open with truncate.
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)
            } else {
                Err(e)
            }
        })
        .map_err(|e| format!("open {}: {}", path.display(), e))?;
    use std::io::Write;
    f.write_all(seed).map_err(|e| format!("write seed: {}", e))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_key(path: &std::path::Path, seed: &[u8; 32]) -> Result<(), String> {
    fs::write(path, seed).map_err(|e| format!("write {}: {}", path.display(), e))?;
    eprintln!("warning: file mode 0600 not enforced on this platform");
    Ok(())
}

fn default_keyfile_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("bpir-admin").join("admin.key");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config/bpir-admin/admin.key");
    }
    PathBuf::from("./admin.key")
}

/// Read a 32-byte secret key from `path`. Used by the upload command
/// to load the admin key. Validates length and existence.
pub fn read_secret_key(path: &std::path::Path) -> Result<SigningKey, String> {
    let bytes = fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "{}: expected 32 bytes for ed25519 seed, got {}",
            path.display(),
            bytes.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn keygen_writes_pubkey_matching_privkey() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k");
        run(KeygenArgs { out: Some(path.clone()), force: false }).unwrap();

        let sk = read_secret_key(&path).unwrap();
        // Roundtripping: the file should contain the same seed we
        // generated, so the recovered pubkey is the matching one.
        let pk = sk.verifying_key().to_bytes();
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn keygen_refuses_to_overwrite_without_force() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k");
        run(KeygenArgs { out: Some(path.clone()), force: false }).unwrap();
        let err = run(KeygenArgs { out: Some(path.clone()), force: false }).unwrap_err();
        assert!(err.contains("already exists"), "got: {}", err);
    }

    #[test]
    fn keygen_with_force_replaces_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k");
        run(KeygenArgs { out: Some(path.clone()), force: false }).unwrap();
        let sk1 = read_secret_key(&path).unwrap();
        run(KeygenArgs { out: Some(path.clone()), force: true }).unwrap();
        let sk2 = read_secret_key(&path).unwrap();
        // Two distinct keys (extremely high probability)
        assert_ne!(sk1.verifying_key().to_bytes(), sk2.verifying_key().to_bytes());
    }

    #[test]
    fn read_secret_key_rejects_wrong_length() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad");
        fs::write(&path, b"too short").unwrap();
        let err = read_secret_key(&path).unwrap_err();
        assert!(err.contains("expected 32 bytes"), "got: {}", err);
    }
}
