//! `bpir-admin upload` — push a DB directory to a server.
//!
//! Flow:
//! 1. Read the operator's ed25519 secret key from disk.
//! 2. Walk `<local-dir>` recursively, hash every file (excluding any
//!    `MANIFEST.toml` already in the dir), build a deterministic
//!    `MANIFEST.toml` content blob in memory.
//! 3. Connect WSS, run admin auth (challenge/response).
//! 4. Send `REQ_ADMIN_DB_UPLOAD_BEGIN { name, manifest_toml }`.
//! 5. For each file in sorted order, stream it as
//!    `REQ_ADMIN_DB_UPLOAD_CHUNK` messages of ≤ `CHUNK_SIZE` bytes.
//! 6. Send `REQ_ADMIN_DB_UPLOAD_FINALIZE` and display the returned
//!    `manifest_root`.
//! 7. Unless `--no-activate`, send `REQ_ADMIN_DB_ACTIVATE { name,
//!    target_path }` and remind the operator to restart the server.

use clap::Args;
use pir_core::merkle::sha256;
use pir_sdk_client::admin::{
    activate as send_activate, authenticate, upload_begin, upload_chunk, upload_finalize,
    AuthOutcome,
};
use pir_sdk_client::WsConnection;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::keygen::read_secret_key;

/// Bytes per CHUNK message. 4 MiB stays well under the 256 MiB
/// WS-frame ceiling and gives a useful progress cadence on multi-GB
/// uploads (~1500 chunks per 6 GB).
const CHUNK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Args, Debug)]
pub struct UploadArgs {
    /// Logical name for this upload (also the staging-dir name on
    /// the server). Must be alphanumeric + `_-.`.
    pub name: String,

    /// Local directory to upload. Every file (recursively) gets
    /// hashed and streamed. `MANIFEST.toml` in the dir is ignored
    /// (the tool generates a fresh one).
    pub local_dir: PathBuf,

    /// Server-side target path (relative to the server's data_root)
    /// where ACTIVATE renames the staged dir, e.g.
    /// `checkpoints/944000` or `deltas/940611_944000`.
    #[arg(long)]
    pub target_path: String,

    /// WebSocket URL of the server, e.g. `wss://weikeng2.bitcoinpir.org`.
    #[arg(long)]
    pub server: String,

    /// Path to the ed25519 secret key file (32 bytes raw). Default:
    /// `$XDG_CONFIG_HOME/bpir-admin/admin.key`.
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Skip the ACTIVATE step (just upload + verify, leave the data
    /// in the staging dir for manual inspection / activation).
    #[arg(long)]
    pub no_activate: bool,
}

pub async fn run(args: UploadArgs) -> Result<(), String> {
    let key_path = args.key.unwrap_or_else(default_keyfile);
    let sk = read_secret_key(&key_path)?;

    // Walk + hash the dir locally.
    let manifest_files = walk_and_hash(&args.local_dir)?;
    if manifest_files.is_empty() {
        return Err(format!("no files to upload in {}", args.local_dir.display()));
    }
    let manifest_toml = render_manifest_toml(&manifest_files);
    let local_root = sha256(&manifest_toml);
    let total_bytes: u64 = manifest_files
        .iter()
        .map(|(rel, _)| fs::metadata(args.local_dir.join(rel)).map(|m| m.len()).unwrap_or(0))
        .sum();
    eprintln!(
        "manifest: {} files, {} bytes total, root={}",
        manifest_files.len(),
        total_bytes,
        hex::encode(local_root)
    );

    // Connect + auth.
    let mut conn = WsConnection::connect(&args.server)
        .await
        .map_err(|e| format!("connect to {}: {}", args.server, e))?;
    eprintln!("connected to {}", args.server);

    match authenticate(&mut conn, &sk).await.map_err(|e| e.to_string())? {
        AuthOutcome::Ok => eprintln!("authenticated"),
        AuthOutcome::Rejected { msg } => {
            return Err(format!("server rejected admin auth: {}", msg));
        }
    }

    // BEGIN
    let ack = upload_begin(&mut conn, &args.name, &manifest_toml)
        .await
        .map_err(|e| e.to_string())?;
    if !ack.ok {
        return Err(format!("BEGIN rejected: {}", ack.msg));
    }

    // Stream every file as CHUNKs.
    let mut bytes_sent: u64 = 0;
    for (rel, _expected_hash) in &manifest_files {
        let path = args.local_dir.join(rel);
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        let mut offset: u64 = 0;
        for chunk in bytes.chunks(CHUNK_SIZE) {
            let ack = upload_chunk(&mut conn, &args.name, rel, offset, chunk)
                .await
                .map_err(|e| e.to_string())?;
            if !ack.ok {
                return Err(format!("CHUNK rejected for {} @ {}: {}", rel, offset, ack.msg));
            }
            offset += chunk.len() as u64;
            bytes_sent += chunk.len() as u64;
        }
        eprintln!("  uploaded {} ({:.1} MB) — total {:.1}/{:.1} MB",
                  rel,
                  bytes.len() as f64 / 1_048_576.0,
                  bytes_sent as f64 / 1_048_576.0,
                  total_bytes as f64 / 1_048_576.0);
    }

    // FINALIZE
    let fin = upload_finalize(&mut conn, &args.name).await.map_err(|e| e.to_string())?;
    if !fin.ok {
        return Err(format!("FINALIZE failed: {}", fin.msg));
    }
    eprintln!("FINALIZE: {}", fin.msg);
    let server_root_hex = hex::encode(fin.manifest_root);
    eprintln!("server-side manifest_root: {}", server_root_hex);

    // Cross-check: the root the SERVER computed should equal what we
    // hashed locally. If not, the wire bytes diverged from disk.
    if fin.manifest_root != local_root {
        return Err(format!(
            "manifest_root mismatch (local {} vs server {}) — upload corrupted",
            hex::encode(local_root),
            server_root_hex,
        ));
    }
    eprintln!("✓ local + server manifest roots agree");

    if args.no_activate {
        eprintln!("(skipping ACTIVATE per --no-activate; staged at .staging/{})", args.name);
        return Ok(());
    }

    // ACTIVATE
    let ack = send_activate(&mut conn, &args.name, &args.target_path)
        .await
        .map_err(|e| e.to_string())?;
    if !ack.ok {
        return Err(format!("ACTIVATE failed: {}", ack.msg));
    }
    eprintln!("ACTIVATE: {}", ack.msg);
    eprintln!();
    eprintln!("Done. Restart the server (e.g. `systemctl restart pir-online`) to load.");
    Ok(())
}

/// Walk `dir` recursively, collect every regular file's relative path
/// + SHA-256 hex. `MANIFEST.toml` (top-level or nested) is excluded
/// so a stale one doesn't end up in the manifest of itself. Returns
/// entries sorted by path so the resulting TOML is deterministic.
pub(crate) fn walk_and_hash(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    walk_recursive(dir, dir, &mut found)?;
    Ok(found.into_iter().collect())
}

fn walk_recursive(
    root: &Path,
    cur: &Path,
    out: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let entries =
        fs::read_dir(cur).map_err(|e| format!("read_dir {}: {}", cur.display(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("entry: {}", e))?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|e| format!("file_type: {}", e))?;
        if ft.is_dir() {
            walk_recursive(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("dir is descendant of root")
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "MANIFEST.toml" || rel.ends_with("/MANIFEST.toml") {
                continue;
            }
            let bytes = fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
            let h = sha256(&bytes);
            out.insert(rel, hex::encode(h));
        }
    }
    Ok(())
}

/// Render the same MANIFEST.toml format `scripts/build_db_manifest.sh`
/// produces, so server-side verification works regardless of which
/// producer was used.
pub(crate) fn render_manifest_toml(files: &[(String, String)]) -> Vec<u8> {
    let mut s = String::new();
    s.push_str("# Auto-generated by bpir-admin upload — do not hand-edit.\n");
    s.push_str("# Files: ");
    s.push_str(&files.len().to_string());
    s.push_str("\n\n");
    s.push_str("[manifest]\n");
    s.push_str("version = 1\n");
    // No `generated_at` — keeping the manifest fully deterministic for
    // identical input dirs (so two runs over the same files produce
    // byte-identical bytes and thus the same manifest_root).
    s.push('\n');
    s.push_str("[files]\n");
    for (path, hash) in files {
        s.push_str(&format!("\"{}\" = \"{}\"\n", path, hash));
    }
    s.into_bytes()
}

fn default_keyfile() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("bpir-admin").join("admin.key");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config/bpir-admin/admin.key");
    }
    PathBuf::from("./admin.key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn walk_and_hash_returns_sorted_files() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("z.bin"), b"z-content").unwrap();
        fs::write(dir.path().join("a.bin"), b"a-content").unwrap();
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/m.bin"), b"m-content").unwrap();

        let result = walk_and_hash(dir.path()).unwrap();
        assert_eq!(result.len(), 3);
        // BTreeMap iteration is sorted by path
        assert_eq!(result[0].0, "a.bin");
        assert_eq!(result[1].0, "sub/m.bin");
        assert_eq!(result[2].0, "z.bin");
        // Hash known: sha256("a-content") begins with...
        assert_eq!(result[0].1.len(), 64);
    }

    #[test]
    fn walk_and_hash_excludes_manifest_toml() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.bin"), b"x").unwrap();
        fs::write(dir.path().join("MANIFEST.toml"), b"old stale").unwrap();

        let result = walk_and_hash(dir.path()).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "a.bin");
    }

    #[test]
    fn render_manifest_is_deterministic() {
        let files = vec![
            ("a.bin".to_string(), hex::encode([1u8; 32])),
            ("sub/b.bin".to_string(), hex::encode([2u8; 32])),
        ];
        let m1 = render_manifest_toml(&files);
        let m2 = render_manifest_toml(&files);
        assert_eq!(m1, m2);
        // Roundtrip parseable
        let parsed: toml::Value =
            toml::from_str(std::str::from_utf8(&m1).unwrap()).unwrap();
        assert_eq!(parsed["manifest"]["version"].as_integer(), Some(1));
    }

    #[test]
    fn render_manifest_round_trips_through_pir_runtime_core_parser() {
        // The whole point: bytes we emit must parse and verify cleanly
        // via the same parser the server will run on them.
        let dir = tempdir().unwrap();
        let files: &[(&str, &[u8])] = &[("a.bin", b"hello"), ("sub/b.bin", b"world")];
        for (name, content) in files {
            let p = dir.path().join(name);
            fs::create_dir_all(p.parent().unwrap()).ok();
            fs::write(&p, content).unwrap();
        }

        let entries = walk_and_hash(dir.path()).unwrap();
        let manifest_bytes = render_manifest_toml(&entries);

        // Write to dir + run the server-side verifier.
        fs::write(dir.path().join("MANIFEST.toml"), &manifest_bytes).unwrap();
        let result =
            pir_runtime_core::manifest::DbManifest::load_and_verify(dir.path()).unwrap();
        let (_m, root) = result.expect("Some");
        assert_eq!(root, sha256(&manifest_bytes));
    }
}
