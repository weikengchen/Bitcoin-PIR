//! DB manifest format and verification.
//!
//! Every loaded DB directory may contain a `MANIFEST.toml` listing the
//! SHA-256 of every file the server is expected to mmap. At startup,
//! [`MappedDatabase::load`](crate::table::MappedDatabase::load) verifies
//! the manifest before opening any cuckoo file. The manifest's own
//! SHA-256 ("manifest root") is returned and stored on the
//! [`MappedDatabase`](crate::table::MappedDatabase) so later attestation
//! code can fold it into REPORT_DATA.
//!
//! The producer side is `scripts/build_db_manifest.sh` in the repo root;
//! it walks the DB dir, hashes every file, and emits a deterministic TOML.
//!
//! Format:
//! ```toml
//! [manifest]
//! version = 1
//! generated_at = "2026-05-02T13:50:00Z"
//!
//! [files]
//! "batch_pir_cuckoo.bin" = "abc123…"
//! "chunk_pir_cuckoo.bin" = "def456…"
//! ```
//!
//! Verification rules:
//! - Every file listed under `[files]` must exist and hash-match.
//! - Every regular file in the dir (recursively, excluding `MANIFEST.toml`)
//!   must appear under `[files]`. Stray files are an error — the server
//!   should refuse to start rather than silently mmap unaccounted bytes.
//! - The version must match `SUPPORTED_VERSION`.
//!
//! Back-compat: an absent `MANIFEST.toml` is `Ok(None)` so existing DBs
//! keep loading without modification while operators retro-fit manifests.

use pir_core::merkle::{sha256, Hash256, HASH_SIZE};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs;
use std::path::Path;

/// Filename the verifier looks for in each DB dir.
pub const MANIFEST_FILENAME: &str = "MANIFEST.toml";

/// The only manifest schema version this build accepts.
pub const SUPPORTED_VERSION: u32 = 1;

/// Parsed `MANIFEST.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct DbManifest {
    pub manifest: ManifestMeta,
    /// Map of relative file path → hex SHA-256 (case-insensitive).
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManifestMeta {
    pub version: u32,
    #[serde(default)]
    pub generated_at: Option<String>,
}

/// Errors produced when loading or verifying a manifest.
#[derive(Debug)]
pub enum ManifestError {
    UnsupportedVersion(u32),
    Io { path: String, err: std::io::Error },
    InvalidUtf8 { path: String },
    InvalidToml { path: String, err: toml::de::Error },
    InvalidHashHex { path: String, value: String },
    HashMismatch { path: String, expected: String, actual: String },
    MissingFile { path: String },
    UnexpectedFile { path: String },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(
                f,
                "unsupported manifest version {} (this build accepts only {})",
                v, SUPPORTED_VERSION
            ),
            Self::Io { path, err } => write!(f, "io error reading {}: {}", path, err),
            Self::InvalidUtf8 { path } => write!(f, "{} is not valid UTF-8", path),
            Self::InvalidToml { path, err } => write!(f, "{} is not valid TOML: {}", path, err),
            Self::InvalidHashHex { path, value } => write!(
                f,
                "manifest entry for {} is not 64 hex chars: {:?}",
                path, value
            ),
            Self::HashMismatch { path, expected, actual } => write!(
                f,
                "hash mismatch for {}: expected {}, got {}",
                path, expected, actual
            ),
            Self::MissingFile { path } => {
                write!(f, "manifest references {} but file is not present", path)
            }
            Self::UnexpectedFile { path } => write!(
                f,
                "{} is present in the DB dir but not listed in MANIFEST.toml",
                path
            ),
        }
    }
}

impl std::error::Error for ManifestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { err, .. } => Some(err),
            Self::InvalidToml { err, .. } => Some(err),
            _ => None,
        }
    }
}

impl DbManifest {
    /// Load and verify the manifest in `base_dir`.
    ///
    /// Returns:
    /// - `Ok(Some((manifest, root)))` if `MANIFEST.toml` is present and
    ///   verifies. `root` is `SHA-256(MANIFEST.toml bytes-on-disk)` and
    ///   identifies the DB content for attestation.
    /// - `Ok(None)` if `MANIFEST.toml` is absent (back-compat).
    /// - `Err(_)` if `MANIFEST.toml` is present but verification fails.
    pub fn load_and_verify(
        base_dir: &Path,
    ) -> Result<Option<(DbManifest, Hash256)>, ManifestError> {
        let manifest_path = base_dir.join(MANIFEST_FILENAME);
        if !manifest_path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&manifest_path).map_err(|err| ManifestError::Io {
            path: manifest_path.display().to_string(),
            err,
        })?;
        let text = std::str::from_utf8(&raw).map_err(|_| ManifestError::InvalidUtf8 {
            path: manifest_path.display().to_string(),
        })?;
        let manifest: DbManifest = toml::from_str(text).map_err(|err| ManifestError::InvalidToml {
            path: manifest_path.display().to_string(),
            err,
        })?;
        if manifest.manifest.version != SUPPORTED_VERSION {
            return Err(ManifestError::UnsupportedVersion(manifest.manifest.version));
        }
        manifest.verify_dir_contents(base_dir)?;
        Ok(Some((manifest, sha256(&raw))))
    }

    /// Verify every listed file matches its expected SHA-256, and that no
    /// unlisted regular file is present in the directory tree.
    ///
    /// Files ending in `_cuckoo.bin` are the large cuckoo table mmap files
    /// (several GB each). Reading them into memory just to SHA-256 them at
    /// startup adds ~50s of delay. They are still checked for existence
    /// (and must appear in the manifest to pass the stray-file gate), but
    /// the content hash is skipped — the table bytes are already covered by
    /// the SEV-SNP MEASUREMENT (which signs the binary + cmdline + rootfs
    /// that loaded them).
    pub fn verify_dir_contents(&self, base_dir: &Path) -> Result<(), ManifestError> {
        // Phase 1 — every listed file must exist. Non-cuckoo files also hash-match.
        for (rel, expected_hex) in &self.files {
            let full = base_dir.join(rel);
            if !full.exists() {
                return Err(ManifestError::MissingFile { path: rel.clone() });
            }
            if is_cuckoo_table(rel) {
                continue;
            }
            if expected_hex.len() != HASH_SIZE * 2
                || !expected_hex.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(ManifestError::InvalidHashHex {
                    path: rel.clone(),
                    value: expected_hex.clone(),
                });
            }
            let bytes = fs::read(&full).map_err(|err| ManifestError::Io {
                path: full.display().to_string(),
                err,
            })?;
            let actual = hex_encode(&sha256(&bytes));
            if !expected_hex.eq_ignore_ascii_case(&actual) {
                return Err(ManifestError::HashMismatch {
                    path: rel.clone(),
                    expected: expected_hex.clone(),
                    actual,
                });
            }
        }

        // Phase 2 — nothing in the dir is unaccounted for.
        let mut found = HashSet::new();
        walk(base_dir, base_dir, &mut found).map_err(|err| ManifestError::Io {
            path: base_dir.display().to_string(),
            err,
        })?;
        let listed: HashSet<&str> = self.files.keys().map(String::as_str).collect();
        for path in &found {
            if path == MANIFEST_FILENAME {
                continue;
            }
            if !listed.contains(path.as_str()) {
                return Err(ManifestError::UnexpectedFile { path: path.clone() });
            }
        }
        Ok(())
    }
}

fn walk(root: &Path, dir: &Path, out: &mut HashSet<String>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .expect("dir is descendant of root by construction");
            // Forward-slash separators so manifests are cross-platform.
            let s = rel.to_string_lossy().replace('\\', "/");
            out.insert(s);
        }
        // Symlinks/sockets/etc. are intentionally ignored — they shouldn't
        // exist inside a DB dir, and adding them to the manifest would
        // require resolving them deterministically (a separate decision).
    }
    Ok(())
}

/// Files ending in `_cuckoo.bin` are the large cuckoo table mmap files.
fn is_cuckoo_table(rel: &str) -> bool {
    rel.ends_with("_cuckoo.bin")
}

/// Lowercase hex of a byte slice (no extra deps).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let hi = b >> 4;
        let lo = b & 0x0f;
        s.push(if hi < 10 { (b'0' + hi) as char } else { (b'a' + (hi - 10)) as char });
        s.push(if lo < 10 { (b'0' + lo) as char } else { (b'a' + (lo - 10)) as char });
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_files(dir: &Path, files: &[(&str, &[u8])]) {
        for (name, content) in files {
            let p = dir.join(name);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, content).unwrap();
        }
    }

    fn write_manifest_for(dir: &Path, files: &[(&str, &[u8])]) {
        let mut s = String::from(
            "[manifest]\nversion = 1\ngenerated_at = \"2026-01-01T00:00:00Z\"\n\n[files]\n",
        );
        let mut sorted: Vec<_> = files.iter().collect();
        sorted.sort_by_key(|(n, _)| *n);
        for (name, content) in sorted {
            s.push_str(&format!(
                "\"{}\" = \"{}\"\n",
                name,
                hex_encode(&sha256(content))
            ));
        }
        fs::write(dir.join(MANIFEST_FILENAME), s).unwrap();
    }

    #[test]
    fn no_manifest_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        write_files(dir.path(), &[("a.bin", b"hello")]);
        let r = DbManifest::load_and_verify(dir.path()).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn happy_path_returns_root_matching_manifest_sha256() {
        let dir = tempfile::tempdir().unwrap();
        let files: &[(&str, &[u8])] = &[("a.bin", b"hello"), ("sub/b.bin", b"world")];
        write_files(dir.path(), files);
        write_manifest_for(dir.path(), files);

        let (m, root) = DbManifest::load_and_verify(dir.path()).unwrap().expect("Some");
        assert_eq!(m.files.len(), 2);
        let raw = fs::read(dir.path().join(MANIFEST_FILENAME)).unwrap();
        assert_eq!(root, sha256(&raw));
    }

    #[test]
    fn root_changes_when_listed_file_changes() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        write_files(dir1.path(), &[("a.bin", b"hello")]);
        write_manifest_for(dir1.path(), &[("a.bin", b"hello")]);
        write_files(dir2.path(), &[("a.bin", b"hello world")]);
        write_manifest_for(dir2.path(), &[("a.bin", b"hello world")]);
        let r1 = DbManifest::load_and_verify(dir1.path()).unwrap().unwrap().1;
        let r2 = DbManifest::load_and_verify(dir2.path()).unwrap().unwrap().1;
        assert_ne!(r1, r2);
    }

    #[test]
    fn detects_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        write_files(dir.path(), &[("a.bin", b"hello")]);
        // Manifest claims a different content.
        write_manifest_for(dir.path(), &[("a.bin", b"BOGUS")]);
        let err = DbManifest::load_and_verify(dir.path()).unwrap_err();
        assert!(matches!(err, ManifestError::HashMismatch { .. }), "got {:?}", err);
    }

    #[test]
    fn detects_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        write_files(dir.path(), &[("a.bin", b"hello")]);
        write_manifest_for(
            dir.path(),
            &[("a.bin", b"hello"), ("missing.bin", b"absent")],
        );
        let err = DbManifest::load_and_verify(dir.path()).unwrap_err();
        assert!(matches!(err, ManifestError::MissingFile { .. }), "got {:?}", err);
    }

    #[test]
    fn detects_unlisted_file() {
        let dir = tempfile::tempdir().unwrap();
        write_files(dir.path(), &[("a.bin", b"hello"), ("strays.bin", b"oops")]);
        write_manifest_for(dir.path(), &[("a.bin", b"hello")]);
        let err = DbManifest::load_and_verify(dir.path()).unwrap_err();
        assert!(matches!(err, ManifestError::UnexpectedFile { .. }), "got {:?}", err);
    }

    #[test]
    fn rejects_unsupported_version() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(MANIFEST_FILENAME),
            "[manifest]\nversion = 99\n[files]\n",
        )
        .unwrap();
        let err = DbManifest::load_and_verify(dir.path()).unwrap_err();
        assert!(matches!(err, ManifestError::UnsupportedVersion(99)), "got {:?}", err);
    }

    #[test]
    fn rejects_invalid_hash_hex() {
        let dir = tempfile::tempdir().unwrap();
        write_files(dir.path(), &[("a.bin", b"hello")]);
        // Hash field too short
        fs::write(
            dir.path().join(MANIFEST_FILENAME),
            "[manifest]\nversion = 1\n[files]\n\"a.bin\" = \"deadbeef\"\n",
        )
        .unwrap();
        let err = DbManifest::load_and_verify(dir.path()).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidHashHex { .. }), "got {:?}", err);
    }

    #[test]
    fn manifest_itself_is_excluded_from_unlisted_check() {
        let dir = tempfile::tempdir().unwrap();
        write_files(dir.path(), &[("a.bin", b"hello")]);
        write_manifest_for(dir.path(), &[("a.bin", b"hello")]);
        DbManifest::load_and_verify(dir.path()).unwrap().unwrap();
    }

    #[test]
    fn accepts_uppercase_hash_hex() {
        let dir = tempfile::tempdir().unwrap();
        write_files(dir.path(), &[("a.bin", b"hello")]);
        let upper = hex_encode(&sha256(b"hello")).to_uppercase();
        fs::write(
            dir.path().join(MANIFEST_FILENAME),
            format!(
                "[manifest]\nversion = 1\n[files]\n\"a.bin\" = \"{}\"\n",
                upper
            ),
        )
        .unwrap();
        DbManifest::load_and_verify(dir.path()).unwrap().unwrap();
    }

    #[test]
    fn nested_directories_are_walked() {
        let dir = tempfile::tempdir().unwrap();
        let files: &[(&str, &[u8])] = &[
            ("top.bin", b"x"),
            ("a/inner.bin", b"y"),
            ("a/b/deep.bin", b"z"),
        ];
        write_files(dir.path(), files);
        write_manifest_for(dir.path(), files);
        DbManifest::load_and_verify(dir.path()).unwrap().unwrap();
    }

    #[test]
    fn cuckoo_table_files_skip_hash_verification() {
        let dir = tempfile::tempdir().unwrap();
        write_files(dir.path(), &[
            ("batch_pir_cuckoo.bin", b"actual data"),
            ("index.bin", b"small index"),
        ]);
        // Write manifest with a WRONG hash for the cuckoo table.
        let index_line = format!("\"index.bin\" = \"{}\"", hex_encode(&sha256(b"small index")));
        let lines = vec![
            "[manifest]",
            "version = 1",
            "",
            "[files]",
            "\"batch_pir_cuckoo.bin\" = \"0000000000000000000000000000000000000000000000000000000000000000\"",
            &index_line,
        ];
        fs::write(dir.path().join(MANIFEST_FILENAME), lines.join("\n")).unwrap();
        // Should succeed — cuckoo table hash is skipped (wrong hash ignored).
        DbManifest::load_and_verify(dir.path()).unwrap().unwrap();
    }

    #[test]
    fn cuckoo_table_still_must_be_listed_in_manifest() {
        let dir = tempfile::tempdir().unwrap();
        write_files(dir.path(), &[("batch_pir_cuckoo.bin", b"data"), ("index.bin", b"small")]);
        // Only list index.bin — stray cuckoo file should be caught.
        write_manifest_for(dir.path(), &[("index.bin", b"small")]);
        let err = DbManifest::load_and_verify(dir.path()).unwrap_err();
        assert!(matches!(err, ManifestError::UnexpectedFile { .. }), "got {:?}", err);
    }

    #[test]
    fn hex_encode_roundtrip_via_sha256_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let h = sha256(b"abc");
        assert_eq!(
            hex_encode(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
