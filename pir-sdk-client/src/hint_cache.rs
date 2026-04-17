//! Persistent hint cache for [`HarmonyClient`](crate::harmony::HarmonyClient).
//!
//! HarmonyPIR pays a substantial upfront cost every time the client opens
//! a database: each main INDEX/CHUNK group plus each sibling group at
//! every Merkle level must download a chunk of hint bytes from the hint
//! server. For a 128-group × 10-level database the pre-query handshake
//! can run into dozens of MiB and several seconds of CPU. As long as the
//! underlying database snapshot hasn't shifted, those hints are
//! bit-exact reusable — they are derived deterministically from
//! `master_prp_key` + PRP backend + group_id, and every relocation is
//! recorded inside [`harmonypir_wasm::HarmonyGroup::serialize`].
//!
//! This module gives callers a small, auditable persistence surface:
//!
//! - [`CacheKey`] — the tuple that identifies a hint snapshot:
//!   `(db_id, height, prp_backend, master_key_fingerprint,
//!   bins shape, tag_seed)`. Every field feeds a SHA-256 fingerprint
//!   so two clients with different master keys / PRP backends never
//!   share a cache file even when `db_id + height` match.
//! - [`encode_hints`] / [`decode_hints`] — pure functions that
//!   round-trip a bundle of per-group byte blobs (main + sibling) to
//!   a versioned, schema-hashed blob. The schema string is hashed
//!   into the header so future format changes surface as a clean
//!   [`PirError::Decode`] rather than a silent corrupt-data fault.
//! - [`resolve_default_cache_dir`] — `$PIR_SDK_HINT_CACHE_DIR` →
//!   `$XDG_CACHE_HOME/pir-sdk/hints` → `$HOME/.cache/pir-sdk/hints`.
//!   Returns `None` when no candidate is reachable; callers treat
//!   that as "cache disabled".
//! - [`read_cache_file`] / [`write_cache_file`] — native-only
//!   filesystem helpers. On `wasm32-unknown-unknown` the module still
//!   compiles and `encode_hints` / `decode_hints` are available so
//!   Session 5 can wrap them with IndexedDB persistence.
//!
//! See also `web/src/harmonypir_hint_db.ts` — the browser reference
//! model for the same cache semantics (IndexedDB-backed, with the
//! same `SCHEMA_VERSION = 1`).

use pir_sdk::{DatabaseInfo, PirError, PirResult};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Magic bytes identifying a hint-cache blob. `PSH` = "PIR Sync Hints",
/// `1` = format family. Any future incompatible binary-layout change
/// (e.g. widening `group_id` to `u16`) bumps this to `PSH2`.
pub const MAGIC: [u8; 4] = *b"PSH1";

/// Blob layout version inside the `PSH1` family.
pub const FORMAT_VERSION: u16 = 1;

/// Schema description hashed into each cache blob.
///
/// Changing this string is the way to invalidate all existing caches
/// without renaming the magic bytes. Example: if we later start
/// embedding per-group `derived_key` fingerprints, bump the "v1" here
/// to "v2" so old caches fail the [`decode_hints`] schema-hash check
/// and get refetched transparently.
const SCHEMA_STRING: &[u8] =
    b"pir-sdk hint cache v1 (PSH1): \
      [magic 4][fmt_ver u16][schema_hash 32][fp 16][backend u8][db_id u8][height u32]\
      [index_bins u32][chunk_bins u32][tag_seed u64][index_k u8][chunk_k u8]\
      [num_main_index u32 (group_id u8, len u32, bytes)]\
      [num_main_chunk u32 (group_id u8, len u32, bytes)]\
      [has_sibling u8]\
      sib_block = [num_index_sib u32 (level u8, group_id u8, len u32, bytes)]\
                  [num_chunk_sib u32 (level u8, group_id u8, len u32, bytes)]";

/// Precomputed SHA-256 of [`SCHEMA_STRING`]. Used verbatim in the blob header.
fn compute_schema_hash() -> [u8; 32] {
    pir_core::merkle::sha256(SCHEMA_STRING)
}

/// Identifies one specific hint snapshot.
///
/// Used both as the cache-file lookup key and the "is this blob valid"
/// fingerprint written into the blob header. Two clients with the same
/// master key but different PRP backends produce different fingerprints,
/// so their files cannot collide on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheKey {
    pub master_prp_key: [u8; 16],
    pub prp_backend: u8,
    pub db_id: u8,
    pub height: u32,
    pub index_bins: u32,
    pub chunk_bins: u32,
    pub tag_seed: u64,
    pub index_k: u8,
    pub chunk_k: u8,
}

impl CacheKey {
    /// Build a cache key from a master PRP key + [`DatabaseInfo`].
    ///
    /// This is the canonical constructor — callers should not assemble
    /// fields by hand, since the field set doubles as the fingerprint
    /// domain and any oversight leads to cache collisions across
    /// incompatible snapshots.
    pub fn from_db_info(
        master_prp_key: [u8; 16],
        prp_backend: u8,
        db_info: &DatabaseInfo,
    ) -> Self {
        Self {
            master_prp_key,
            prp_backend,
            db_id: db_info.db_id,
            height: db_info.height,
            index_bins: db_info.index_bins,
            chunk_bins: db_info.chunk_bins,
            tag_seed: db_info.tag_seed,
            index_k: db_info.index_k,
            chunk_k: db_info.chunk_k,
        }
    }

    /// 16-byte deterministic fingerprint.
    ///
    /// Two `CacheKey` values with any differing field produce different
    /// fingerprints with overwhelming probability (SHA-256 truncated to
    /// 128 bits). This is the identity embedded in both the cache file
    /// name and the blob header, so the disk layout self-certifies
    /// against rotations of the master key, PRP backend, or snapshot
    /// shape.
    pub fn fingerprint(&self) -> [u8; 16] {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"pir-sdk hint cache v1 fingerprint");
        buf.extend_from_slice(&self.master_prp_key);
        buf.push(self.prp_backend);
        buf.push(self.db_id);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.index_bins.to_le_bytes());
        buf.extend_from_slice(&self.chunk_bins.to_le_bytes());
        buf.extend_from_slice(&self.tag_seed.to_le_bytes());
        buf.push(self.index_k);
        buf.push(self.chunk_k);
        let full = pir_core::merkle::sha256(&buf);
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }

    /// Deterministic filename for this key — hex of the 16-byte
    /// fingerprint plus a `.hints` suffix (e.g. `deadbeef….hints`).
    ///
    /// The hash-only name means the master PRP key never appears on
    /// disk as cleartext — even the file path is a SHA-256 pre-image
    /// resistance problem for anyone who can list the cache directory.
    pub fn filename(&self) -> String {
        let fp = self.fingerprint();
        let mut s = String::with_capacity(32 + 6);
        for b in &fp {
            s.push_str(&format!("{:02x}", b));
        }
        s.push_str(".hints");
        s
    }
}

/// Per-group hint bundle ready for persistence.
///
/// Main groups are keyed by `group_id`; sibling groups are keyed by
/// `(sib_level, group_id)`. The bytes are the output of
/// `HarmonyGroup::serialize()` — its deserializer replays the
/// relocation log exactly, so no other state is needed for
/// reconstruction.
#[derive(Clone, Debug, Default)]
pub struct HintBundle {
    pub main_index: HashMap<u8, Vec<u8>>,
    pub main_chunk: HashMap<u8, Vec<u8>>,
    /// Empty when the server doesn't publish bucket Merkle (no sibling
    /// hints were loaded).
    pub index_sib: HashMap<(u8, u8), Vec<u8>>,
    pub chunk_sib: HashMap<(u8, u8), Vec<u8>>,
}

impl HintBundle {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when the client had sibling hints loaded at save time
    /// (i.e. the database publishes per-bucket Merkle). Reload must
    /// pass the same flag back through [`encode_hints`] so
    /// verification state doesn't silently degrade.
    pub fn has_siblings(&self) -> bool {
        !self.index_sib.is_empty() || !self.chunk_sib.is_empty()
    }

    /// Total main+sibling byte count. Informational — useful for
    /// log statements and size budgeting.
    pub fn total_hint_bytes(&self) -> usize {
        self.main_index.values().map(|v| v.len()).sum::<usize>()
            + self.main_chunk.values().map(|v| v.len()).sum::<usize>()
            + self.index_sib.values().map(|v| v.len()).sum::<usize>()
            + self.chunk_sib.values().map(|v| v.len()).sum::<usize>()
    }
}

/// Serialize a `(CacheKey, HintBundle)` pair into a self-describing blob.
///
/// Layout documented in [`SCHEMA_STRING`].
pub fn encode_hints(key: &CacheKey, bundle: &HintBundle) -> Vec<u8> {
    let schema_hash = compute_schema_hash();
    let fp = key.fingerprint();

    let mut buf = Vec::with_capacity(256);

    // Header.
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf.extend_from_slice(&schema_hash);
    buf.extend_from_slice(&fp);
    buf.push(key.prp_backend);
    buf.push(key.db_id);
    buf.extend_from_slice(&key.height.to_le_bytes());
    buf.extend_from_slice(&key.index_bins.to_le_bytes());
    buf.extend_from_slice(&key.chunk_bins.to_le_bytes());
    buf.extend_from_slice(&key.tag_seed.to_le_bytes());
    buf.push(key.index_k);
    buf.push(key.chunk_k);

    // Main INDEX groups, sorted by group_id for deterministic output.
    let mut idx_ids: Vec<u8> = bundle.main_index.keys().copied().collect();
    idx_ids.sort();
    buf.extend_from_slice(&(idx_ids.len() as u32).to_le_bytes());
    for gid in idx_ids {
        let bytes = &bundle.main_index[&gid];
        buf.push(gid);
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(bytes);
    }

    // Main CHUNK groups.
    let mut chunk_ids: Vec<u8> = bundle.main_chunk.keys().copied().collect();
    chunk_ids.sort();
    buf.extend_from_slice(&(chunk_ids.len() as u32).to_le_bytes());
    for gid in chunk_ids {
        let bytes = &bundle.main_chunk[&gid];
        buf.push(gid);
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(bytes);
    }

    // Sibling block.
    let has_sib = bundle.has_siblings();
    buf.push(if has_sib { 1 } else { 0 });
    if has_sib {
        let mut idx_sib: Vec<(u8, u8)> = bundle.index_sib.keys().copied().collect();
        idx_sib.sort();
        buf.extend_from_slice(&(idx_sib.len() as u32).to_le_bytes());
        for (level, gid) in idx_sib {
            let bytes = &bundle.index_sib[&(level, gid)];
            buf.push(level);
            buf.push(gid);
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
        }
        let mut chunk_sib: Vec<(u8, u8)> = bundle.chunk_sib.keys().copied().collect();
        chunk_sib.sort();
        buf.extend_from_slice(&(chunk_sib.len() as u32).to_le_bytes());
        for (level, gid) in chunk_sib {
            let bytes = &bundle.chunk_sib[&(level, gid)];
            buf.push(level);
            buf.push(gid);
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
        }
    }

    buf
}

/// Outcome of [`decode_hints`] — the parsed key + group bundle.
///
/// `key.master_prp_key` is **not** embedded in the blob (it never goes
/// to disk) and is returned as zeros; callers must cross-check the
/// embedded fingerprint against their own master key + shape.
#[derive(Debug)]
pub struct DecodedHints {
    pub key: CacheKey,
    pub bundle: HintBundle,
}

/// Parse a blob produced by [`encode_hints`].
///
/// Returns an error when:
/// - the magic bytes or format version don't match this build (bumping
///   either invalidates older caches cleanly);
/// - the schema hash doesn't match — a code change in this module
///   reshuffled the layout but kept the magic bytes stable;
/// - the `expected_fingerprint` (if provided) doesn't match the
///   fingerprint embedded in the blob — catches file-system swaps,
///   master-key rotations, etc.;
/// - any length field overruns the buffer.
pub fn decode_hints(
    data: &[u8],
    expected_fingerprint: Option<&[u8; 16]>,
) -> PirResult<DecodedHints> {
    // Minimum header: magic(4) + ver(2) + sha(32) + fp(16) +
    //   backend(1) + db_id(1) + height(4) + index_bins(4) + chunk_bins(4) +
    //   tag_seed(8) + index_k(1) + chunk_k(1) + num_main_index(4) +
    //   num_main_chunk(4) + has_sibling(1) = 87 bytes.
    const MIN_HEADER_BYTES: usize = 4 + 2 + 32 + 16 + 1 + 1 + 4 + 4 + 4 + 8 + 1 + 1 + 4 + 4 + 1;
    if data.len() < MIN_HEADER_BYTES {
        return Err(PirError::Decode(format!(
            "hint cache: buffer too short ({} < {})",
            data.len(),
            MIN_HEADER_BYTES
        )));
    }

    let mut pos = 0usize;

    let magic: [u8; 4] = data[pos..pos + 4].try_into().unwrap();
    pos += 4;
    if magic != MAGIC {
        return Err(PirError::Decode(format!(
            "hint cache: bad magic {:02x?}",
            magic
        )));
    }

    let fmt_ver = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    if fmt_ver != FORMAT_VERSION {
        return Err(PirError::Decode(format!(
            "hint cache: format version {} != {}",
            fmt_ver, FORMAT_VERSION
        )));
    }

    let mut schema_hash = [0u8; 32];
    schema_hash.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;
    if schema_hash != compute_schema_hash() {
        return Err(PirError::Decode(
            "hint cache: schema hash mismatch (format reshuffled; refetch)".into(),
        ));
    }

    let mut fp = [0u8; 16];
    fp.copy_from_slice(&data[pos..pos + 16]);
    pos += 16;
    if let Some(want) = expected_fingerprint {
        if &fp != want {
            return Err(PirError::InvalidState(
                "hint cache: fingerprint mismatch (cache is for a different \
                 master key / PRP backend / db snapshot)"
                    .into(),
            ));
        }
    }

    let prp_backend = data[pos];
    pos += 1;
    let db_id = data[pos];
    pos += 1;
    let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let index_bins = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let chunk_bins = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let tag_seed = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    let index_k = data[pos];
    pos += 1;
    let chunk_k = data[pos];
    pos += 1;

    // The master key is not on disk (security); callers re-attach.
    let key = CacheKey {
        master_prp_key: [0u8; 16],
        prp_backend,
        db_id,
        height,
        index_bins,
        chunk_bins,
        tag_seed,
        index_k,
        chunk_k,
    };

    // Per-group records: 1 byte id + 4 byte len + bytes (sibling records
    // get an extra leading `level` byte).
    fn read_u32(data: &[u8], pos: &mut usize) -> PirResult<u32> {
        if *pos + 4 > data.len() {
            return Err(PirError::Decode("hint cache: truncated (u32)".into()));
        }
        let v = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
        *pos += 4;
        Ok(v)
    }
    fn read_u8(data: &[u8], pos: &mut usize) -> PirResult<u8> {
        if *pos + 1 > data.len() {
            return Err(PirError::Decode("hint cache: truncated (u8)".into()));
        }
        let v = data[*pos];
        *pos += 1;
        Ok(v)
    }
    fn read_bytes(data: &[u8], pos: &mut usize, len: usize) -> PirResult<Vec<u8>> {
        if *pos + len > data.len() {
            return Err(PirError::Decode(format!(
                "hint cache: truncated body (need {} bytes, have {})",
                len,
                data.len() - *pos
            )));
        }
        let slice = data[*pos..*pos + len].to_vec();
        *pos += len;
        Ok(slice)
    }

    let num_main_index = read_u32(data, &mut pos)?;
    let mut main_index = HashMap::with_capacity(num_main_index as usize);
    for _ in 0..num_main_index {
        let gid = read_u8(data, &mut pos)?;
        let len = read_u32(data, &mut pos)? as usize;
        let bytes = read_bytes(data, &mut pos, len)?;
        main_index.insert(gid, bytes);
    }

    let num_main_chunk = read_u32(data, &mut pos)?;
    let mut main_chunk = HashMap::with_capacity(num_main_chunk as usize);
    for _ in 0..num_main_chunk {
        let gid = read_u8(data, &mut pos)?;
        let len = read_u32(data, &mut pos)? as usize;
        let bytes = read_bytes(data, &mut pos, len)?;
        main_chunk.insert(gid, bytes);
    }

    let has_sib = read_u8(data, &mut pos)?;
    let (index_sib, chunk_sib) = if has_sib == 0 {
        (HashMap::new(), HashMap::new())
    } else {
        let num_is = read_u32(data, &mut pos)?;
        let mut idx = HashMap::with_capacity(num_is as usize);
        for _ in 0..num_is {
            let level = read_u8(data, &mut pos)?;
            let gid = read_u8(data, &mut pos)?;
            let len = read_u32(data, &mut pos)? as usize;
            let bytes = read_bytes(data, &mut pos, len)?;
            idx.insert((level, gid), bytes);
        }
        let num_cs = read_u32(data, &mut pos)?;
        let mut chk = HashMap::with_capacity(num_cs as usize);
        for _ in 0..num_cs {
            let level = read_u8(data, &mut pos)?;
            let gid = read_u8(data, &mut pos)?;
            let len = read_u32(data, &mut pos)? as usize;
            let bytes = read_bytes(data, &mut pos, len)?;
            chk.insert((level, gid), bytes);
        }
        (idx, chk)
    };

    Ok(DecodedHints {
        key,
        bundle: HintBundle {
            main_index,
            main_chunk,
            index_sib,
            chunk_sib,
        },
    })
}

/// Pure-function core of [`resolve_default_cache_dir`] — same resolution
/// order, but with env accessors passed in so tests can exercise the
/// decision tree without mutating global state.
///
/// Gated to native + test builds because the public `resolve_default_cache_dir`
/// shortcut-returns `None` on wasm32 before ever calling this helper.
#[cfg(any(not(target_arch = "wasm32"), test))]
fn resolve_cache_dir_from(
    override_var: Option<&str>,
    xdg_cache_home: Option<&str>,
    home: Option<&str>,
) -> Option<PathBuf> {
    if let Some(v) = override_var {
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    if let Some(v) = xdg_cache_home {
        if !v.is_empty() {
            return Some(PathBuf::from(v).join("pir-sdk").join("hints"));
        }
    }
    if let Some(v) = home {
        if !v.is_empty() {
            return Some(
                PathBuf::from(v)
                    .join(".cache")
                    .join("pir-sdk")
                    .join("hints"),
            );
        }
    }
    None
}

/// Resolve the default cache dir.
///
/// 1. `$PIR_SDK_HINT_CACHE_DIR` — manual override (takes precedence).
/// 2. `$XDG_CACHE_HOME/pir-sdk/hints` — XDG Base Directory Specification.
/// 3. `$HOME/.cache/pir-sdk/hints` — Unix fallback.
///
/// Returns `None` when none of the above are reachable (e.g. on
/// `wasm32` where we always return `None` — the browser uses
/// IndexedDB via a Session 5 wrapper, not a filesystem).
#[cfg(not(target_arch = "wasm32"))]
pub fn resolve_default_cache_dir() -> Option<PathBuf> {
    resolve_cache_dir_from(
        std::env::var("PIR_SDK_HINT_CACHE_DIR").ok().as_deref(),
        std::env::var("XDG_CACHE_HOME").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
    )
}

#[cfg(target_arch = "wasm32")]
pub fn resolve_default_cache_dir() -> Option<PathBuf> {
    None
}

/// Attempt to read a cached hint blob.
///
/// Returns `Ok(None)` when the file doesn't exist — the common "cold
/// cache" path that callers should treat as "fetch fresh hints". All
/// other I/O errors bubble up as [`PirError::Io`].
#[cfg(not(target_arch = "wasm32"))]
pub fn read_cache_file(path: &Path) -> PirResult<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(PirError::Io(e)),
    }
}

/// Atomically write a cache blob: write to `<path>.tmp`, then rename
/// into place. Creates parent directories if they don't exist.
///
/// The rename is the atomic commit point on POSIX; on partial-write
/// crashes the `.tmp` stays orphaned (callers can garbage-collect on
/// startup if they care) but the live cache file remains intact.
#[cfg(not(target_arch = "wasm32"))]
pub fn write_cache_file(path: &Path, data: &[u8]) -> PirResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Use a sibling path for the temp file so the rename is always on
    // the same filesystem (cross-device renames aren't atomic).
    let mut tmp = path.to_path_buf();
    let mut tmp_name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("hints"));
    tmp_name.push(".tmp");
    tmp.set_file_name(tmp_name);
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir_sdk::DatabaseKind;

    fn sample_info() -> DatabaseInfo {
        DatabaseInfo {
            db_id: 7,
            kind: DatabaseKind::Full,
            name: "t".into(),
            height: 12_345,
            index_bins: 1024,
            chunk_bins: 2048,
            index_k: 3,
            chunk_k: 5,
            tag_seed: 0x_DEAD_BEEF_DEAD_BEEF,
            dpf_n_index: 10,
            dpf_n_chunk: 11,
            has_bucket_merkle: true,
        }
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let info = sample_info();
        let k1 = CacheKey::from_db_info([1u8; 16], 0, &info);
        let k2 = CacheKey::from_db_info([1u8; 16], 0, &info);
        assert_eq!(k1.fingerprint(), k2.fingerprint());
        assert_eq!(k1.filename(), k2.filename());
    }

    #[test]
    fn fingerprint_varies_with_master_key() {
        let info = sample_info();
        let k1 = CacheKey::from_db_info([1u8; 16], 0, &info);
        let k2 = CacheKey::from_db_info([2u8; 16], 0, &info);
        assert_ne!(k1.fingerprint(), k2.fingerprint());
        assert_ne!(k1.filename(), k2.filename());
    }

    #[test]
    fn fingerprint_varies_with_backend() {
        let info = sample_info();
        let k0 = CacheKey::from_db_info([0u8; 16], 0, &info);
        let k1 = CacheKey::from_db_info([0u8; 16], 1, &info);
        let k2 = CacheKey::from_db_info([0u8; 16], 2, &info);
        assert_ne!(k0.fingerprint(), k1.fingerprint());
        assert_ne!(k1.fingerprint(), k2.fingerprint());
        assert_ne!(k0.fingerprint(), k2.fingerprint());
    }

    #[test]
    fn fingerprint_varies_with_height() {
        let info1 = sample_info();
        let mut info2 = sample_info();
        info2.height += 1;
        let k1 = CacheKey::from_db_info([0u8; 16], 0, &info1);
        let k2 = CacheKey::from_db_info([0u8; 16], 0, &info2);
        assert_ne!(k1.fingerprint(), k2.fingerprint());
    }

    #[test]
    fn fingerprint_varies_with_shape() {
        let info1 = sample_info();
        let mut info2 = sample_info();
        info2.index_bins *= 2;
        let k1 = CacheKey::from_db_info([0u8; 16], 0, &info1);
        let k2 = CacheKey::from_db_info([0u8; 16], 0, &info2);
        assert_ne!(k1.fingerprint(), k2.fingerprint());
    }

    #[test]
    fn fingerprint_varies_with_db_id() {
        let info1 = sample_info();
        let mut info2 = sample_info();
        info2.db_id = info1.db_id + 1;
        let k1 = CacheKey::from_db_info([0u8; 16], 0, &info1);
        let k2 = CacheKey::from_db_info([0u8; 16], 0, &info2);
        assert_ne!(k1.fingerprint(), k2.fingerprint());
    }

    #[test]
    fn encode_decode_round_trip_empty_bundle() {
        let info = sample_info();
        let key = CacheKey::from_db_info([5u8; 16], 0, &info);
        let bundle = HintBundle::new();
        let blob = encode_hints(&key, &bundle);

        let decoded = decode_hints(&blob, Some(&key.fingerprint())).unwrap();
        assert_eq!(decoded.bundle.main_index.len(), 0);
        assert_eq!(decoded.bundle.main_chunk.len(), 0);
        assert!(!decoded.bundle.has_siblings());
        assert_eq!(decoded.key.db_id, info.db_id);
        assert_eq!(decoded.key.height, info.height);
        assert_eq!(decoded.key.index_bins, info.index_bins);
        assert_eq!(decoded.key.chunk_bins, info.chunk_bins);
        assert_eq!(decoded.key.tag_seed, info.tag_seed);
        // Master key is deliberately zeroed on disk.
        assert_eq!(decoded.key.master_prp_key, [0u8; 16]);
    }

    #[test]
    fn encode_decode_round_trip_with_main_and_sibling_groups() {
        let info = sample_info();
        let key = CacheKey::from_db_info([9u8; 16], 1, &info);
        let mut bundle = HintBundle::new();
        bundle.main_index.insert(0, vec![1, 2, 3]);
        bundle.main_index.insert(1, vec![4, 5, 6, 7]);
        bundle.main_index.insert(2, vec![]); // zero-len is legal
        bundle.main_chunk.insert(0, vec![8, 9]);
        bundle.main_chunk.insert(4, vec![10; 100]);
        bundle.index_sib.insert((0, 0), vec![11; 8]);
        bundle.index_sib.insert((1, 2), vec![20; 4]);
        bundle.chunk_sib.insert((0, 0), vec![30; 2]);

        let blob = encode_hints(&key, &bundle);
        let decoded = decode_hints(&blob, Some(&key.fingerprint())).unwrap();
        assert_eq!(decoded.bundle.main_index, bundle.main_index);
        assert_eq!(decoded.bundle.main_chunk, bundle.main_chunk);
        assert_eq!(decoded.bundle.index_sib, bundle.index_sib);
        assert_eq!(decoded.bundle.chunk_sib, bundle.chunk_sib);
        assert!(decoded.bundle.has_siblings());
        assert_eq!(
            decoded.bundle.total_hint_bytes(),
            bundle.total_hint_bytes()
        );
    }

    #[test]
    fn encode_is_deterministic() {
        // Sorting the group-id iterators inside `encode_hints` must
        // produce byte-identical output no matter the HashMap insertion
        // order — otherwise cache files would churn on every write
        // and cross-client reproduction tests would fail.
        let info = sample_info();
        let key = CacheKey::from_db_info([0u8; 16], 0, &info);
        let mut a = HintBundle::new();
        a.main_index.insert(3, vec![1, 2]);
        a.main_index.insert(0, vec![5, 6]);
        a.main_index.insert(1, vec![7]);
        let mut b = HintBundle::new();
        b.main_index.insert(1, vec![7]);
        b.main_index.insert(3, vec![1, 2]);
        b.main_index.insert(0, vec![5, 6]);
        assert_eq!(encode_hints(&key, &a), encode_hints(&key, &b));
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let info = sample_info();
        let key = CacheKey::from_db_info([0u8; 16], 0, &info);
        let mut blob = encode_hints(&key, &HintBundle::new());
        blob[0] = b'X';
        let err = decode_hints(&blob, None).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)));
    }

    #[test]
    fn decode_rejects_bad_format_version() {
        let info = sample_info();
        let key = CacheKey::from_db_info([0u8; 16], 0, &info);
        let mut blob = encode_hints(&key, &HintBundle::new());
        blob[4] = 0xFE;
        blob[5] = 0xFF;
        let err = decode_hints(&blob, None).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)));
    }

    #[test]
    fn decode_rejects_bad_schema_hash() {
        let info = sample_info();
        let key = CacheKey::from_db_info([0u8; 16], 0, &info);
        let mut blob = encode_hints(&key, &HintBundle::new());
        // Flip one bit in the schema hash (bytes 6..38).
        blob[6] ^= 0x01;
        let err = decode_hints(&blob, None).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)));
    }

    #[test]
    fn decode_rejects_wrong_fingerprint() {
        let info = sample_info();
        let key = CacheKey::from_db_info([0u8; 16], 0, &info);
        let blob = encode_hints(&key, &HintBundle::new());
        let mut wrong = key.fingerprint();
        wrong[0] ^= 0xAA;
        let err = decode_hints(&blob, Some(&wrong)).unwrap_err();
        assert!(matches!(err, PirError::InvalidState(_)));
    }

    #[test]
    fn decode_rejects_truncated_body() {
        let info = sample_info();
        let key = CacheKey::from_db_info([0u8; 16], 0, &info);
        let mut bundle = HintBundle::new();
        bundle.main_index.insert(0, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let mut blob = encode_hints(&key, &bundle);
        blob.truncate(blob.len() - 3);
        let err = decode_hints(&blob, None).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)));
    }

    #[test]
    fn decode_rejects_too_small_buffer() {
        let tiny = [0u8; 10];
        let err = decode_hints(&tiny, None).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)));
    }

    #[test]
    fn filename_is_stable_and_unique() {
        let info1 = sample_info();
        let mut info2 = sample_info();
        info2.height += 1;
        let k1 = CacheKey::from_db_info([0u8; 16], 0, &info1);
        let k2 = CacheKey::from_db_info([0u8; 16], 0, &info2);
        assert_eq!(k1.filename(), k1.filename());
        assert_ne!(k1.filename(), k2.filename());
        assert!(k1.filename().ends_with(".hints"));
        // 16-byte fingerprint → 32 hex chars, plus ".hints".
        assert_eq!(k1.filename().len(), 32 + ".hints".len());
    }

    #[test]
    fn resolve_cache_dir_from_prefers_override() {
        let p = resolve_cache_dir_from(
            Some("/tmp/override"),
            Some("/xdg"),
            Some("/home/u"),
        )
        .unwrap();
        assert_eq!(p, PathBuf::from("/tmp/override"));
    }

    #[test]
    fn resolve_cache_dir_from_falls_back_to_xdg() {
        let p =
            resolve_cache_dir_from(None, Some("/xdg"), Some("/home/u")).unwrap();
        assert_eq!(p, PathBuf::from("/xdg/pir-sdk/hints"));
    }

    #[test]
    fn resolve_cache_dir_from_falls_back_to_home() {
        let p = resolve_cache_dir_from(None, None, Some("/home/u")).unwrap();
        assert_eq!(p, PathBuf::from("/home/u/.cache/pir-sdk/hints"));
    }

    #[test]
    fn resolve_cache_dir_from_returns_none_when_empty() {
        assert!(resolve_cache_dir_from(None, None, None).is_none());
        // Empty strings must not fool the resolver into joining from ""
        assert!(resolve_cache_dir_from(Some(""), Some(""), Some("")).is_none());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn write_and_read_cache_file_round_trip() {
        let tmp = std::env::temp_dir().join(format!(
            "pir-sdk-hint-cache-test-{}-{}",
            std::process::id(),
            pir_core::merkle::sha256(b"round-trip")[0]
        ));
        let path = tmp.join("a").join("b").join("test.hints");

        let payload = b"hello hints".to_vec();
        write_cache_file(&path, &payload).unwrap();
        let got = read_cache_file(&path).unwrap().unwrap();
        assert_eq!(got, payload);

        // Re-write should overwrite, not append.
        let payload2 = b"second".to_vec();
        write_cache_file(&path, &payload2).unwrap();
        let got2 = read_cache_file(&path).unwrap().unwrap();
        assert_eq!(got2, payload2);

        // Cold-cache path.
        let missing = tmp.join("does-not-exist.hints");
        assert!(read_cache_file(&missing).unwrap().is_none());

        // Cleanup.
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
