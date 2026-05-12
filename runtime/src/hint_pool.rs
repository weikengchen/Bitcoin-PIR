//! Pre-computed HarmonyPIR hint pool with background replenishment.
//!
//! The pool generates (prp_key, serialized hint frames) pairs in a background
//! thread and serves them to clients with zero computation on the hot path.
//!
//! ## Memory locality
//!
//! Each pool entry is generated key-at-a-time: one random PRP key, all 155
//! groups computed in parallel via rayon. This keeps each group's `hints`
//! array (~170-350 KB) in L2 cache and the `cell_of` array (~4-8 MB) in L3.
//! Cross-key batching would thrash the per-group hints across cache lines.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use harmonypir::params::Params;
use harmonypir::prp::BatchPrp;
use harmonypir_wasm;

use pir_runtime_core::table::MappedDatabase;

// ─── Config ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct HintPoolConfig {
    /// Target number of entries to keep ready.
    pub pool_size: usize,
    /// PRP backend for background generation (2 = ALF is fastest on native).
    pub prp_backend: u8,
    /// Directory for disk-backed pool persistence (None = in-memory only).
    pub pool_dir: Option<PathBuf>,
}

impl Default for HintPoolConfig {
    fn default() -> Self {
        Self {
            pool_size: 8,
            // Default to PRP_FASTPRP. Was PRP_ALF before 2026-05-12; ALF
            // panicked on small (sibling) domains, crashing pir-vpsbg.
            prp_backend: harmonypir_wasm::PRP_FASTPRP,
            pool_dir: None,
        }
    }
}

// ─── Key preamble wire format ────────────────────────────────────────────────

/// Sentinel value in the key-preamble `level` field meaning "applies to both
/// INDEX and CHUNK."
pub const HINT_LEVEL_ALL: u8 = 0xFF;

/// Response variant byte for the key preamble frame.
pub const RESP_HARMONY_HINTS_KEY: u8 = 0x44;

/// Response variant byte for per-group hint frames (reuses V1 format).
pub const RESP_HARMONY_HINTS: u8 = 0x41;

/// Build the key preamble frame (the first frame sent in response to a V2
/// hint request). The caller prepends the outer 4-byte length prefix.
pub fn build_key_preamble(prp_backend: u8, total_groups: u8, prp_key: &[u8; 16]) -> Vec<u8> {
    // Layout: [RESP_HARMONY_HINTS_KEY][1B prp_backend][1B level_sentinel=0xFF][1B total_groups][16B prp_key]
    let payload_len: u32 = 1 + 1 + 1 + 1 + 16;
    let mut frame = Vec::with_capacity(4 + payload_len as usize);
    frame.extend_from_slice(&payload_len.to_le_bytes());
    frame.push(RESP_HARMONY_HINTS_KEY);
    frame.push(prp_backend);
    frame.push(HINT_LEVEL_ALL);
    frame.push(total_groups);
    frame.extend_from_slice(prp_key);
    frame
}

// ─── Pool entry ──────────────────────────────────────────────────────────────

/// One pre-computed entry: a full set of per-group hint frames for both
/// INDEX and CHUNK levels, bound to a randomly-generated PRP key.
pub struct PoolEntry {
    /// Server-generated PRP key.
    pub prp_key: [u8; 16],
    /// PRP backend used.
    pub prp_backend: u8,
    /// Pre-serialized RESP_HARMONY_HINTS frames for INDEX groups (0..K-1).
    pub index_frames: Vec<Vec<u8>>,
    /// Pre-serialized RESP_HARMONY_HINTS frames for CHUNK groups (0..K_CHUNK-1).
    pub chunk_frames: Vec<Vec<u8>>,
    /// Pre-built key preamble frame (includes outer length prefix).
    pub key_preamble: Vec<u8>,
    /// When this entry was created.
    pub created_at: Instant,
}

// ─── Hint pool ───────────────────────────────────────────────────────────────

/// Thread-safe pool of pre-computed hint entries.
///
/// A background thread keeps the pool filled to `config.pool_size`. When a
/// client connects, `take()` pops an entry — zero computation on the hot path.
pub struct HintPool {
    entries: Arc<Mutex<VecDeque<PoolEntry>>>,
    condvar: Arc<Condvar>,
    shutdown: Arc<AtomicBool>,
    _generator: Option<JoinHandle<()>>,
}

impl HintPool {
    /// Create a new pool and start the background generator.
    ///
    /// `db` is the database to generate hints against (typically db_id=0,
    /// the main UTXO snapshot).
    pub fn new(config: HintPoolConfig, db: &MappedDatabase) -> Self {
        let entries = Arc::new(Mutex::new(VecDeque::with_capacity(config.pool_size)));
        let condvar = Arc::new(Condvar::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        // Load any existing pool files from disk before starting generation.
        let initial_entries = if let Some(ref dir) = config.pool_dir {
            load_pool_files(dir)
        } else {
            Vec::new()
        };
        {
            let mut q = entries.lock().unwrap();
            for e in initial_entries {
                q.push_back(e);
            }
            println!(
                "[hint-pool] Loaded {} entries from disk, target pool size {}",
                q.len(),
                config.pool_size
            );
        }

        // Snapshot the immutable DB parameters for the generator thread.
        let db_params = DbParams {
            index_params: db.index.params.clone(),
            chunk_params: db.chunk.params.clone(),
            index_bins: db.index.bins_per_table,
            chunk_bins: db.chunk.bins_per_table,
            index_entry_size: db.index.params.bin_size(),
            chunk_entry_size: db.chunk.params.bin_size(),
        };
        let index_mmap_ptr = db.index.mmap.as_ptr() as usize;
        let index_mmap_len = db.index.mmap.len();
        let chunk_mmap_ptr = db.chunk.mmap.as_ptr() as usize;
        let chunk_mmap_len = db.chunk.mmap.len();

        let gen_config = config.clone();
        let gen_shutdown = Arc::clone(&shutdown);
        let gen_entries = Arc::clone(&entries);
        let gen_cv = Arc::clone(&condvar);
        let handle = std::thread::spawn(move || {
            generation_loop(
                gen_config,
                db_params,
                index_mmap_ptr,
                index_mmap_len,
                chunk_mmap_ptr,
                chunk_mmap_len,
                &gen_entries,
                &gen_cv,
                &gen_shutdown,
            );
        });

        HintPool {
            entries,
            condvar,
            shutdown,
            _generator: Some(handle),
        }
    }

    /// Block until an entry is available, then remove and return it.
    /// Returns `None` only if the pool is shutting down.
    pub fn take(&self) -> Option<PoolEntry> {
        let mut q = self.entries.lock().unwrap();
        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                return q.pop_front();
            }
            if let Some(entry) = q.pop_front() {
                return Some(entry);
            }
            q = self.condvar.wait(q).unwrap();
        }
    }

    /// Number of entries currently in the pool.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// True if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for HintPool {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.condvar.notify_all();
        // Generator thread will see shutdown=true and exit.
    }
}

// ─── Background generation ───────────────────────────────────────────────────

/// Snapshot of database parameters needed for hint generation.
struct DbParams {
    index_params: pir_core::params::TableParams,
    chunk_params: pir_core::params::TableParams,
    index_bins: usize,
    chunk_bins: usize,
    index_entry_size: usize,
    chunk_entry_size: usize,
}

fn generation_loop(
    config: HintPoolConfig,
    db_params: DbParams,
    index_mmap_ptr: usize,
    index_mmap_len: usize,
    chunk_mmap_ptr: usize,
    chunk_mmap_len: usize,
    entries: &Arc<Mutex<VecDeque<PoolEntry>>>,
    cv: &Arc<Condvar>,
    shutdown: &AtomicBool,
) {
    // SAFETY: the mmap lives for the lifetime of the server process.
    // The generator thread only reads from these slices.
    let index_mmap: &[u8] =
        unsafe { std::slice::from_raw_parts(index_mmap_ptr as *const u8, index_mmap_len) };
    let chunk_mmap: &[u8] =
        unsafe { std::slice::from_raw_parts(chunk_mmap_ptr as *const u8, chunk_mmap_len) };

    let index_k = db_params.index_params.k as u32;
    let chunk_k = db_params.chunk_params.k as u32;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Check if we need more entries.
        let need_more = {
            let q = entries.lock().unwrap();
            q.len() < config.pool_size
        };

        if !need_more {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }

        // Generate one pool entry.
        let t0 = Instant::now();
        match generate_pool_entry(
            &config,
            &db_params,
            index_mmap,
            chunk_mmap,
            index_k,
            chunk_k,
        ) {
            Ok(entry) => {
                let elapsed = t0.elapsed();
                let prp_key_hex: String = entry
                    .prp_key
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect();
                println!(
                    "[hint-pool] Generated entry (prp_key={}..., {} groups) in {:.2?}",
                    &prp_key_hex[..8],
                    entry.index_frames.len() + entry.chunk_frames.len(),
                    elapsed,
                );

                // Persist to disk if configured.
                if let Some(ref dir) = config.pool_dir {
                    if let Err(e) = persist_pool_entry(dir, &entry) {
                        eprintln!("[hint-pool] Failed to persist entry: {}", e);
                    }
                }

                let mut q = entries.lock().unwrap();
                q.push_back(entry);
                cv.notify_all();
            }
            Err(e) => {
                eprintln!("[hint-pool] Generation failed: {}", e);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    println!("[hint-pool] Generator thread shutting down");
}

fn generate_pool_entry(
    config: &HintPoolConfig,
    db_params: &DbParams,
    index_mmap: &[u8],
    chunk_mmap: &[u8],
    index_k: u32,
    chunk_k: u32,
) -> Result<PoolEntry, String> {
    use rand::RngCore;
    let mut prp_key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut prp_key);

    let total_groups = (index_k + chunk_k) as u8;

    // Generate INDEX frames in parallel.
    let index_frames: Vec<Vec<u8>> = (0..index_k)
        .into_par_iter()
        .map(|g| {
            compute_and_serialize_hint_frame(
                &prp_key,
                config.prp_backend,
                0, // level = INDEX
                g,
                0, // k_offset for INDEX groups
                index_mmap,
                db_params.index_params.header_size,
                db_params.index_bins,
                db_params.index_entry_size,
            )
        })
        .collect();

    // Generate CHUNK frames in parallel.
    let chunk_frames: Vec<Vec<u8>> = (0..chunk_k)
        .into_par_iter()
        .map(|g| {
            compute_and_serialize_hint_frame(
                &prp_key,
                config.prp_backend,
                1, // level = CHUNK
                g,
                index_k, // k_offset for CHUNK groups
                chunk_mmap,
                db_params.chunk_params.header_size,
                db_params.chunk_bins,
                db_params.chunk_entry_size,
            )
        })
        .collect();

    let key_preamble = build_key_preamble(config.prp_backend, total_groups, &prp_key);

    Ok(PoolEntry {
        prp_key,
        prp_backend: config.prp_backend,
        index_frames,
        chunk_frames,
        key_preamble,
        created_at: Instant::now(),
    })
}

// ─── Hint computation (extracted from unified_server) ────────────────────────

/// Derive a per-group PRP key from the master key. Must match the WASM client.
fn derive_group_key(master_key: &[u8; 16], group_id: u32) -> [u8; 16] {
    let mut key = *master_key;
    let id_bytes = group_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
}

/// XOR src into dst element-wise.
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

use rayon::prelude::*;

/// Compute hints for a single group and return the pre-serialized
/// RESP_HARMONY_HINTS frame (ready to send on the wire).
///
/// This is the same computation as `compute_hints_for_group()` in
/// `unified_server.rs`, but returns the wire-ready frame directly.
fn compute_and_serialize_hint_frame(
    prp_key: &[u8; 16],
    prp_backend: u8,
    _level: u8,
    group_id: u32,
    k_offset: u32,
    table_mmap: &[u8],
    header_size: usize,
    bins_per_table: usize,
    entry_size: usize,
) -> Vec<u8> {
    let real_n = bins_per_table;
    let w = entry_size;
    let t_raw = harmonypir_wasm::find_best_t(real_n as u32);
    let (padded_n, t_val) = harmonypir_wasm::pad_n_for_t(real_n as u32, t_raw);
    let pn = padded_n as usize;
    let t = t_val as usize;

    let params = Params::new(pn, w, t).expect("valid params");
    let m = params.m;

    let derived_key = derive_group_key(prp_key, k_offset + group_id);
    let domain = 2 * pn;
    let r = harmonypir_wasm::compute_rounds(padded_n);

    // Batch PRP evaluation.
    // PRP_ALF (= 2) was removed 2026-05-12 — see harmonypir-wasm/src/lib.rs:36
    // for the rationale (panic on domain<65536 crashed pir-vpsbg).
    let cell_of: Vec<usize> = match prp_backend {
        #[cfg(feature = "fastprp")]
        harmonypir_wasm::PRP_FASTPRP => {
            use harmonypir::prp::fast::FastPrpWrapper;
            let prp = FastPrpWrapper::new(&derived_key, domain);
            prp.batch_forward()
        }
        _ => {
            use harmonypir::prp::hoang::HoangPrp;
            let prp = HoangPrp::new(domain, r, &derived_key);
            prp.batch_forward()
        }
    };

    // Scatter-XOR: for each row k, XOR its entry into hints[cell_of[k] / T].
    let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();
    let table_offset = header_size + group_id as usize * bins_per_table * entry_size;
    for k in 0..pn {
        let segment = cell_of[k] / t;
        if k < real_n {
            let entry_off = table_offset + k * entry_size;
            let entry = &table_mmap[entry_off..entry_off + entry_size];
            xor_into(&mut hints[segment], entry);
        }
    }

    // Flatten hints and build the RESP_HARMONY_HINTS frame.
    // Frame layout (before outer length prefix):
    //   [RESP_HARMONY_HINTS][1B group_id][4B n LE][4B t LE][4B m LE][flat_hints]
    let flat: Vec<u8> = hints.into_iter().flat_map(|h| h.into_iter()).collect();
    let frame_payload_len: u32 = 1 + 1 + 4 + 4 + 4 + flat.len() as u32;
    let mut frame = Vec::with_capacity(4 + frame_payload_len as usize);
    frame.extend_from_slice(&frame_payload_len.to_le_bytes());
    frame.push(RESP_HARMONY_HINTS);
    frame.push(group_id as u8);
    frame.extend_from_slice(&(padded_n as u32).to_le_bytes());
    frame.extend_from_slice(&(t_val as u32).to_le_bytes());
    frame.extend_from_slice(&(m as u32).to_le_bytes());
    frame.extend_from_slice(&flat);
    frame
}

// ─── Disk persistence ────────────────────────────────────────────────────────

const POOL_FILE_MAGIC: &[u8] = b"HMPOOL\x01";

/// Persist a pool entry to disk.
fn persist_pool_entry(pool_dir: &Path, entry: &PoolEntry) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::{BufWriter, Write};

    // Find next sequence number.
    let mut seq = 0u64;
    if let Ok(rd) = std::fs::read_dir(pool_dir) {
        for de in rd.flatten() {
            let name = de.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("pool_") && name.ends_with(".hints") {
                if let Some(num_str) = name.strip_prefix("pool_").and_then(|s| s.strip_suffix(".hints")) {
                    if let Ok(n) = u64::from_str_radix(num_str, 16) {
                        seq = seq.max(n + 1);
                    }
                }
            }
        }
    }

    let path = pool_dir.join(format!("pool_{:08x}.hints", seq));
    let tmp_path = pool_dir.join(format!("pool_{:08x}.hints.tmp", seq));

    let f = File::create(&tmp_path)?;
    let mut w = BufWriter::new(f);

    // Header (80 bytes).
    let created_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    w.write_all(POOL_FILE_MAGIC)?;
    w.write_all(&1u32.to_le_bytes())?; // version
    w.write_all(&[entry.prp_backend])?;
    w.write_all(&[0u8; 3])?; // _pad
    w.write_all(&entry.prp_key)?;
    w.write_all(&created_ts.to_le_bytes())?;
    w.write_all(&(entry.index_frames.len() as u32).to_le_bytes())?;
    w.write_all(&(entry.chunk_frames.len() as u32).to_le_bytes())?;
    w.write_all(&[0u8; 44])?; // reserved

    // Frame data.
    for frame in &entry.index_frames {
        w.write_all(&(frame.len() as u32).to_le_bytes())?;
        w.write_all(frame)?;
    }
    for frame in &entry.chunk_frames {
        w.write_all(&(frame.len() as u32).to_le_bytes())?;
        w.write_all(frame)?;
    }
    w.write_all(&(entry.key_preamble.len() as u32).to_le_bytes())?;
    w.write_all(&entry.key_preamble)?;

    w.flush()?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Load pool entries from disk at startup. Non-existent or corrupt files
/// are silently skipped (the generator thread will replenish).
fn load_pool_files(pool_dir: &Path) -> Vec<PoolEntry> {
    use std::fs::File;
    use std::io::Read;

    let mut entries = Vec::new();
    let rd = match std::fs::read_dir(pool_dir) {
        Ok(rd) => rd,
        Err(_) => return entries,
    };

    for de in rd.flatten() {
        let path = de.path();
        let name = path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
        if !name.starts_with("pool_") || !name.ends_with(".hints") {
            continue;
        }

        let mut f = match File::open(&path) {
            Ok(f) => f,
            Err(_) => {
                let _ = std::fs::remove_file(&path);
                continue;
            }
        };

        let mut header = [0u8; 80];
        if f.read_exact(&mut header).is_err() {
            let _ = std::fs::remove_file(&path);
            continue;
        }

        if &header[..POOL_FILE_MAGIC.len()] != POOL_FILE_MAGIC {
            let _ = std::fs::remove_file(&path);
            continue;
        }

        let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
        if version != 1 {
            let _ = std::fs::remove_file(&path);
            continue;
        }

        let prp_backend = header[12];
        let mut prp_key = [0u8; 16];
        prp_key.copy_from_slice(&header[16..32]);
        let index_k = u32::from_le_bytes(header[40..44].try_into().unwrap()) as usize;
        let chunk_k = u32::from_le_bytes(header[44..48].try_into().unwrap()) as usize;

        // Read frames.
        let mut read_frame = || -> std::io::Result<Vec<u8>> {
            let mut len_buf = [0u8; 4];
            f.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf)?;
            Ok(buf)
        };

        let mut index_frames = Vec::with_capacity(index_k);
        for _ in 0..index_k {
            match read_frame() {
                Ok(fr) => index_frames.push(fr),
                Err(_) => {
                    let _ = std::fs::remove_file(&path);
                    index_frames.clear();
                    break;
                }
            }
        }
        if index_frames.is_empty() && index_k > 0 {
            continue;
        }

        let mut chunk_frames = Vec::with_capacity(chunk_k);
        for _ in 0..chunk_k {
            match read_frame() {
                Ok(fr) => chunk_frames.push(fr),
                Err(_) => {
                    let _ = std::fs::remove_file(&path);
                    chunk_frames.clear();
                    break;
                }
            }
        }
        if chunk_frames.is_empty() && chunk_k > 0 {
            continue;
        }

        let key_preamble = match read_frame() {
            Ok(fr) => fr,
            Err(_) => {
                let _ = std::fs::remove_file(&path);
                continue;
            }
        };

        entries.push(PoolEntry {
            prp_key,
            prp_backend,
            index_frames,
            chunk_frames,
            key_preamble,
            created_at: Instant::now(),
        });

        // Remove the consumed file.
        let _ = std::fs::remove_file(&path);
    }

    entries
}
