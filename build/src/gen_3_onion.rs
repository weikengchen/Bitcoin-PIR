//! Build OnionPIR index database: 75 groups with 2-hash cuckoo (slots_per_bin=256).
//!
//! Reads the OnionPIR index file (27-byte entries from gen_1_onion), assigns
//! entries to 75 PBC groups, builds per-group cuckoo tables, and produces
//! OnionPIR preprocessed databases (one per group).
//!
//! Each cuckoo bin holds 256 × 15-byte tagged index slots = 3840 bytes,
//! which is exactly one OnionPIR entry.
//!
//! Index slot format (15 bytes):
//!   [8B tag | 4B entry_id | 2B byte_offset | 1B num_entries]
//!
//! Output:
//!   - onion_index_pir/group_N.bin: preprocessed OnionPIR databases (one per group)
//!   - onion_index_meta.bin: header with parameters for the server to load
//!
//! Usage:
//!   cargo run --release -p build --bin gen_3_onion [-- --data-dir <dir>]
//!
//! With no flags, reads `/Volumes/Bitcoin/data/intermediate/onion_index.bin`
//! and writes outputs to `/Volumes/Bitcoin/data/`.
//!
//! With `--data-dir <D>`, reads `<D>/onion_index.bin` and writes all outputs
//! under `<D>/`. Use this for delta DB builds.

use memmap2::Mmap;
use onionpir::{self, Server as PirServer, Client as PirClient};
use rayon::prelude::*;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

// ─── Default paths (used when --data-dir is not specified) ──────────────────

const DEFAULT_INDEX_FILE: &str = "/Volumes/Bitcoin/data/intermediate/onion_index.bin";
const DEFAULT_OUTPUT_DIR: &str = "/Volumes/Bitcoin/data/onion_index_pir";
const DEFAULT_META_FILE: &str = "/Volumes/Bitcoin/data/onion_index_meta.bin";
const DEFAULT_BIN_HASHES_FILE: &str = "/Volumes/Bitcoin/data/onion_index_bin_hashes.bin";
const DEFAULT_INDEX_ALL_FILE: &str = "/Volumes/Bitcoin/data/onion_index_all.bin";

/// Magic for the consolidated onion_index_all.bin file. The byte layout after
/// this 32-byte master header is just K per-group preprocessed databases
/// concatenated back-to-back, each in OnionPIR's standard save_db_to_file
/// format. The per-group size is identical because all K groups share the
/// same bins_per_table and OnionPIR params.
const ONION_INDEX_ALL_MAGIC: u64 = 0xBA7C_0010_0000_0003;
const ONION_INDEX_ALL_HEADER_BYTES: usize = 32; // 4 * u64

/// Paths resolved from optional `--data-dir <D>` argument.
struct GenPaths {
    index_file: String,
    output_dir: PathBuf,     // per-group dir (used as scratch)
    meta_file: String,
    bin_hashes_file: String,
    index_all_file: String,  // NEW: consolidated single-file output
}

struct GenArgs {
    paths: GenPaths,
    /// When true, skip steps 1–7 and only run step 8 (read existing
    /// group_N.bin files from output_dir, concat into index_all_file,
    /// remove output_dir). Used to retrofit existing preprocessed snapshots
    /// into the new single-file layout without re-running preprocessing.
    consolidate_only: bool,
}

fn resolve_paths() -> GenArgs {
    let args: Vec<String> = env::args().collect();
    let mut data_dir: Option<String> = None;
    let mut consolidate_only = false;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--data-dir" {
            if let Some(v) = args.get(i + 1) {
                data_dir = Some(v.clone());
                i += 1;
            }
        } else if args[i] == "--consolidate-only" {
            consolidate_only = true;
        }
        i += 1;
    }
    let paths = match data_dir {
        Some(d) => GenPaths {
            index_file: format!("{}/onion_index.bin", d),
            output_dir: PathBuf::from(format!("{}/onion_index_pir", d)),
            meta_file: format!("{}/onion_index_meta.bin", d),
            bin_hashes_file: format!("{}/onion_index_bin_hashes.bin", d),
            index_all_file: format!("{}/onion_index_all.bin", d),
        },
        None => GenPaths {
            index_file: DEFAULT_INDEX_FILE.to_string(),
            output_dir: PathBuf::from(DEFAULT_OUTPUT_DIR),
            meta_file: DEFAULT_META_FILE.to_string(),
            bin_hashes_file: DEFAULT_BIN_HASHES_FILE.to_string(),
            index_all_file: DEFAULT_INDEX_ALL_FILE.to_string(),
        },
    };
    GenArgs { paths, consolidate_only }
}

/// OnionPIR index entry from gen_1_onion: 20B script_hash + 4B entry_id + 2B offset + 1B num_entries
const ONION_INDEX_RECORD_SIZE: usize = 27;
const SCRIPT_HASH_SIZE: usize = 20;

/// Index slot in the cuckoo table: 8B tag + 4B entry_id + 2B offset + 1B num_entries
const INDEX_SLOT_SIZE: usize = 15;

/// PBC parameters
const K: usize = 75;
const NUM_HASHES: usize = 3;
const MASTER_SEED: u64 = 0x71a2ef38b4c90d15;

/// Cuckoo parameters for index level
const CUCKOO_NUM_HASHES: usize = 2;
const SLOTS_PER_BIN: usize = 256; // 256 × 15B = 3840B
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 5000;
const EMPTY: u32 = u32::MAX;

/// Tag seed for fingerprint computation
const TAG_SEED: u64 = 0xd4e5f6a7b8c91023;

/// OnionPIR entry size (must equal SLOTS_PER_BIN * INDEX_SLOT_SIZE)
const ONIONPIR_ENTRY_SIZE: usize = 3840;

const FLAG_WHALE: u8 = 0x40;

// ─── Hash utilities ─────────────────────────────────────────────────────────

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

#[inline]
fn sh_a(sh: &[u8]) -> u64 {
    u64::from_le_bytes([sh[0], sh[1], sh[2], sh[3], sh[4], sh[5], sh[6], sh[7]])
}

#[inline]
fn sh_b(sh: &[u8]) -> u64 {
    u64::from_le_bytes([sh[8], sh[9], sh[10], sh[11], sh[12], sh[13], sh[14], sh[15]])
}

#[inline]
fn sh_c(sh: &[u8]) -> u64 {
    u32::from_le_bytes([sh[16], sh[17], sh[18], sh[19]]) as u64
}

#[inline]
fn hash_for_group(sh: &[u8], nonce: u64) -> u64 {
    let mut h = sh_a(sh).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15));
    h ^= sh_b(sh);
    splitmix64(h ^ sh_c(sh))
}

fn derive_groups(sh: &[u8]) -> [usize; NUM_HASHES] {
    let mut groups = [0usize; NUM_HASHES];
    let mut nonce: u64 = 0;
    let mut count = 0;
    while count < NUM_HASHES {
        let h = hash_for_group(sh, nonce);
        let group = (h % K as u64) as usize;
        nonce += 1;
        let mut dup = false;
        for i in 0..count {
            if groups[i] == group { dup = true; break; }
        }
        if dup { continue; }
        groups[count] = group;
        count += 1;
    }
    groups
}

#[inline]
fn derive_cuckoo_key(group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        MASTER_SEED
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

#[inline]
fn cuckoo_hash(sh: &[u8], key: u64, num_bins: usize) -> usize {
    let mut h = sh_a(sh) ^ key;
    h ^= sh_b(sh);
    h = splitmix64(h ^ sh_c(sh));
    (h % num_bins as u64) as usize
}

#[inline]
fn compute_tag(tag_seed: u64, sh: &[u8]) -> u64 {
    let mut h = sh_a(sh) ^ tag_seed;
    h ^= sh_b(sh);
    splitmix64(h ^ sh_c(sh))
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1e9)
    } else if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1e6)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1e3)
    } else {
        format!("{} B", bytes)
    }
}

// ─── Cuckoo table builder (2-hash, slots_per_bin=256) ───────────────────────

/// Build a 2-hash cuckoo table with large slots_per_bin.
/// Returns (table, success). table[bin * SLOTS_PER_BIN + slot] = entry index.
fn build_index_cuckoo(
    group_id: usize,
    entries: &[u32],
    mmap: &[u8],
    num_bins: usize,
) -> (Vec<u32>, bool) {
    let total_slots = num_bins * SLOTS_PER_BIN;
    let mut table = vec![EMPTY; total_slots];
    let mut bin_occupancy = vec![0u16; num_bins];

    let key0 = derive_cuckoo_key(group_id, 0);
    let key1 = derive_cuckoo_key(group_id, 1);

    let get_sh = |idx: u32| -> &[u8] {
        let base = idx as usize * ONION_INDEX_RECORD_SIZE;
        &mmap[base..base + SCRIPT_HASH_SIZE]
    };

    let mut stash = 0usize;

    for &idx in entries {
        let sh = get_sh(idx);
        let bin0 = cuckoo_hash(sh, key0, num_bins);
        let bin1 = cuckoo_hash(sh, key1, num_bins);

        // Place in whichever bin has more room (2-choice)
        let (first, second) = if bin_occupancy[bin0] <= bin_occupancy[bin1] {
            (bin0, bin1)
        } else {
            (bin1, bin0)
        };

        let occ0 = bin_occupancy[first] as usize;
        if occ0 < SLOTS_PER_BIN {
            table[first * SLOTS_PER_BIN + occ0] = idx;
            bin_occupancy[first] += 1;
            continue;
        }

        let occ1 = bin_occupancy[second] as usize;
        if occ1 < SLOTS_PER_BIN {
            table[second * SLOTS_PER_BIN + occ1] = idx;
            bin_occupancy[second] += 1;
            continue;
        }

        // Both bins full — try cuckoo eviction
        let mut current_idx = idx;
        let mut current_bin = first;
        let mut success = false;

        for kick in 0..CUCKOO_MAX_KICKS {
            let occ = bin_occupancy[current_bin] as usize;
            let evict_slot = kick % occ;
            let evicted = table[current_bin * SLOTS_PER_BIN + evict_slot];
            table[current_bin * SLOTS_PER_BIN + evict_slot] = current_idx;

            let ev_sh = get_sh(evicted);
            let ev_bin0 = cuckoo_hash(ev_sh, key0, num_bins);
            let ev_bin1 = cuckoo_hash(ev_sh, key1, num_bins);
            let alt_bin = if ev_bin0 == current_bin { ev_bin1 } else { ev_bin0 };

            let alt_occ = bin_occupancy[alt_bin] as usize;
            if alt_occ < SLOTS_PER_BIN {
                table[alt_bin * SLOTS_PER_BIN + alt_occ] = evicted;
                bin_occupancy[alt_bin] += 1;
                success = true;
                break;
            }

            current_idx = evicted;
            current_bin = alt_bin;
        }

        if !success {
            stash += 1;
        }
    }

    (table, stash == 0)
}

/// Serialize a cuckoo table into OnionPIR entries.
/// Each bin (256 slots × 15 bytes) becomes one 3840-byte OnionPIR entry.
fn serialize_cuckoo_bin(
    table: &[u32],
    bin: usize,
    mmap: &[u8],
) -> [u8; ONIONPIR_ENTRY_SIZE] {
    let mut entry = [0u8; ONIONPIR_ENTRY_SIZE];
    let base = bin * SLOTS_PER_BIN;

    for slot in 0..SLOTS_PER_BIN {
        let idx = table[base + slot];
        let slot_offset = slot * INDEX_SLOT_SIZE;

        if idx == EMPTY {
            // Zero-filled (already initialized)
            continue;
        }

        let entry_base = idx as usize * ONION_INDEX_RECORD_SIZE;
        let sh = &mmap[entry_base..entry_base + SCRIPT_HASH_SIZE];

        // Tag (8 bytes)
        let tag = compute_tag(TAG_SEED, sh);
        entry[slot_offset..slot_offset + 8].copy_from_slice(&tag.to_le_bytes());

        // entry_id (4 bytes) + byte_offset (2 bytes) + num_entries (1 byte)
        // These are at bytes 20..27 of the onion index entry
        entry[slot_offset + 8..slot_offset + 15]
            .copy_from_slice(&mmap[entry_base + 20..entry_base + 27]);
    }

    entry
}

// ─── --consolidate-only helper ──────────────────────────────────────────────

/// Concatenate existing group_{0..K-1}.bin files from `output_dir` into
/// `index_all_file` and remove the scratch directory. Used by the
/// `--consolidate-only` flag to retrofit existing preprocessed snapshots
/// into the new single-file layout without re-running NTT preprocessing.
fn consolidate_only_main(
    output_dir: &Path,
    index_all_file: &str,
    total_start: Instant,
) {
    println!("[consolidate-only] Scanning {} for group_*.bin files...", output_dir.display());

    // Discover K by counting group_N.bin files. We require them to be
    // contiguously numbered 0..K-1, all the same size.
    let mut group_paths: Vec<PathBuf> = Vec::new();
    let mut b = 0usize;
    loop {
        let path = output_dir.join(format!("group_{}.bin", b));
        if !path.exists() {
            break;
        }
        group_paths.push(path);
        b += 1;
    }
    if group_paths.is_empty() {
        panic!(
            "[consolidate-only] No group_N.bin files found in {}. Was this directory already consolidated?",
            output_dir.display()
        );
    }
    let k_found = group_paths.len();
    let per_group_bytes = fs::metadata(&group_paths[0])
        .expect("stat group_0.bin")
        .len() as usize;
    println!(
        "[consolidate-only] Found K={} preprocessed groups, per_group_bytes={} ({})",
        k_found,
        per_group_bytes,
        format_bytes(per_group_bytes as u64),
    );

    let total_bytes = ONION_INDEX_ALL_HEADER_BYTES + k_found * per_group_bytes;
    println!(
        "[consolidate-only] Total output: {} bytes ({})",
        total_bytes,
        format_bytes(total_bytes as u64),
    );

    let out = File::create(index_all_file).expect("create onion_index_all.bin");
    let mut w = BufWriter::with_capacity(16 * 1024 * 1024, out);

    // Master header (32 bytes)
    w.write_all(&ONION_INDEX_ALL_MAGIC.to_le_bytes()).unwrap();
    w.write_all(&(k_found as u64).to_le_bytes()).unwrap();
    w.write_all(&(per_group_bytes as u64).to_le_bytes()).unwrap();
    w.write_all(&0u64.to_le_bytes()).unwrap();

    let mut written: u64 = 0;
    for (b, path) in group_paths.iter().enumerate() {
        let meta = fs::metadata(path).expect("stat group file");
        assert_eq!(
            meta.len() as usize,
            per_group_bytes,
            "group_{}.bin size mismatch: expected {}, got {}",
            b, per_group_bytes, meta.len(),
        );
        let bytes = fs::read(path).expect("read group file");
        w.write_all(&bytes).unwrap();
        written += bytes.len() as u64;
        if b % 5 == 0 || b + 1 == k_found {
            eprint!("\r  Appending group {}/{}", b + 1, k_found);
            let _ = io::stderr().flush();
        }
    }
    eprintln!();
    w.flush().unwrap();
    drop(w);

    let actual_size = fs::metadata(index_all_file).expect("stat output").len() as usize;
    assert_eq!(
        actual_size, total_bytes,
        "onion_index_all.bin size mismatch: expected {}, got {}",
        total_bytes, actual_size
    );
    println!("[consolidate-only] Wrote {} bytes; removing scratch dir {}", written, output_dir.display());
    fs::remove_dir_all(output_dir).expect("remove per-group dir");

    println!("\n=== Summary (consolidate-only) ===");
    println!("Consolidated K:    {}", k_found);
    println!("Per-group bytes:   {} ({})", per_group_bytes, format_bytes(per_group_bytes as u64));
    println!("Total output:      {} ({})", total_bytes, format_bytes(total_bytes as u64));
    println!("Total time:        {:.2?}", total_start.elapsed());
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    assert!(
        SLOTS_PER_BIN * INDEX_SLOT_SIZE <= ONIONPIR_ENTRY_SIZE,
        "slots_per_bin * slot_size must fit within OnionPIR entry size ({}*{}={} > {})",
        SLOTS_PER_BIN, INDEX_SLOT_SIZE,
        SLOTS_PER_BIN * INDEX_SLOT_SIZE, ONIONPIR_ENTRY_SIZE,
    );

    println!("=== gen_3_onion: Build OnionPIR Index Database ===\n");
    let total_start = Instant::now();

    let gen_args = resolve_paths();
    let paths = &gen_args.paths;
    let index_file_path = &paths.index_file;
    let output_dir = &paths.output_dir;
    let meta_file = &paths.meta_file;
    let bin_hashes_file = &paths.bin_hashes_file;
    let index_all_file = &paths.index_all_file;
    println!("Paths:");
    println!("  Input index:     {}", index_file_path);
    println!("  Scratch dir:     {}", output_dir.display());
    println!("  Output meta:     {}", meta_file);
    println!("  Output hashes:   {}", bin_hashes_file);
    println!("  Output all:      {}", index_all_file);
    if gen_args.consolidate_only {
        println!("  Mode:            --consolidate-only (skip steps 1\u{2013}7)");
    }
    println!();

    // ── --consolidate-only fast path ────────────────────────────────────
    //
    // Skip steps 1–7 (the expensive parts: read input, build cuckoo tables,
    // preprocess). Assume output_dir already contains K preprocessed
    // group_{0..K-1}.bin files from a prior build, and just concatenate
    // them into index_all_file. Used to retrofit existing main-DB snapshots
    // into the consolidated layout without re-running NTT preprocessing.
    if gen_args.consolidate_only {
        consolidate_only_main(output_dir, index_all_file, total_start);
        return;
    }

    // ── 1. Read index file ──────────────────────────────────────────────
    println!("[1] Memory-mapping index file: {}", index_file_path);
    let file = File::open(&index_file_path).expect("open index file");
    let mmap = unsafe { Mmap::map(&file) }.expect("mmap index");
    let n = mmap.len() / ONION_INDEX_RECORD_SIZE;
    assert_eq!(mmap.len() % ONION_INDEX_RECORD_SIZE, 0, "index file not aligned");
    println!("  {} entries ({})", n, format_bytes(mmap.len() as u64));

    // Count non-whale entries
    let mut non_whale = 0usize;
    for i in 0..n {
        let base = i * ONION_INDEX_RECORD_SIZE;
        let num_entries_byte = mmap[base + 26]; // last byte = num_entries or FLAG_WHALE
        // Whale entries have num_entries = FLAG_WHALE (0x40) from gen_1_onion
        // Actually, gen_1_onion writes: entry_id=0, offset=0, num_entries=FLAG_WHALE
        // So the last byte (num_entries field) is 0x40 for whales
        if num_entries_byte != FLAG_WHALE {
            non_whale += 1;
        }
    }
    println!("  Non-whale entries: {} (whale: {})", non_whale, n - non_whale);

    // ── 2. Assign entries to PBC groups ─────────────────────────────────
    println!("\n[2] Assigning entries to {} PBC groups...", K);
    let t_assign = Instant::now();

    let expected_per_group = (n * NUM_HASHES) / K + 1;
    let mut groups: Vec<Vec<u32>> = (0..K)
        .map(|_| Vec::with_capacity(expected_per_group))
        .collect();

    // Include whale entries — they must be findable in the index so clients
    // can detect them and skip the chunk phase.
    for i in 0..n {
        let base = i * ONION_INDEX_RECORD_SIZE;
        let sh = &mmap[base..base + SCRIPT_HASH_SIZE];
        let assigned = derive_groups(sh);
        for &b in &assigned {
            groups[b].push(i as u32);
        }
    }

    let group_sizes: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    let max_group = *group_sizes.iter().max().unwrap();
    let min_group = *group_sizes.iter().min().unwrap();
    let avg_group = group_sizes.iter().sum::<usize>() as f64 / K as f64;
    println!("  Done in {:.2?}", t_assign.elapsed());
    println!("  Group sizes: min={}, max={}, avg={:.0}", min_group, max_group, avg_group);

    // ── 3. Build cuckoo tables in parallel ──────────────────────────────
    let bins_per_table =
        ((max_group as f64) / (SLOTS_PER_BIN as f64 * CUCKOO_LOAD_FACTOR)).ceil() as usize;

    println!("\n[3] Building cuckoo tables ({}-hash, bs={}, bins_per_table={})...",
        CUCKOO_NUM_HASHES, SLOTS_PER_BIN, bins_per_table);
    let t_cuckoo = Instant::now();

    let mmap_slice: &[u8] = &mmap;
    let completed = AtomicUsize::new(0);

    let cuckoo_results: Vec<(usize, Vec<u32>, bool)> = groups
        .into_par_iter()
        .enumerate()
        .map(|(group_id, entries)| {
            let (table, success) = build_index_cuckoo(group_id, &entries, mmap_slice, bins_per_table);
            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            if done % 10 == 0 || done == K {
                eprint!("\r  Progress: {}/{} groups", done, K);
                let _ = io::stderr().flush();
            }
            (group_id, table, success)
        })
        .collect();

    eprintln!();
    println!("  Done in {:.2?}", t_cuckoo.elapsed());

    // Check for failures
    let failures: Vec<_> = cuckoo_results.iter().filter(|(_, _, s)| !s).collect();
    if !failures.is_empty() {
        for (bid, _, _) in &failures {
            eprintln!("  FAILED: group {}", bid);
        }
        panic!("{} groups failed cuckoo insertion!", failures.len());
    }

    // ── 4. Build OnionPIR databases ─────────────────────────────────────
    println!("\n[4] Building OnionPIR databases (push_chunk → preprocess → save)...");
    fs::create_dir_all(&output_dir).expect("create output dir");

    let t_pir = Instant::now();
    let p = onionpir::params_info(bins_per_table as u64);
    let padded_num = p.num_entries as usize;
    let entry_size = p.entry_size as usize;
    let fst_dim = p.fst_dim_sz as usize;
    let other_dim = p.other_dim_sz as usize;

    println!("  OnionPIR params: padded={}, entry_size={}, fst_dim={}, other_dim={}",
        padded_num, entry_size, fst_dim, other_dim);
    println!("  Physical size per group: {:.2} MB", p.physical_size_mb);
    println!("  Total for {} groups: {:.2} GB", K, p.physical_size_mb * K as f64 / 1024.0);

    // Process groups sequentially (OnionPIR Server is not Send)
    for (group_id, table, _) in &cuckoo_results {
        let preproc_path = output_dir.join(format!("group_{}.bin", group_id));

        // Check if already preprocessed
        let mut server = PirServer::new(bins_per_table as u64);
        if preproc_path.exists() && server.load_db(preproc_path.to_str().unwrap()) {
            if *group_id == 0 {
                println!("  Loading existing preprocessed databases...");
            }
            continue;
        }

        if *group_id == 0 {
            println!("  Building new databases (this takes a while)...");
        }

        let t_group = Instant::now();

        // Populate: each cuckoo bin → one OnionPIR entry
        let chunk_size = fst_dim * entry_size;
        for chunk_idx in 0..other_dim {
            let mut chunk_data = vec![0u8; chunk_size];
            for i in 0..fst_dim {
                let global_bin = chunk_idx * fst_dim + i;
                if global_bin < bins_per_table {
                    let entry_bytes = serialize_cuckoo_bin(table, global_bin, mmap_slice);
                    let offset = i * entry_size;
                    chunk_data[offset..offset + entry_size].copy_from_slice(&entry_bytes);
                }
            }
            server.push_chunk(&chunk_data, chunk_idx);
        }

        server.preprocess();
        server.save_db(preproc_path.to_str().unwrap());

        if *group_id % 10 == 0 || *group_id + 1 == K {
            eprintln!("  Group {}/{} preprocessed in {:.2?}", group_id + 1, K, t_group.elapsed());
        }
    }
    println!("  All groups built in {:.2?}", t_pir.elapsed());

    // ── 5. Save metadata ────────────────────────────────────────────────
    println!("\n[5] Saving metadata to {}...", meta_file);
    {
        let meta_out = File::create(&meta_file).expect("create meta file");
        let mut w = BufWriter::new(meta_out);
        let magic: u64 = 0xBA7C_0010_0000_0002;
        w.write_all(&magic.to_le_bytes()).unwrap();
        w.write_all(&(K as u32).to_le_bytes()).unwrap();
        w.write_all(&(CUCKOO_NUM_HASHES as u32).to_le_bytes()).unwrap();
        w.write_all(&(SLOTS_PER_BIN as u32).to_le_bytes()).unwrap();
        w.write_all(&(bins_per_table as u32).to_le_bytes()).unwrap();
        w.write_all(&MASTER_SEED.to_le_bytes()).unwrap();
        w.write_all(&TAG_SEED.to_le_bytes()).unwrap();
        w.write_all(&(INDEX_SLOT_SIZE as u32).to_le_bytes()).unwrap();
        w.flush().unwrap();
    }
    println!("  Done");

    // ── 6. Compute and write INDEX bin hashes (for per-bin Merkle) ─────
    println!("\n[6] Computing INDEX bin hashes for per-bin Merkle...");
    let t_hash = Instant::now();
    {
        let total_bins = K * bins_per_table;
        let mut bin_hashes = Vec::with_capacity(total_bins * 32);
        for (group_id, table, _) in &cuckoo_results {
            for bin in 0..bins_per_table {
                let entry_bytes = serialize_cuckoo_bin(table, bin, mmap_slice);
                let hash = pir_core::merkle::sha256(&entry_bytes);
                bin_hashes.extend_from_slice(&hash);
            }
            if *group_id % 10 == 0 || *group_id + 1 == K {
                eprint!("\r  Hashing group {}/{}", group_id + 1, K);
            }
        }
        eprintln!();

        // Header: [4B K][4B bins_per_table]
        let f = File::create(&bin_hashes_file).expect("create bin hashes file");
        let mut w = BufWriter::new(f);
        w.write_all(&(K as u32).to_le_bytes()).unwrap();
        w.write_all(&(bins_per_table as u32).to_le_bytes()).unwrap();
        w.write_all(&bin_hashes).unwrap();
        w.flush().unwrap();
        println!("  Wrote {} bin hashes ({} bytes) to {} in {:.2?}",
            total_bins, 8 + total_bins * 32, bin_hashes_file, t_hash.elapsed());
    }

    // ── 7. Verify with test query ───────────────────────────────────────
    println!("\n[7] Verification: test query against group 0...");

    // Find a non-whale entry assigned to group 0
    let mut test_idx = None;
    for i in 0..n {
        let base = i * ONION_INDEX_RECORD_SIZE;
        if mmap[base + 26] == FLAG_WHALE { continue; }
        let sh = &mmap[base..base + SCRIPT_HASH_SIZE];
        let assigned = derive_groups(sh);
        if assigned.contains(&0) {
            test_idx = Some(i);
            break;
        }
    }
    let test_idx = test_idx.expect("no entries in group 0");
    let test_base = test_idx * ONION_INDEX_RECORD_SIZE;
    let test_sh = &mmap[test_base..test_base + SCRIPT_HASH_SIZE];
    let test_tag = compute_tag(TAG_SEED, test_sh);

    // Find which bin this entry is in
    let test_table = &cuckoo_results[0].1;
    let key0 = derive_cuckoo_key(0, 0);
    let key1 = derive_cuckoo_key(0, 1);
    let bin0 = cuckoo_hash(test_sh, key0, bins_per_table);
    let bin1 = cuckoo_hash(test_sh, key1, bins_per_table);

    let mut found_bin = None;
    for &candidate_bin in &[bin0, bin1] {
        let base = candidate_bin * SLOTS_PER_BIN;
        for slot in 0..SLOTS_PER_BIN {
            if test_table[base + slot] == test_idx as u32 {
                found_bin = Some(candidate_bin);
                break;
            }
        }
        if found_bin.is_some() { break; }
    }
    let test_bin = found_bin.expect("test entry not found in cuckoo table");

    println!("  Test entry: index={}, bin={}, tag=0x{:016x}", test_idx, test_bin, test_tag);

    // Load the preprocessed database and query
    let preproc_path = output_dir.join("group_0.bin");
    let mut server = PirServer::new(bins_per_table as u64);
    assert!(server.load_db(preproc_path.to_str().unwrap()), "failed to load group_0.bin");

    let mut client = PirClient::new(bins_per_table as u64);
    let client_id = client.id();
    server.set_galois_key(client_id, &client.generate_galois_keys());
    server.set_gsw_key(client_id, &client.generate_gsw_keys());

    let query = client.generate_query(test_bin as u64);
    let response = server.answer_query(client_id, &query);
    let decrypted = client.decrypt_response(test_bin as u64, &response);

    // The decrypted data is a 3840-byte bin with 256 × 15-byte slots.
    // Scan for our tag.
    let mut tag_found = false;
    for slot in 0..SLOTS_PER_BIN {
        let offset = slot * INDEX_SLOT_SIZE;
        if offset + 8 > decrypted.len() { break; }
        let slot_tag = u64::from_le_bytes(decrypted[offset..offset + 8].try_into().unwrap());
        if slot_tag == test_tag {
            let entry_id = u32::from_le_bytes(decrypted[offset + 8..offset + 12].try_into().unwrap());
            let byte_offset = u16::from_le_bytes(decrypted[offset + 12..offset + 14].try_into().unwrap());
            let num_entries = decrypted[offset + 14];
            println!("  Tag match at slot {}: entry_id={}, offset={}, num_entries={}",
                slot, entry_id, byte_offset, num_entries);

            // Verify against original index entry
            let orig_entry_id = u32::from_le_bytes(mmap[test_base + 20..test_base + 24].try_into().unwrap());
            let orig_offset = u16::from_le_bytes(mmap[test_base + 24..test_base + 26].try_into().unwrap());
            let orig_num = mmap[test_base + 26];

            if entry_id == orig_entry_id && byte_offset == orig_offset && num_entries == orig_num {
                println!("  Verification: PASS (matches original index entry)");
            } else {
                println!("  Verification: MISMATCH!");
                println!("    Expected: entry_id={}, offset={}, num={}", orig_entry_id, orig_offset, orig_num);
            }
            tag_found = true;
            break;
        }
    }
    if !tag_found {
        println!("  Verification: FAIL (tag 0x{:016x} not found in decrypted bin)", test_tag);
    }

    // ── 8. Consolidate per-group files into one onion_index_all.bin ─────
    //
    // Layout: [master header: 32B][group_0: per_group_bytes][group_1: ...]
    //         ... [group_{K-1}: per_group_bytes]
    // The 32-byte master header is [ONION_INDEX_ALL_MAGIC u64 | K u64 |
    // per_group_bytes u64 | reserved u64]. Each group payload is whatever
    // OnionPIR's save_db_to_file produced — server-side mmaps the whole
    // file once and passes a per-group slice to load_db_from_bytes().
    println!("\n[8] Consolidating {} per-group files into {}...", K, index_all_file);
    let t_consolidate = Instant::now();
    {
        // All groups have identical size because they share params.
        // Read the first group's size and assert the rest match.
        let first_path = output_dir.join("group_0.bin");
        let per_group_bytes = fs::metadata(&first_path)
            .expect("stat group_0.bin")
            .len() as usize;
        println!("  Per-group bytes: {} ({})", per_group_bytes, format_bytes(per_group_bytes as u64));

        let total_bytes = ONION_INDEX_ALL_HEADER_BYTES + K * per_group_bytes;
        println!("  Total output:    {} ({})", total_bytes, format_bytes(total_bytes as u64));

        let out = File::create(index_all_file).expect("create onion_index_all.bin");
        let mut w = BufWriter::with_capacity(16 * 1024 * 1024, out);

        // Master header (32 bytes)
        w.write_all(&ONION_INDEX_ALL_MAGIC.to_le_bytes()).unwrap();
        w.write_all(&(K as u64).to_le_bytes()).unwrap();
        w.write_all(&(per_group_bytes as u64).to_le_bytes()).unwrap();
        w.write_all(&0u64.to_le_bytes()).unwrap();

        // Append each group's preprocessed bytes in order.
        let mut written: u64 = 0;
        for b in 0..K {
            let path = output_dir.join(format!("group_{}.bin", b));
            let meta = fs::metadata(&path).expect("stat group file");
            assert_eq!(
                meta.len() as usize,
                per_group_bytes,
                "group_{}.bin size mismatch: expected {}, got {}",
                b, per_group_bytes, meta.len()
            );
            let bytes = fs::read(&path).expect("read group file");
            w.write_all(&bytes).unwrap();
            written += bytes.len() as u64;
            if b % 10 == 0 || b + 1 == K {
                eprint!("\r  Appending group {}/{}", b + 1, K);
                let _ = io::stderr().flush();
            }
        }
        eprintln!();
        w.flush().unwrap();
        drop(w);

        let actual_size = fs::metadata(index_all_file).expect("stat output").len() as usize;
        assert_eq!(
            actual_size, total_bytes,
            "onion_index_all.bin size mismatch: expected {}, got {}",
            total_bytes, actual_size
        );

        // Clean up the scratch per-group directory. We intentionally delete
        // it so subsequent runs don't mix stale per-group files with the new
        // consolidated layout. The server's load path is fully switched to
        // the consolidated file.
        println!("  Wrote {} bytes; removing scratch dir {}", written, output_dir.display());
        fs::remove_dir_all(&output_dir).expect("remove per-group dir");
    }
    println!("  Consolidated in {:.2?}", t_consolidate.elapsed());

    // ── Summary ─────────────────────────────────────────────────────────
    println!("\n=== Summary ===");
    println!("Index entries:     {} ({} non-whale)", n, non_whale);
    println!("PBC groups:        {}", K);
    println!("Bins per table:    {} ({} slots × {} bytes = {} B/bin)",
        bins_per_table, SLOTS_PER_BIN, INDEX_SLOT_SIZE, ONIONPIR_ENTRY_SIZE);
    println!("OnionPIR per group: {:.2} MB (NTT-expanded)", p.physical_size_mb);
    println!("Total NTT storage: {:.2} GB", p.physical_size_mb * K as f64 / 1024.0);
    println!("Total time:        {:.2?}", total_start.elapsed());
}
