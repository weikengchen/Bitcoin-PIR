//! HarmonyPIR hint generation CLI.
//!
//! Reads cuckoo table files (same as DPF server) and generates a HarmonyPIR
//! state file containing pre-computed hints for all PBC buckets.
//!
//! Usage:
//!   cargo run --release -p runtime --bin harmonypir_gen_hints -- \
//!       --output /tmp/harmony_state.bin \
//!       [--prp-key <32-char hex>]

use build::common::*;
use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::Prp;
use harmonypir::relocation::RelocationDS;
use harmonypir_wasm::state::{self, BucketEntry, StateFileHeader};
use harmonypir_wasm::{compute_rounds, derive_bucket_key, find_best_t, HarmonyBucket, PRP_HOANG};

use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;
use std::io::BufWriter;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output_path = parse_arg(&args, "--output")
        .unwrap_or_else(|| "/tmp/harmony_state.bin".to_string());
    let prp_key = parse_prp_key(&args);

    println!("=== HarmonyPIR Hint Generator ===\n");
    println!("Output: {}", output_path);
    println!("PRP key: {}\n", hex_encode(&prp_key));

    // Load cuckoo tables.
    println!("[1] Loading index cuckoo: {}", CUCKOO_FILE);
    let index_file = File::open(CUCKOO_FILE).expect("open index cuckoo");
    let index_mmap = unsafe { Mmap::map(&index_file) }.expect("mmap index cuckoo");
    let (index_bins_per_table, tag_seed) = read_cuckoo_header(&index_mmap);
    let index_entry_size = CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE;
    println!("  bins_per_table={}, entry_size={}B, tag_seed=0x{:016x}",
        index_bins_per_table, index_entry_size, tag_seed);

    println!("[2] Loading chunk cuckoo: {}", CHUNK_CUCKOO_FILE);
    let chunk_file = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
    let chunk_mmap = unsafe { Mmap::map(&chunk_file) }.expect("mmap chunk cuckoo");
    let chunk_bins_per_table = read_chunk_cuckoo_header(&chunk_mmap);
    let chunk_entry_size = CHUNK_CUCKOO_BUCKET_SIZE * (4 + CHUNK_SIZE);
    println!("  bins_per_table={}, entry_size={}B", chunk_bins_per_table, chunk_entry_size);

    // Compute hints for index buckets.
    println!("\n[3] Computing hints for {} index buckets (N={}, w={})...",
        K, index_bins_per_table, index_entry_size);
    let t_start = Instant::now();

    let index_entries: Vec<BucketEntry> = (0..K as u32)
        .into_par_iter()
        .map(|b| {
            compute_bucket_hints(
                &prp_key, b, 0,
                &index_mmap, HEADER_SIZE, index_bins_per_table, index_entry_size,
            )
        })
        .collect();
    println!("  Done in {:.2?}", t_start.elapsed());

    // Compute hints for chunk buckets.
    println!("[4] Computing hints for {} chunk buckets (N={}, w={})...",
        K_CHUNK, chunk_bins_per_table, chunk_entry_size);
    let t_start = Instant::now();

    let chunk_entries: Vec<BucketEntry> = (0..K_CHUNK as u32)
        .into_par_iter()
        .map(|b| {
            compute_bucket_hints(
                &prp_key, K as u32 + b, 1,
                &chunk_mmap, CHUNK_HEADER_SIZE, chunk_bins_per_table, chunk_entry_size,
            )
        })
        .collect();
    println!("  Done in {:.2?}", t_start.elapsed());

    // Write state file.
    let all_entries: Vec<BucketEntry> = index_entries
        .into_iter()
        .chain(chunk_entries.into_iter())
        .collect();

    println!("\n[5] Writing state file ({} buckets)...", all_entries.len());
    let header = StateFileHeader {
        prp_backend: PRP_HOANG,
        prp_key,
        index_bins_per_table: index_bins_per_table as u32,
        chunk_bins_per_table: chunk_bins_per_table as u32,
        tag_seed,
    };

    let out_file = File::create(&output_path).expect("create output file");
    let mut writer = BufWriter::new(out_file);
    state::write_state_file(&mut writer, &header, &all_entries).unwrap();

    let file_size = std::fs::metadata(&output_path).unwrap().len();
    println!("  Written: {} ({:.2} MB)", output_path, file_size as f64 / (1024.0 * 1024.0));
    println!("\n=== Done ===");
}

fn compute_bucket_hints(
    prp_key: &[u8; 16],
    bucket_id: u32,
    level: u8,
    table_mmap: &[u8],
    header_size: usize,
    bins_per_table: usize,
    entry_size: usize,
) -> BucketEntry {
    let n = bins_per_table;
    let w = entry_size;
    let t = find_best_t(n as u32) as usize;

    let params = Params::new(n, w, t).expect("valid params");
    let m = params.m;

    let derived_key = derive_bucket_key(prp_key, bucket_id);
    let r = compute_rounds(n as u32);
    let domain = 2 * n;
    let prp: Box<dyn Prp> = Box::new(HoangPrp::new(domain, r, &derived_key));
    let ds = RelocationDS::new(n, t, prp).expect("DS init");

    // Compute hint parities.
    let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w]).collect();

    // The bucket's cuckoo table within the file.
    // For level 0 (index): bucket_id is used directly.
    // For level 1 (chunk): bucket_id has K offset, so strip it.
    let actual_bucket = if level == 1 { bucket_id - K as u32 } else { bucket_id };
    let table_offset = header_size + actual_bucket as usize * bins_per_table * entry_size;

    for k in 0..n {
        let cell = ds.locate(k).expect("locate");
        let seg = cell / t;
        let entry_start = table_offset + k * entry_size;
        let entry = &table_mmap[entry_start..entry_start + entry_size];
        for (d, s) in hints[seg].iter_mut().zip(entry.iter()) {
            *d ^= s;
        }
    }

    // Create a HarmonyBucket, load hints, serialize.
    let mut bucket = HarmonyBucket::new_with_backend(
        n as u32, w as u32, t as u32, prp_key, bucket_id, PRP_HOANG,
    ).expect("bucket creation");

    let flat: Vec<u8> = hints.into_iter().flat_map(|h| h.into_iter()).collect();
    bucket.load_hints(&flat).expect("load hints");

    BucketEntry {
        bucket_id,
        level,
        data: bucket.serialize(),
    }
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() - 1 {
        if args[i] == flag {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn parse_prp_key(args: &[String]) -> [u8; 16] {
    if let Some(hex) = parse_arg(args, "--prp-key") {
        let bytes = hex_decode(&hex);
        assert_eq!(bytes.len(), 16, "PRP key must be 16 bytes (32 hex chars)");
        let mut key = [0u8; 16];
        key.copy_from_slice(&bytes);
        key
    } else {
        // Generate random key using OS CSPRNG.
        use rand::RngCore;
        let mut key = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
