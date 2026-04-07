//! Generic cuckoo table builder for any sub-table type (INDEX or CHUNK).
//!
//! This is the parameterized version of gen_2/gen_3 that works for both
//! main UTXO databases and delta databases. It reads table parameters
//! from the command line and uses pir-core's generic cuckoo building.
//!
//! For INDEX level:
//!   build_cuckoo_generic index <index_file> <output_file>
//!   Reads 25-byte index entries, builds K=75 cuckoo tables with tagged slots.
//!
//! For CHUNK level:
//!   build_cuckoo_generic chunk <chunks_file> <index_file> <output_file>
//!   Reads chunks data + index file, builds K=80 cuckoo tables with inlined data.

use memmap2::Mmap;
use pir_core::cuckoo;
use pir_core::hash;
use pir_core::params::*;
use rayon::prelude::*;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 2000;
const TAG_SEED: u64 = 0xd4e5f6a7b8c91023;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  {} index <index_file> <output_file>", args[0]);
        eprintln!("  {} chunk <chunks_file> <index_file> <output_file>", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "index" => {
            if args.len() != 4 {
                eprintln!("Usage: {} index <index_file> <output_file>", args[0]);
                std::process::exit(1);
            }
            build_index_cuckoo(&args[2], &args[3]);
        }
        "chunk" => {
            if args.len() != 5 {
                eprintln!("Usage: {} chunk <chunks_file> <index_file> <output_file>", args[0]);
                std::process::exit(1);
            }
            build_chunk_cuckoo(&args[2], &args[3], &args[4]);
        }
        _ => {
            eprintln!("Unknown mode: {}. Use 'index' or 'chunk'.", args[1]);
            std::process::exit(1);
        }
    }
}

// ─── INDEX-level cuckoo builder ─────────────────────────────────────────────

fn build_index_cuckoo(index_file: &str, output_file: &str) {
    let params = &INDEX_PARAMS;

    println!("=== Generic Index Cuckoo Builder ===");
    println!("Input:  {}", index_file);
    println!("Output: {}", output_file);
    println!("K={}, slots_per_bin={}, slot_size={}, num_hashes={}",
        params.k, params.slots_per_bin, params.slot_size, params.num_hashes);
    println!();

    // Memory-map input
    let f = File::open(index_file).expect("open index file");
    let mmap = unsafe { Mmap::map(&f) }.expect("mmap index file");
    let n = mmap.len() / INDEX_RECORD_SIZE;
    println!("[1] Loaded {} index entries ({:.1} MB)", n, mmap.len() as f64 / 1e6);

    // Step 2: Assign entries to groups
    println!("[2] Assigning entries to {} groups...", params.k);
    let t = Instant::now();

    let mut group_entries: Vec<Vec<usize>> = vec![Vec::new(); params.k];
    for i in 0..n {
        let offset = i * INDEX_RECORD_SIZE;
        let script_hash = &mmap[offset..offset + SCRIPT_HASH_SIZE];
        let groups = hash::derive_groups_3(script_hash, params.k);
        for &b in &groups {
            group_entries[b].push(i);
        }
    }

    let max_load = group_entries.iter().map(|v| v.len()).max().unwrap_or(0);
    let bins_per_table = cuckoo::compute_bins_per_table(max_load, params.slots_per_bin);
    println!("    Max group load: {}, bins_per_table: {}", max_load, bins_per_table);
    println!("    Done in {:.2?}", t.elapsed());

    // Step 3: Build cuckoo tables in parallel
    println!("[3] Building cuckoo tables...");
    let t = Instant::now();
    let done_count = AtomicUsize::new(0);

    let tables: Vec<Vec<u32>> = (0..params.k)
        .into_par_iter()
        .map(|group_id| {
            let entries = &group_entries[group_id];
            let script_hashes: Vec<&[u8]> = entries
                .iter()
                .map(|&i| &mmap[i * INDEX_RECORD_SIZE..i * INDEX_RECORD_SIZE + SCRIPT_HASH_SIZE])
                .collect();

            let table = cuckoo::build_byte_keyed_table(&script_hashes, group_id, params, bins_per_table);

            let d = done_count.fetch_add(1, Ordering::Relaxed) + 1;
            if d % 10 == 0 || d == params.k {
                eprint!("\r    {}/{} tables built   ", d, params.k);
            }
            table
        })
        .collect();

    eprintln!();
    println!("    Done in {:.2?}", t.elapsed());

    // Step 4: Serialize
    println!("[4] Serializing to {}...", output_file);
    let t = Instant::now();

    let header = cuckoo::write_header(params, bins_per_table, TAG_SEED);
    let f = File::create(output_file).expect("create output file");
    let mut w = BufWriter::with_capacity(16 * 1024 * 1024, f);
    w.write_all(&header).unwrap();

    for group_id in 0..params.k {
        let table = &tables[group_id];
        let entries = &group_entries[group_id];

        for slot_idx in 0..(bins_per_table * params.slots_per_bin) {
            let entry_local = table[slot_idx];
            if entry_local == cuckoo::EMPTY {
                // Empty slot: write zeros (13 bytes = INDEX_SLOT_SIZE)
                w.write_all(&[0u8; INDEX_SLOT_SIZE]).unwrap();
            } else {
                let global_idx = entries[entry_local as usize];
                let offset = global_idx * INDEX_RECORD_SIZE;
                let script_hash = &mmap[offset..offset + SCRIPT_HASH_SIZE];

                // Write tagged entry: [8B tag][4B start_chunk_id][1B num_chunks]
                let tag = hash::compute_tag(TAG_SEED, script_hash);
                w.write_all(&tag.to_le_bytes()).unwrap();
                // start_chunk_id (4B) + num_chunks (1B)
                w.write_all(&mmap[offset + SCRIPT_HASH_SIZE..offset + INDEX_RECORD_SIZE]).unwrap();
            }
        }
    }

    w.flush().unwrap();
    let file_size = std::fs::metadata(output_file).map(|m| m.len()).unwrap_or(0);
    println!("    Written {:.2} GB in {:.2?}", file_size as f64 / 1e9, t.elapsed());
    println!();
    println!("Done.");
}

// ─── CHUNK-level cuckoo builder ─────────────────────────────────────────────

fn build_chunk_cuckoo(chunks_file: &str, index_file: &str, output_file: &str) {
    let params = &CHUNK_PARAMS;

    println!("=== Generic Chunk Cuckoo Builder ===");
    println!("Chunks: {}", chunks_file);
    println!("Index:  {}", index_file);
    println!("Output: {}", output_file);
    println!("K={}, slots_per_bin={}, num_hashes={}", params.k, params.slots_per_bin, params.num_hashes);
    println!();

    // Memory-map chunks data
    let f = File::open(chunks_file).expect("open chunks file");
    let chunks_mmap = unsafe { Mmap::map(&f) }.expect("mmap chunks file");
    let num_chunks = chunks_mmap.len() / CHUNK_SIZE;
    println!("[1] Loaded {} chunks ({:.1} MB)", num_chunks, chunks_mmap.len() as f64 / 1e6);

    // Step 2: Assign chunks to groups
    println!("[2] Assigning {} chunks to {} groups...", num_chunks, params.k);
    let t = Instant::now();

    let mut group_chunks: Vec<Vec<u32>> = vec![Vec::new(); params.k];
    for chunk_id in 0..num_chunks as u32 {
        let groups = hash::derive_int_groups_3(chunk_id, params.k);
        for &b in &groups {
            group_chunks[b].push(chunk_id);
        }
    }

    let max_load = group_chunks.iter().map(|v| v.len()).max().unwrap_or(0);
    let bins_per_table = cuckoo::compute_bins_per_table(max_load, params.slots_per_bin);
    println!("    Max group load: {}, bins_per_table: {}", max_load, bins_per_table);
    println!("    Done in {:.2?}", t.elapsed());

    // Step 3: Build cuckoo tables in parallel
    println!("[3] Building cuckoo tables...");
    let t = Instant::now();
    let done_count = AtomicUsize::new(0);

    let tables: Vec<Vec<u32>> = (0..params.k)
        .into_par_iter()
        .map(|group_id| {
            let ids = &group_chunks[group_id];
            let table = cuckoo::build_int_keyed_table(ids, group_id, params, bins_per_table);

            let d = done_count.fetch_add(1, Ordering::Relaxed) + 1;
            if d % 10 == 0 || d == params.k {
                eprint!("\r    {}/{} tables built   ", d, params.k);
            }
            table
        })
        .collect();

    eprintln!();
    println!("    Done in {:.2?}", t.elapsed());

    // Step 4: Serialize with inlined data
    println!("[4] Serializing to {}...", output_file);
    let t = Instant::now();

    let header = cuckoo::write_header(params, bins_per_table, 0);
    let f = File::create(output_file).expect("create output file");
    let mut w = BufWriter::with_capacity(16 * 1024 * 1024, f);
    w.write_all(&header).unwrap();

    let slot_size = 4 + CHUNK_SIZE; // 44 bytes
    let zero_slot = vec![0u8; slot_size];

    for group_id in 0..params.k {
        let table = &tables[group_id];
        let ids = &group_chunks[group_id];

        for slot_idx in 0..(bins_per_table * params.slots_per_bin) {
            let entry_local = table[slot_idx];
            if entry_local == cuckoo::EMPTY {
                w.write_all(&zero_slot).unwrap();
            } else {
                let chunk_id = ids[entry_local as usize];
                let data_offset = chunk_id as usize * CHUNK_SIZE;
                let chunk_data = &chunks_mmap[data_offset..data_offset + CHUNK_SIZE];

                // Write inlined slot: [4B chunk_id LE][40B data]
                w.write_all(&chunk_id.to_le_bytes()).unwrap();
                w.write_all(chunk_data).unwrap();
            }
        }
    }

    w.flush().unwrap();
    let file_size = std::fs::metadata(output_file).map(|m| m.len()).unwrap_or(0);
    println!("    Written {:.2} GB in {:.2?}", file_size as f64 / 1e9, t.elapsed());
    println!();
    println!("Done.");
}
