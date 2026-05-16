//! Pack grouped delta data into 40-byte chunks + index.
//!
//! Reads the output of delta_gen_0 (`delta_grouped_<A>_<B>.bin`) and produces:
//! - `delta_chunks_<A>_<B>.bin`       — delta data in 40-byte blocks
//! - `delta_index_<A>_<B>.bin`        — index (script_hash → offset, num_chunks)
//!
//! The format matches the main UTXO chunks/index format so the same
//! gen_2 (chunk cuckoo) and gen_3 (index cuckoo) pipeline can be reused.
//!
//! Per-scripthash data block format (same as stored in grouped delta):
//!   [varint num_spent]
//!     per spent: [32B txid][varint vout]
//!   [varint num_new]
//!     per new: [32B txid][varint vout][varint amount]
//!
//! Index entry format (25 bytes, same as main UTXO):
//!   [20B scripthash][4B start_chunk_id LE][1B num_chunks]
//!
//! Usage:
//!   delta_gen_1 <start_height> <end_height>

use pir_core::codec::read_varint;
use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::time::Instant;

const DATA_DIR: &str = "/Volumes/Bitcoin/data/intermediate";
const BLOCK_SIZE: usize = 40;
const SCRIPT_HASH_SIZE: usize = 20;
const MAX_CHUNKS_PER_SPK: usize = 255; // u8 max
const ZERO_PAD: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <start_height> <end_height>", args[0]);
        std::process::exit(1);
    }

    let start_height: u64 = args[1].parse().expect("start_height");
    let end_height: u64 = args[2].parse().expect("end_height");

    let input_path = format!("{}/delta_grouped_{}_{}.bin", DATA_DIR, start_height, end_height);
    let chunks_path = format!("{}/delta_chunks_{}_{}.bin", DATA_DIR, start_height, end_height);
    let index_path = format!("{}/delta_index_{}_{}.bin", DATA_DIR, start_height, end_height);

    println!("=== Delta Gen 1: Build Delta Chunks + Index ===");
    println!("Input:  {}", input_path);
    println!("Chunks: {}", chunks_path);
    println!("Index:  {}", index_path);
    println!();

    let t = Instant::now();

    // Read entire grouped delta file
    println!("[1] Reading grouped delta...");
    let mut data = Vec::new();
    File::open(&input_path)
        .expect("open delta grouped file")
        .read_to_end(&mut data)
        .expect("read delta grouped file");

    let num_scripts = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    println!("    {} scripthashes", num_scripts);

    // Open output files
    let chunks_file = File::create(&chunks_path).expect("create chunks file");
    let mut chunks_w = BufWriter::with_capacity(4 * 1024 * 1024, chunks_file);
    let index_file = File::create(&index_path).expect("create index file");
    let mut index_w = BufWriter::with_capacity(1024 * 1024, index_file);

    // Process each scripthash entry
    println!("[2] Packing into chunks...");

    let mut pos = 4; // skip header
    let mut chunk_id: u32 = 0;
    let mut total_chunks: u64 = 0;
    let mut skipped_too_large: u64 = 0;

    for i in 0..num_scripts {
        // Read scripthash
        let script_hash = &data[pos..pos + SCRIPT_HASH_SIZE];
        pos += SCRIPT_HASH_SIZE;

        // Read the delta data for this scripthash (spent + new)
        let data_start = pos;

        // Skip past spent entries
        let (num_spent, consumed) = read_varint(&data[pos..]);
        pos += consumed;
        for _ in 0..num_spent {
            pos += 32; // txid
            let (_, consumed) = read_varint(&data[pos..]); // vout
            pos += consumed;
        }

        // Skip past new entries
        let (num_new, consumed) = read_varint(&data[pos..]);
        pos += consumed;
        for _ in 0..num_new {
            pos += 32; // txid
            let (_, consumed) = read_varint(&data[pos..]); // vout
            pos += consumed;
            let (_, consumed) = read_varint(&data[pos..]); // amount
            pos += consumed;
        }

        let data_end = pos;
        let delta_bytes = &data[data_start..data_end];

        // Compute number of 40-byte chunks needed
        let num_blocks = delta_bytes.len().div_ceil(BLOCK_SIZE);

        if num_blocks > MAX_CHUNKS_PER_SPK {
            // Write sentinel index entry (num_chunks = 0)
            index_w.write_all(script_hash).unwrap();
            index_w.write_all(&0u32.to_le_bytes()).unwrap();
            index_w.write_all(&[0u8]).unwrap();
            skipped_too_large += 1;
            continue;
        }

        // Write chunk data (padded to BLOCK_SIZE boundary)
        chunks_w.write_all(delta_bytes).unwrap();
        let padding = num_blocks * BLOCK_SIZE - delta_bytes.len();
        if padding > 0 {
            chunks_w.write_all(&ZERO_PAD[..padding]).unwrap();
        }

        // Write index entry
        index_w.write_all(script_hash).unwrap();
        index_w.write_all(&chunk_id.to_le_bytes()).unwrap();
        index_w.write_all(&[num_blocks as u8]).unwrap();

        chunk_id += num_blocks as u32;
        total_chunks += num_blocks as u64;

        if (i + 1) % 100_000 == 0 {
            print!("\r    {}/{} scripthashes, {} chunks   ", i + 1, num_scripts, total_chunks);
            io::stdout().flush().ok();
        }
    }

    chunks_w.flush().unwrap();
    index_w.flush().unwrap();

    let chunks_size = std::fs::metadata(&chunks_path).map(|m| m.len()).unwrap_or(0);
    let index_size = std::fs::metadata(&index_path).map(|m| m.len()).unwrap_or(0);

    println!("\r    Done: {} scripthashes processed                           ", num_scripts);
    println!();
    println!("=== Summary ===");
    println!("Scripthashes:    {}", num_scripts);
    println!("Total chunks:    {} ({:.2} MB)", total_chunks, chunks_size as f64 / 1e6);
    println!("Index entries:   {} ({:.2} MB)", num_scripts, index_size as f64 / 1e6);
    println!("Skipped (>255):  {}", skipped_too_large);
    println!("Time:            {:.1}s", t.elapsed().as_secs_f64());
    println!();
    println!("Done. Next steps:");
    println!("  gen_2_build_chunk_cuckoo (on delta_chunks)");
    println!("  gen_3_build_index_cuckoo (on delta_index)");
}
