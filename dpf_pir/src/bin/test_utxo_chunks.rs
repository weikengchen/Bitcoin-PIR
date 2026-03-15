//! Test binary for UtxoChunkDatabase
//!
//! Usage:
//!   cargo run --bin test_utxo_chunks -- <index>
//!
//! Examples:
//!   cargo run --bin test_utxo_chunks -- 0
//!   cargo run --bin test_utxo_chunks -- 1208235
//!   cargo run --bin test_utxo_chunks -- 999999

use dpf_pir::{Database, UtxoChunkDatabase};
use std::env;

const DATA_PATH: &str = "/Volumes/Bitcoin/pir/utxo_chunks.bin";
const NUM_ENTRIES: usize = 33_038; // Total number of 32KB chunks in the database
const ENTRY_SIZE: usize = 32768;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        eprintln!("Usage: {} <index>", args[0]);
        eprintln!("  index: 0 to {} inclusive", NUM_ENTRIES - 1);
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} 0        # First entry", args[0]);
        eprintln!("  {} 33037    # Last entry", args[0]);
        eprintln!("  {} 9999     # Entry at index 9999", args[0]);
        std::process::exit(1);
    }

    let index: usize = match args[1].parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("Error: Invalid index '{}'. Must be a number.", args[1]);
            std::process::exit(1);
        }
    };

    if index >= NUM_ENTRIES {
        eprintln!(
            "Error: Index {} out of range. Must be 0 to {} inclusive.",
            index, NUM_ENTRIES - 1
        );
        std::process::exit(1);
    }

    println!("Opening UTXO chunks database...");
    println!("  Path: {}", DATA_PATH);
    println!("  Num entries: {}", NUM_ENTRIES);
    println!("  Entry size: {} bytes", ENTRY_SIZE);
    println!();

    // Create database with memory mapping for faster access
    let db = match UtxoChunkDatabase::with_mmap(
        "utxo_chunks",
        DATA_PATH,
        NUM_ENTRIES,
        ENTRY_SIZE,
    ) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Error opening database: {}", e);
            std::process::exit(1);
        }
    };

    println!("Database opened successfully:");
    println!("  ID: {}", db.id());
    println!("  File size: {} bytes", db.file_size());
    println!("  Expected size: {} bytes", db.expected_size());
    
    if db.file_size() < db.expected_size() {
        println!("  Note: File is smaller than expected. Last entry will be zero-padded.");
    }
    println!();

    // Read the entry
    println!("Reading entry at index {}...", index);
    let entry = match db.read_entry(index) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading entry: {}", e);
            std::process::exit(1);
        }
    };

    println!("Entry read successfully ({} bytes):", entry.len());
    println!();

    // Display entry info
    println!("First 64 bytes (hex):");
    for (i, chunk) in entry[..64].chunks(16).enumerate() {
        let hex: String = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if b >= 32 && b < 127 { b as char } else { '.' })
            .collect();
        println!("  {:04x}: {}  |{}|", i * 16, hex, ascii);
    }

    println!();
    println!("Last 64 bytes (hex):");
    let start = entry.len() - 64;
    for (i, chunk) in entry[start..].chunks(16).enumerate() {
        let hex: String = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if b >= 32 && b < 127 { b as char } else { '.' })
            .collect();
        println!("  {:04x}: {}  |{}|", start + i * 16, hex, ascii);
    }

    // Count non-zero bytes
    let non_zero_count = entry.iter().filter(|&&b| b != 0).count();
    let zero_count = entry.len() - non_zero_count;
    
    println!();
    println!("Summary:");
    println!("  Total bytes: {}", entry.len());
    println!("  Non-zero bytes: {}", non_zero_count);
    println!("  Zero bytes: {}", zero_count);
    
    if zero_count > 0 && index == NUM_ENTRIES - 1 {
        println!("  (Zero bytes are from padding for incomplete last entry)");
    }
}