//! Append whale sentinel entries to the existing UTXO index file.
//!
//! Scans utxo_set.bin to find script hashes with more than MAX_UTXOS_PER_SPK
//! non-dust UTXOs and appends sentinel index entries (num_chunks=0)
//! for each one. Also writes whale_addresses.txt for testing.
//!
//! Run this AFTER gen_1 (which may have been built before the whale sentinel feature)
//! and BEFORE gen_2b / gen_3, to patch the index file in-place.
//!
//! Usage:
//!   cargo run --release -p build --bin append_whale_sentinels

mod common;

use common::*;
use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::time::Instant;

const UTXO_FILE: &str = "/Volumes/Bitcoin/data/utxo_set.bin";
const WHALES_FILE: &str = "/Volumes/Bitcoin/data/whale_addresses.txt";

const ENTRY_SIZE: usize = 68;
const DUST_THRESHOLD: u64 = 576;
const MAX_UTXOS_PER_SPK: usize = 100;

fn main() {
    println!("=== Append Whale Sentinel Entries to Index ===");
    println!();

    let start = Instant::now();

    // ── 1. Memory-map UTXO set ──────────────────────────────────────────
    println!("[1] Memory-mapping UTXO set: {}", UTXO_FILE);
    let input_file = File::open(UTXO_FILE).expect("open utxo_set.bin");
    let mmap = unsafe { Mmap::map(&input_file) }.expect("mmap");
    let entry_count = mmap.len() / ENTRY_SIZE;
    assert_eq!(mmap.len() % ENTRY_SIZE, 0);
    println!("  {} entries ({:.2} GB)", entry_count, mmap.len() as f64 / 1e9);

    // ── 2. Count non-dust UTXOs per script hash ─────────────────────────
    println!("[2] Counting UTXOs per script hash (skipping dust <= {} sats)...", DUST_THRESHOLD);
    let scan_start = Instant::now();

    let mut counts: HashMap<[u8; SCRIPT_HASH_SIZE], usize> = HashMap::with_capacity(80_000_000);
    let one_percent = std::cmp::max(1, entry_count / 100);
    let mut last_pct = 0u64;

    for i in 0..entry_count {
        let base = i * ENTRY_SIZE;
        let chunk = &mmap[base..base + ENTRY_SIZE];

        let amount = u64::from_le_bytes(chunk[56..64].try_into().unwrap());
        if amount <= DUST_THRESHOLD {
            continue;
        }

        let mut script_hash = [0u8; SCRIPT_HASH_SIZE];
        script_hash.copy_from_slice(&chunk[..SCRIPT_HASH_SIZE]);

        *counts.entry(script_hash).or_insert(0) += 1;

        let current_pct = (i as u64 + 1) / one_percent as u64;
        if current_pct > last_pct && current_pct <= 100 {
            eprint!("\r  Scanning: {}% | {} entries | {} unique hashes",
                current_pct, i + 1, counts.len());
            let _ = io::stderr().flush();
            last_pct = current_pct;
        }
    }
    eprintln!();
    println!("  Scanned in {:.2?}, {} unique script hashes", scan_start.elapsed(), counts.len());

    // ── 3. Find whales ──────────────────────────────────────────────────
    let mut whale_entries: Vec<([u8; SCRIPT_HASH_SIZE], usize)> = counts
        .iter()
        .filter(|(_, &count)| count > MAX_UTXOS_PER_SPK)
        .map(|(hash, &count)| (*hash, count))
        .collect();
    whale_entries.sort_by(|a, b| b.1.cmp(&a.1));

    println!("  Found {} whale addresses (>{} UTXOs)", whale_entries.len(), MAX_UTXOS_PER_SPK);

    if whale_entries.is_empty() {
        println!("  No whales found. Nothing to do.");
        return;
    }

    // ── 4. Check existing index for already-present whales ──────────────
    println!("[3] Checking existing index for already-present whale entries...");
    let index_data = std::fs::read(INDEX_FILE).expect("read index file");
    let existing_entries = index_data.len() / INDEX_ENTRY_SIZE;

    let mut already_present = 0usize;
    let mut existing_hashes: std::collections::HashSet<[u8; SCRIPT_HASH_SIZE]> =
        std::collections::HashSet::with_capacity(existing_entries);
    for i in 0..existing_entries {
        let base = i * INDEX_ENTRY_SIZE;
        let mut sh = [0u8; SCRIPT_HASH_SIZE];
        sh.copy_from_slice(&index_data[base..base + SCRIPT_HASH_SIZE]);
        existing_hashes.insert(sh);
    }

    let new_whales: Vec<_> = whale_entries.iter()
        .filter(|(hash, _)| {
            if existing_hashes.contains(hash) {
                already_present += 1;
                false
            } else {
                true
            }
        })
        .cloned()
        .collect();

    println!("  Existing index: {} entries", existing_entries);
    println!("  Whales already in index: {} (skipping)", already_present);
    println!("  New whale sentinels to append: {}", new_whales.len());

    // ── 5. Append sentinel entries ──────────────────────────────────────
    if !new_whales.is_empty() {
        println!("[4] Appending {} sentinel entries to {}...", new_whales.len(), INDEX_FILE);
        let index_file = OpenOptions::new()
            .append(true)
            .open(INDEX_FILE)
            .expect("open index for append");
        let mut writer = BufWriter::new(index_file);

        for (script_hash, _count) in &new_whales {
            writer.write_all(script_hash).unwrap();          // 20B script_hash
            writer.write_all(&0u32.to_le_bytes()).unwrap();   // 4B start_chunk_id = 0
            writer.write_all(&[0u8]).unwrap();                // 1B num_chunks = 0
        }
        writer.flush().unwrap();

        let new_total = existing_entries + new_whales.len();
        println!("  Done. Index now has {} entries ({} bytes)",
            new_total, new_total * INDEX_ENTRY_SIZE);
    }

    // ── 6. Write whale addresses file ───────────────────────────────────
    println!("[5] Writing whale addresses to {}...", WHALES_FILE);
    {
        let whale_file = File::create(WHALES_FILE).expect("create whale addresses file");
        let mut w = BufWriter::new(whale_file);
        writeln!(w, "# Excluded whale addresses (>{} UTXOs per scriptPubKey)", MAX_UTXOS_PER_SPK).unwrap();
        writeln!(w, "# Format: script_hash_hex  utxo_count").unwrap();
        for (script_hash, count) in &whale_entries {
            let hex: String = script_hash.iter().map(|b| format!("{:02x}", b)).collect();
            writeln!(w, "{}  {}", hex, count).unwrap();
        }
        w.flush().unwrap();
    }
    println!("  Written {} entries", whale_entries.len());

    // Print sample for testing
    println!();
    println!("  Sample excluded whale addresses (for testing):");
    println!("  {:>4}  {:>8}  script_hash (hex)", "#", "UTXOs");
    for (i, (script_hash, count)) in whale_entries.iter().take(20).enumerate() {
        let hex: String = script_hash.iter().map(|b| format!("{:02x}", b)).collect();
        println!("  {:>4}  {:>8}  {}", i + 1, count, hex);
    }

    println!();
    println!("  Total time: {:.2?}", start.elapsed());
    println!();
    println!("Next steps:");
    println!("  1. cargo run --release -p build --bin gen_3_build_index_cuckoo");
}
