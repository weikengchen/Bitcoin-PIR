//! Build UTXO chunks from gen2 UTXO set with bin-packing (multi-pass partitioned)
//!
//! Reads `/Volumes/Bitcoin/data/utxo_set.bin` (64-byte entries),
//! groups entries by HASH160 script hash, and writes compact output to:
//! - `/Volumes/Bitcoin/data/utxo_chunks.bin`       — compact UTXO data by address
//! - `/Volumes/Bitcoin/data/utxo_chunks_index.bin`  — index (script_hash → offset)
//!
//! Uses a multi-pass partitioned approach to limit memory usage:
//! - Entries are partitioned by `script_hash[0] % N`
//! - Each pass loads only one partition into memory, serializes, bin-packs, and writes
//! - The mmap is kept open across all passes; only the HashMap is rebuilt each pass
//!
//! Uses bin-packing algorithm to fill fixed-size blocks efficiently:
//! - Serialize all groups first, grouped by length
//! - Pack entries starting with largest, filling blocks optimally
//! - Large entries (> block size) span multiple blocks
//!
//! Input entry format (64 bytes each):
//!   [0..20)  HASH160 script hash (20 bytes)
//!   [20..52) Full TXID (32 bytes)
//!   [52..56) vout  (u32 LE)
//!   [56..64) amount (u64 LE)
//!
//! Output chunk format (utxo_chunks.bin):
//!   For each group (no script_hash prefix — use the index to find groups):
//!     [varint entry_count]
//!     For each entry (sorted by TXID descending, byte comparison):
//!       [32B raw TXID]
//!       [varint vout]
//!       [varint amount]
//!
//! Output index format (utxo_chunks_index.bin):
//!   For each group: [20B script_hash] [4B start_offset_half u32 LE]
//!   NOTE: The stored offset is byte_offset / 2 (right-shifted by 1).
//!   This doubles the addressable range to ~8.6GB, avoiding u32 overflow
//!   for files larger than 4GB. All group starts are 2-byte aligned by
//!   inserting 1-byte padding when needed.
//!
//! `--small` variant:
//!   Preliminary scan counts UTXOs per script_hash. Addresses with more UTXOs
//!   than average ("whale addresses") are serialized as varint(0) — a single byte
//!   indicating the address exists but its UTXOs are excluded. Output files use
//!   `_small` suffix.
//!
//! Usage:
//!   cargo run --bin gen_2_utxo_chunks -- [block_size_kb] [--partitions N] [--small]
//!
//! Examples:
//!   cargo run --bin gen_2_utxo_chunks                       # Default: 32KB blocks, 4 partitions
//!   cargo run --bin gen_2_utxo_chunks -- 64                 # 64KB blocks
//!   cargo run --bin gen_2_utxo_chunks -- 32 --partitions 8  # 8 partitions
//!   cargo run --bin gen_2_utxo_chunks -- 32 --small         # Small variant (exclude whales)

use bitcoinpir::utils;
use memmap2::Mmap;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

/// Input file path
const INPUT_FILE: &str = "/Volumes/Bitcoin/data/utxo_set.bin";

/// Output file paths (normal)
const CHUNKS_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks.bin";
const INDEX_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_index.bin";

/// Output file paths (small variant)
const CHUNKS_FILE_SMALL: &str = "/Volumes/Bitcoin/data/utxo_chunks_small.bin";
const INDEX_FILE_SMALL: &str = "/Volumes/Bitcoin/data/utxo_chunks_index_small.bin";

/// Size of each input entry in bytes
const ENTRY_SIZE: usize = 64;

/// Size of the HASH160 script hash
const SCRIPT_HASH_SIZE: usize = 20;

/// Size of the TXID
const TXID_SIZE: usize = 32;

/// Default block size in KB
const DEFAULT_BLOCK_SIZE_KB: usize = 32;

/// Default number of partitions
const DEFAULT_PARTITIONS: usize = 4;

/// A shortened UTXO entry with full 32-byte TXID
#[derive(Clone)]
struct ShortenedEntry {
    txid: [u8; TXID_SIZE],
    vout: u32,
    amount: u64,
}

/// A serialized group ready for bin-packing
struct SerializedGroup {
    script_hash: [u8; SCRIPT_HASH_SIZE],
    data: Vec<u8>,
}

/// Write a value as unsigned LEB128 (VarInt) to a Vec<u8>.
#[inline]
fn write_varint_to_vec(vec: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        vec.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Serialize a group of entries to bytes.
/// Returns the serialized data (varint entry_count + entries).
/// Each entry is: [32B raw TXID] [varint vout] [varint amount]
/// Entries are sorted by TXID descending (byte comparison).
fn serialize_group(entries: &mut [ShortenedEntry]) -> Vec<u8> {
    // Sort entries by txid descending (byte comparison)
    entries.sort_unstable_by(|a, b| b.txid.cmp(&a.txid));

    let mut data = Vec::with_capacity(entries.len() * (TXID_SIZE + 8) + 4);

    // Write entry count as varint
    write_varint_to_vec(&mut data, entries.len() as u64);

    for entry in entries.iter() {
        // Write raw 32-byte TXID (no delta encoding)
        data.extend_from_slice(&entry.txid);

        // Write vout as VarInt
        write_varint_to_vec(&mut data, entry.vout as u64);

        // Write amount as VarInt
        write_varint_to_vec(&mut data, entry.amount);
    }

    data
}

/// Serialize a whale group as varint(0) — a single byte indicating zero entries.
/// This signals to clients that the address exists but its UTXOs are excluded.
fn serialize_whale_group() -> Vec<u8> {
    let mut data = Vec::with_capacity(1);
    write_varint_to_vec(&mut data, 0);
    data
}

/// Parse CLI arguments: [block_size_kb] [--partitions N] [--small]
fn parse_args() -> (usize, usize, bool) {
    let args: Vec<String> = env::args().collect();
    let mut block_size_kb = DEFAULT_BLOCK_SIZE_KB;
    let mut num_partitions = DEFAULT_PARTITIONS;
    let mut small_mode = false;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--partitions" {
            i += 1;
            if i < args.len() {
                num_partitions = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("Warning: Invalid partition count '{}', using default {}", args[i], DEFAULT_PARTITIONS);
                    DEFAULT_PARTITIONS
                });
                if num_partitions == 0 {
                    eprintln!("Warning: Partition count must be > 0, using default {}", DEFAULT_PARTITIONS);
                    num_partitions = DEFAULT_PARTITIONS;
                }
            }
        } else if args[i] == "--small" {
            small_mode = true;
        } else {
            // Positional argument: block_size_kb
            match args[i].parse::<usize>() {
                Ok(kb) if kb > 0 => block_size_kb = kb,
                _ => {
                    eprintln!("Warning: Invalid block size '{}', using default {}KB",
                        args[i], DEFAULT_BLOCK_SIZE_KB);
                }
            }
        }
        i += 1;
    }

    (block_size_kb, num_partitions, small_mode)
}

fn main() {
    println!("=== Build Gen2 UTXO Chunks (Partitioned Bin-Packing) ===");
    println!();

    // Parse CLI arguments
    let (block_size_kb, num_partitions, small_mode) = parse_args();
    let block_size = block_size_kb * 1024;

    let (chunks_path, index_path) = if small_mode {
        (CHUNKS_FILE_SMALL, INDEX_FILE_SMALL)
    } else {
        (CHUNKS_FILE, INDEX_FILE)
    };

    println!("Configuration:");
    println!("  Block size:   {}KB ({} bytes)", block_size_kb, block_size);
    println!("  Partitions:   {}", num_partitions);
    println!("  Small mode:   {}", small_mode);
    println!("  Input:        {}", INPUT_FILE);
    println!("  Output:       {}", chunks_path);
    println!("  Index:        {}", index_path);
    println!();

    let total_start = Instant::now();

    // ── Step 1: Memory-map the input file ──────────────────────────────
    println!("[1] Memory-mapping input file...");

    let input_file = File::open(INPUT_FILE).unwrap_or_else(|e| {
        eprintln!("Failed to open input file: {}", e);
        std::process::exit(1);
    });

    let mmap = unsafe { Mmap::map(&input_file) }.unwrap_or_else(|e| {
        eprintln!("Failed to mmap input file: {}", e);
        std::process::exit(1);
    });

    let file_size = mmap.len();
    if file_size % ENTRY_SIZE != 0 {
        eprintln!(
            "Input file size ({}) is not a multiple of entry size ({})",
            file_size, ENTRY_SIZE
        );
        std::process::exit(1);
    }

    let entry_count = file_size / ENTRY_SIZE;
    println!(
        "  Mapped {} ({} entries)",
        utils::format_bytes(file_size as u64),
        entry_count
    );
    println!();

    // ── Step 2 (optional): Preliminary scan for --small mode ───────────
    let whale_counts: Option<HashMap<[u8; SCRIPT_HASH_SIZE], u32>> = if small_mode {
        println!("[2] Preliminary scan: counting UTXOs per script_hash...");
        let scan_start = Instant::now();

        let mut counts: HashMap<[u8; SCRIPT_HASH_SIZE], u32> = HashMap::with_capacity(80_000_000);

        let one_percent = std::cmp::max(1, entry_count / 100);
        let mut last_pct = 0u64;

        for i in 0..entry_count {
            let base = i * ENTRY_SIZE;
            let mut script_hash = [0u8; SCRIPT_HASH_SIZE];
            script_hash.copy_from_slice(&mmap[base..base + SCRIPT_HASH_SIZE]);

            *counts.entry(script_hash).or_insert(0) += 1;

            let current_pct = (i as u64 + 1) / one_percent as u64;
            if current_pct > last_pct && current_pct <= 100 {
                let elapsed = scan_start.elapsed().as_secs_f64();
                let frac = current_pct as f64 / 100.0;
                let eta = if frac > 0.0 {
                    (elapsed / frac) * (1.0 - frac)
                } else {
                    0.0
                };
                print!(
                    "\r    Scanning: {}% | ETA: {} | Entries: {}/{} | Unique: {}",
                    current_pct,
                    utils::format_duration(eta),
                    i + 1,
                    entry_count,
                    counts.len()
                );
                io::stdout().flush().ok();
                last_pct = current_pct;
            }
        }
        println!();

        let unique = counts.len() as u64;
        let average = entry_count as u64 / unique;
        let whale_count = counts.values().filter(|&&c| c as u64 > average).count();
        let whale_utxos: u64 = counts
            .values()
            .filter(|&&c| c as u64 > average)
            .map(|&c| c as u64)
            .sum();

        let scan_elapsed = scan_start.elapsed();
        println!(
            "  Scan completed in {:.2?} — {} unique script_hashes",
            scan_elapsed, unique
        );
        println!("  Average UTXOs per address: {}", average);
        println!(
            "  Whale addresses (count > {}): {} ({} UTXOs, {:.2}% of total)",
            average,
            whale_count,
            whale_utxos,
            whale_utxos as f64 / entry_count as f64 * 100.0
        );
        println!();

        Some(counts)
    } else {
        None
    };

    // Compute the whale threshold (average UTXOs per address) if in small mode
    let whale_threshold: u64 = if let Some(ref counts) = whale_counts {
        let unique = counts.len() as u64;
        if unique > 0 {
            entry_count as u64 / unique
        } else {
            u64::MAX
        }
    } else {
        u64::MAX
    };

    // ── Step 3: Open output files ──────────────────────────────────────
    let step_num = if small_mode { 3 } else { 2 };
    println!("[{}] Opening output files...", step_num);

    let chunks_file = File::create(chunks_path).unwrap_or_else(|e| {
        eprintln!("Failed to create chunks file: {}", e);
        std::process::exit(1);
    });
    let mut chunks_writer = BufWriter::with_capacity(1024 * 1024, chunks_file);

    let index_file = File::create(index_path).unwrap_or_else(|e| {
        eprintln!("Failed to create index file: {}", e);
        std::process::exit(1);
    });
    let mut index_writer = BufWriter::with_capacity(1024 * 1024, index_file);

    println!("  Output files opened");
    println!();

    // ── Step 4: Partitioned processing ─────────────────────────────────
    let step_num = step_num + 1;
    println!(
        "[{}] Processing {} partitions with bin-packing into {}KB blocks...",
        step_num, num_partitions, block_size_kb
    );
    println!();

    let packing_start = Instant::now();

    // Global statistics
    let mut current_offset: u64 = 0;
    let mut total_blocks_written: u64 = 0;
    let mut total_groups_written: u64 = 0;
    let mut total_padding_bytes: u64 = 0;
    let mut total_large_entries: u64 = 0;
    let mut total_whale_groups: u64 = 0;

    // Index entries collected across all partitions
    let mut all_index_entries: Vec<([u8; SCRIPT_HASH_SIZE], u32)> = Vec::new();

    for partition in 0..num_partitions {
        println!(
            "=== Partition {}/{} ===",
            partition + 1,
            num_partitions
        );
        let partition_start = Instant::now();

        // ── Build HashMap for this partition ───────────────────────────
        let build_start = Instant::now();
        let estimated_keys = 80_000_000 / num_partitions;
        let mut map: HashMap<[u8; SCRIPT_HASH_SIZE], Vec<ShortenedEntry>> =
            HashMap::with_capacity(estimated_keys);

        let one_percent = std::cmp::max(1, entry_count / 100);
        let mut last_pct = 0u64;

        for i in 0..entry_count {
            let base = i * ENTRY_SIZE;
            let chunk = &mmap[base..base + ENTRY_SIZE];

            // Check partition assignment
            if chunk[0] as usize % num_partitions != partition {
                continue;
            }

            // Extract script hash
            let mut script_hash = [0u8; SCRIPT_HASH_SIZE];
            script_hash.copy_from_slice(&chunk[..SCRIPT_HASH_SIZE]);

            // Parse TXID (32 bytes)
            let mut txid = [0u8; TXID_SIZE];
            txid.copy_from_slice(&chunk[20..52]);

            // Parse vout (u32 LE)
            let vout = u32::from_le_bytes([chunk[52], chunk[53], chunk[54], chunk[55]]);

            // Parse amount (u64 LE)
            let amount = u64::from_le_bytes([
                chunk[56], chunk[57], chunk[58], chunk[59],
                chunk[60], chunk[61], chunk[62], chunk[63],
            ]);

            map.entry(script_hash)
                .or_insert_with(Vec::new)
                .push(ShortenedEntry { txid, vout, amount });

            // Progress reporting
            let current_pct = (i as u64 + 1) / one_percent as u64;
            if current_pct > last_pct && current_pct <= 100 {
                let elapsed = build_start.elapsed().as_secs_f64();
                let frac = current_pct as f64 / 100.0;
                let eta = if frac > 0.0 {
                    (elapsed / frac) * (1.0 - frac)
                } else {
                    0.0
                };
                print!(
                    "\r    Building: {}% | ETA: {} | Entries scanned: {}/{} | Unique keys: {}",
                    current_pct,
                    utils::format_duration(eta),
                    i + 1,
                    entry_count,
                    map.len()
                );
                io::stdout().flush().ok();
                last_pct = current_pct;
            }
        }
        println!();

        let unique_keys = map.len();
        println!(
            "  HashMap built in {:.2?} — {} unique script_hashes in this partition",
            build_start.elapsed(),
            unique_keys
        );

        // ── Serialize groups and group by length ───────────────────────
        let serialize_start = Instant::now();

        let mut length_groups: BTreeMap<usize, VecDeque<SerializedGroup>> = BTreeMap::new();
        let mut partition_serialized_bytes: u64 = 0;
        let mut partition_whale_groups: u64 = 0;

        for (script_hash, mut entries) in map.drain() {
            // Check if this is a whale address in --small mode
            let is_whale = if let Some(ref counts) = whale_counts {
                counts
                    .get(&script_hash)
                    .map_or(false, |&c| c as u64 > whale_threshold)
            } else {
                false
            };

            let data = if is_whale {
                partition_whale_groups += 1;
                serialize_whale_group()
            } else {
                serialize_group(&mut entries)
            };

            let len = data.len();
            partition_serialized_bytes += len as u64;

            length_groups
                .entry(len)
                .or_default()
                .push_back(SerializedGroup { script_hash, data });
        }

        // Explicitly drop the empty HashMap to free memory
        drop(map);

        println!(
            "  Serialized {} groups in {:.2?} — {} total bytes{}",
            unique_keys,
            serialize_start.elapsed(),
            utils::format_bytes(partition_serialized_bytes),
            if partition_whale_groups > 0 {
                format!(" ({} whale groups as varint(0))", partition_whale_groups)
            } else {
                String::new()
            }
        );

        total_whale_groups += partition_whale_groups;

        // ── Bin-packing for this partition ──────────────────────────────
        let pack_start = Instant::now();

        let mut total_remaining: u64 = length_groups.values().map(|v| v.len() as u64).sum();
        let mut partition_blocks: u64 = 0;
        let mut partition_groups: u64 = 0;
        let mut partition_padding: u64 = 0;
        let mut partition_large: u64 = 0;

        // Collect index entries for this partition
        let mut partition_index: Vec<([u8; SCRIPT_HASH_SIZE], u32)> =
            Vec::with_capacity(unique_keys);

        while total_remaining > 0 {
            // Remaining space in current block
            let remaining = block_size - (current_offset as usize % block_size);

            // Find the largest entry that fits in remaining space
            let best_fit_len: Option<usize> = length_groups
                .range(..=remaining)
                .next_back()
                .map(|(&k, _)| k);

            if let Some(len) = best_fit_len {
                // Pop from this length group
                let group = length_groups.get_mut(&len).unwrap().pop_front().unwrap();

                // Remove the length group if now empty
                if length_groups.get(&len).unwrap().is_empty() {
                    length_groups.remove(&len);
                }
                total_remaining -= 1;

                // Ensure 2-byte alignment for offset encoding (offset/2 stored as u32)
                if current_offset % 2 != 0 {
                    chunks_writer.write_all(&[0u8]).unwrap();
                    partition_padding += 1;
                    current_offset += 1;
                }

                // Record offset in index (stored as offset/2 to address up to ~8.6GB)
                partition_index.push((group.script_hash, (current_offset / 2) as u32));

                // Write data
                chunks_writer.write_all(&group.data).unwrap();
                current_offset += len as u64;
                partition_groups += 1;

                // Update blocks count
                partition_blocks = current_offset / block_size as u64;
            } else {
                // No entry fits — take the largest available group
                let len = *length_groups.keys().next_back().unwrap();
                let group = length_groups.get_mut(&len).unwrap().pop_front().unwrap();

                if length_groups.get(&len).map_or(true, |v| v.is_empty()) {
                    length_groups.remove(&len);
                }
                total_remaining -= 1;

                // Pad remaining space
                if remaining > 0 && remaining < block_size {
                    chunks_writer.write_all(&vec![0u8; remaining]).unwrap();
                    partition_padding += remaining as u64;
                    current_offset += remaining as u64;
                }

                // Ensure 2-byte alignment for offset encoding (offset/2 stored as u32)
                if current_offset % 2 != 0 {
                    chunks_writer.write_all(&[0u8]).unwrap();
                    partition_padding += 1;
                    current_offset += 1;
                }

                // Record offset in index (stored as offset/2 to address up to ~8.6GB)
                partition_index.push((group.script_hash, (current_offset / 2) as u32));

                // Write the entire entry
                chunks_writer.write_all(&group.data).unwrap();
                current_offset += len as u64;
                partition_groups += 1;

                if len > block_size {
                    partition_large += 1;
                }

                partition_blocks = current_offset / block_size as u64;
            }
        }

        // Pad final partial block for this partition
        let final_remaining = block_size - (current_offset as usize % block_size);
        if final_remaining > 0 && final_remaining < block_size {
            chunks_writer.write_all(&vec![0u8; final_remaining]).unwrap();
            partition_padding += final_remaining as u64;
            current_offset += final_remaining as u64;
            partition_blocks = current_offset / block_size as u64;
        }

        println!(
            "  Bin-packing done in {:.2?} — {} groups, {} blocks, {} padding",
            pack_start.elapsed(),
            partition_groups,
            partition_blocks - total_blocks_written,
            utils::format_bytes(partition_padding)
        );

        // Write index entries for this partition to the index file
        for (script_hash, offset) in &partition_index {
            index_writer.write_all(script_hash).unwrap();
            index_writer.write_all(&offset.to_le_bytes()).unwrap();
        }

        // Accumulate global stats
        let partition_new_blocks = partition_blocks - total_blocks_written;
        total_blocks_written = partition_blocks;
        total_groups_written += partition_groups;
        total_padding_bytes += partition_padding;
        total_large_entries += partition_large;
        all_index_entries.extend(partition_index);

        println!(
            "  Partition {}/{} completed in {:.2?} — {} groups, {} new blocks",
            partition + 1,
            num_partitions,
            partition_start.elapsed(),
            partition_groups,
            partition_new_blocks
        );
        println!();
    }

    let packing_elapsed = packing_start.elapsed();

    // ── Step 5: Flush and report ───────────────────────────────────────
    let step_num = step_num + 1;
    println!("[{}] Flushing output files...", step_num);

    chunks_writer.flush().unwrap_or_else(|e| {
        eprintln!("Failed to flush chunks file: {}", e);
        std::process::exit(1);
    });
    index_writer.flush().unwrap_or_else(|e| {
        eprintln!("Failed to flush index file: {}", e);
        std::process::exit(1);
    });

    // Drop the whale counts map if it exists
    drop(whale_counts);

    println!("  Done!");
    println!();

    let total_elapsed = total_start.elapsed();

    println!("=== Summary ===");
    println!("Input entries:        {}", entry_count);
    println!("Groups written:       {}", total_groups_written);
    if small_mode {
        println!("Whale groups (excluded): {}", total_whale_groups);
    }
    println!();
    println!("Block size:           {}KB", block_size_kb);
    println!("Partitions:           {}", num_partitions);
    println!("Blocks written:       {}", total_blocks_written);
    println!(
        "Chunks file size:     {} ({} blocks x {}KB)",
        utils::format_bytes(current_offset),
        total_blocks_written,
        block_size_kb
    );
    let index_size = total_groups_written * 24;
    println!(
        "Index file size:      {} ({} entries x 24 bytes)",
        utils::format_bytes(index_size),
        total_groups_written
    );
    println!(
        "Padding overhead:     {} ({:.2}%)",
        utils::format_bytes(total_padding_bytes),
        if current_offset > 0 {
            total_padding_bytes as f64 / current_offset as f64 * 100.0
        } else {
            0.0
        }
    );
    println!(
        "Large entries (span): {}",
        total_large_entries
    );
    println!();

    // Compression ratio
    let original_size = entry_count as f64 * ENTRY_SIZE as f64;
    let compact_size = current_offset as f64 + index_size as f64;
    println!(
        "Original size:        {}",
        utils::format_bytes(original_size as u64)
    );
    println!(
        "Compact size:         {} (chunks + index)",
        utils::format_bytes(compact_size as u64)
    );
    if compact_size > 0.0 {
        println!("Compression ratio:    {:.2}x", original_size / compact_size);
    }
    println!();
    println!("Partitioned packing:  {:.2?}", packing_elapsed);
    println!("Total time:           {:.2?}", total_elapsed);
}
