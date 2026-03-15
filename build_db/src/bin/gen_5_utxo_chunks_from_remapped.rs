//! Build UTXO chunks from the remapped UTXO set with bin-packing
//!
//! Reads `/Volumes/Bitcoin/data/remapped_utxo_set.bin` (36-byte entries),
//! groups entries by ScriptPubKey hash, and writes compact output to:
//! - `/Volumes/Bitcoin/data/utxo_chunks.bin`      — compact UTXO data by address
//! - `/Volumes/Bitcoin/data/utxo_chunks_index.bin` — index (script_hash → offset)
//!
//! Uses bin-packing algorithm to fill fixed-size blocks efficiently:
//! - Serialize all groups first, grouped by length
//! - Pack entries starting with largest, filling blocks optimally
//! - Large entries (> block size) span multiple blocks
//!
//! Input entry format (36 bytes each):
//!   [0..20)  ScriptPubKey hash (RIPEMD-160)
//!   [20..24) TXID  (u32 LE, mapped via MPHF)
//!   [24..28) vout  (u32 LE)
//!   [32..40) amount (u64 LE)
//!
//! Output chunk format (utxo_chunks.bin):
//!   For each group (no script_hash prefix — use the index to find groups):
//!     [varint entry_count]
//!     Entry 0: [4B txid LE] [varint vout] [varint amount]
//!     Entry i>0: [varint delta_txid] [varint vout] [varint amount]
//!   (entries sorted by height descending; delta_txid = prev_txid wrapping_sub this_txid)
//!
//! Output index format (utxo_chunks_index.bin):
//!   For each group: [20B script_hash] [4B start_offset u32 LE]
//!
//! Usage:
//!   cargo run --bin gen_5_utxo_chunks_from_remapped -- [block_size_kb]
//!
//! Examples:
//!   cargo run --bin gen_5_utxo_chunks_from_remapped        # Default: 32KB blocks
//!   cargo run --bin gen_5_utxo_chunks_from_remapped -- 32  # 32KB blocks
//!   cargo run --bin gen_5_utxo_chunks_from_remapped -- 64  # 64KB blocks

use memmap2::Mmap;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

/// Input file path
const INPUT_FILE: &str = "/Volumes/Bitcoin/data/remapped_utxo_set.bin";

/// Output file paths
const CHUNKS_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks.bin";
const INDEX_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_index.bin";

/// Size of each input entry in bytes
const ENTRY_SIZE: usize = 36;

/// Size of the ScriptPubKey hash
const SCRIPT_HASH_SIZE: usize = 20;

/// Default block size in bytes (32KB)
const DEFAULT_BLOCK_SIZE_KB: usize = 32;

/// A shortened UTXO entry (fields 2–5 from the original 40-byte record)
#[derive(Clone, Copy)]
struct ShortenedEntry {
    txid: u32,
    vout: u32,
    amount: u64,
}

/// A serialized group ready for bin-packing
struct SerializedGroup {
    script_hash: [u8; 20],
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
fn serialize_group(entries: &mut [ShortenedEntry]) -> Vec<u8> {
    // Sort entries by txid descending (higher txids first)
    entries.sort_unstable_by(|a, b| b.txid.cmp(&a.txid));

    let mut data = Vec::with_capacity(entries.len() * 12 + 4);

    // Write entry count as varint
    write_varint_to_vec(&mut data, entries.len() as u64);

    let mut prev_txid: u32 = 0;

    for (i, entry) in entries.iter().enumerate() {
        if i == 0 {
            // First entry: write raw 4-byte TXID (LE)
            data.extend_from_slice(&entry.txid.to_le_bytes());
        } else {
            // Subsequent entries: write VarInt(prev_txid wrapping_sub this_txid)
            let delta = (prev_txid.checked_sub(entry.txid).unwrap()) as u64;
            write_varint_to_vec(&mut data, delta);
        }
        prev_txid = entry.txid;

        // Write vout as VarInt
        write_varint_to_vec(&mut data, entry.vout as u64);

        // Write amount as VarInt
        write_varint_to_vec(&mut data, entry.amount);
    }

    data
}

/// Format a duration in seconds to a human-readable string
fn format_duration(secs: f64) -> String {
    if secs.is_infinite() || secs.is_nan() {
        return "calculating...".to_string();
    }
    let total_secs = secs as u64;
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Format bytes to human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

fn main() {
    println!("=== Build UTXO Chunks (Bin-Packing) ===");
    println!();

    // Parse CLI arguments
    let args: Vec<String> = env::args().collect();
    let block_size_kb: usize = if args.len() > 1 {
        match args[1].parse() {
            Ok(kb) if kb > 0 => kb,
            _ => {
                eprintln!("Warning: Invalid block size '{}', using default {}KB", 
                    args[1], DEFAULT_BLOCK_SIZE_KB);
                DEFAULT_BLOCK_SIZE_KB
            }
        }
    } else {
        DEFAULT_BLOCK_SIZE_KB
    };
    let block_size = block_size_kb * 1024;

    println!("Configuration:");
    println!("  Block size: {}KB ({} bytes)", block_size_kb, block_size);
    println!("  Input:  {}", INPUT_FILE);
    println!("  Output: {}", CHUNKS_FILE);
    println!("  Index:  {}", INDEX_FILE);
    println!();

    let total_start = Instant::now();

    // ── Step 1: Memory-map the input file ──────────────────────────────
    println!("[1] Memory-mapping input file...");

    let input_file = File::open(INPUT_FILE).unwrap_or_else(|e| {
        eprintln!("✗ Failed to open input file: {}", e);
        std::process::exit(1);
    });

    let mmap = unsafe { Mmap::map(&input_file) }.unwrap_or_else(|e| {
        eprintln!("✗ Failed to mmap input file: {}", e);
        std::process::exit(1);
    });

    let file_size = mmap.len();
    if file_size % ENTRY_SIZE != 0 {
        eprintln!(
            "✗ Input file size ({}) is not a multiple of entry size ({})",
            file_size, ENTRY_SIZE
        );
        std::process::exit(1);
    }

    let entry_count = file_size / ENTRY_SIZE;
    println!(
        "✓ Mapped {} ({} entries)",
        format_bytes(file_size as u64),
        entry_count
    );
    println!();

    // ── Step 2: Build the HashMap ──────────────────────────────────────
    println!("[2] Building HashMap (grouping by ScriptPubKey hash)...");
    let step2_start = Instant::now();

    // Pre-allocate with an estimate of unique addresses
    // (~50-80M unique ScriptPubKey hashes expected)
    let mut map: HashMap<[u8; 20], Vec<ShortenedEntry>> = HashMap::with_capacity(80_000_000);

    let one_percent = std::cmp::max(1, entry_count / 100);
    let mut last_pct = 0u64;

    for i in 0..entry_count {
        let base = i * ENTRY_SIZE;
        let chunk = &mmap[base..base + ENTRY_SIZE];

        // Extract ScriptPubKey hash (first 20 bytes)
        let mut script_hash = [0u8; 20];
        script_hash.copy_from_slice(&chunk[..SCRIPT_HASH_SIZE]);

        // Parse shortened entry (bytes 20..36)
        let txid = u32::from_le_bytes([chunk[20], chunk[21], chunk[22], chunk[23]]);
        let vout = u32::from_le_bytes([chunk[24], chunk[25], chunk[26], chunk[27]]);
        let amount = u64::from_le_bytes([
            chunk[28], chunk[29], chunk[30], chunk[31], chunk[32], chunk[33], chunk[34], chunk[35],
        ]);

        map.entry(script_hash)
            .or_insert_with(Vec::new)
            .push(ShortenedEntry {
                txid,
                vout,
                amount,
            });

        // Progress reporting
        let current_pct = (i as u64 + 1) / one_percent as u64;
        if current_pct > last_pct && current_pct <= 100 {
            let elapsed = step2_start.elapsed().as_secs_f64();
            let frac = current_pct as f64 / 100.0;
            let eta = if frac > 0.0 {
                (elapsed / frac) * (1.0 - frac)
            } else {
                0.0
            };
            print!(
                "\r    Building: {}% | ETA: {} | Entries: {}/{} | Unique keys: {}",
                current_pct,
                format_duration(eta),
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
    let step2_elapsed = step2_start.elapsed();
    println!(
        "✓ HashMap built in {:.2?} — {} entries, {} unique ScriptPubKey hashes",
        step2_elapsed, entry_count, unique_keys
    );
    println!();

    // Drop mmap to free memory
    drop(mmap);
    println!("✓ Released mmap memory");
    println!();

    // ── Step 3: Serialize and group by length ───────────────────────────
    println!("[3] Serializing groups and grouping by length...");
    let step3_start = Instant::now();

    // Group serialized entries by their length
    // BTreeMap automatically keeps keys sorted
    let mut length_groups: BTreeMap<usize, VecDeque<SerializedGroup>> = BTreeMap::new();
    
    // Temporary storage for the index (script_hash → offset)
    let mut temp_index: HashMap<[u8; 20], u32> = HashMap::with_capacity(unique_keys);

    let mut total_serialized_bytes: u64 = 0;
    let mut groups_serialized: u64 = 0;
    let one_percent_groups = std::cmp::max(1, unique_keys / 100) as u64;
    let mut last_group_pct: u64 = 0;

    // Drain the HashMap, serialize each group, and release memory progressively
    for (script_hash, mut entries) in map.drain() {
        // Serialize the group
        let data = serialize_group(&mut entries);
        let len = data.len();
        total_serialized_bytes += len as u64;

        // Store in length-grouped structure
        length_groups.entry(len).or_default().push_back(SerializedGroup {
            script_hash,
            data,
        });

        groups_serialized += 1;

        // Progress reporting
        let current_pct = groups_serialized / one_percent_groups;
        if current_pct > last_group_pct && current_pct <= 100 {
            let elapsed = step3_start.elapsed().as_secs_f64();
            let frac = current_pct as f64 / 100.0;
            let eta = if frac > 0.0 {
                (elapsed / frac) * (1.0 - frac)
            } else {
                0.0
            };
            print!(
                "\r    Serializing: {}% | ETA: {} | Groups: {}/{} | Total bytes: {}",
                current_pct,
                format_duration(eta),
                groups_serialized,
                unique_keys,
                format_bytes(total_serialized_bytes)
            );
            io::stdout().flush().ok();
            last_group_pct = current_pct;
        }
    }
    println!();

    // Explicitly drop the empty HashMap
    drop(map);

    let step3_elapsed = step3_start.elapsed();
    println!(
        "✓ Serialized {} groups in {:.2?} — {} total bytes",
        groups_serialized,
        step3_elapsed,
        format_bytes(total_serialized_bytes)
    );
    println!("✓ Released HashMap memory");
    println!();

    // ── Step 4: Open output files ──────────────────────────────────────
    println!("[4] Opening output files...");

    let chunks_file = File::create(CHUNKS_FILE).unwrap_or_else(|e| {
        eprintln!("✗ Failed to create chunks file: {}", e);
        std::process::exit(1);
    });
    let mut chunks_writer = BufWriter::with_capacity(1024 * 1024, chunks_file);

    let index_file = File::create(INDEX_FILE).unwrap_or_else(|e| {
        eprintln!("✗ Failed to create index file: {}", e);
        std::process::exit(1);
    });
    let mut index_writer = BufWriter::with_capacity(1024 * 1024, index_file);

    println!("✓ Output files opened");
    println!();

    // ── Step 5: Bin-packing algorithm ───────────────────────────────────
    println!("[5] Bin-packing groups into {}KB blocks...", block_size_kb);
    let step5_start = Instant::now();

    // Track total number of groups remaining (avoids expensive values().all() scan)
    let mut total_groups_remaining: u64 = length_groups.values().map(|v| v.len() as u64).sum();

    // Statistics
    let mut current_offset: u64 = 0;
    let mut blocks_written: u64 = 0;
    let mut groups_written: u64 = 0;
    let mut padding_bytes: u64 = 0;
    let mut large_entries_spanning: u64 = 0;

    // Total bytes to write (calculated from serialization step)
    let total_bytes_to_write = total_serialized_bytes;

    // Calculate percentage increments for progress (1% of total bytes)
    let one_percent_bytes = std::cmp::max(1, total_bytes_to_write / 100);
    let mut last_written_pct = 0u64;

    // Update progress display - tracks actual bytes written (excluding padding)
    let update_progress = |actual_bytes_written: u64, total: u64, start: Instant, blocks: u64, groups: u64, padding: u64, pct: &mut u64| {
        let current_pct = actual_bytes_written / one_percent_bytes;
        if current_pct > *pct && current_pct <= 100 {
            let elapsed = start.elapsed().as_secs_f64();
            let frac = current_pct as f64 / 100.0;
            let eta = if frac > 0.0 {
                (elapsed / frac) * (1.0 - frac)
            } else {
                0.0
            };
            print!(
                "\r    Packing: {}% | ETA: {} | Bytes: {}/{} | Groups: {} | Blocks: {} | Padding: {}",
                current_pct,
                format_duration(eta),
                format_bytes(actual_bytes_written),
                format_bytes(total),
                groups,
                blocks,
                format_bytes(padding)
            );
            io::stdout().flush().ok();
            *pct = current_pct;
        }
    };

    // Process all groups
    // Use total_groups_remaining counter instead of scanning all values for emptiness.
    // Use BTreeMap range queries instead of linear scans over a separate sorted_lengths vec.
    // Delete empty length groups from the BTreeMap to keep it compact.
    while total_groups_remaining > 0 {
        // Remaining space in current block
        let remaining = block_size - (current_offset as usize % block_size);

        // Find the largest entry that fits in remaining space.
        // BTreeMap keys are sorted ascending, so iterate in reverse to find the largest key <= remaining.
        // range(..=remaining) gives all keys <= remaining; .next_back() gives the largest one.
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
            total_groups_remaining -= 1;

            // Record offset in temp index
            temp_index.insert(group.script_hash, current_offset as u32);

            // Write directly to writer
            chunks_writer.write_all(&group.data).unwrap();
            current_offset += len as u64;
            groups_written += 1;

            // Actual bytes written = current_offset - padding_bytes (excluding padding)
            let actual_bytes_written = current_offset - padding_bytes;
            update_progress(actual_bytes_written, total_bytes_to_write, step5_start, blocks_written, groups_written, padding_bytes, &mut last_written_pct);

            // Update blocks count
            blocks_written = current_offset as u64 / block_size as u64;
        } else {
            // No entry fits in remaining space - take the largest available group (last key in BTreeMap)
            let len = *length_groups.keys().next_back().unwrap();

            let group = length_groups.get_mut(&len).unwrap().pop_front().unwrap();

            // Remove the length group if now empty
            if length_groups.get(&len).map_or(true, |v| v.is_empty()) {
                length_groups.remove(&len);
            }
            total_groups_remaining -= 1;

            // Pad remaining if needed
            if remaining > 0 {
                chunks_writer.write_all(&vec![0u8; remaining]).unwrap();
                padding_bytes += remaining as u64;
                current_offset += remaining as u64;
            }

            // Record offset in temp index
            temp_index.insert(group.script_hash, current_offset as u32);

            // Write the entire entry (handles both single and multi-block cases)
            chunks_writer.write_all(&group.data).unwrap();
            current_offset += len as u64;
            groups_written += 1;

            if len > block_size {
                large_entries_spanning += 1;
            }

            // Actual bytes written = current_offset - padding_bytes (excluding padding)
            let actual_bytes_written = current_offset - padding_bytes;
            update_progress(actual_bytes_written, total_bytes_to_write, step5_start, blocks_written, groups_written, padding_bytes, &mut last_written_pct);

            // Update blocks count
            blocks_written = current_offset as u64 / block_size as u64;
        }
    }

    // Handle final partial block (if any)
    let remaining = block_size - (current_offset as usize % block_size);
    if remaining > 0 {
        padding_bytes += remaining as u64;
        chunks_writer.write_all(&vec![0u8; remaining]).unwrap();
        current_offset += remaining as u64;
    }
    blocks_written = current_offset as u64 / block_size as u64;

    println!();

    let step5_elapsed = step5_start.elapsed();
    println!(
        "✓ Bin-packing completed in {:.2?}",
        step5_elapsed
    );
    println!(
        "  Blocks written:       {}",
        blocks_written
    );
    println!(
        "  Groups written:       {}",
        groups_written
    );
    println!(
        "  Large entries (span): {}",
        large_entries_spanning
    );
    println!(
        "  Padding bytes:        {} ({:.2}% of total)",
        format_bytes(padding_bytes),
        padding_bytes as f64 / current_offset as f64 * 100.0
    );
    println!();

    // ── Step 6: Write index file ───────────────────────────────────────
    println!("[6] Writing index file...");
    let step6_start = Instant::now();

    // Sort index entries by script_hash for binary search
    let mut index_entries: Vec<([u8; 20], u32)> = temp_index.into_iter().collect();
    index_entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (script_hash, offset) in &index_entries {
        index_writer.write_all(script_hash).unwrap_or_else(|e| {
            eprintln!("✗ Failed to write index script hash: {}", e);
            std::process::exit(1);
        });
        index_writer.write_all(&offset.to_le_bytes()).unwrap_or_else(|e| {
            eprintln!("✗ Failed to write index offset: {}", e);
            std::process::exit(1);
        });
    }

    let step6_elapsed = step6_start.elapsed();
    println!(
        "✓ Index file written in {:.2?} — {} entries",
        step6_elapsed,
        index_entries.len()
    );
    println!();

    // ── Step 7: Flush and report ───────────────────────────────────────
    println!("[7] Flushing output files...");

    chunks_writer.flush().unwrap_or_else(|e| {
        eprintln!("✗ Failed to flush chunks file: {}", e);
        std::process::exit(1);
    });
    index_writer.flush().unwrap_or_else(|e| {
        eprintln!("✗ Failed to flush index file: {}", e);
        std::process::exit(1);
    });

    let total_elapsed = total_start.elapsed();

    println!("✓ Done!");
    println!();
    println!("=== Summary ===");
    println!("Input entries:        {}", entry_count);
    println!("Unique addresses:     {}", unique_keys);
    println!("Groups written:       {}", groups_written);
    println!();
    println!("Block size:           {}KB", block_size_kb);
    println!("Blocks written:       {}", blocks_written);
    println!(
        "Chunks file size:     {} ({} blocks × {}KB)",
        format_bytes(current_offset),
        blocks_written,
        block_size_kb
    );
    let index_size = groups_written * 24;
    println!(
        "Index file size:      {} ({} entries × 24 bytes)",
        format_bytes(index_size),
        groups_written
    );
    println!(
        "Padding overhead:     {} ({:.2}%)",
        format_bytes(padding_bytes),
        padding_bytes as f64 / current_offset as f64 * 100.0
    );
    println!();

    // Compression ratio
    let original_size = entry_count as f64 * ENTRY_SIZE as f64;
    let compact_size = current_offset as f64 + index_size as f64;
    println!(
        "Original size:        {}",
        format_bytes(original_size as u64)
    );
    println!(
        "Compact size:         {} (chunks + index)",
        format_bytes(compact_size as u64)
    );
    println!("Compression ratio:    {:.2}x", original_size / compact_size);
    println!();
    println!("HashMap build time:   {:.2?}", step2_elapsed);
    println!("Serialization time:   {:.2?}", step3_elapsed);
    println!("Bin-packing time:     {:.2?}", step5_elapsed);
    println!("Index write time:     {:.2?}", step6_elapsed);
    println!("Total time:           {:.2?}", total_elapsed);
}