//! Pack UTXO data into 3840-byte OnionPIR entries + build new-format index.
//!
//! Reads `/Volumes/Bitcoin/data/intermediate/utxo_set.bin` (68-byte raw UTXO entries),
//! groups by script hash, serializes with varint encoding, and greedily packs
//! into 3840-byte entries (one OnionPIR plaintext = 2048 coefficients × 15 bits).
//!
//! Output:
//!   - packed_entries.bin:  sequential 3840-byte entries with greedily packed UTXO data
//!   - onion_index.bin:     27-byte index entries (script_hash + entry_id + offset + num_entries)
//!
//! Packing rules:
//!   - Multiple addresses per entry (greedy packing)
//!   - If an address doesn't fit in the remaining space, pad and start a new entry
//!   - Large addresses (>3840B) always start at offset 0, spanning consecutive entries
//!   - Addresses are processed in sorted (by script_hash) order for determinism
//!
//! Usage:
//!   cargo run --release -p build --bin gen_1_onion [-- --partitions N]

use memmap2::Mmap;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

/// Default data dir; reads `<dir>/utxo_set.bin` and writes
/// `<dir>/onion_packed_entries.bin` + `<dir>/onion_index.bin`.
/// Override with `--data-dir <D>`.
const DEFAULT_DATA_DIR: &str = "/Volumes/Bitcoin/data/intermediate";

const ENTRY_SIZE_RAW: usize = 68; // raw UTXO entry from utxo_set.bin
const SCRIPT_HASH_SIZE: usize = 20;
const TXID_SIZE: usize = 32;

/// OnionPIR entry size derived from the linked `onionpir` crate at runtime.
/// Pre-port (SEAL build at PlainMod=15) this was 3840 bytes hardcoded
/// (`2048 × 15 / 8`). Post-port (BV build at PlainMod=14, the default
/// `CONFIG_N2048_K1`) it's 3328. Read once at startup in `main()` and
/// flowed through every consumer via the `Packer` struct + local
/// variables so the build pipeline stays config-agnostic.
fn onion_entry_size() -> usize {
    onionpir::params_info(0).entry_size as usize
}

/// New index entry: 20B script_hash + 4B entry_id + 2B byte_offset + 1B num_entries
const ONION_INDEX_RECORD_SIZE: usize = 20 + 4 + 2 + 1; // 27

const DEFAULT_PARTITIONS: usize = 4;
const DUST_THRESHOLD: u64 = 576;
const MAX_UTXOS_PER_SPK: usize = 100;
const FLAG_WHALE: u8 = 0x40;

// ─── Serialization (same format as gen_1) ────────────────────────────────────

#[derive(Clone)]
struct ShortenedEntry {
    txid: [u8; TXID_SIZE],
    vout: u32,
    amount: u64,
    height: u32,
}

#[inline]
fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Serialize a group of UTXO entries. Entries must already be sorted.
fn serialize_group(entries: &[ShortenedEntry]) -> Vec<u8> {
    let mut data = Vec::with_capacity(entries.len() * (TXID_SIZE + 8) + 4);
    write_varint(&mut data, entries.len() as u64);
    for entry in entries {
        data.extend_from_slice(&entry.txid);
        write_varint(&mut data, entry.vout as u64);
        write_varint(&mut data, entry.amount);
    }
    data
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

fn parse_cli() -> (usize, String) {
    let args: Vec<String> = env::args().collect();
    let mut partitions = DEFAULT_PARTITIONS;
    let mut data_dir = DEFAULT_DATA_DIR.to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--partitions" => {
                i += 1;
                if i < args.len() {
                    partitions = args[i].parse().unwrap_or(DEFAULT_PARTITIONS).max(1);
                }
            }
            "--data-dir" => {
                i += 1;
                if i < args.len() {
                    data_dir = args[i].clone();
                }
            }
            "-h" | "--help" => {
                println!("Usage: {} [--partitions N] [--data-dir <dir>]", args[0]);
                println!();
                println!("Reads <dir>/utxo_set.bin, writes");
                println!("<dir>/{{onion_packed_entries.bin, onion_index.bin}}.");
                println!("Default dir: {}", DEFAULT_DATA_DIR);
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    (partitions, data_dir)
}

// ─── Packing engine ─────────────────────────────────────────────────────────

struct Packer {
    writer: BufWriter<File>,
    current_entry: Vec<u8>,
    current_pos: usize,
    entry_count: u64,
    total_padding: u64,
    total_data: u64,
    /// Byte size of one packed entry. Equals `onionpir::params_info(0).entry_size`
    /// at the time the `Packer` was constructed. Captured per-instance so
    /// the OnionPIR linker step doesn't have to run on every `pack` call.
    entry_size: usize,
}

impl Packer {
    fn new(file: File, entry_size: usize) -> Self {
        Packer {
            writer: BufWriter::with_capacity(1024 * 1024, file),
            current_entry: vec![0u8; entry_size],
            current_pos: 0,
            entry_count: 0,
            total_padding: 0,
            total_data: 0,
            entry_size,
        }
    }

    /// Flush the current entry to disk (pad remaining bytes with zeros).
    fn flush_entry(&mut self) {
        if self.current_pos > 0 {
            // Remaining bytes are already zero from initialization
            self.writer.write_all(&self.current_entry).unwrap();
            self.total_padding += (self.entry_size - self.current_pos) as u64;
            self.entry_count += 1;
            // Reset for next entry
            self.current_entry.fill(0);
            self.current_pos = 0;
        }
    }

    /// Pack one address's serialized data. Returns (entry_id, byte_offset, num_entries).
    fn pack(&mut self, data: &[u8]) -> (u32, u16, u8) {
        let data_len = data.len();
        self.total_data += data_len as u64;

        if data_len == 0 {
            // Shouldn't happen, but handle gracefully
            let entry_id = if self.current_pos > 0 {
                self.entry_count
            } else {
                self.entry_count
            };
            return (entry_id as u32, self.current_pos as u16, 1);
        }

        // Case 1: fits in remaining space of current entry
        let remaining = self.entry_size - self.current_pos;
        if data_len <= remaining {
            let entry_id = self.entry_count;
            let offset = self.current_pos;
            self.current_entry[self.current_pos..self.current_pos + data_len]
                .copy_from_slice(data);
            self.current_pos += data_len;

            // If entry is exactly full, flush it
            if self.current_pos == self.entry_size {
                self.writer.write_all(&self.current_entry).unwrap();
                self.entry_count += 1;
                self.current_entry.fill(0);
                self.current_pos = 0;
            }

            return (entry_id as u32, offset as u16, 1);
        }

        // Case 2: doesn't fit — pad current entry, start fresh
        self.flush_entry();

        // Now current_pos == 0, entry is fresh
        let entry_id = self.entry_count;

        if data_len <= self.entry_size {
            // Fits in a single fresh entry
            self.current_entry[..data_len].copy_from_slice(data);
            self.current_pos = data_len;

            if self.current_pos == self.entry_size {
                self.writer.write_all(&self.current_entry).unwrap();
                self.entry_count += 1;
                self.current_entry.fill(0);
                self.current_pos = 0;
            }

            return (entry_id as u32, 0, 1);
        }

        // Case 3: spans multiple entries
        let num_entries = (data_len + self.entry_size - 1) / self.entry_size;
        assert!(num_entries <= 255, "address data {} bytes needs {} entries, exceeds u8",
            data_len, num_entries);

        let mut written = 0;
        for i in 0..num_entries {
            let chunk_len = (data_len - written).min(self.entry_size);
            self.current_entry[..chunk_len].copy_from_slice(&data[written..written + chunk_len]);
            // Remaining bytes are already zero
            written += chunk_len;

            if i < num_entries - 1 {
                // Full entry — flush immediately
                self.writer.write_all(&self.current_entry).unwrap();
                self.entry_count += 1;
                self.current_entry.fill(0);
                self.current_pos = 0;
            } else {
                // Last entry — might have space for more addresses
                self.current_pos = chunk_len;
                if self.current_pos == self.entry_size {
                    self.writer.write_all(&self.current_entry).unwrap();
                    self.entry_count += 1;
                    self.current_entry.fill(0);
                    self.current_pos = 0;
                }
            }
        }

        (entry_id as u32, 0, num_entries as u8)
    }

    /// Finalize: flush any remaining partial entry.
    fn finish(&mut self) {
        self.flush_entry();
        self.writer.flush().unwrap();
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    // OnionPIRv2 port (commit 5b): pull the entry size from the
    // linked onionpir crate once at startup instead of hardcoding
    // 3840. Captured here so every downstream consumer sees the
    // same value even if the linked rev changes mid-run (unlikely
    // — onionpir is a build dep, not dynamic — but explicit is
    // better than implicit).
    let packed_entry_size = onion_entry_size();

    println!("=== gen_1_onion: Pack UTXOs into {}-byte OnionPIR Entries ===", packed_entry_size);
    println!();

    let (num_partitions, data_dir) = parse_cli();
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let input_path = format!("{}/utxo_set.bin", data_dir);
    let packed_path = format!("{}/onion_packed_entries.bin", data_dir);
    let onion_index_path = format!("{}/onion_index.bin", data_dir);

    println!("Configuration:");
    println!("  OnionPIR entry size: {} bytes (from onionpir::params_info(0))", packed_entry_size);
    println!("  Index entry size:    {} bytes", ONION_INDEX_RECORD_SIZE);
    println!("  Partitions:          {}", num_partitions);
    println!("  Dust threshold:      {} sats", DUST_THRESHOLD);
    println!("  Max UTXOs/SPK:       {} (skip larger)", MAX_UTXOS_PER_SPK);
    println!("  Input:               {}", input_path);
    println!("  Output packed:       {}", packed_path);
    println!("  Output index:        {}", onion_index_path);
    println!();

    let total_start = Instant::now();

    // ── 1. mmap input ──────────────────────────────────────────────────
    println!("[1] Memory-mapping input...");
    let input_file = File::open(&input_path).expect("open input");
    let mmap = unsafe { Mmap::map(&input_file) }.expect("mmap");
    let entry_count = mmap.len() / ENTRY_SIZE_RAW;
    assert_eq!(mmap.len() % ENTRY_SIZE_RAW, 0);
    println!("  {} entries ({})", entry_count, format_bytes(mmap.len() as u64));
    println!();

    // ── 2. Open output files ───────────────────────────────────────────
    println!("[2] Opening output files...");
    let packed_file = File::create(&packed_path).expect("create packed entries file");
    let mut packer = Packer::new(packed_file, packed_entry_size);
    let index_file = File::create(&onion_index_path).expect("create index file");
    let mut index_writer = BufWriter::with_capacity(1024 * 1024, index_file);
    println!("  Done");
    println!();

    // ── 3. Partitioned processing ──────────────────────────────────────
    println!("[3] Processing {} partitions...", num_partitions);
    println!();

    let packing_start = Instant::now();
    let mut total_groups: u64 = 0;
    let mut total_whale: u64 = 0;
    let mut total_dust: u64 = 0;
    let mut max_serialized_len: usize = 0;
    let mut size_histogram = [0u64; 8]; // [0-40, 40-100, 100-500, 500-1K, 1K-2K, 2K-3840, >3840, whale]

    for partition in 0..num_partitions {
        println!("=== Partition {}/{} ===", partition + 1, num_partitions);
        let partition_start = Instant::now();

        // ── 3a. Build HashMap ────────────────────────────────────────────
        let build_start = Instant::now();
        let estimated_keys = 80_000_000 / num_partitions;
        let mut map: HashMap<[u8; SCRIPT_HASH_SIZE], Vec<ShortenedEntry>> =
            HashMap::with_capacity(estimated_keys);

        let one_percent = entry_count.max(1) / 100;
        let mut last_pct = 0u64;
        let mut partition_dust = 0u64;

        for i in 0..entry_count {
            let base = i * ENTRY_SIZE_RAW;
            let chunk = &mmap[base..base + ENTRY_SIZE_RAW];

            if chunk[0] as usize % num_partitions != partition {
                continue;
            }

            let amount = u64::from_le_bytes(chunk[56..64].try_into().unwrap());
            if amount <= DUST_THRESHOLD {
                partition_dust += 1;
                continue;
            }

            let mut script_hash = [0u8; SCRIPT_HASH_SIZE];
            script_hash.copy_from_slice(&chunk[..SCRIPT_HASH_SIZE]);

            let mut txid = [0u8; TXID_SIZE];
            txid.copy_from_slice(&chunk[20..52]);

            let vout = u32::from_le_bytes(chunk[52..56].try_into().unwrap());
            let height = u32::from_le_bytes(chunk[64..68].try_into().unwrap());

            map.entry(script_hash)
                .or_default()
                .push(ShortenedEntry { txid, vout, amount, height });

            if one_percent > 0 {
                let current_pct = (i as u64 + 1) / one_percent as u64;
                if current_pct > last_pct && current_pct <= 100 {
                    eprint!("\r    Building: {}% | Keys: {} | Dust: {}",
                        current_pct, map.len(), partition_dust);
                    let _ = io::stderr().flush();
                    last_pct = current_pct;
                }
            }
        }
        eprintln!();
        total_dust += partition_dust;

        println!("  HashMap: {} unique script_hashes, {} dust skipped ({:.2?})",
            map.len(), partition_dust, build_start.elapsed());

        // ── 3b. Sort by script_hash for deterministic ordering ──────────
        let sort_start = Instant::now();
        let mut sorted_entries: Vec<([u8; SCRIPT_HASH_SIZE], Vec<ShortenedEntry>)> =
            map.drain().collect();
        sorted_entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        println!("  Sorted {} entries by script_hash ({:.2?})",
            sorted_entries.len(), sort_start.elapsed());

        // ── 3c. Serialize and pack ──────────────────────────────────────
        let pack_start = Instant::now();
        let mut partition_groups = 0u64;
        let mut partition_whale = 0u64;

        for (script_hash, mut entries) in sorted_entries {
            if entries.len() > MAX_UTXOS_PER_SPK {
                // Whale: write sentinel index entry
                index_writer.write_all(&script_hash).unwrap();
                index_writer.write_all(&0u32.to_le_bytes()).unwrap();
                index_writer.write_all(&0u16.to_le_bytes()).unwrap();
                index_writer.write_all(&[FLAG_WHALE]).unwrap();
                partition_whale += 1;
                size_histogram[7] += 1;
                continue;
            }

            // Sort by height descending (most recent first)
            entries.sort_unstable_by(|a, b| b.height.cmp(&a.height));

            // Serialize
            let data = serialize_group(&entries);
            let data_len = data.len();

            if data_len > max_serialized_len {
                max_serialized_len = data_len;
            }

            // Histogram
            if data_len <= 40 {
                size_histogram[0] += 1;
            } else if data_len <= 100 {
                size_histogram[1] += 1;
            } else if data_len <= 500 {
                size_histogram[2] += 1;
            } else if data_len <= 1000 {
                size_histogram[3] += 1;
            } else if data_len <= 2000 {
                size_histogram[4] += 1;
            } else if data_len <= packed_entry_size {
                size_histogram[5] += 1;
            } else {
                size_histogram[6] += 1;
            }

            // Pack into entries
            let (entry_id, byte_offset, num_entries) = packer.pack(&data);

            // Write index entry: [20B script_hash | 4B entry_id | 2B offset | 1B num_entries]
            index_writer.write_all(&script_hash).unwrap();
            index_writer.write_all(&entry_id.to_le_bytes()).unwrap();
            index_writer.write_all(&byte_offset.to_le_bytes()).unwrap();
            index_writer.write_all(&[num_entries]).unwrap();

            partition_groups += 1;
        }

        total_groups += partition_groups;
        total_whale += partition_whale;

        println!("  Packed {} groups, {} whale ({:.2?})",
            partition_groups, partition_whale, pack_start.elapsed());
        println!("  Partition {}/{} completed in {:.2?}",
            partition + 1, num_partitions, partition_start.elapsed());
        println!();
    }

    // ── 4. Finalize ────────────────────────────────────────────────────
    println!("[4] Finalizing...");
    packer.finish();
    index_writer.flush().unwrap();
    println!("  Done");
    println!();

    // ── 5. Summary ─────────────────────────────────────────────────────
    let total_elapsed = total_start.elapsed();
    let packed_file_size = packer.entry_count * packed_entry_size as u64;
    let index_file_size = (total_groups + total_whale) * ONION_INDEX_RECORD_SIZE as u64;

    println!("=== Summary ===");
    println!("Input entries:        {}", entry_count);
    println!("Dust skipped:         {}", total_dust);
    println!("Whale excluded:       {}", total_whale);
    println!("Groups packed:        {}", total_groups);
    println!();
    println!("OnionPIR entries:     {}", packer.entry_count);
    println!("Packed file size:     {} ({} entries × {} B)",
        format_bytes(packed_file_size), packer.entry_count, packed_entry_size);
    println!("Index file size:      {} ({} entries × {} B)",
        format_bytes(index_file_size), total_groups + total_whale, ONION_INDEX_RECORD_SIZE);
    println!();
    println!("Actual data:          {} ({:.2}% of packed file)",
        format_bytes(packer.total_data),
        if packed_file_size > 0 { packer.total_data as f64 / packed_file_size as f64 * 100.0 } else { 0.0 });
    println!("Padding overhead:     {} ({:.2}%)",
        format_bytes(packer.total_padding),
        if packed_file_size > 0 { packer.total_padding as f64 / packed_file_size as f64 * 100.0 } else { 0.0 });
    println!("Max serialized len:   {} bytes", max_serialized_len);
    println!("Avg addresses/entry:  {:.1}", total_groups as f64 / packer.entry_count.max(1) as f64);
    println!();
    println!("Serialized size distribution:");
    println!("  0-40 B:     {:>10} ({:.2}%)", size_histogram[0],
        size_histogram[0] as f64 / total_groups.max(1) as f64 * 100.0);
    println!("  40-100 B:   {:>10} ({:.2}%)", size_histogram[1],
        size_histogram[1] as f64 / total_groups.max(1) as f64 * 100.0);
    println!("  100-500 B:  {:>10} ({:.2}%)", size_histogram[2],
        size_histogram[2] as f64 / total_groups.max(1) as f64 * 100.0);
    println!("  500-1K B:   {:>10} ({:.2}%)", size_histogram[3],
        size_histogram[3] as f64 / total_groups.max(1) as f64 * 100.0);
    println!("  1K-2K B:    {:>10} ({:.2}%)", size_histogram[4],
        size_histogram[4] as f64 / total_groups.max(1) as f64 * 100.0);
    println!("  2K-3840 B:  {:>10} ({:.2}%)", size_histogram[5],
        size_histogram[5] as f64 / total_groups.max(1) as f64 * 100.0);
    println!("  >3840 B:    {:>10} ({:.2}%) [span multiple entries]", size_histogram[6],
        size_histogram[6] as f64 / total_groups.max(1) as f64 * 100.0);
    println!("  Whale:      {:>10}", size_histogram[7]);
    println!();
    println!("Packing time:         {:.2?}", packing_start.elapsed());
    println!("Total time:           {:.2?}", total_elapsed);

    // ── Sanity checks ──────────────────────────────────────────────────
    if packer.entry_count > u32::MAX as u64 {
        println!("WARNING: entry_count {} overflows u32!", packer.entry_count);
    }
    if max_serialized_len > 255 * packed_entry_size {
        println!("WARNING: max serialized length {} exceeds u8 num_entries capacity!", max_serialized_len);
    }
}
