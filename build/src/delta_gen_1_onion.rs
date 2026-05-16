//! Pack delta data into 3840-byte OnionPIR entries + 27-byte index.
//!
//! This is the delta-DB analogue of `gen_1_onion`. It reads a grouped delta
//! file (`delta_grouped_<A>_<B>.bin`) produced by `delta_gen_0` and packs
//! each scripthash's raw delta bytes into 3840-byte OnionPIR entries, writing:
//!
//!   <data-dir>/onion_packed_entries.bin   — 3840B packed entries
//!   <data-dir>/onion_index.bin            — 27B index records
//!
//! The per-scripthash byte layout inside the packed entry is the same as
//! what `delta_gen_1` writes to 40B chunks, so the existing delta decoder
//! (`decodeDeltaData` in the web client / `runtime::protocol::decode_delta*`
//! in Rust) consumes the bytes unchanged:
//!
//!   [varint num_spent]
//!     per spent: [32B txid][varint vout]
//!   [varint num_new]
//!     per new:   [32B txid][varint vout][varint amount]
//!
//! Entries larger than 255 * 3840B are dropped (whale sentinel). This is the
//! same cap `delta_gen_1_build_chunks` applies (num_chunks is u8), and it
//! matches `gen_1_onion`'s whale handling.
//!
//! Usage:
//!   delta_gen_1_onion <start_height> <end_height> [--data-dir <dir>]
//!
//! Defaults:
//!   intermediate = /Volumes/Bitcoin/data/intermediate
//!   data-dir     = /Volumes/Bitcoin/data/deltas/<A>_<B>

use memmap2::Mmap;
use pir_core::codec::read_varint;
use std::env;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::time::Instant;

const DEFAULT_INTERMEDIATE_DIR: &str = "/Volumes/Bitcoin/data/intermediate";
const DEFAULT_DELTA_ROOT: &str = "/Volumes/Bitcoin/data/deltas";

const SCRIPT_HASH_SIZE: usize = 20;

/// OnionPIR entry size derived from the linked `onionpir` crate at runtime.
/// Pre-port (SEAL build, PlainMod=15) this was 3840 bytes hardcoded.
/// Post-port (BV build, default CONFIG_N2048_K1) it's 3328. Mirrors the
/// runtime-derived approach used in `gen_1_onion::onion_entry_size`.
fn onion_entry_size() -> usize {
    onionpir::params_info(0).entry_size as usize
}

/// Onion index record: 20B script_hash + 4B entry_id + 2B byte_offset + 1B num_entries.
const ONION_INDEX_RECORD_SIZE: usize = 20 + 4 + 2 + 1; // 27

/// Whale flag (same value as gen_1_onion).
const FLAG_WHALE: u8 = 0x40;

// ─── Packing engine (mirrors gen_1_onion::Packer) ───────────────────────────

struct Packer {
    writer: BufWriter<File>,
    current_entry: Vec<u8>,
    current_pos: usize,
    entry_count: u64,
    total_padding: u64,
    total_data: u64,
    /// Per-instance OnionPIR plaintext byte size, captured at ctor time
    /// (matches `gen_1_onion::Packer::entry_size`).
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
            self.writer.write_all(&self.current_entry).unwrap();
            self.total_padding += (self.entry_size - self.current_pos) as u64;
            self.entry_count += 1;
            self.current_entry.fill(0);
            self.current_pos = 0;
        }
    }

    /// Pack one scripthash's delta bytes. Returns (entry_id, byte_offset, num_entries).
    fn pack(&mut self, data: &[u8]) -> (u32, u16, u8) {
        let data_len = data.len();
        self.total_data += data_len as u64;

        if data_len == 0 {
            return (self.entry_count as u32, self.current_pos as u16, 1);
        }

        // Case 1: fits in remaining space of current entry.
        let remaining = self.entry_size - self.current_pos;
        if data_len <= remaining {
            let entry_id = self.entry_count;
            let offset = self.current_pos;
            self.current_entry[self.current_pos..self.current_pos + data_len]
                .copy_from_slice(data);
            self.current_pos += data_len;

            if self.current_pos == self.entry_size {
                self.writer.write_all(&self.current_entry).unwrap();
                self.entry_count += 1;
                self.current_entry.fill(0);
                self.current_pos = 0;
            }
            return (entry_id as u32, offset as u16, 1);
        }

        // Case 2: doesn't fit — pad current entry, start fresh.
        self.flush_entry();
        let entry_id = self.entry_count;

        if data_len <= self.entry_size {
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

        // Case 3: spans multiple entries.
        let num_entries = data_len.div_ceil(self.entry_size);
        assert!(
            num_entries <= 255,
            "delta data {} bytes needs {} entries, exceeds u8",
            data_len, num_entries
        );

        let mut written = 0;
        for i in 0..num_entries {
            let chunk_len = (data_len - written).min(self.entry_size);
            self.current_entry[..chunk_len]
                .copy_from_slice(&data[written..written + chunk_len]);
            written += chunk_len;

            if i < num_entries - 1 {
                self.writer.write_all(&self.current_entry).unwrap();
                self.entry_count += 1;
                self.current_entry.fill(0);
                self.current_pos = 0;
            } else {
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

    fn finish(&mut self) {
        self.flush_entry();
        self.writer.flush().unwrap();
    }
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

// ─── Main ────────────────────────────────────────────────────────────────────

struct CliArgs {
    start_height: u64,
    end_height: u64,
    intermediate_dir: String,
    data_dir: String,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <start_height> <end_height> [--data-dir <dir>] [--intermediate <dir>]",
            args[0]
        );
        std::process::exit(1);
    }
    let start_height: u64 = args[1].parse().expect("start_height must be a number");
    let end_height: u64 = args[2].parse().expect("end_height must be a number");
    assert!(start_height < end_height, "start_height must be < end_height");

    let mut intermediate_dir = DEFAULT_INTERMEDIATE_DIR.to_string();
    let mut data_dir = format!("{}/{}_{}", DEFAULT_DELTA_ROOT, start_height, end_height);

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                if let Some(v) = args.get(i + 1) {
                    data_dir = v.clone();
                    i += 1;
                }
            }
            "--intermediate" => {
                if let Some(v) = args.get(i + 1) {
                    intermediate_dir = v.clone();
                    i += 1;
                }
            }
            other => {
                eprintln!("warning: ignoring unknown arg {}", other);
            }
        }
        i += 1;
    }

    CliArgs { start_height, end_height, intermediate_dir, data_dir }
}

fn main() {
    let cli = parse_args();

    let input_path = format!(
        "{}/delta_grouped_{}_{}.bin",
        cli.intermediate_dir, cli.start_height, cli.end_height
    );
    let packed_path = format!("{}/onion_packed_entries.bin", cli.data_dir);
    let index_path = format!("{}/onion_index.bin", cli.data_dir);

    // OnionPIRv2 port (commit 5b extension): pull entry size from the
    // linked onionpir crate (3328 default post-port, was 3840 pre-port).
    let packed_entry_size = onion_entry_size();

    println!("=== delta_gen_1_onion: Pack Delta into OnionPIR {}-byte Entries ===", packed_entry_size);
    println!();
    println!("Configuration:");
    println!("  Start/end height:   {} → {}", cli.start_height, cli.end_height);
    println!("  Entry size:         {} bytes (from onionpir::params_info(0))", packed_entry_size);
    println!("  Index record size:  {} bytes", ONION_INDEX_RECORD_SIZE);
    println!("  Input (grouped):    {}", input_path);
    println!("  Output packed:      {}", packed_path);
    println!("  Output index:       {}", index_path);
    println!();

    fs::create_dir_all(&cli.data_dir).expect("create data dir");

    let total_start = Instant::now();

    // ── 1. mmap grouped delta ──────────────────────────────────────────────
    println!("[1] Memory-mapping input...");
    let input_file = File::open(&input_path).expect("open grouped delta file");
    let mmap = unsafe { Mmap::map(&input_file) }.expect("mmap grouped delta file");
    assert!(mmap.len() >= 4, "grouped delta file too short");
    let num_scripts = u32::from_le_bytes(mmap[0..4].try_into().unwrap()) as usize;
    println!(
        "  {} scripthashes ({})",
        num_scripts,
        format_bytes(mmap.len() as u64)
    );
    println!();

    // ── 2. Open output files ───────────────────────────────────────────────
    println!("[2] Opening output files...");
    let packed_file = File::create(&packed_path).expect("create packed entries file");
    let mut packer = Packer::new(packed_file, packed_entry_size);
    let index_file = File::create(&index_path).expect("create index file");
    let mut index_writer = BufWriter::with_capacity(1024 * 1024, index_file);
    println!("  Done");
    println!();

    // ── 3. Iterate scripthashes and pack each delta block ──────────────────
    println!("[3] Packing {} scripthashes...", num_scripts);
    let t_pack = Instant::now();

    let mut pos: usize = 4;
    let mut total_groups: u64 = 0;
    let mut total_whale: u64 = 0;
    let mut max_delta_len: usize = 0;
    let mut size_histogram = [0u64; 8]; // 0-40, 40-100, 100-500, 500-1k, 1k-2k, 2k-3840, >3840, whale

    for i in 0..num_scripts {
        if pos + SCRIPT_HASH_SIZE > mmap.len() {
            panic!("truncated: scripthash header at entry {}", i);
        }
        let script_hash: [u8; SCRIPT_HASH_SIZE] = mmap[pos..pos + SCRIPT_HASH_SIZE]
            .try_into()
            .unwrap();
        pos += SCRIPT_HASH_SIZE;

        let data_start = pos;

        // Walk the varint-encoded body to find its length (same structure as
        // delta_gen_1_build_chunks and the web client's `decodeDeltaData`).
        let (num_spent, consumed) = read_varint(&mmap[pos..]);
        pos += consumed;
        for _ in 0..num_spent {
            pos += 32; // txid
            let (_, c) = read_varint(&mmap[pos..]); // vout
            pos += c;
        }
        let (num_new, consumed) = read_varint(&mmap[pos..]);
        pos += consumed;
        for _ in 0..num_new {
            pos += 32; // txid
            let (_, c) = read_varint(&mmap[pos..]); // vout
            pos += c;
            let (_, c) = read_varint(&mmap[pos..]); // amount
            pos += c;
        }

        let data_end = pos;
        let delta_bytes = &mmap[data_start..data_end];
        let data_len = delta_bytes.len();

        if data_len > max_delta_len {
            max_delta_len = data_len;
        }

        // Whale: drop entries that would span > 255 packed entries.
        let num_blocks_if_packed = data_len.div_ceil(packed_entry_size);
        if num_blocks_if_packed > 255 {
            index_writer.write_all(&script_hash).unwrap();
            index_writer.write_all(&0u32.to_le_bytes()).unwrap();
            index_writer.write_all(&0u16.to_le_bytes()).unwrap();
            index_writer.write_all(&[FLAG_WHALE]).unwrap();
            total_whale += 1;
            size_histogram[7] += 1;
            continue;
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

        // Pack into entries and emit index record.
        let (entry_id, byte_offset, num_entries) = packer.pack(delta_bytes);

        index_writer.write_all(&script_hash).unwrap();
        index_writer.write_all(&entry_id.to_le_bytes()).unwrap();
        index_writer.write_all(&byte_offset.to_le_bytes()).unwrap();
        index_writer.write_all(&[num_entries]).unwrap();

        total_groups += 1;

        if (i + 1) % 100_000 == 0 || i + 1 == num_scripts {
            eprint!(
                "\r  {}/{} scripthashes, {} entries packed",
                i + 1,
                num_scripts,
                packer.entry_count
            );
        }
    }
    eprintln!();
    println!("  Packed in {:.2?}", t_pack.elapsed());
    println!();

    // ── 4. Finalize ────────────────────────────────────────────────────────
    println!("[4] Finalizing...");
    packer.finish();
    index_writer.flush().unwrap();
    println!("  Done");
    println!();

    // ── 5. Summary ─────────────────────────────────────────────────────────
    let total_elapsed = total_start.elapsed();
    let packed_file_size = packer.entry_count * packed_entry_size as u64;
    let index_file_size = (total_groups + total_whale) * ONION_INDEX_RECORD_SIZE as u64;

    println!("=== Summary ===");
    println!("Input scripthashes:   {}", num_scripts);
    println!("Whale excluded:       {}", total_whale);
    println!("Groups packed:        {}", total_groups);
    println!();
    println!("OnionPIR entries:     {}", packer.entry_count);
    println!(
        "Packed file size:     {} ({} entries × {} B)",
        format_bytes(packed_file_size),
        packer.entry_count,
        packed_entry_size
    );
    println!(
        "Index file size:      {} ({} entries × {} B)",
        format_bytes(index_file_size),
        total_groups + total_whale,
        ONION_INDEX_RECORD_SIZE
    );
    println!();
    println!(
        "Actual data:          {} ({:.2}% of packed file)",
        format_bytes(packer.total_data),
        if packed_file_size > 0 {
            packer.total_data as f64 / packed_file_size as f64 * 100.0
        } else {
            0.0
        }
    );
    println!(
        "Padding overhead:     {} ({:.2}%)",
        format_bytes(packer.total_padding),
        if packed_file_size > 0 {
            packer.total_padding as f64 / packed_file_size as f64 * 100.0
        } else {
            0.0
        }
    );
    println!("Max delta len:        {} bytes", max_delta_len);
    if packer.entry_count > 0 {
        println!(
            "Avg scripthashes/ent: {:.1}",
            total_groups as f64 / packer.entry_count as f64
        );
    }
    println!();
    println!("Size distribution:");
    let pct = |n: u64| n as f64 / total_groups.max(1) as f64 * 100.0;
    println!("  0-40 B:     {:>10} ({:.2}%)", size_histogram[0], pct(size_histogram[0]));
    println!("  40-100 B:   {:>10} ({:.2}%)", size_histogram[1], pct(size_histogram[1]));
    println!("  100-500 B:  {:>10} ({:.2}%)", size_histogram[2], pct(size_histogram[2]));
    println!("  500-1K B:   {:>10} ({:.2}%)", size_histogram[3], pct(size_histogram[3]));
    println!("  1K-2K B:    {:>10} ({:.2}%)", size_histogram[4], pct(size_histogram[4]));
    println!("  2K-3840 B:  {:>10} ({:.2}%)", size_histogram[5], pct(size_histogram[5]));
    println!("  >3840 B:    {:>10} ({:.2}%) [span multiple entries]",
        size_histogram[6], pct(size_histogram[6]));
    println!("  Whale:      {:>10}", size_histogram[7]);
    println!();
    println!("Total time:           {:.2?}", total_elapsed);

    if packer.entry_count > u32::MAX as u64 {
        println!(
            "WARNING: entry_count {} overflows u32!",
            packer.entry_count
        );
    }
}
