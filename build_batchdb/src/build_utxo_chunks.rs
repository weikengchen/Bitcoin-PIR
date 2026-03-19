//! Build UTXO chunks database, skipping dust UTXOs (amount ≤ 576 sats).
//!
//! Reads `/Volumes/Bitcoin/data/utxo_set.bin` (68-byte entries),
//! groups entries by HASH160 script hash (excluding dust), and writes:
//! - `/Volumes/Bitcoin/data/utxo_chunks_nodust.bin`       — compact UTXO data in 80-byte blocks
//! - `/Volumes/Bitcoin/data/utxo_chunks_index_nodust.bin`  — index (script_hash → offset, num_chunks)
//! - `/Volumes/Bitcoin/data/top100_addresses.bin`          — top 100 largest groups
//!
//! Each group occupies ceil(data_len / 80) contiguous 80-byte blocks, padded with zeros.
//! Index stores offset/2 as u32 (2-byte alignment guaranteed by 80-byte blocks).
//!
//! Usage:
//!   cargo run --release -p build_batchdb --bin build_utxo_chunks [-- --partitions N]

use memmap2::Mmap;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::time::Instant;

const INPUT_FILE: &str = "/Volumes/Bitcoin/data/utxo_set.bin";
const CHUNKS_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_nodust.bin";
const INDEX_FILE: &str = "/Volumes/Bitcoin/data/utxo_chunks_index_nodust.bin";
const TOP_FILE: &str = "/Volumes/Bitcoin/data/top100_addresses.bin";

const ENTRY_SIZE: usize = 68;
const SCRIPT_HASH_SIZE: usize = 20;
const TXID_SIZE: usize = 32;
const BLOCK_SIZE: usize = 80;
const DEFAULT_PARTITIONS: usize = 4;
const DUST_THRESHOLD: u64 = 576; // sats
const MAX_UTXOS_PER_SPK: usize = 100; // skip script pubkeys with more than this many UTXOs
const TOP_N: usize = 100;
const INDEX_ENTRY_SIZE: usize = 20 + 4 + 4; // script_hash + offset_half + num_chunks

/// Zero buffer for padding (max padding = BLOCK_SIZE - 1 = 79 bytes)
const ZERO_PAD: [u8; BLOCK_SIZE] = [0u8; BLOCK_SIZE];

#[derive(Clone)]
struct ShortenedEntry {
    txid: [u8; TXID_SIZE],
    vout: u32,
    amount: u64,
    height: u32,
}

/// Top-100 entry: (data_len, script_hash, first_txid, first_vout)
type TopEntry = (usize, [u8; SCRIPT_HASH_SIZE], [u8; TXID_SIZE], u32);

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

/// Serialize a group of entries. Entries must already be sorted by height descending.
fn serialize_group_sorted(entries: &[ShortenedEntry]) -> Vec<u8> {
    let mut data = Vec::with_capacity(entries.len() * (TXID_SIZE + 8) + 4);
    write_varint_to_vec(&mut data, entries.len() as u64);

    for entry in entries.iter() {
        data.extend_from_slice(&entry.txid);
        write_varint_to_vec(&mut data, entry.vout as u64);
        write_varint_to_vec(&mut data, entry.amount);
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

fn parse_partitions() -> usize {
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--partitions" {
            i += 1;
            if i < args.len() {
                return args[i].parse().unwrap_or(DEFAULT_PARTITIONS).max(1);
            }
        }
        i += 1;
    }
    DEFAULT_PARTITIONS
}

fn main() {
    println!("=== Build UTXO Chunks (No Dust, 80-byte blocks) ===");
    println!();

    let num_partitions = parse_partitions();

    println!("Configuration:");
    println!("  Block size:     {} bytes", BLOCK_SIZE);
    println!("  Partitions:     {}", num_partitions);
    println!("  Dust threshold: {} sats", DUST_THRESHOLD);
    println!("  Max UTXOs/SPK:  {} (skip larger)", MAX_UTXOS_PER_SPK);
    println!("  Input:          {}", INPUT_FILE);
    println!("  Output chunks:  {}", CHUNKS_FILE);
    println!("  Output index:   {}", INDEX_FILE);
    println!("  Top-100 file:   {}", TOP_FILE);
    println!();

    let total_start = Instant::now();

    // ── 1. mmap input ──────────────────────────────────────────────────
    println!("[1] Memory-mapping input...");
    let input_file = File::open(INPUT_FILE).expect("open input");
    let mmap = unsafe { Mmap::map(&input_file) }.expect("mmap");
    let entry_count = mmap.len() / ENTRY_SIZE;
    assert_eq!(mmap.len() % ENTRY_SIZE, 0);
    println!("  {} entries ({})", entry_count, format_bytes(mmap.len() as u64));
    println!();

    // ── 2. Open output files ───────────────────────────────────────────
    println!("[2] Opening output files...");
    let chunks_file = File::create(CHUNKS_FILE).expect("create chunks file");
    let mut chunks_writer = BufWriter::with_capacity(1024 * 1024, chunks_file);
    let index_file = File::create(INDEX_FILE).expect("create index file");
    let mut index_writer = BufWriter::with_capacity(1024 * 1024, index_file);
    println!("  Done");
    println!();

    // ── 3. Partitioned processing ──────────────────────────────────────
    println!("[3] Processing {} partitions...", num_partitions);
    println!();

    let packing_start = Instant::now();

    let mut current_offset: u64 = 0;
    let mut total_blocks_written: u64 = 0;
    let mut total_groups_written: u64 = 0;
    let mut total_padding_bytes: u64 = 0;
    let mut total_dust_skipped: u64 = 0;
    let mut total_data_bytes: u64 = 0;
    let mut total_whale_skipped: u64 = 0;

    // Min-heap of top 100 largest groups (by data_len)
    let mut top_heap: BinaryHeap<Reverse<TopEntry>> = BinaryHeap::new();

    for partition in 0..num_partitions {
        println!("=== Partition {}/{} ===", partition + 1, num_partitions);
        let partition_start = Instant::now();

        // ── 3a. Build HashMap for this partition ────────────────────────
        let build_start = Instant::now();
        let estimated_keys = 80_000_000 / num_partitions;
        let mut map: HashMap<[u8; SCRIPT_HASH_SIZE], Vec<ShortenedEntry>> =
            HashMap::with_capacity(estimated_keys);

        let one_percent = std::cmp::max(1, entry_count / 100);
        let mut last_pct = 0u64;
        let mut partition_dust = 0u64;

        for i in 0..entry_count {
            let base = i * ENTRY_SIZE;
            let chunk = &mmap[base..base + ENTRY_SIZE];

            if chunk[0] as usize % num_partitions != partition {
                continue;
            }

            let amount = u64::from_le_bytes(chunk[56..64].try_into().unwrap());

            // Skip dust UTXOs
            if amount <= DUST_THRESHOLD {
                partition_dust += 1;
                let current_pct = (i as u64 + 1) / one_percent as u64;
                if current_pct > last_pct && current_pct <= 100 {
                    eprint!(
                        "\r    Building: {}% | Scanned: {}/{} | Keys: {} | Dust skipped: {}",
                        current_pct, i + 1, entry_count, map.len(), partition_dust
                    );
                    let _ = io::stderr().flush();
                    last_pct = current_pct;
                }
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

            let current_pct = (i as u64 + 1) / one_percent as u64;
            if current_pct > last_pct && current_pct <= 100 {
                eprint!(
                    "\r    Building: {}% | Scanned: {}/{} | Keys: {} | Dust skipped: {}",
                    current_pct, i + 1, entry_count, map.len(), partition_dust
                );
                let _ = io::stderr().flush();
                last_pct = current_pct;
            }
        }
        eprintln!();

        let unique_keys = map.len();
        total_dust_skipped += partition_dust;
        println!(
            "  HashMap built in {:.2?} — {} unique script_hashes, {} dust UTXOs skipped",
            build_start.elapsed(), unique_keys, partition_dust
        );

        // ── 3b+3c+3d. Serialize, write blocks, write index ─────────────
        let write_start = Instant::now();

        let mut partition_groups: u64 = 0;
        let mut partition_blocks: u64 = 0;
        let mut partition_padding: u64 = 0;
        let mut partition_data: u64 = 0;
        let mut partition_whale_skipped: u64 = 0;

        for (script_hash, mut entries) in map.drain() {
            if entries.len() > MAX_UTXOS_PER_SPK {
                partition_whale_skipped += 1;
                continue;
            }
            // Sort entries by block height descending (most recent first)
            entries.sort_unstable_by(|a, b| b.height.cmp(&a.height));

            // Capture first entry's txid and vout (for top-100 tracking)
            let first_txid = entries[0].txid;
            let first_vout = entries[0].vout;

            // Serialize (entries already sorted, serialize_group_sorted won't re-sort)
            let data = serialize_group_sorted(&entries);
            let data_len = data.len();

            // ── Top-100 tracking (min-heap by data_len) ─────────────────
            if top_heap.len() < TOP_N {
                top_heap.push(Reverse((data_len, script_hash, first_txid, first_vout)));
            } else if data_len > top_heap.peek().unwrap().0 .0 {
                top_heap.pop();
                top_heap.push(Reverse((data_len, script_hash, first_txid, first_vout)));
            }

            // ── Write to chunks file ────────────────────────────────────
            // current_offset is always a multiple of BLOCK_SIZE (80), which is even,
            // so the /2 trick works without extra alignment padding.
            let num_chunks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
            let padded_len = num_chunks * BLOCK_SIZE;
            let padding = padded_len - data_len;

            // Write index entry: [20B script_hash][4B offset_half LE][4B num_chunks LE]
            let offset_half = (current_offset / 2) as u32;
            index_writer.write_all(&script_hash).unwrap();
            index_writer.write_all(&offset_half.to_le_bytes()).unwrap();
            index_writer.write_all(&(num_chunks as u32).to_le_bytes()).unwrap();

            // Write data
            chunks_writer.write_all(&data).unwrap();

            // Pad to fill the last 80-byte block
            if padding > 0 {
                // padding is at most BLOCK_SIZE - 1 = 79 bytes
                chunks_writer.write_all(&ZERO_PAD[..padding]).unwrap();
            }

            current_offset += padded_len as u64;
            partition_groups += 1;
            partition_blocks += num_chunks as u64;
            partition_padding += padding as u64;
            partition_data += data_len as u64;
        }
        drop(map);

        total_groups_written += partition_groups;
        total_blocks_written += partition_blocks;
        total_padding_bytes += partition_padding;
        total_data_bytes += partition_data;
        total_whale_skipped += partition_whale_skipped;

        println!(
            "  Written {} groups ({} blocks) in {:.2?} — data: {}, padding: {}, whale-skipped: {}",
            partition_groups,
            partition_blocks,
            write_start.elapsed(),
            format_bytes(partition_data),
            format_bytes(partition_padding),
            partition_whale_skipped
        );
        println!(
            "  Partition {}/{} completed in {:.2?}",
            partition + 1, num_partitions, partition_start.elapsed()
        );
        println!();
    }

    let packing_elapsed = packing_start.elapsed();

    // ── 4. Flush output files ──────────────────────────────────────────
    println!("[4] Flushing output files...");
    chunks_writer.flush().unwrap();
    index_writer.flush().unwrap();
    println!("  Done");
    println!();

    // ── 5. Write top-100 file ──────────────────────────────────────────
    println!("[5] Writing top-100 largest groups to {}...", TOP_FILE);

    // Drain heap into a vec, sorted by data_len descending
    let mut top_entries: Vec<TopEntry> = top_heap.into_sorted_vec()
        .into_iter()
        .map(|Reverse(e)| e)
        .collect();
    top_entries.reverse(); // largest first

    {
        let top_file = File::create(TOP_FILE).expect("create top-100 file");
        let mut top_writer = BufWriter::new(top_file);

        for (data_len, script_hash, first_txid, first_vout) in &top_entries {
            top_writer.write_all(script_hash).unwrap();        // 20 bytes
            top_writer.write_all(first_txid).unwrap();         // 32 bytes
            top_writer.write_all(&first_vout.to_le_bytes()).unwrap(); // 4 bytes
            // Also store data_len so the file is self-descriptive
            top_writer.write_all(&(*data_len as u32).to_le_bytes()).unwrap(); // 4 bytes
        }
        top_writer.flush().unwrap();
    }

    println!("  Written {} entries (60 bytes each: 20B hash + 32B txid + 4B vout + 4B data_len)",
        top_entries.len());

    // Print the top 10 for quick reference
    println!();
    println!("  Top 10 largest groups:");
    println!("  {:>4}  {:>12}  {:>8}  script_hash (hex)", "Rank", "Data (B)", "Chunks");
    for (i, (data_len, script_hash, _txid, _vout)) in top_entries.iter().take(10).enumerate() {
        let num_chunks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
        let hash_hex: String = script_hash.iter().map(|b| format!("{:02x}", b)).collect();
        println!("  {:>4}  {:>12}  {:>8}  {}", i + 1, data_len, num_chunks, hash_hex);
    }
    println!();

    // ── Summary ────────────────────────────────────────────────────────
    let total_elapsed = total_start.elapsed();

    println!("=== Summary ===");
    println!("Input entries:        {}", entry_count);
    println!("Dust UTXOs skipped:   {} (amount <= {} sats)", total_dust_skipped, DUST_THRESHOLD);
    println!("Whale SPKs skipped:   {} (>{} UTXOs)", total_whale_skipped, MAX_UTXOS_PER_SPK);
    println!("Groups written:       {}", total_groups_written);
    println!();
    println!("Block size:           {} bytes", BLOCK_SIZE);
    println!("Partitions:           {}", num_partitions);
    println!("Total blocks:         {}", total_blocks_written);
    println!(
        "Chunks file size:     {} ({} blocks x {} B)",
        format_bytes(current_offset),
        total_blocks_written,
        BLOCK_SIZE
    );
    let index_size = total_groups_written * INDEX_ENTRY_SIZE as u64;
    println!(
        "Index file size:      {} ({} entries x {} bytes)",
        format_bytes(index_size),
        total_groups_written,
        INDEX_ENTRY_SIZE
    );
    println!(
        "Actual data:          {} ({:.2}% of chunks file)",
        format_bytes(total_data_bytes),
        if current_offset > 0 {
            total_data_bytes as f64 / current_offset as f64 * 100.0
        } else {
            0.0
        }
    );
    println!(
        "Padding overhead:     {} ({:.2}%)",
        format_bytes(total_padding_bytes),
        if current_offset > 0 {
            total_padding_bytes as f64 / current_offset as f64 * 100.0
        } else {
            0.0
        }
    );
    println!(
        "Avg blocks/group:     {:.2}",
        total_blocks_written as f64 / total_groups_written as f64
    );

    // Verify offset doesn't overflow u32 offset_half
    let max_offset_half = current_offset / 2;
    if max_offset_half > u32::MAX as u64 {
        println!("WARNING: offset_half overflows u32! Max offset_half = {} > {}", max_offset_half, u32::MAX);
    } else {
        println!(
            "Max offset_half:      {} / {} ({:.1}% of u32 range)",
            max_offset_half,
            u32::MAX,
            max_offset_half as f64 / u32::MAX as f64 * 100.0
        );
    }

    println!();
    println!("Packing time:         {:.2?}", packing_elapsed);
    println!("Total time:           {:.2?}", total_elapsed);
}
