//! Bitcoin block size & witness data analysis
//!
//! Streams the last N blocks from blk*.dat files using brk_reader and computes:
//! - Full vs stripped (no-witness) block sizes
//! - Witness data percentage
//! - Block size distributions and percentiles
//!
//! Usage: block_stats <bitcoin_datadir> [num_blocks]
//! Example: block_stats /Volumes/Bitcoin/bitcoin 10000

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Instant;

use brk_reader::Reader;
use brk_rpc::{Auth, Client};

/// Compute the size of a Bitcoin varint encoding
fn varint_size(n: usize) -> usize {
    if n < 0xfd {
        1
    } else if n <= 0xffff {
        3
    } else if n <= 0xffff_ffff {
        5
    } else {
        9
    }
}

struct BlockRecord {
    height: u64,
    total_size: usize,
    stripped_size: usize,
    num_tx: usize,
    weight: usize,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: {} <bitcoin_datadir> [num_blocks]", args[0]);
        eprintln!("Example: {} /Volumes/Bitcoin/bitcoin 10000", args[0]);
        std::process::exit(1);
    }

    let bitcoin_dir = PathBuf::from(&args[1]);
    let num_blocks: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10_000);

    let blocks_dir = bitcoin_dir.join("blocks");
    if !blocks_dir.exists() {
        eprintln!("Error: blocks directory does not exist: {:?}", blocks_dir);
        std::process::exit(1);
    }

    let cookie_path = bitcoin_dir.join(".cookie");
    if !cookie_path.exists() {
        eprintln!("Error: Cookie file not found: {:?}", cookie_path);
        eprintln!("Make sure Bitcoin Core is running.");
        std::process::exit(1);
    }

    // Connect to Bitcoin Core
    let client = Client::new("http://127.0.0.1:8332", Auth::CookieFile(cookie_path))
        .expect("Failed to create RPC client");

    let chain_height = client.get_block_count().expect("Failed to get block count");
    let start_height = if chain_height >= num_blocks {
        chain_height - num_blocks + 1
    } else {
        0
    };
    let end_height = chain_height + 1; // exclusive

    println!("=== Bitcoin Block Size & Witness Analysis ===");
    println!("Chain height:  {}", chain_height);
    println!("Analyzing:     blocks {} to {} ({} blocks)", start_height, chain_height, end_height - start_height);
    println!();

    // Stream blocks
    let reader = Reader::new(blocks_dir, &client);
    let receiver = reader.read(
        Some((start_height as u32).into()),
        Some((end_height as u32).into()),
    );

    let mut records: Vec<BlockRecord> = Vec::with_capacity(num_blocks as usize);
    let start_time = Instant::now();
    let mut last_print = Instant::now();

    for block in receiver.iter() {
        let height: u64 = block.height().into();
        let total_size = block.total_size();
        let num_tx = block.txdata.len();

        // Stripped size = 80-byte header + varint(num_tx) + sum of base_size per tx
        let stripped_size: usize = 80
            + varint_size(num_tx)
            + block.txdata.iter().map(|tx| tx.base_size()).sum::<usize>();

        let weight = block.weight().to_wu() as usize;

        records.push(BlockRecord {
            height,
            total_size,
            stripped_size,
            num_tx,
            weight,
        });

        if last_print.elapsed().as_millis() >= 500 || records.len() as u64 == num_blocks {
            let done = records.len() as u64;
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = done as f64 / elapsed;
            let eta = if rate > 0.0 {
                (num_blocks - done) as f64 / rate
            } else {
                0.0
            };
            print!(
                "\rStreaming: {}/{} blocks ({:.1}%) | {:.0} blk/s | ETA {:.0}s   ",
                done, num_blocks, 100.0 * done as f64 / num_blocks as f64, rate, eta
            );
            io::stdout().flush().ok();
            last_print = Instant::now();
        }
    }

    let elapsed = start_time.elapsed();
    println!(
        "\rStreamed {} blocks in {:.1}s ({:.0} blk/s)                        ",
        records.len(),
        elapsed.as_secs_f64(),
        records.len() as f64 / elapsed.as_secs_f64()
    );
    println!();

    if records.is_empty() {
        println!("No blocks to analyze.");
        return;
    }

    // ── Aggregate stats ──────────────────────────────────────────────

    let total_full: u64 = records.iter().map(|r| r.total_size as u64).sum();
    let total_stripped: u64 = records.iter().map(|r| r.stripped_size as u64).sum();
    let total_witness = total_full - total_stripped;

    let full_sizes: Vec<f64> = records.iter().map(|r| r.total_size as f64).collect();
    let strip_sizes: Vec<f64> = records.iter().map(|r| r.stripped_size as f64).collect();
    let witness_pcts: Vec<f64> = records
        .iter()
        .map(|r| {
            if r.total_size > 0 {
                100.0 * (r.total_size - r.stripped_size) as f64 / r.total_size as f64
            } else {
                0.0
            }
        })
        .collect();

    println!("=== SIZES WITH WITNESS (full blocks) ===");
    println!("  Total:   {:.3} GB", total_full as f64 / 1e9);
    print_stats("  ", &full_sizes, 1e6, "MB");

    println!();
    println!("=== SIZES WITHOUT WITNESS (stripped) ===");
    println!("  Total:   {:.3} GB", total_stripped as f64 / 1e9);
    print_stats("  ", &strip_sizes, 1e6, "MB");

    println!();
    println!("=== WITNESS DATA ===");
    println!("  Total witness:  {:.3} GB", total_witness as f64 / 1e9);
    println!(
        "  Witness %:      {:.1}%",
        100.0 * total_witness as f64 / total_full as f64
    );
    println!(
        "  Stripped/Full:  {:.1}%",
        100.0 * total_stripped as f64 / total_full as f64
    );

    println!();
    println!("=== PER-BLOCK WITNESS % DISTRIBUTION ===");
    print_stats("  ", &witness_pcts, 1.0, "%");

    // ── Histograms ───────────────────────────────────────────────────

    println!();
    println!("=== FULL BLOCK SIZE DISTRIBUTION ===");
    let full_buckets: Vec<(f64, f64, &str)> = vec![
        (0.0, 250e3, "<250KB"),
        (250e3, 500e3, "250-500KB"),
        (500e3, 1e6, "0.5-1MB"),
        (1e6, 1.5e6, "1-1.5MB"),
        (1.5e6, 2e6, "1.5-2MB"),
        (2e6, 2.5e6, "2-2.5MB"),
        (2.5e6, 3e6, "2.5-3MB"),
        (3e6, 3.5e6, "3-3.5MB"),
        (3.5e6, 4e6, "3.5-4MB"),
        (4e6, f64::MAX, ">4MB"),
    ];
    print_histogram(&full_sizes, &full_buckets);

    println!();
    println!("=== STRIPPED BLOCK SIZE DISTRIBUTION ===");
    let strip_buckets: Vec<(f64, f64, &str)> = vec![
        (0.0, 100e3, "<100KB"),
        (100e3, 250e3, "100-250KB"),
        (250e3, 500e3, "250-500KB"),
        (500e3, 750e3, "500-750KB"),
        (750e3, 1e6, "750KB-1MB"),
        (1e6, 1.25e6, "1-1.25MB"),
        (1.25e6, f64::MAX, ">1.25MB"),
    ];
    print_histogram(&strip_sizes, &strip_buckets);

    // ── Percentiles ──────────────────────────────────────────────────

    println!();
    println!("=== PERCENTILES ===");
    let mut sorted_full: Vec<f64> = full_sizes.clone();
    let mut sorted_strip: Vec<f64> = strip_sizes.clone();
    sorted_full.sort_by(|a, b| a.partial_cmp(b).unwrap());
    sorted_strip.sort_by(|a, b| a.partial_cmp(b).unwrap());

    println!(
        "  {:>4}  {:>12}  {:>12}  {:>8}",
        "", "Full", "Stripped", "Ratio"
    );
    for p in [5, 10, 25, 50, 75, 90, 95, 99] {
        let idx = (sorted_full.len() * p / 100).min(sorted_full.len() - 1);
        let f = sorted_full[idx];
        let s = sorted_strip[idx];
        let ratio = if f > 0.0 { 100.0 * s / f } else { 0.0 };
        println!(
            "  P{:<3} {:>9.2} MB  {:>9.2} MB  {:>6.1}%",
            p,
            f / 1e6,
            s / 1e6,
            ratio
        );
    }

    // ── Per-transaction stats ────────────────────────────────────────

    let total_txs: u64 = records.iter().map(|r| r.num_tx as u64).sum();
    let tx_counts: Vec<f64> = records.iter().map(|r| r.num_tx as f64).collect();

    println!();
    println!("=== TRANSACTION COUNTS ===");
    println!("  Total transactions: {}", total_txs);
    print_stats("  ", &tx_counts, 1.0, "");
}

fn mean(data: &[f64]) -> f64 {
    data.iter().sum::<f64>() / data.len() as f64
}

fn stdev(data: &[f64]) -> f64 {
    let m = mean(data);
    let variance = data.iter().map(|x| (x - m).powi(2)).sum::<f64>() / data.len() as f64;
    variance.sqrt()
}

fn median(data: &[f64]) -> f64 {
    let mut sorted = data.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len();
    if n.is_multiple_of(2) {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    }
}

fn print_stats(prefix: &str, data: &[f64], divisor: f64, unit: &str) {
    let min_val = data.iter().cloned().fold(f64::MAX, f64::min);
    let max_val = data.iter().cloned().fold(f64::MIN, f64::max);
    println!(
        "{}Mean:    {:.3} {}",
        prefix,
        mean(data) / divisor,
        unit
    );
    println!(
        "{}Median:  {:.3} {}",
        prefix,
        median(data) / divisor,
        unit
    );
    println!(
        "{}Stdev:   {:.3} {}",
        prefix,
        stdev(data) / divisor,
        unit
    );
    println!(
        "{}Min:     {:.3} {}",
        prefix,
        min_val / divisor,
        unit
    );
    println!(
        "{}Max:     {:.3} {}",
        prefix,
        max_val / divisor,
        unit
    );
}

fn print_histogram(data: &[f64], buckets: &[(f64, f64, &str)]) {
    let n = data.len();
    println!(
        "  {:<12} {:>6} {:>7}  Bar",
        "Bucket", "Count", "Pct"
    );
    for &(lo, hi, label) in buckets {
        let count = data.iter().filter(|&&v| v >= lo && v < hi).count();
        let pct = 100.0 * count as f64 / n as f64;
        let bar: String = std::iter::repeat_n('#', (pct / 2.0) as usize).collect();
        println!("  {:<12} {:>6} {:>6.1}%  {}", label, count, pct, bar);
    }
}
