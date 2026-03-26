//! Analyze chunk size — focus on useful-data efficiency.
//!
//! Key metric: how many bytes of USEFUL data do I get per byte of PIR cost?
//! Reading 80 bytes but only needing 37 → only 37 counts as useful.
//!
//! Usage: cargo run --release -p build --bin chunk_size_analysis

mod common;
use common::*;
use memmap2::Mmap;
use std::fs::File;
use std::time::Instant;

fn main() {
    println!("=== Useful-Data Efficiency Analysis ===");
    println!();
    let start = Instant::now();

    let chunks_file = File::open(CHUNKS_DATA_FILE).expect("open chunks data");
    let chunks_mmap = unsafe { Mmap::map(&chunks_file) }.expect("mmap chunks");
    let index_data = std::fs::read(INDEX_FILE).expect("read index");
    let num_entries = index_data.len() / INDEX_ENTRY_SIZE;

    let mut data_sizes: Vec<usize> = Vec::with_capacity(num_entries);
    for i in 0..num_entries {
        let base = i * INDEX_ENTRY_SIZE;
        let num_chunks = index_data[base + 24] as usize;
        if num_chunks == 0 { continue; }
        let offset_half = u32::from_le_bytes(index_data[base + 20..base + 24].try_into().unwrap());
        let offset = offset_half as usize * 2;
        let padded_size = num_chunks * CHUNK_SIZE;
        if offset + padded_size > chunks_mmap.len() { continue; }

        let group_data = &chunks_mmap[offset..offset + padded_size];
        let (entry_count, mut pos) = read_varint(group_data);
        for _ in 0..entry_count {
            pos += 32;
            let (_, vl) = read_varint(&group_data[pos..]); pos += vl;
            let (_, al) = read_varint(&group_data[pos..]); pos += al;
        }
        data_sizes.push(pos);
    }

    let total_groups = data_sizes.len();
    let total_useful: u64 = data_sizes.iter().map(|&s| s as u64).sum();
    let mean_useful = total_useful as f64 / total_groups as f64;
    let mut sorted = data_sizes.clone();
    sorted.sort_unstable();
    let median_useful = sorted[total_groups / 2];

    println!("Groups: {}   Total useful data: {:.2} GB", total_groups, total_useful as f64 / 1e9);
    println!("Useful data per query: median={} B, mean={:.1} B", median_useful, mean_useful);
    println!();

    // ════════════════════════════════════════════════════════════════════
    // METRIC 1: Block-level useful ratio
    //   = useful_bytes / bytes_actually_in_fetched_blocks
    //   This ignores cuckoo overhead — just "of the block bytes I receive,
    //   how much is my data vs padding/other groups?"
    // ════════════════════════════════════════════════════════════════════
    println!("================================================================");
    println!("  METRIC 1: Block-level useful ratio");
    println!("  = useful_data / (rounds × block_size)");
    println!("  \"Of the block bytes I fetched, how much is MY data?\"");
    println!("================================================================");
    println!();

    let block_sizes = [37, 40, 48, 56, 64, 72, 80, 96, 112, 128, 160, 192, 256, 512];

    println!("{:>6}  {:>10}  {:>10}  {:>8}  {:>10}  {:>10}",
        "block", "blk_fetched", "useful", "ratio", "med_ratio", "wasted/q");

    for &bs in &block_sizes {
        let mut total_fetched: u64 = 0;
        let mut ratios: Vec<f64> = Vec::with_capacity(total_groups);

        for &sz in &data_sizes {
            let nblocks = (sz + bs - 1) / bs;
            let fetched = nblocks * bs;
            total_fetched += fetched as u64;
            ratios.push(sz as f64 / fetched as f64);
        }

        ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median_ratio = ratios[total_groups / 2];
        let avg_ratio = total_useful as f64 / total_fetched as f64;
        let avg_wasted = (total_fetched - total_useful) as f64 / total_groups as f64;

        println!("{:>5}B  {:>7.2} GB  {:>7.2} GB  {:>6.1}%   {:>7.1}%   {:>7.1} B",
            bs, total_fetched as f64 / 1e9, total_useful as f64 / 1e9,
            avg_ratio * 100.0, median_ratio * 100.0, avg_wasted);
    }

    // ════════════════════════════════════════════════════════════════════
    // METRIC 2: Full PIR useful ratio
    //   = useful_bytes / total_PIR_bandwidth
    //   bandwidth = rounds × bins_per_table × bucket_size × block_size
    //   This is the end-to-end "useful bits per bit transmitted"
    // ════════════════════════════════════════════════════════════════════
    println!();
    println!("================================================================");
    println!("  METRIC 2: End-to-end PIR useful ratio");
    println!("  = useful_data / total_PIR_bandwidth");
    println!("  bandwidth = avg_rounds × bins × bucket_size × block_size");
    println!("================================================================");
    println!();

    // Isolated model
    println!("  --- Isolated (each group = own blocks) ---");
    println!();
    println!("{:>6}  {:>8}  {:>8}  {:>10}  {:>12}  {:>12}  {:>10}",
        "block", "avg_rnd", "bw/rnd", "avg_bw/q", "useful/q", "ratio", "useful/MB");

    for &bs in &block_sizes {
        let mut total_blocks: u64 = 0;
        let mut total_rounds: u64 = 0;
        for &sz in &data_sizes {
            let n = ((sz + bs - 1) / bs) as u64;
            total_blocks += n;
            total_rounds += n;
        }
        let bins = (total_blocks as f64 / K_CHUNK as f64
            / (CHUNK_CUCKOO_BUCKET_SIZE as f64 * 0.95)).ceil() as u64;
        let bw_per_round = bins as f64 * CHUNK_CUCKOO_BUCKET_SIZE as f64 * bs as f64;
        let avg_rounds = total_rounds as f64 / total_groups as f64;
        let avg_bw = avg_rounds * bw_per_round;
        let ratio = mean_useful / avg_bw;
        let useful_per_mb = mean_useful / (avg_bw / 1e6);

        println!("{:>5}B  {:>6.3}   {:>5.1}MB  {:>8.1}MB  {:>8.1}B     {:>8.2e}  {:>7.2}B",
            bs, avg_rounds, bw_per_round / 1e6, avg_bw / 1e6,
            mean_useful, ratio, useful_per_mb);
    }

    // Packed model
    println!();
    println!("  --- Packed (multiple groups per block, no spanning) ---");
    println!();
    println!("{:>6}  {:>8}  {:>8}  {:>10}  {:>12}  {:>12}  {:>10}",
        "block", "avg_rnd", "bw/rnd", "avg_bw/q", "useful/q", "ratio", "useful/MB");

    let mut sorted_for_packing = data_sizes.clone();
    sorted_for_packing.sort_unstable();

    for &bs in &block_sizes {
        // Count packed blocks
        let mut pk_blocks: u64 = 0;
        let mut cur: usize = 0;
        let mut started = false;
        for &sz in &sorted_for_packing {
            if sz > bs {
                if started && cur > 0 { pk_blocks += 1; }
                pk_blocks += ((sz + bs - 1) / bs) as u64;
                cur = 0; started = false;
            } else if !started || cur + sz > bs {
                if started && cur > 0 { pk_blocks += 1; }
                cur = sz; started = true;
            } else {
                cur += sz;
            }
        }
        if started && cur > 0 { pk_blocks += 1; }

        // Rounds per query is still based on individual group size
        let mut total_rounds: u64 = 0;
        for &sz in &data_sizes {
            total_rounds += ((sz + bs - 1) / bs) as u64;
        }

        let bins = (pk_blocks as f64 / K_CHUNK as f64
            / (CHUNK_CUCKOO_BUCKET_SIZE as f64 * 0.95)).ceil() as u64;
        let bw_per_round = bins as f64 * CHUNK_CUCKOO_BUCKET_SIZE as f64 * bs as f64;
        let avg_rounds = total_rounds as f64 / total_groups as f64;
        let avg_bw = avg_rounds * bw_per_round;
        let ratio = mean_useful / avg_bw;
        let useful_per_mb = mean_useful / (avg_bw / 1e6);

        println!("{:>5}B  {:>6.3}   {:>5.1}MB  {:>8.1}MB  {:>8.1}B     {:>8.2e}  {:>7.2}B",
            bs, avg_rounds, bw_per_round / 1e6, avg_bw / 1e6,
            mean_useful, ratio, useful_per_mb);
    }

    // ════════════════════════════════════════════════════════════════════
    // METRIC 3: For the MEDIAN query (37 bytes), detailed breakdown
    // ════════════════════════════════════════════════════════════════════
    println!();
    println!("================================================================");
    println!("  METRIC 3: Breakdown for MEDIAN query ({} bytes useful)", median_useful);
    println!("  \"I need {} bytes. What do I actually receive/pay?\"", median_useful);
    println!("================================================================");
    println!();

    println!("{:>6} {:>5}  {:>8}  {:>10}  {:>14}  {:>12}  {:>8}",
        "block", "model", "rounds", "blk_bytes", "PIR_bw", "useful", "util%");

    for &bs in &[40, 48, 64, 80, 128, 256] {
        let rounds_med = (median_useful + bs - 1) / bs;
        let blk_bytes = rounds_med * bs;

        // Isolated
        let mut iso_blocks: u64 = 0;
        for &sz in &data_sizes {
            iso_blocks += ((sz + bs - 1) / bs) as u64;
        }
        let iso_bins = (iso_blocks as f64 / K_CHUNK as f64
            / (CHUNK_CUCKOO_BUCKET_SIZE as f64 * 0.95)).ceil() as u64;
        let iso_bw = rounds_med as f64 * iso_bins as f64
            * CHUNK_CUCKOO_BUCKET_SIZE as f64 * bs as f64;
        let iso_pct = median_useful as f64 / iso_bw * 100.0;

        println!("{:>5}B {:>5}  {:>6}    {:>6}B    {:>10.1}MB  {:>8}B    {:>5.2e}%",
            bs, "iso", rounds_med, blk_bytes, iso_bw / 1e6, median_useful, iso_pct);

        // Packed
        let mut pk_blocks: u64 = 0;
        let mut cur: usize = 0;
        let mut started = false;
        for &sz in &sorted_for_packing {
            if sz > bs {
                if started && cur > 0 { pk_blocks += 1; }
                pk_blocks += ((sz + bs - 1) / bs) as u64;
                cur = 0; started = false;
            } else if !started || cur + sz > bs {
                if started && cur > 0 { pk_blocks += 1; }
                cur = sz; started = true;
            } else {
                cur += sz;
            }
        }
        if started && cur > 0 { pk_blocks += 1; }

        let pk_bins = (pk_blocks as f64 / K_CHUNK as f64
            / (CHUNK_CUCKOO_BUCKET_SIZE as f64 * 0.95)).ceil() as u64;
        let pk_bw = rounds_med as f64 * pk_bins as f64
            * CHUNK_CUCKOO_BUCKET_SIZE as f64 * bs as f64;
        let pk_pct = median_useful as f64 / pk_bw * 100.0;

        println!("{:>5}B {:>5}  {:>6}    {:>6}B    {:>10.1}MB  {:>8}B    {:>5.2e}%",
            bs, "pack", rounds_med, blk_bytes, pk_bw / 1e6, median_useful, pk_pct);
        println!();
    }

    println!();
    println!("  Total time: {:.2?}", start.elapsed());
}
