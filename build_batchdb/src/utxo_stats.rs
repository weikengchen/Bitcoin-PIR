//! Compute statistics on per-ScriptPubKey data sizes and chunk counts.
//!
//! Reads utxo_set.bin (68-byte entries), groups by HASH160 script hash,
//! serializes each group using the same format as gen_2_utxo_chunks, and
//! reports distributions.
//!
//! Usage:
//!   cargo run --release -p build_batchdb --bin utxo_stats

use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::time::Instant;

const INPUT_FILE: &str = "/Volumes/Bitcoin/data/utxo_set.bin";

const ENTRY_SIZE: usize = 68;
const SCRIPT_HASH_SIZE: usize = 20;
const TXID_SIZE: usize = 32;
const BLOCK_SIZE: usize = 32 * 1024; // 32KB

/// A shortened UTXO entry
struct ShortenedEntry {
    txid: [u8; TXID_SIZE],
    vout: u32,
    amount: u64,
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

/// Serialize a group of entries (same format as gen_2_utxo_chunks).
fn serialize_group(entries: &mut [ShortenedEntry]) -> Vec<u8> {
    entries.sort_unstable_by(|a, b| b.txid.cmp(&a.txid));

    let mut data = Vec::with_capacity(entries.len() * (TXID_SIZE + 8) + 4);
    write_varint_to_vec(&mut data, entries.len() as u64);

    for entry in entries.iter() {
        data.extend_from_slice(&entry.txid);
        write_varint_to_vec(&mut data, entry.vout as u64);
        write_varint_to_vec(&mut data, entry.amount);
    }

    data
}

fn main() {
    println!("=== UTXO Per-ScriptPubKey Statistics ===");
    println!();
    let start = Instant::now();

    // ── 1. mmap input ────────────────────────────────────────────────────
    println!("[1] Memory-mapping input: {}", INPUT_FILE);
    let file = File::open(INPUT_FILE).expect("open input");
    let mmap = unsafe { Mmap::map(&file) }.expect("mmap");
    let n = mmap.len() / ENTRY_SIZE;
    assert_eq!(mmap.len() % ENTRY_SIZE, 0);
    println!("  {} entries ({:.2} GB)", n, mmap.len() as f64 / 1e9);
    println!();

    // ── 2. Group by script_hash ──────────────────────────────────────────
    println!("[2] Grouping entries by script_hash...");
    let group_start = Instant::now();

    const DUST_THRESHOLD: u64 = 576; // sats

    let mut map: HashMap<[u8; SCRIPT_HASH_SIZE], Vec<ShortenedEntry>> =
        HashMap::with_capacity(80_000_000);

    let mut total_dust_utxos: u64 = 0;
    // Track script_hashes that had *only* dust (they won't appear in `map`)
    // We do this via a separate set of all script_hashes seen (dust or not).
    let all_script_hashes: u64;
    let mut dust_only_scripts: HashMap<[u8; SCRIPT_HASH_SIZE], bool> =
        HashMap::with_capacity(1_000_000);

    let one_pct = std::cmp::max(1, n / 100);
    let mut last_pct = 0u64;

    for i in 0..n {
        let base = i * ENTRY_SIZE;
        let chunk = &mmap[base..base + ENTRY_SIZE];

        let amount = u64::from_le_bytes(chunk[56..64].try_into().unwrap());

        // Skip dust UTXOs
        if amount <= DUST_THRESHOLD {
            total_dust_utxos += 1;
            // Mark this script_hash as seen; if no non-dust entry adds it to
            // `map`, it will remain dust-only.
            let mut sh = [0u8; SCRIPT_HASH_SIZE];
            sh.copy_from_slice(&chunk[..SCRIPT_HASH_SIZE]);
            dust_only_scripts.entry(sh).or_insert(true);

            let pct = (i as u64 + 1) / one_pct as u64;
            if pct > last_pct && pct <= 100 {
                eprint!(
                    "\r  {}% ({}/{})  unique: {} | dust skipped: {}",
                    pct, i + 1, n, map.len(), total_dust_utxos
                );
                let _ = io::stderr().flush();
                last_pct = pct;
            }
            continue;
        }

        let mut script_hash = [0u8; SCRIPT_HASH_SIZE];
        script_hash.copy_from_slice(&chunk[..SCRIPT_HASH_SIZE]);

        let mut txid = [0u8; TXID_SIZE];
        txid.copy_from_slice(&chunk[20..52]);

        let vout = u32::from_le_bytes(chunk[52..56].try_into().unwrap());

        // This script_hash has at least one non-dust UTXO
        dust_only_scripts.insert(script_hash, false);

        map.entry(script_hash)
            .or_default()
            .push(ShortenedEntry { txid, vout, amount });

        let pct = (i as u64 + 1) / one_pct as u64;
        if pct > last_pct && pct <= 100 {
            eprint!(
                "\r  {}% ({}/{})  unique: {} | dust skipped: {}",
                pct, i + 1, n, map.len(), total_dust_utxos
            );
            let _ = io::stderr().flush();
            last_pct = pct;
        }
    }
    eprintln!();

    let dust_only_count = dust_only_scripts.values().filter(|&&v| v).count() as u64;
    all_script_hashes = map.len() as u64 + dust_only_count;
    drop(dust_only_scripts);

    let num_groups = map.len();
    println!(
        "  Done in {:.2?} — {} unique script_hashes (non-dust)",
        group_start.elapsed(),
        num_groups
    );
    println!("  Dust UTXOs skipped:   {} (amount <= {} sats)", total_dust_utxos, DUST_THRESHOLD);
    println!(
        "  Dust-only addresses:  {} (all UTXOs were dust, excluded entirely)",
        dust_only_count
    );
    println!(
        "  Total unique addresses (incl. dust-only): {}",
        all_script_hashes
    );
    println!();

    // Free the mmap — all data is now in `map`
    drop(mmap);
    drop(file);
    println!("  (mmap released)");
    println!();

    // ── 3. Serialize each group and collect sizes ────────────────────────
    println!("[3] Serializing groups and computing sizes...");
    let ser_start = Instant::now();

    let mut sizes: Vec<usize> = Vec::with_capacity(num_groups);
    let mut utxo_counts: Vec<usize> = Vec::with_capacity(num_groups);

    let one_pct_g = std::cmp::max(1, num_groups / 100);
    let mut done = 0usize;
    let mut last_pct_g = 0u64;

    for (_sh, mut entries) in map.drain() {
        utxo_counts.push(entries.len());
        let data = serialize_group(&mut entries);
        sizes.push(data.len());
        // data is dropped here — we only keep the length
        done += 1;

        let pct = done as u64 / one_pct_g as u64;
        if pct > last_pct_g && pct <= 100 {
            eprint!("\r  {}% ({}/{})", pct, done, num_groups);
            let _ = io::stderr().flush();
            last_pct_g = pct;
        }
    }
    eprintln!();

    println!("  Done in {:.2?}", ser_start.elapsed());
    println!();

    // Build per-UTXO-count storage map (before sizes is sorted and unpaired)
    let mut utxo_count_storage: HashMap<usize, (u64, u64)> = HashMap::new(); // count -> (num_groups, total_bytes)
    for i in 0..num_groups {
        let entry = utxo_count_storage.entry(utxo_counts[i]).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += sizes[i] as u64;
    }

    // ── 4. Compute statistics ────────────────────────────────────────────
    println!("[4] Statistics on serialized data size per ScriptPubKey:");
    println!();

    sizes.sort_unstable();

    let total_bytes: u64 = sizes.iter().map(|&s| s as u64).sum();
    let avg = total_bytes as f64 / num_groups as f64;
    let median = sizes[num_groups / 2];
    let min = sizes[0];
    let max = sizes[sizes.len() - 1];

    println!("  Total groups:       {}", num_groups);
    println!("  Total data bytes:   {} ({:.2} GB)", total_bytes, total_bytes as f64 / 1e9);
    println!("  Average size:       {:.1} bytes", avg);
    println!("  Median size:        {} bytes", median);
    println!("  Min size:           {} bytes", min);
    println!("  Max size:           {} bytes", max);
    println!();

    // Lowest 10 distinct sizes and their frequencies
    println!("  Lowest 10 distinct sizes:");
    println!(
        "  {:>10}  {:>12}  {:>9}  {:>14}  {:>9}",
        "Size (B)", "Count", "% groups", "Storage (B)", "% data"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "-".repeat(10), "-".repeat(12), "-".repeat(9), "-".repeat(14), "-".repeat(9)
    );

    let mut seen_sizes = 0;
    let mut i = 0;
    while i < sizes.len() && seen_sizes < 10 {
        let s = sizes[i];
        // Count how many have this exact size
        let mut count: u64 = 0;
        while i < sizes.len() && sizes[i] == s {
            count += 1;
            i += 1;
        }
        let storage = s as u64 * count;
        println!(
            "  {:>10}  {:>12}  {:>8.3}%  {:>14}  {:>8.3}%",
            s,
            count,
            count as f64 / num_groups as f64 * 100.0,
            storage,
            storage as f64 / total_bytes as f64 * 100.0
        );
        seen_sizes += 1;
    }
    println!();

    // Percentiles (size at percentile + cumulative storage up to that percentile)
    // Build prefix sum of storage bytes (sizes is already sorted)
    let mut cum_storage: Vec<u64> = Vec::with_capacity(num_groups);
    let mut running: u64 = 0;
    for &s in &sizes {
        running += s as u64;
        cum_storage.push(running);
    }

    println!("  Percentiles:");
    println!(
        "    {:>3}  {:>10}  {:>14}  {:>9}",
        "", "Size (B)", "Cum storage", "% data"
    );
    for &p in &[1, 5, 10, 25, 50, 75, 90, 95, 99] {
        let idx = (num_groups as f64 * p as f64 / 100.0) as usize;
        let idx = idx.min(num_groups - 1);
        let cum = cum_storage[idx];
        println!(
            "    P{:>2}  {:>10}  {:>14}  {:>8.3}%",
            p,
            sizes[idx],
            cum,
            cum as f64 / total_bytes as f64 * 100.0
        );
    }
    println!();

    // ── 5. Chunk count per ScriptPubKey ──────────────────────────────────
    println!("[5] Chunk count per ScriptPubKey (32KB blocks):");
    println!("  (if it shares a block with others, still counts as 1)");
    println!();

    // Number of 32KB chunks a group touches: max(1, ceil(size / BLOCK_SIZE))
    let mut chunk_counts: HashMap<usize, (usize, u64)> = HashMap::new(); // (count, storage_bytes)
    let mut total_chunks: u64 = 0;

    for &s in &sizes {
        let chunks = if s <= BLOCK_SIZE {
            1
        } else {
            (s + BLOCK_SIZE - 1) / BLOCK_SIZE
        };
        let entry = chunk_counts.entry(chunks).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += s as u64;
        total_chunks += chunks as u64;
    }

    let mut chunk_dist: Vec<(usize, usize, u64)> = chunk_counts
        .into_iter()
        .map(|(c, (cnt, st))| (c, cnt, st))
        .collect();
    chunk_dist.sort_by_key(|&(c, _, _)| c);

    println!(
        "  {:>8}  {:>12}  {:>9}  {:>14}  {:>9}",
        "Chunks", "Count", "% groups", "Storage (B)", "% data"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "-".repeat(8), "-".repeat(12), "-".repeat(9), "-".repeat(14), "-".repeat(9)
    );
    for &(chunks, count, storage) in &chunk_dist {
        println!(
            "  {:>8}  {:>12}  {:>8.4}%  {:>14}  {:>8.3}%",
            chunks,
            count,
            count as f64 / num_groups as f64 * 100.0,
            storage,
            storage as f64 / total_bytes as f64 * 100.0
        );
    }

    println!();
    println!("  Total chunks needed:  {}", total_chunks);
    println!(
        "  Avg chunks/group:     {:.4}",
        total_chunks as f64 / num_groups as f64
    );
    println!();

    // ── 6. UTXO count distribution ───────────────────────────────────────
    println!("[6] UTXOs per ScriptPubKey:");
    utxo_counts.sort_unstable();

    let total_utxos: u64 = utxo_counts.iter().map(|&c| c as u64).sum();
    let avg_utxos = total_utxos as f64 / num_groups as f64;

    println!("  Total UTXOs:   {}", total_utxos);
    println!("  Average:       {:.2}", avg_utxos);
    println!("  Median:        {}", utxo_counts[num_groups / 2]);
    println!("  Max:           {}", utxo_counts[num_groups - 1]);
    println!();

    // Full distribution sorted by UTXO count
    let mut utxo_dist: Vec<(usize, u64, u64)> = utxo_count_storage
        .into_iter()
        .map(|(uc, (cnt, st))| (uc, cnt, st))
        .collect();
    utxo_dist.sort_by_key(|&(uc, _, _)| uc);

    println!("  Distribution by UTXO count:");
    println!(
        "  {:>8}  {:>12}  {:>9}  {:>14}  {:>9}",
        "UTXOs", "Addresses", "% groups", "Storage (B)", "% data"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "-".repeat(8), "-".repeat(12), "-".repeat(9), "-".repeat(14), "-".repeat(9)
    );

    // Show all distinct counts up to 20, then bucket the rest
    let mut cum_groups_above: u64 = 0;
    let mut cum_storage_above: u64 = 0;
    for &(uc, cnt, storage) in &utxo_dist {
        if uc <= 20 {
            println!(
                "  {:>8}  {:>12}  {:>8.3}%  {:>14}  {:>8.3}%",
                uc,
                cnt,
                cnt as f64 / num_groups as f64 * 100.0,
                storage,
                storage as f64 / total_bytes as f64 * 100.0
            );
        } else {
            cum_groups_above += cnt;
            cum_storage_above += storage;
        }
    }
    if cum_groups_above > 0 {
        println!(
            "  {:>8}  {:>12}  {:>8.3}%  {:>14}  {:>8.3}%",
            ">20",
            cum_groups_above,
            cum_groups_above as f64 / num_groups as f64 * 100.0,
            cum_storage_above,
            cum_storage_above as f64 / total_bytes as f64 * 100.0
        );
    }
    println!();

    // Tail: top UTXO counts (addresses with most UTXOs)
    println!("  Top 10 UTXO counts (whales):");
    println!(
        "  {:>10}  {:>12}  {:>14}  {:>9}",
        "UTXOs", "Addresses", "Storage (B)", "% data"
    );
    println!(
        "  {}  {}  {}  {}",
        "-".repeat(10), "-".repeat(12), "-".repeat(14), "-".repeat(9)
    );
    let tail_start = if utxo_dist.len() > 10 { utxo_dist.len() - 10 } else { 0 };
    for &(uc, cnt, storage) in &utxo_dist[tail_start..] {
        println!(
            "  {:>10}  {:>12}  {:>14}  {:>8.3}%",
            uc,
            cnt,
            storage,
            storage as f64 / total_bytes as f64 * 100.0
        );
    }
    println!();

    // Cumulative from the top: "if we exclude addresses with > X UTXOs"
    println!("  Cumulative tail (addresses with > N UTXOs):");
    println!(
        "  {:>10}  {:>12}  {:>9}  {:>14}  {:>9}",
        "> N UTXOs", "Addresses", "% groups", "Storage (B)", "% data"
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "-".repeat(10), "-".repeat(12), "-".repeat(9), "-".repeat(14), "-".repeat(9)
    );
    let thresholds = [1, 2, 3, 5, 10, 20, 50, 100, 500, 1000, 5000, 10000, 50000];

    // Build reverse cumulative suffix sums from utxo_dist (sorted ascending)
    // For efficiency, walk once from the end.
    let mut suffix_groups: Vec<u64> = vec![0; utxo_dist.len() + 1];
    let mut suffix_storage: Vec<u64> = vec![0; utxo_dist.len() + 1];
    for i in (0..utxo_dist.len()).rev() {
        suffix_groups[i] = suffix_groups[i + 1] + utxo_dist[i].1;
        suffix_storage[i] = suffix_storage[i + 1] + utxo_dist[i].2;
    }

    for &thr in &thresholds {
        // Find first index where uc > thr
        let pos = utxo_dist.partition_point(|&(uc, _, _)| uc <= thr);
        let g = suffix_groups[pos];
        let s = suffix_storage[pos];
        if g == 0 { continue; }
        println!(
            "  {:>10}  {:>12}  {:>8.3}%  {:>14}  {:>8.3}%",
            format!(">{}", thr),
            g,
            g as f64 / num_groups as f64 * 100.0,
            s,
            s as f64 / total_bytes as f64 * 100.0
        );
    }
    println!();

    // ── 7. Dust summary ──────────────────────────────────────────────────
    let total_utxos_kept: u64 = utxo_counts.iter().map(|&c| c as u64).sum();
    let total_utxos_original = total_utxos_kept + total_dust_utxos;

    println!("[7] Dust filtering summary (amount <= {} sats):", DUST_THRESHOLD);
    println!("  Original UTXOs:     {}", total_utxos_original);
    println!("  Dust UTXOs removed: {} ({:.3}%)",
        total_dust_utxos,
        total_dust_utxos as f64 / total_utxos_original as f64 * 100.0
    );
    println!("  UTXOs kept:         {} ({:.3}%)",
        total_utxos_kept,
        total_utxos_kept as f64 / total_utxos_original as f64 * 100.0
    );
    println!("  Original addresses: {}", all_script_hashes);
    println!("  Dust-only removed:  {}", dust_only_count);
    println!("  Addresses kept:     {} ({:.3}%)",
        num_groups,
        num_groups as f64 / all_script_hashes as f64 * 100.0
    );
    println!();

    println!("  Total time: {:.2?}", start.elapsed());
}
