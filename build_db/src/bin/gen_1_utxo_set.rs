//! Generate flat UTXO set with HASH160 script hashes and full TXIDs
//!
//! This tool reads a Bitcoin Core UTXO snapshot (`bitcoin-cli dumptxoutset`)
//! and produces a flat binary file with 64-byte entries suitable for
//! downstream PIR database construction.
//!
//! Unlike gen_4_utxo_remapped, this step does NOT require MPHF or
//! txid_locations — it stores the full 32-byte TXID directly and uses
//! HASH160 (RIPEMD160(SHA256(scriptPubKey))) instead of bare RIPEMD160.
//!
//! Output format per UTXO (68 bytes):
//!   [0..20)   HASH160 of scriptPubKey (20 bytes) — RIPEMD160(SHA256(script))
//!   [20..52)  Full TXID (32 bytes)
//!   [52..56)  vout (u32 little-endian)
//!   [56..64)  amount in satoshis (u64 little-endian)
//!   [64..68)  block height (u32 little-endian)
//!
//! Usage:
//!   gen_1_utxo_set <utxo_snapshot_file>
//!
//! Example:
//!   gen_1_utxo_set /path/to/utxo.dat

use bitcoin::hashes::{ripemd160, sha256, Hash};
use bitcoinpir::utils;
use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::Instant;
use txoutset::Dump;

/// Output file path for the flat UTXO set
const OUTPUT_FILE: &str = "/Volumes/Bitcoin/data/utxo_set.bin";

/// Size of each output entry in bytes
const ENTRY_SIZE: u64 = 68;

/// Write a single UTXO entry to the output file
/// Format: hash160 (20B) + txid (32B) + vout (4B) + amount (8B) + height (4B) = 68 bytes
fn write_utxo_entry(
    writer: &mut BufWriter<File>,
    script_hash: &[u8; 20],
    txid: &[u8; 32],
    vout: u32,
    amount: u64,
    height: u32,
) -> io::Result<()> {
    writer.write_all(script_hash)?;
    writer.write_all(txid)?;
    writer.write_all(&vout.to_le_bytes())?;
    writer.write_all(&amount.to_le_bytes())?;
    writer.write_all(&height.to_le_bytes())?;
    Ok(())
}

/// Process the UTXO snapshot and write flat UTXO entries
fn process_utxo_snapshot(snapshot_path: &Path) -> Result<(), String> {
    println!();
    println!("[1] Opening UTXO snapshot...");
    println!("    Snapshot path: {}", snapshot_path.display());

    if !snapshot_path.exists() {
        return Err(format!(
            "snapshot file does not exist: {}",
            snapshot_path.display()
        ));
    }

    let dump = match Dump::new(snapshot_path, txoutset::ComputeAddresses::No) {
        Ok(dump) => dump,
        Err(e) => return Err(format!("Unable to open UTXO snapshot: {:?}", e)),
    };

    println!("    Block hash: {}", dump.block_hash);
    println!("    UTXO set size: {}", dump.utxo_set_size);

    let total_entries = dump.utxo_set_size;

    // Open output file
    println!();
    println!("[2] Opening output file: {}", OUTPUT_FILE);
    let output_file =
        File::create(OUTPUT_FILE).map_err(|e| format!("Failed to create output file: {}", e))?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, output_file); // 1MB buffer

    println!();
    println!("[3] Processing UTXOs...");
    println!();

    let mut total_utxos: u64 = 0;
    let mut total_amount: u64 = 0;
    let mut entry_count: u64 = 0;
    let mut skipped_height: u64 = 0;
    let start_time = Instant::now();

    // Progress tracking (every 0.1%)
    let one_tenth_percent = std::cmp::max(1, total_entries / 1000);
    let mut last_reported_permille = 0u64;

    for txout in dump {
        entry_count += 1;

        // Update progress every 0.1%
        let current_permille = entry_count / one_tenth_percent;
        if current_permille > last_reported_permille && current_permille <= 1000 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let progress_fraction = current_permille as f64 / 1000.0;
            let eta_secs = if progress_fraction > 0.0 {
                (elapsed / progress_fraction) * (1.0 - progress_fraction)
            } else {
                0.0
            };
            let eta_str = utils::format_duration(eta_secs);
            print!(
                "\rProcessing: {:.1}% | ETA: {} | Entries: {}/{} | UTXOs: {}",
                current_permille as f64 / 10.0,
                eta_str,
                entry_count,
                total_entries,
                total_utxos
            );
            io::stdout().flush().ok();
            last_reported_permille = current_permille;
        }

        // Skip entries with height >= 940_612
        if txout.height >= 940_612 {
            skipped_height += 1;
            continue;
        }

        // Get TXID bytes
        let txid_bytes = txout.out_point.txid.to_byte_array();
        let vout = txout.out_point.vout;
        let amount: u64 = txout.amount.into();
        let script = txout.script_pubkey;

        // Compute HASH160 = RIPEMD160(SHA256(scriptPubKey))
        let sha256_hash = sha256::Hash::hash(script.as_bytes());
        let hash160 = ripemd160::Hash::hash(&sha256_hash.to_byte_array());
        let script_hash_array: [u8; 20] = hash160.to_byte_array();

        let height = txout.height;

        // Write UTXO entry
        if let Err(e) = write_utxo_entry(&mut writer, &script_hash_array, &txid_bytes, vout, amount, height)
        {
            return Err(format!("Failed to write UTXO entry: {}", e));
        }

        total_utxos += 1;
        total_amount += amount;
    }

    // Flush the writer
    if let Err(e) = writer.flush() {
        return Err(format!("Failed to flush output file: {}", e));
    }

    let elapsed = start_time.elapsed();

    println!(
        "\rProcessing: 100.0% | Complete | Entries: {}/{} | UTXOs: {}",
        entry_count, total_entries, total_utxos
    );
    println!();
    println!("=== Summary ===");
    println!("Total entries processed: {}", entry_count);
    println!("Total UTXOs written: {}", total_utxos);
    println!("Skipped (height >= 940612): {}", skipped_height);
    println!(
        "Total amount: {:.8} BTC",
        total_amount as f64 / 100_000_000.0
    );
    println!("Output file: {}", OUTPUT_FILE);
    println!("Time elapsed: {}", utils::format_duration(elapsed.as_secs_f64()));
    println!(
        "Entries per second: {:.0}",
        entry_count as f64 / elapsed.as_secs_f64()
    );

    // Get output file size
    if let Ok(metadata) = std::fs::metadata(OUTPUT_FILE) {
        let size = metadata.len();
        println!("Output file size: {} ({})", utils::format_bytes(size), size);
        println!(
            "Entry count from file size: {} ({}B x {})",
            size / ENTRY_SIZE,
            ENTRY_SIZE,
            size / ENTRY_SIZE
        );
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <utxo_snapshot_file>", args[0]);
        eprintln!();
        eprintln!("Create a UTXO snapshot with: bitcoin-cli dumptxoutset <path>");
        std::process::exit(1);
    }

    let snapshot_path = Path::new(&args[1]);

    println!("=== Generate UTXO Set (64-byte entries with HASH160 + full TXID) ===");
    println!("Snapshot: {}", snapshot_path.display());
    println!("Output:   {}", OUTPUT_FILE);
    println!();

    if let Err(e) = process_utxo_snapshot(snapshot_path) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    println!();
    println!("Done.");
}
