//! Find original scriptPubKeys for a batch of HASH160 script hashes.
//!
//! Reads target hashes from a binary file (N * 20 bytes), then scans the
//! UTXO snapshot once to find the original scriptPubKey for each.
//! Outputs a JSON array to stdout for embedding in the web client.
//!
//! Usage:
//!   cargo run --release -p bitcoinpir --bin debug_find_scripts_batch -- \
//!     /path/to/utxo.dat /path/to/hashes.bin

use bitcoin::hashes::{ripemd160, sha256, Hash};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use txoutset::Dump;

fn bin2hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <utxo_snapshot> <hashes.bin>", args[0]);
        eprintln!("  hashes.bin: N * 20 bytes of HASH160 targets");
        std::process::exit(1);
    }

    let snapshot_path = Path::new(&args[1]);
    let hashes_path = Path::new(&args[2]);

    // Read target hashes
    let hashes_data = fs::read(hashes_path).expect("read hashes file");
    assert!(hashes_data.len() % 20 == 0, "hashes file must be a multiple of 20 bytes");
    let num_targets = hashes_data.len() / 20;

    let mut targets: HashSet<[u8; 20]> = HashSet::new();
    let mut order: Vec<[u8; 20]> = Vec::with_capacity(num_targets);
    for i in 0..num_targets {
        let mut h = [0u8; 20];
        h.copy_from_slice(&hashes_data[i * 20..(i + 1) * 20]);
        targets.insert(h);
        order.push(h);
    }

    eprintln!("=== Batch Script Finder ===");
    eprintln!("Targets:  {} hashes from {}", num_targets, hashes_path.display());
    eprintln!("Snapshot: {}", snapshot_path.display());

    let dump = Dump::new(snapshot_path, txoutset::ComputeAddresses::No)
        .expect("Failed to open snapshot");

    eprintln!("Block:    {}", dump.block_hash);
    eprintln!("UTXOs:    {}", dump.utxo_set_size);
    eprintln!();

    let total = dump.utxo_set_size;
    let report_interval = std::cmp::max(1, total / 200);
    let mut count: u64 = 0;
    let start = std::time::Instant::now();

    let mut found: HashMap<[u8; 20], String> = HashMap::new();

    for txout in dump {
        count += 1;

        if count % report_interval == 0 {
            let pct = count as f64 / total as f64 * 100.0;
            eprint!("\r  {:.1}% — found {}/{}", pct, found.len(), num_targets);
            io::stderr().flush().ok();
        }

        if found.len() == targets.len() {
            break;
        }

        let script = &txout.script_pubkey;
        let sha = sha256::Hash::hash(script.as_bytes());
        let h160 = ripemd160::Hash::hash(&sha.to_byte_array());
        let h160_arr: [u8; 20] = h160.to_byte_array();

        if targets.contains(&h160_arr) && !found.contains_key(&h160_arr) {
            found.insert(h160_arr, bin2hex(script.as_bytes()));
        }
    }

    let elapsed = start.elapsed();
    eprintln!("\r  Done. Scanned {} entries in {:.1?}, found {}/{}",
        count, elapsed, found.len(), num_targets);
    eprintln!();

    // Output JSON array to stdout (only found entries, preserving order)
    println!("[");
    let mut first = true;
    for h in &order {
        if let Some(spk) = found.get(h) {
            if !first { println!(","); }
            print!("  \"{}\"", spk);
            first = false;
        }
    }
    println!();
    println!("]");

    let not_found = num_targets - found.len();
    if not_found > 0 {
        eprintln!("WARNING: {} hashes not found in snapshot", not_found);
    }
}
