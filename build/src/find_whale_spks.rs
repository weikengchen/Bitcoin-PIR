//! Find scriptPubKeys for whale addresses by scanning the UTXO snapshot.
//!
//! Usage: cargo run --release -p build --bin find_whale_spks

use bitcoin::hashes::{ripemd160, sha256, Hash};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use txoutset::Dump;

const SNAPSHOT_FILE: &str = "/Volumes/Bitcoin/data/archive/txoutset.dat";
const WHALE_FILE: &str = "/Volumes/Bitcoin/data/intermediate/whale_addresses.txt";

fn main() {
    println!("=== Find Whale ScriptPubKeys ===");
    let start = Instant::now();

    // Load target whale hashes (just top 10)
    let mut targets: HashSet<[u8; 20]> = HashSet::new();
    let whale_data = std::fs::read_to_string(WHALE_FILE).expect("read whale file");
    for line in whale_data.lines() {
        if line.starts_with('#') { continue; }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let mut h = [0u8; 20];
            for j in 0..20 {
                h[j] = u8::from_str_radix(&parts[0][j*2..j*2+2], 16).unwrap();
            }
            targets.insert(h);
            if targets.len() >= 10 {
                break;
            }
        }
    }
    println!("  Looking for {} whale hashes", targets.len());

    // Scan snapshot
    let dump = Dump::new(SNAPSHOT_FILE, txoutset::ComputeAddresses::No)
        .expect("open snapshot");

    let mut found: HashMap<[u8; 20], String> = HashMap::new();
    let mut count = 0u64;

    for txout in dump {
        count += 1;
        if count.is_multiple_of(20_000_000) {
            eprintln!("  Scanned {}M entries, found {}/{}...",
                count / 1_000_000, found.len(), targets.len());
        }

        let script = txout.script_pubkey;
        let script_bytes = script.as_bytes();

        let sha = sha256::Hash::hash(script_bytes);
        let h160 = ripemd160::Hash::hash(sha.as_ref());
        let mut h = [0u8; 20];
        h.copy_from_slice(h160.as_ref());

        if targets.contains(&h) && !found.contains_key(&h) {
            let spk_hex: String = script_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            let h_hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
            println!("  FOUND: hash={} spk_len={} spk={:.120}{}",
                h_hex, script_bytes.len(), spk_hex,
                if spk_hex.len() > 120 { "..." } else { "" });
            found.insert(h, spk_hex);
            if found.len() == targets.len() {
                break;
            }
        }
    }

    println!();
    println!("=== Results ({}/{} found) ===", found.len(), targets.len());

    // Re-read whale file to get counts
    let mut whale_counts: HashMap<String, String> = HashMap::new();
    for line in whale_data.lines() {
        if line.starts_with('#') { continue; }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            whale_counts.insert(parts[0].to_string(), parts[1].to_string());
        }
    }

    for (h, spk) in &found {
        let h_hex: String = h.iter().map(|b| format!("{:02x}", b)).collect();
        let count = whale_counts.get(&h_hex).map(|s| s.as_str()).unwrap_or("?");
        println!("  hash={} utxos={} spk={}", h_hex, count, spk);
    }

    println!();
    println!("  Total time: {:.2?}", start.elapsed());
}
