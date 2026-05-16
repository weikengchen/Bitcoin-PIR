//! Compute a scripthash-grouped UTXO delta between heights A and B.
//!
//! 1. Loads a dumptxoutset at height A to build a (txid, vout) → scripthash lookup.
//! 2. Replays blocks A+1..=B using brk_reader to compute MINUS/PLUS sets.
//! 3. Groups both sets by scripthash and writes a grouped delta file.
//!
//! Output format (`delta_grouped_<A>_<B>.bin`):
//!   [4B num_scripthashes LE]
//!   Per scripthash:
//!     [20B scripthash]
//!     [varint num_spent]
//!       per spent: [32B txid][varint vout]
//!     [varint num_new]
//!       per new: [32B txid][varint vout][varint amount]
//!
//! Usage:
//!   delta_gen_0 <dumptxoutset_file> <bitcoin_datadir> <start_height> <end_height>

use bitcoin::hashes::{ripemd160, sha256, Hash};
use brk_reader::Reader;
use brk_rpc::{Auth, Client};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;
use txoutset::Dump;

const OUTPUT_DIR: &str = "/Volumes/Bitcoin/data/intermediate";
const DUST_THRESHOLD: u64 = 576;

/// Write a LEB128 varint to a BufWriter.
fn write_varint<W: Write>(w: &mut W, mut value: u64) -> io::Result<()> {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        w.write_all(&[byte])?;
        if value == 0 {
            break;
        }
    }
    Ok(())
}

fn format_duration(secs: f64) -> String {
    if secs < 60.0 {
        format!("{:.1}s", secs)
    } else if secs < 3600.0 {
        format!("{}m {}s", secs as u64 / 60, secs as u64 % 60)
    } else {
        format!("{}h {}m", secs as u64 / 3600, (secs as u64 % 3600) / 60)
    }
}

/// Spent UTXO reference (no amount needed for delta).
struct SpentRef {
    txid: [u8; 32],
    vout: u32,
}

/// New UTXO (still unspent at height B).
struct NewUtxo {
    txid: [u8; 32],
    vout: u32,
    amount: u64,
}

/// Per-scripthash delta accumulator.
#[derive(Default)]
struct ScriptDelta {
    spent: Vec<SpentRef>,
    new_utxos: Vec<NewUtxo>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: {} <dumptxoutset_file> <bitcoin_datadir> <start_height> <end_height>", args[0]);
        eprintln!("Example: {} /path/to/utxo.dat /Volumes/Bitcoin/bitcoin 938612 940612", args[0]);
        std::process::exit(1);
    }

    let snapshot_path = PathBuf::from(&args[1]);
    let bitcoin_dir = PathBuf::from(&args[2]);
    let start_height: u64 = args[3].parse().expect("start_height must be a number");
    let end_height: u64 = args[4].parse().expect("end_height must be a number");

    assert!(start_height < end_height, "start_height must be < end_height");

    // ── Step 1: Load dumptxoutset@A into (txid, vout) → scripthash map ──────

    println!("=== Delta Gen 0: Compute Grouped Delta ===");
    println!("Snapshot:     {}", snapshot_path.display());
    println!("Bitcoin dir:  {}", bitcoin_dir.display());
    println!("Range:        {} → {} ({} blocks)", start_height, end_height, end_height - start_height);
    println!();

    println!("[1] Loading dumptxoutset into memory...");
    let t = Instant::now();

    let dump = Dump::new(&snapshot_path, txoutset::ComputeAddresses::No)
        .expect("Failed to open UTXO snapshot");
    println!("    Block hash: {}", dump.block_hash);
    println!("    UTXO set size: {}", dump.utxo_set_size);

    // Map: (txid_bytes, vout) → scripthash
    // This takes ~10-15 GB RAM for ~180M UTXOs.
    let mut utxo_map: HashMap<([u8; 32], u32), [u8; 20]> = HashMap::with_capacity(dump.utxo_set_size as usize);
    let mut loaded: u64 = 0;
    let total = dump.utxo_set_size;

    for txout in dump {
        let txid_bytes = txout.out_point.txid.to_byte_array();
        let vout = txout.out_point.vout;
        let script = txout.script_pubkey;

        // Compute HASH160 = RIPEMD160(SHA256(scriptPubKey))
        let sha256_hash = sha256::Hash::hash(script.as_bytes());
        let hash160 = ripemd160::Hash::hash(&sha256_hash.to_byte_array());
        let script_hash: [u8; 20] = hash160.to_byte_array();

        utxo_map.insert((txid_bytes, vout), script_hash);

        loaded += 1;
        if loaded.is_multiple_of(5_000_000) {
            let pct = 100.0 * loaded as f64 / total as f64;
            let elapsed = t.elapsed().as_secs_f64();
            let eta = elapsed / (loaded as f64 / total as f64) - elapsed;
            print!("\r    Loaded {}/{} ({:.1}%) | ETA: {}   ",
                loaded, total, pct, format_duration(eta));
            io::stdout().flush().ok();
        }
    }

    println!("\r    Loaded {} UTXOs in {}                              ",
        loaded, format_duration(t.elapsed().as_secs_f64()));
    println!("    Map memory: ~{:.1} GB (estimated)",
        (utxo_map.len() as f64 * (32.0 + 4.0 + 20.0 + 40.0)) / 1e9); // key+value+overhead

    // ── Step 2: Replay blocks, compute per-scripthash delta ─────────────────

    println!();
    println!("[2] Replaying blocks {} → {} ...", start_height + 1, end_height);

    let blocks_dir = bitcoin_dir.join("blocks");
    assert!(blocks_dir.exists(), "blocks directory not found: {:?}", blocks_dir);

    let cookie_path = bitcoin_dir.join(".cookie");
    assert!(cookie_path.exists(), "Cookie file not found: {:?}", cookie_path);

    let client = Client::new("http://127.0.0.1:8332", Auth::CookieFile(cookie_path))
        .expect("Failed to create RPC client");

    let reader = Reader::new(blocks_dir, &client);
    let receiver = reader.read(
        Some(((start_height + 1) as u32).into()), // start replaying AFTER height A
        Some(((end_height + 1) as u32).into()),    // exclusive end
    );

    // Track new outputs created in range (may be spent within range)
    let mut in_range_created: HashMap<([u8; 32], u32), ([u8; 20], u64)> = HashMap::new();

    // Per-scripthash delta
    let mut deltas: HashMap<[u8; 20], ScriptDelta> = HashMap::new();

    let t2 = Instant::now();
    let num_blocks = end_height - start_height;
    let mut blocks_done: u64 = 0;
    let mut total_inputs: u64 = 0;
    let mut total_outputs: u64 = 0;
    let mut created_and_consumed: u64 = 0;
    let mut unknown_spends: u64 = 0;
    let mut last_print = Instant::now();

    for block in receiver.iter() {
        for tx in &block.txdata {
            if !tx.is_coinbase() {
                for input in &tx.input {
                    total_inputs += 1;
                    let prev = &input.previous_output;
                    let key = (prev.txid.to_byte_array(), prev.vout);

                    if let Some((_sh, _amt)) = in_range_created.remove(&key) {
                        // Created and consumed within range — exclude
                        created_and_consumed += 1;
                    } else if let Some(script_hash) = utxo_map.get(&key) {
                        // Pre-range UTXO spent → MINUS
                        let delta = deltas.entry(*script_hash).or_default();
                        delta.spent.push(SpentRef {
                            txid: key.0,
                            vout: key.1,
                        });
                    } else {
                        // Unknown spend — the UTXO wasn't in our snapshot.
                        // This can happen if the snapshot height doesn't match start_height.
                        unknown_spends += 1;
                    }
                }
            }

            let txid = tx.compute_txid();
            let txid_bytes = txid.to_byte_array();
            for (vout, output) in tx.output.iter().enumerate() {
                total_outputs += 1;
                let amount = output.value.to_sat();

                // Compute scripthash for the new output
                let sha256_hash = sha256::Hash::hash(output.script_pubkey.as_bytes());
                let hash160 = ripemd160::Hash::hash(&sha256_hash.to_byte_array());
                let script_hash: [u8; 20] = hash160.to_byte_array();

                in_range_created.insert(
                    (txid_bytes, vout as u32),
                    (script_hash, amount),
                );
            }
        }

        blocks_done += 1;
        if last_print.elapsed().as_millis() >= 500 || blocks_done == num_blocks {
            let elapsed = t2.elapsed().as_secs_f64();
            let rate = blocks_done as f64 / elapsed;
            let eta = if rate > 0.0 { (num_blocks - blocks_done) as f64 / rate } else { 0.0 };
            print!("\r    {}/{} blocks ({:.1}%) | {:.0} blk/s | ETA {:.0}s | scripts: {}   ",
                blocks_done, num_blocks,
                100.0 * blocks_done as f64 / num_blocks as f64,
                rate, eta, deltas.len());
            io::stdout().flush().ok();
            last_print = Instant::now();
        }
    }

    // Remaining in_range_created are PLUS (new UTXOs still unspent at B)
    let plus_before_dust = in_range_created.len();
    for ((txid_bytes, vout), (script_hash, amount)) in in_range_created.drain() {
        if amount <= DUST_THRESHOLD {
            continue;
        }
        let delta = deltas.entry(script_hash).or_default();
        delta.new_utxos.push(NewUtxo { txid: txid_bytes, vout, amount });
    }

    let dust_filtered = plus_before_dust - deltas.values().map(|d| d.new_utxos.len()).sum::<usize>();

    println!("\r    Processed {} blocks in {}                                                  ",
        blocks_done, format_duration(t2.elapsed().as_secs_f64()));
    println!();

    // ── Summary ─────────────────────────────────────────────────────────────

    let total_spent: usize = deltas.values().map(|d| d.spent.len()).sum();
    let total_new: usize = deltas.values().map(|d| d.new_utxos.len()).sum();

    println!("=== Summary ===");
    println!("Inputs consumed:        {}", total_inputs);
    println!("Outputs created:        {}", total_outputs);
    println!("Created & consumed:     {}", created_and_consumed);
    println!("Unknown spends:         {}", unknown_spends);
    println!("Dust filtered (PLUS):   {}", dust_filtered);
    println!();
    println!("Unique scripthashes:    {}", deltas.len());
    println!("Total MINUS entries:    {}", total_spent);
    println!("Total PLUS entries:     {}", total_new);
    println!();

    // ── Step 3: Write grouped delta file ────────────────────────────────────

    let output_path = format!("{}/delta_grouped_{}_{}.bin", OUTPUT_DIR, start_height, end_height);
    println!("[3] Writing grouped delta to {} ...", output_path);

    let f = File::create(&output_path).expect("create delta file");
    let mut w = BufWriter::with_capacity(4 * 1024 * 1024, f);

    // Header: number of scripthashes
    let num_scripts = deltas.len() as u32;
    w.write_all(&num_scripts.to_le_bytes()).unwrap();

    for (script_hash, delta) in &deltas {
        // Write scripthash
        w.write_all(script_hash).unwrap();

        // Write spent entries
        write_varint(&mut w, delta.spent.len() as u64).unwrap();
        for s in &delta.spent {
            w.write_all(&s.txid).unwrap();
            write_varint(&mut w, s.vout as u64).unwrap();
        }

        // Write new UTXO entries
        write_varint(&mut w, delta.new_utxos.len() as u64).unwrap();
        for n in &delta.new_utxos {
            w.write_all(&n.txid).unwrap();
            write_varint(&mut w, n.vout as u64).unwrap();
            write_varint(&mut w, n.amount).unwrap();
        }
    }

    w.flush().unwrap();

    let file_size = std::fs::metadata(&output_path).map(|m| m.len()).unwrap_or(0);
    println!("    Written: {} scripthashes, {:.2} MB", num_scripts, file_size as f64 / 1e6);
    println!();
    println!("Done. Total time: {}", format_duration(t.elapsed().as_secs_f64()));
}
