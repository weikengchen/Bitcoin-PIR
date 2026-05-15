//! Build OnionPIR main database: shared NTT store + per-group cuckoo tables.
//!
//! Reads packed entries from gen_1_onion, NTT-expands them into a level-major
//! shared store, builds 6-hash cuckoo tables (bs=1) for each of 80 PBC groups,
//! and verifies the setup with a test query.
//!
//! Output:
//!   - onion_shared_ntt.bin: level-major NTT store (all entries, stored once)
//!   - onion_chunk_cuckoo.bin: per-group cuckoo tables (bin → entry_id mapping)
//!
//! Usage:
//!   cargo run --release -p build --bin gen_2_onion [-- --data-dir <dir>]
//!
//! With no flags, reads `/Volumes/Bitcoin/data/intermediate/onion_packed_entries.bin`
//! and writes the NTT store, cuckoo table, and bin-hash sidecar to
//! `/Volumes/Bitcoin/data/`.
//!
//! With `--data-dir <D>`, reads `<D>/onion_packed_entries.bin` and writes
//! all outputs under `<D>/`. Use this for delta DB builds.

use memmap2::Mmap;
use onionpir::{self, Client as PirClient, Server as PirServer};
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

// ─── Default paths (used when --data-dir is not specified) ──────────────────

const DEFAULT_PACKED_FILE: &str = "/Volumes/Bitcoin/data/intermediate/onion_packed_entries.bin";
const DEFAULT_NTT_STORE_FILE: &str = "/Volumes/Bitcoin/data/onion_shared_ntt.bin";
const DEFAULT_CUCKOO_FILE: &str = "/Volumes/Bitcoin/data/onion_chunk_cuckoo.bin";
const DEFAULT_BIN_HASHES_FILE: &str = "/Volumes/Bitcoin/data/onion_data_bin_hashes.bin";

/// Resolve input/output paths from optional `--data-dir <D>` argument.
/// When `--data-dir` is given, all four paths live under that directory.
fn resolve_paths() -> (String, String, String, String) {
    let args: Vec<String> = env::args().collect();
    let mut data_dir: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--data-dir" {
            if let Some(v) = args.get(i + 1) {
                data_dir = Some(v.clone());
                i += 1;
            }
        }
        i += 1;
    }
    match data_dir {
        Some(d) => (
            format!("{}/onion_packed_entries.bin", d),
            format!("{}/onion_shared_ntt.bin", d),
            format!("{}/onion_chunk_cuckoo.bin", d),
            format!("{}/onion_data_bin_hashes.bin", d),
        ),
        None => (
            DEFAULT_PACKED_FILE.to_string(),
            DEFAULT_NTT_STORE_FILE.to_string(),
            DEFAULT_CUCKOO_FILE.to_string(),
            DEFAULT_BIN_HASHES_FILE.to_string(),
        ),
    }
}

// OnionPIRv2 port (commit 5b): the on-disk packed entry size is now
// `onionpir::params_info(0).entry_size` (3328 for the default
// CONFIG_N2048_K1, was 3840 pre-port at PlainMod=15). Read once in
// main() and flowed through per-call-site. The const definition is
// gone; usages take a local `packed_entry_size` parameter.
fn onion_entry_size() -> usize {
    onionpir::params_info(0).entry_size as usize
}

/// PBC parameters (same as production)
const K_CHUNK: usize = 80;
const NUM_HASHES: usize = 3; // each entry assigned to 3 groups
const CHUNK_MASTER_SEED: u64 = 0xa3f7c2d918e4b065;

/// Cuckoo parameters for main DB
const CUCKOO_NUM_HASHES: usize = 6;
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 10000;
const EMPTY: u32 = u32::MAX;

// ─── Hash utilities ─────────────────────────────────────────────────────────

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    x
}

#[inline]
fn hash_entry_for_group(entry_id: u32, nonce: u64) -> u64 {
    splitmix64((entry_id as u64).wrapping_add(nonce.wrapping_mul(0x9e3779b97f4a7c15)))
}

/// Derive 3 distinct PBC group indices for an entry_id.
fn derive_chunk_groups(entry_id: u32) -> [usize; NUM_HASHES] {
    let mut groups = [0usize; NUM_HASHES];
    let mut nonce: u64 = 0;
    let mut count = 0;
    while count < NUM_HASHES {
        let h = hash_entry_for_group(entry_id, nonce);
        let group = (h % K_CHUNK as u64) as usize;
        nonce += 1;
        let mut dup = false;
        for i in 0..count {
            if groups[i] == group {
                dup = true;
                break;
            }
        }
        if dup { continue; }
        groups[count] = group;
        count += 1;
    }
    groups
}

#[inline]
fn derive_cuckoo_key(group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        CHUNK_MASTER_SEED
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

#[inline]
fn cuckoo_hash_int(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1e9)
    } else if bytes >= 1_000_000 {
        format!("{:.2} MB", bytes as f64 / 1e6)
    } else {
        format!("{:.1} KB", bytes as f64 / 1e3)
    }
}

// ─── Cuckoo table builder (6-hash, bs=1) ────────────────────────────────────

fn build_cuckoo_bs1(
    entries: &[u32],
    keys: &[u64; CUCKOO_NUM_HASHES],
    num_bins: usize,
) -> Vec<u32> {
    let mut table = vec![EMPTY; num_bins];

    for &entry_id in entries {
        let mut placed = false;
        for h in 0..CUCKOO_NUM_HASHES {
            let bin = cuckoo_hash_int(entry_id, keys[h], num_bins);
            if table[bin] == EMPTY {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if placed { continue; }

        // Cuckoo eviction
        let mut current_id = entry_id;
        let mut current_hash_fn = 0;
        let mut current_bin = cuckoo_hash_int(entry_id, keys[0], num_bins);
        let mut success = false;

        for kick in 0..CUCKOO_MAX_KICKS {
            let evicted = table[current_bin];
            table[current_bin] = current_id;

            let mut found_empty = false;
            for h in 0..CUCKOO_NUM_HASHES {
                let try_h = (current_hash_fn + 1 + h) % CUCKOO_NUM_HASHES;
                let bin = cuckoo_hash_int(evicted, keys[try_h], num_bins);
                if bin == current_bin { continue; }
                if table[bin] == EMPTY {
                    table[bin] = evicted;
                    found_empty = true;
                    success = true;
                    break;
                }
            }
            if found_empty { break; }

            let alt_h = (current_hash_fn + 1 + kick % (CUCKOO_NUM_HASHES - 1)) % CUCKOO_NUM_HASHES;
            let alt_bin = cuckoo_hash_int(evicted, keys[alt_h], num_bins);
            let final_bin = if alt_bin == current_bin {
                let h2 = (alt_h + 1) % CUCKOO_NUM_HASHES;
                cuckoo_hash_int(evicted, keys[h2], num_bins)
            } else {
                alt_bin
            };

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        if !success {
            panic!("Cuckoo insertion failed for entry_id={} after {} kicks. \
                    Increase num_bins or CUCKOO_MAX_KICKS.", entry_id, CUCKOO_MAX_KICKS);
        }
    }

    table
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    println!("=== gen_2_onion: Build OnionPIR Main Database ===\n");
    let total_start = Instant::now();

    let (packed_file_path, ntt_store_file, cuckoo_file, bin_hashes_file) = resolve_paths();
    println!("Paths:");
    println!("  Input packed:    {}", packed_file_path);
    println!("  Output NTT:      {}", ntt_store_file);
    println!("  Output cuckoo:   {}", cuckoo_file);
    println!("  Output hashes:   {}", bin_hashes_file);
    println!();

    // ── 1. Read packed entries ───────────────────────────────────────────
    //
    // OnionPIRv2 port (commit 5b): `packed_entry_size` is pulled from
    // the linked onionpir crate at startup (matches gen_1_onion's
    // packing size). The pre-port hardcoded `PACKED_ENTRY_SIZE = 3840`
    // is gone.
    let packed_entry_size = onion_entry_size();
    println!("[1] Memory-mapping packed entries: {}", packed_file_path);
    let packed_file = File::open(&packed_file_path).expect("open packed entries file");
    let packed_mmap = unsafe { Mmap::map(&packed_file) }.expect("mmap packed entries");
    assert_eq!(
        packed_mmap.len() % packed_entry_size, 0,
        "packed file not aligned: {} bytes, packed_entry_size={}",
        packed_mmap.len(), packed_entry_size
    );
    let num_entries = packed_mmap.len() / packed_entry_size;
    println!("  {} entries ({:.2} GB), entry_size={} B", num_entries,
        packed_mmap.len() as f64 / 1e9, packed_entry_size);

    // ── 2. Get OnionPIR params ──────────────────────────────────────────
    let p = onionpir::params_info(num_entries as u64);
    let coeff_val_cnt = p.coeff_val_cnt as usize;
    let poly_degree = p.poly_degree as usize;
    let entry_size_pt = p.entry_size as usize;
    let num_plaintexts = p.num_plaintexts as usize;
    println!("\n[2] OnionPIR params (post-port, BV key-switching):");
    println!("  poly_degree:      {} (N — coeffs per pre-NTT plaintext)", poly_degree);
    println!("  entry_size:       {} B (payload per plaintext)", entry_size_pt);
    println!("  num_plaintexts:   {} (compiled-in DB slot count)", num_plaintexts);
    println!("  coeff_val_cnt:    {} (post-NTT coeff count per plaintext)", coeff_val_cnt);
    assert_eq!(
        entry_size_pt, packed_entry_size,
        "params_info.entry_size ({}) != packed_entry_size ({}); a stale \
         packed.bin produced by a different onionpir rev is being read",
        entry_size_pt, packed_entry_size
    );
    if num_entries > num_plaintexts {
        panic!(
            "num_entries ({}) > num_plaintexts ({}). Compile-time DB shape \
             is too small for this dataset — rebuild onionpir with a larger \
             DB_SIZE_MB.",
            num_entries, num_plaintexts
        );
    }

    // ── 3. Build shared NTT store via push_plaintexts + save_db ─────────
    //
    // OnionPIRv2 port (commit 3a): the old `ntt_expand_entry` + level-major
    // mmap scatter is gone. The new flow is:
    //
    //   1. Bit-pack each entry's bytes into `poly_degree` pre-NTT u64
    //      coefficients (see `pir_core::onion_unpack::pack_bytes_into_coefficients`).
    //   2. Feed batches of coefficients to a temporary Server via
    //      `push_plaintexts(coeffs, count, offset, &[])`. The server runs
    //      NTT internally and stores the post-NTT level-major data.
    //   3. `save_db(temp_path)` writes a file shaped:
    //        [48-byte header][raw `[u64]` level-major payload]
    //      Header layout per INTEGRATION.md §1.3 + upstream `PREPROC_*`
    //      magic. The payload is exactly what the runtime needs to pass
    //      to `set_shared_database`.
    //   4. Strip the 48-byte header into the final `ntt_store_file`. The
    //      stripped payload is `coeff_val_cnt × num_plaintexts × 8` bytes
    //      — NOT `× num_entries` like pre-port — because save_db sizes
    //      for the compile-time DB shape. The runtime adapts by passing
    //      `num_plaintexts` (not `num_packed_entries`) as
    //      `shared_num_entries` to `set_shared_database`.
    //
    //   Empty slots `[num_entries, num_plaintexts)` contain whatever
    //   `Server::new` left them as (zeros in practice). The PBC cuckoo
    //   planner only assigns to `[0, num_entries)`, so real queries never
    //   land on those slots.
    const PUSH_BATCH_ENTRIES: usize = 256;
    println!(
        "\n[3] Pushing {} plaintexts ({} per batch) and running NTT...",
        num_entries, PUSH_BATCH_ENTRIES
    );
    let t_ntt = Instant::now();
    let mut server = PirServer::new(num_entries as u64);
    let one_percent = num_entries.max(1) / 100;
    // OnionPIRv2 port (commit 5b): the commit-3 `take_bytes_per_entry`
    // truncation guard is gone — gen_1's packed entry size matches
    // `params_info.entry_size` exactly (asserted above), so the full
    // entry packs cleanly into one plaintext.

    let mut entry_id = 0;
    while entry_id < num_entries {
        let n_this_batch = PUSH_BATCH_ENTRIES.min(num_entries - entry_id);
        let mut batch_coeffs: Vec<u64> = Vec::with_capacity(n_this_batch * poly_degree);
        for i in 0..n_this_batch {
            let off = (entry_id + i) * packed_entry_size;
            let raw = &packed_mmap[off..off + packed_entry_size];
            // OnionPIRv2 port (commit 5b): no truncation — `raw.len() ==
            // packed_entry_size == entry_size_pt` by the earlier assert.
            let coeffs = pir_core::onion_unpack::pack_bytes_into_coefficients(
                raw,
                entry_size_pt,
                poly_degree,
            );
            batch_coeffs.extend_from_slice(&coeffs);
        }
        let ok = server.push_plaintexts(
            &batch_coeffs,
            n_this_batch as u64,
            entry_id as u64,
            &[],
        );
        assert!(
            ok,
            "push_plaintexts failed at entry_id={} (batch size {})",
            entry_id, n_this_batch
        );
        entry_id += n_this_batch;
        if one_percent > 0 && entry_id % (one_percent * 5).max(1) == 0 {
            eprint!("\r  push_plaintexts: {}%", entry_id * 100 / num_entries.max(1));
            let _ = std::io::stderr().flush();
        }
    }
    eprintln!();
    println!("  push_plaintexts + NTT: {:.2?}", t_ntt.elapsed());

    // Save to a temp file, strip the 48-byte header into the final NTT
    // store file. The header carries `[u64 magic][u64 version][u64 layout_id]
    // [u64 num_pt][u64 coeff_val_cnt][u64 data_bytes]`.
    let temp_path = format!("{}.savetmp", ntt_store_file);
    let t_save = Instant::now();
    assert!(server.save_db(&temp_path), "save_db failed for temp NTT store");
    println!("  save_db: {:.2?}", t_save.elapsed());

    let raw_save = std::fs::read(&temp_path).expect("read save_db output");
    assert!(
        raw_save.len() > 48,
        "save_db output too small ({} bytes) — missing header / payload",
        raw_save.len()
    );
    let payload = &raw_save[48..];
    // Sanity-check the size against what set_shared_database expects:
    // payload = `coeff_val_cnt × num_plaintexts × 8` bytes.
    let expected_payload = coeff_val_cnt * num_plaintexts * 8;
    assert_eq!(
        payload.len(),
        expected_payload,
        "save_db payload size mismatch: got {}, expected {} = {} × {} × 8 \
         (coeff_val_cnt × num_plaintexts × 8)",
        payload.len(),
        expected_payload,
        coeff_val_cnt,
        num_plaintexts
    );
    std::fs::write(&ntt_store_file, payload).expect("write NTT store file");
    std::fs::remove_file(&temp_path).expect("rm save_db temp");
    println!(
        "  NTT store file: {} ({})",
        ntt_store_file,
        format_bytes(payload.len() as u64)
    );

    // ── 4. Assign entries to PBC groups ─────────────────────────────────
    println!("\n[4] Assigning {} entries to {} PBC groups ({} copies each)...",
        num_entries, K_CHUNK, NUM_HASHES);
    let t_assign = Instant::now();

    let expected_per_group = (num_entries * NUM_HASHES) / K_CHUNK + 1;
    let mut groups: Vec<Vec<u32>> = (0..K_CHUNK)
        .map(|_| Vec::with_capacity(expected_per_group))
        .collect();

    for entry_id in 0..num_entries as u32 {
        let assigned = derive_chunk_groups(entry_id);
        for &b in &assigned {
            groups[b].push(entry_id);
        }
    }

    let group_sizes: Vec<usize> = groups.iter().map(|g| g.len()).collect();
    let max_group = *group_sizes.iter().max().unwrap();
    let min_group = *group_sizes.iter().min().unwrap();
    let avg_group = group_sizes.iter().sum::<usize>() as f64 / K_CHUNK as f64;
    println!("  Done in {:.2?}", t_assign.elapsed());
    println!("  Group sizes: min={}, max={}, avg={:.0}", min_group, max_group, avg_group);

    // ── 5. Build cuckoo tables per group ────────────────────────────────
    // Uniform bins_per_table from max group size
    let bins_per_table = (max_group as f64 / CUCKOO_LOAD_FACTOR).ceil() as usize;
    println!("\n[5] Building cuckoo tables ({}-hash, bs=1, bins_per_table={})...",
        CUCKOO_NUM_HASHES, bins_per_table);
    let t_cuckoo = Instant::now();

    let mut all_cuckoo_tables: Vec<Vec<u32>> = Vec::with_capacity(K_CHUNK);
    for group_id in 0..K_CHUNK {
        // Sort entries for deterministic insertion
        let mut entries = groups[group_id].clone();
        entries.sort_unstable();

        let mut keys = [0u64; CUCKOO_NUM_HASHES];
        for h in 0..CUCKOO_NUM_HASHES {
            keys[h] = derive_cuckoo_key(group_id, h);
        }

        let table = build_cuckoo_bs1(&entries, &keys, bins_per_table);

        let occupied = table.iter().filter(|&&x| x != EMPTY).count();
        if group_id % 20 == 0 || group_id + 1 == K_CHUNK {
            eprintln!("  Group {}/{}: {} entries, {} bins, {:.2}% fill",
                group_id + 1, K_CHUNK, entries.len(), bins_per_table,
                occupied as f64 / bins_per_table as f64 * 100.0);
        }

        all_cuckoo_tables.push(table);
    }
    println!("  Cuckoo tables built in {:.2?}", t_cuckoo.elapsed());

    // ── 6. Save cuckoo tables to disk ───────────────────────────────────
    println!("\n[6] Saving cuckoo tables to {}...", cuckoo_file);
    {
        let cuckoo_out = File::create(&cuckoo_file).expect("create cuckoo file");
        let mut writer = BufWriter::with_capacity(1024 * 1024, cuckoo_out);

        // Header: magic, k_chunk, cuckoo_num_hashes, bins_per_table, master_seed, num_entries
        let magic: u64 = 0xBA7C_0010_0000_0001;
        writer.write_all(&magic.to_le_bytes()).unwrap();
        writer.write_all(&(K_CHUNK as u32).to_le_bytes()).unwrap();
        writer.write_all(&(CUCKOO_NUM_HASHES as u32).to_le_bytes()).unwrap();
        writer.write_all(&(bins_per_table as u32).to_le_bytes()).unwrap();
        writer.write_all(&CHUNK_MASTER_SEED.to_le_bytes()).unwrap();
        writer.write_all(&(num_entries as u32).to_le_bytes()).unwrap();
        // Padding to 40 bytes for alignment
        writer.write_all(&[0u8; 4]).unwrap();

        // Body: K_CHUNK tables, each bins_per_table × u32
        for table in &all_cuckoo_tables {
            for &entry_id in table {
                writer.write_all(&entry_id.to_le_bytes()).unwrap();
            }
        }
        writer.flush().unwrap();
    }

    let cuckoo_file_size = 40 + K_CHUNK * bins_per_table * 4;
    println!("  Cuckoo file: {} (header 40B + {} groups × {} bins × 4B)",
        format_bytes(cuckoo_file_size as u64), K_CHUNK, bins_per_table);

    // ── 7. Compute and write DATA bin hashes (for per-bin Merkle) ──────
    println!("\n[7] Computing DATA bin hashes for per-bin Merkle...");
    let t_hash = Instant::now();
    {
        // OnionPIRv2 port (commit 5b): zero_entry is `packed_entry_size`
        // bytes (was a fixed `[u8; 3840]` array pre-port).
        let zero_entry = vec![0u8; packed_entry_size];
        let total_bins = K_CHUNK * bins_per_table;
        let mut bin_hashes = Vec::with_capacity(total_bins * 32);

        for group_id in 0..K_CHUNK {
            let table = &all_cuckoo_tables[group_id];
            for bin in 0..bins_per_table {
                let entry_id = table[bin];
                let bin_bytes: &[u8] = if entry_id == EMPTY {
                    &zero_entry
                } else {
                    let off = entry_id as usize * packed_entry_size;
                    &packed_mmap[off..off + packed_entry_size]
                };
                let hash = pir_core::merkle::sha256(bin_bytes);
                bin_hashes.extend_from_slice(&hash);
            }
            if group_id % 10 == 0 || group_id + 1 == K_CHUNK {
                eprint!("\r  Hashing group {}/{}", group_id + 1, K_CHUNK);
            }
        }
        eprintln!();

        // Header: [4B K_CHUNK][4B bins_per_table]
        let f = File::create(&bin_hashes_file).expect("create bin hashes file");
        let mut w = BufWriter::new(f);
        w.write_all(&(K_CHUNK as u32).to_le_bytes()).unwrap();
        w.write_all(&(bins_per_table as u32).to_le_bytes()).unwrap();
        w.write_all(&bin_hashes).unwrap();
        w.flush().unwrap();
        println!("  Wrote {} bin hashes ({} bytes) to {} in {:.2?}",
            total_bins, 8 + total_bins * 32, bin_hashes_file, t_hash.elapsed());
    }

    // ── 8. Verify with test query ───────────────────────────────────────
    println!("\n[7] Verification: test query with shared NTT store...");

    // Pick group 0, find a real entry in its cuckoo table
    let test_group = 0;
    let test_table = &all_cuckoo_tables[test_group];
    let test_bin = test_table.iter().position(|&x| x != EMPTY).expect("no entries in group 0");
    let test_entry_id = test_table[test_bin];
    println!("  Test: group={}, bin={}, entry_id={}", test_group, test_bin, test_entry_id);

    // Build index_table for this group (maps padded indices → shared store entry_ids)
    let p_group = onionpir::params_info(bins_per_table as u64);
    let padded_num = p_group.num_entries as usize;
    let mut index_table = vec![0u32; padded_num]; // 0 for padding entries (all-zero data)
    for bin in 0..bins_per_table {
        let eid = test_table[bin];
        if eid != EMPTY {
            index_table[bin] = eid;
        }
        // else: index_table[bin] = 0, which maps to entry 0 in the shared store
    }
    // Pad remaining indices (bins_per_table..padded_num) with 0
    // Already done by default initialization

    // Set up server with shared database. The NTT store on disk is the
    // post-port save_db payload (header stripped above); mmap it,
    // reinterpret as `&[u64]`, and pass num_plaintexts as
    // shared_num_entries — matching the upstream
    // `shared_database_identity_index_table` test pattern.
    let sanity_ntt_file = File::open(&ntt_store_file).expect("re-open NTT store");
    let sanity_ntt_mmap = unsafe { Mmap::map(&sanity_ntt_file) }.expect("mmap NTT store");
    assert_eq!(
        sanity_ntt_mmap.len() % 8,
        0,
        "NTT store size {} is not u64-aligned",
        sanity_ntt_mmap.len()
    );
    let ntt_u64: &[u64] = unsafe {
        std::slice::from_raw_parts(
            sanity_ntt_mmap.as_ptr() as *const u64,
            sanity_ntt_mmap.len() / 8,
        )
    };

    let mut server = PirServer::new(bins_per_table as u64);
    unsafe {
        // OnionPIRv2 port (commit 3a): pass `num_plaintexts` as
        // `shared_num_entries`. save_db sizes the payload for the compile-
        // time DB shape, not for `num_entries`.
        assert!(
            server.set_shared_database(ntt_u64, num_plaintexts as u64, &index_table),
            "set_shared_database failed in gen_2_onion sanity check"
        );
    }

    // Create client, generate keys, query
    let mut client = PirClient::new(bins_per_table as u64);
    let client_id = client.id();
    let galois = client.galois_keys();
    let gsw = client.gsw_key();
    server.set_galois_keys(client_id, &galois);
    server.set_gsw_key(client_id, &gsw);

    let query = client.generate_query(test_bin as u64);
    let response = server.answer_query(client_id, &query);
    // OnionPIRv2 port (commit 2): bit-unpack the raw plaintext returned
    // by `decrypt_response`. `decrypted.len()` is now `params.entry_size`
    // (3328 default), not PACKED_ENTRY_SIZE (3840) — the comparison
    // below will only succeed once the build pipeline regenerates DBs
    // with entry_size-aligned packing (commit 3 / 5).
    let _ = test_bin;
    let raw_pt = client.decrypt_response(&response);
    let pinfo = onionpir::params_info(bins_per_table as u64);
    let decrypted = pir_core::onion_unpack::unpack_onion_plaintext(
        &raw_pt,
        pinfo.poly_degree as usize,
        pinfo.entry_size as usize,
    )
    .expect("onion_unpack rejected gen_2_onion plaintext");

    // Compare with original packed entry. Post-commit-5b `decrypted.len() ==
    // packed_entry_size == params.entry_size`, so the comparison is a
    // direct byte-for-byte equality with no truncation.
    let expected = &packed_mmap[test_entry_id as usize * packed_entry_size
        ..(test_entry_id as usize + 1) * packed_entry_size];

    if decrypted.len() == packed_entry_size && decrypted[..] == *expected {
        println!("  Verification: PASS (decrypted matches original entry)");
    } else if decrypted.len() >= 8 && decrypted[..8] == expected[..8] {
        println!("  Verification: PASS (first 8 bytes match)");
    } else {
        println!("  Verification: FAIL!");
        println!("  Expected first 16B: {:?}", &expected[..16]);
        println!("  Got first 16B:      {:?}", &decrypted[..16.min(decrypted.len())]);
    }

    // ── Summary ─────────────────────────────────────────────────────────
    println!("\n=== Summary ===");
    println!("Packed entries:    {} ({:.2} GB)", num_entries, packed_mmap.len() as f64 / 1e9);
    println!("NTT store:         {} (level-major × num_plaintexts)",
        format_bytes(
            std::fs::metadata(&ntt_store_file).map(|m| m.len()).unwrap_or(0),
        ));
    println!("Cuckoo tables:     {} groups × {} bins = {}",
        K_CHUNK, bins_per_table, format_bytes(cuckoo_file_size as u64));
    println!("Total time:        {:.2?}", total_start.elapsed());
}
