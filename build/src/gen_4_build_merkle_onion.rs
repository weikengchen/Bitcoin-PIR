//! Build per-bin Merkle trees for OnionPIR: INDEX-MERKLE and DATA-MERKLE.
//!
//! Each leaf = SHA256(one 3.75KB bin). The client already fetches the full bin
//! during each PIR round, so leaf verification is free — just hash what you have.
//!
//! Two separate trees:
//!   INDEX-MERKLE: leaves = SHA256(each INDEX cuckoo bin across all K groups)
//!   DATA-MERKLE:  leaves = SHA256(each DATA/chunk bin across all K_CHUNK groups)
//!
//! Sibling tables: 6-hash cuckoo bs=1, shared NTT store per level (same as gen_2_onion).
//!
//! Output files (per tree, prefix = "index" or "data"):
//!   merkle_onion_{prefix}_sib_L{N}_ntt.bin    — shared NTT store per sibling level
//!   merkle_onion_{prefix}_sib_L{N}_cuckoo.bin — 6-hash cuckoo tables per sibling level
//!   merkle_onion_{prefix}_sib_L{N}_packed.bin — raw packed 3840B entries (for verification)
//!   merkle_onion_{prefix}_tree_top.bin        — tree-top cache
//!   merkle_onion_{prefix}_root.bin            — root hash
//!
//! Usage: gen_4_build_merkle_onion [--data-dir <dir>]

mod merkle_builder;

use memmap2::MmapMut;
use merkle_builder::{
    compute_next_level, parse_data_dir, write_tree_top_cache,
    TREE_TOP_GROUP_THRESHOLD_PUB as TREE_TOP_GROUP_THRESHOLD,
};
use onionpir::{self, Server as PirServer};
use pir_core::merkle::{Hash256, ZERO_HASH};
use std::fs::{File, OpenOptions};
use std::io::Write as IoWrite;
use std::io::{BufWriter, Write};
use std::time::Instant;

// OnionPIRv2 port (commit 5b): the Merkle fan-out is `entry_size / 32`
// — pinned to the OnionPIR plaintext size so each internal node's
// ARITY child hashes (32 bytes each) fit in exactly one plaintext.
//
//   CONFIG_N2048_K1 (default post-port): entry_size=3328 → ARITY=104
//   pre-port (PlainMod=15):                 entry_size=3840 → ARITY=120
//
// The tree depth, sibling-proof shape, and tree-top cache layout all
// flow from ARITY, so changing the linked onionpir rev re-shapes
// every tree. The runtime publishes ARITY back to the client via the
// metadata file (see `write_tree_top_cache`'s `arity` field).
fn onion_merkle_arity() -> usize {
    onionpir::params_info(0).entry_size as usize / 32
}

fn onion_merkle_packed_entry_size() -> usize {
    onion_merkle_arity() * 32
}

// ─── Adaptive K for PBC groups ──────────────────────────────────────────────

fn adaptive_k(num_groups: usize) -> usize {
    if num_groups >= 100_000 { 75 }
    else if num_groups >= 1_000 { 25 }
    else { (num_groups / 10).max(5) }
}

// ─── Hash utilities (same as gen_2_onion) ───────────────────────────────────

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

/// Derive 3 distinct PBC group indices for an entry_id, with given K.
fn derive_pbc_groups(entry_id: u32, k: usize) -> [usize; 3] {
    let mut groups = [0usize; 3];
    let mut nonce: u64 = 0;
    let mut count = 0;
    while count < 3 {
        let h = hash_entry_for_group(entry_id, nonce);
        let group = (h % k as u64) as usize;
        nonce += 1;
        let mut dup = false;
        for i in 0..count {
            if groups[i] == group { dup = true; break; }
        }
        if dup { continue; }
        groups[count] = group;
        count += 1;
    }
    groups
}

/// Per-level cuckoo master seed (distinct per level to avoid collisions).
/// Offset by 0x100 for INDEX-MERKLE sibling levels, 0x200 for DATA-MERKLE,
/// to avoid collision with the old per-entry Merkle seeds.
fn level_master_seed(tree_kind: &str, level: usize) -> u64 {
    let base = match tree_kind {
        "index" => 0xBA7C_51B1_FEED_0100u64,
        "data"  => 0xBA7C_51B1_FEED_0200u64,
        _ => panic!("unknown tree_kind: {}", tree_kind),
    };
    base.wrapping_add(level as u64)
}

#[inline]
fn derive_cuckoo_key(master_seed: u64, group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        master_seed
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

#[inline]
fn cuckoo_hash_int(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

const CUCKOO_NUM_HASHES: usize = 6;
const CUCKOO_LOAD_FACTOR: f64 = 0.95;
const CUCKOO_MAX_KICKS: usize = 10000;
const EMPTY: u32 = u32::MAX;

// ─── 6-hash cuckoo builder (bs=1, same as gen_2_onion) ─────────────────────

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
            panic!("Cuckoo insertion failed for entry_id={} after {} kicks", entry_id, CUCKOO_MAX_KICKS);
        }
    }
    table
}

// ─── Read bin hashes from sidecar file ─────────────────────────────────────

/// Read bin hashes written by gen_2/gen_3.
/// File format: [4B K LE][4B bins_per_table LE][K * bins_per_table * 32B hashes]
fn read_bin_hashes(path: &str) -> (usize, usize, Vec<Hash256>) {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    assert!(data.len() >= 8, "{} too short", path);
    let k = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let bins_per_table = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let total_bins = k * bins_per_table;
    assert_eq!(data.len(), 8 + total_bins * 32, "{} size mismatch: expected {} got {}",
        path, 8 + total_bins * 32, data.len());

    let mut hashes = Vec::with_capacity(total_bins);
    for i in 0..total_bins {
        let off = 8 + i * 32;
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[off..off + 32]);
        hashes.push(h);
    }

    (k, bins_per_table, hashes)
}

// ─── Build OnionPIR sibling database for one level ──────────────────────────

fn build_sibling_level(
    level_nodes: &[Hash256],
    level: usize,
    tree_kind: &str,
    data_dir: &str,
) {
    let arity = onion_merkle_arity();
    let packed_entry_size = onion_merkle_packed_entry_size();

    let t = Instant::now();
    let nodes_at_level = level_nodes.len();
    let num_groups = (nodes_at_level + arity - 1) / arity;
    let k = adaptive_k(num_groups);
    let master_seed = level_master_seed(tree_kind, level);

    println!("    L{}: {} nodes, {} groups, K={}", level, nodes_at_level, num_groups, k);

    // ── 1. Pack groups as `packed_entry_size`-byte entries ──────────────────

    let packed_path = format!("{}/merkle_onion_{}_sib_L{}_packed.bin", data_dir, tree_kind, level);
    {
        let f = File::create(&packed_path).expect("create packed file");
        let mut w = BufWriter::with_capacity(16 * 1024 * 1024, f);
        for group_id in 0..num_groups {
            let first = group_id * arity;
            for c in 0..arity {
                let idx = first + c;
                if idx < level_nodes.len() {
                    w.write_all(&level_nodes[idx]).unwrap();
                } else {
                    w.write_all(&ZERO_HASH).unwrap();
                }
            }
        }
        w.flush().unwrap();
    }
    let packed_size = num_groups * packed_entry_size;
    println!("      Packed: {} entries × {}B = {:.1} MB",
        num_groups, packed_entry_size, packed_size as f64 / 1e6);

    // ── 2. NTT expansion → shared NTT store ────────────────────────────────
    //
    // OnionPIRv2 port (commit 3c): mirrors gen_2_onion's push_plaintexts +
    // save_db pattern. Build a temporary Server, push all entries via
    // `push_plaintexts` (NTT runs internally), `save_db` to a temp file,
    // strip the 48-byte header into the final ntt_path. The runtime
    // mmaps ntt_path, reinterprets as `&[u64]`, and passes
    // `num_plaintexts` (not `num_groups`) as `shared_num_entries` to
    // `set_shared_database`.

    let p = onionpir::params_info(num_groups as u64);
    let poly_degree = p.poly_degree as usize;
    let entry_size_pt = p.entry_size as usize;
    let num_plaintexts = p.num_plaintexts as usize;

    let ntt_path = format!("{}/merkle_onion_{}_sib_L{}_ntt.bin", data_dir, tree_kind, level);
    let temp_ntt_path = format!("{}.savetmp", ntt_path);

    // Mmap the packed file for reading
    let packed_file = File::open(&packed_path).expect("open packed");
    let packed_mmap = unsafe { memmap2::Mmap::map(&packed_file) }.expect("mmap packed");

    if num_groups > num_plaintexts {
        panic!(
            "num_groups ({}) > num_plaintexts ({}). Compile-time OnionPIR DB \
             shape too small — rebuild with larger DB_SIZE_MB.",
            num_groups, num_plaintexts
        );
    }

    // OnionPIRv2 port (commit 5b): ARITY is now pinned to
    // `entry_size_pt / 32`, so each packed Merkle entry is exactly
    // `entry_size_pt` bytes — the commit-3 truncation guard is now
    // a no-op and is removed.
    assert_eq!(
        packed_entry_size, entry_size_pt,
        "onion_merkle_packed_entry_size ({}) drifted from \
         params_info.entry_size ({}); a stale onionpir crate is linked",
        packed_entry_size, entry_size_pt
    );

    const PUSH_BATCH_ENTRIES: usize = 256;
    let mut server = PirServer::new(num_groups as u64);
    let one_pct = num_groups.max(1) / 100;
    let mut entry_id = 0usize;
    let t_push = Instant::now();
    while entry_id < num_groups {
        let n_this_batch = PUSH_BATCH_ENTRIES.min(num_groups - entry_id);
        let mut batch_coeffs: Vec<u64> = Vec::with_capacity(n_this_batch * poly_degree);
        for i in 0..n_this_batch {
            let off = (entry_id + i) * packed_entry_size;
            let raw = &packed_mmap[off..off + packed_entry_size];
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
        if one_pct > 0 && entry_id % (one_pct * 5).max(1) == 0 {
            eprint!("\r      NTT: {}%", entry_id * 100 / num_groups.max(1));
        }
    }
    eprintln!();
    assert!(
        server.save_db(&temp_ntt_path),
        "save_db failed for Merkle level {} → {}",
        level,
        temp_ntt_path
    );

    let raw_save = std::fs::read(&temp_ntt_path).expect("read save_db output");
    assert!(
        raw_save.len() > 48,
        "save_db output too small ({} bytes)",
        raw_save.len()
    );
    let payload = &raw_save[48..];
    std::fs::write(&ntt_path, payload).expect("write NTT store");
    std::fs::remove_file(&temp_ntt_path).expect("rm temp");
    println!(
        "      NTT store: {} ({:.1} GB) in {:.2?}",
        ntt_path,
        payload.len() as f64 / 1e9,
        t_push.elapsed()
    );

    // ── 3. Assign entries to PBC groups ────────────────────────────────────

    let expected_per_group = (num_groups * 3) / k + 1;
    let mut groups: Vec<Vec<u32>> = (0..k).map(|_| Vec::with_capacity(expected_per_group)).collect();
    for entry_id in 0..num_groups as u32 {
        let assigned = derive_pbc_groups(entry_id, k);
        for &b in &assigned {
            groups[b].push(entry_id);
        }
    }

    let max_group = groups.iter().map(|g| g.len()).max().unwrap_or(0);
    let bins_per_table = (max_group as f64 / CUCKOO_LOAD_FACTOR).ceil() as usize;
    println!("      PBC: K={}, max_group={}, bins_per_table={}", k, max_group, bins_per_table);

    // ── 4. Build 6-hash cuckoo tables ──────────────────────────────────────

    let mut all_tables: Vec<Vec<u32>> = Vec::with_capacity(k);
    for group_id in 0..k {
        let mut entries = groups[group_id].clone();
        entries.sort_unstable();

        let mut keys = [0u64; CUCKOO_NUM_HASHES];
        for h in 0..CUCKOO_NUM_HASHES {
            keys[h] = derive_cuckoo_key(master_seed, group_id, h);
        }

        let table = build_cuckoo_bs1(&entries, &keys, bins_per_table);
        all_tables.push(table);
    }

    // ── 5. Write cuckoo file ───────────────────────────────────────────────

    let cuckoo_path = format!("{}/merkle_onion_{}_sib_L{}_cuckoo.bin", data_dir, tree_kind, level);
    {
        let f = File::create(&cuckoo_path).expect("create cuckoo file");
        let mut w = BufWriter::with_capacity(1024 * 1024, f);

        // Header (36 bytes, same as gen_2_onion)
        let magic: u64 = master_seed;
        w.write_all(&magic.to_le_bytes()).unwrap();
        w.write_all(&(k as u32).to_le_bytes()).unwrap();
        w.write_all(&(CUCKOO_NUM_HASHES as u32).to_le_bytes()).unwrap();
        w.write_all(&(bins_per_table as u32).to_le_bytes()).unwrap();
        w.write_all(&master_seed.to_le_bytes()).unwrap();
        w.write_all(&(num_groups as u32).to_le_bytes()).unwrap();
        w.write_all(&[0u8; 4]).unwrap(); // padding to 36B

        for table in &all_tables {
            for &entry_id in table {
                w.write_all(&entry_id.to_le_bytes()).unwrap();
            }
        }
        w.flush().unwrap();
    }

    let cuckoo_size = 36 + k * bins_per_table * 4;
    println!("      Cuckoo: {}B, {:.2?} total", cuckoo_size, t.elapsed());
}

// ─── Build one Merkle tree from bin hashes ──────────────────────────────────

fn build_tree(
    tree_kind: &str,
    leaf_hashes: Vec<Hash256>,
    num_real: usize,
    data_dir: &str,
) {
    let arity = onion_merkle_arity();
    let t_total = Instant::now();

    // No power-of-arity padding needed: compute_next_level handles partial
    // last groups by implicitly padding with ZERO_HASH. This avoids
    // creating millions of empty NTT entries.
    let mut current_level = leaf_hashes;

    let mut depth = 0;
    { let mut v = num_real; while v > 1 { v = (v + arity - 1) / arity; depth += 1; } }

    println!("  {} leaves, depth {} (arity={})", num_real, depth, arity);

    let mut cached_levels: Vec<Vec<Hash256>> = Vec::new();
    let mut cache_from_level = depth;
    let root;

    for level in 0..depth {
        let num_groups = (current_level.len() + arity - 1) / arity;

        if num_groups <= TREE_TOP_GROUP_THRESHOLD {
            if cached_levels.is_empty() {
                cache_from_level = level;
                println!("    L{}: {} nodes, {} groups ≤ {} → tree-top cache",
                    level, current_level.len(), num_groups, TREE_TOP_GROUP_THRESHOLD);
            }
            cached_levels.push(current_level.clone());
        } else {
            build_sibling_level(&current_level, level, tree_kind, data_dir);
        }

        let next_level = compute_next_level(&current_level, arity);
        current_level = next_level;
    }

    assert_eq!(current_level.len(), 1);
    root = current_level[0];
    if cached_levels.is_empty() {
        cache_from_level = depth;
    }
    cached_levels.push(current_level);

    // Write root
    let root_path = format!("{}/merkle_onion_{}_root.bin", data_dir, tree_kind);
    std::fs::write(&root_path, &root).expect("write root");
    let root_hex: String = root.iter().take(8).map(|b| format!("{:02x}", b)).collect();
    println!("    Root: {}...", root_hex);

    // Write tree-top cache
    let top_path = format!("{}/merkle_onion_{}_tree_top.bin", data_dir, tree_kind);
    write_tree_top_cache(&top_path, cache_from_level, &cached_levels, arity);

    let num_sib_levels = cache_from_level;
    println!("    Sibling levels: {} (L0..L{}), tree-top: L{}..L{}",
        num_sib_levels, num_sib_levels.saturating_sub(1), cache_from_level, depth);
    println!("    Built in {:.1}s", t_total.elapsed().as_secs_f64());
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() {
    let data_dir = parse_data_dir();

    // OnionPIRv2 port (commit 5b): pull arity from the linked
    // onionpir crate's entry size. Pinned so each Merkle node's
    // (arity × 32) bytes fit in exactly one OnionPIR plaintext.
    let arity = onion_merkle_arity();
    let packed_entry_size = onion_merkle_packed_entry_size();

    println!("=== Gen 4: Build Per-Bin OnionPIR Merkle Trees (arity={}) ===", arity);
    println!("Data dir: {}", data_dir);
    println!("Entry size: {} bytes ({}×32) — from params_info(0).entry_size", packed_entry_size, arity);
    println!("Tree-top cache: groups ≤ {}", TREE_TOP_GROUP_THRESHOLD);
    println!("Two trees: INDEX-MERKLE (per INDEX bin) + DATA-MERKLE (per DATA bin)");
    println!();

    let t_total = Instant::now();

    // ── 1. Read INDEX bin hashes ────────────────────────────────────────────
    let index_hashes_path = format!("{}/onion_index_bin_hashes.bin", data_dir);
    println!("[1] Reading INDEX bin hashes from {}...", index_hashes_path);
    let (index_k, index_bins, index_hashes) = read_bin_hashes(&index_hashes_path);
    let index_total = index_k * index_bins;
    println!("    K={}, bins_per_table={}, total leaves={}", index_k, index_bins, index_total);

    // ── 2. Read DATA bin hashes ─────────────────────────────────────────────
    let data_hashes_path = format!("{}/onion_data_bin_hashes.bin", data_dir);
    println!("[2] Reading DATA bin hashes from {}...", data_hashes_path);
    let (data_k, data_bins, data_hashes) = read_bin_hashes(&data_hashes_path);
    let data_total = data_k * data_bins;
    println!("    K={}, bins_per_table={}, total leaves={}", data_k, data_bins, data_total);

    // ── 3. Build INDEX-MERKLE tree ──────────────────────────────────────────
    println!("\n[3] Building INDEX-MERKLE tree...");
    build_tree("index", index_hashes, index_total, &data_dir);

    // ── 4. Build DATA-MERKLE tree ───────────────────────────────────────────
    println!("\n[4] Building DATA-MERKLE tree...");
    build_tree("data", data_hashes, data_total, &data_dir);

    // ── Summary ─────────────────────────────────────────────────────────────
    println!();
    println!("=== Summary ===");
    println!("Arity:           {}", arity);
    println!("INDEX-MERKLE:    {} leaves (K={}, bins={})", index_total, index_k, index_bins);
    println!("DATA-MERKLE:     {} leaves (K={}, bins={})", data_total, data_k, data_bins);
    println!("Per-bin leaves:  no tree_loc, no sorted-order assignment");
    println!("Total time:      {:.1}s", t_total.elapsed().as_secs_f64());
}
