//! Integration test: verify random bin leaves against per-bin OnionPIR Merkle trees.
//!
//! Two trees: INDEX-MERKLE and DATA-MERKLE. Each leaf = SHA256(3840B bin).
//! For each test:
//! 1. Pick a random bin from the bin_hashes sidecar file
//! 2. Walk sibling levels using the packed sibling data (no FHE — offline verification)
//! 3. Walk tree-top cache for remaining levels
//! 4. Verify against root
//!
//! Usage: test_merkle_verify_onion [--data-dir <dir>] [--count N]

mod merkle_builder;

use memmap2::Mmap;
use pir_core::merkle::{self, Hash256, ZERO_HASH};
use std::fs::File;
use std::io::Read;

const DEFAULT_DATA_DIR: &str = "/Volumes/Bitcoin/data";
const ARITY: usize = 120;
const PACKED_ENTRY_SIZE: usize = 3840;
const DEFAULT_NUM_TESTS: usize = 100;

// ─── Hash utilities (same as gen_4_build_merkle_onion) ──────────────────────

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

fn derive_pbc_groups(entry_id: u32, k: usize) -> [usize; 3] {
    let mut groups = [0usize; 3];
    let mut nonce: u64 = 0;
    let mut count = 0;
    while count < 3 {
        let h = hash_entry_for_group(entry_id, nonce);
        let group = (h % k as u64) as usize;
        nonce += 1;
        let mut dup = false;
        for i in 0..count { if groups[i] == group { dup = true; break; } }
        if dup { continue; }
        groups[count] = group;
        count += 1;
    }
    groups
}

fn derive_cuckoo_key(master_seed: u64, group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        master_seed
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

fn cuckoo_hash_int(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

// ─── Tree-top cache loader ─────────────────────────────────────────────────

struct TreeTopCache {
    _cache_from_level: usize,
    arity: usize,
    levels: Vec<Vec<Hash256>>,
}

fn load_tree_top_cache(path: &str) -> TreeTopCache {
    let data = std::fs::read(path).expect("read tree-top");
    let cache_from_level = data[0] as usize;
    let arity = u16::from_le_bytes(data[5..7].try_into().unwrap()) as usize;
    let num_cached_levels = data[7] as usize;
    let mut offset = 8;
    let mut levels = Vec::with_capacity(num_cached_levels);
    for _ in 0..num_cached_levels {
        let num_nodes = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let mut level = Vec::with_capacity(num_nodes);
        for _ in 0..num_nodes {
            let mut h = [0u8; 32];
            h.copy_from_slice(&data[offset..offset + 32]);
            level.push(h);
            offset += 32;
        }
        levels.push(level);
    }
    TreeTopCache { _cache_from_level: cache_from_level, arity, levels }
}

// ─── Sibling level loader ──────────────────────────────────────────────────

struct SiblingLevel {
    k: usize,
    bins_per_table: usize,
    master_seed: u64,
    num_groups: usize,
    cuckoo_mmap: Mmap,
    packed_mmap: Mmap,
}

fn load_sibling_level(data_dir: &str, tree_kind: &str, level: usize) -> Option<SiblingLevel> {
    let cuckoo_path = format!("{}/merkle_onion_{}_sib_L{}_cuckoo.bin", data_dir, tree_kind, level);
    let packed_path = format!("{}/merkle_onion_{}_sib_L{}_packed.bin", data_dir, tree_kind, level);
    if !std::path::Path::new(&cuckoo_path).exists() { return None; }
    if !std::path::Path::new(&packed_path).exists() { return None; }

    let cuckoo_file = File::open(&cuckoo_path).expect("open cuckoo");
    let cuckoo_mmap = unsafe { Mmap::map(&cuckoo_file) }.expect("mmap cuckoo");

    let k = u32::from_le_bytes(cuckoo_mmap[8..12].try_into().unwrap()) as usize;
    let bins_per_table = u32::from_le_bytes(cuckoo_mmap[16..20].try_into().unwrap()) as usize;
    let master_seed = u64::from_le_bytes(cuckoo_mmap[20..28].try_into().unwrap());
    let num_groups = u32::from_le_bytes(cuckoo_mmap[28..32].try_into().unwrap()) as usize;

    let packed_file = File::open(&packed_path).expect("open packed");
    let packed_mmap = unsafe { Mmap::map(&packed_file) }.expect("mmap packed");

    Some(SiblingLevel { k, bins_per_table, master_seed, num_groups, cuckoo_mmap, packed_mmap })
}

/// Look up a group_id in the sibling level's cuckoo table.
/// Returns the ARITY child hashes from the packed data.
fn lookup_sibling_group(sib: &SiblingLevel, group_id: u32) -> Option<Vec<Hash256>> {
    let pbc_groups = derive_pbc_groups(group_id, sib.k);
    let header_size = 36;

    for &pbc_group in &pbc_groups {
        let table_offset = header_size + pbc_group * sib.bins_per_table * 4;

        for h in 0..6 {
            let key = derive_cuckoo_key(sib.master_seed, pbc_group, h);
            let bin = cuckoo_hash_int(group_id, key, sib.bins_per_table);
            let entry_offset = table_offset + bin * 4;

            if entry_offset + 4 > sib.cuckoo_mmap.len() { continue; }
            let stored_id = u32::from_le_bytes(
                sib.cuckoo_mmap[entry_offset..entry_offset + 4].try_into().unwrap()
            );

            if stored_id == group_id {
                let data_offset = group_id as usize * PACKED_ENTRY_SIZE;
                if data_offset + PACKED_ENTRY_SIZE > sib.packed_mmap.len() { return None; }

                let packed = &sib.packed_mmap[data_offset..data_offset + PACKED_ENTRY_SIZE];
                let mut children = Vec::with_capacity(ARITY);
                for c in 0..ARITY {
                    let off = c * 32;
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&packed[off..off + 32]);
                    children.push(h);
                }
                return Some(children);
            }
        }
    }
    None
}

// ─── Bin hash loader ───────────────────────────────────────────────────────

/// Read bin hashes from sidecar file.
/// Format: [4B K][4B bins_per_table][K * bins_per_table * 32B hashes]
fn load_bin_hashes(path: &str) -> (usize, usize, Vec<Hash256>) {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    let k = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let bins_per_table = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let total = k * bins_per_table;
    assert_eq!(data.len(), 8 + total * 32);

    let mut hashes = Vec::with_capacity(total);
    for i in 0..total {
        let off = 8 + i * 32;
        let mut h = [0u8; 32];
        h.copy_from_slice(&data[off..off + 32]);
        hashes.push(h);
    }
    (k, bins_per_table, hashes)
}

// ─── Verify one sub-tree ───────────────────────────────────────────────────

fn verify_sub_tree(
    tree_kind: &str,
    data_dir: &str,
    bin_hashes: &[Hash256],
    num_tests: usize,
) -> (usize, usize) {
    let root_path = format!("{}/merkle_onion_{}_root.bin", data_dir, tree_kind);
    let mut root = [0u8; 32];
    File::open(&root_path)
        .unwrap_or_else(|_| panic!("open {}", root_path))
        .read_exact(&mut root)
        .unwrap();
    let root_hex: String = root.iter().take(4).map(|b| format!("{:02x}", b)).collect();
    println!("  Root: {}...", root_hex);

    let top_path = format!("{}/merkle_onion_{}_tree_top.bin", data_dir, tree_kind);
    let cache = load_tree_top_cache(&top_path);
    println!("  Tree-top: arity={}, {} cached levels", cache.arity, cache.levels.len());

    // Load sibling levels
    let mut sib_levels: Vec<SiblingLevel> = Vec::new();
    for level in 0..10 {
        match load_sibling_level(data_dir, tree_kind, level) {
            Some(sib) => {
                println!("  Sib L{}: K={}, bins={}, {} groups", level, sib.k, sib.bins_per_table, sib.num_groups);
                sib_levels.push(sib);
            }
            None => break,
        }
    }
    let num_sibling_levels = sib_levels.len();

    let num_bins = bin_hashes.len();
    let actual_tests = num_tests.min(num_bins);

    let mut rng_state: u64 = 0xdeadbeef12345678;
    let mut pass = 0usize;
    let mut fail = 0usize;

    for test_i in 0..actual_tests {
        // Pick a random bin index
        rng_state = rng_state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = rng_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        let leaf_pos = (z as usize) % num_bins;

        let mut current_hash = bin_hashes[leaf_pos];
        let mut node_idx = leaf_pos;
        let mut verified = true;

        // Walk sibling levels
        for level in 0..num_sibling_levels {
            let group_id = (node_idx / ARITY) as u32;

            let children = match lookup_sibling_group(&sib_levels[level], group_id) {
                Some(c) => c,
                None => {
                    println!("  [{}] FAIL: sibling group not found {} L{} leaf={} group={}",
                        test_i, tree_kind, level, leaf_pos, group_id);
                    verified = false;
                    break;
                }
            };

            // The packed sibling data already contains all children including ours
            // But we need to replace our position with our current_hash
            let child_pos = node_idx % ARITY;
            let mut merged = children;
            merged[child_pos] = current_hash;

            current_hash = merkle::compute_parent_n(&merged);
            node_idx = group_id as usize;
        }

        if !verified { fail += 1; continue; }

        // Walk tree-top cache
        for ci in 0..cache.levels.len().saturating_sub(1) {
            let level_nodes = &cache.levels[ci];
            let parent_start = (node_idx / ARITY) * ARITY;
            let mut children = Vec::with_capacity(ARITY);
            for c in 0..ARITY {
                let child_idx = parent_start + c;
                if child_idx < level_nodes.len() {
                    children.push(level_nodes[child_idx]);
                } else {
                    children.push(ZERO_HASH);
                }
            }
            current_hash = merkle::compute_parent_n(&children);
            node_idx /= ARITY;
        }

        if current_hash == root {
            if test_i < 5 || test_i % 20 == 0 {
                println!("  [{}] PASS {} leaf_pos={}", test_i, tree_kind, leaf_pos);
            }
            pass += 1;
        } else {
            let got: String = current_hash.iter().take(4).map(|b| format!("{:02x}", b)).collect();
            println!("  [{}] FAIL {} leaf_pos={}: root mismatch (got={}... expected={}...)",
                test_i, tree_kind, leaf_pos, got, root_hex);
            fail += 1;
        }
    }

    (pass, fail)
}

// ─── Main ──────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut data_dir = DEFAULT_DATA_DIR.to_string();
    let mut num_tests = DEFAULT_NUM_TESTS;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" if i + 1 < args.len() => { data_dir = args[i + 1].clone(); i += 1; }
            "--count" if i + 1 < args.len() => { num_tests = args[i + 1].parse().expect("--count N"); i += 1; }
            _ => {}
        }
        i += 1;
    }

    println!("=== Per-Bin OnionPIR Merkle Verification Test (arity={}) ===\n", ARITY);

    // Load INDEX bin hashes
    let index_hashes_path = format!("{}/onion_index_bin_hashes.bin", data_dir);
    let data_hashes_path = format!("{}/onion_data_bin_hashes.bin", data_dir);

    let mut total_pass = 0usize;
    let mut total_fail = 0usize;

    if std::path::Path::new(&index_hashes_path).exists() {
        println!("[1] INDEX-MERKLE tree");
        let (_k, _bins, index_hashes) = load_bin_hashes(&index_hashes_path);
        println!("  {} bin hashes loaded", index_hashes.len());
        let (p, f) = verify_sub_tree("index", &data_dir, &index_hashes, num_tests);
        total_pass += p;
        total_fail += f;
        println!("  INDEX: {}/{} passed\n", p, p + f);
    } else {
        println!("[1] INDEX-MERKLE: skipped (no {})", index_hashes_path);
    }

    if std::path::Path::new(&data_hashes_path).exists() {
        println!("[2] DATA-MERKLE tree");
        let (_k, _bins, data_hashes) = load_bin_hashes(&data_hashes_path);
        println!("  {} bin hashes loaded", data_hashes.len());
        let (p, f) = verify_sub_tree("data", &data_dir, &data_hashes, num_tests);
        total_pass += p;
        total_fail += f;
        println!("  DATA: {}/{} passed\n", p, p + f);
    } else {
        println!("[2] DATA-MERKLE: skipped (no {})", data_hashes_path);
    }

    println!("=== Results ===");
    println!("Total: {} passed, {} failed", total_pass, total_fail);
    if total_fail > 0 { std::process::exit(1); }
    if total_pass > 0 {
        println!("All verified successfully!");
    } else {
        println!("No bin hashes available — run gen_2_onion and gen_3_onion first.");
    }
}
