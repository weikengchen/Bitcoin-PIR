//! Integration test: verify random entries against an N-ary Merkle tree.
//!
//! For N randomly chosen index entries:
//! 1. Fetch chunk data and verify data_hash = SHA256(chunks)
//! 2. Look up the entry in MERKLE_DATA cuckoo table (44B slots), verify tag + data_hash
//! 3. Extract tree_loc from MERKLE_DATA slot
//! 4. Compute leaf_hash = SHA256(scripthash || tree_loc || data_hash)
//! 5. Collect sibling hashes from L0..Lk cuckoo tables + tree-top cache
//! 6. Walk the N-ary proof up to the root and verify it matches merkle_root.bin
//!
//! Usage:
//!   test_merkle_verify_n [--data-dir <dir>] [--suffix <sfx>] [--count N]

use memmap2::Mmap;
use pir_core::merkle::{self, Hash256};
use pir_core::hash;
use pir_core::params::*;
use std::fs::File;
use std::io::Read;

const DEFAULT_DATA_DIR: &str = "/Volumes/Bitcoin/data";
const CHUNK_SIZE_BYTES: usize = 40;
const DEFAULT_NUM_TESTS: usize = 100;

/// Read a cuckoo table file, return (bins_per_table, header_size, mmap).
fn open_cuckoo_file(path: &str, header_size: usize) -> (usize, usize, Mmap) {
    let file = File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path, e));
    let mmap = unsafe { Mmap::map(&file).unwrap() };
    let bins = u32::from_le_bytes(mmap[16..20].try_into().unwrap()) as usize;
    (bins, header_size, mmap)
}


/// Look up a sibling group from an N-ary sibling cuckoo table.
/// Slot layout: [4B group_index][arity × 32B child_hashes]
/// Returns all A child hashes for the group containing `node_local`.
fn lookup_sibling_group(
    mmap: &[u8],
    header_size: usize,
    bins_per_table: usize,
    slots_per_bin: usize,
    level: usize,
    node_local: u32,
    arity: usize,
) -> Option<Vec<Hash256>> {
    let k = 75;
    let cuckoo_num_hashes = 2;
    let master_seed = 0xBA7C_51B1_0000_0000u64.wrapping_add(level as u64);
    let slot_size = merkle::merkle_sibling_slot_size(arity);
    let group_id = node_local / arity as u32;

    let candidate_groups = hash::derive_int_groups_3(group_id, k);

    for &pbc_group in &candidate_groups {
        let keys: Vec<u64> = (0..cuckoo_num_hashes)
            .map(|hf| hash::derive_cuckoo_key(master_seed, pbc_group, hf))
            .collect();

        for &key in &keys {
            let bin = hash::cuckoo_hash_int(group_id, key, bins_per_table);

            for slot in 0..slots_per_bin {
                let global_slot = pbc_group * bins_per_table * slots_per_bin
                    + bin * slots_per_bin + slot;
                let offset = header_size + global_slot * slot_size;

                if offset + slot_size > mmap.len() { continue; }

                let slot_data = &mmap[offset..offset + slot_size];
                let stored_id = u32::from_le_bytes(slot_data[0..4].try_into().unwrap());

                if stored_id == group_id {
                    let mut children = Vec::with_capacity(arity);
                    for c in 0..arity {
                        let off = 4 + c * 32;
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&slot_data[off..off + 32]);
                        children.push(h);
                    }
                    return Some(children);
                }
            }
        }
    }
    None
}

/// Tree-top cache: per-level arrays of node hashes.
struct TreeTopCache {
    /// cache_from_level: first level (from leaves) that is cached
    cache_from_level: usize,
    /// arity read from file
    arity: usize,
    /// levels[0] = hashes at cache_from_level, levels[last] = [root]
    levels: Vec<Vec<Hash256>>,
}

fn load_tree_top_cache(path: &str) -> TreeTopCache {
    let data = std::fs::read(path).expect("read tree-top cache");
    // New header: [1B cache_from_level][4B total_nodes LE][2B arity LE][1B num_cached_levels]
    let cache_from_level = data[0] as usize;
    let _total_nodes = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
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

    TreeTopCache { cache_from_level, arity, levels }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut data_dir = DEFAULT_DATA_DIR.to_string();
    let mut suffix = String::new();
    let mut num_tests = DEFAULT_NUM_TESTS;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" if i + 1 < args.len() => { data_dir = args[i + 1].clone(); i += 1; }
            "--suffix" if i + 1 < args.len() => { suffix = args[i + 1].clone(); i += 1; }
            "--count" if i + 1 < args.len() => { num_tests = args[i + 1].parse().expect("--count N"); i += 1; }
            _ => {}
        }
        i += 1;
    }

    println!("=== N-ary Merkle Verification Test (suffix='{}') ===\n", suffix);

    // ── Load files ────────────────────────────────────────────────────────

    println!("[1] Loading data files...");

    // Index
    let index_path = format!("{}/intermediate/utxo_chunks_index_nodust.bin", data_dir);
    let index_file = File::open(&index_path).expect("open index");
    let index_mmap = unsafe { Mmap::map(&index_file).unwrap() };
    let num_entries = index_mmap.len() / INDEX_RECORD_SIZE;
    println!("  Index: {} entries", num_entries);

    // Chunks
    let chunks_path = format!("{}/intermediate/utxo_chunks_nodust.bin", data_dir);
    let chunks_file = File::open(&chunks_path).expect("open chunks");
    let chunks_mmap = unsafe { Mmap::map(&chunks_file).unwrap() };
    println!("  Chunks: {} bytes", chunks_mmap.len());

    // Merkle root
    let root_path = format!("{}/merkle_root{}.bin", data_dir, suffix);
    let mut root = [0u8; 32];
    File::open(&root_path).expect("open root").read_exact(&mut root).unwrap();
    println!("  Root: {:02x}{:02x}{:02x}{:02x}...", root[0], root[1], root[2], root[3]);

    // Tree-top cache (auto-detect arity)
    let top_path = format!("{}/merkle_tree_top{}.bin", data_dir, suffix);
    let cache = load_tree_top_cache(&top_path);
    let arity = cache.arity;
    let cache_from_level = cache.cache_from_level;
    println!("  Tree-top cache: arity={}, cache_from_level={}, {} cached levels",
        arity, cache_from_level, cache.levels.len());

    // Load tree_locs.bin (produced by gen_4)
    let tree_locs_path = format!("{}/intermediate/tree_locs.bin", data_dir);
    let tree_locs_data = std::fs::read(&tree_locs_path).expect("read tree_locs.bin (run gen_4 first)");
    assert_eq!(tree_locs_data.len(), num_entries * 4, "tree_locs.bin size mismatch");
    let tree_locs: Vec<u32> = (0..num_entries)
        .map(|i| u32::from_le_bytes(tree_locs_data[i * 4..i * 4 + 4].try_into().unwrap()))
        .collect();
    println!("  tree_locs: {} entries (from tree_locs.bin)", tree_locs.len());

    // Sibling cuckoo tables (L0..L{cache_from_level-1})
    let num_sibling_levels = cache_from_level;
    let sib_slot_size = merkle::merkle_sibling_slot_size(arity);
    let mut sib_tables: Vec<(usize, usize, usize, Mmap)> = Vec::new(); // (bins, header_size, slots_per_bin, mmap)
    for level in 0..num_sibling_levels {
        let path = format!("{}/merkle_sibling{}_L{}.bin", data_dir, suffix, level);
        let (bins, header, mmap) = open_cuckoo_file(&path, 32);
        let slots_per_bin_val = u32::from_le_bytes(mmap[12..16].try_into().unwrap()) as usize;
        sib_tables.push((bins, header, slots_per_bin_val, mmap));
    }
    println!("  Loaded {} sibling tables (L0..L{}, slot={}B)",
        num_sibling_levels, num_sibling_levels.saturating_sub(1), sib_slot_size);

    // ── Test random entries ───────────────────────────────────────────────

    println!("\n[2] Testing {} random entries (arity={})...\n", num_tests, arity);

    let mut rng_state: u64 = 0xdeadbeef12345678;
    let mut pass = 0;
    let mut fail = 0;

    for test_i in 0..num_tests {
        // Simple splitmix64 PRNG
        rng_state = rng_state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = rng_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        let entry_idx = (z as usize) % num_entries;

        // Read index entry
        let base = entry_idx * INDEX_RECORD_SIZE;
        let mut scripthash = [0u8; 20];
        scripthash.copy_from_slice(&index_mmap[base..base + 20]);
        let start_chunk_id = u32::from_le_bytes(
            index_mmap[base + 20..base + 24].try_into().unwrap()
        );
        let num_chunks = index_mmap[base + 24] as usize;

        // Step 1: Compute data_hash from chunks
        let data_hash = if num_chunks > 0 {
            let data_start = start_chunk_id as usize * CHUNK_SIZE_BYTES;
            let data_end = data_start + num_chunks * CHUNK_SIZE_BYTES;
            merkle::compute_data_hash(&chunks_mmap[data_start..data_end])
        } else {
            merkle::ZERO_HASH
        };

        // Step 2: Get tree_loc from precomputed tree_locs
        let tree_loc = tree_locs[entry_idx];

        // Step 3: Compute leaf hash
        let leaf_hash = merkle::compute_leaf_hash(&scripthash, tree_loc, &data_hash);

        // Step 4: Collect siblings and walk up the N-ary tree
        let mut current_hash = leaf_hash;
        let mut node_idx = tree_loc as usize;
        let mut verified = true;

        // Levels L0..L{cache_from_level-1}: sibling groups from cuckoo tables
        for (level, sib_table) in sib_tables.iter().enumerate() {
            let (sib_bins, sib_header, sib_slots_per_bin, sib_mmap) = sib_table;
            let (sib_bins, sib_header, sib_slots_per_bin) =
                (*sib_bins, *sib_header, *sib_slots_per_bin);

            let children = match lookup_sibling_group(
                sib_mmap, sib_header, sib_bins, sib_slots_per_bin,
                level, node_idx as u32, arity,
            ) {
                Some(c) => c,
                None => {
                    println!("  [{}] FAIL entry {}: sibling group not found at L{} node={} group={}",
                        test_i, entry_idx, level, node_idx, node_idx / arity);
                    verified = false;
                    break;
                }
            };

            // The group has all A children. Hash them to get the parent.
            current_hash = merkle::compute_parent_n(&children);
            node_idx /= arity;
        }

        if !verified {
            fail += 1;
            continue;
        }

        // Levels cache_from_level..depth: siblings from tree-top cache
        // cache.levels[0] = all nodes at cache_from_level, etc.
        for cache_level_idx in 0..cache.levels.len().saturating_sub(1) {
            let level_nodes = &cache.levels[cache_level_idx];
            let pos_in_parent = node_idx % arity;
            let parent_start = (node_idx / arity) * arity;

            let mut children = Vec::with_capacity(arity);
            for c in 0..arity {
                let child_idx = parent_start + c;
                if c == pos_in_parent {
                    children.push(current_hash);
                } else if child_idx < level_nodes.len() {
                    children.push(level_nodes[child_idx]);
                } else {
                    children.push(merkle::ZERO_HASH);
                }
            }
            current_hash = merkle::compute_parent_n(&children);
            node_idx /= arity;
        }

        // Final check: current_hash should equal root
        if current_hash == root {
            if test_i < 5 || test_i % 20 == 0 {
                println!("  [{}] PASS entry {} (scripthash {:02x}{:02x}..., tree_loc={}, chunks={})",
                    test_i, entry_idx,
                    scripthash[0], scripthash[1],
                    tree_loc, num_chunks);
            }
            pass += 1;
        } else {
            println!("  [{}] FAIL entry {}: root mismatch!", test_i, entry_idx);
            println!("    Expected: {:02x}{:02x}{:02x}{:02x}...",
                root[0], root[1], root[2], root[3]);
            println!("    Got:      {:02x}{:02x}{:02x}{:02x}...",
                current_hash[0], current_hash[1], current_hash[2], current_hash[3]);
            fail += 1;
        }
    }

    println!("\n=== Results ===");
    println!("Arity:   {}", arity);
    println!("Passed:  {}/{}", pass, num_tests);
    println!("Failed:  {}/{}", fail, num_tests);

    if fail > 0 {
        std::process::exit(1);
    }
    println!("\nAll entries verified successfully!");
}
