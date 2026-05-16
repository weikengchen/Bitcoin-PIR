//! Shared N-ary Merkle tree builder logic (memory-efficient).
//!
//! Parameterized by arity and slots_per_bin. Both DPF (arity=8, slots_per_bin=4)
//! and OnionPIR (arity=120, slots_per_bin=1) use this same core.
//!
//! Memory strategy: build the tree level-by-level, processing and writing each
//! sibling cuckoo table immediately, then dropping the current level before
//! computing the next. Only one full level is held in memory at a time.

use memmap2::Mmap;
use pir_core::cuckoo;
use pir_core::hash;
use pir_core::merkle::{self, Hash256, ZERO_HASH};
use pir_core::params::*;
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

const DEFAULT_DATA_DIR: &str = "/Volumes/Bitcoin/data";

/// Tree-top cache threshold: cache all levels with ≤ 4096 sibling groups.
/// This ensures every PIR-queried level has bins_per_table > 128 (dpf_n > 7),
/// avoiding the DPF library's minimum domain requirement.
const TREE_TOP_GROUP_THRESHOLD: usize = 4096;

/// MERKLE_SIBLING table parameters for a given level.
/// Slot = [4B node_index][(arity-1)*32B hashes]
fn merkle_sibling_params(level: usize, arity: usize, slots_per_bin: usize) -> TableParams {
    TableParams {
        k: 75,
        num_hashes: 3,
        master_seed: 0xBA7C_51B1_0000_0000u64.wrapping_add(level as u64),
        slots_per_bin,
        cuckoo_num_hashes: 2,
        slot_size: merkle::merkle_sibling_slot_size(arity),
        dpf_n: 0, // computed per-level
        magic: 0xBA7C_51B1_0000_0000u64 | (level as u64),
        header_size: 32,
        has_tag_seed: false,
    }
}

/// Compute minimum DPF exponent n such that 2^n >= value.
fn min_dpf_n(value: usize) -> u8 {
    if value <= 1 { return 1; }
    let mut n = 0u8;
    let mut v = 1usize;
    while v < value {
        v <<= 1;
        n += 1;
    }
    n
}

/// Compute the smallest power of `base` that is >= `n`.
pub fn next_power_of(n: usize, base: usize) -> usize {
    if n <= 1 { return 1; }
    let mut v = 1;
    while v < n { v *= base; }
    v
}

/// Per-entry leaf info extracted from the index + chunks files.
pub struct LeafInfo {
    pub scripthash: [u8; 20],
    pub data_hash: Hash256,
}

/// Result of leaf preparation: everything needed to build tree levels.
pub struct PreparedLeaves {
    pub leaf_infos: Vec<LeafInfo>,
    pub tree_locs: Vec<u32>,
    pub leaf_hashes_padded: Vec<Hash256>,
    pub num_real: usize,
    pub depth: usize,
}

/// Load index + chunks, compute data hashes, sort, assign tree_locs, compute leaf hashes.
/// Returns padded leaf hash array and metadata.
pub fn prepare_leaves(data_dir: &str, arity: usize) -> PreparedLeaves {
    let index_file = format!("{}/intermediate/utxo_chunks_index_nodust.bin", data_dir);
    let chunks_file = format!("{}/intermediate/utxo_chunks_nodust.bin", data_dir);

    println!("[1] Loading index and chunks...");
    let f = File::open(&index_file).expect("open index file");
    let index_mmap = unsafe { Mmap::map(&f) }.expect("mmap index");
    let num_entries = index_mmap.len() / INDEX_RECORD_SIZE;
    println!("    {} index entries", num_entries);

    let f = File::open(&chunks_file).expect("open chunks file");
    let chunks_mmap = unsafe { Mmap::map(&f) }.expect("mmap chunks");
    let num_chunks = chunks_mmap.len() / CHUNK_SIZE;
    println!("    {} chunks ({:.2} GB)", num_chunks, chunks_mmap.len() as f64 / 1e9);

    println!("[2] Computing data hashes ({} entries)...", num_entries);
    let t = Instant::now();

    let leaf_infos: Vec<LeafInfo> = (0..num_entries)
        .into_par_iter()
        .map(|i| {
            let offset = i * INDEX_RECORD_SIZE;
            let mut scripthash = [0u8; 20];
            scripthash.copy_from_slice(&index_mmap[offset..offset + 20]);
            let num_chunks_val = index_mmap[offset + 24];
            let data_hash = if num_chunks_val > 0 {
                let start_chunk_id = u32::from_le_bytes(
                    index_mmap[offset + 20..offset + 24].try_into().unwrap()
                );
                let data_start = start_chunk_id as usize * CHUNK_SIZE;
                let data_end = data_start + (num_chunks_val as usize * CHUNK_SIZE);
                merkle::sha256(&chunks_mmap[data_start..data_end])
            } else {
                ZERO_HASH
            };
            LeafInfo { scripthash, data_hash }
        })
        .collect();
    println!("    Done in {:.2?}", t.elapsed());

    println!("[3] Sorting {} entries by scripthash...", num_entries);
    let t = Instant::now();
    let mut sorted_indices: Vec<usize> = (0..num_entries).collect();
    sorted_indices.sort_unstable_by(|&a, &b| leaf_infos[a].scripthash.cmp(&leaf_infos[b].scripthash));
    let mut tree_locs = vec![0u32; num_entries];
    for (sorted_pos, &orig_idx) in sorted_indices.iter().enumerate() {
        tree_locs[orig_idx] = sorted_pos as u32;
    }
    println!("    Done in {:.2?}", t.elapsed());

    // Write tree_locs.bin sidecar for gen_3 INDEX cuckoo builders
    let tree_locs_path = format!("{}/intermediate/tree_locs.bin", data_dir);
    {
        let f = File::create(&tree_locs_path).expect("create tree_locs.bin");
        let mut w = BufWriter::with_capacity(4 * 1024 * 1024, f);
        for &loc in &tree_locs {
            w.write_all(&loc.to_le_bytes()).unwrap();
        }
        w.flush().unwrap();
    }
    println!("    Wrote tree_locs.bin ({} entries, {} bytes)", num_entries, num_entries * 4);

    println!("[4] Computing leaf hashes (arity={})...", arity);
    let t = Instant::now();
    let num_leaves_padded = next_power_of(num_entries, arity);
    let mut leaf_hashes: Vec<Hash256> = sorted_indices
        .par_iter()
        .map(|&orig_idx| {
            let info = &leaf_infos[orig_idx];
            merkle::compute_leaf_hash(&info.scripthash, tree_locs[orig_idx], &info.data_hash)
        })
        .collect();
    leaf_hashes.resize(num_leaves_padded, ZERO_HASH);

    let mut depth = 0;
    { let mut v = num_leaves_padded; while v > 1 { v = v.div_ceil(arity); depth += 1; } }
    println!("    {} real, {} padded, depth {}", num_entries, num_leaves_padded, depth);
    println!("    Done in {:.2?}", t.elapsed());

    PreparedLeaves {
        leaf_infos,
        tree_locs,
        leaf_hashes_padded: leaf_hashes,
        num_real: num_entries,
        depth,
    }
}

pub const TREE_TOP_GROUP_THRESHOLD_PUB: usize = 4096;

/// Parse --data-dir from command line args.
pub fn parse_data_dir() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut data_dir = DEFAULT_DATA_DIR.to_string();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--data-dir" && i + 1 < args.len() {
            data_dir = args[i + 1].clone();
            i += 1;
        }
        i += 1;
    }
    data_dir
}

/// Write tree-top cache to file.
pub fn write_tree_top_cache(
    path: &str,
    cache_from_level: usize,
    cached_levels: &[Vec<Hash256>],
    arity: usize,
) {
    let total_cached_nodes: usize = cached_levels.iter().map(|l| l.len()).sum();
    let f = File::create(path).expect("create merkle_tree_top.bin");
    let mut w = BufWriter::new(f);
    w.write_all(&[cache_from_level as u8]).unwrap();
    w.write_all(&(total_cached_nodes as u32).to_le_bytes()).unwrap();
    w.write_all(&(arity as u16).to_le_bytes()).unwrap();
    let num_cached_levels = cached_levels.len() as u8;
    w.write_all(&[num_cached_levels]).unwrap();
    for level in cached_levels {
        w.write_all(&(level.len() as u32).to_le_bytes()).unwrap();
        for hash in level {
            w.write_all(hash).unwrap();
        }
    }
    w.flush().unwrap();
    let top_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    println!("    Wrote tree-top cache: {} levels, {} nodes, {} bytes to {}",
        cached_levels.len(), total_cached_nodes, top_size, path);
}

/// Compute the next level from the current level: group by arity, hash each group.
pub fn compute_next_level(current: &[Hash256], arity: usize) -> Vec<Hash256> {
    let next_len = current.len().div_ceil(arity);
    (0..next_len)
        .into_par_iter()
        .map(|i| {
            let start = i * arity;
            let end = (start + arity).min(current.len());
            let mut children = Vec::with_capacity(arity);
            children.extend_from_slice(&current[start..end]);
            children.resize(arity, ZERO_HASH);
            merkle::compute_parent_n(&children)
        })
        .collect()
}

/// Build a sibling GROUP cuckoo table for a level and write it to disk.
///
/// One entry per parent group (not per node). Slot layout:
///   [4B group_index][A × 32B child_hashes]
///
/// The client queries group_id = node_idx / arity, gets all A children.
/// Its own hash is at position (node_idx % arity); the rest are siblings.
/// This is A× more space-efficient than storing (A-1) siblings per node.
fn build_and_write_sibling_table(
    level_nodes: &[Hash256],
    level: usize,
    arity: usize,
    slots_per_bin: usize,
    data_dir: &str,
    suffix: &str,
) {
    let t = Instant::now();
    let nodes_at_level = level_nodes.len();
    let num_groups = nodes_at_level.div_ceil(arity);
    let sib_slot_size = merkle::merkle_sibling_slot_size(arity);
    let mut sib_params = merkle_sibling_params(level, arity, slots_per_bin);

    // Assign groups to PBC groups (integer-keyed by group index)
    let mut pbc_group_items: Vec<Vec<usize>> = vec![Vec::new(); sib_params.k];
    for group_id in 0..num_groups {
        let pbc_groups = hash::derive_int_groups_3(group_id as u32, sib_params.k);
        for &b in &pbc_groups {
            pbc_group_items[b].push(group_id);
        }
    }

    let max_load = pbc_group_items.iter().map(|v| v.len()).max().unwrap_or(0);
    let bins = cuckoo::compute_bins_per_table(max_load, sib_params.slots_per_bin);
    sib_params.dpf_n = min_dpf_n(bins);

    let tables: Vec<Vec<u32>> = (0..sib_params.k)
        .into_par_iter()
        .map(|group_id| {
            let items = &pbc_group_items[group_id];
            let ids: Vec<u32> = items.iter().map(|&gi| gi as u32).collect();
            cuckoo::build_int_keyed_table(&ids, group_id, &sib_params, bins)
        })
        .collect();

    // Serialize
    let sib_path = format!("{}/merkle_sibling{}_L{}.bin", data_dir, suffix, level);
    {
        let header = cuckoo::write_header(&sib_params, bins, 0);
        let f = File::create(&sib_path).expect("create sibling file");
        let mut w = BufWriter::with_capacity(4 * 1024 * 1024, f);
        w.write_all(&header).unwrap();

        let zero_slot = vec![0u8; sib_slot_size];
        for group_id in 0..sib_params.k {
            let table = &tables[group_id];
            let items = &pbc_group_items[group_id];

            for &entry_local in table.iter().take(bins * sib_params.slots_per_bin) {
                if entry_local == cuckoo::EMPTY {
                    w.write_all(&zero_slot).unwrap();
                } else {
                    let group_id = items[entry_local as usize];
                    let first_child = group_id * arity;

                    // [4B group_index LE][A × 32B child_hashes]
                    w.write_all(&(group_id as u32).to_le_bytes()).unwrap();
                    for c in 0..arity {
                        let child_idx = first_child + c;
                        if child_idx < level_nodes.len() {
                            w.write_all(&level_nodes[child_idx]).unwrap();
                        } else {
                            w.write_all(&ZERO_HASH).unwrap();
                        }
                    }
                }
            }
        }
        w.flush().unwrap();
    }

    let sib_size = std::fs::metadata(&sib_path).map(|m| m.len()).unwrap_or(0);
    println!("    L{}: {} nodes, {} groups, bins={}, dpf_n={}, {:.1} MB ({:.2?})",
        level, nodes_at_level, num_groups, bins, sib_params.dpf_n,
        sib_size as f64 / 1e6, t.elapsed());
}

/// Build the full N-ary Merkle tree for DPF/Batch PIR and write all output files.
///
/// * `arity` — branching factor (e.g. 2, 8, 120)
/// * `slots_per_bin` — cuckoo slots per bin for all tables (4 for DPF)
/// * `suffix` — file name suffix (e.g. "_dpf")
pub fn build_merkle_n(arity: usize, slots_per_bin: usize, suffix: &str) {
    let data_dir = parse_data_dir();
    let sib_slot = merkle::merkle_sibling_slot_size(arity);

    println!("=== Gen 4: Build N-ary Merkle Tree (arity={}, slots_per_bin={}, suffix='{}') ===",
        arity, slots_per_bin, suffix);
    println!("Data dir: {}", data_dir);
    println!("Sibling slot:     {} bytes (arity × 32B + 4B)", sib_slot);
    println!("Tree-top cache:   groups ≤ {}", TREE_TOP_GROUP_THRESHOLD);
    println!("(tree_loc embedded in INDEX slot — no MERKLE_DATA table)");
    println!();

    let t_total = Instant::now();

    let prep = prepare_leaves(&data_dir, arity);
    let num_entries = prep.num_real;
    let depth = prep.depth;
    let mut current_level = prep.leaf_hashes_padded;

    let sib_slot_size = merkle::merkle_sibling_slot_size(arity);
    let mut cached_levels: Vec<Vec<Hash256>> = Vec::new();
    let mut cache_from_level = depth;
    let mut num_sibling_levels = 0;

    println!("[5] Building sibling tables level-by-level (arity={}, slot={}B)...", arity, sib_slot_size);

    for level in 0..depth {
        let nodes_at_level = current_level.len();
        let num_groups = nodes_at_level.div_ceil(arity);

        if num_groups <= TREE_TOP_GROUP_THRESHOLD {
            if cached_levels.is_empty() {
                cache_from_level = level;
                println!("    L{}: {} nodes, {} groups ≤ {} → tree-top cache starts here",
                    level, nodes_at_level, num_groups, TREE_TOP_GROUP_THRESHOLD);
            }
            cached_levels.push(current_level.clone());
        } else {
            // Build and write sibling cuckoo table for this level
            num_sibling_levels = level + 1;
            build_and_write_sibling_table(&current_level, level, arity, slots_per_bin, &data_dir, suffix);
        }

        // Compute next level from current, then drop current
        let next_level = compute_next_level(&current_level, arity);
        current_level = next_level;
    }

    // The final level (root)
    assert_eq!(current_level.len(), 1);
    let root = current_level[0];
    if cached_levels.is_empty() {
        cache_from_level = depth;
    }
    cached_levels.push(current_level); // root level

    let total_cached_nodes: usize = cached_levels.iter().map(|l| l.len()).sum();
    println!("    Tree-top cache: L{}..L{}, {} cached levels, {} total nodes",
        cache_from_level, depth, cached_levels.len(), total_cached_nodes);

    // ── Step 7: Write merkle_root.bin ───────────────────────────────────────

    let root_path = format!("{}/merkle_root{}.bin", data_dir, suffix);
    std::fs::write(&root_path, root).expect("write merkle_root.bin");
    println!("    Root: {:?}", &root[..8]);
    println!("    Wrote root to {}", root_path);

    // ── Step 8: Write tree-top cache ────────────────────────────────────────

    let top_path = format!("{}/merkle_tree_top{}.bin", data_dir, suffix);
    write_tree_top_cache(&top_path, cache_from_level, &cached_levels, arity);

    // ── Done ────────────────────────────────────────────────────────────────

    println!();
    println!("=== Summary ===");
    println!("Arity:           {}", arity);
    println!("Merkle tree:     {} leaves, depth {}", num_entries, depth);
    println!("tree_loc:        embedded in INDEX (no MERKLE_DATA table)");
    println!("Sibling levels:  {} (L0..L{}, {}B slots)", num_sibling_levels, num_sibling_levels.saturating_sub(1), sib_slot_size);
    println!("Tree-top cache:  L{}..L{} ({} nodes)", cache_from_level, depth, total_cached_nodes);
    println!("Root:            {}", root_path);
    println!("Total time:      {:.1}s", t_total.elapsed().as_secs_f64());
}
