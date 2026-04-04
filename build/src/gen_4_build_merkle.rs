//! Build Merkle tree + sibling databases for verifiable PIR.
//!
//! Reads the UTXO chunks index and chunks data, then:
//! 1. For each scripthash: compute data_hash = SHA256(chunk_data)
//! 2. Sort all scripthashes lexicographically, assign tree_loc = sorted position
//! 3. Compute leaf hashes, build Merkle tree
//! 4. Output:
//!    - MERKLE_DATA cuckoo table (tag + tree_loc + data_hash per scripthash)
//!    - Per-level sibling cuckoo tables (one per tree level below cache)
//!    - merkle_tree_top.bin (cached top levels, ~32KB)
//!    - merkle_root.bin (32 bytes)
//!
//! Usage:
//!   gen_4_build_merkle [--data-dir <dir>]
//!
//! By default reads intermediates from /Volumes/Bitcoin/data/intermediate/ and writes server files to /Volumes/Bitcoin/data/.
//! With --data-dir, reads/writes from a database directory.

use memmap2::Mmap;
use pir_core::cuckoo;
use pir_core::hash;
use pir_core::merkle::{self, Hash256, MerkleTree, MERKLE_SIBLING_SLOT_SIZE};

/// Legacy MERKLE_DATA slot: [8B tag][4B tree_loc][32B data_hash] = 44 bytes
const MERKLE_DATA_SLOT_SIZE: usize = 44;
use pir_core::params::*;
use rayon::prelude::*;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

const DEFAULT_DATA_DIR: &str = "/Volumes/Bitcoin/data";
const TAG_SEED: u64 = 0xd4e5f6a7b8c91023;

/// Number of top levels to cache (given directly, no PIR needed).
/// 10 levels = 1024 nodes = 32KB of hashes.
const TREE_TOP_CACHE_LEVELS: usize = 10;

/// MERKLE_DATA table parameters: same K=75, bucket_size=4 as INDEX.
/// slot_size = 76 bytes: [8B tag][4B tree_loc][32B data_hash][32B L0_sibling]
fn merkle_data_params() -> TableParams {
    TableParams {
        k: 75,
        num_hashes: 3,
        master_seed: 0x71a2ef38b4c90d15, // same as INDEX — same scripthash entries, same cuckoo layout
        cuckoo_bucket_size: 4,
        cuckoo_num_hashes: 2,
        slot_size: MERKLE_DATA_SLOT_SIZE,
        dpf_n: 20, // same domain as INDEX
        magic: 0xBA7C_0EDA_0000_0001,
        header_size: 40,
        has_tag_seed: true,
    }
}

/// MERKLE_SIBLING table parameters for a given level.
/// slot_size = 36 bytes: [4B node_index][32B hash]
fn merkle_sibling_params(level: usize) -> TableParams {
    TableParams {
        k: 75,
        num_hashes: 3,
        master_seed: 0xBA7C_51B1_0000_0000u64.wrapping_add(level as u64),
        cuckoo_bucket_size: 4,
        cuckoo_num_hashes: 2,
        slot_size: MERKLE_SIBLING_SLOT_SIZE,
        dpf_n: 0, // computed per-level based on actual size
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

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut data_dir = DEFAULT_DATA_DIR.to_string();

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--data-dir" && i + 1 < args.len() {
            data_dir = args[i + 1].clone();
            i += 1;
        }
        i += 1;
    }

    let index_file = format!("{}/intermediate/utxo_chunks_index_nodust.bin", data_dir);
    let chunks_file = format!("{}/intermediate/utxo_chunks_nodust.bin", data_dir);

    println!("=== Gen 4: Build Merkle Tree ===");
    println!("Data dir: {}", data_dir);
    println!("Tree top cache: {} levels ({} nodes)", TREE_TOP_CACHE_LEVELS, 1 << TREE_TOP_CACHE_LEVELS);
    println!();

    let t_total = Instant::now();

    // ── Step 1: Load index and chunks ───────────────────────────────────────

    println!("[1] Loading index and chunks...");
    let f = File::open(&index_file).expect("open index file");
    let index_mmap = unsafe { Mmap::map(&f) }.expect("mmap index");
    let num_entries = index_mmap.len() / INDEX_ENTRY_SIZE;
    println!("    {} index entries", num_entries);

    let f = File::open(&chunks_file).expect("open chunks file");
    let chunks_mmap = unsafe { Mmap::map(&f) }.expect("mmap chunks");
    let num_chunks = chunks_mmap.len() / CHUNK_SIZE;
    println!("    {} chunks ({:.2} GB)", num_chunks, chunks_mmap.len() as f64 / 1e9);

    // ── Step 2: Extract scripthashes, compute data hashes ───────────────────

    println!("[2] Computing data hashes ({} entries)...", num_entries);
    let t = Instant::now();

    // Parallel: for each index entry, extract scripthash and compute data_hash
    struct LeafInfo {
        scripthash: [u8; 20],
        data_hash: Hash256,
        // Original index entry data for MERKLE_DATA table
        start_chunk_id: u32,
        num_chunks_val: u8,
    }

    let leaf_infos: Vec<LeafInfo> = (0..num_entries)
        .into_par_iter()
        .map(|i| {
            let offset = i * INDEX_ENTRY_SIZE;
            let mut scripthash = [0u8; 20];
            scripthash.copy_from_slice(&index_mmap[offset..offset + 20]);

            let start_chunk_id = u32::from_le_bytes(
                index_mmap[offset + 20..offset + 24].try_into().unwrap()
            );
            let num_chunks_val = index_mmap[offset + 24];

            // Compute data_hash = SHA256(all chunk data for this scripthash)
            let data_hash = if num_chunks_val > 0 {
                let data_start = start_chunk_id as usize * CHUNK_SIZE;
                let data_end = data_start + (num_chunks_val as usize * CHUNK_SIZE);
                let data = &chunks_mmap[data_start..data_end];
                merkle::sha256(data)
            } else {
                // Whale sentinel (num_chunks=0) — hash empty data
                merkle::ZERO_HASH
            };

            LeafInfo { scripthash, data_hash, start_chunk_id, num_chunks_val }
        })
        .collect();

    println!("    Done in {:.2?}", t.elapsed());

    // ── Step 3: Sort by scripthash, assign tree_loc ─────────────────────────

    println!("[3] Sorting {} entries by scripthash...", num_entries);
    let t = Instant::now();

    let mut sorted_indices: Vec<usize> = (0..num_entries).collect();
    sorted_indices.sort_unstable_by(|&a, &b| leaf_infos[a].scripthash.cmp(&leaf_infos[b].scripthash));

    // tree_loc[original_index] = sorted_position
    let mut tree_locs = vec![0u32; num_entries];
    for (sorted_pos, &orig_idx) in sorted_indices.iter().enumerate() {
        tree_locs[orig_idx] = sorted_pos as u32;
    }

    println!("    Done in {:.2?}", t.elapsed());

    // ── Step 4: Compute leaf hashes and build tree ──────────────────────────

    println!("[4] Computing leaf hashes and building Merkle tree...");
    let t = Instant::now();

    // Build leaf hashes in sorted order
    let leaf_hashes: Vec<Hash256> = sorted_indices
        .par_iter()
        .map(|&orig_idx| {
            let info = &leaf_infos[orig_idx];
            merkle::compute_leaf_hash(&info.scripthash, tree_locs[orig_idx], &info.data_hash)
        })
        .collect();

    let tree = MerkleTree::build(&leaf_hashes);
    println!("    Tree: {} real leaves, {} padded, depth {}",
        tree.num_real_leaves, tree.num_leaves, tree.depth);
    println!("    Root: {:?}", &tree.root()[..8]);
    println!("    Done in {:.2?}", t.elapsed());

    // ── Step 5: Write merkle_root.bin ───────────────────────────────────────

    let root_path = format!("{}/merkle_root.bin", data_dir);
    std::fs::write(&root_path, tree.root()).expect("write merkle_root.bin");
    println!("    Wrote root to {}", root_path);

    // ── Step 6: Write merkle_tree_top.bin (cached top levels) ───────────────

    let cache_from_level = TREE_TOP_CACHE_LEVELS.min(tree.depth);
    let top_cache = tree.tree_top_cache(cache_from_level);
    let top_path = format!("{}/merkle_tree_top.bin", data_dir);
    {
        let f = File::create(&top_path).expect("create merkle_tree_top.bin");
        let mut w = BufWriter::new(f);
        // Header: [1B cache_from_level][4B num_nodes LE]
        w.write_all(&[cache_from_level as u8]).unwrap();
        w.write_all(&(top_cache.len() as u32).to_le_bytes()).unwrap();
        for hash in &top_cache {
            w.write_all(hash).unwrap();
        }
        w.flush().unwrap();
    }
    println!("    Wrote {} cached nodes ({} bytes) to {}",
        top_cache.len(), 5 + top_cache.len() * 32, top_path);

    // ── Step 7: Build MERKLE_DATA cuckoo table ──────────────────────────────

    println!("[5] Building MERKLE_DATA cuckoo table...");
    let t = Instant::now();
    let md_params = merkle_data_params();

    // Assign to buckets (same as INDEX — by scripthash)
    let mut md_bucket_entries: Vec<Vec<usize>> = vec![Vec::new(); md_params.k];
    for i in 0..num_entries {
        let buckets = hash::derive_buckets_3(&leaf_infos[i].scripthash, md_params.k);
        for &b in &buckets {
            md_bucket_entries[b].push(i);
        }
    }

    let md_max_load = md_bucket_entries.iter().map(|v| v.len()).max().unwrap_or(0);
    let md_bins = cuckoo::compute_bins_per_table(md_max_load, md_params.cuckoo_bucket_size);
    println!("    K={}, max_load={}, bins_per_table={}", md_params.k, md_max_load, md_bins);

    let done = AtomicUsize::new(0);
    let md_tables: Vec<Vec<u32>> = (0..md_params.k)
        .into_par_iter()
        .map(|bucket_id| {
            let entries = &md_bucket_entries[bucket_id];
            let script_hashes: Vec<&[u8]> = entries.iter()
                .map(|&i| leaf_infos[i].scripthash.as_slice())
                .collect();
            let table = cuckoo::build_byte_keyed_table(&script_hashes, bucket_id, &md_params, md_bins);
            let d = done.fetch_add(1, Ordering::Relaxed) + 1;
            if d % 10 == 0 || d == md_params.k { eprint!("\r    {}/{} tables   ", d, md_params.k); }
            table
        })
        .collect();
    eprintln!();

    // Serialize MERKLE_DATA
    let md_path = format!("{}/merkle_data_cuckoo.bin", data_dir);
    {
        let header = cuckoo::write_header(&md_params, md_bins, TAG_SEED);
        let f = File::create(&md_path).expect("create merkle_data_cuckoo.bin");
        let mut w = BufWriter::with_capacity(16 * 1024 * 1024, f);
        w.write_all(&header).unwrap();

        for bucket_id in 0..md_params.k {
            let table = &md_tables[bucket_id];
            let entries = &md_bucket_entries[bucket_id];

            for slot_idx in 0..(md_bins * md_params.cuckoo_bucket_size) {
                let entry_local = table[slot_idx];
                if entry_local == cuckoo::EMPTY {
                    w.write_all(&[0u8; MERKLE_DATA_SLOT_SIZE]).unwrap();
                } else {
                    let orig_idx = entries[entry_local as usize];
                    let info = &leaf_infos[orig_idx];

                    // [8B tag][4B tree_loc][32B data_hash][32B L0_sibling]
                    let tag = hash::compute_tag(TAG_SEED, &info.scripthash);
                    let leaf_idx = tree_locs[orig_idx] as usize;
                    let sibling_abs = (tree.num_leaves + leaf_idx) ^ 1;
                    let l0_sibling = if sibling_abs < tree.nodes.len() {
                        tree.nodes[sibling_abs]
                    } else {
                        merkle::ZERO_HASH
                    };
                    w.write_all(&tag.to_le_bytes()).unwrap();
                    w.write_all(&tree_locs[orig_idx].to_le_bytes()).unwrap();
                    w.write_all(&info.data_hash).unwrap();
                    w.write_all(&l0_sibling).unwrap();
                }
            }
        }
        w.flush().unwrap();
    }
    let md_size = std::fs::metadata(&md_path).map(|m| m.len()).unwrap_or(0);
    println!("    Wrote {:.2} GB to {}", md_size as f64 / 1e9, md_path);
    println!("    Done in {:.2?}", t.elapsed());

    // ── Step 8: Build per-level sibling cuckoo tables ───────────────────────

    let num_sibling_levels = if tree.depth > cache_from_level {
        tree.depth - cache_from_level
    } else {
        0
    };

    // L0 siblings are embedded in MERKLE_DATA, so sibling tables cover L1..L(num_sibling_levels).
    // After that, tree-top cache covers the remaining levels up to root.
    // num_sibling_levels = depth - cache_from_level (e.g. 26-10=16).
    println!("[6] Building {} sibling cuckoo tables (L1..L{}, L0 in MERKLE_DATA)...",
        num_sibling_levels - 1, num_sibling_levels);

    for level in 1..=num_sibling_levels {
        let t = Instant::now();
        let nodes_at_level = tree.num_leaves >> level;
        // Number of sibling pairs = nodes_at_level / 2
        let num_sibling_nodes = nodes_at_level / 2;

        let mut sib_params = merkle_sibling_params(level);
        let bins_needed = cuckoo::compute_bins_per_table(
            // Rough estimate of max bucket load
            (num_sibling_nodes * 3) / sib_params.k + 1,
            sib_params.cuckoo_bucket_size,
        );
        sib_params.dpf_n = min_dpf_n(bins_needed);

        // Collect sibling data: for each node at this level, store its sibling's hash
        // Node i at level L has sibling i^1.
        // We only need to store siblings for nodes that have real descendants.
        let mut sibling_ids: Vec<u32> = Vec::new();
        let mut sibling_hashes: Vec<Hash256> = Vec::new();

        let level_offset = tree.num_leaves >> level;
        for node_local in 0..nodes_at_level {
            let abs_idx = level_offset + node_local;
            if abs_idx < tree.nodes.len() {
                let sibling_abs = abs_idx ^ 1;
                if sibling_abs < tree.nodes.len() {
                    sibling_ids.push(node_local as u32);
                    sibling_hashes.push(tree.nodes[sibling_abs]);
                }
            }
        }

        // Assign to buckets (integer-keyed by node index)
        let mut bucket_items: Vec<Vec<usize>> = vec![Vec::new(); sib_params.k];
        for (local_idx, &node_id) in sibling_ids.iter().enumerate() {
            let buckets = hash::derive_int_buckets_3(node_id, sib_params.k);
            for &b in &buckets {
                bucket_items[b].push(local_idx);
            }
        }

        let max_load = bucket_items.iter().map(|v| v.len()).max().unwrap_or(0);
        let bins = cuckoo::compute_bins_per_table(max_load, sib_params.cuckoo_bucket_size);
        sib_params.dpf_n = min_dpf_n(bins);

        let tables: Vec<Vec<u32>> = (0..sib_params.k)
            .into_par_iter()
            .map(|bucket_id| {
                let items = &bucket_items[bucket_id];
                let ids: Vec<u32> = items.iter().map(|&li| sibling_ids[li]).collect();
                cuckoo::build_int_keyed_table(&ids, bucket_id, &sib_params, bins)
            })
            .collect();

        // Serialize
        let sib_path = format!("{}/merkle_sibling_L{}.bin", data_dir, level);
        {
            let header = cuckoo::write_header(&sib_params, bins, 0);
            let f = File::create(&sib_path).expect("create sibling file");
            let mut w = BufWriter::with_capacity(4 * 1024 * 1024, f);
            w.write_all(&header).unwrap();

            let zero_slot = vec![0u8; MERKLE_SIBLING_SLOT_SIZE];
            for bucket_id in 0..sib_params.k {
                let table = &tables[bucket_id];
                let items = &bucket_items[bucket_id];

                for slot_idx in 0..(bins * sib_params.cuckoo_bucket_size) {
                    let entry_local = table[slot_idx];
                    if entry_local == cuckoo::EMPTY {
                        w.write_all(&zero_slot).unwrap();
                    } else {
                        let local_idx = items[entry_local as usize];
                        let node_id = sibling_ids[local_idx];
                        let sib_hash = &sibling_hashes[local_idx];

                        // [4B node_index LE][32B sibling_hash]
                        w.write_all(&node_id.to_le_bytes()).unwrap();
                        w.write_all(sib_hash).unwrap();
                    }
                }
            }
            w.flush().unwrap();
        }

        let sib_size = std::fs::metadata(&sib_path).map(|m| m.len()).unwrap_or(0);
        println!("    L{}: {} nodes, bins={}, dpf_n={}, {:.1} MB ({:.2?})",
            level, sibling_ids.len(), bins, sib_params.dpf_n,
            sib_size as f64 / 1e6, t.elapsed());
    }

    // ── Done ────────────────────────────────────────────────────────────────

    println!();
    println!("=== Summary ===");
    println!("Merkle tree:     {} leaves, depth {}", tree.num_real_leaves, tree.depth);
    println!("MERKLE_DATA:     {}", format!("{}/merkle_data_cuckoo.bin", data_dir));
    println!("Sibling levels:  {} (L1..L{}, L0 embedded in MERKLE_DATA)", num_sibling_levels, num_sibling_levels);
    println!("Tree-top cache:  {} levels ({} nodes)", cache_from_level, top_cache.len());
    println!("Root:            {}", format!("{}/merkle_root.bin", data_dir));
    println!("Total time:      {:.1}s", t_total.elapsed().as_secs_f64());
}
