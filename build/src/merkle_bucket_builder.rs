//! Per-bucket bin Merkle tree builder.
//!
//! For each PBC group in the INDEX and CHUNK cuckoo tables, builds an arity-8
//! Merkle tree over the bins. The leaf hash for bin i is:
//!   SHA256(bin_index_u32_LE || bin_content)
//!
//! Sibling tables are flat (no cuckoo hashing): row[group_id] = [arity × 32B].
//! This works because the group_id is a deterministic index into the parent
//! level's node array — the client knows exactly which row to query.
//!
//! The flat table file reuses the standard 32B cuckoo-compatible header:
//!   [8B magic][4B k][4B slots_per_bin=1][4B num_rows][4B num_hashes=0][8B seed]
//!   Body: k × num_rows × 256B
//! Group g's data starts at offset header + g × (num_rows × 256).

use memmap2::Mmap;
use pir_core::hash;
use pir_core::merkle::{self, Hash256, ZERO_HASH};
use pir_core::params::*;
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Instant;

const ARITY: usize = 8;
const SIB_ROW_SIZE: usize = ARITY * 32; // 256 bytes per sibling row
const TREE_TOP_THRESHOLD: usize = 1024;

/// Magic numbers for bucket Merkle sibling tables.
/// Format: 0xBA7C_B0TT_00LL_0000 where TT=table_type (00=idx, 01=chunk), LL=level.
fn bucket_sib_magic(table_type: u8, level: u8) -> u64 {
    0xBA7C_B000_0000_0000u64
        | ((table_type as u64) << 40)
        | ((level as u64) << 16)
}

/// Build per-bucket Merkle trees for both INDEX and CHUNK tables.
pub fn build_bucket_merkle(data_dir: &str) {
    let t0 = Instant::now();
    println!("=== Per-Bucket Bin Merkle Builder ===");
    println!("Data dir: {}", data_dir);
    println!("Arity: {}", ARITY);
    println!();

    // Load INDEX cuckoo table
    let index_path = Path::new(data_dir).join("batch_pir_cuckoo.bin");
    let index_mmap = mmap_file(&index_path);
    let (index_bins, _tag_seed) = hash::read_cuckoo_header(
        &index_mmap, INDEX_PARAMS.magic, INDEX_PARAMS.header_size, INDEX_PARAMS.has_tag_seed,
    );
    let index_bin_size = INDEX_PARAMS.bin_size();
    println!("[INDEX] bins_per_table={}, bin_size={}B, K={}", index_bins, index_bin_size, INDEX_PARAMS.k);

    // Load CHUNK cuckoo table
    let chunk_path = Path::new(data_dir).join("chunk_pir_cuckoo.bin");
    let chunk_mmap = mmap_file(&chunk_path);
    let (chunk_bins, _) = hash::read_cuckoo_header(
        &chunk_mmap, CHUNK_PARAMS.magic, CHUNK_PARAMS.header_size, CHUNK_PARAMS.has_tag_seed,
    );
    let chunk_bin_size = CHUNK_PARAMS.bin_size();
    println!("[CHUNK] bins_per_table={}, bin_size={}B, K={}", chunk_bins, chunk_bin_size, CHUNK_PARAMS.k);
    println!();

    // Build trees for INDEX groups
    println!("[1] Building INDEX Merkle trees ({} groups, {} bins each)...", INDEX_PARAMS.k, index_bins);
    let t = Instant::now();
    let index_trees: Vec<PerGroupTree> = (0..INDEX_PARAMS.k)
        .into_par_iter()
        .map(|g| {
            build_group_tree(
                &index_mmap,
                INDEX_PARAMS.header_size,
                g,
                index_bins,
                index_bin_size,
            )
        })
        .collect();
    println!("    Done in {:.2?}", t.elapsed());

    // Build trees for CHUNK groups
    println!("[2] Building CHUNK Merkle trees ({} groups, {} bins each)...", CHUNK_PARAMS.k, chunk_bins);
    let t = Instant::now();
    let chunk_trees: Vec<PerGroupTree> = (0..CHUNK_PARAMS.k)
        .into_par_iter()
        .map(|g| {
            build_group_tree(
                &chunk_mmap,
                CHUNK_PARAMS.header_size,
                g,
                chunk_bins,
                chunk_bin_size,
            )
        })
        .collect();
    println!("    Done in {:.2?}", t.elapsed());

    // Determine sibling level structure
    let index_sib_levels = compute_sibling_levels(index_bins);
    let chunk_sib_levels = compute_sibling_levels(chunk_bins);
    println!();
    println!("INDEX sibling levels: {} (groups: {:?})", index_sib_levels.len(),
        index_sib_levels.iter().map(|&n| n).collect::<Vec<_>>());
    println!("CHUNK sibling levels: {} (groups: {:?})", chunk_sib_levels.len(),
        chunk_sib_levels.iter().map(|&n| n).collect::<Vec<_>>());

    // Write sibling tables
    println!();
    println!("[3] Writing flat sibling tables...");

    for (level_idx, &num_groups) in index_sib_levels.iter().enumerate() {
        let path = Path::new(data_dir).join(format!("merkle_bucket_index_sib_L{}.bin", level_idx));
        let magic = bucket_sib_magic(0, level_idx as u8);
        write_flat_sibling_table(&path, &index_trees, level_idx, num_groups, INDEX_PARAMS.k, magic);
    }

    for (level_idx, &num_groups) in chunk_sib_levels.iter().enumerate() {
        let path = Path::new(data_dir).join(format!("merkle_bucket_chunk_sib_L{}.bin", level_idx));
        let magic = bucket_sib_magic(1, level_idx as u8);
        write_flat_sibling_table(&path, &chunk_trees, level_idx, num_groups, CHUNK_PARAMS.k, magic);
    }

    // Write tree-top caches (all 155 trees concatenated)
    println!("[4] Writing tree-top caches...");
    let tree_tops_path = Path::new(data_dir).join("merkle_bucket_tree_tops.bin");
    write_tree_tops(&tree_tops_path, &index_trees, &chunk_trees, &index_sib_levels, &chunk_sib_levels);

    // Write roots
    println!("[5] Writing roots...");
    let mut all_roots: Vec<Hash256> = Vec::with_capacity(INDEX_PARAMS.k + CHUNK_PARAMS.k);
    for tree in &index_trees {
        all_roots.push(tree.root);
    }
    for tree in &chunk_trees {
        all_roots.push(tree.root);
    }

    let roots_path = Path::new(data_dir).join("merkle_bucket_roots.bin");
    let mut f = BufWriter::new(File::create(&roots_path).expect("create roots"));
    for root in &all_roots {
        f.write_all(root).unwrap();
    }
    f.flush().unwrap();
    println!("    {} roots ({} bytes)", all_roots.len(), all_roots.len() * 32);

    // Compute and write super-root
    let mut super_preimage = Vec::with_capacity(all_roots.len() * 32);
    for root in &all_roots {
        super_preimage.extend_from_slice(root);
    }
    let super_root = merkle::sha256(&super_preimage);

    let super_root_path = Path::new(data_dir).join("merkle_bucket_root.bin");
    std::fs::write(&super_root_path, &super_root).expect("write super root");
    println!("    Super-root: {:02x}{:02x}{:02x}{:02x}...", super_root[0], super_root[1], super_root[2], super_root[3]);

    println!();
    println!("=== Done in {:.2?} ===", t0.elapsed());

    // Summary
    println!();
    println!("Summary:");
    println!("  INDEX: {} groups, {} bins/group, {} sibling levels", INDEX_PARAMS.k, index_bins, index_sib_levels.len());
    println!("  CHUNK: {} groups, {} bins/group, {} sibling levels", CHUNK_PARAMS.k, chunk_bins, chunk_sib_levels.len());
    for (level_idx, &num_groups) in index_sib_levels.iter().enumerate() {
        let file_size = INDEX_PARAMS.k * num_groups * SIB_ROW_SIZE + 32;
        println!("  merkle_bucket_index_sib_L{}: {} groups/tree, {:.1} MB",
            level_idx, num_groups, file_size as f64 / 1e6);
    }
    for (level_idx, &num_groups) in chunk_sib_levels.iter().enumerate() {
        let file_size = CHUNK_PARAMS.k * num_groups * SIB_ROW_SIZE + 32;
        println!("  merkle_bucket_chunk_sib_L{}: {} groups/tree, {:.1} MB",
            level_idx, num_groups, file_size as f64 / 1e6);
    }
}

// ─── Per-group tree ───────────────────────────────────────────────────────

/// Result of building a Merkle tree for one PBC group.
struct PerGroupTree {
    /// All levels of the tree. levels[0] = leaf hashes, levels[depth] = [root].
    levels: Vec<Vec<Hash256>>,
    /// Root hash.
    root: Hash256,
}

/// Build the arity-8 Merkle tree for one PBC group.
///
/// Does NOT pad to the next power of arity — handles incomplete final
/// groups at each level by padding with ZERO_HASH. This avoids inflating
/// tree-top caches (e.g. 565K bins padded to 2.1M would waste 30× space).
fn build_group_tree(
    mmap: &[u8],
    header_size: usize,
    group_id: usize,
    bins_per_table: usize,
    bin_size: usize,
) -> PerGroupTree {
    let table_byte_size = bins_per_table * bin_size;
    let group_offset = header_size + group_id * table_byte_size;
    let group_data = &mmap[group_offset..group_offset + table_byte_size];

    // Compute leaf hashes: leaf[i] = SHA256(i_u32_LE || bin_content)
    let leaf_hashes: Vec<Hash256> = (0..bins_per_table)
        .map(|i| {
            let bin_start = i * bin_size;
            let bin_content = &group_data[bin_start..bin_start + bin_size];
            merkle::compute_bin_leaf_hash(i as u32, bin_content)
        })
        .collect();

    // Build tree bottom-up WITHOUT padding to next power of arity.
    // Incomplete final groups are padded with ZERO_HASH.
    let mut levels: Vec<Vec<Hash256>> = Vec::new();
    levels.push(leaf_hashes);

    loop {
        let prev = levels.last().unwrap();
        if prev.len() <= 1 { break; }
        let next_len = (prev.len() + ARITY - 1) / ARITY;
        let mut next_level = Vec::with_capacity(next_len);
        for i in 0..next_len {
            let start = i * ARITY;
            let end = (start + ARITY).min(prev.len());
            let mut children: Vec<Hash256> = prev[start..end].to_vec();
            children.resize(ARITY, ZERO_HASH); // pad incomplete group
            next_level.push(merkle::compute_parent_n(&children));
        }
        levels.push(next_level);
    }

    let root = levels.last().unwrap()[0];
    PerGroupTree { levels, root }
}

// ─── Sibling level computation ────────────────────────────────────────────

/// Compute which sibling levels need PIR queries (below the tree-top threshold).
/// Returns a vector of num_groups per sibling level.
fn compute_sibling_levels(bins_per_table: usize) -> Vec<usize> {
    let mut levels = Vec::new();
    let mut nodes_at_level = bins_per_table;

    loop {
        let num_groups = (nodes_at_level + ARITY - 1) / ARITY;
        if num_groups <= TREE_TOP_THRESHOLD {
            break;
        }
        levels.push(num_groups);
        nodes_at_level = num_groups;
    }
    levels
}

// ─── Flat sibling table writer ────────────────────────────────────────────

/// Write a flat sibling table for one level across all K groups.
///
/// File format:
///   [32B header: magic, k, slots_per_bin=1, num_rows, num_hashes=0, seed=0]
///   Body: k × num_rows × 256B
///
/// For group g, row r: levels[level_idx + 1] node at position r, which is
/// the parent of children [r*8 .. r*8+7] at levels[level_idx].
/// Each row = [child_0 hash (32B)][child_1]...[child_7] = 256B.
fn write_flat_sibling_table(
    path: &Path,
    trees: &[PerGroupTree],
    level_idx: usize,
    num_groups: usize,
    k: usize,
    magic: u64,
) {
    let t = Instant::now();
    let f = File::create(path).expect("create sibling table");
    let mut w = BufWriter::with_capacity(16 * 1024 * 1024, f);

    // Write 32-byte header (cuckoo-compatible)
    w.write_all(&magic.to_le_bytes()).unwrap();        // 0-7: magic
    w.write_all(&(k as u32).to_le_bytes()).unwrap();   // 8-11: k
    w.write_all(&1u32.to_le_bytes()).unwrap();          // 12-15: slots_per_bin = 1
    w.write_all(&(num_groups as u32).to_le_bytes()).unwrap(); // 16-19: bins_per_table = num_groups
    w.write_all(&0u32.to_le_bytes()).unwrap();          // 20-23: num_hashes = 0 (flat, no cuckoo)
    w.write_all(&0u64.to_le_bytes()).unwrap();          // 24-31: master_seed = 0

    // Write body: k groups × num_groups rows × 256B per row
    // For level L of the tree, level_idx maps to tree.levels[level_idx].
    // At level_idx in the tree, nodes are the LEAVES of the sibling query.
    // The sibling row for group_id g at parent r contains the ARITY children:
    //   tree.levels[level_idx][r*ARITY + 0], ..., tree.levels[level_idx][r*ARITY + ARITY-1]
    // These children's parent is tree.levels[level_idx + 1][r].
    for g in 0..k {
        let tree = &trees[g];
        // The children live at tree.levels[level_idx]
        // (level_idx here corresponds to the Merkle tree level where the children are)
        // Sibling L0 queries: children are at levels[0] (the leaves), grouped into parents
        // Sibling L1 queries: children are at levels[1], etc.
        // So the children are at tree.levels[sib_tree_level] where sib_tree_level is
        // the tree level index.
        //
        // For sibling level 0: children are leaves (tree.levels[0]), parents at levels[1]
        // For sibling level 1: children are levels[1] nodes, parents at levels[2]
        // So sib_tree_level = level_idx
        let children_level = &tree.levels[level_idx];

        for r in 0..num_groups {
            let start = r * ARITY;
            for c in 0..ARITY {
                let idx = start + c;
                if idx < children_level.len() {
                    w.write_all(&children_level[idx]).unwrap();
                } else {
                    w.write_all(&ZERO_HASH).unwrap();
                }
            }
        }
    }

    w.flush().unwrap();
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    println!("    {} — {} groups × {} rows × 256B = {:.1} MB ({:.2?})",
        path.file_name().unwrap().to_str().unwrap(),
        k, num_groups, file_size as f64 / 1e6, t.elapsed());
}

// ─── Tree-top cache writer ────────────────────────────────────────────────

/// Write tree-top caches for all 155 groups.
///
/// Format:
///   [4B num_trees LE]
///   Per tree:
///     [1B cache_from_level][4B total_nodes LE][2B arity LE][1B num_cached_levels]
///     Per cached level: [4B num_nodes LE][num_nodes × 32B hashes]
fn write_tree_tops(
    path: &Path,
    index_trees: &[PerGroupTree],
    chunk_trees: &[PerGroupTree],
    index_sib_levels: &[usize],
    chunk_sib_levels: &[usize],
) {
    let f = File::create(path).expect("create tree tops");
    let mut w = BufWriter::with_capacity(4 * 1024 * 1024, f);

    let num_trees = (index_trees.len() + chunk_trees.len()) as u32;
    w.write_all(&num_trees.to_le_bytes()).unwrap();

    // INDEX tree-tops: cache_from_level = number of PIR sibling levels
    for tree in index_trees {
        write_one_tree_top(&mut w, tree, index_sib_levels.len());
    }

    // CHUNK tree-tops: cache_from_level = number of PIR sibling levels
    for tree in chunk_trees {
        write_one_tree_top(&mut w, tree, chunk_sib_levels.len());
    }

    w.flush().unwrap();
    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    println!("    tree_tops: {} trees, {:.1} MB", num_trees, file_size as f64 / 1e6);
}

fn write_one_tree_top(w: &mut impl Write, tree: &PerGroupTree, cache_from_level: usize) {
    let num_cached_levels = tree.levels.len().saturating_sub(cache_from_level);
    let total_nodes: usize = tree.levels[cache_from_level..].iter().map(|l| l.len()).sum();

    w.write_all(&[cache_from_level as u8]).unwrap();
    w.write_all(&(total_nodes as u32).to_le_bytes()).unwrap();
    w.write_all(&(ARITY as u16).to_le_bytes()).unwrap();
    w.write_all(&[num_cached_levels as u8]).unwrap();

    for level in &tree.levels[cache_from_level..] {
        w.write_all(&(level.len() as u32).to_le_bytes()).unwrap();
        for hash in level {
            w.write_all(hash).unwrap();
        }
    }
}

// ─── Utility ──────────────────────────────────────────────────────────────

fn mmap_file(path: &Path) -> Mmap {
    let f = File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path.display(), e));
    unsafe { Mmap::map(&f) }.unwrap_or_else(|e| panic!("mmap {}: {}", path.display(), e))
}
