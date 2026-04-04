//! Integration test: verify random entries against the Merkle tree.
//!
//! For N randomly chosen index entries:
//! 1. Fetch chunk data and verify data_hash = SHA256(chunks)
//! 2. Look up the entry in MERKLE_DATA cuckoo table, verify tag + data_hash match
//! 3. Extract tree_loc and L0 sibling from MERKLE_DATA slot
//! 4. Compute leaf_hash = SHA256(scripthash || tree_loc || data_hash)
//! 5. Collect sibling hashes from L1..L15 cuckoo tables + tree-top cache
//! 6. Walk the proof up to the root and verify it matches merkle_root.bin

use memmap2::Mmap;
use pir_core::merkle::{self, Hash256, MERKLE_SIBLING_SLOT_SIZE};

/// Legacy MERKLE_DATA slot: [8B tag][4B tree_loc][32B data_hash][32B L0_sibling] = 76 bytes
const MERKLE_DATA_SLOT_SIZE: usize = 76;
use pir_core::hash;
use pir_core::params::*;
use std::fs::File;
use std::io::Read;

const DATA_DIR: &str = "/Volumes/Bitcoin/data";
const TAG_SEED: u64 = 0xd4e5f6a7b8c91023;
const CHUNK_SIZE: usize = 40;
const NUM_TEST_ENTRIES: usize = 100;

/// Read a cuckoo table file, return (bins_per_table, header_size, mmap).
/// Header layout: [8B magic][4B k][4B bucket_size][4B bins_per_table][4B num_hashes][8B master_seed][8B tag_seed?]
fn open_cuckoo_file(path: &str, header_size: usize) -> (usize, usize, Mmap) {
    let file = File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path, e));
    let mmap = unsafe { Mmap::map(&file).unwrap() };

    // bins_per_table is at offset 16 as u32 LE
    let bins = u32::from_le_bytes(mmap[16..20].try_into().unwrap()) as usize;
    (bins, header_size, mmap)
}

/// Look up a scripthash in a MERKLE_DATA cuckoo table.
/// Returns (tree_loc, data_hash, l0_sibling) or None.
fn lookup_merkle_data(
    mmap: &[u8],
    header_size: usize,
    bins_per_table: usize,
    bucket_size: usize,
    scripthash: &[u8; 20],
) -> Option<(u32, Hash256, Hash256)> {
    let expected_tag = hash::compute_tag(TAG_SEED, scripthash);
    let k = 75;
    let cuckoo_num_hashes = 2;
    let master_seed: u64 = 0x71a2ef38b4c90d15;

    let candidate_buckets = hash::derive_buckets_3(scripthash, k);

    for &bucket_id in &candidate_buckets {
        let keys: Vec<u64> = (0..cuckoo_num_hashes)
            .map(|hf| hash::derive_cuckoo_key(master_seed, bucket_id, hf))
            .collect();

        for hf in 0..cuckoo_num_hashes {
            let bin = hash::cuckoo_hash(scripthash, keys[hf], bins_per_table);

            for slot in 0..bucket_size {
                let global_slot = bucket_id * bins_per_table * bucket_size
                    + bin * bucket_size + slot;
                let offset = header_size + global_slot * MERKLE_DATA_SLOT_SIZE;

                if offset + MERKLE_DATA_SLOT_SIZE > mmap.len() { continue; }

                let slot_data = &mmap[offset..offset + MERKLE_DATA_SLOT_SIZE];
                let tag = u64::from_le_bytes(slot_data[0..8].try_into().unwrap());

                if tag == expected_tag && tag != 0 {
                    let tree_loc = u32::from_le_bytes(slot_data[8..12].try_into().unwrap());
                    let mut data_hash = [0u8; 32];
                    data_hash.copy_from_slice(&slot_data[12..44]);
                    let mut l0_sibling = [0u8; 32];
                    l0_sibling.copy_from_slice(&slot_data[44..76]);
                    return Some((tree_loc, data_hash, l0_sibling));
                }
            }
        }
    }
    None
}

/// Look up a node's sibling hash from a sibling cuckoo table.
fn lookup_sibling(
    mmap: &[u8],
    header_size: usize,
    bins_per_table: usize,
    bucket_size: usize,
    level: usize,
    node_local: u32,
) -> Option<Hash256> {
    let k = 75;
    let cuckoo_num_hashes = 2;
    let master_seed = 0xBA7C_51B1_0000_0000u64.wrapping_add(level as u64);

    let candidate_buckets = hash::derive_int_buckets_3(node_local, k);

    for &bucket_id in &candidate_buckets {
        let keys: Vec<u64> = (0..cuckoo_num_hashes)
            .map(|hf| hash::derive_cuckoo_key(master_seed, bucket_id, hf))
            .collect();

        for hf in 0..cuckoo_num_hashes {
            let bin = hash::cuckoo_hash_int(node_local, keys[hf], bins_per_table);

            for slot in 0..bucket_size {
                let global_slot = bucket_id * bins_per_table * bucket_size
                    + bin * bucket_size + slot;
                let offset = header_size + global_slot * MERKLE_SIBLING_SLOT_SIZE;

                if offset + MERKLE_SIBLING_SLOT_SIZE > mmap.len() { continue; }

                let slot_data = &mmap[offset..offset + MERKLE_SIBLING_SLOT_SIZE];
                let stored_id = u32::from_le_bytes(slot_data[0..4].try_into().unwrap());

                if stored_id == node_local {
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(&slot_data[4..36]);
                    return Some(hash);
                }
            }
        }
    }
    None
}

fn main() {
    println!("=== Merkle Verification Integration Test ===\n");

    // ── Load files ────────────────────────────────────────────────────────

    println!("[1] Loading data files...");

    // Index
    let index_file = File::open(INDEX_FILE).expect("open index");
    let index_mmap = unsafe { Mmap::map(&index_file).unwrap() };
    let num_entries = index_mmap.len() / INDEX_ENTRY_SIZE;
    println!("  Index: {} entries", num_entries);

    // Chunks
    let chunks_file = File::open(CHUNKS_DATA_FILE).expect("open chunks");
    let chunks_mmap = unsafe { Mmap::map(&chunks_file).unwrap() };
    println!("  Chunks: {} bytes", chunks_mmap.len());

    // Merkle root
    let root_path = format!("{}/merkle_root.bin", DATA_DIR);
    let mut root = [0u8; 32];
    File::open(&root_path).expect("open root").read_exact(&mut root).unwrap();
    println!("  Root: {:02x}{:02x}{:02x}{:02x}...", root[0], root[1], root[2], root[3]);

    // Tree-top cache
    let top_path = format!("{}/merkle_tree_top.bin", DATA_DIR);
    let top_data = std::fs::read(&top_path).expect("read tree-top");
    let cache_from_level = top_data[0] as usize;
    let num_cached = u32::from_le_bytes(top_data[1..5].try_into().unwrap()) as usize;
    let mut top_cache: Vec<Hash256> = Vec::with_capacity(num_cached);
    for i in 0..num_cached {
        let off = 5 + i * 32;
        let mut h = [0u8; 32];
        h.copy_from_slice(&top_data[off..off + 32]);
        top_cache.push(h);
    }
    println!("  Tree-top cache: {} levels, {} nodes", cache_from_level, num_cached);

    // MERKLE_DATA cuckoo table
    let md_path = format!("{}/merkle_data_cuckoo.bin", DATA_DIR);
    let (md_bins, md_header, md_mmap) = open_cuckoo_file(&md_path, 40);
    let md_bucket_size = 4;
    println!("  MERKLE_DATA: bins={}", md_bins);

    // Sibling cuckoo tables (L1..L16)
    // num_sibling_levels = depth - cache_from_level = 26 - 10 = 16
    let depth = 26;
    let num_sibling_levels = depth - cache_from_level; // 16
    let mut sib_tables: Vec<(usize, usize, Mmap)> = Vec::new(); // (bins, header_size, mmap)
    for level in 1..=num_sibling_levels {
        let path = format!("{}/merkle_sibling_L{}.bin", DATA_DIR, level);
        let (bins, header, mmap) = open_cuckoo_file(&path, 32);
        sib_tables.push((bins, header, mmap));
    }
    println!("  Loaded {} sibling tables (L1..L{})", num_sibling_levels, num_sibling_levels);

    // ── Test random entries ───────────────────────────────────────────────

    println!("\n[2] Testing {} random entries...\n", NUM_TEST_ENTRIES);

    let mut rng_state: u64 = 0xdeadbeef12345678;
    let mut pass = 0;
    let mut fail = 0;

    for test_i in 0..NUM_TEST_ENTRIES {
        // Simple splitmix64 PRNG
        rng_state = rng_state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = rng_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        let entry_idx = (z as usize) % num_entries;

        // Read index entry
        let base = entry_idx * INDEX_ENTRY_SIZE;
        let mut scripthash = [0u8; 20];
        scripthash.copy_from_slice(&index_mmap[base..base + 20]);
        let start_chunk_id = u32::from_le_bytes(
            index_mmap[base + 20..base + 24].try_into().unwrap()
        );
        let num_chunks = index_mmap[base + 24] as usize;

        // Step 1: Compute data_hash from chunks
        let data_hash = if num_chunks > 0 {
            let data_start = start_chunk_id as usize * CHUNK_SIZE;
            let data_end = data_start + num_chunks * CHUNK_SIZE;
            merkle::compute_data_hash(&chunks_mmap[data_start..data_end])
        } else {
            merkle::ZERO_HASH // whale sentinel
        };

        // Step 2: Look up in MERKLE_DATA
        let md_result = lookup_merkle_data(
            &md_mmap, md_header, md_bins, md_bucket_size, &scripthash,
        );

        let (tree_loc, stored_data_hash, l0_sibling) = match md_result {
            Some(v) => v,
            None => {
                println!("  [{}] FAIL entry {}: not found in MERKLE_DATA", test_i, entry_idx);
                fail += 1;
                continue;
            }
        };

        // Verify data_hash matches
        if data_hash != stored_data_hash {
            println!("  [{}] FAIL entry {}: data_hash mismatch", test_i, entry_idx);
            fail += 1;
            continue;
        }

        // Step 3: Compute leaf hash
        let leaf_hash = merkle::compute_leaf_hash(&scripthash, tree_loc, &data_hash);

        // Step 4: Collect siblings and walk up the tree
        // L0 from MERKLE_DATA, L1..L16 from sibling tables, L17..L25 from cache
        let mut current_hash = leaf_hash;
        let mut node_idx = tree_loc as usize; // local index at leaf level
        let mut verified = true;

        // L0: sibling from MERKLE_DATA
        if node_idx & 1 == 0 {
            current_hash = merkle::compute_parent(&current_hash, &l0_sibling);
        } else {
            current_hash = merkle::compute_parent(&l0_sibling, &current_hash);
        }
        node_idx >>= 1;

        // L1..L15: siblings from cuckoo tables
        for level in 1..=num_sibling_levels {
            let sibling_node = (node_idx ^ 1) as u32; // sibling's local index at this level
            let (sib_bins, sib_header, ref sib_mmap) = sib_tables[level - 1];

            let sibling_hash = match lookup_sibling(
                sib_mmap, sib_header, sib_bins, 4, level, node_idx as u32,
            ) {
                Some(h) => h,
                None => {
                    // Try looking up the sibling's own index
                    match lookup_sibling(
                        sib_mmap, sib_header, sib_bins, 4, level, sibling_node,
                    ) {
                        Some(h) => h,
                        None => {
                            println!("  [{}] FAIL entry {}: sibling not found at L{} node={}",
                                test_i, entry_idx, level, node_idx);
                            verified = false;
                            break;
                        }
                    }
                }
            };

            if node_idx & 1 == 0 {
                current_hash = merkle::compute_parent(&current_hash, &sibling_hash);
            } else {
                current_hash = merkle::compute_parent(&sibling_hash, &current_hash);
            }
            node_idx >>= 1;
        }

        if !verified {
            fail += 1;
            continue;
        }

        // L16..L25: siblings from tree-top cache
        // At this point, node_idx is the local index at level 16
        // Tree-top cache stores nodes at levels [depth - cache_from_level .. depth]
        // which is levels [16..26], corresponding to tree node indices [1..1024)
        // At level L (from root=0), there are 2^L nodes.
        // Our node at level 16 has a global 1-indexed tree position.
        for level in (num_sibling_levels + 1)..depth {
            let sibling_local = node_idx ^ 1;

            // Cache stores 1-indexed nodes from level (depth - cache_from_level) up to root
            // At level `level` (counting from leaves=0, root=depth), the tree level from root is (depth - level).
            // Nodes at tree level L from root are at 1-indexed positions [2^L, 2^(L+1)).
            let tree_level_from_root = depth - level;
            let cache_idx = (1 << tree_level_from_root) + sibling_local;

            if cache_idx == 0 || cache_idx > top_cache.len() {
                println!("  [{}] FAIL entry {}: cache index {} out of range at level {}",
                    test_i, entry_idx, cache_idx, level);
                verified = false;
                break;
            }

            let sibling_hash = top_cache[cache_idx - 1]; // 1-indexed to 0-indexed

            if node_idx & 1 == 0 {
                current_hash = merkle::compute_parent(&current_hash, &sibling_hash);
            } else {
                current_hash = merkle::compute_parent(&sibling_hash, &current_hash);
            }
            node_idx >>= 1;
        }

        if !verified {
            fail += 1;
            continue;
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
    println!("Passed: {}/{}", pass, NUM_TEST_ENTRIES);
    println!("Failed: {}/{}", fail, NUM_TEST_ENTRIES);

    if fail > 0 {
        std::process::exit(1);
    }
    println!("\nAll entries verified successfully!");
}
