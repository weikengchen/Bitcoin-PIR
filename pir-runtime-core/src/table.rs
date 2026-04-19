//! Shared cuckoo table loading for PIR servers.
//!
//! Provides both the legacy `CuckooTablePair` (loads exactly two files)
//! and the new `MappedSubTable` / `MappedDatabase` types that support
//! multiple databases with different parameters.

use memmap2::Mmap;
use pir_core::params::{
    TableParams, CHUNK_CUCKOO_FILE, CHUNK_SIZE, CHUNK_SLOTS_PER_BIN, CUCKOO_FILE, HEADER_SIZE,
    INDEX_SLOTS_PER_BIN, INDEX_SLOT_SIZE, MAGIC,
};
use std::fs::File;
use std::path::Path;

// Wrappers kept local (moved from the ex-`build::common`) so table.rs's
// call sites stay readable — `read_cuckoo_header(bytes)` vs the full
// pir-core signature with four arguments.
fn read_cuckoo_header(data: &[u8]) -> (usize, u64) {
    pir_core::hash::read_cuckoo_header(data, MAGIC, HEADER_SIZE, true)
}

fn read_chunk_cuckoo_header(data: &[u8]) -> usize {
    pir_core::hash::read_chunk_cuckoo_header(data)
}

// ─── New generic types ─────────────────────────────────────────────────────

/// A single memory-mapped cuckoo sub-table with its parameters.
pub struct MappedSubTable {
    /// Memory-mapped file contents.
    pub mmap: Mmap,
    /// Parameters that describe this table's layout.
    pub params: TableParams,
    /// Number of cuckoo bins per PBC group (read from header).
    pub bins_per_table: usize,
    /// Byte size of one group's sub-table (bins × slots_per_bin × slot_size).
    pub table_byte_size: usize,
    /// Tag seed from header (0 if the table has no tag seed).
    pub tag_seed: u64,
}

impl MappedSubTable {
    /// Load and memory-map a cuckoo table file.
    pub fn load(path: &Path, params: TableParams) -> Self {
        println!("  Loading sub-table: {}", path.display());
        let f = File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path.display(), e));
        let mmap = unsafe { Mmap::map(&f) }.unwrap_or_else(|e| panic!("mmap {}: {}", path.display(), e));

        let (bins_per_table, tag_seed) = pir_core::hash::read_cuckoo_header(
            &mmap,
            params.magic,
            params.header_size,
            params.has_tag_seed,
        );
        let table_byte_size = params.table_byte_size(bins_per_table);

        println!(
            "    bins_per_table={}, slot={}B, table={:.1}MB, file={:.2}GB",
            bins_per_table,
            params.slot_size,
            table_byte_size as f64 / (1024.0 * 1024.0),
            mmap.len() as f64 / (1024.0 * 1024.0 * 1024.0),
        );
        if params.has_tag_seed {
            println!("    tag_seed=0x{:016x}", tag_seed);
        }

        #[cfg(unix)]
        {
            use libc::{madvise, MADV_SEQUENTIAL};
            unsafe {
                madvise(mmap.as_ptr() as *mut libc::c_void, mmap.len(), MADV_SEQUENTIAL);
            }
        }

        MappedSubTable { mmap, params, bins_per_table, table_byte_size, tag_seed }
    }

    /// Get the byte slice for a specific group's sub-table.
    pub fn group_bytes(&self, group_id: usize) -> &[u8] {
        let offset = self.params.header_size + group_id * self.table_byte_size;
        &self.mmap[offset..offset + self.table_byte_size]
    }
}

/// Describes a complete PIR database (INDEX + CHUNK + optional Merkle sub-tables).
/// Whether a database is a full UTXO snapshot or a delta between two heights.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DatabaseType {
    /// Full UTXO set at a single height (base_height is always 0).
    Full,
    /// Delta (new + spent UTXOs) between base_height and height.
    Delta,
}

pub struct DatabaseDescriptor {
    /// Human-readable name (e.g. "main", "delta_940611_944000").
    pub name: String,
    /// Full or delta.
    pub db_type: DatabaseType,
    /// Starting height (0 for full snapshots, >0 for deltas).
    pub base_height: u32,
    /// Snapshot height (full) or end height (delta).
    pub height: u32,
    /// Parameters for the INDEX-level sub-table.
    pub index_params: TableParams,
    /// Parameters for the CHUNK-level sub-table.
    pub chunk_params: TableParams,
}

/// A fully loaded database with all sub-tables memory-mapped.
pub struct MappedDatabase {
    /// Descriptor for this database.
    pub descriptor: DatabaseDescriptor,
    /// INDEX-level cuckoo table.
    pub index: MappedSubTable,
    /// CHUNK-level cuckoo table.
    pub chunk: MappedSubTable,
    /// Per-level sibling cuckoo tables (empty if Merkle not built).
    pub merkle_siblings: Vec<MappedSubTable>,
    /// Cached top of the Merkle tree (node hashes).
    pub merkle_tree_top: Option<Vec<u8>>,
    /// Merkle root hash (32 bytes).
    pub merkle_root: Option<Vec<u8>>,
    /// Merkle tree arity (e.g. 8 for DPF, 120 for OnionPIR). 0 if no Merkle.
    pub merkle_arity: usize,

    // ── Per-bucket bin Merkle ────────────────────────────────────────────
    /// Flat sibling tables for INDEX-level per-bucket Merkle (L0, L1, ...).
    pub bucket_merkle_index_siblings: Vec<MappedSubTable>,
    /// Flat sibling tables for CHUNK-level per-bucket Merkle (L0, L1, ...).
    pub bucket_merkle_chunk_siblings: Vec<MappedSubTable>,
    /// Tree-top caches for all 155 per-bucket trees.
    pub bucket_merkle_tree_tops: Option<Vec<u8>>,
    /// Per-group roots: 155 × 32B (75 index + 80 chunk).
    pub bucket_merkle_roots: Option<Vec<u8>>,
    /// Super-root: SHA256 of all 155 roots concatenated.
    pub bucket_merkle_root: Option<Vec<u8>>,
}

impl MappedDatabase {
    /// Load a database from a directory containing cuckoo table files.
    ///
    /// Automatically detects and loads Merkle sub-tables if present.
    pub fn load(base_dir: &Path, descriptor: DatabaseDescriptor) -> Self {
        println!("[DB:{}] Loading from {}", descriptor.name, base_dir.display());

        let index = MappedSubTable::load(
            &base_dir.join("batch_pir_cuckoo.bin"),
            descriptor.index_params.clone(),
        );
        let chunk = MappedSubTable::load(
            &base_dir.join("chunk_pir_cuckoo.bin"),
            descriptor.chunk_params.clone(),
        );

        // Try to load Merkle sibling tables (DPF: _dpf suffix, then fallback to no suffix)
        let mut merkle_siblings = Vec::new();
        let mut merkle_arity = 0usize;

        // Detect arity from tree-top cache header (byte 5-6 = arity LE u16)
        let top_dpf = base_dir.join("merkle_tree_top_dpf.bin");
        let top_plain = base_dir.join("merkle_tree_top.bin");
        let (top_path, sib_prefix) = if top_dpf.exists() {
            (top_dpf, "merkle_sibling_dpf")
        } else if top_plain.exists() {
            (top_plain, "merkle_sibling")
        } else {
            (top_plain, "") // no Merkle
        };

        let merkle_tree_top = std::fs::read(&top_path).ok();
        if let Some(ref top_data) = merkle_tree_top {
            if top_data.len() >= 8 {
                merkle_arity = u16::from_le_bytes(top_data[5..7].try_into().unwrap()) as usize;
            }
        }

        if merkle_arity > 0 && !sib_prefix.is_empty() {
            let sib_slot_size = pir_core::merkle::merkle_sibling_slot_size(merkle_arity);
            for level in 0.. {
                let sib_path = base_dir.join(format!("{}_L{}.bin", sib_prefix, level));
                if !sib_path.exists() { break; }
                println!("  Loading {} L{} (arity={}, slot={}B)...", sib_prefix, level, merkle_arity, sib_slot_size);
                let params = pir_core::params::TableParams {
                    k: 75,
                    num_hashes: 3,
                    master_seed: 0xBA7C_51B1_0000_0000u64.wrapping_add(level as u64),
                    slots_per_bin: 4,
                    cuckoo_num_hashes: 2,
                    slot_size: sib_slot_size,
                    dpf_n: 0, // read from file header
                    magic: 0xBA7C_51B1_0000_0000u64 | (level as u64),
                    header_size: 32,
                    has_tag_seed: false,
                };
                merkle_siblings.push(MappedSubTable::load(&sib_path, params));
            }
        }

        // Load Merkle root
        let root_dpf = base_dir.join("merkle_root_dpf.bin");
        let root_plain = base_dir.join("merkle_root.bin");
        let merkle_root = std::fs::read(&root_dpf).ok()
            .or_else(|| std::fs::read(&root_plain).ok());

        if !merkle_siblings.is_empty() {
            println!("  Merkle: arity={}, {} sibling levels, tree-top={}, root={}",
                merkle_arity, merkle_siblings.len(),
                if merkle_tree_top.is_some() { "yes" } else { "no" },
                if merkle_root.is_some() { "yes" } else { "no" },
            );
        }

        // ── Load per-bucket bin Merkle files ──────────────────────────────
        let mut bucket_merkle_index_siblings = Vec::new();
        let mut bucket_merkle_chunk_siblings = Vec::new();

        // INDEX sibling tables: merkle_bucket_index_sib_L0.bin, L1.bin, ...
        for level in 0.. {
            let path = base_dir.join(format!("merkle_bucket_index_sib_L{}.bin", level));
            if !path.exists() { break; }
            let magic = 0xBA7C_B000_0000_0000u64 | ((level as u64) << 16);
            let params = pir_core::params::TableParams {
                k: descriptor.index_params.k,
                num_hashes: 0,
                master_seed: 0,
                slots_per_bin: 1,
                cuckoo_num_hashes: 0,
                slot_size: 8 * 32, // 256B per row (arity=8 × 32B hashes)
                dpf_n: 0,
                magic,
                header_size: 32,
                has_tag_seed: false,
            };
            println!("  Loading bucket Merkle INDEX sib L{} (slot=256B)...", level);
            bucket_merkle_index_siblings.push(MappedSubTable::load(&path, params));
        }

        // CHUNK sibling tables: merkle_bucket_chunk_sib_L0.bin, L1.bin, ...
        for level in 0.. {
            let path = base_dir.join(format!("merkle_bucket_chunk_sib_L{}.bin", level));
            if !path.exists() { break; }
            let magic = 0xBA7C_B000_0000_0000u64 | (1u64 << 40) | ((level as u64) << 16);
            let params = pir_core::params::TableParams {
                k: descriptor.chunk_params.k,
                num_hashes: 0,
                master_seed: 0,
                slots_per_bin: 1,
                cuckoo_num_hashes: 0,
                slot_size: 8 * 32,
                dpf_n: 0,
                magic,
                header_size: 32,
                has_tag_seed: false,
            };
            println!("  Loading bucket Merkle CHUNK sib L{} (slot=256B)...", level);
            bucket_merkle_chunk_siblings.push(MappedSubTable::load(&path, params));
        }

        let bucket_merkle_tree_tops = std::fs::read(base_dir.join("merkle_bucket_tree_tops.bin")).ok();
        let bucket_merkle_roots = std::fs::read(base_dir.join("merkle_bucket_roots.bin")).ok();
        let bucket_merkle_root = std::fs::read(base_dir.join("merkle_bucket_root.bin")).ok();

        if !bucket_merkle_index_siblings.is_empty() {
            println!("  Bucket Merkle: {} INDEX sib levels, {} CHUNK sib levels, tree-tops={}, super-root={}",
                bucket_merkle_index_siblings.len(),
                bucket_merkle_chunk_siblings.len(),
                if bucket_merkle_tree_tops.is_some() { "yes" } else { "no" },
                if bucket_merkle_root.is_some() { "yes" } else { "no" },
            );
        }

        MappedDatabase {
            descriptor, index, chunk,
            merkle_siblings, merkle_tree_top, merkle_root, merkle_arity,
            bucket_merkle_index_siblings, bucket_merkle_chunk_siblings,
            bucket_merkle_tree_tops, bucket_merkle_roots, bucket_merkle_root,
        }
    }

    /// Whether this database has (legacy) global Merkle verification data.
    pub fn has_merkle(&self) -> bool {
        !self.merkle_siblings.is_empty()
    }

    /// Whether this database has per-bucket bin Merkle verification data.
    pub fn has_bucket_merkle(&self) -> bool {
        !self.bucket_merkle_index_siblings.is_empty()
    }
}

/// Server state holding multiple databases.
pub struct ServerState {
    /// All loaded databases. Index 0 is typically the main UTXO database.
    pub databases: Vec<MappedDatabase>,
}

impl ServerState {
    /// Get a database by index. Returns None if db_id is out of range.
    pub fn get_db(&self, db_id: u8) -> Option<&MappedDatabase> {
        self.databases.get(db_id as usize)
    }
}

// ─── Legacy CuckooTablePair (backward compatible) ──────────────────────────

/// A pair of memory-mapped cuckoo tables (index + chunk).
///
/// This is the legacy loading interface. New code should use
/// `MappedDatabase` instead.
pub struct CuckooTablePair {
    /// Memory-mapped index cuckoo table.
    pub index_cuckoo: Mmap,
    /// Number of bins per sub-table in the index cuckoo.
    pub index_bins_per_table: usize,
    /// Total byte size of one index sub-table (bins × slots_per_bin × slot_size).
    pub index_table_byte_size: usize,
    /// Fingerprint tag seed from the index cuckoo header.
    pub tag_seed: u64,

    /// Memory-mapped chunk cuckoo table.
    pub chunk_cuckoo: Mmap,
    /// Number of bins per sub-table in the chunk cuckoo.
    pub chunk_bins_per_table: usize,
    /// Total byte size of one chunk sub-table.
    pub chunk_table_byte_size: usize,
}

impl CuckooTablePair {
    /// Load and memory-map both cuckoo table files.
    ///
    /// Reads headers to extract layout parameters and applies madvise
    /// hints for sequential access patterns.
    pub fn load() -> Self {
        println!("[1] Loading index cuckoo: {}", CUCKOO_FILE);
        let f = File::open(CUCKOO_FILE).expect("open index cuckoo");
        let index_cuckoo = unsafe { Mmap::map(&f) }.expect("mmap index cuckoo");
        let (index_bins_per_table, tag_seed) = read_cuckoo_header(&index_cuckoo);
        let index_table_byte_size = index_bins_per_table * INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE;
        println!(
            "  bins_per_table = {}, slot_size = {}B, table_size = {:.1} MB",
            index_bins_per_table,
            INDEX_SLOT_SIZE,
            index_table_byte_size as f64 / (1024.0 * 1024.0)
        );
        println!("  tag_seed = 0x{:016x}", tag_seed);
        println!(
            "  total file = {:.2} GB",
            index_cuckoo.len() as f64 / (1024.0 * 1024.0 * 1024.0)
        );

        #[cfg(unix)]
        {
            use libc::{madvise, MADV_SEQUENTIAL};
            unsafe {
                madvise(
                    index_cuckoo.as_ptr() as *mut libc::c_void,
                    index_cuckoo.len(),
                    MADV_SEQUENTIAL,
                );
            }
        }

        println!("[2] Loading chunk cuckoo: {}", CHUNK_CUCKOO_FILE);
        let f = File::open(CHUNK_CUCKOO_FILE).expect("open chunk cuckoo");
        let chunk_cuckoo = unsafe { Mmap::map(&f) }.expect("mmap chunk cuckoo");
        let chunk_bins_per_table = read_chunk_cuckoo_header(&chunk_cuckoo);
        let chunk_slot_size = 4 + CHUNK_SIZE;
        let chunk_table_byte_size =
            chunk_bins_per_table * CHUNK_SLOTS_PER_BIN * chunk_slot_size;
        println!(
            "  bins_per_table = {}, slot_size = {}B, table_size = {:.1} MB",
            chunk_bins_per_table,
            chunk_slot_size,
            chunk_table_byte_size as f64 / (1024.0 * 1024.0)
        );
        println!(
            "  total file = {:.2} GB",
            chunk_cuckoo.len() as f64 / (1024.0 * 1024.0 * 1024.0)
        );

        #[cfg(unix)]
        {
            use libc::{madvise, MADV_SEQUENTIAL};
            unsafe {
                madvise(
                    chunk_cuckoo.as_ptr() as *mut libc::c_void,
                    chunk_cuckoo.len(),
                    MADV_SEQUENTIAL,
                );
            }
        }

        CuckooTablePair {
            index_cuckoo,
            index_bins_per_table,
            index_table_byte_size,
            tag_seed,
            chunk_cuckoo,
            chunk_bins_per_table,
            chunk_table_byte_size,
        }
    }
}
