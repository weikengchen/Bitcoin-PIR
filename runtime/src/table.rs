//! Shared cuckoo table loading for PIR servers.
//!
//! Provides both the legacy `CuckooTablePair` (loads exactly two files)
//! and the new `MappedSubTable` / `MappedDatabase` types that support
//! multiple databases with different parameters.

use build::common::*;
use memmap2::Mmap;
use pir_core::params::TableParams;
use std::fs::File;
use std::path::Path;

// ─── New generic types ─────────────────────────────────────────────────────

/// A single memory-mapped cuckoo sub-table with its parameters.
pub struct MappedSubTable {
    /// Memory-mapped file contents.
    pub mmap: Mmap,
    /// Parameters that describe this table's layout.
    pub params: TableParams,
    /// Number of cuckoo bins per Batch PIR bucket (read from header).
    pub bins_per_table: usize,
    /// Byte size of one bucket's sub-table (bins × bucket_size × slot_size).
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

    /// Get the byte slice for a specific bucket's sub-table.
    pub fn bucket_bytes(&self, bucket_id: usize) -> &[u8] {
        let offset = self.params.header_size + bucket_id * self.table_byte_size;
        &self.mmap[offset..offset + self.table_byte_size]
    }
}

/// Describes a complete PIR database (INDEX + CHUNK + optional Merkle sub-tables).
pub struct DatabaseDescriptor {
    /// Human-readable name (e.g. "main", "delta_938612_940612").
    pub name: String,
    /// Snapshot or end height.
    pub height: u32,
    /// Parameters for the INDEX-level sub-table.
    pub index_params: TableParams,
    /// Parameters for the CHUNK-level sub-table.
    pub chunk_params: TableParams,
    // Future: merkle_data_params, merkle_sibling_params, etc.
}

/// A fully loaded database with all sub-tables memory-mapped.
pub struct MappedDatabase {
    /// Descriptor for this database.
    pub descriptor: DatabaseDescriptor,
    /// INDEX-level cuckoo table.
    pub index: MappedSubTable,
    /// CHUNK-level cuckoo table.
    pub chunk: MappedSubTable,
    /// MERKLE_DATA cuckoo table (optional).
    pub merkle_data: Option<MappedSubTable>,
    /// Per-level sibling cuckoo tables (empty if Merkle not built).
    pub merkle_siblings: Vec<MappedSubTable>,
    /// Cached top of the Merkle tree (node hashes).
    pub merkle_tree_top: Option<Vec<u8>>,
    /// Merkle root hash (32 bytes).
    pub merkle_root: Option<Vec<u8>>,
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

        // Try to load Merkle data table
        let merkle_data_path = base_dir.join("merkle_data_cuckoo.bin");
        let merkle_data = if merkle_data_path.exists() {
            println!("  Loading MERKLE_DATA...");
            Some(MappedSubTable::load(
                &merkle_data_path,
                pir_core::params::TableParams {
                    k: 75,
                    num_hashes: 3,
                    master_seed: 0xBA7C_0EDA_0000_0000,
                    cuckoo_bucket_size: 4,
                    cuckoo_num_hashes: 2,
                    slot_size: pir_core::merkle::MERKLE_DATA_SLOT_SIZE,
                    dpf_n: 20,
                    magic: 0xBA7C_0EDA_0000_0001,
                    header_size: 40,
                    has_tag_seed: true,
                },
            ))
        } else {
            None
        };

        // Try to load sibling tables (L0, L1, L2, ...)
        let mut merkle_siblings = Vec::new();
        for level in 0.. {
            let sib_path = base_dir.join(format!("merkle_sibling_L{}.bin", level));
            if !sib_path.exists() {
                break;
            }
            println!("  Loading MERKLE_SIBLING L{}...", level);
            let params = pir_core::params::TableParams {
                k: 75,
                num_hashes: 3,
                master_seed: 0xBA7C_51B1_0000_0000u64.wrapping_add(level as u64),
                cuckoo_bucket_size: 3,
                cuckoo_num_hashes: 2,
                slot_size: pir_core::merkle::MERKLE_SIBLING_SLOT_SIZE,
                dpf_n: 0, // read from header
                magic: 0xBA7C_51B1_0000_0000u64 | (level as u64),
                header_size: 32,
                has_tag_seed: false,
            };
            merkle_siblings.push(MappedSubTable::load(&sib_path, params));
        }

        // Try to load tree-top cache and root
        let merkle_tree_top = std::fs::read(base_dir.join("merkle_tree_top.bin")).ok();
        let merkle_root = std::fs::read(base_dir.join("merkle_root.bin")).ok();

        if merkle_data.is_some() {
            println!("  Merkle: {} sibling levels, tree-top={}, root={}",
                merkle_siblings.len(),
                if merkle_tree_top.is_some() { "yes" } else { "no" },
                if merkle_root.is_some() { "yes" } else { "no" },
            );
        }

        MappedDatabase {
            descriptor, index, chunk,
            merkle_data, merkle_siblings, merkle_tree_top, merkle_root,
        }
    }

    /// Whether this database has Merkle verification data.
    pub fn has_merkle(&self) -> bool {
        self.merkle_data.is_some()
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
    /// Total byte size of one index sub-table (bins × bucket_size × slot_size).
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
        let index_table_byte_size = index_bins_per_table * CUCKOO_BUCKET_SIZE * INDEX_SLOT_SIZE;
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
            chunk_bins_per_table * CHUNK_CUCKOO_BUCKET_SIZE * chunk_slot_size;
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
