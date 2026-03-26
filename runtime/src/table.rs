//! Shared cuckoo table loading for PIR servers.
//!
//! Both the DPF query server and HarmonyPIR hint server load the same
//! pair of memory-mapped cuckoo table files. This module provides a
//! shared struct and loading function to avoid duplication.

use build::common::*;
use memmap2::Mmap;
use std::fs::File;

/// A pair of memory-mapped cuckoo tables (index + chunk).
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
