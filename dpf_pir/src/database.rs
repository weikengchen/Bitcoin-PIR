//! Database trait and implementations for PIR-queryable data stores.
//!
//! This module provides a modular database system that supports:
//! - Single-location or two-location (cuckoo) hashing
//! - Configurable hash functions
//! - Multiple databases per server
//! - Bucket-based storage

use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

/// Default hash function 1 seed (FNV offset basis)
pub const DEFAULT_HASH1_SEED: u64 = 0xcbf29ce484222325;

/// Default hash function 2 seed
pub const DEFAULT_HASH2_SEED: u64 = 0x517cc1b727220a95;

/// Default hash function 1 prime
pub const DEFAULT_HASH1_PRIME: u64 = 0x100000001b3;

/// Default hash function 2 prime
pub const DEFAULT_HASH2_PRIME: u64 = 0x9e3779b97f4a7c15;

/// Database trait for PIR-queryable data stores.
///
/// This trait defines the interface for databases that can be queried
/// using the PIR protocol. Implementations can use different hashing
/// strategies, bucket sizes, and storage backends.
///
/// Hash functions are provided as optional methods with default implementations
/// using the standard cuckoo hash algorithm. Implementations can override
/// these to use completely different hash algorithms.
pub trait Database: Send + Sync {
    // === Core Configuration ===

    /// Unique identifier for this database (e.g., "utxo_chunks", "map1")
    fn id(&self) -> &str;

    /// Path to the database file
    fn data_path(&self) -> &str;

    /// Size of each entry in bytes
    fn entry_size(&self) -> usize;

    /// Number of entries per bucket (1 = not bucketed)
    fn bucket_size(&self) -> usize;

    /// Number of buckets
    fn num_buckets(&self) -> usize;

    // === Location Strategy ===

    /// Number of hash locations (1 or 2 for cuckoo hashing)
    fn num_locations(&self) -> usize;

    /// Compute hash location 1 for a key.
    /// Override this method to use a custom hash algorithm.
    fn hash1(&self, key: &[u8]) -> usize {
        cuckoo_hash1(key, self.num_buckets(), DEFAULT_HASH1_SEED, DEFAULT_HASH1_PRIME)
    }

    /// Compute hash location 2 for a key.
    /// Override this method to use a custom hash algorithm.
    /// Only used when num_locations() == 2.
    fn hash2(&self, key: &[u8]) -> usize {
        cuckoo_hash2(key, self.num_buckets(), DEFAULT_HASH2_SEED, DEFAULT_HASH2_PRIME)
    }

    /// Compute hash location(s) for a key.
    /// Returns 1 or 2 bucket indices depending on num_locations().
    /// Override this for completely custom location computation.
    fn compute_locations(&self, key: &[u8]) -> Vec<usize> {
        if self.num_locations() == 1 {
            vec![self.hash1(key)]
        } else {
            vec![self.hash1(key), self.hash2(key)]
        }
    }

    // === Data Access ===

    /// Read entries at a specific bucket (for peeking).
    /// Returns a vector of entries, each entry_size bytes.
    fn read_bucket(&self, bucket_idx: usize) -> Result<Vec<Vec<u8>>, String>;

    /// Get the total size of the database in bytes
    fn total_size(&self) -> usize {
        self.num_buckets() * self.bucket_size() * self.entry_size()
    }

    /// Get the bucket size in bytes
    fn bucket_bytes(&self) -> usize {
        self.bucket_size() * self.entry_size()
    }
}

/// Configuration for creating a database.
///
/// This configuration contains the basic parameters for database creation.
/// For custom hash functions, implement the Database trait directly and
/// override the `hash1()`, `hash2()`, or `compute_locations()` methods.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Unique identifier for this database
    pub id: String,

    /// Path to the database file
    pub data_path: String,

    /// Size of each entry in bytes
    pub entry_size: usize,

    /// Number of entries per bucket (1 = not bucketed)
    pub bucket_size: usize,

    /// Number of buckets
    pub num_buckets: usize,

    /// Number of hash locations (1 or 2)
    pub num_locations: usize,
}

impl DatabaseConfig {
    /// Create a new DatabaseConfig with all required fields
    ///
    /// # Arguments
    /// * `id` - Unique identifier for this database
    /// * `data_path` - Path to the database file
    /// * `entry_size` - Size of each entry in bytes
    /// * `bucket_size` - Number of entries per bucket
    /// * `num_buckets` - Total number of buckets
    /// * `num_locations` - Number of hash locations (1 or 2 for cuckoo)
    pub fn new(
        id: impl Into<String>,
        data_path: impl Into<String>,
        entry_size: usize,
        bucket_size: usize,
        num_buckets: usize,
        num_locations: usize,
    ) -> Self {
        Self {
            id: id.into(),
            data_path: data_path.into(),
            entry_size,
            bucket_size,
            num_buckets,
            num_locations,
        }
    }

    /// Set the entry size
    pub fn with_entry_size(mut self, entry_size: usize) -> Self {
        self.entry_size = entry_size;
        self
    }

    /// Set the bucket size
    pub fn with_bucket_size(mut self, bucket_size: usize) -> Self {
        self.bucket_size = bucket_size;
        self
    }

    /// Set the number of buckets
    pub fn with_num_buckets(mut self, num_buckets: usize) -> Self {
        self.num_buckets = num_buckets;
        self
    }

    /// Set the number of locations (1 or 2)
    pub fn with_num_locations(mut self, num_locations: usize) -> Self {
        self.num_locations = num_locations;
        self
    }
}

/// Cuckoo hash database implementation.
///
/// This is the default implementation that uses two hash functions
/// to compute two possible bucket locations for each key.
/// 
/// The hash functions use the default cuckoo hash algorithm with default seeds.
/// For custom hash functions, create a custom implementation of the Database trait.
pub struct CuckooDatabase {
    config: DatabaseConfig,
    mmap: Option<Mmap>,
}

impl CuckooDatabase {
    /// Create a new CuckooDatabase without memory mapping
    pub fn new(config: DatabaseConfig) -> Result<Self, String> {
        // Verify the file exists
        let path = std::path::Path::new(&config.data_path);
        if !path.exists() {
            return Err(format!("Database file does not exist: {}", config.data_path));
        }

        Ok(Self {
            config,
            mmap: None,
        })
    }

    /// Create a new CuckooDatabase with memory mapping for faster peeking
    pub fn with_mmap(config: DatabaseConfig) -> Result<Self, String> {
        let path = std::path::Path::new(&config.data_path);
        if !path.exists() {
            return Err(format!("Database file does not exist: {}", config.data_path));
        }

        let file = File::open(path)
            .map_err(|e| format!("Failed to open database file: {}", e))?;

        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| format!("Failed to mmap database file: {}", e))?;

        Ok(Self {
            config,
            mmap: Some(mmap),
        })
    }

    /// Get a reference to the configuration
    pub fn config(&self) -> &DatabaseConfig {
        &self.config
    }
}

impl Database for CuckooDatabase {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn data_path(&self) -> &str {
        &self.config.data_path
    }

    fn entry_size(&self) -> usize {
        self.config.entry_size
    }

    fn bucket_size(&self) -> usize {
        self.config.bucket_size
    }

    fn num_buckets(&self) -> usize {
        self.config.num_buckets
    }

    fn num_locations(&self) -> usize {
        self.config.num_locations
    }

    // Uses default hash1(), hash2(), and compute_locations() from trait

    fn read_bucket(&self, bucket_idx: usize) -> Result<Vec<Vec<u8>>, String> {
        if bucket_idx >= self.config.num_buckets {
            return Err(format!(
                "Bucket index {} out of range (num_buckets={})",
                bucket_idx, self.config.num_buckets
            ));
        }

        let bucket_bytes = self.bucket_bytes();
        let offset = bucket_idx * bucket_bytes;

        let mut entries = Vec::with_capacity(self.config.bucket_size);

        // Use mmap if available, otherwise read from file
        if let Some(ref mmap) = self.mmap {
            for i in 0..self.config.bucket_size {
                let entry_offset = offset + i * self.config.entry_size;
                if entry_offset + self.config.entry_size <= mmap.len() {
                    let entry = mmap[entry_offset..entry_offset + self.config.entry_size].to_vec();
                    entries.push(entry);
                } else {
                    entries.push(vec![0u8; self.config.entry_size]);
                }
            }
        } else {
            let mut file = File::open(&self.config.data_path)
                .map_err(|e| format!("Failed to open database file: {}", e))?;

            file.seek(SeekFrom::Start(offset as u64))
                .map_err(|e| format!("Failed to seek to bucket {}: {}", bucket_idx, e))?;

            for _ in 0..self.config.bucket_size {
                let mut entry = vec![0u8; self.config.entry_size];
                file.read_exact(&mut entry)
                    .map_err(|e| format!("Failed to read entry: {}", e))?;
                entries.push(entry);
            }
        }

        Ok(entries)
    }
}

/// Single-location database implementation.
///
/// Uses only one hash function to compute the bucket location.
/// The hash function uses the default cuckoo hash algorithm.
/// For custom hash functions, create a custom implementation of the Database trait.
pub struct SingleLocationDatabase {
    config: DatabaseConfig,
    mmap: Option<Mmap>,
}

impl SingleLocationDatabase {
    /// Create a new SingleLocationDatabase without memory mapping
    pub fn new(config: DatabaseConfig) -> Result<Self, String> {
        if config.num_locations != 1 {
            return Err("SingleLocationDatabase requires num_locations = 1".to_string());
        }

        let path = std::path::Path::new(&config.data_path);
        if !path.exists() {
            return Err(format!("Database file does not exist: {}", config.data_path));
        }

        Ok(Self {
            config,
            mmap: None,
        })
    }

    /// Create a new SingleLocationDatabase with memory mapping
    pub fn with_mmap(config: DatabaseConfig) -> Result<Self, String> {
        if config.num_locations != 1 {
            return Err("SingleLocationDatabase requires num_locations = 1".to_string());
        }

        let path = std::path::Path::new(&config.data_path);
        if !path.exists() {
            return Err(format!("Database file does not exist: {}", config.data_path));
        }

        let file = File::open(path)
            .map_err(|e| format!("Failed to open database file: {}", e))?;

        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| format!("Failed to mmap database file: {}", e))?;

        Ok(Self {
            config,
            mmap: Some(mmap),
        })
    }

    /// Get a reference to the configuration
    pub fn config(&self) -> &DatabaseConfig {
        &self.config
    }
}

impl Database for SingleLocationDatabase {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn data_path(&self) -> &str {
        &self.config.data_path
    }

    fn entry_size(&self) -> usize {
        self.config.entry_size
    }

    fn bucket_size(&self) -> usize {
        self.config.bucket_size
    }

    fn num_buckets(&self) -> usize {
        self.config.num_buckets
    }

    fn num_locations(&self) -> usize {
        1
    }

    // Uses default hash1(), hash2(), and compute_locations() from trait

    fn read_bucket(&self, bucket_idx: usize) -> Result<Vec<Vec<u8>>, String> {
        if bucket_idx >= self.config.num_buckets {
            return Err(format!(
                "Bucket index {} out of range (num_buckets={})",
                bucket_idx, self.config.num_buckets
            ));
        }

        let bucket_bytes = self.bucket_bytes();
        let offset = bucket_idx * bucket_bytes;

        let mut entries = Vec::with_capacity(self.config.bucket_size);

        if let Some(ref mmap) = self.mmap {
            for i in 0..self.config.bucket_size {
                let entry_offset = offset + i * self.config.entry_size;
                if entry_offset + self.config.entry_size <= mmap.len() {
                    let entry = mmap[entry_offset..entry_offset + self.config.entry_size].to_vec();
                    entries.push(entry);
                } else {
                    entries.push(vec![0u8; self.config.entry_size]);
                }
            }
        } else {
            let mut file = File::open(&self.config.data_path)
                .map_err(|e| format!("Failed to open database file: {}", e))?;

            file.seek(SeekFrom::Start(offset as u64))
                .map_err(|e| format!("Failed to seek to bucket {}: {}", bucket_idx, e))?;

            for _ in 0..self.config.bucket_size {
                let mut entry = vec![0u8; self.config.entry_size];
                file.read_exact(&mut entry)
                    .map_err(|e| format!("Failed to read entry: {}", e))?;
                entries.push(entry);
            }
        }

        Ok(entries)
    }
}

// === Hash Functions ===

/// Cuckoo hash function 1 with configurable seed and prime.
/// Uses FNV-1a style mixing over the key bytes.
#[inline(always)]
pub fn cuckoo_hash1(key: &[u8], num_buckets: usize, seed: u64, prime: u64) -> usize {
    let mut h: u64 = seed;
    for &byte in key {
        h ^= byte as u64;
        h = h.wrapping_mul(prime);
    }
    // Extra mixing
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    (h as usize) % num_buckets
}

/// Cuckoo hash function 2 with configurable seed and prime.
/// Different seed/constants from hash1.
#[inline(always)]
pub fn cuckoo_hash2(key: &[u8], num_buckets: usize, seed: u64, prime: u64) -> usize {
    let mut h: u64 = seed;
    for &byte in key {
        h ^= byte as u64;
        h = h.wrapping_mul(prime);
    }
    h ^= h >> 32;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^= h >> 32;
    (h as usize) % num_buckets
}

/// Compute both cuckoo hash locations for a key with default seeds.
/// Returns (location1, location2) tuple.
#[inline(always)]
pub fn cuckoo_locations_default(key: &[u8], num_buckets: usize) -> (usize, usize) {
    (
        cuckoo_hash1(key, num_buckets, DEFAULT_HASH1_SEED, DEFAULT_HASH1_PRIME),
        cuckoo_hash2(key, num_buckets, DEFAULT_HASH2_SEED, DEFAULT_HASH2_PRIME),
    )
}

// === Database Registry ===

/// Information about a database (for listing and discovery)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatabaseInfo {
    /// Unique identifier
    pub id: String,
    /// Path to the database file
    pub data_path: String,
    /// Entry size in bytes
    pub entry_size: usize,
    /// Number of entries per bucket
    pub bucket_size: usize,
    /// Number of buckets
    pub num_buckets: usize,
    /// Number of hash locations (1 or 2)
    pub num_locations: usize,
    /// Total size in bytes
    pub total_size: usize,
}

impl From<&DatabaseConfig> for DatabaseInfo {
    fn from(config: &DatabaseConfig) -> Self {
        Self {
            id: config.id.clone(),
            data_path: config.data_path.clone(),
            entry_size: config.entry_size,
            bucket_size: config.bucket_size,
            num_buckets: config.num_buckets,
            num_locations: config.num_locations,
            total_size: config.num_buckets * config.bucket_size * config.entry_size,
        }
    }
}

impl From<&dyn Database> for DatabaseInfo {
    fn from(db: &dyn Database) -> Self {
        Self {
            id: db.id().to_string(),
            data_path: db.data_path().to_string(),
            entry_size: db.entry_size(),
            bucket_size: db.bucket_size(),
            num_buckets: db.num_buckets(),
            num_locations: db.num_locations(),
            total_size: db.total_size(),
        }
    }
}

/// UTXO Chunk Database implementation.
///
/// A simple direct-index database where each location maps directly to a 1024-byte chunk.
/// No hashing is used - the caller provides a direct index (0 to num_entries-1).
/// 
/// This database is designed for the UTXO chunks file at /Volumes/Bitcoin/pir/utxo_chunks.bin
/// which contains 1,208,236 entries of 1024 bytes each.
pub struct UtxoChunkDatabase {
    /// Database ID
    id: String,
    /// Path to the database file
    data_path: String,
    /// Size of each entry in bytes (1024)
    entry_size: usize,
    /// Number of entries (1,208,236)
    num_entries: usize,
    /// Memory mapped file
    mmap: Option<Mmap>,
    /// Actual file size (may be smaller than num_entries * entry_size)
    file_size: usize,
}

impl UtxoChunkDatabase {
    /// Create a new UtxoChunkDatabase
    ///
    /// # Arguments
    /// * `id` - Database identifier
    /// * `data_path` - Path to the data file
    /// * `num_entries` - Number of entries (1,208,236)
    /// * `entry_size` - Size of each entry in bytes (1024)
    pub fn new(
        id: impl Into<String>,
        data_path: impl Into<String>,
        num_entries: usize,
        entry_size: usize,
    ) -> Result<Self, String> {
        let id = id.into();
        let data_path = data_path.into();

        let path = std::path::Path::new(&data_path);
        if !path.exists() {
            return Err(format!("Database file does not exist: {}", data_path));
        }

        let file = File::open(path)
            .map_err(|e| format!("Failed to open database file: {}", e))?;

        let metadata = file.metadata()
            .map_err(|e| format!("Failed to get file metadata: {}", e))?;
        let file_size = metadata.len() as usize;

        Ok(Self {
            id,
            data_path,
            entry_size,
            num_entries,
            mmap: None,
            file_size,
        })
    }

    /// Create a new UtxoChunkDatabase with memory mapping for faster access
    pub fn with_mmap(
        id: impl Into<String>,
        data_path: impl Into<String>,
        num_entries: usize,
        entry_size: usize,
    ) -> Result<Self, String> {
        let id = id.into();
        let data_path = data_path.into();

        let path = std::path::Path::new(&data_path);
        if !path.exists() {
            return Err(format!("Database file does not exist: {}", data_path));
        }

        let file = File::open(path)
            .map_err(|e| format!("Failed to open database file: {}", e))?;

        let metadata = file.metadata()
            .map_err(|e| format!("Failed to get file metadata: {}", e))?;
        let file_size = metadata.len() as usize;

        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| format!("Failed to mmap database file: {}", e))?;

        Ok(Self {
            id,
            data_path,
            entry_size,
            num_entries,
            mmap: Some(mmap),
            file_size,
        })
    }

    /// Read a single entry at the given index.
    /// Returns 1024 bytes, padding with zeros if the file ends early.
    pub fn read_entry(&self, index: usize) -> Result<Vec<u8>, String> {
        if index >= self.num_entries {
            return Err(format!(
                "Index {} out of range (num_entries={})",
                index, self.num_entries
            ));
        }

        let offset = index * self.entry_size;
        let mut entry = vec![0u8; self.entry_size];

        // Check if we have data to read (handle incomplete last entry)
        if offset < self.file_size {
            let bytes_available = std::cmp::min(self.entry_size, self.file_size - offset);
            
            if let Some(ref mmap) = self.mmap {
                // Use mmap
                entry[..bytes_available].copy_from_slice(&mmap[offset..offset + bytes_available]);
            } else {
                // Read from file
                let mut file = File::open(&self.data_path)
                    .map_err(|e| format!("Failed to open database file: {}", e))?;
                
                file.seek(SeekFrom::Start(offset as u64))
                    .map_err(|e| format!("Failed to seek to index {}: {}", index, e))?;
                
                let mut buf = vec![0u8; bytes_available];
                file.read_exact(&mut buf)
                    .map_err(|e| format!("Failed to read entry at index {}: {}", index, e))?;
                
                entry[..bytes_available].copy_from_slice(&buf);
            }
        }

        Ok(entry)
    }

    /// Get the number of entries
    pub fn num_entries(&self) -> usize {
        self.num_entries
    }

    /// Get the actual file size
    pub fn file_size(&self) -> usize {
        self.file_size
    }

    /// Get the expected size (num_entries * entry_size)
    pub fn expected_size(&self) -> usize {
        self.num_entries * self.entry_size
    }
}

impl Database for UtxoChunkDatabase {
    fn id(&self) -> &str {
        &self.id
    }

    fn data_path(&self) -> &str {
        &self.data_path
    }

    fn entry_size(&self) -> usize {
        self.entry_size
    }

    fn bucket_size(&self) -> usize {
        1 // Each bucket contains exactly one entry
    }

    fn num_buckets(&self) -> usize {
        self.num_entries
    }

    fn num_locations(&self) -> usize {
        1 // Single location database
    }

    /// For UtxoChunkDatabase, the key is interpreted directly as an index.
    /// The key should be a valid usize encoded as bytes.
    fn hash1(&self, key: &[u8]) -> usize {
        // Interpret key as a direct index (big-endian usize)
        if key.len() >= 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&key[key.len()-8..]);
            usize::from_be_bytes(arr) % self.num_entries
        } else {
            // Fallback for short keys
            let mut arr = [0u8; 8];
            arr[8-key.len()..].copy_from_slice(key);
            usize::from_be_bytes(arr) % self.num_entries
        }
    }

    fn read_bucket(&self, bucket_idx: usize) -> Result<Vec<Vec<u8>>, String> {
        // Each bucket is a single entry
        let entry = self.read_entry(bucket_idx)?;
        Ok(vec![entry])
    }
}

// ============================================================================
// TXID Mapping Database (4-byte to 32-byte TXID mapping)
// ============================================================================

/// Registry to manage multiple databases.
///
/// The registry allows a server to host multiple databases
/// and clients to query specific databases by ID.
pub struct DatabaseRegistry {
    databases: HashMap<String, Arc<dyn Database>>,
}

impl DatabaseRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            databases: HashMap::new(),
        }
    }

    /// Register a database
    pub fn register(&mut self, db: Arc<dyn Database>) {
        self.databases.insert(db.id().to_string(), db);
    }

    /// Get a database by ID
    pub fn get(&self, id: &str) -> Option<Arc<dyn Database>> {
        self.databases.get(id).cloned()
    }

    /// List all registered database IDs
    pub fn list(&self) -> Vec<&str> {
        self.databases.keys().map(|s| s.as_str()).collect()
    }

    /// Get information about all registered databases
    pub fn list_info(&self) -> Vec<DatabaseInfo> {
        self.databases
            .values()
            .map(|db| DatabaseInfo::from(db.as_ref()))
            .collect()
    }

    /// Check if a database exists
    pub fn contains(&self, id: &str) -> bool {
        self.databases.contains_key(id)
    }

    /// Get the number of registered databases
    pub fn len(&self) -> usize {
        self.databases.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.databases.is_empty()
    }
}

impl Default for DatabaseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_functions_produce_different_results() {
        let key = [0u8; 20];
        let h1 = cuckoo_hash1(&key, 1000, DEFAULT_HASH1_SEED, DEFAULT_HASH1_PRIME);
        let h2 = cuckoo_hash2(&key, 1000, DEFAULT_HASH2_SEED, DEFAULT_HASH2_PRIME);
        assert_ne!(h1, h2, "Hash functions should produce different results");
    }

    #[test]
    fn test_hash_within_bounds() {
        let key = [0xAB; 20];
        let num_buckets = 14_008_287;
        let h1 = cuckoo_hash1(&key, num_buckets, DEFAULT_HASH1_SEED, DEFAULT_HASH1_PRIME);
        let h2 = cuckoo_hash2(&key, num_buckets, DEFAULT_HASH2_SEED, DEFAULT_HASH2_PRIME);
        assert!(h1 < num_buckets);
        assert!(h2 < num_buckets);
    }

    #[test]
    fn test_cuckoo_locations_default() {
        let key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                   0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                   0x99, 0xAA, 0xBB, 0xCC];
        let num_buckets = 14_008_287;
        let (loc1, loc2) = cuckoo_locations_default(&key, num_buckets);
        assert!(loc1 < num_buckets);
        assert!(loc2 < num_buckets);
        assert_ne!(loc1, loc2);
    }

    #[test]
    fn test_database_config_new() {
        let config = DatabaseConfig::new(
            "test_db",
            "/path/to/data.bin",
            32,   // entry_size
            8,    // bucket_size
            1000, // num_buckets
            2,    // num_locations
        );

        assert_eq!(config.id, "test_db");
        assert_eq!(config.data_path, "/path/to/data.bin");
        assert_eq!(config.entry_size, 32);
        assert_eq!(config.bucket_size, 8);
        assert_eq!(config.num_buckets, 1000);
        assert_eq!(config.num_locations, 2);
    }

    #[test]
    fn test_database_registry() {
        let mut registry = DatabaseRegistry::new();
        assert!(registry.is_empty());

        // Registry should be empty
        assert_eq!(registry.len(), 0);
        assert!(!registry.contains("test"));
    }
}