//! Server Configuration Module
//!
//! This module provides a configuration system for the PIR server.
//! Databases are registered programmatically in the `load_configuration()` function.
//!
//! # Usage
//!
//! Modify the `load_configuration()` function to register your databases.
//! See the examples in the `load_configuration()` function documentation.

use crate::{Database, DatabaseRegistry, SERVER1_PORT, CuckooDatabase, DatabaseConfig, SingleLocationDatabase, TxidMappingDatabase};
use std::sync::Arc;

/// Server configuration containing all registered databases
pub struct ServerConfiguration {
    /// Port to listen on
    pub port: u16,
    /// Whether to load data into memory
    pub load_to_memory: bool,
    /// Database registry
    pub registry: DatabaseRegistry,
}

impl ServerConfiguration {
    /// Create a new server configuration with default settings
    pub fn new() -> Self {
        Self {
            port: SERVER1_PORT,
            load_to_memory: false,
            registry: DatabaseRegistry::new(),
        }
    }

    /// Set the server port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Enable memory loading
    pub fn with_load_to_memory(mut self, load: bool) -> Self {
        self.load_to_memory = load;
        self
    }

    /// Register a database
    pub fn register_database(&mut self, db: Arc<dyn Database>) {
        log::info!("Registering database: {}", db.id());
        self.registry.register(db);
    }

    /// Get the number of registered databases
    pub fn database_count(&self) -> usize {
        self.registry.len()
    }
}

impl Default for ServerConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

/// Load the server configuration.
/// 
/// **Modify this function to register your databases.**
/// 
/// # Examples
/// 
/// ## Register a CuckooDatabase (two-location hashing)
/// ```ignore
/// let db_config = DatabaseConfig::new("utxo_chunks", "/path/to/utxo_chunks_cuckoo.bin")
///     .with_num_buckets(14_008_287)
///     .with_entry_size(24)
///     .with_bucket_size(4)
///     .with_num_locations(2);
/// 
/// match CuckooDatabase::new(db_config) {
///     Ok(db) => config.register_database(Arc::new(db)),
///     Err(e) => warn!("Failed to register utxo_chunks: {}", e),
/// }
/// ```
/// 
/// ## Register a SingleLocationDatabase
/// ```ignore
/// let db_config = DatabaseConfig::new("simple_map", "/path/to/simple.bin")
///     .with_num_buckets(1_000_000)
///     .with_entry_size(20)
///     .with_bucket_size(1)
///     .with_num_locations(1);
/// 
/// match SingleLocationDatabase::new(db_config) {
///     Ok(db) => config.register_database(Arc::new(db)),
///     Err(e) => warn!("Failed to register simple_map: {}", e),
/// }
/// ```
/// 
/// ## Register a custom database with different hash functions
/// ```ignore
/// // Implement the Database trait with custom hash1() and hash2() methods
/// let custom_db = Arc::new(MyCustomDatabase::new("custom", "/path/to/custom.bin"));
/// config.register_database(custom_db);
/// ```
pub fn load_configuration() -> ServerConfiguration {
    let mut config = ServerConfiguration::new()
        .with_load_to_memory(true); // Load databases into memory for faster queries

    // ============================================================
    // REGISTER YOUR DATABASES HERE
    // ============================================================
    
    // Database 1: Cuckoo Index (maps script_hash -> chunk_offset)
    // - Two-location cuckoo hashing
    // - Entry: 20-byte key (script_hash) + 4-byte offset = 24 bytes
    // - Bucket: 4 entries per bucket
    let cuckoo_config = DatabaseConfig::new(
        "utxo_cuckoo_index",          // id
        "/Volumes/Bitcoin/pir/utxo_chunks_cuckoo.bin", // data_path
        24,    // entry_size (20-byte key + 4-byte offset)
        4,     // bucket_size
        15_385_139, // num_buckets
        2,     // num_locations (cuckoo hashing)
    );

    match CuckooDatabase::new(cuckoo_config) {
        Ok(db) => {
            log::info!("Registered utxo_cuckoo_index database");
            config.register_database(Arc::new(db));
        }
        Err(e) => log::warn!("Failed to register utxo_cuckoo_index: {}", e),
    }

    // Database 2: UTXO Chunks Data (actual UTXO data)
    // - Single-location, direct index (no cuckoo hashing)
    // - Entry: 32KB (one chunk)
    // - Bucket: 1 entry per bucket (direct index)
    let chunks_config = DatabaseConfig::new(
        "utxo_chunks_data",           // id
        "/Volumes/Bitcoin/pir/utxo_chunks.bin", // data_path
        32768,  // entry_size (32KB per chunk)
        1,     // bucket_size
        33_038, // num_buckets (33,038 chunks)
        1,     // num_locations (direct index)
    );

    match SingleLocationDatabase::new(chunks_config) {
        Ok(db) => {
            log::info!("Registered utxo_chunks_data database");
            config.register_database(Arc::new(db));
        }
        Err(e) => log::warn!("Failed to register utxo_chunks_data: {}", e),
    }

    // Database 3: TXID Mapping (4-byte to 32-byte TXID)
    // - Two-location cuckoo hashing with DIFFERENT hash functions (murmurhash3-style)
    // - Entry: 4-byte key (4b TXID) + 32-byte value (32b TXID) = 36 bytes
    // - Bucket: 4 entries per bucket
    // - Total buckets: 30,097,234
    match TxidMappingDatabase::new(
        "utxo_4b_to_32b",             // id
        "/Volumes/Bitcoin/pir/utxo_4b_to_32b_cuckoo.bin", // data_path
        30_097_234,                   // num_buckets
    ) {
        Ok(db) => {
            log::info!("Registered utxo_4b_to_32b database");
            config.register_database(Arc::new(db));
        }
        Err(e) => log::warn!("Failed to register utxo_4b_to_32b: {}", e),
    }

    // ============================================================
    // END DATABASE REGISTRATION
    // ============================================================

    config
}
