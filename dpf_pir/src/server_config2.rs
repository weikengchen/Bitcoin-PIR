//! Server Configuration Module (Gen2)
//!
//! This module provides a configuration system for the gen2 PIR server.
//! Databases are registered programmatically in the `load_configuration2()` function.
//!
//! # Usage
//!
//! Modify the `load_configuration2()` function to register your databases.

use crate::{Database, DatabaseRegistry, SERVER2_PORT, CuckooDatabase, DatabaseConfig, SingleLocationDatabase};
use std::sync::Arc;

/// Server configuration containing all registered databases
pub struct ServerConfiguration2 {
    /// Port to listen on
    pub port: u16,
    /// Whether to load data into memory
    pub load_to_memory: bool,
    /// Database registry
    pub registry: DatabaseRegistry,
}

impl ServerConfiguration2 {
    /// Create a new server configuration with default settings
    pub fn new() -> Self {
        Self {
            port: SERVER2_PORT,
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

impl Default for ServerConfiguration2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Load the gen2 server configuration.
///
/// **Modify this function to register your databases.**
///
/// # Arguments
///
/// * `small` - If true, use small database paths and reduced num_buckets
pub fn load_configuration2(small: bool) -> ServerConfiguration2 {
    let mut config = ServerConfiguration2::new()
        .with_load_to_memory(true); // Load databases into memory for faster queries

    // ============================================================
    // REGISTER YOUR DATABASES HERE
    // ============================================================

    // Database 1: Gen2 Cuckoo Index (maps script_hash -> chunk_offset)
    // - Two-location cuckoo hashing
    // - Entry: 20-byte key (script_hash) + 4-byte offset = 24 bytes
    // - Bucket: 4 entries per bucket
    let cuckoo_path = if small {
        "/Volumes/Bitcoin/pir/gen2_utxo_chunks_cuckoo_small.bin"
    } else {
        "/Volumes/Bitcoin/pir/gen2_utxo_chunks_cuckoo.bin"
    };

    let cuckoo_config = DatabaseConfig::new(
        "gen2_utxo_cuckoo_index",     // id
        cuckoo_path,                  // data_path
        24,                           // entry_size (20-byte key + 4-byte offset)
        4,                            // bucket_size
        15_385_139,                   // num_buckets
        2,                            // num_locations (cuckoo hashing)
    );

    match CuckooDatabase::new(cuckoo_config) {
        Ok(db) => {
            log::info!("Registered gen2_utxo_cuckoo_index database");
            config.register_database(Arc::new(db));
        }
        Err(e) => log::warn!("Failed to register gen2_utxo_cuckoo_index: {}", e),
    }

    // Database 2: Gen2 UTXO Chunks Data (actual UTXO data)
    // - Single-location, direct index (no cuckoo hashing)
    // - Entry: 32KB (one chunk)
    // - Bucket: 1 entry per bucket (direct index)
    let chunks_path = if small {
        "/Volumes/Bitcoin/pir/gen2_utxo_chunks_small.bin"
    } else {
        "/Volumes/Bitcoin/pir/gen2_utxo_chunks.bin"
    };

    let num_buckets = if small { 65_294 } else { 181_833 };

    let chunks_config = DatabaseConfig::new(
        "gen2_utxo_chunks_data",      // id
        chunks_path,                  // data_path
        32768,                        // entry_size (32KB per chunk)
        1,                            // bucket_size
        num_buckets,                  // num_buckets
        1,                            // num_locations (direct index)
    );

    match SingleLocationDatabase::new(chunks_config) {
        Ok(db) => {
            log::info!("Registered gen2_utxo_chunks_data database");
            config.register_database(Arc::new(db));
        }
        Err(e) => log::warn!("Failed to register gen2_utxo_chunks_data: {}", e),
    }

    // ============================================================
    // END DATABASE REGISTRATION
    // ============================================================

    config
}
