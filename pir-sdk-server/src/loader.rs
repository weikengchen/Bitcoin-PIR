//! Database loading utilities.

use crate::config::DatabaseEntry;
use pir_sdk::{DatabaseCatalog, DatabaseInfo, PirResult};
use pir_runtime_core::table::{DatabaseDescriptor, DatabaseType, MappedDatabase};
use std::path::Path;

/// Loads PIR databases from disk.
pub struct DatabaseLoader {
    databases: Vec<MappedDatabase>,
    catalog: DatabaseCatalog,
}

impl DatabaseLoader {
    /// Create a new empty loader.
    pub fn new() -> Self {
        Self {
            databases: Vec::new(),
            catalog: DatabaseCatalog::default(),
        }
    }

    /// Load a database from a directory using a DatabaseEntry config.
    pub fn load_from_entry(&mut self, entry: &DatabaseEntry) -> PirResult<u8> {
        let db_id = self.databases.len() as u8;

        let db_type = if entry.is_delta() {
            DatabaseType::Delta
        } else {
            DatabaseType::Full
        };

        let descriptor = DatabaseDescriptor {
            name: entry.name.clone(),
            db_type,
            base_height: entry.base_height,
            height: entry.height,
            index_params: pir_core::params::INDEX_PARAMS.clone(),
            chunk_params: pir_core::params::CHUNK_PARAMS.clone(),
        };

        let mapped = MappedDatabase::load(&entry.path, descriptor);

        // Build catalog entry
        let info = DatabaseInfo {
            db_id,
            kind: entry.kind(),
            name: entry.name.clone(),
            height: entry.height,
            index_bins: mapped.index.bins_per_table as u32,
            chunk_bins: mapped.chunk.bins_per_table as u32,
            index_k: mapped.index.params.k as u8,
            chunk_k: mapped.chunk.params.k as u8,
            tag_seed: mapped.index.tag_seed,
            dpf_n_index: pir_core::params::compute_dpf_n(mapped.index.bins_per_table),
            dpf_n_chunk: pir_core::params::compute_dpf_n(mapped.chunk.bins_per_table),
            has_bucket_merkle: mapped.has_bucket_merkle(),
        };

        self.databases.push(mapped);
        self.catalog.databases.push(info);

        Ok(db_id)
    }

    /// Load a full snapshot database.
    pub fn load_full(&mut self, path: &Path, height: u32) -> PirResult<u8> {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("full_{}", height));
        let entry = DatabaseEntry::full(name, path, height);
        self.load_from_entry(&entry)
    }

    /// Load a delta database.
    pub fn load_delta(&mut self, path: &Path, base_height: u32, tip_height: u32) -> PirResult<u8> {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("delta_{}_{}", base_height, tip_height));
        let entry = DatabaseEntry::delta(name, path, base_height, tip_height);
        self.load_from_entry(&entry)
    }

    /// Load all databases from a ServerConfig.
    pub fn load_all(&mut self, entries: &[DatabaseEntry]) -> PirResult<()> {
        for entry in entries {
            self.load_from_entry(entry)?;
        }
        Ok(())
    }

    /// Get the loaded databases.
    pub fn databases(&self) -> &[MappedDatabase] {
        &self.databases
    }

    /// Take ownership of the loaded databases.
    pub fn into_databases(self) -> Vec<MappedDatabase> {
        self.databases
    }

    /// Get the catalog.
    pub fn catalog(&self) -> &DatabaseCatalog {
        &self.catalog
    }

    /// Take ownership of the catalog.
    pub fn into_catalog(self) -> DatabaseCatalog {
        self.catalog
    }

    /// Get a database by ID.
    pub fn get(&self, db_id: u8) -> Option<&MappedDatabase> {
        self.databases.get(db_id as usize)
    }

    /// Number of loaded databases.
    pub fn len(&self) -> usize {
        self.databases.len()
    }

    /// Returns true if no databases are loaded.
    pub fn is_empty(&self) -> bool {
        self.databases.is_empty()
    }
}

impl Default for DatabaseLoader {
    fn default() -> Self {
        Self::new()
    }
}
