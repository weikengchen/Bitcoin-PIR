//! TOML-based server configuration for multi-database setups.
//!
//! Instead of passing many `--checkpoint` and `--delta` CLI flags, the server
//! can load a single `databases.toml` file that declares all databases, their
//! types, heights, paths, and warmup priority.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Configuration for a single database (full checkpoint or delta).
#[derive(Deserialize, Clone, Debug)]
pub struct DatabaseConfig {
    /// Human-readable name (e.g. "main", "delta_940611_944000").
    pub name: String,
    /// "full" for a complete UTXO snapshot, "delta" for a diff between heights.
    #[serde(rename = "type")]
    pub db_type: String,
    /// Path to the database directory (relative to the config file's parent).
    pub path: String,
    /// Starting height (0 for full snapshots, start height for deltas).
    pub base_height: u32,
    /// Snapshot height (full) or end height (delta).
    pub height: u32,
    /// Warmup priority: lower = higher priority (warmed up first).
    /// Defaults to 5 if omitted.
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_priority() -> u32 {
    5
}

/// Top-level server configuration loaded from a TOML file.
#[derive(Deserialize, Debug)]
pub struct ServerConfig {
    /// Ordered list of databases. The first entry becomes db_id=0.
    #[serde(rename = "database")]
    pub databases: Vec<DatabaseConfig>,
}

impl ServerConfig {
    /// Load and parse a TOML config file.
    pub fn load(path: &Path) -> Self {
        let contents = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read config {}: {}", path.display(), e));
        let mut config: ServerConfig = toml::from_str(&contents)
            .unwrap_or_else(|e| panic!("Failed to parse config {}: {}", path.display(), e));

        // Resolve relative paths against the config file's parent directory
        let base_dir = path.parent().unwrap_or(Path::new("."));
        for db in &mut config.databases {
            let p = Path::new(&db.path);
            if p.is_relative() {
                db.path = base_dir.join(p).to_string_lossy().into_owned();
            }
        }

        config
    }

    /// Get the resolved path for a database entry.
    pub fn db_path(&self, index: usize) -> PathBuf {
        PathBuf::from(&self.databases[index].path)
    }
}
