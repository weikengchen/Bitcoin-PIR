//! DPF-PIR: Distributed Point Function Private Information Retrieval
//!
//! This crate implements a PIR system using DPF (Distributed Point Functions)
//! with two servers and a client.
//!
//! ## Modules
//!
//! - `database`: Database trait and implementations for PIR-queryable data stores
//! - `protocol`: Communication protocol between client and servers (legacy bincode)
//! - `pir_protocol`: Simple Binary Protocol for WebSocket communication
//! - `hash`: Cuckoo hash functions for location computation
//! - `server_config`: Server configuration for programmatic database registration

pub mod database;
pub mod protocol;
pub mod pir_protocol;
pub mod pir_backend;
pub mod hash;
pub mod server_config;
pub mod server_config2;
pub mod websocket;

// Re-export main types from each module
pub use protocol::*;
pub use pir_protocol::{Request as PirRequest, Response as PirResponse};
pub use hash::*;
pub use database::{
    Database, DatabaseConfig, DatabaseInfo, DatabaseRegistry,
    CuckooDatabase, SingleLocationDatabase, UtxoChunkDatabase,
    TxidMappingDatabase,
    cuckoo_hash1, cuckoo_hash2, cuckoo_locations_default,
    txid_mapping_locations,
    DEFAULT_HASH1_SEED, DEFAULT_HASH2_SEED,
    DEFAULT_HASH1_PRIME, DEFAULT_HASH2_PRIME,
};
pub use server_config::{ServerConfiguration, load_configuration};
pub use server_config2::{ServerConfiguration2, load_configuration2};
pub use pir_backend::{PirBackend, DpfPirBackend};
