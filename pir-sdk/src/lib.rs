//! PIR SDK: Core types, traits, and abstractions for Private Information Retrieval.
//!
//! This crate provides the foundational building blocks for both PIR servers and clients.
//! It defines:
//!
//! - **Types**: Common data structures like `UtxoEntry`, `DatabaseInfo`, `SyncPlan`
//! - **Error**: A unified error type for all PIR operations
//! - **Backend trait**: Server-side interface for handling PIR requests
//! - **Client trait**: Client-side interface for querying PIR servers
//! - **Sync**: Delta synchronization planning and merging
//!
//! # Architecture
//!
//! The SDK supports three PIR backends:
//! - **DPF-PIR**: Two-server, stateless, uses Distributed Point Functions
//! - **HarmonyPIR**: Two-server (hint + query), stateful per-group hints
//! - **OnionPIR**: Single-server, FHE-based, requires key registration
//!
//! All backends share the same two-level (INDEX + CHUNK) cuckoo table structure
//! and support chained delta synchronization (snapshot A -> delta A->B -> delta B->C -> ...).
//!
//! # Example
//!
//! ```ignore
//! use pir_sdk::{PirClientBuilder, ScriptHash};
//!
//! // Create a DPF client (two servers)
//! let mut client = PirClientBuilder::dpf("ws://server0:8091", "ws://server1:8092").build();
//!
//! // Connect and sync
//! client.connect().await?;
//! let result = client.sync(&[script_hash], None).await?;
//!
//! for entry in result.entries {
//!     println!("UTXO: {}:{} = {} sats", hex::encode(entry.txid), entry.vout, entry.amount_sats);
//! }
//! ```

pub mod types;
pub mod error;
pub mod backend;
pub mod client;
pub mod sync;

// Re-export main types at crate root
pub use types::*;
pub use error::{ErrorKind, PirError, PirResult};
pub use backend::PirBackend;
pub use client::{
    ConnectionState, NoProgress, PirClient, PirClientConfig, PrintProgress, StateListener,
    SyncProgress,
};
pub use sync::{SyncPlan, SyncStep, compute_sync_plan, merge_delta, merge_delta_batch, DeltaData, decode_delta_data};

// Re-export pir-core for convenience
pub use pir_core;
