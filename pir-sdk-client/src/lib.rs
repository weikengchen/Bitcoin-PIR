//! PIR SDK Client: Native Rust client for PIR queries.
//!
//! This crate provides PIR client implementations for supported backends:
//!
//! - **DPF** (`DpfClient`): Two-server client using Distributed Point Functions.
//!   This is the recommended backend for production use.
//! - **HarmonyPIR** (`HarmonyClient`): Two-server client with offline hint phase.
//!   Connects to a separate hint server and query server; enable the `fastprp` or
//!   `alf` cargo feature to select a faster PRP backend.
//! - **OnionPIR** (`OnionClient`): Single-server FHE-based client.
//!   Currently a placeholder - requires FHE library integration.
//!
//! # Quick Start
//!
//! ```ignore
//! use pir_sdk_client::{DpfClient, PirClient, ScriptHash};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create client with two server URLs
//!     let mut client = DpfClient::new("ws://server0:8091", "ws://server1:8092");
//!     client.connect().await.unwrap();
//!
//!     // Query for a script hash
//!     let script_hash: ScriptHash = [0u8; 20]; // your HASH160 script hash
//!     let result = client.sync(&[script_hash], None).await.unwrap();
//!
//!     // Process results
//!     if let Some(query_result) = &result.results[0] {
//!         for entry in &query_result.entries {
//!             println!("UTXO: {} sats at {}:{}", entry.amount_sats, hex::encode(entry.txid), entry.vout);
//!         }
//!         println!("Total balance: {} sats", query_result.total_balance());
//!     }
//! }
//! ```
//!
//! # Delta Synchronization
//!
//! The SDK supports efficient delta sync - if you have results from a previous
//! height, you only need to query the changes:
//!
//! ```ignore
//! // First sync
//! let result = client.sync(&script_hashes, None).await?;
//! let height = result.synced_height;
//!
//! // Later: only query changes since last sync
//! let updated = client.sync(&script_hashes, Some(height)).await?;
//! ```

// `connection` hosts the tokio-tungstenite + rustls native WebSocket client.
// It is native-only: its deps (`tokio::net::TcpStream`, `rustls`,
// `tokio_tungstenite::connect_async`) don't compile to
// `wasm32-unknown-unknown`. On wasm32 the equivalent role is played by
// [`wasm_transport::WasmWebSocketTransport`], which wraps `web_sys::WebSocket`
// and bridges its callback-driven API to `async/.await` via an mpsc channel.
#[cfg(not(target_arch = "wasm32"))]
mod connection;
mod dpf;
mod harmony;
pub mod hint_cache;
mod merkle_verify;
mod onion;
#[cfg(feature = "onion")]
mod onion_merkle;
mod protocol;
mod transport;
#[cfg(target_arch = "wasm32")]
mod wasm_transport;

#[cfg(not(target_arch = "wasm32"))]
pub use connection::{
    RetryPolicy, WsConnection, DEFAULT_CONNECT_TIMEOUT, DEFAULT_INITIAL_BACKOFF_DELAY,
    DEFAULT_MAX_BACKOFF_DELAY, DEFAULT_MAX_CONNECT_ATTEMPTS, DEFAULT_REQUEST_TIMEOUT,
};
pub use dpf::DpfClient;
pub use harmony::{HarmonyClient, PRP_ALF, PRP_FASTPRP, PRP_HOANG};
pub use onion::OnionClient;
pub use transport::PirTransport;
#[cfg(target_arch = "wasm32")]
pub use wasm_transport::WasmWebSocketTransport;

// Re-export SDK types
pub use pir_sdk::{
    compute_sync_plan, merge_delta, merge_delta_batch, DatabaseCatalog, DatabaseInfo,
    PirBackendType, PirClient, PirClientConfig, PirError, PirResult, QueryResult,
    ScriptHash, SyncPlan, SyncResult,
};
