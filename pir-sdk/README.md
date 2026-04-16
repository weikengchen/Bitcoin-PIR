# PIR SDK

A Rust SDK for Private Information Retrieval (PIR) on Bitcoin UTXO data.

## Overview

This SDK provides a unified interface for PIR queries with support for multiple backends:

- **DPF-PIR**: Two-server protocol using Distributed Point Functions (recommended)
- **HarmonyPIR**: Two-server protocol with offline hints (hint server + query server)
- **OnionPIR**: Single-server FHE-based protocol (placeholder — requires FHE library integration)

## Crates

| Crate | Description |
|-------|-------------|
| `pir-sdk` | Core types, traits, and sync planning |
| `pir-sdk-client` | Client implementations for all backends |
| `pir-sdk-server` | Server builder and configuration |

## Quick Start

### Client Usage

```rust
use pir_sdk_client::{DpfClient, PirClient, ScriptHash};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a DPF client with two server URLs
    let mut client = DpfClient::new(
        "ws://server0:8091",
        "ws://server1:8092"
    );
    
    // Connect to servers
    client.connect().await?;
    
    // Query for a script hash (HASH160 of script)
    let script_hash: ScriptHash = [0u8; 20]; // your script hash
    let result = client.sync(&[script_hash], None).await?;
    
    // Process results
    if let Some(query_result) = &result.results[0] {
        println!("Found {} UTXOs", query_result.entries.len());
        println!("Total: {} sats", query_result.total_balance());
    }
    
    client.disconnect().await?;
    Ok(())
}
```

### Delta Synchronization

The SDK supports efficient incremental sync using delta databases:

```rust
// First sync (fresh)
let result = client.sync(&script_hashes, None).await?;
let height = result.synced_height;

// Save results...

// Later: only query changes since last sync
let updated = client.sync(&script_hashes, Some(height)).await?;
```

### Server Setup

```rust
use pir_sdk_server::PirServerBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = PirServerBuilder::new()
        .port(8091)
        .add_full_db("./snapshot.bin", 900000)
        .add_delta_db("./delta.bin", 900000, 910000)
        .build()
        .await?;
    
    server.run().await?;
    Ok(())
}
```

## Core Types

### ScriptHash

A 20-byte HASH160 of a Bitcoin script. This is the primary identifier for querying UTXOs.

### UtxoEntry

```rust
pub struct UtxoEntry {
    pub txid: [u8; 32],      // Transaction ID (little-endian)
    pub vout: u32,           // Output index
    pub amount_sats: u64,    // Amount in satoshis
}
```

### QueryResult

```rust
pub struct QueryResult {
    pub entries: Vec<UtxoEntry>,  // UTXO entries found
    pub is_whale: bool,           // True if address has too many UTXOs
    pub raw_chunk_data: Option<Vec<u8>>,  // For delta merging
}
```

### SyncResult

```rust
pub struct SyncResult {
    pub results: Vec<Option<QueryResult>>,  // One per script hash
    pub synced_height: u32,                 // Block height after sync
    pub was_fresh_sync: bool,               // True if started from snapshot
}
```

## PirClient Trait

All clients implement the `PirClient` trait:

```rust
#[async_trait]
pub trait PirClient: Send + Sync {
    /// Get the backend type.
    fn backend_type(&self) -> PirBackendType;
    
    /// Connect to PIR server(s).
    async fn connect(&mut self) -> PirResult<()>;
    
    /// Disconnect from server(s).
    async fn disconnect(&mut self) -> PirResult<()>;
    
    /// Check connection status.
    fn is_connected(&self) -> bool;
    
    /// Fetch the database catalog from the server.
    async fn fetch_catalog(&mut self) -> PirResult<DatabaseCatalog>;
    
    /// Get cached catalog (if any).
    fn cached_catalog(&self) -> Option<&DatabaseCatalog>;
    
    /// Compute an optimal sync plan.
    fn compute_sync_plan(
        &self,
        catalog: &DatabaseCatalog,
        last_height: Option<u32>,
    ) -> PirResult<SyncPlan>;
    
    /// Sync script hashes to latest tip.
    async fn sync(
        &mut self,
        script_hashes: &[ScriptHash],
        last_height: Option<u32>,
    ) -> PirResult<SyncResult>;
    
    /// Query a specific database.
    async fn query_batch(
        &mut self,
        script_hashes: &[ScriptHash],
        db_id: u8,
    ) -> PirResult<Vec<Option<QueryResult>>>;
}
```

## Sync Planning

The SDK automatically plans optimal sync paths:

1. **Fresh sync**: Query snapshot + chain deltas to tip
2. **Incremental sync**: Find shortest delta chain (max 5 steps)
3. **Fallback**: If delta chain is too long, fall back to fresh sync

```rust
// Manual sync planning
let catalog = client.fetch_catalog().await?;
let plan = client.compute_sync_plan(&catalog, Some(last_height))?;

println!("Steps: {}", plan.steps.len());
println!("Fresh sync: {}", plan.is_fresh_sync);

for step in &plan.steps {
    println!("  {} (db_id={}, height={})", step.name, step.db_id, step.tip_height);
}
```

## Error Handling

```rust
pub enum PirError {
    NotConnected,
    ConnectionFailed(String),
    Protocol(String),
    Decode(String),
    Encode(String),
    Io(std::io::Error),
    Config(String),
    InvalidState(String),
    NoSyncPath(String),
    InvalidCatalog(String),
    DatabaseNotFound(u8),
    MergeError(String),
}
```

## Running Examples

```bash
# Simple query (requires servers running on 8091/8092)
cargo run -p pir-sdk-client --example simple_query -- \
    <script_hash_hex>

# Delta sync demo
cargo run -p pir-sdk-client --example delta_sync

# Start a server
cargo run -p pir-sdk-server --example simple_server -- \
    --port 8091 \
    --db ./snapshot.bin:900000
```

## Running Tests

```bash
# Unit tests (no server required)
cargo test -p pir-sdk -p pir-sdk-client -p pir-sdk-server

# Integration tests (requires running servers)
cargo test -p pir-sdk-client --test integration_test -- --ignored
```

## License

MIT OR Apache-2.0
