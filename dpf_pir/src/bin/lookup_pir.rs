//! Two-Phase DPF-PIR Client for UTXO Lookup (WebSocket Version) - 
//!
//! This client performs private UTXO lookups using two WebSocket servers:
//! - Phase 1: Query cuckoo index to get chunk offset
//! - Phase 2: Query chunks database to get UTXO data
//!
//! Uses HASH160 (RIPEMD160(SHA256(script))) for script hashing.
//!
//! Usage:
//!   cargo run --bin lookup_pir -- <script_hex_or_hash> [--hash]
//!
//! Example:
//!   cargo run --bin lookup_pir -- 76a914e4986f7364f238102f1889ef9d24d80e2d2d7a4488ac
//!   cargo run --bin lookup_pir -- 09d9fb5e2c298cdf69a06fdc188334305e9cb20d --hash

use dpf_pir::{
    cuckoo_locations_default,
    PirRequest as Request, PirResponse as Response, ScriptHash, KEY_SIZE,
};
use libdpf::Dpf;
use log::{debug, error, info};
use ripemd::{Ripemd160, Digest};
use sha2::Sha256;
use std::env;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Database ID for the cuckoo index
const CUCKOO_DB_ID: &str = "utxo_cuckoo_index";

/// Database ID for the chunks data
const CHUNKS_DB_ID: &str = "utxo_chunks_data";

/// Number of buckets in the cuckoo index
const CUCKOO_NUM_BUCKETS: usize = 15_385_139;

/// Number of entries in the chunks database
const CHUNKS_NUM_ENTRIES: usize = 181_833;

/// Chunk size in bytes (32KB)
const CHUNK_SIZE: usize = 32 * 1024;

/// Entry size in cuckoo index (20-byte key + 4-byte offset)
const CUCKOO_ENTRY_SIZE: usize = 24;

/// Bucket size in cuckoo index
const CUCKOO_BUCKET_SIZE: usize = 4;

/// Default WebSocket ports
const WS_SERVER1_PORT: u16 = 8091;
const WS_SERVER2_PORT: u16 = 8092;

// ============================================================================
// WEBSOCKET CLIENT
// ============================================================================

/// WebSocket-based PIR Client for two-phase UTXO lookup
struct PIRClientWs {
    /// Server 1 WebSocket URL
    server1_url: String,
    /// Server 2 WebSocket URL
    server2_url: String,
}

impl PIRClientWs {
    /// Create a new WebSocket PIR client
    fn new(server1_url: String, server2_url: String) -> Self {
        Self { server1_url, server2_url }
    }

    /// Phase 1: Query cuckoo index to get chunk offset for a script hash
    async fn query_cuckoo_index(&self, script_hash: &ScriptHash) -> Result<Option<u32>, String> {
        info!("Phase 1: Querying cuckoo index for script hash");

        let (loc1, loc2) = cuckoo_locations_default(script_hash, CUCKOO_NUM_BUCKETS);
        info!("Cuckoo locations: loc1={}, loc2={}", loc1, loc2);

        let n = (CUCKOO_NUM_BUCKETS as f64).log2().ceil() as u8;
        let dpf = Dpf::with_default_key();

        let (k0_loc1, k1_loc1) = dpf.gen(loc1 as u64, n);
        let (k0_loc2, k1_loc2) = dpf.gen(loc2 as u64, n);

        info!("DPF keys generated: domain=2^{}", n);

        // Store key bytes in variables to avoid temporary value issues
        let k0_loc1_bytes = k0_loc1.to_bytes();
        let k0_loc2_bytes = k0_loc2.to_bytes();
        let k1_loc1_bytes = k1_loc1.to_bytes();
        let k1_loc2_bytes = k1_loc2.to_bytes();

        // Query both servers concurrently
        let server1_future = self.query_server_two_keys(
            &self.server1_url,
            CUCKOO_DB_ID,
            &k0_loc1_bytes,
            &k0_loc2_bytes,
        );
        let server2_future = self.query_server_two_keys(
            &self.server2_url,
            CUCKOO_DB_ID,
            &k1_loc1_bytes,
            &k1_loc2_bytes,
        );

        let (result1, result2) = tokio::try_join!(server1_future, server2_future)?;

        let combined_loc1 = xor_bytes(&result1.0, &result2.0);
        let combined_loc2 = xor_bytes(&result1.1, &result2.1);

        info!("Combined results: loc1={} bytes, loc2={} bytes",
              combined_loc1.len(), combined_loc2.len());

        for (bucket_data, loc_name) in [(&combined_loc1, "loc1"), (&combined_loc2, "loc2")] {
            for i in 0..CUCKOO_BUCKET_SIZE {
                let offset = i * CUCKOO_ENTRY_SIZE;
                if offset + CUCKOO_ENTRY_SIZE > bucket_data.len() {
                    continue;
                }

                let key = &bucket_data[offset..offset + KEY_SIZE];

                if key.iter().all(|&b| b == 0) {
                    continue;
                }

                if key == script_hash.as_slice() {
                    let value = u32::from_le_bytes([
                        bucket_data[offset + KEY_SIZE],
                        bucket_data[offset + KEY_SIZE + 1],
                        bucket_data[offset + KEY_SIZE + 2],
                        bucket_data[offset + KEY_SIZE + 3],
                    ]);
                    info!("Found matching key at {} with offset {}", loc_name, value);
                    return Ok(Some(value));
                }
            }
        }

        info!("Script hash not found in cuckoo index");
        Ok(None)
    }

    /// Phase 2: Query chunks database at a specific chunk index
    async fn query_chunk(&self, chunk_index: usize) -> Result<Vec<u8>, String> {
        debug!("Querying chunks database for chunk {}", chunk_index);

        let n = (CHUNKS_NUM_ENTRIES as f64).log2().ceil() as u8;
        let dpf = Dpf::with_default_key();

        let (k0, k1) = dpf.gen(chunk_index as u64, n);

        // Store key bytes in variables
        let k0_bytes = k0.to_bytes();
        let k1_bytes = k1.to_bytes();

        let server1_future = self.query_server_single(
            &self.server1_url,
            CHUNKS_DB_ID,
            &k0_bytes,
        );
        let server2_future = self.query_server_single(
            &self.server2_url,
            CHUNKS_DB_ID,
            &k1_bytes,
        );

        let (result1, result2) = tokio::try_join!(server1_future, server2_future)?;

        let combined = xor_bytes(&result1, &result2);
        debug!("Chunk data retrieved: {} bytes", combined.len());

        Ok(combined)
    }

    /// Query a WebSocket server with two DPF keys
    async fn query_server_two_keys(
        &self,
        url: &str,
        db_id: &str,
        key1: &[u8],
        key2: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        info!("Connecting to {} for database '{}' query", url, db_id);

        let (ws_stream, _) = connect_async(url).await
            .map_err(|e| format!("Failed to connect to {}: {}", url, e))?;

        let (mut write, mut read) = ws_stream.split();

        let request = Request::QueryDatabase {
            database_id: db_id.to_string(),
            pir_query1: key1.to_vec(),
            pir_query2: key2.to_vec(),
        };

        // Send request using SBP protocol
        let request_bytes = request.encode();
        write
            .send(Message::Binary(request_bytes))
            .await
            .map_err(|e| format!("Failed to send WebSocket message: {}", e))?;

        // Receive response
        let response = receive_ws_response(&mut read).await?;

        match response {
            Response::QueryTwoResults { data1, data2 } => {
                info!("Received results from {}: data1={} bytes, data2={} bytes",
                      url, data1.len(), data2.len());
                Ok((data1, data2))
            }
            Response::Error { message } => Err(format!("Server error: {}", message)),
            _ => Err(format!("Unexpected response: {:?}", response)),
        }
    }

    /// Query a WebSocket server with a single DPF key
    async fn query_server_single(
        &self,
        url: &str,
        db_id: &str,
        key: &[u8],
    ) -> Result<Vec<u8>, String> {
        debug!("Connecting to {} for database '{}' single query", url, db_id);

        let (ws_stream, _) = connect_async(url).await
            .map_err(|e| format!("Failed to connect to {}: {}", url, e))?;

        let (mut write, mut read) = ws_stream.split();

        let request = Request::QueryDatabaseSingle {
            database_id: db_id.to_string(),
            pir_query: key.to_vec(),
        };

        // Send request using SBP protocol
        let request_bytes = request.encode();
        write
            .send(Message::Binary(request_bytes))
            .await
            .map_err(|e| format!("Failed to send WebSocket message: {}", e))?;

        // Receive response
        let response = receive_ws_response(&mut read).await?;

        match response {
            Response::QueryResult { data } => {
                debug!("Received result from {}: {} bytes", url, data.len());
                Ok(data)
            }
            Response::Error { message } => Err(format!("Server error: {}", message)),
            _ => Err(format!("Unexpected response: {:?}", response)),
        }
    }

    /// Full two-phase lookup for a script hash
    async fn lookup_utxo(&self, script_hash: &ScriptHash) -> Result<Option<u64>, String> {
        let offset = match self.query_cuckoo_index(script_hash).await? {
            Some(o) => o,
            None => return Ok(None),
        };

        // The stored offset is byte_offset/2 (to fit >4GB files in u32)
        let byte_offset = (offset as u64) * 2;
        let chunk_index = byte_offset as usize / CHUNK_SIZE;
        let local_offset = byte_offset as usize % CHUNK_SIZE;
        info!("Stored offset {} -> byte_offset={}, chunk_index={}, local_offset={}", offset, byte_offset, chunk_index, local_offset);

        Ok(Some(byte_offset))
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// XOR two byte vectors together
fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let min_len = a.len().min(b.len());
    let mut result = vec![0u8; min_len];
    for i in 0..min_len {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Receive a WebSocket response
async fn receive_ws_response<R>(read: &mut R) -> Result<Response, String>
where
    R: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let msg = read
        .next()
        .await
        .ok_or("No response received from server")?
        .map_err(|e| format!("WebSocket error: {}", e))?;

    if !msg.is_binary() {
        return Err(format!("Expected binary message, got: {:?}", msg));
    }

    let data = msg.into_data();
    Response::decode(&data)
        .map_err(|e| format!("Failed to decode response: {}", e))
}

/// Convert script hex to HASH160 hash (RIPEMD160(SHA256(script)))
fn script_to_hash(script_hex: &str) -> Result<ScriptHash, String> {
    let script_bytes = hex::decode(script_hex)
        .map_err(|e| format!("Invalid hex: {}", e))?;
    // HASH160 = RIPEMD160(SHA256(script))
    let sha256_result = Sha256::digest(&script_bytes);
    let hash160 = Ripemd160::digest(&sha256_result);
    let mut hash = [0u8; KEY_SIZE];
    hash.copy_from_slice(&hash160);
    Ok(hash)
}

/// Convert hex string to bytes
fn hex2bin(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex character: {}", e))
        })
        .collect()
}

/// Convert bytes to hex string
fn bin2hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert bytes to hex string in reverse order (for Bitcoin TXID display)
fn bin2hex_reversed(bytes: &[u8]) -> String {
    bytes.iter().rev().map(|b| format!("{:02x}", b)).collect()
}

// ============================================================================
// UTXO PARSING
// ============================================================================

/// A parsed UTXO entry
#[derive(Debug, Clone)]
struct UtxoEntry {
    txid: [u8; 32],
    vout: u32,
    amount: u64,
}

/// Statistics for PIR queries
#[derive(Debug, Clone, Default)]
struct QueryStats {
    chunk_queries: usize,
    total_bytes_received: usize,
    start_chunk_index: usize,
    end_chunk_index: usize,
    bytes_read: usize,
}

/// Streaming reader for UTXO chunks
struct ChunkReaderWs<'a> {
    client: &'a PIRClientWs,
    chunk_index: usize,
    chunk_pos: usize,
    chunk: Vec<u8>,
    stats: QueryStats,
}

impl<'a> ChunkReaderWs<'a> {
    async fn new(client: &'a PIRClientWs, start_offset: usize) -> Result<Self, String> {
        let chunk_index = start_offset / CHUNK_SIZE;
        let chunk_pos = start_offset % CHUNK_SIZE;

        let chunk = client.query_chunk(chunk_index).await?;
        let chunk_len = chunk.len();

        Ok(Self {
            client,
            chunk_index,
            chunk_pos,
            chunk,
            stats: QueryStats {
                chunk_queries: 1,
                total_bytes_received: chunk_len,
                start_chunk_index: chunk_index,
                end_chunk_index: chunk_index,
                bytes_read: 0,
            },
        })
    }

    async fn read_byte(&mut self) -> Result<u8, String> {
        if self.chunk_pos >= self.chunk.len() {
            self.chunk_index += 1;
            if self.chunk_index >= CHUNKS_NUM_ENTRIES {
                return Err("End of database reached".to_string());
            }
            self.chunk = self.client.query_chunk(self.chunk_index).await?;
            self.chunk_pos = 0;

            self.stats.chunk_queries += 1;
            self.stats.total_bytes_received += self.chunk.len();
            self.stats.end_chunk_index = self.chunk_index;
        }

        let byte = self.chunk[self.chunk_pos];
        self.chunk_pos += 1;
        self.stats.bytes_read += 1;
        Ok(byte)
    }

    fn get_stats(&self) -> &QueryStats {
        &self.stats
    }

    async fn read_varint(&mut self) -> Result<u64, String> {
        let mut result: u64 = 0;
        let mut shift = 0;

        loop {
            let byte = self.read_byte().await?;
            result |= ((byte & 0x7F) as u64) << shift;

            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;

            if shift >= 64 {
                return Err("VarInt too large".to_string());
            }
        }

        Ok(result)
    }
}

/// Print a progress bar to stderr
fn print_progress(current: usize, total: usize, width: usize) {
    if total == 0 {
        return;
    }
    let percent = (current * 100) / total;
    let filled = (current * width) / total;
    let bar: String = "█".repeat(filled);
    let empty: String = "░".repeat(width - filled);
    eprint!("\r  Reading entries: [{}{}] {}% ({}/{})", bar, empty, percent, current, total);
    if current == total {
        eprintln!();
    }
}

/// Result of parsing UTXO entries
struct ParseResult {
    entries: Vec<UtxoEntry>,
    stats: QueryStats,
}

/// Parse UTXO entries starting at the given offset
async fn parse_utxo_entries(client: &PIRClientWs, start_offset: usize) -> Result<ParseResult, String> {
    let mut reader = ChunkReaderWs::new(client, start_offset).await?;

    let entry_count = reader.read_varint().await? as usize;

    if entry_count == 0 {
        println!("🐋 Whale Address Detected");
        println!("  This address has UTXOs but is excluded from the lightweight database.");
        println!("  It exceeds the average UTXO count threshold.");
        let stats = reader.get_stats().clone();
        return Ok(ParseResult {
            entries: Vec::new(),
            stats,
        });
    }

    let show_progress = entry_count > 100;
    if show_progress {
        eprintln!("  Fetching {} UTXO entries...", entry_count);
    }

    let mut entries = Vec::with_capacity(entry_count.min(10000));

    let progress_interval = ((entry_count / 100).max(100)).min(1000);

    for i in 0..entry_count {
        // Read 32 raw TXID bytes
        let mut txid = [0u8; 32];
        for j in 0..32 {
            txid[j] = reader.read_byte().await?;
        }
        let vout = reader.read_varint().await? as u32;
        let amount = reader.read_varint().await?;

        entries.push(UtxoEntry { txid, vout, amount });

        if show_progress && (i % progress_interval == 0 || i == entry_count - 1) {
            print_progress(i + 1, entry_count, 30);
        }
    }

    let stats = reader.get_stats().clone();
    Ok(ParseResult { entries, stats })
}

// ============================================================================
// COMMAND LINE PARSING
// ============================================================================

fn parse_args(args: &[String]) -> (String, String, Option<String>, bool) {
    let mut server1_url = format!("ws://127.0.0.1:{}", WS_SERVER1_PORT);
    let mut server2_url = format!("ws://127.0.0.1:{}", WS_SERVER2_PORT);
    let mut script_input: Option<String> = None;
    let mut use_hash = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server1" | "-s1" => {
                if i + 1 < args.len() {
                    server1_url = args[i + 1].clone();
                    i += 1;
                }
            }
            "--server2" | "-s2" => {
                if i + 1 < args.len() {
                    server2_url = args[i + 1].clone();
                    i += 1;
                }
            }
            "--hash" => {
                use_hash = true;
            }
            "--help" | "-h" => {
                print_help(&args[0]);
                std::process::exit(0);
            }
            _ => {
                if !args[i].starts_with('-') && script_input.is_none() {
                    script_input = Some(args[i].clone());
                }
            }
        }
        i += 1;
    }

    (server1_url, server2_url, script_input, use_hash)
}

fn print_help(program: &str) {
    println!("Two-Phase DPF-PIR Client for UTXO Lookup (WebSocket Version) - ");
    println!();
    println!("Usage:");
    println!("  {} [OPTIONS] <SCRIPT_HEX_OR_HASH>", program);
    println!();
    println!("Arguments:");
    println!("  <SCRIPT_HEX_OR_HASH>  Script pubkey hex or HASH160 hash");
    println!();
    println!("Options:");
    println!("  --server1, -s1 <URL>  Server 1 WebSocket URL (default: ws://127.0.0.1:{})", WS_SERVER1_PORT);
    println!("  --server2, -s2 <URL>  Server 2 WebSocket URL (default: ws://127.0.0.1:{})", WS_SERVER2_PORT);
    println!("  --hash                Treat input as HASH160 hash (40 hex chars)");
    println!("  --help, -h            Show this help message");
    println!();
    println!("Examples:");
    println!("  # Single query with script pubkey:");
    println!("  {} 76a914e4986f7364f238102f1889ef9d24d80e2d2d7a4488ac", program);
    println!();
    println!("  # Single query with HASH160 hash:");
    println!("  {} 09d9fb5e2c298cdf69a06fdc188334305e9cb20d --hash", program);
}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args: Vec<String> = env::args().collect();
    let (server1_url, server2_url, script_input, use_hash) = parse_args(&args);

    let client = PIRClientWs::new(server1_url.clone(), server2_url.clone());

    let script_hex = match script_input {
        Some(s) => s,
        None => {
            error!("No script provided. Use --help for usage.");
            std::process::exit(1);
        }
    };

    let script_hash = if use_hash {
        let hash_bytes = match hex2bin(&script_hex) {
            Ok(h) => h,
            Err(e) => {
                error!("Error parsing hash hex: {}", e);
                std::process::exit(1);
            }
        };
        if hash_bytes.len() != KEY_SIZE {
            error!("HASH160 hash must be exactly 20 bytes (40 hex chars), got {} bytes",
                   hash_bytes.len());
            std::process::exit(1);
        }
        let mut hash = [0u8; KEY_SIZE];
        hash.copy_from_slice(&hash_bytes);
        hash
    } else {
        match script_to_hash(&script_hex) {
            Ok(h) => h,
            Err(e) => {
                error!("Error computing script hash: {}", e);
                std::process::exit(1);
            }
        }
    };

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║       Two-Phase DPF-PIR UTXO Lookup (WebSocket)        ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ Server 1:     {:<46}║", server1_url);
    println!("║ Server 2:     {:<46}║", server2_url);
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ Script input: {:<46}║", &script_hex[..std::cmp::min(script_hex.len(), 46)]);
    println!("║ HASH160:      {:<46}║", bin2hex(&script_hash));
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    match client.lookup_utxo(&script_hash).await {
        Ok(Some(byte_offset)) => {
            let local_offset = byte_offset as usize % CHUNK_SIZE;
            println!("✓ Lookup successful!");
            println!("  Byte offset:  {}", byte_offset);
            println!("  Chunk index:  {}", byte_offset as usize / CHUNK_SIZE);
            println!("  Local offset: {}", local_offset);
            println!();

            match parse_utxo_entries(&client, byte_offset as usize).await {
                Ok(result) => {
                    let total_amount: u64 = result.entries.iter().map(|e| e.amount).sum();
                    let stats = &result.stats;

                    println!("╔══════════════════════════════════════════════════════════════╗");
                    println!("║                    UTXO QUERY RESULT                        ║");
                    println!("╠══════════════════════════════════════════════════════════════╣");
                    println!("║ UTXO Count:   {:<45}║", result.entries.len());
                    println!("║ Total Amount: {:<45}║", format!("{} satoshis ({:.8} BTC)",
                        total_amount, total_amount as f64 / 100_000_000.0));
                    println!("╠══════════════════════════════════════════════════════════════╣");
                    println!("║                    QUERY STATISTICS                         ║");
                    println!("╠══════════════════════════════════════════════════════════════╣");
                    println!("║ Chunk Queries:    {:<40}║", stats.chunk_queries);
                    println!("║ Chunks Range:     {:<40}║",
                        format!("[{}..{}]", stats.start_chunk_index, stats.end_chunk_index));
                    println!("║ Data Retrieved:   {:<40}║",
                        format!("{} bytes ({:.2} KB)", stats.total_bytes_received,
                               stats.total_bytes_received as f64 / 1024.0));
                    println!("║ Data Consumed:    {:<40}║",
                        format!("{} bytes", stats.bytes_read));
                    println!("╚══════════════════════════════════════════════════════════════╝");
                    println!();

                    let display_count = result.entries.len().min(20);
                    if result.entries.len() > 20 {
                        println!("Showing first 20 of {} UTXOs:", result.entries.len());
                    } else {
                        println!("UTXO Entries:");
                    }
                    println!();

                    for (i, entry) in result.entries.iter().take(display_count).enumerate() {
                        println!("  UTXO #{}:", i + 1);
                        println!("    TXID: {}", bin2hex_reversed(&entry.txid));
                        println!("    URL:  https://mempool.space/tx/{}", bin2hex_reversed(&entry.txid));
                        println!("    Vout:             {}", entry.vout);
                        println!("    Amount:           {} satoshis ({:.8} BTC)",
                            entry.amount, entry.amount as f64 / 100_000_000.0);
                    }

                    if result.entries.len() > 20 {
                        println!();
                        println!("  ... and {} more UTXOs", result.entries.len() - 20);
                    }
                }
                Err(e) => {
                    error!("Failed to parse UTXO entries: {}", e);
                    println!("Chunk data retrieved but parsing failed: {}", e);
                }
            }
        }
        Ok(None) => {
            println!("✗ Script hash not found in database.");
            println!("  This address has no UTXOs in the database.");
        }
        Err(e) => {
            error!("Lookup failed: {}", e);
            std::process::exit(1);
        }
    }
}
