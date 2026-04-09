//! OnionPIRv2 wire protocol + message types for Bitcoin PIR.
//!
//! This module exposes the WebSocket variant codes and encode/decode logic
//! for the OnionPIR request/response messages (key registration, batched
//! queries, Merkle sibling queries). It is consumed by:
//!
//!   - `bin/unified_server.rs` — the production server, which owns its own
//!     `PirServer` setup via consolidated `onion_index_all.bin` mmap +
//!     shared NTT store, and only uses this module for wire formats.
//!   - `bin/onionpir_client.rs` — the CLI client, which uses the same wire
//!     formats + the `REQ_*`/`RESP_*` variant constants.
//!
//! The older `GroupServers::load` / `populate_server` helper that built
//! one `PirServer` per PBC group from a cuckoo table file was removed
//! after the INDEX layout migrated to the consolidated `onion_index_all.bin`
//! format (see `gen_3_onion` + `unified_server.rs` INDEX load path).

// ─── Wire protocol constants for OnionPIR messages ──────────────────────────

// NOTE: 0x30-0x32 were the original OnionPIR codes but collide with
// REQ_MERKLE_SIBLING_BATCH (0x31) and REQ_MERKLE_TREE_TOP (0x32).
// Moved to 0x50-0x52 to avoid conflicts.
pub const REQ_REGISTER_KEYS: u8 = 0x50;
pub const REQ_ONIONPIR_INDEX_QUERY: u8 = 0x51;
pub const REQ_ONIONPIR_CHUNK_QUERY: u8 = 0x52;

pub const REQ_ONIONPIR_MERKLE_INDEX_SIBLING: u8 = 0x53;
pub const REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP: u8 = 0x54;
pub const REQ_ONIONPIR_MERKLE_DATA_SIBLING: u8 = 0x55;
pub const REQ_ONIONPIR_MERKLE_DATA_TREE_TOP: u8 = 0x56;

pub const RESP_KEYS_ACK: u8 = 0x50;
pub const RESP_ONIONPIR_INDEX_RESULT: u8 = 0x51;
pub const RESP_ONIONPIR_CHUNK_RESULT: u8 = 0x52;
pub const RESP_ONIONPIR_MERKLE_INDEX_SIBLING: u8 = 0x53;
pub const RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP: u8 = 0x54;
pub const RESP_ONIONPIR_MERKLE_DATA_SIBLING: u8 = 0x55;
pub const RESP_ONIONPIR_MERKLE_DATA_TREE_TOP: u8 = 0x56;

// ─── Wire protocol encoding/decoding ────────────────────────────────────────

/// Key registration request from client.
///
/// Wire format:
///   [4B galois_len][galois_keys][4B gsw_len][gsw_keys]
///   Optional trailing [1B db_id] — only present when db_id != 0 (backward compat).
pub struct RegisterKeysMsg {
    pub galois_keys: Vec<u8>,
    pub gsw_keys: Vec<u8>,
    /// Database ID to register keys against (0 = main DB; 1+ = delta DBs).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

impl RegisterKeysMsg {
    pub fn encode(&self) -> Vec<u8> {
        let trailing = if self.db_id != 0 { 1 } else { 0 };
        let payload_len = 1 + 4 + self.galois_keys.len() + 4 + self.gsw_keys.len() + trailing;
        let mut buf = Vec::with_capacity(4 + payload_len);
        buf.extend_from_slice(&(payload_len as u32).to_le_bytes());
        buf.push(REQ_REGISTER_KEYS);
        buf.extend_from_slice(&(self.galois_keys.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.galois_keys);
        buf.extend_from_slice(&(self.gsw_keys.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.gsw_keys);
        // Trailing db_id byte: only appended when non-zero for backward compatibility.
        if self.db_id != 0 {
            buf.push(self.db_id);
        }
        buf
    }

    pub fn decode(data: &[u8]) -> std::io::Result<Self> {
        // data starts after the variant byte
        if data.len() < 8 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "keys msg too short"));
        }
        let mut pos = 0;
        let gk_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + gk_len + 4 > data.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated galois keys"));
        }
        let galois_keys = data[pos..pos + gk_len].to_vec();
        pos += gk_len;
        let gsw_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + gsw_len > data.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated gsw keys"));
        }
        let gsw_keys = data[pos..pos + gsw_len].to_vec();
        pos += gsw_len;
        // Read trailing db_id if present (backward compatible: old clients don't send it).
        let db_id = if pos < data.len() { data[pos] } else { 0 };
        Ok(RegisterKeysMsg { galois_keys, gsw_keys, db_id })
    }
}

/// Batch of OnionPIR queries — one encrypted query blob per group.
///
/// Wire format:
///   [1B variant][2B round_id][1B num_groups]
///   For each group:
///     [4B query_len][query_data...]
///   (zero-length query_len means "skip this group / dummy")
///   Optional trailing [1B db_id] — only present when db_id != 0 (backward compat).
pub struct OnionPirBatchQuery {
    pub round_id: u16,
    pub queries: Vec<Vec<u8>>,
    /// Database ID to query (0 = main DB; 1+ = delta DBs).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

impl OnionPirBatchQuery {
    pub fn encode(&self, variant: u8) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(variant);
        payload.extend_from_slice(&self.round_id.to_le_bytes());
        payload.push(self.queries.len() as u8);
        for q in &self.queries {
            payload.extend_from_slice(&(q.len() as u32).to_le_bytes());
            payload.extend_from_slice(q);
        }
        // Trailing db_id byte: only appended when non-zero for backward compatibility.
        if self.db_id != 0 {
            payload.push(self.db_id);
        }
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    pub fn decode(data: &[u8]) -> std::io::Result<Self> {
        // data starts after the variant byte
        if data.len() < 3 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "query batch too short"));
        }
        let mut pos = 0;
        let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
        pos += 2;
        let num_groups = data[pos] as usize;
        pos += 1;
        let mut queries = Vec::with_capacity(num_groups);
        for _ in 0..num_groups {
            if pos + 4 > data.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated query"));
            }
            let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + len > data.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated query data"));
            }
            queries.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        // Read trailing db_id if present (backward compatible: old clients don't send it).
        let db_id = if pos < data.len() { data[pos] } else { 0 };
        Ok(OnionPirBatchQuery { round_id, queries, db_id })
    }
}

/// Batch of OnionPIR responses — one encrypted response blob per group.
///
/// Wire format: same shape as query batch.
pub struct OnionPirBatchResult {
    pub round_id: u16,
    pub results: Vec<Vec<u8>>,
}

impl OnionPirBatchResult {
    pub fn encode(&self, variant: u8) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(variant);
        payload.extend_from_slice(&self.round_id.to_le_bytes());
        payload.push(self.results.len() as u8);
        for r in &self.results {
            payload.extend_from_slice(&(r.len() as u32).to_le_bytes());
            payload.extend_from_slice(r);
        }
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    pub fn decode(data: &[u8]) -> std::io::Result<Self> {
        // data starts after the variant byte
        if data.len() < 3 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "result batch too short"));
        }
        let mut pos = 0;
        let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
        pos += 2;
        let num_buckets = data[pos] as usize;
        pos += 1;
        let mut results = Vec::with_capacity(num_buckets);
        for _ in 0..num_buckets {
            if pos + 4 > data.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated result"));
            }
            let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + len > data.len() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "truncated result data"));
            }
            results.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        Ok(OnionPirBatchResult { round_id, results })
    }
}

// Note: OnionPirServerInfo (binary format) removed — all clients now use JSON (0x03).
// The Java client (bitcoinj-pir) has its own copy and will need a similar migration.
