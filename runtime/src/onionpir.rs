//! OnionPIRv2 integration for 1-server Bitcoin PIR.
//!
//! Maps existing PBC cuckoo tables into OnionPIR databases.
//! Each PBC group becomes its own OnionPIR `Server` instance.
//! Within a group, each cuckoo bin maps to one OnionPIR entry (by index).
//!
//! Architecture:
//!   - K OnionPIR Server instances (one per PBC group)
//!   - All share the same `num_entries` (= bins_per_table), so clients
//!     can reuse a single set of encryption parameters
//!   - Client queries group g for entry i  ⟹  OnionPIR query to servers[g] at index i
//!   - Server returns encrypted entry  ⟹  client decrypts to get cuckoo bin contents

use onionpir::{self, Server as PirServer};
use std::path::Path;
use std::time::Instant;

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

// ─── OnionPIR database population ───────────────────────────────────────────

/// Populate one OnionPIR Server from a single group's cuckoo table data.
///
/// `table_bytes`: the raw bytes of this group's cuckoo table (no header — just bins).
///   Length must be `bins_per_table * bin_byte_size`.
/// `bins_per_table`: number of cuckoo bins in this group.
/// `bin_byte_size`: byte size of one cuckoo bin (all slots concatenated).
///   - Index level: INDEX_SLOTS_PER_BIN * INDEX_SLOT_SIZE = 4 * 17 = 68
///   - Chunk level: CHUNK_SLOTS_PER_BIN * CHUNK_SLOT_SIZE = 3 * 44 = 132
///
/// Each cuckoo bin becomes one OnionPIR entry at the same index.
/// If `entry_size > bin_byte_size`, the entry is zero-padded.
/// If `entry_size < bin_byte_size`, this panics — rebuild OnionPIR with larger EntrySize.
fn populate_server(
    server: &mut PirServer,
    table_bytes: &[u8],
    bins_per_table: usize,
    bin_byte_size: usize,
) {
    let p = onionpir::params_info(bins_per_table as u64);
    let entry_size = p.entry_size as usize;
    assert!(
        entry_size >= bin_byte_size,
        "OnionPIR entry_size ({}) < cuckoo bin size ({}). \
         Rebuild OnionPIR with EntrySize >= {}.",
        entry_size, bin_byte_size, bin_byte_size
    );

    let entries_per_pt = 1; // one entry per plaintext (standard for small entries)
    let fst_dim = p.fst_dim_sz as usize;
    let chunk_size = fst_dim * entries_per_pt * entry_size;

    for chunk_idx in 0..(p.other_dim_sz as usize) {
        let mut chunk_data = vec![0u8; chunk_size];

        for i in 0..fst_dim {
            let global_idx = chunk_idx * fst_dim * entries_per_pt + i;
            if global_idx < bins_per_table {
                let src_offset = global_idx * bin_byte_size;
                let dst_offset = i * entry_size;
                let src = &table_bytes[src_offset..src_offset + bin_byte_size];
                chunk_data[dst_offset..dst_offset + bin_byte_size].copy_from_slice(src);
                // remaining bytes in [dst_offset + bin_byte_size .. dst_offset + entry_size]
                // are already zero from vec initialization
            }
        }

        server.push_chunk(&chunk_data, chunk_idx);
    }
}

// ─── Bucket server set ──────────────────────────────────────────────────────

/// Manages K OnionPIR Server instances loaded from a cuckoo table file.
///
/// Each PBC group has its own preprocessed OnionPIR database.
/// Preprocessing is expensive (NTT transforms), so results are saved to disk
/// and mmap-loaded on subsequent runs.
pub struct GroupServers {
    pub servers: Vec<PirServer>,
    pub num_groups: usize,
    pub bins_per_table: usize,
    pub entry_size: usize,
}

impl GroupServers {
    /// Load or build OnionPIR databases for all groups from a cuckoo table file.
    ///
    /// Parameters:
    ///   - `cuckoo_mmap`: the full memory-mapped cuckoo file (header + all group tables)
    ///   - `header_size`: byte offset where group data starts (after file header)
    ///   - `num_groups`: K (number of PBC groups)
    ///   - `bins_per_table`: cuckoo bins per group
    ///   - `bin_byte_size`: bytes per cuckoo bin (all slots)
    ///   - `preprocess_dir`: directory for saving/loading preprocessed .bin files
    pub fn load(
        cuckoo_mmap: &[u8],
        header_size: usize,
        num_groups: usize,
        bins_per_table: usize,
        bin_byte_size: usize,
        preprocess_dir: &Path,
    ) -> Self {
        let p = onionpir::params_info(bins_per_table as u64);
        let entry_size = p.entry_size as usize;
        let padded_entries = p.num_entries as usize;

        println!("  OnionPIR params: num_entries={} (padded from {}), entry_size={}, fst_dim={}, other_dim={}",
            padded_entries, bins_per_table, entry_size, p.fst_dim_sz, p.other_dim_sz);

        let table_byte_size = bins_per_table * bin_byte_size;
        let mut servers = Vec::with_capacity(num_groups);

        for b in 0..num_groups {
            let preproc_path = preprocess_dir.join(format!("group_{}.bin", b));
            let mut server = PirServer::new(bins_per_table as u64);

            let loaded = preproc_path.exists()
                && server.load_db(preproc_path.to_str().expect("valid path"));

            if loaded {
                if b == 0 {
                    println!("  Loading preprocessed databases from {:?}", preprocess_dir);
                }
            } else {
                if b == 0 {
                    println!("  Building OnionPIR databases (this is slow — NTT preprocessing)...");
                }
                let t = Instant::now();

                let table_offset = header_size + b * table_byte_size;
                let table_bytes = &cuckoo_mmap[table_offset..table_offset + table_byte_size];
                populate_server(&mut server, table_bytes, bins_per_table, bin_byte_size);

                server.preprocess();

                // Ensure directory exists
                std::fs::create_dir_all(preprocess_dir).ok();
                server.save_db(preproc_path.to_str().expect("valid path"));

                if b % 10 == 0 || b + 1 == num_groups {
                    println!("    Group {}/{} preprocessed in {:.2?}", b + 1, num_groups, t.elapsed());
                }
            }

            servers.push(server);
        }

        GroupServers { servers, num_groups, bins_per_table, entry_size }
    }

    /// Register a client's encryption keys with ALL group servers.
    ///
    /// `galois_keys` and `gsw_keys` are the serialized SEAL keys from the client.
    /// These are several MB each and only sent once per session.
    pub fn register_client(&mut self, client_id: u64, galois_keys: &[u8], gsw_keys: &[u8]) {
        for server in &mut self.servers {
            server.set_galois_key(client_id, galois_keys);
            server.set_gsw_key(client_id, gsw_keys);
        }
    }

    /// Answer a batch of OnionPIR queries (one per group).
    ///
    /// `queries[g]` is the encrypted query for group `g`.
    /// Empty entries (zero-length) are skipped (no query for that group).
    /// Returns `responses[g]` = encrypted response (or empty if skipped).
    pub fn answer_batch(&mut self, client_id: u64, queries: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert_eq!(queries.len(), self.num_groups);
        queries.iter().enumerate().map(|(b, q)| {
            if q.is_empty() {
                Vec::new()
            } else {
                self.servers[b].answer_query(client_id, q)
            }
        }).collect()
    }
}

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
