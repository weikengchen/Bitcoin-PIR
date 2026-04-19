//! Simple binary protocol for two-level Batch PIR.
//!
//! All integers are little-endian. Messages are length-prefixed:
//!   [4B total_len][1B variant][payload...]
//!
//! The outer 4-byte length includes the variant byte.

use std::io;

// ─── Request variants ───────────────────────────────────────────────────────

pub const REQ_PING: u8 = 0x00;
pub const REQ_GET_INFO: u8 = 0x01;
pub const REQ_INDEX_BATCH: u8 = 0x11;
pub const REQ_CHUNK_BATCH: u8 = 0x21;
pub const REQ_MERKLE_SIBLING_BATCH: u8 = 0x31;
pub const REQ_MERKLE_TREE_TOP: u8 = 0x32;
pub const REQ_BUCKET_MERKLE_SIB_BATCH: u8 = 0x33;
pub const REQ_BUCKET_MERKLE_TREE_TOPS: u8 = 0x34;

// ─── HarmonyPIR request variants ────────────────────────────────────────────

pub const REQ_HARMONY_GET_INFO: u8 = 0x40;
pub const REQ_HARMONY_HINTS: u8 = 0x41;
pub const REQ_HARMONY_QUERY: u8 = 0x42;
pub const REQ_HARMONY_BATCH_QUERY: u8 = 0x43;

// ─── Extended request variants (multi-database) ────────────────────────────

pub const REQ_GET_DB_CATALOG: u8 = 0x02;

// ─── Monitoring ────────────────────────────────────────────────────────────

pub const REQ_RESIDENCY: u8 = 0x04;

// ─── Response variants ──────────────────────────────────────────────────────

pub const RESP_PONG: u8 = 0x00;
pub const RESP_INFO: u8 = 0x01;
pub const RESP_DB_CATALOG: u8 = 0x02;
pub const RESP_INDEX_BATCH: u8 = 0x11;
pub const RESP_CHUNK_BATCH: u8 = 0x21;
pub const RESP_MERKLE_SIBLING_BATCH: u8 = 0x31;
pub const RESP_MERKLE_TREE_TOP: u8 = 0x32;
pub const RESP_BUCKET_MERKLE_SIB_BATCH: u8 = 0x33;
pub const RESP_BUCKET_MERKLE_TREE_TOPS: u8 = 0x34;
pub const RESP_RESIDENCY: u8 = 0x04;
pub const RESP_ERROR: u8 = 0xFF;

// ─── HarmonyPIR response variants ──────────────────────────────────────────

pub const RESP_HARMONY_INFO: u8 = 0x40;
pub const RESP_HARMONY_HINTS: u8 = 0x41;
pub const RESP_HARMONY_QUERY: u8 = 0x42;
pub const RESP_HARMONY_BATCH_QUERY: u8 = 0x43;

// ─── Request types ──────────────────────────────────────────────────────────

/// A batch of DPF keys for one level.
/// Each group has N DPF keys (one per cuckoo hash function).
#[derive(Clone, Debug)]
pub struct BatchQuery {
    /// 0 for index, 1 for chunk
    pub level: u8,
    /// Round ID (only meaningful for chunk level; 0 for index)
    pub round_id: u16,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
    /// Per-group: list of DPF keys. Length = K (75) or K_CHUNK (80).
    /// Inner Vec length = number of cuckoo hash functions (2 for index, 3 for chunks).
    pub keys: Vec<Vec<Vec<u8>>>,
}

/// HarmonyPIR hint request: client asks Hint Server to compute hints.
///
/// Wire: [16B prp_key][1B prp_backend][1B level][1B num_groups][per group: 1B id]
///       [optional trailing 1B db_id, only when non-zero — backward compatible]
#[derive(Clone, Debug)]
pub struct HarmonyHintRequest {
    pub prp_key: [u8; 16],
    pub prp_backend: u8,
    pub level: u8,
    pub group_ids: Vec<u8>,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

/// HarmonyPIR query: client sends T indices for one group to Query Server.
///
/// Wire: [1B level][1B group_id][2B round_id][4B count][count × 4B u32 LE indices]
///       [optional trailing 1B db_id, only when non-zero — backward compatible]
#[derive(Clone, Debug)]
pub struct HarmonyQuery {
    pub level: u8,
    pub group_id: u8,
    pub round_id: u16,
    pub indices: Vec<u32>,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

/// HarmonyPIR query result: server returns T entries for one group.
#[derive(Clone, Debug)]
pub struct HarmonyQueryResult {
    pub group_id: u8,
    pub round_id: u16,
    pub data: Vec<u8>,
}

/// HarmonyPIR batch query: client sends queries for multiple groups in one message.
///
/// Wire format:
///   [1B level][2B round_id LE][2B num_groups LE][1B sub_queries_per_group]
///   per group:
///     [1B group_id]
///     per sub_query (× sub_queries_per_group):
///       [4B count LE][count × 4B u32 LE indices]
///   [optional trailing 1B db_id, only when non-zero — backward compatible]
#[derive(Clone, Debug)]
pub struct HarmonyBatchQuery {
    pub level: u8,
    pub round_id: u16,
    pub sub_queries_per_group: u8,
    /// Per-group items.  Each item has `sub_queries_per_group` sub-queries.
    pub items: Vec<HarmonyBatchItem>,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

#[derive(Clone, Debug)]
pub struct HarmonyBatchItem {
    pub group_id: u8,
    /// Each sub-query is a Vec of sorted u32 indices.
    pub sub_queries: Vec<Vec<u32>>,
}

/// HarmonyPIR batch result.
///
/// Wire format:
///   [1B level][2B round_id LE][2B num_groups LE][1B sub_results_per_group]
///   per group:
///     [1B group_id]
///     per sub_result (× sub_results_per_group):
///       [4B data_len LE][data_len bytes]
#[derive(Clone, Debug)]
pub struct HarmonyBatchResult {
    pub level: u8,
    pub round_id: u16,
    pub sub_results_per_group: u8,
    pub items: Vec<HarmonyBatchResultItem>,
}

#[derive(Clone, Debug)]
pub struct HarmonyBatchResultItem {
    pub group_id: u8,
    pub sub_results: Vec<Vec<u8>>,
}

pub enum Request {
    Ping,
    GetInfo,
    GetDbCatalog,
    IndexBatch(BatchQuery),
    ChunkBatch(BatchQuery),
    MerkleSiblingBatch(BatchQuery),
    BucketMerkleSibBatch(BatchQuery),
    HarmonyGetInfo,
    HarmonyHints(HarmonyHintRequest),
    HarmonyQuery(HarmonyQuery),
    HarmonyBatchQuery(HarmonyBatchQuery),
}

// ─── Response types ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub index_bins_per_table: u32,
    pub chunk_bins_per_table: u32,
    pub index_k: u8,
    pub chunk_k: u8,
    pub tag_seed: u64,
}

/// Info about a single database in the server's catalog.
#[derive(Clone, Debug)]
pub struct DatabaseCatalogEntry {
    /// Database ID (index into the server's database list).
    pub db_id: u8,
    /// 0 = full UTXO snapshot, 1 = delta between two heights.
    pub db_type: u8,
    /// Human-readable name (e.g. "main", "delta_940611_944000").
    pub name: String,
    /// Base height (0 for full snapshots, start height for deltas).
    pub base_height: u32,
    /// Tip height (snapshot height for full, end height for deltas).
    pub height: u32,
    /// INDEX-level bins_per_table.
    pub index_bins_per_table: u32,
    /// CHUNK-level bins_per_table.
    pub chunk_bins_per_table: u32,
    /// INDEX-level group count.
    pub index_k: u8,
    /// CHUNK-level group count.
    pub chunk_k: u8,
    /// Tag seed for INDEX-level fingerprints.
    pub tag_seed: u64,
    /// DPF domain exponent for INDEX level.
    pub dpf_n_index: u8,
    /// DPF domain exponent for CHUNK level.
    pub dpf_n_chunk: u8,
    /// Whether this database has per-bucket bin Merkle verification data.
    pub has_bucket_merkle: bool,
}

/// Server's database catalog listing all available databases.
#[derive(Clone, Debug)]
pub struct DatabaseCatalog {
    pub databases: Vec<DatabaseCatalogEntry>,
}

#[derive(Clone, Debug)]
pub struct BatchResult {
    pub level: u8,
    pub round_id: u16,
    /// Per-group: list of results. Same structure as request keys.
    pub results: Vec<Vec<Vec<u8>>>,
}

pub enum Response {
    Pong,
    Info(ServerInfo),
    DbCatalog(DatabaseCatalog),
    IndexBatch(BatchResult),
    ChunkBatch(BatchResult),
    MerkleSiblingBatch(BatchResult),
    BucketMerkleSibBatch(BatchResult),
    Error(String),
    HarmonyInfo(ServerInfo),
    HarmonyQueryResult(HarmonyQueryResult),
    HarmonyBatchResult(HarmonyBatchResult),
}

// ─── Encoding ───────────────────────────────────────────────────────────────

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Request::Ping => {
                payload.push(REQ_PING);
            }
            Request::GetInfo => {
                payload.push(REQ_GET_INFO);
            }
            Request::GetDbCatalog => {
                payload.push(REQ_GET_DB_CATALOG);
            }
            Request::IndexBatch(q) => {
                payload.push(REQ_INDEX_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::ChunkBatch(q) => {
                payload.push(REQ_CHUNK_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::MerkleSiblingBatch(q) => {
                payload.push(REQ_MERKLE_SIBLING_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::BucketMerkleSibBatch(q) => {
                payload.push(REQ_BUCKET_MERKLE_SIB_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::HarmonyGetInfo => {
                payload.push(REQ_HARMONY_GET_INFO);
            }
            Request::HarmonyHints(h) => {
                payload.push(REQ_HARMONY_HINTS);
                payload.extend_from_slice(&h.prp_key);
                payload.push(h.prp_backend);
                payload.push(h.level);
                payload.push(h.group_ids.len() as u8);
                payload.extend_from_slice(&h.group_ids);
                // Trailing db_id byte: only appended when non-zero for backward compatibility.
                if h.db_id != 0 {
                    payload.push(h.db_id);
                }
            }
            Request::HarmonyQuery(q) => {
                payload.push(REQ_HARMONY_QUERY);
                payload.push(q.level);
                payload.push(q.group_id);
                payload.extend_from_slice(&q.round_id.to_le_bytes());
                payload.extend_from_slice(&(q.indices.len() as u32).to_le_bytes());
                for idx in &q.indices {
                    payload.extend_from_slice(&idx.to_le_bytes());
                }
                // Trailing db_id byte: only appended when non-zero for backward compatibility.
                if q.db_id != 0 {
                    payload.push(q.db_id);
                }
            }
            Request::HarmonyBatchQuery(q) => {
                payload.push(REQ_HARMONY_BATCH_QUERY);
                encode_harmony_batch_query(&mut payload, q);
            }
        }
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty request"));
        }
        match data[0] {
            REQ_PING => Ok(Request::Ping),
            REQ_GET_INFO => Ok(Request::GetInfo),
            REQ_GET_DB_CATALOG => Ok(Request::GetDbCatalog),
            REQ_INDEX_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::IndexBatch(q))
            }
            REQ_CHUNK_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::ChunkBatch(q))
            }
            REQ_MERKLE_SIBLING_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::MerkleSiblingBatch(q))
            }
            REQ_BUCKET_MERKLE_SIB_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::BucketMerkleSibBatch(q))
            }
            REQ_HARMONY_GET_INFO => Ok(Request::HarmonyGetInfo),
            REQ_HARMONY_HINTS => {
                let h = decode_harmony_hint_request(&data[1..])?;
                Ok(Request::HarmonyHints(h))
            }
            REQ_HARMONY_QUERY => {
                let q = decode_harmony_query(&data[1..])?;
                Ok(Request::HarmonyQuery(q))
            }
            REQ_HARMONY_BATCH_QUERY => {
                let q = decode_harmony_batch_query(&data[1..])?;
                Ok(Request::HarmonyBatchQuery(q))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown request variant: 0x{:02x}", v),
            )),
        }
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Response::Pong => {
                payload.push(RESP_PONG);
            }
            Response::Info(info) => {
                payload.push(RESP_INFO);
                payload.extend_from_slice(&info.index_bins_per_table.to_le_bytes());
                payload.extend_from_slice(&info.chunk_bins_per_table.to_le_bytes());
                payload.push(info.index_k);
                payload.push(info.chunk_k);
                payload.extend_from_slice(&info.tag_seed.to_le_bytes());
            }
            Response::DbCatalog(cat) => {
                payload.push(RESP_DB_CATALOG);
                encode_db_catalog(&mut payload, cat);
            }
            Response::IndexBatch(r) => {
                payload.push(RESP_INDEX_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::ChunkBatch(r) => {
                payload.push(RESP_CHUNK_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::MerkleSiblingBatch(r) => {
                payload.push(RESP_MERKLE_SIBLING_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::BucketMerkleSibBatch(r) => {
                payload.push(RESP_BUCKET_MERKLE_SIB_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::Error(msg) => {
                payload.push(RESP_ERROR);
                let bytes = msg.as_bytes();
                payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                payload.extend_from_slice(bytes);
            }
            Response::HarmonyInfo(info) => {
                payload.push(RESP_HARMONY_INFO);
                payload.extend_from_slice(&info.index_bins_per_table.to_le_bytes());
                payload.extend_from_slice(&info.chunk_bins_per_table.to_le_bytes());
                payload.push(info.index_k);
                payload.push(info.chunk_k);
                payload.extend_from_slice(&info.tag_seed.to_le_bytes());
            }
            Response::HarmonyQueryResult(r) => {
                payload.push(RESP_HARMONY_QUERY);
                payload.push(r.group_id);
                payload.extend_from_slice(&r.round_id.to_le_bytes());
                payload.extend_from_slice(&r.data);
            }
            Response::HarmonyBatchResult(r) => {
                payload.push(RESP_HARMONY_BATCH_QUERY);
                encode_harmony_batch_result(&mut payload, r);
            }
        }
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty response"));
        }
        match data[0] {
            RESP_PONG => Ok(Response::Pong),
            RESP_INFO => {
                if data.len() < 19 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "info too short"));
                }
                Ok(Response::Info(ServerInfo {
                    index_bins_per_table: u32::from_le_bytes(data[1..5].try_into().unwrap()),
                    chunk_bins_per_table: u32::from_le_bytes(data[5..9].try_into().unwrap()),
                    index_k: data[9],
                    chunk_k: data[10],
                    tag_seed: u64::from_le_bytes(data[11..19].try_into().unwrap()),
                }))
            }
            RESP_DB_CATALOG => {
                let cat = decode_db_catalog(&data[1..])?;
                Ok(Response::DbCatalog(cat))
            }
            RESP_INDEX_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::IndexBatch(r))
            }
            RESP_CHUNK_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::ChunkBatch(r))
            }
            RESP_MERKLE_SIBLING_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::MerkleSiblingBatch(r))
            }
            RESP_BUCKET_MERKLE_SIB_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::BucketMerkleSibBatch(r))
            }
            RESP_ERROR => {
                let len = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
                let msg = String::from_utf8_lossy(&data[5..5 + len]).to_string();
                Ok(Response::Error(msg))
            }
            RESP_HARMONY_INFO => {
                if data.len() < 19 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony info too short"));
                }
                Ok(Response::HarmonyInfo(ServerInfo {
                    index_bins_per_table: u32::from_le_bytes(data[1..5].try_into().unwrap()),
                    chunk_bins_per_table: u32::from_le_bytes(data[5..9].try_into().unwrap()),
                    index_k: data[9],
                    chunk_k: data[10],
                    tag_seed: u64::from_le_bytes(data[11..19].try_into().unwrap()),
                }))
            }
            RESP_HARMONY_QUERY => {
                if data.len() < 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony query result too short"));
                }
                Ok(Response::HarmonyQueryResult(HarmonyQueryResult {
                    group_id: data[1],
                    round_id: u16::from_le_bytes(data[2..4].try_into().unwrap()),
                    data: data[4..].to_vec(),
                }))
            }
            RESP_HARMONY_BATCH_QUERY => {
                let r = decode_harmony_batch_result(&data[1..])?;
                Ok(Response::HarmonyBatchResult(r))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown response variant: 0x{:02x}", v),
            )),
        }
    }
}

// ─── Batch encoding helpers ─────────────────────────────────────────────────

/// Wire format:
///   [2B round_id][1B num_groups][1B keys_per_group]
///   For each group:
///     For each key (keys_per_group times):
///       [2B key_len][key_data]
fn encode_batch_query(buf: &mut Vec<u8>, q: &BatchQuery) {
    buf.extend_from_slice(&q.round_id.to_le_bytes());
    buf.push(q.keys.len() as u8);
    let keys_per_group = q.keys.first().map_or(0, |k| k.len()) as u8;
    buf.push(keys_per_group);
    for group_keys in &q.keys {
        for k in group_keys {
            buf.extend_from_slice(&(k.len() as u16).to_le_bytes());
            buf.extend_from_slice(k);
        }
    }
    // Trailing db_id byte: only appended when non-zero for backward compatibility.
    if q.db_id != 0 {
        buf.push(q.db_id);
    }
}

fn decode_batch_query(data: &[u8]) -> io::Result<BatchQuery> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "batch query too short"));
    }
    let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_groups = data[pos] as usize;
    pos += 1;
    let keys_per_group = data[pos] as usize;
    pos += 1;
    let mut keys = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        let mut group_keys = Vec::with_capacity(keys_per_group);
        for _ in 0..keys_per_group {
            if pos + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key"));
            }
            let len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key data"));
            }
            group_keys.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        keys.push(group_keys);
    }
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if pos < data.len() { data[pos] } else { 0 };
    Ok(BatchQuery {
        level: 0,
        round_id,
        db_id,
        keys,
    })
}

fn encode_batch_result(buf: &mut Vec<u8>, r: &BatchResult) {
    buf.extend_from_slice(&r.round_id.to_le_bytes());
    buf.push(r.results.len() as u8);
    let results_per_group = r.results.first().map_or(0, |r| r.len()) as u8;
    buf.push(results_per_group);
    for group_results in &r.results {
        for res in group_results {
            buf.extend_from_slice(&(res.len() as u16).to_le_bytes());
            buf.extend_from_slice(res);
        }
    }
}

fn decode_batch_result(data: &[u8]) -> io::Result<BatchResult> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "batch result too short"));
    }
    let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_groups = data[pos] as usize;
    pos += 1;
    let results_per_group = data[pos] as usize;
    pos += 1;
    let mut results = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        let mut group_results = Vec::with_capacity(results_per_group);
        for _ in 0..results_per_group {
            if pos + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated result"));
            }
            let len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated result data"));
            }
            group_results.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        results.push(group_results);
    }
    Ok(BatchResult {
        level: 0,
        round_id,
        results,
    })
}

// ─── HarmonyPIR encoding helpers ────────────────────────────────────────────

fn decode_harmony_hint_request(data: &[u8]) -> io::Result<HarmonyHintRequest> {
    // [16B prp_key][1B prp_backend][1B level][1B num_groups][per group: 1B id]
    // [optional trailing 1B db_id, only when non-zero — backward compatible]
    if data.len() < 19 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony hint request too short"));
    }
    let mut prp_key = [0u8; 16];
    prp_key.copy_from_slice(&data[0..16]);
    let prp_backend = data[16];
    let level = data[17];
    let num_groups = data[18] as usize;
    let pos = 19 + num_groups;
    if data.len() < pos {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated group list"));
    }
    let group_ids = data[19..pos].to_vec();
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if pos < data.len() { data[pos] } else { 0 };
    Ok(HarmonyHintRequest {
        prp_key,
        prp_backend,
        level,
        group_ids,
        db_id,
    })
}

// ─── HarmonyPIR batch encoding helpers ─────────────────────────────────────

fn encode_harmony_batch_query(buf: &mut Vec<u8>, q: &HarmonyBatchQuery) {
    buf.push(q.level);
    buf.extend_from_slice(&q.round_id.to_le_bytes());
    buf.extend_from_slice(&(q.items.len() as u16).to_le_bytes());
    buf.push(q.sub_queries_per_group);
    for item in &q.items {
        buf.push(item.group_id);
        for sq in &item.sub_queries {
            buf.extend_from_slice(&(sq.len() as u32).to_le_bytes());
            for &idx in sq {
                buf.extend_from_slice(&idx.to_le_bytes());
            }
        }
    }
    // Trailing db_id byte: only appended when non-zero for backward compatibility.
    if q.db_id != 0 {
        buf.push(q.db_id);
    }
}

fn decode_harmony_batch_query(data: &[u8]) -> io::Result<HarmonyBatchQuery> {
    if data.len() < 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony batch query too short"));
    }
    let level = data[0];
    let round_id = u16::from_le_bytes(data[1..3].try_into().unwrap());
    let num_groups = u16::from_le_bytes(data[3..5].try_into().unwrap()) as usize;
    let sub_queries_per_group = data[5];
    let mut pos = 6;
    let mut items = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        if pos >= data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch group"));
        }
        let group_id = data[pos];
        pos += 1;
        let mut sub_queries = Vec::with_capacity(sub_queries_per_group as usize);
        for _ in 0..sub_queries_per_group {
            if pos + 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch sub-query count"));
            }
            let count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + count * 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch indices"));
            }
            let mut indices = Vec::with_capacity(count);
            for i in 0..count {
                let off = pos + i * 4;
                indices.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
            }
            pos += count * 4;
            sub_queries.push(indices);
        }
        items.push(HarmonyBatchItem { group_id, sub_queries });
    }
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if pos < data.len() { data[pos] } else { 0 };
    Ok(HarmonyBatchQuery { level, round_id, sub_queries_per_group, items, db_id })
}

fn encode_harmony_batch_result(buf: &mut Vec<u8>, r: &HarmonyBatchResult) {
    buf.push(r.level);
    buf.extend_from_slice(&r.round_id.to_le_bytes());
    buf.extend_from_slice(&(r.items.len() as u16).to_le_bytes());
    buf.push(r.sub_results_per_group);
    for item in &r.items {
        buf.push(item.group_id);
        for sr in &item.sub_results {
            buf.extend_from_slice(&(sr.len() as u32).to_le_bytes());
            buf.extend_from_slice(sr);
        }
    }
}

fn decode_harmony_batch_result(data: &[u8]) -> io::Result<HarmonyBatchResult> {
    if data.len() < 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony batch result too short"));
    }
    let level = data[0];
    let round_id = u16::from_le_bytes(data[1..3].try_into().unwrap());
    let num_groups = u16::from_le_bytes(data[3..5].try_into().unwrap()) as usize;
    let sub_results_per_group = data[5];
    let mut pos = 6;
    let mut items = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        if pos >= data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch result group"));
        }
        let group_id = data[pos];
        pos += 1;
        let mut sub_results = Vec::with_capacity(sub_results_per_group as usize);
        for _ in 0..sub_results_per_group {
            if pos + 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch result len"));
            }
            let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch result data"));
            }
            sub_results.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        items.push(HarmonyBatchResultItem { group_id, sub_results });
    }
    Ok(HarmonyBatchResult { level, round_id, sub_results_per_group, items })
}

// ─── Database catalog encoding helpers ─────────────────────────────────────

/// Wire format:
///   [1B num_databases]
///   Per database:
///     [1B db_id][1B name_len][name bytes][4B height]
///     [4B index_bins][4B chunk_bins][1B index_k][1B chunk_k]
///     [8B tag_seed][1B dpf_n_index][1B dpf_n_chunk]
fn encode_db_catalog(buf: &mut Vec<u8>, cat: &DatabaseCatalog) {
    buf.push(cat.databases.len() as u8);
    for entry in &cat.databases {
        buf.push(entry.db_id);
        buf.push(entry.db_type);
        let name_bytes = entry.name.as_bytes();
        buf.push(name_bytes.len() as u8);
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&entry.base_height.to_le_bytes());
        buf.extend_from_slice(&entry.height.to_le_bytes());
        buf.extend_from_slice(&entry.index_bins_per_table.to_le_bytes());
        buf.extend_from_slice(&entry.chunk_bins_per_table.to_le_bytes());
        buf.push(entry.index_k);
        buf.push(entry.chunk_k);
        buf.extend_from_slice(&entry.tag_seed.to_le_bytes());
        buf.push(entry.dpf_n_index);
        buf.push(entry.dpf_n_chunk);
        buf.push(if entry.has_bucket_merkle { 1 } else { 0 });
    }
}

fn decode_db_catalog(data: &[u8]) -> io::Result<DatabaseCatalog> {
    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "catalog too short"));
    }
    let num_dbs = data[0] as usize;
    let mut pos = 1;
    let mut databases = Vec::with_capacity(num_dbs);
    for _ in 0..num_dbs {
        if pos + 3 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated catalog entry"));
        }
        let db_id = data[pos];
        pos += 1;
        let db_type = data[pos];
        pos += 1;
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated catalog name"));
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
        pos += name_len;
        // base_height(4) + height(4) + index_bins(4) + chunk_bins(4) + index_k(1) + chunk_k(1) + tag_seed(8) + dpf_n_index(1) + dpf_n_chunk(1) = 28
        // + has_bucket_merkle(1) = 29 (optional for backward compat)
        if pos + 28 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated catalog fields"));
        }
        let base_height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_bins_per_table = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let chunk_bins_per_table = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_k = data[pos];
        pos += 1;
        let chunk_k = data[pos];
        pos += 1;
        let tag_seed = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let dpf_n_index = data[pos];
        pos += 1;
        let dpf_n_chunk = data[pos];
        pos += 1;
        // has_bucket_merkle: always present in current wire format (1 byte, 0 or 1)
        let has_bucket_merkle = if pos < data.len() {
            let v = data[pos] != 0;
            pos += 1;
            v
        } else {
            false
        };
        databases.push(DatabaseCatalogEntry {
            db_id,
            db_type,
            name,
            base_height,
            height,
            index_bins_per_table,
            chunk_bins_per_table,
            index_k,
            chunk_k,
            tag_seed,
            dpf_n_index,
            dpf_n_chunk,
            has_bucket_merkle,
        });
    }
    Ok(DatabaseCatalog { databases })
}

fn decode_harmony_query(data: &[u8]) -> io::Result<HarmonyQuery> {
    // [1B level][1B group_id][2B round_id][4B count][count × 4B u32 LE]
    // [optional trailing 1B db_id, only when non-zero — backward compatible]
    if data.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony query too short"));
    }
    let level = data[0];
    let group_id = data[1];
    let round_id = u16::from_le_bytes(data[2..4].try_into().unwrap());
    let count = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let expected = 8 + count * 4;
    if data.len() < expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated harmony query indices"));
    }
    let mut indices = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * 4;
        indices.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
    }
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if expected < data.len() { data[expected] } else { 0 };
    Ok(HarmonyQuery {
        level,
        group_id,
        round_id,
        indices,
        db_id,
    })
}
