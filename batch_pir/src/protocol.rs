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

// ─── Response variants ──────────────────────────────────────────────────────

pub const RESP_PONG: u8 = 0x00;
pub const RESP_INFO: u8 = 0x01;
pub const RESP_INDEX_BATCH: u8 = 0x11;
pub const RESP_CHUNK_BATCH: u8 = 0x21;
pub const RESP_ERROR: u8 = 0xFF;

// ─── Request types ──────────────────────────────────────────────────────────

/// A batch of DPF keys for one level.
/// Each bucket has two DPF keys (for the two cuckoo hash locations).
#[derive(Clone, Debug)]
pub struct BatchQuery {
    /// 0 for index, 1 for chunk
    pub level: u8,
    /// Round ID (only meaningful for chunk level; 0 for index)
    pub round_id: u16,
    /// Per-bucket: (dpf_key_q0, dpf_key_q1). Length = K (75) or K_CHUNK (80).
    pub keys: Vec<(Vec<u8>, Vec<u8>)>,
}

pub enum Request {
    Ping,
    GetInfo,
    IndexBatch(BatchQuery),
    ChunkBatch(BatchQuery),
}

// ─── Response types ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub index_bins_per_table: u32,
    pub chunk_bins_per_table: u32,
    pub index_k: u8,
    pub chunk_k: u8,
}

#[derive(Clone, Debug)]
pub struct BatchResult {
    pub level: u8,
    pub round_id: u16,
    /// Per-bucket: (result_q0, result_q1). Same length as the request keys.
    pub results: Vec<(Vec<u8>, Vec<u8>)>,
}

pub enum Response {
    Pong,
    Info(ServerInfo),
    IndexBatch(BatchResult),
    ChunkBatch(BatchResult),
    Error(String),
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
            Request::IndexBatch(q) => {
                payload.push(REQ_INDEX_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::ChunkBatch(q) => {
                payload.push(REQ_CHUNK_BATCH);
                encode_batch_query(&mut payload, q);
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
            REQ_INDEX_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::IndexBatch(q))
            }
            REQ_CHUNK_BATCH => {
                let q = decode_batch_query(&data[1..])?;
                Ok(Request::ChunkBatch(q))
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
            }
            Response::IndexBatch(r) => {
                payload.push(RESP_INDEX_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::ChunkBatch(r) => {
                payload.push(RESP_CHUNK_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::Error(msg) => {
                payload.push(RESP_ERROR);
                let bytes = msg.as_bytes();
                payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                payload.extend_from_slice(bytes);
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
                if data.len() < 11 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "info too short"));
                }
                Ok(Response::Info(ServerInfo {
                    index_bins_per_table: u32::from_le_bytes(data[1..5].try_into().unwrap()),
                    chunk_bins_per_table: u32::from_le_bytes(data[5..9].try_into().unwrap()),
                    index_k: data[9],
                    chunk_k: data[10],
                }))
            }
            RESP_INDEX_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::IndexBatch(r))
            }
            RESP_CHUNK_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::ChunkBatch(r))
            }
            RESP_ERROR => {
                let len = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
                let msg = String::from_utf8_lossy(&data[5..5 + len]).to_string();
                Ok(Response::Error(msg))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown response variant: 0x{:02x}", v),
            )),
        }
    }
}

// ─── Batch encoding helpers ─────────────────────────────────────────────────

fn encode_batch_query(buf: &mut Vec<u8>, q: &BatchQuery) {
    buf.extend_from_slice(&q.round_id.to_le_bytes());
    buf.push(q.keys.len() as u8);
    for (k0, k1) in &q.keys {
        buf.extend_from_slice(&(k0.len() as u16).to_le_bytes());
        buf.extend_from_slice(k0);
        buf.extend_from_slice(&(k1.len() as u16).to_le_bytes());
        buf.extend_from_slice(k1);
    }
}

fn decode_batch_query(data: &[u8]) -> io::Result<BatchQuery> {
    let mut pos = 0;
    if data.len() < 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "batch query too short"));
    }
    let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let count = data[pos] as usize;
    pos += 1;
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 2 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key"));
        }
        let len0 = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if pos + len0 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key data"));
        }
        let k0 = data[pos..pos + len0].to_vec();
        pos += len0;

        if pos + 2 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key"));
        }
        let len1 = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        if pos + len1 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key data"));
        }
        let k1 = data[pos..pos + len1].to_vec();
        pos += len1;

        keys.push((k0, k1));
    }
    Ok(BatchQuery {
        level: 0, // set by caller based on variant
        round_id,
        keys,
    })
}

fn encode_batch_result(buf: &mut Vec<u8>, r: &BatchResult) {
    buf.extend_from_slice(&r.round_id.to_le_bytes());
    buf.push(r.results.len() as u8);
    for (r0, r1) in &r.results {
        buf.extend_from_slice(&(r0.len() as u16).to_le_bytes());
        buf.extend_from_slice(r0);
        buf.extend_from_slice(&(r1.len() as u16).to_le_bytes());
        buf.extend_from_slice(r1);
    }
}

fn decode_batch_result(data: &[u8]) -> io::Result<BatchResult> {
    let mut pos = 0;
    if data.len() < 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "batch result too short"));
    }
    let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let count = data[pos] as usize;
    pos += 1;
    let mut results = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 2 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated result"));
        }
        let len0 = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let r0 = data[pos..pos + len0].to_vec();
        pos += len0;

        if pos + 2 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated result"));
        }
        let len1 = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
        pos += 2;
        let r1 = data[pos..pos + len1].to_vec();
        pos += len1;

        results.push((r0, r1));
    }
    Ok(BatchResult {
        level: 0,
        round_id,
        results,
    })
}
