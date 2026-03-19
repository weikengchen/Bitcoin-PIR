//! Simple Binary Protocol (SBP) for PIR communication.
//!
//! This is an application-specific binary format designed for simplicity and reliability:
//! - All integers are little-endian (native for x86/ARM and JavaScript)
//! - Strings/bytes use 4-byte length prefix (u32, sufficient for all cases)
//! - Enum variants use 1-byte discriminant
//! - No nested type tags - the variant determines the exact structure
//!
//! ## Request Format:
//! ```text
//! [1 byte: variant] [variant-specific fields...]
//! ```
//!
//! ## Response Format:
//! ```text
//! [1 byte: variant] [variant-specific fields...]
//! ```

use std::io::{self, Write};

use crate::database::DatabaseInfo;

// ============================================================================
// Request Types
// ============================================================================

/// Request variant discriminants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestVariant {
    Query = 0,
    QueryTwoLocations = 1,
    QueryDatabase = 2,
    QueryDatabaseSingle = 3,
    ListDatabases = 4,
    GetDatabaseInfo = 5,
    Ping = 6,
}

/// Request message
#[derive(Debug, Clone)]
pub enum Request {
    /// Query for a script hash at a specific bucket location (legacy)
    Query {
        bucket_index: u64,
        pir_query: Vec<u8>,
    },
    /// Query for both cuckoo hash locations in one request (legacy)
    QueryTwoLocations {
        pir_query1: Vec<u8>,
        pir_query2: Vec<u8>,
    },
    /// Query a specific database at two cuckoo hash locations
    QueryDatabase {
        database_id: String,
        pir_query1: Vec<u8>,
        pir_query2: Vec<u8>,
    },
    /// Query a single-location database
    QueryDatabaseSingle {
        database_id: String,
        pir_query: Vec<u8>,
    },
    /// List available databases on the server
    ListDatabases,
    /// Get information about a specific database
    GetDatabaseInfo {
        database_id: String,
    },
    /// Health check
    Ping,
}

impl Request {
    /// Encode this request to bytes using SBP format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_to(&mut buf).expect("Vec write should not fail");
        buf
    }

    /// Encode this request to a writer using SBP format
    pub fn encode_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        match self {
            Request::Query { bucket_index, pir_query } => {
                w.write_all(&[RequestVariant::Query as u8])?;
                w.write_all(&bucket_index.to_le_bytes())?;
                encode_bytes(&mut w, pir_query)?;
            }
            Request::QueryTwoLocations { pir_query1, pir_query2 } => {
                w.write_all(&[RequestVariant::QueryTwoLocations as u8])?;
                encode_bytes(&mut w, pir_query1)?;
                encode_bytes(&mut w, pir_query2)?;
            }
            Request::QueryDatabase { database_id, pir_query1, pir_query2 } => {
                w.write_all(&[RequestVariant::QueryDatabase as u8])?;
                encode_string(&mut w, database_id)?;
                encode_bytes(&mut w, pir_query1)?;
                encode_bytes(&mut w, pir_query2)?;
            }
            Request::QueryDatabaseSingle { database_id, pir_query } => {
                w.write_all(&[RequestVariant::QueryDatabaseSingle as u8])?;
                encode_string(&mut w, database_id)?;
                encode_bytes(&mut w, pir_query)?;
            }
            Request::ListDatabases => {
                w.write_all(&[RequestVariant::ListDatabases as u8])?;
            }
            Request::GetDatabaseInfo { database_id } => {
                w.write_all(&[RequestVariant::GetDatabaseInfo as u8])?;
                encode_string(&mut w, database_id)?;
            }
            Request::Ping => {
                w.write_all(&[RequestVariant::Ping as u8])?;
            }
        }
        Ok(())
    }

    /// Decode a request from bytes using SBP format
    pub fn decode(data: &[u8]) -> io::Result<Self> {
        let mut cursor = 0;
        Self::decode_from(&data, &mut cursor)
    }

    /// Decode a request from bytes with cursor position
    fn decode_from(data: &[u8], cursor: &mut usize) -> io::Result<Self> {
        if *cursor >= data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "No variant byte"));
        }

        let variant = data[*cursor];
        *cursor += 1;

        match variant {
            v if v == RequestVariant::Query as u8 => {
                let bucket_index = decode_u64(data, cursor)?;
                let pir_query = decode_bytes(data, cursor)?;
                Ok(Request::Query { bucket_index, pir_query })
            }
            v if v == RequestVariant::QueryTwoLocations as u8 => {
                let pir_query1 = decode_bytes(data, cursor)?;
                let pir_query2 = decode_bytes(data, cursor)?;
                Ok(Request::QueryTwoLocations { pir_query1, pir_query2 })
            }
            v if v == RequestVariant::QueryDatabase as u8 => {
                let database_id = decode_string(data, cursor)?;
                let pir_query1 = decode_bytes(data, cursor)?;
                let pir_query2 = decode_bytes(data, cursor)?;
                Ok(Request::QueryDatabase { database_id, pir_query1, pir_query2 })
            }
            v if v == RequestVariant::QueryDatabaseSingle as u8 => {
                let database_id = decode_string(data, cursor)?;
                let pir_query = decode_bytes(data, cursor)?;
                Ok(Request::QueryDatabaseSingle { database_id, pir_query })
            }
            v if v == RequestVariant::ListDatabases as u8 => {
                Ok(Request::ListDatabases)
            }
            v if v == RequestVariant::GetDatabaseInfo as u8 => {
                let database_id = decode_string(data, cursor)?;
                Ok(Request::GetDatabaseInfo { database_id })
            }
            v if v == RequestVariant::Ping as u8 => {
                Ok(Request::Ping)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown request variant: {}", variant),
            )),
        }
    }
}

// ============================================================================
// Response Types
// ============================================================================

/// Response variant discriminants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseVariant {
    QueryResult = 0,
    QueryTwoResults = 1,
    DatabaseList = 2,
    DatabaseInfo = 3,
    Error = 4,
    Pong = 5,
}

/// Response message
#[derive(Debug, Clone)]
pub enum Response {
    /// Query result containing the value at the queried location
    QueryResult {
        data: Vec<u8>,
    },
    /// Query result for two-location query (two independent results)
    QueryTwoResults {
        data1: Vec<u8>,
        data2: Vec<u8>,
    },
    /// List of available databases
    DatabaseList {
        databases: Vec<DatabaseInfo>,
    },
    /// Information about a specific database
    DatabaseInfo {
        info: DatabaseInfo,
    },
    /// Error response
    Error {
        message: String,
    },
    /// Pong response for health check
    Pong,
}

impl Response {
    /// Encode this response to bytes using SBP format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_to(&mut buf).expect("Vec write should not fail");
        buf
    }

    /// Encode this response to a writer using SBP format
    pub fn encode_to<W: Write>(&self, mut w: W) -> io::Result<()> {
        match self {
            Response::QueryResult { data } => {
                w.write_all(&[ResponseVariant::QueryResult as u8])?;
                encode_bytes(&mut w, data)?;
            }
            Response::QueryTwoResults { data1, data2 } => {
                w.write_all(&[ResponseVariant::QueryTwoResults as u8])?;
                encode_bytes(&mut w, data1)?;
                encode_bytes(&mut w, data2)?;
            }
            Response::DatabaseList { databases } => {
                w.write_all(&[ResponseVariant::DatabaseList as u8])?;
                encode_u32(&mut w, databases.len() as u32)?;
                for db in databases {
                    encode_database_info(&mut w, db)?;
                }
            }
            Response::DatabaseInfo { info } => {
                w.write_all(&[ResponseVariant::DatabaseInfo as u8])?;
                encode_database_info(&mut w, info)?;
            }
            Response::Error { message } => {
                w.write_all(&[ResponseVariant::Error as u8])?;
                encode_string(&mut w, message)?;
            }
            Response::Pong => {
                w.write_all(&[ResponseVariant::Pong as u8])?;
            }
        }
        Ok(())
    }

    /// Decode a response from bytes using SBP format
    pub fn decode(data: &[u8]) -> io::Result<Self> {
        let mut cursor = 0;
        Self::decode_from(data, &mut cursor)
    }

    /// Decode a response from bytes with cursor position
    fn decode_from(data: &[u8], cursor: &mut usize) -> io::Result<Self> {
        if *cursor >= data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "No variant byte"));
        }

        let variant = data[*cursor];
        *cursor += 1;

        match variant {
            v if v == ResponseVariant::QueryResult as u8 => {
                let data = decode_bytes(data, cursor)?;
                Ok(Response::QueryResult { data })
            }
            v if v == ResponseVariant::QueryTwoResults as u8 => {
                let data1 = decode_bytes(data, cursor)?;
                let data2 = decode_bytes(data, cursor)?;
                Ok(Response::QueryTwoResults { data1, data2 })
            }
            v if v == ResponseVariant::DatabaseList as u8 => {
                let count = decode_u32(data, cursor)? as usize;
                let mut databases = Vec::with_capacity(count);
                for _ in 0..count {
                    databases.push(decode_database_info(data, cursor)?);
                }
                Ok(Response::DatabaseList { databases })
            }
            v if v == ResponseVariant::DatabaseInfo as u8 => {
                let info = decode_database_info(data, cursor)?;
                Ok(Response::DatabaseInfo { info })
            }
            v if v == ResponseVariant::Error as u8 => {
                let message = decode_string(data, cursor)?;
                Ok(Response::Error { message })
            }
            v if v == ResponseVariant::Pong as u8 => {
                Ok(Response::Pong)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown response variant: {}", variant),
            )),
        }
    }
}

// ============================================================================
// Primitive Encoding/Decoding Functions
// ============================================================================

/// Encode a u32 in little-endian
#[inline]
fn encode_u32<W: Write>(w: &mut W, value: u32) -> io::Result<()> {
    w.write_all(&value.to_le_bytes())
}

/// Encode a usize in little-endian (as u64 for consistency)
#[inline]
fn encode_usize<W: Write>(w: &mut W, value: usize) -> io::Result<()> {
    w.write_all(&(value as u64).to_le_bytes())
}

/// Encode a byte slice with 4-byte length prefix
#[inline]
fn encode_bytes<W: Write>(w: &mut W, data: &[u8]) -> io::Result<()> {
    encode_u32(w, data.len() as u32)?;
    w.write_all(data)
}

/// Encode a string with 4-byte length prefix
#[inline]
fn encode_string<W: Write>(w: &mut W, s: &str) -> io::Result<()> {
    encode_bytes(w, s.as_bytes())
}

/// Encode a DatabaseInfo
fn encode_database_info<W: Write>(w: &mut W, info: &DatabaseInfo) -> io::Result<()> {
    encode_string(w, &info.id)?;
    encode_string(w, &info.data_path)?;
    encode_usize(w, info.entry_size)?;
    encode_usize(w, info.bucket_size)?;
    encode_usize(w, info.num_buckets)?;
    encode_usize(w, info.num_locations)?;
    encode_usize(w, info.total_size)?;
    Ok(())
}

/// Decode a u32 from little-endian
#[inline]
fn decode_u32(data: &[u8], cursor: &mut usize) -> io::Result<u32> {
    if *cursor + 4 > data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Not enough bytes for u32"));
    }
    let bytes: [u8; 4] = data[*cursor..*cursor + 4].try_into().unwrap();
    *cursor += 4;
    Ok(u32::from_le_bytes(bytes))
}

/// Decode a u64 from little-endian
#[inline]
fn decode_u64(data: &[u8], cursor: &mut usize) -> io::Result<u64> {
    if *cursor + 8 > data.len() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Not enough bytes for u64"));
    }
    let bytes: [u8; 8] = data[*cursor..*cursor + 8].try_into().unwrap();
    *cursor += 8;
    Ok(u64::from_le_bytes(bytes))
}

/// Decode a usize from little-endian (as u64)
#[inline]
fn decode_usize(data: &[u8], cursor: &mut usize) -> io::Result<usize> {
    let value = decode_u64(data, cursor)?;
    Ok(value as usize)
}

/// Decode a byte vector with 4-byte length prefix
#[inline]
fn decode_bytes(data: &[u8], cursor: &mut usize) -> io::Result<Vec<u8>> {
    let len = decode_u32(data, cursor)? as usize;
    if *cursor + len > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("Not enough bytes for data: need {}, have {}", len, data.len() - *cursor),
        ));
    }
    let result = data[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(result)
}

/// Decode a string with 4-byte length prefix
#[inline]
fn decode_string(data: &[u8], cursor: &mut usize) -> io::Result<String> {
    let bytes = decode_bytes(data, cursor)?;
    String::from_utf8(bytes).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("Invalid UTF-8: {}", e))
    })
}

/// Decode a DatabaseInfo
fn decode_database_info(data: &[u8], cursor: &mut usize) -> io::Result<DatabaseInfo> {
    let id = decode_string(data, cursor)?;
    let data_path = decode_string(data, cursor)?;
    let entry_size = decode_usize(data, cursor)?;
    let bucket_size = decode_usize(data, cursor)?;
    let num_buckets = decode_usize(data, cursor)?;
    let num_locations = decode_usize(data, cursor)?;
    let total_size = decode_usize(data, cursor)?;

    Ok(DatabaseInfo {
        id,
        data_path,
        entry_size,
        bucket_size,
        num_buckets,
        num_locations,
        total_size,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_pong() {
        let request = Request::Ping;
        let encoded = request.encode();
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], RequestVariant::Ping as u8);

        let decoded = Request::decode(&encoded).unwrap();
        assert!(matches!(decoded, Request::Ping));

        let response = Response::Pong;
        let encoded = response.encode();
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], ResponseVariant::Pong as u8);

        let decoded = Response::decode(&encoded).unwrap();
        assert!(matches!(decoded, Response::Pong));
    }

    #[test]
    fn test_error_response() {
        let response = Response::Error {
            message: "Database not found".to_string(),
        };
        let encoded = response.encode();
        
        // Verify structure: [variant:1][len:4][string:N]
        assert_eq!(encoded[0], ResponseVariant::Error as u8);
        
        let decoded = Response::decode(&encoded).unwrap();
        match decoded {
            Response::Error { message } => {
                assert_eq!(message, "Database not found");
            }
            _ => panic!("Expected Error variant"),
        }
    }

    #[test]
    fn test_query_database() {
        let request = Request::QueryDatabase {
            database_id: "utxo_chunks".to_string(),
            pir_query1: vec![1, 2, 3, 4],
            pir_query2: vec![5, 6, 7, 8],
        };
        let encoded = request.encode();

        // Verify structure: [variant:1][db_id_len:4][db_id:N][key1_len:4][key1:N][key2_len:4][key2:N]
        assert_eq!(encoded[0], RequestVariant::QueryDatabase as u8);

        let decoded = Request::decode(&encoded).unwrap();
        match decoded {
            Request::QueryDatabase { database_id, pir_query1, pir_query2 } => {
                assert_eq!(database_id, "utxo_chunks");
                assert_eq!(pir_query1, vec![1, 2, 3, 4]);
                assert_eq!(pir_query2, vec![5, 6, 7, 8]);
            }
            _ => panic!("Expected QueryDatabase variant"),
        }
    }

    #[test]
    fn test_query_result() {
        let response = Response::QueryResult {
            data: vec![0xAA; 1024],
        };
        let encoded = response.encode();
        
        // Verify structure: [variant:1][len:4][data:N]
        assert_eq!(encoded[0], ResponseVariant::QueryResult as u8);
        
        let decoded = Response::decode(&encoded).unwrap();
        match decoded {
            Response::QueryResult { data } => {
                assert_eq!(data.len(), 1024);
                assert!(data.iter().all(|&b| b == 0xAA));
            }
            _ => panic!("Expected QueryResult variant"),
        }
    }

    #[test]
    fn test_database_list() {
        let response = Response::DatabaseList {
            databases: vec![
                DatabaseInfo {
                    id: "db1".to_string(),
                    data_path: "/path/to/db1".to_string(),
                    entry_size: 32,
                    bucket_size: 4,
                    num_buckets: 1000,
                    num_locations: 2,
                    total_size: 128000,
                },
                DatabaseInfo {
                    id: "db2".to_string(),
                    data_path: "/path/to/db2".to_string(),
                    entry_size: 64,
                    bucket_size: 1,
                    num_buckets: 2000,
                    num_locations: 1,
                    total_size: 128000,
                },
            ],
        };
        let encoded = response.encode();
        let decoded = Response::decode(&encoded).unwrap();
        
        match decoded {
            Response::DatabaseList { databases } => {
                assert_eq!(databases.len(), 2);
                assert_eq!(databases[0].id, "db1");
                assert_eq!(databases[1].id, "db2");
            }
            _ => panic!("Expected DatabaseList variant"),
        }
    }
}
