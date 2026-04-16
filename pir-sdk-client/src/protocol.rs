//! Shared wire-protocol helpers for PIR clients.
//!
//! All three native clients (`DpfClient`, `HarmonyClient`, `OnionClient`) speak
//! to the same `unified_server` binary and share a handful of primitives:
//!
//! * the `[4B len LE][1B variant][payload]` request frame,
//! * the `REQ_GET_DB_CATALOG` / `RESP_DB_CATALOG` shape defined by
//!   [`runtime::protocol`], and
//! * the generic `RESP_ERROR = 0xff` envelope the server uses for soft errors.
//!
//! Centralising them here keeps the clients in lock-step with the server's
//! wire format — previously each client maintained its own copy of
//! `decode_catalog`, and three separate off-by-one fixes had to be tracked
//! whenever the catalog layout changed.

use pir_sdk::{DatabaseCatalog, DatabaseInfo, DatabaseKind, PirError, PirResult};

// ─── Wire constants (mirror `runtime::protocol`) ────────────────────────────

/// Request-catalog variant byte. Supported by both Harmony roles
/// (hint + query) and the DPF/Onion `unified_server` builds — the match arm
/// in `unified_server.rs::REQ_GET_DB_CATALOG` runs before any role check.
pub(crate) const REQ_GET_DB_CATALOG: u8 = 0x02;

/// Successful catalog response variant.
pub(crate) const RESP_DB_CATALOG: u8 = 0x02;

/// Generic server-side error envelope: `[0xff][utf8 reason...]`. Clients must
/// short-circuit to a protocol error before attempting to decode the body.
pub(crate) const RESP_ERROR: u8 = 0xff;

// ─── Request framing ────────────────────────────────────────────────────────

/// Build a `[4B len LE][1B variant][payload]` request frame.
///
/// This is the wrapper the server expects on every WebSocket message —
/// `WsConnection::send` just writes the buffer through, and `roundtrip()`
/// strips the outer length prefix from the response before returning.
pub(crate) fn encode_request(variant: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 1 + payload.len();
    let mut buf = Vec::with_capacity(4 + total_len);
    buf.extend_from_slice(&(total_len as u32).to_le_bytes());
    buf.push(variant);
    buf.extend_from_slice(payload);
    buf
}

// ─── Catalog decoding ───────────────────────────────────────────────────────

/// Decode a `DatabaseCatalog` from the body of a `RESP_DB_CATALOG` message.
///
/// `data` is expected to start at the first byte AFTER the `RESP_DB_CATALOG`
/// variant byte — callers slice off the leading byte before calling this.
///
/// Wire format matches `runtime::protocol::encode_db_catalog`:
/// `[1B num_dbs][entry...]*` where each entry is
/// `[1B db_id][1B db_type][1B name_len][name][29B fixed]`.
///
/// `num_dbs` is a single byte — a prior u16 read silently accepted
/// single-entry catalogs (since `db_id == 0x00` made the high byte zero)
/// but then pushed the cursor off-by-one into every subsequent field,
/// producing "truncated catalog name" against real servers.
pub(crate) fn decode_catalog(data: &[u8]) -> PirResult<DatabaseCatalog> {
    if data.is_empty() {
        return Err(PirError::Decode("catalog too short".into()));
    }
    let num_dbs = data[0] as usize;
    let mut pos = 1;
    let mut databases = Vec::with_capacity(num_dbs);

    for _ in 0..num_dbs {
        if pos + 3 > data.len() {
            return Err(PirError::Decode("truncated catalog entry header".into()));
        }
        let db_id = data[pos];
        pos += 1;
        let db_type = data[pos];
        pos += 1;
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() {
            return Err(PirError::Decode("truncated catalog name".into()));
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
        pos += name_len;

        // 29 fixed bytes: base_height(4) + height(4) + index_bins(4)
        // + chunk_bins(4) + index_k(1) + chunk_k(1) + tag_seed(8)
        // + dpf_n_index(1) + dpf_n_chunk(1) + has_bucket_merkle(1).
        if pos + 29 > data.len() {
            return Err(PirError::Decode("truncated catalog fields".into()));
        }
        let base_height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_bins = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let chunk_bins = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
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
        let has_bucket_merkle = data[pos] != 0;
        pos += 1;

        let kind = if db_type == 1 {
            DatabaseKind::Delta { base_height }
        } else {
            DatabaseKind::Full
        };

        databases.push(DatabaseInfo {
            db_id,
            kind,
            name,
            height,
            index_bins,
            chunk_bins,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip one full catalog entry through `decode_catalog`, mirroring
    /// the server encoder's exact byte layout.
    #[test]
    fn decode_catalog_single_entry() {
        // 1 num_dbs + entry(1 db_id + 1 db_type + 1 name_len + 4 name + 29 fixed)
        let mut buf = Vec::new();
        buf.push(1u8); // num_dbs
        buf.push(0u8); // db_id
        buf.push(0u8); // db_type (full)
        buf.push(4u8); // name_len
        buf.extend_from_slice(b"main");
        buf.extend_from_slice(&0u32.to_le_bytes()); // base_height
        buf.extend_from_slice(&900_000u32.to_le_bytes()); // height
        buf.extend_from_slice(&750_000u32.to_le_bytes()); // index_bins
        buf.extend_from_slice(&1_500_000u32.to_le_bytes()); // chunk_bins
        buf.push(75u8); // index_k
        buf.push(80u8); // chunk_k
        buf.extend_from_slice(&0xdead_beef_cafe_f00du64.to_le_bytes()); // tag_seed
        buf.push(17u8); // dpf_n_index
        buf.push(18u8); // dpf_n_chunk
        buf.push(1u8); // has_bucket_merkle

        let catalog = decode_catalog(&buf).expect("decode");
        assert_eq!(catalog.databases.len(), 1);
        let db = &catalog.databases[0];
        assert_eq!(db.db_id, 0);
        assert!(matches!(db.kind, DatabaseKind::Full));
        assert_eq!(db.name, "main");
        assert_eq!(db.height, 900_000);
        assert_eq!(db.index_bins, 750_000);
        assert_eq!(db.chunk_bins, 1_500_000);
        assert_eq!(db.index_k, 75);
        assert_eq!(db.chunk_k, 80);
        assert_eq!(db.tag_seed, 0xdead_beef_cafe_f00d);
        assert!(db.has_bucket_merkle);
    }

    #[test]
    fn decode_catalog_rejects_empty() {
        let err = decode_catalog(&[]).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)));
    }

    #[test]
    fn decode_catalog_rejects_truncated_entry() {
        // num_dbs=1 but no entry bytes follow.
        let err = decode_catalog(&[1u8]).unwrap_err();
        assert!(matches!(err, PirError::Decode(_)));
    }

    #[test]
    fn encode_request_layout() {
        let r = encode_request(0x02, b"hi");
        // [len=3 LE][variant][payload]
        assert_eq!(&r[..4], &3u32.to_le_bytes());
        assert_eq!(r[4], 0x02);
        assert_eq!(&r[5..], b"hi");
    }
}
