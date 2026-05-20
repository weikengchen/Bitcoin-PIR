//! Wire-explorer helpers for HarmonyPIR frames.
//!
//! Exposes a `#[wasm_bindgen]` decoder that pulls the per-group sub-query
//! `count` fields out of a `REQ_HARMONY_BATCH_QUERY` (opcode `0x43`)
//! frame so JS consumers — notably the public dev site's wire-explorer at
//! <https://bitcoin-pir.github.io/playground/explorer> — can verify the
//! **HarmonyPIR Per-Group Request-Count Symmetry** privacy invariant
//! ("every per-group query slot, INDEX / CHUNK / sibling, sends exactly
//! `T − 1` sorted distinct `u32` indices") against live captured traffic.
//!
//! Without this decoder the JS side can only see frame envelopes — the
//! per-group `count` lives inside an opaque length-prefixed payload it
//! cannot parse, so the invariant was previously marked `n/a` at the
//! wire layer in the explorer UI.
//!
//! # Source-of-truth pinning
//!
//! The byte layout decoded here MUST stay in lock-step with
//! [`pir_runtime_core::protocol::decode_harmony_batch_query`] (and its
//! companion encoder). To prevent silent drift, the unit test
//! `harmony_decode_counts_matches_native_encoder` round-trips a fake
//! batch through the canonical native encoder and asserts our decoder
//! recovers identical counts. The mirror exists at all because
//! `pir-runtime-core` pulls in `libdpf`/`memmap2`/server-side deps that
//! do not compile to `wasm32-unknown-unknown` — the same reason
//! `pir-sdk-client::attest::decode_attest_response` mirrors
//! `pir_runtime_core::protocol::decode_attest_result`.

use wasm_bindgen::prelude::*;

/// Opcode for `REQ_HARMONY_BATCH_QUERY` — mirrors
/// `pir_runtime_core::protocol::REQ_HARMONY_BATCH_QUERY`.
const OPCODE_HARMONY_BATCH_QUERY: u8 = 0x43;

/// Decode the per-group sub-query `count` fields from a
/// `REQ_HARMONY_BATCH_QUERY` (opcode `0x43`) frame, returning one entry
/// per `(group, sub_query)` slot in declaration order so JS can assert
/// **HarmonyPIR Per-Group Request-Count Symmetry** on observed traffic.
///
/// # Input shapes accepted
///
/// `frame` may be supplied in either of the two shapes a wire-explorer
/// is likely to capture:
///
/// 1. **Full wire frame** — `[4B payload_len LE][1B opcode = 0x43][payload]`,
///    matching the bytes emitted on the WebSocket by
///    `pir_runtime_core::protocol::Request::encode`. Auto-detected when
///    `frame.len() >= 5`, the leading u32 equals `frame.len() - 4`, and
///    `frame[4] == 0x43`.
/// 2. **Stripped payload** — `[1B opcode = 0x43][payload]`, the shape a
///    middleware that already peels the length envelope would expose.
///    Auto-detected when the full-frame check fails but `frame[0] == 0x43`.
/// 3. **Raw payload** — just `[payload]` (no envelope, no opcode). Used
///    as the fallback when neither (1) nor (2) match. Callers who pre-
///    strip the opcode should hit this branch.
///
/// # Output
///
/// A flat `Uint32Array` of length `num_groups × sub_queries_per_group`,
/// in `(group, sub_query)` row-major order — i.e. the first
/// `sub_queries_per_group` entries belong to group 0, the next slab to
/// group 1, and so on. JS callers reshape with the same
/// `sub_queries_per_group` they read elsewhere in the frame.
///
/// Symmetry-check pattern:
/// ```text
/// const counts = harmony_decode_counts(frameBytes);
/// const t = readTFromHintsResponseElsewhere(); // T from REQ_HARMONY_HINTS
/// const ok = counts.every(c => c === t - 1);   // privacy invariant
/// ```
///
/// # Errors
///
/// Returns `Err(JsError)` for: empty input, opcode not `0x43` (when the
/// envelope check fails on a non-payload-shaped buffer), truncated header
/// (< 6 payload bytes), per-group `count` declared larger than the
/// remaining payload, or any other inconsistency that would also trip
/// the canonical native decoder.
#[wasm_bindgen]
pub fn harmony_decode_counts(frame: &[u8]) -> Result<Vec<u32>, JsError> {
    let payload = strip_envelope(frame)
        .map_err(|e| JsError::new(&format!("harmony_decode_counts: {}", e)))?;
    decode_payload_counts(payload)
        .map_err(|e| JsError::new(&format!("harmony_decode_counts: {}", e)))
}

/// Inspect `frame` and return the payload slice — i.e. the bytes after
/// the optional `[4B length][1B opcode = 0x43]` prefix.
///
/// Detection priority:
/// 1. Try the full envelope: `frame.len() >= 5`,
///    `u32::from_le_bytes(frame[0..4]) == frame.len() - 4`, and
///    `frame[4] == 0x43`. Returns `&frame[5..]`.
/// 2. Else if `frame[0] == 0x43`: treat as `[opcode][payload]`,
///    return `&frame[1..]`.
/// 3. Else: treat the whole buffer as a raw payload.
///
/// Pulled into its own function so the unit tests can call it directly
/// without going through `JsError` (which panics on non-wasm targets).
fn strip_envelope(frame: &[u8]) -> Result<&[u8], String> {
    if frame.is_empty() {
        return Err("empty frame".into());
    }
    // Shape 1: full wire frame [4B len LE][1B opcode][payload].
    if frame.len() >= 5 {
        let declared_len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        if declared_len == frame.len() - 4 && frame[4] == OPCODE_HARMONY_BATCH_QUERY {
            return Ok(&frame[5..]);
        }
    }
    // Shape 2: stripped envelope, opcode kept: [1B opcode][payload].
    if frame[0] == OPCODE_HARMONY_BATCH_QUERY {
        return Ok(&frame[1..]);
    }
    // Shape 3: raw payload (no envelope, no opcode). We have no opcode
    // to sanity-check here — the per-group / count consistency checks
    // inside `decode_payload_counts` are what catch a misrouted buffer.
    Ok(frame)
}

/// Walk the `HarmonyBatchQuery` *payload* layout — see
/// `pir_runtime_core::protocol::decode_harmony_batch_query` for the
/// canonical reader. This function only retains the per-group sub-query
/// `count` values; it intentionally drops `level`, `round_id`,
/// `group_id`, the actual index arrays, and the trailing `db_id` byte
/// because the wire-explorer's symmetry check only needs the counts.
///
/// Wire format being decoded (LE everywhere):
/// ```text
/// [1B level]
/// [2B round_id]
/// [2B num_groups]
/// [1B sub_queries_per_group]
/// per group (num_groups times):
///   [1B group_id]
///   per sub_query (sub_queries_per_group times):
///     [4B count][count × 4B u32 indices]
/// [optional 1B db_id, present iff non-zero]
/// ```
fn decode_payload_counts(data: &[u8]) -> Result<Vec<u32>, String> {
    // Header: 1 + 2 + 2 + 1 = 6 bytes.
    if data.len() < 6 {
        return Err("payload too short for HarmonyBatchQuery header (<6 bytes)".into());
    }
    // We don't surface level / round_id from this helper, but we still
    // consume their byte positions so `pos` matches the canonical
    // decoder's cursor exactly.
    let _level = data[0];
    let _round_id = u16::from_le_bytes([data[1], data[2]]);
    let num_groups = u16::from_le_bytes([data[3], data[4]]) as usize;
    let sub_queries_per_group = data[5] as usize;
    let mut pos = 6usize;
    let mut counts = Vec::with_capacity(num_groups.saturating_mul(sub_queries_per_group));
    for g in 0..num_groups {
        if pos >= data.len() {
            return Err(format!(
                "truncated batch: missing group_id for group #{}",
                g
            ));
        }
        // Consume the group_id byte (not surfaced).
        let _group_id = data[pos];
        pos += 1;
        for s in 0..sub_queries_per_group {
            if pos + 4 > data.len() {
                return Err(format!(
                    "truncated batch: missing 4B count for group #{} sub_query #{}",
                    g, s
                ));
            }
            let count =
                u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
            // Bounds-check the indices block declared by `count`, even
            // though we skip the bytes themselves. Catching this here
            // (vs. silently returning a count that points past EOF)
            // gives the wire-explorer a clear "frame inconsistent" error
            // instead of an apparently-fine count that fails further on.
            let indices_bytes = (count as usize).checked_mul(4).ok_or_else(|| {
                format!("count overflow in group #{} sub_query #{}: {}", g, s, count)
            })?;
            if pos + indices_bytes > data.len() {
                return Err(format!(
                    "truncated batch: group #{} sub_query #{} declared count={} \
                     needs {} bytes, only {} remain",
                    g,
                    s,
                    count,
                    indices_bytes,
                    data.len() - pos
                ));
            }
            pos += indices_bytes;
            counts.push(count);
        }
    }
    // Trailing `db_id` byte is optional — present iff non-zero in the
    // encoder, absent otherwise. Either way it doesn't affect counts.
    Ok(counts)
}

// Native-only test module — the parity tests below import
// `pir_runtime_core` to round-trip fixtures through the canonical
// encoder, and that crate (libdpf, memmap2, server-side deps) does not
// compile to `wasm32-unknown-unknown`. Matches the dev-dependency
// target-gate in `Cargo.toml`.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use pir_runtime_core::protocol::{
        encode_harmony_batch_query, HarmonyBatchItem, HarmonyBatchQuery,
    };

    fn make_batch(per_group_counts: &[Vec<u32>], sub_queries_per_group: u8) -> HarmonyBatchQuery {
        let items = per_group_counts
            .iter()
            .enumerate()
            .map(|(i, counts_for_group)| {
                assert_eq!(
                    counts_for_group.len(),
                    sub_queries_per_group as usize,
                    "fixture mismatch"
                );
                let sub_queries: Vec<Vec<u32>> = counts_for_group
                    .iter()
                    .map(|&c| (0u32..c).collect())
                    .collect();
                HarmonyBatchItem {
                    group_id: i as u8,
                    sub_queries,
                }
            })
            .collect();
        HarmonyBatchQuery {
            level: 1,
            round_id: 7,
            sub_queries_per_group,
            items,
            db_id: 0,
        }
    }

    #[test]
    fn strip_envelope_full_wire_frame() {
        // [4B len = 6][1B opcode][6B fake payload]
        let mut wire = Vec::new();
        wire.extend_from_slice(&7u32.to_le_bytes()); // payload_len = opcode + 6
        wire.push(OPCODE_HARMONY_BATCH_QUERY);
        wire.extend_from_slice(&[0xAA; 6]);
        let payload = strip_envelope(&wire).unwrap();
        assert_eq!(payload, &[0xAA; 6]);
    }

    #[test]
    fn strip_envelope_stripped_envelope_with_opcode() {
        // [1B opcode][payload]
        let mut wire = vec![OPCODE_HARMONY_BATCH_QUERY];
        wire.extend_from_slice(&[0xBB; 4]);
        let payload = strip_envelope(&wire).unwrap();
        assert_eq!(payload, &[0xBB; 4]);
    }

    #[test]
    fn strip_envelope_raw_payload() {
        // No envelope, no opcode. The leading byte is *not* 0x43 and the
        // length prefix doesn't match, so we fall through to raw.
        let payload_bytes = [0x01, 0x07, 0x00, 0x00, 0x00, 0x01];
        let payload = strip_envelope(&payload_bytes).unwrap();
        assert_eq!(payload, &payload_bytes[..]);
    }

    #[test]
    fn strip_envelope_empty_input_errs() {
        assert!(strip_envelope(&[]).is_err());
    }

    #[test]
    fn strip_envelope_prefers_full_wire_frame_when_both_match() {
        // Crafted so byte 0 *also* equals 0x43 (would match shape 2) AND
        // the LE length prefix is consistent with shape 1 — we expect
        // the shape-1 branch to win because it's more specific.
        //
        // Shape-1 requires `u32::from_le(frame[0..4]) == frame.len() - 4`
        // AND `frame[4] == 0x43`. To also have `frame[0] == 0x43` so
        // shape-2 *would* also match, we set the length prefix bytes to
        // `[0x43, 0x00, 0x00, 0x00]`, i.e. declared_len = 67. Then we
        // need `frame.len() - 4 == 67`, so `frame.len() == 71`, i.e. 4
        // header + 1 opcode + 66 payload bytes (67 trailing bytes total
        // matches the declared length, of which the opcode is one).
        let mut wire = Vec::new();
        wire.extend_from_slice(&67u32.to_le_bytes()); // frame[0..4] = [0x43, 0, 0, 0]
        wire.push(OPCODE_HARMONY_BATCH_QUERY); // frame[4] = 0x43
        wire.extend(std::iter::repeat(0xCC).take(66)); // 66 bytes of "payload"
        assert_eq!(wire[0], OPCODE_HARMONY_BATCH_QUERY); // shape 2 plausible
        assert_eq!(wire[4], OPCODE_HARMONY_BATCH_QUERY); // shape 1 trigger
        assert_eq!(wire.len(), 71);
        let payload = strip_envelope(&wire).unwrap();
        // Shape 1 wins → payload is `&frame[5..]`, length 66, all 0xCC.
        // (If shape 2 had won we'd get 70 bytes starting with [0, 0, 0, opcode, …].)
        assert_eq!(payload.len(), 66);
        assert!(payload.iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn harmony_decode_counts_matches_native_encoder() {
        // Build a representative batch via the canonical native encoder
        // and verify our wasm-side decoder recovers identical counts.
        // Three groups, two sub-queries per group, varying counts.
        let per_group = vec![vec![3u32, 5u32], vec![0u32, 7u32], vec![4u32, 4u32]];
        let batch = make_batch(&per_group, 2);
        let mut payload = Vec::new();
        encode_harmony_batch_query(&mut payload, &batch);

        // Test all three input shapes:

        // Raw payload.
        let counts_raw = decode_payload_counts(&payload).unwrap();
        assert_eq!(counts_raw, vec![3, 5, 0, 7, 4, 4]);

        // [opcode][payload].
        let mut stripped = vec![OPCODE_HARMONY_BATCH_QUERY];
        stripped.extend_from_slice(&payload);
        let counts_stripped = decode_payload_counts(strip_envelope(&stripped).unwrap()).unwrap();
        assert_eq!(counts_stripped, vec![3, 5, 0, 7, 4, 4]);

        // Full wire frame: [4B len][1B opcode][payload].
        let mut full = Vec::new();
        full.extend_from_slice(&((payload.len() + 1) as u32).to_le_bytes());
        full.push(OPCODE_HARMONY_BATCH_QUERY);
        full.extend_from_slice(&payload);
        let counts_full = decode_payload_counts(strip_envelope(&full).unwrap()).unwrap();
        assert_eq!(counts_full, vec![3, 5, 0, 7, 4, 4]);
    }

    #[test]
    fn harmony_decode_counts_with_nonzero_db_id_trailing_byte() {
        // db_id != 0 means the encoder appends a trailing byte. Our
        // decoder must not be confused by it.
        let per_group = vec![vec![1u32]];
        let mut batch = make_batch(&per_group, 1);
        batch.db_id = 7;
        let mut payload = Vec::new();
        encode_harmony_batch_query(&mut payload, &batch);
        // The encoder appends 1 byte for the nonzero db_id.
        assert_eq!(*payload.last().unwrap(), 7);
        let counts = decode_payload_counts(&payload).unwrap();
        assert_eq!(counts, vec![1]);
    }

    #[test]
    fn harmony_decode_counts_t_minus_1_symmetry_witness() {
        // The privacy invariant this binding exists to validate: every
        // slot reports count = T-1 for a fixed T. With T=4 → count=3.
        // Three groups × two sub-queries, all 3.
        let t_minus_1 = 3u32;
        let per_group = vec![vec![t_minus_1; 2]; 3];
        let batch = make_batch(&per_group, 2);
        let mut payload = Vec::new();
        encode_harmony_batch_query(&mut payload, &batch);
        let counts = decode_payload_counts(&payload).unwrap();
        // The invariant the JS-side check will assert against:
        assert!(counts.iter().all(|&c| c == t_minus_1));
        assert_eq!(counts.len(), 6);
    }

    #[test]
    fn decode_payload_counts_truncated_header_errs() {
        assert!(decode_payload_counts(&[0u8; 5]).is_err());
    }

    #[test]
    fn decode_payload_counts_count_past_eof_errs() {
        // Header says 1 group, 1 sub_query/group, count=10 — but no
        // bytes follow. Decoder must reject.
        let mut bad = Vec::new();
        bad.push(0u8); // level
        bad.extend_from_slice(&0u16.to_le_bytes()); // round_id
        bad.extend_from_slice(&1u16.to_le_bytes()); // num_groups
        bad.push(1u8); // sub_queries_per_group
        bad.push(0u8); // group_id
        bad.extend_from_slice(&10u32.to_le_bytes()); // count
                                                     // No actual indices bytes — should error.
        let err = decode_payload_counts(&bad).unwrap_err();
        assert!(err.contains("truncated") || err.contains("declared"));
    }

    #[test]
    fn decode_payload_counts_zero_groups_is_ok() {
        // A valid empty batch (legal in theory) decodes to an empty
        // counts vec.
        let mut payload = Vec::new();
        payload.push(0u8); // level
        payload.extend_from_slice(&0u16.to_le_bytes()); // round_id
        payload.extend_from_slice(&0u16.to_le_bytes()); // num_groups = 0
        payload.push(2u8); // sub_queries_per_group (irrelevant when no groups)
        let counts = decode_payload_counts(&payload).unwrap();
        assert!(counts.is_empty());
    }
}
