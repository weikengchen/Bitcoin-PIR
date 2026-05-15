//! Inverse-bit-packing for OnionPIRv2 plaintexts.
//!
//! Upstream OnionPIRv2 (after the SEAL-free port at commit `92fceb01`) ships
//! `Client::decrypt_response` that returns the raw plaintext as
//! `[u32 N (LE)][u64 coeff_0 (LE)]…[u64 coeff_{N-1} (LE)]` — bit-packed into
//! `N` ring coefficients with `bits_per_coeff = entry_size * 8 / poly_degree`
//! bits of payload per coefficient. The previous SEAL-based version returned
//! the inverse-unpacked entry bytes directly; the port moves that
//! responsibility into app code (INTEGRATION.md §1.4 / §1.5).
//!
//! This module implements both directions:
//!
//! * [`pack_bytes_into_coefficients`] — byte stream → `Vec<u64>` of length
//!   `poly_degree`, suitable for feeding into `Server::push_plaintexts`.
//! * [`unpack_onion_plaintext`] — the raw plaintext bytes returned by
//!   `Client::decrypt_response` → recovered byte stream.
//!
//! `pack` then `unpack` is identity on any byte stream of length
//! ≤ `entry_size`. The functions are pure, allocate-only, and have no FFI
//! or compile-time dependencies, so the same code can be used by:
//!
//! * the Rust client (`pir-sdk-client::onion`)
//! * the standalone OnionPIR CLI / bench (`runtime::bin::onionpir_*`)
//! * the build pipeline (`build::gen_*_onion`)
//! * a future `pir-sdk-wasm` `WasmOnionClient` (when the WASM bindings of
//!   the new fork get wired up — `web/src/onionpir_client.ts` is the
//!   current hand-rolled TS twin).
//!
//! ## Encoding details
//!
//! The packing fills a rolling `u128` buffer by shifting each successive
//! byte into the high bits, then drains the buffer one coefficient at a
//! time once it holds at least `bits_per_coeff` bits. Each coefficient
//! gets the low `bits_per_coeff` bits of the buffer (masked) and the
//! remainder shifts down.
//!
//! Because `bits_per_coeff` is always strictly less than `log2(PlainMod)`
//! by construction, the high bit of each coefficient stays zero — the
//! plaintext modulus reserves the top bit for noise-flooding headroom.
//!
//! The unpacker is the literal inverse: it pushes each coefficient into a
//! rolling `u128` buffer, then drains 8 bits at a time once the buffer
//! holds ≥ 8 bits.

/// Derive the bit width packed into each plaintext coefficient.
///
/// For OnionPIRv2 with `CONFIG_N2048_K1` defaults: `entry_size = 3328`,
/// `poly_degree = 2048` → `bits_per_coeff = 13`, matching the upstream
/// `PlainMod - 1 = 14 - 1` rule (the high bit is reserved for noise).
///
/// Returns `None` if the params are inconsistent (`entry_size * 8` not
/// divisible by `poly_degree` would mean we cannot exactly tile the
/// payload into coefficients — should never happen for a valid OnionPIR
/// config).
pub fn bits_per_coeff(entry_size: usize, poly_degree: usize) -> Option<u32> {
    if poly_degree == 0 {
        return None;
    }
    let total_bits = entry_size.checked_mul(8)?;
    if total_bits % poly_degree != 0 {
        return None;
    }
    Some((total_bits / poly_degree) as u32)
}

/// Pack a byte stream into `poly_degree` `u64` coefficients.
///
/// The output is exactly `poly_degree` long. Bytes are consumed in order;
/// unused high bits of the last coefficient are zero. If `bytes.len() >
/// entry_size` the surplus bytes are silently truncated (caller error —
/// the caller should know `entry_size` from `params_info(0).entry_size`).
///
/// This is the inverse of [`unpack_onion_plaintext`].
pub fn pack_bytes_into_coefficients(
    bytes: &[u8],
    entry_size: usize,
    poly_degree: usize,
) -> Vec<u64> {
    let bpc = bits_per_coeff(entry_size, poly_degree)
        .expect("entry_size * 8 must be a multiple of poly_degree");
    let mut out = vec![0u64; poly_degree];
    let mut buffer: u128 = 0;
    let mut offset: u32 = 0;
    let mut coeff_idx: usize = 0;
    let take = bytes.len().min(entry_size);
    for &b in &bytes[..take] {
        buffer |= (b as u128) << offset;
        offset += 8;
        while offset >= bpc {
            let mask: u128 = (1u128 << bpc) - 1;
            if coeff_idx >= poly_degree {
                // Should be unreachable when bytes.len() <= entry_size
                // and `bits_per_coeff` math checks out, but guard anyway.
                return out;
            }
            out[coeff_idx] = (buffer & mask) as u64;
            coeff_idx += 1;
            buffer >>= bpc;
            offset -= bpc;
        }
    }
    // Flush trailing partial buffer into the next coefficient. If
    // `bytes.len() == entry_size` and the bits align cleanly,
    // `offset` is zero here and this is a no-op.
    if offset > 0 && coeff_idx < poly_degree {
        let mask: u128 = (1u128 << bpc) - 1;
        out[coeff_idx] = (buffer & mask) as u64;
    }
    out
}

/// Decode the raw `decrypt_response` bytes into the original packed payload.
///
/// Input format (verbatim from `onion_ffi.cpp` / upstream Rust binding):
///
/// ```text
/// [u32 N (LE)][u64 coeff_0 (LE)]…[u64 coeff_{N-1} (LE)]
/// ```
///
/// `params_poly_degree` is what `params_info(0).poly_degree` returns
/// (currently always 2048 for `CONFIG_N2048_K1`). `entry_size` is the
/// per-plaintext payload length in bytes (3328 for the default config).
///
/// Returns the first `entry_size` payload bytes — i.e. what was originally
/// fed to [`pack_bytes_into_coefficients`].
///
/// Returns `None` on any of:
///
/// * `plaintext_bytes.len() < 4 + 8 * poly_degree` (truncated input)
/// * The leading `u32 N` does not equal `params_poly_degree`
/// * `bits_per_coeff(entry_size, poly_degree)` is None
///
/// The function does **not** validate that the coefficient high bits are
/// zero. A malformed plaintext (e.g. from a buggy server response) will
/// roundtrip lossily; that is the server's bug, not this decoder's.
pub fn unpack_onion_plaintext(
    plaintext_bytes: &[u8],
    params_poly_degree: usize,
    entry_size: usize,
) -> Option<Vec<u8>> {
    let bpc = bits_per_coeff(entry_size, params_poly_degree)?;
    let header_len = 4;
    let body_len = params_poly_degree.checked_mul(8)?;
    if plaintext_bytes.len() < header_len + body_len {
        return None;
    }
    // Header: u32 LE N. Must match the params; the upstream binding
    // emits exactly `poly_degree` coefficients, no fewer.
    let n_in_blob = u32::from_le_bytes(plaintext_bytes[0..4].try_into().ok()?);
    if (n_in_blob as usize) != params_poly_degree {
        return None;
    }

    // Body: N × u64 LE coefficients.
    let mut out = Vec::with_capacity(entry_size);
    let mut buffer: u128 = 0;
    let mut offset: u32 = 0;
    for i in 0..params_poly_degree {
        let off = header_len + i * 8;
        let c = u64::from_le_bytes(plaintext_bytes[off..off + 8].try_into().ok()?);
        // Mask high bits — the high `64 - bpc` bits of the coefficient
        // are not part of the payload. They should be zero for a clean
        // server response, but masking defensively keeps the byte
        // stream unaffected by noise / future encoding changes.
        let mask: u64 = if bpc == 64 { u64::MAX } else { (1u64 << bpc) - 1 };
        let payload_bits = c & mask;
        buffer |= (payload_bits as u128) << offset;
        offset += bpc;
        while offset >= 8 && out.len() < entry_size {
            out.push((buffer & 0xFF) as u8);
            buffer >>= 8;
            offset -= 8;
        }
        if out.len() == entry_size {
            break;
        }
    }
    // If we exited the loop early but still have residual bits in
    // `buffer`, they're padding from the last coefficient that didn't
    // make it into a full byte — discard.
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default OnionPIRv2 `CONFIG_N2048_K1` post-port shape.
    const N: usize = 2048;
    const ENTRY_SIZE: usize = 3328;

    #[test]
    fn bits_per_coeff_default_config() {
        assert_eq!(bits_per_coeff(ENTRY_SIZE, N), Some(13));
    }

    #[test]
    fn bits_per_coeff_inconsistent_returns_none() {
        // 3329 * 8 = 26632 not divisible by 2048 → None.
        assert_eq!(bits_per_coeff(3329, N), None);
        assert_eq!(bits_per_coeff(ENTRY_SIZE, 0), None);
    }

    /// Encode `pack(bytes)` as the decrypt_response wire format:
    /// `[u32 N (LE)][u64 coeff_i (LE)…]`.
    fn synthesize_wire_bytes(coeffs: &[u64]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(4 + 8 * coeffs.len());
        wire.extend_from_slice(&(coeffs.len() as u32).to_le_bytes());
        for c in coeffs {
            wire.extend_from_slice(&c.to_le_bytes());
        }
        wire
    }

    #[test]
    fn roundtrip_default_config_full_entry() {
        // Arbitrary "user data" of exactly `entry_size` bytes.
        let payload: Vec<u8> = (0..ENTRY_SIZE).map(|i| (i % 251) as u8).collect();
        let coeffs = pack_bytes_into_coefficients(&payload, ENTRY_SIZE, N);
        assert_eq!(coeffs.len(), N);
        // Every coefficient fits within 13 bits.
        for &c in &coeffs {
            assert!(c < (1u64 << 13), "coefficient {} exceeds 13 bits", c);
        }
        let wire = synthesize_wire_bytes(&coeffs);
        let recovered = unpack_onion_plaintext(&wire, N, ENTRY_SIZE).unwrap();
        assert_eq!(recovered.len(), ENTRY_SIZE);
        assert_eq!(recovered, payload);
    }

    #[test]
    fn roundtrip_short_payload_pads_with_zero() {
        // 100 bytes of payload, the rest is zero-padded inside the
        // coefficient stream. Unpack returns `entry_size` bytes, with
        // the trailing bytes all zero.
        let payload: Vec<u8> = (0..100u8).collect();
        let coeffs = pack_bytes_into_coefficients(&payload, ENTRY_SIZE, N);
        let wire = synthesize_wire_bytes(&coeffs);
        let recovered = unpack_onion_plaintext(&wire, N, ENTRY_SIZE).unwrap();
        assert_eq!(recovered.len(), ENTRY_SIZE);
        assert_eq!(&recovered[..100], &payload[..]);
        assert!(
            recovered[100..].iter().all(|&b| b == 0),
            "tail bytes should be zero, got {:?}",
            &recovered[100..120]
        );
    }

    #[test]
    fn unpack_rejects_short_input() {
        // 4 + 8*N - 1 bytes is just short.
        let short = vec![0u8; 4 + 8 * N - 1];
        assert!(unpack_onion_plaintext(&short, N, ENTRY_SIZE).is_none());
    }

    #[test]
    fn unpack_rejects_n_mismatch() {
        // u32 prefix says N=4096 but params say N=2048 → reject.
        let mut wire = vec![0u8; 4 + 8 * N];
        wire[0..4].copy_from_slice(&4096u32.to_le_bytes());
        assert!(unpack_onion_plaintext(&wire, N, ENTRY_SIZE).is_none());
    }

    #[test]
    fn pack_truncates_oversize_input() {
        // Input bigger than entry_size: surplus bytes silently dropped.
        // (Caller's responsibility to know entry_size.)
        let oversize: Vec<u8> = vec![0xABu8; ENTRY_SIZE + 100];
        let coeffs = pack_bytes_into_coefficients(&oversize, ENTRY_SIZE, N);
        let wire = synthesize_wire_bytes(&coeffs);
        let recovered = unpack_onion_plaintext(&wire, N, ENTRY_SIZE).unwrap();
        assert_eq!(recovered.len(), ENTRY_SIZE);
        assert!(recovered.iter().all(|&b| b == 0xAB));
    }

    /// A second config to make sure the algorithm isn't accidentally
    /// hardcoded to 13-bit coefficients. Use the upstream
    /// `CONFIG_N4096_K2_MP` shape: N=4096, entry_size=19968,
    /// bits_per_coeff = 19968*8 / 4096 = 39.
    #[test]
    fn roundtrip_n4096_k2_mp_shape() {
        const N4096: usize = 4096;
        const ENTRY_19968: usize = 19968;
        assert_eq!(bits_per_coeff(ENTRY_19968, N4096), Some(39));

        let payload: Vec<u8> = (0..ENTRY_19968).map(|i| (i & 0xFF) as u8).collect();
        let coeffs = pack_bytes_into_coefficients(&payload, ENTRY_19968, N4096);
        assert_eq!(coeffs.len(), N4096);
        let wire = synthesize_wire_bytes(&coeffs);
        let recovered = unpack_onion_plaintext(&wire, N4096, ENTRY_19968).unwrap();
        assert_eq!(recovered, payload);
    }
}
