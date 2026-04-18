//! WASM bindings for HarmonyPIR stateful PIR client.
//!
//! Exposes `HarmonyGroup` — a per-PBC-group client that manages the
//! relocation data structure (DS'), hint parities, and query execution.
//!
//! Protocol flow:
//!   1. `new(n, w, t, prp_key, group_id)` — create DS' with PRP
//!   2. `load_hints(data)` — load hint parities from Hint Server
//!   3. `build_request(q)` → request bytes to send to Query Server
//!   4. `process_response(response)` → recovered DB entry + hint update
//!   5. `serialize()` → persist full state to bytes
//!   6. `deserialize(data, prp_key, group_id, backend)` → restore from bytes

use wasm_bindgen::prelude::*;

use harmonypir::params::{Params, BETA};
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::prp::Prp;
use harmonypir::relocation::{RelocationDS, EMPTY};

#[cfg(feature = "fastprp")]
use harmonypir::prp::fast::FastPrpWrapper;

#[cfg(feature = "alf")]
use harmonypir::prp::alf::AlfPrp;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub mod state;

// ─── PRP backend constants ──────────────────────────────────────────────────

pub const PRP_HOANG: u8 = 0;
pub const PRP_FASTPRP: u8 = 1;
pub const PRP_ALF: u8 = 2;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Compute PRP rounds for domain = 2*n.
pub fn compute_rounds(n: u32) -> usize {
    let domain = 2 * n as usize;
    let log_domain = (domain as f64).log2().ceil() as usize;
    let r_raw = log_domain + 40;
    ((r_raw + BETA - 1) / BETA) * BETA
}

/// Derive per-group PRP key from master key + group_id.
pub fn derive_group_key(master_key: &[u8], group_id: u32) -> [u8; 16] {
    let mut key = [0u8; 16];
    let len = master_key.len().min(16);
    key[..len].copy_from_slice(&master_key[..len]);
    let id_bytes = group_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
}

/// Compute balanced T ≈ sqrt(2*n). Does NOT require T | 2N.
/// Instead, N will be padded up so 2*padded_n % T == 0.
pub fn find_best_t(n: u32) -> u32 {
    let two_n = 2 * n as u64;
    let t = (two_n as f64).sqrt().round().max(1.0) as u32;
    t
}

/// Pad N up so that 2*N is a multiple of T.
/// Returns (padded_n, t) where 2*padded_n % t == 0.
pub fn pad_n_for_t(n: u32, t: u32) -> (u32, u32) {
    let two_n = 2 * n as u64;
    let t64 = t as u64;
    // padded_2n must be a multiple of both T and 2 (so padded_n is an integer).
    // Use lcm(t, 2) as the rounding unit.
    let unit = if t64 % 2 == 0 { t64 } else { t64 * 2 };
    let padded_2n = ((two_n + unit - 1) / unit) * unit;
    let padded_n = (padded_2n / 2) as u32;
    debug_assert!(padded_2n % t64 == 0);
    debug_assert!(padded_2n == 2 * padded_n as u64);
    (padded_n, t)
}

/// Build a PRP for the given backend, key, and domain.
fn build_prp(backend: u8, key: &[u8; 16], domain: usize, n: u32, _prp_cache: &[u8]) -> Box<dyn Prp> {
    match backend {
        PRP_HOANG => {
            let r = compute_rounds(n);
            Box::new(HoangPrp::new(domain, r, key))
        }
        #[cfg(feature = "fastprp")]
        PRP_FASTPRP => {
            if _prp_cache.is_empty() {
                Box::new(FastPrpWrapper::new(key, domain))
            } else {
                Box::new(FastPrpWrapper::from_cache(key, domain, _prp_cache))
            }
        }
        #[cfg(feature = "alf")]
        PRP_ALF => {
            // ALF uses the key as both AES key and tweak (tweak varies per group via derive_group_key).
            Box::new(AlfPrp::new(key, domain, key, 0x4250_4952)) // app_id = "BPIR"
        }
        _ => {
            // Fallback to Hoang for unknown backends.
            let r = compute_rounds(n);
            Box::new(HoangPrp::new(domain, r, key))
        }
    }
}

/// Save PRP cache bytes (only for FastPRP, empty otherwise).
#[allow(unused_variables)]
fn save_prp_cache(backend: u8, prp_key: &[u8; 16], domain: usize, existing_cache: &[u8]) -> Vec<u8> {
    #[cfg(feature = "fastprp")]
    if backend == PRP_FASTPRP {
        // If we already have a cache, return it (it doesn't change).
        if !existing_cache.is_empty() {
            return existing_cache.to_vec();
        }
        // Build a fresh PRP just to save its cache.
        let prp = FastPrpWrapper::new(prp_key, domain);
        return prp.save_cache();
    }
    Vec::new()
}

/// Make RNG seed from key + group_id + query_count.
fn make_rng_seed(key: &[u8; 16], group_id: u32, query_count: u32) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(key);
    seed[16..20].copy_from_slice(&group_id.to_le_bytes());
    seed[20..24].copy_from_slice(&query_count.to_le_bytes());
    seed
}

// ─── WASM-exported types ────────────────────────────────────────────────────

#[wasm_bindgen]
pub struct HarmonyRequest {
    request_bytes: Vec<u8>,
    segment: u32,
    position: u32,
    query_index: u32,
}

#[wasm_bindgen]
impl HarmonyRequest {
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request_bytes.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn segment(&self) -> u32 {
        self.segment
    }
    #[wasm_bindgen(getter)]
    pub fn position(&self) -> u32 {
        self.position
    }
    #[wasm_bindgen(getter)]
    pub fn query_index(&self) -> u32 {
        self.query_index
    }
}

// ─── HarmonyGroup ──────────────────────────────────────────────────────────

/// Per-PBC-group HarmonyPIR client state.
#[wasm_bindgen]
pub struct HarmonyGroup {
    params: Params,
    ds: RelocationDS,
    hints: Vec<Vec<u8>>,
    query_count: usize,
    rng: ChaCha20Rng,
    /// PRP backend identifier (0=Hoang, 1=FastPRP).
    prp_backend: u8,
    /// Cached PRP data (for FastPRP). Empty for Hoang.
    prp_cache: Vec<u8>,
    // NOTE: `derived_key` / `group_id` are intentionally NOT stored on
    // the struct. `serialize()` doesn't persist them — instead,
    // `deserialize(data, prp_key, group_id, ...)` takes them as
    // explicit arguments and re-derives the per-group key via
    // `derive_group_key(prp_key, group_id)`. The caller is responsible
    // for remembering which `(prp_key, group_id)` pair was used at
    // construction time.
    /// Original (unpadded) N — the actual number of DB rows.
    /// The PRP domain uses padded_n (>= real_n) so that 2*padded_n % T == 0.
    /// Rows in [real_n, padded_n) are virtual empty rows.
    real_n: u32,
    /// Tracks which segments have been relocated (shadows DS' internal history).
    /// Needed for serialization since DS' history is private.
    relocated_segments: Vec<u32>,
    // Metadata for process_response().
    last_segment: usize,
    last_position: usize,
    last_query: usize,
    /// Maps each entry in the sorted request → its position in the segment.
    /// Used by process_response() to reconstruct per-position entries for relocation.
    last_position_map: Vec<usize>,
    /// Stashed state for deferred relocation (set by process_response_xor_only).
    deferred_entries: Option<Vec<Vec<u8>>>,
    deferred_answer: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl HarmonyGroup {
    /// Create a new HarmonyGroup with Hoang PRP (default).
    #[wasm_bindgen(constructor)]
    pub fn new(n: u32, w: u32, t: u32, prp_key: &[u8], group_id: u32) -> Result<HarmonyGroup, JsError> {
        Self::new_with_backend(n, w, t, prp_key, group_id, PRP_HOANG)
    }

    /// Create with a specific PRP backend.
    ///
    /// `n` is the real number of DB rows. Internally, N is padded up so
    /// that `2*padded_n % T == 0`. Rows in `[n, padded_n)` are virtual
    /// empty rows (the server returns zeros for them).
    pub fn new_with_backend(
        n: u32, w: u32, t: u32,
        prp_key: &[u8], group_id: u32,
        prp_backend: u8,
    ) -> Result<HarmonyGroup, JsError> {
        let w_usize = w as usize;
        let t_val = if t == 0 { find_best_t(n) } else { t };

        // Pad N so 2*padded_n is a multiple of T.
        let (padded_n, t_val) = pad_n_for_t(n, t_val);
        let padded_n_usize = padded_n as usize;
        let t_usize = t_val as usize;

        let params = Params::new(padded_n_usize, w_usize, t_usize)
            .map_err(|e| JsError::new(&format!("invalid params: {e:?}")))?;

        let key = derive_group_key(prp_key, group_id);
        let domain = 2 * padded_n_usize;
        let prp_cache = save_prp_cache(prp_backend, &key, domain, &[]);
        let prp = build_prp(prp_backend, &key, domain, padded_n, &prp_cache);

        let ds = RelocationDS::new(padded_n_usize, t_usize, prp)
            .map_err(|e| JsError::new(&format!("DS init failed: {e:?}")))?;

        let m = params.m;
        let hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w_usize]).collect();
        let seed = make_rng_seed(&key, group_id, 0);

        // `key` and `group_id` are consumed by `make_rng_seed` above
        // and by the `derive_group_key` call that produced `prp_cache` —
        // neither is retained on the struct. See the NOTE on
        // `HarmonyGroup` above for the rationale.
        let _ = key;
        let _ = group_id;

        Ok(HarmonyGroup {
            params,
            ds,
            hints,
            query_count: 0,
            rng: ChaCha20Rng::from_seed(seed),
            prp_backend,
            prp_cache,
            real_n: n,
            relocated_segments: Vec::new(),
            last_segment: 0,
            last_position: 0,
            last_query: 0,
            last_position_map: Vec::new(),
            deferred_entries: None,
            deferred_answer: None,
        })
    }

    /// Load pre-computed hint parities (M × w bytes, flat).
    pub fn load_hints(&mut self, hints_data: &[u8]) -> Result<(), JsError> {
        let m = self.params.m;
        let w = self.params.w;
        let expected = m * w;
        if hints_data.len() != expected {
            return Err(JsError::new(&format!(
                "expected {expected} bytes of hints, got {}", hints_data.len()
            )));
        }
        for i in 0..m {
            let start = i * w;
            self.hints[i].copy_from_slice(&hints_data[start..start + w]);
        }
        Ok(())
    }

    /// Build a request for database row `q`.
    ///
    /// Returns only the non-empty indices from the segment (excluding the
    /// dummy at position r), sorted for server cache efficiency.  The dummy
    /// is omitted entirely — the server never sees it.
    pub fn build_request(&mut self, q: u32) -> Result<HarmonyRequest, JsError> {
        let q_usize = q as usize;
        if q_usize >= self.params.n {
            return Err(JsError::new(&format!("query index {q} >= N={}", self.params.n)));
        }
        if self.query_count >= self.params.max_queries {
            return Err(JsError::new("no more queries available; rehint needed"));
        }

        let t = self.params.t;
        let c = self.ds.locate(q_usize)
            .map_err(|e| JsError::new(&format!("locate failed: {e:?}")))?;
        let s = c / t;
        let r = c % t;

        // Batch-access all cells in the segment except position r.
        // Uses 4-way PRP pipelining internally.
        let mut cells: Vec<usize> = Vec::with_capacity(t);
        let mut cell_positions: Vec<usize> = Vec::with_capacity(t); // original position in segment
        for i in 0..t {
            if i != r {
                cells.push(s * t + i);
                cell_positions.push(i);
            }
        }
        let values = self.ds.batch_access(&cells)
            .map_err(|e| JsError::new(&format!("batch_access failed: {e:?}")))?;

        let mut filtered: Vec<(u32, usize)> = Vec::new();
        for (k, &val) in values.iter().enumerate() {
            if val != EMPTY {
                filtered.push((val as u32, cell_positions[k]));
            }
        }

        // Sort by DB index for cache-friendly server lookups.
        filtered.sort_unstable_by_key(|&(idx, _)| idx);

        // Store position mapping for process_response().
        self.last_position_map = filtered.iter().map(|&(_, pos)| pos).collect();
        self.last_segment = s;
        self.last_position = r;
        self.last_query = q_usize;

        // Serialize only the sorted indices (no EMPTY markers, no dummy).
        let mut request_bytes = Vec::with_capacity(filtered.len() * 4);
        for &(idx, _) in &filtered {
            request_bytes.extend_from_slice(&idx.to_le_bytes());
        }

        Ok(HarmonyRequest {
            request_bytes,
            segment: s as u32,
            position: r as u32,
            query_index: q,
        })
    }

    /// Build a dummy request for a group the client doesn't actually need.
    ///
    /// Picks a random bin in `[0, real_n)` and builds a real-looking request.
    /// The client discards the server's response — **no `process_response`
    /// call, no hint consumed, no relocation**.
    ///
    /// The Query Server cannot distinguish this from a real request because it
    /// does not know the PRP key — it just sees sorted indices into the table.
    ///
    /// # TODO (privacy)
    ///
    /// The count of non-empty indices per segment follows a distribution that
    /// depends on T and N.  A truly indistinguishable dummy would need to sample
    /// from that same distribution (~Binomial(T, 0.5)) rather than using an
    /// actual segment.  For now we query a random real bin, which produces a
    /// realistic but not perfectly simulated count.  This must be revisited
    /// before production — see the protocol's privacy analysis.
    pub fn build_dummy_request(&mut self) -> Result<HarmonyRequest, JsError> {
        let q = self.rng.next_u32() % self.real_n as u32;

        // Save state that build_request will overwrite.
        let saved_segment = self.last_segment;
        let saved_position = self.last_position;
        let saved_query = self.last_query;
        let saved_map = std::mem::take(&mut self.last_position_map);

        let result = self.build_request(q);

        // Restore — the dummy never happened as far as client state is concerned.
        self.last_segment = saved_segment;
        self.last_position = saved_position;
        self.last_query = saved_query;
        self.last_position_map = saved_map;

        result
    }

    /// Build a **synthetic** dummy request that is distribution-matched with
    /// real queries but touches NO real segment or DS' state.
    ///
    /// Privacy rationale: `build_dummy_request()` queries a real segment
    /// without relocating it, which could let the server correlate the
    /// dummy with future real queries to the same segment.  Synthetic
    /// dummies avoid this — they sample random indices that look
    /// statistically identical to a real query:
    ///
    /// - count ~ Binomial(T, 0.5) — each of T cells has ~50% chance of
    ///   being non-empty (N values fill 2N cells).
    /// - indices: `count` unique values drawn uniformly from [0, real_n),
    ///   sorted ascending — matches the distribution of non-empty cell
    ///   values in a real segment (PRP makes them uniform in [0, N)).
    ///
    /// Returns raw bytes: `count × 4B u32 LE` (same format as
    /// `HarmonyRequest.request`).
    ///
    /// **No state mutation**: hints, DS', query count, and RNG-derived
    /// segment state are untouched.  (The RNG *is* advanced, which is fine.)
    pub fn build_synthetic_dummy(&mut self) -> Vec<u8> {
        let t = self.params.t;
        let n = self.real_n;

        // 1. Sample count ~ Binomial(T, 0.5): flip T coins.
        let mut count = 0u32;
        for _ in 0..t {
            if self.rng.next_u32() & 1 == 0 {
                count += 1;
            }
        }

        // 2. Sample `count` unique values from [0, real_n), sort.
        //    Rejection sampling — fast because count ≈ T/2 << N.
        let mut indices: Vec<u32> = Vec::with_capacity(count as usize);
        // Use a simple seen-set for dedup.  For T ≈ 1200 and N ≈ 750K
        // the collision probability per draw is < 0.2%, so few redraws.
        let mut seen = std::collections::HashSet::with_capacity(count as usize);
        while indices.len() < count as usize {
            let v = self.rng.next_u32() % n;
            if seen.insert(v) {
                indices.push(v);
            }
        }
        indices.sort_unstable();

        // 3. Encode as [u32 LE] bytes — same format as build_request().request.
        let mut bytes = Vec::with_capacity(indices.len() * 4);
        for &idx in &indices {
            bytes.extend_from_slice(&idx.to_le_bytes());
        }
        bytes
    }

    /// Process the Query Server's response and recover the target entry.
    ///
    /// Response contains `count` entries of w bytes each, in the same sorted
    /// order as the request indices.  The answer is H[s] ⊕ XOR(all entries).
    pub fn process_response(&mut self, response: &[u8]) -> Result<Vec<u8>, JsError> {
        let w = self.params.w;
        let count = self.last_position_map.len();
        let expected = count * w;
        if response.len() != expected {
            return Err(JsError::new(&format!(
                "expected {} bytes response ({} entries × {}B), got {}",
                expected, count, w, response.len()
            )));
        }

        let s = self.last_segment;
        let r = self.last_position;

        // Split response into individual entries (sorted order).
        let entries: Vec<&[u8]> = (0..count)
            .map(|i| &response[i * w..(i + 1) * w])
            .collect();

        // answer = H[s] ⊕ all entries  (dummy was never sent, so no skip needed)
        let mut answer = self.hints[s].clone();
        for entry in &entries {
            xor_into(&mut answer, entry);
        }

        self.relocate_and_update_hints(s, r, &entries, &answer)?;
        self.query_count += 1;
        Ok(answer)
    }

    /// Fast path: recover the answer via XOR only, deferring relocation.
    ///
    /// Call `finish_relocation()` before the next query on this group.
    pub fn process_response_xor_only(&mut self, response: &[u8]) -> Result<Vec<u8>, JsError> {
        let w = self.params.w;
        let count = self.last_position_map.len();
        let expected = count * w;
        if response.len() != expected {
            return Err(JsError::new(&format!(
                "expected {} bytes response ({} entries × {}B), got {}",
                expected, count, w, response.len()
            )));
        }

        // Split response into owned entries.
        let entries: Vec<Vec<u8>> = (0..count)
            .map(|i| response[i * w..(i + 1) * w].to_vec())
            .collect();

        // answer = H[s] ⊕ all entries
        let mut answer = self.hints[self.last_segment].clone();
        for entry in &entries {
            xor_into(&mut answer, entry);
        }

        // Stash for deferred relocation.
        self.deferred_entries = Some(entries);
        self.deferred_answer = Some(answer.clone());
        Ok(answer)
    }

    /// Complete the deferred relocation from a prior `process_response_xor_only` call.
    pub fn finish_relocation(&mut self) -> Result<(), JsError> {
        let entries = self.deferred_entries.take()
            .ok_or_else(|| JsError::new("finish_relocation called with no deferred state"))?;
        let answer = self.deferred_answer.take()
            .ok_or_else(|| JsError::new("finish_relocation: missing deferred answer"))?;

        let s = self.last_segment;
        let r = self.last_position;
        let entry_refs: Vec<&[u8]> = entries.iter().map(|e| e.as_slice()).collect();
        self.relocate_and_update_hints(s, r, &entry_refs, &answer)?;
        self.query_count += 1;
        Ok(())
    }

    // ─── Serialization ──────────────────────────────────────────────────

    /// Serialize this group's full mutable state to bytes.
    ///
    /// Format:
    /// ```text
    /// [4B padded_n][4B w][4B t][4B query_count][1B prp_backend][4B real_n]
    /// [4B num_relocated][num_relocated × 4B segments]
    /// [4B prp_cache_len][prp_cache bytes]
    /// [M × w bytes: hints]
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let m = self.params.m;
        let w = self.params.w;
        let num_relocated = self.relocated_segments.len();
        let cache_len = self.prp_cache.len();
        let hints_len = m * w;

        let total = 4 + 4 + 4 + 4 + 1 + 4 // header (added real_n)
            + 4 + num_relocated * 4     // relocated segments
            + 4 + cache_len             // PRP cache
            + hints_len;                // hints

        let mut buf = Vec::with_capacity(total);

        // Header: padded_n (used for PRP domain), w, t, query_count, backend, real_n.
        buf.extend_from_slice(&(self.params.n as u32).to_le_bytes()); // padded_n
        buf.extend_from_slice(&(self.params.w as u32).to_le_bytes());
        buf.extend_from_slice(&(self.params.t as u32).to_le_bytes());
        buf.extend_from_slice(&(self.query_count as u32).to_le_bytes());
        buf.push(self.prp_backend);
        buf.extend_from_slice(&self.real_n.to_le_bytes());

        // Relocated segments.
        buf.extend_from_slice(&(num_relocated as u32).to_le_bytes());
        for &seg in &self.relocated_segments {
            buf.extend_from_slice(&seg.to_le_bytes());
        }

        // PRP cache.
        buf.extend_from_slice(&(cache_len as u32).to_le_bytes());
        buf.extend_from_slice(&self.prp_cache);

        // Hints (flat).
        for hint in &self.hints {
            buf.extend_from_slice(hint);
        }

        buf
    }

    /// Restore a group from serialized bytes.
    ///
    /// Reconstructs the PRP from key + params (+ cache for FastPRP),
    /// creates a fresh DS', then replays all relocated segments to
    /// restore the exact same DS' state.
    pub fn deserialize(
        data: &[u8],
        prp_key: &[u8],
        group_id: u32,
    ) -> Result<HarmonyGroup, JsError> {
        if data.len() < 25 {
            return Err(JsError::new("serialized data too short"));
        }

        let mut pos = 0;

        // Parse header: padded_n, w, t, query_count, backend, real_n.
        let n = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()); pos += 4; // padded_n
        let w = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()); pos += 4;
        let t = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()); pos += 4;
        let query_count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize; pos += 4;
        let prp_backend = data[pos]; pos += 1;
        let real_n = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()); pos += 4;

        // Parse relocated segments.
        let num_relocated = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize; pos += 4;
        let mut relocated_segments = Vec::with_capacity(num_relocated);
        for _ in 0..num_relocated {
            let seg = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()); pos += 4;
            relocated_segments.push(seg);
        }

        // Parse PRP cache.
        let cache_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize; pos += 4;
        let prp_cache = data[pos..pos + cache_len].to_vec(); pos += cache_len;

        // Construct params and PRP.
        let n_usize = n as usize;
        let w_usize = w as usize;
        let t_usize = t as usize;

        let params = Params::new(n_usize, w_usize, t_usize)
            .map_err(|e| JsError::new(&format!("invalid params: {e:?}")))?;

        let key = derive_group_key(prp_key, group_id);
        let domain = 2 * n_usize;
        let prp = build_prp(prp_backend, &key, domain, n, &prp_cache);

        let mut ds = RelocationDS::new(n_usize, t_usize, prp)
            .map_err(|e| JsError::new(&format!("DS init failed: {e:?}")))?;

        // Replay relocated segments to restore DS' state.
        for &seg in &relocated_segments {
            ds.relocate_segment(seg as usize)
                .map_err(|e| JsError::new(&format!("replay relocate failed: {e:?}")))?;
        }

        // Parse hints.
        let m = params.m;
        let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w_usize]).collect();
        for i in 0..m {
            let start = pos + i * w_usize;
            let end = start + w_usize;
            if end > data.len() {
                return Err(JsError::new(&format!(
                    "truncated hints at segment {i}: need {end}, have {}", data.len()
                )));
            }
            hints[i].copy_from_slice(&data[start..end]);
        }

        let seed = make_rng_seed(&key, group_id, query_count as u32);

        // `key` and `group_id` are consumed by `make_rng_seed` above —
        // neither is retained on the struct. See the NOTE on
        // `HarmonyGroup` above for the rationale.
        let _ = key;
        let _ = group_id;

        Ok(HarmonyGroup {
            params,
            ds,
            hints,
            query_count,
            rng: ChaCha20Rng::from_seed(seed),
            prp_backend,
            prp_cache,
            real_n,
            relocated_segments,
            last_segment: 0,
            last_position: 0,
            last_query: 0,
            last_position_map: Vec::new(),
            deferred_entries: None,
            deferred_answer: None,
        })
    }

    // ─── Getters ────────────────────────────────────────────────────────

    pub fn queries_remaining(&self) -> u32 {
        (self.params.max_queries - self.query_count) as u32
    }
    pub fn queries_used(&self) -> u32 {
        self.query_count as u32
    }
    /// Padded N (PRP domain = 2*padded_n). Always >= real_n.
    pub fn n(&self) -> u32 {
        self.params.n as u32
    }
    /// Original (unpadded) N — the actual number of DB rows.
    pub fn real_n(&self) -> u32 {
        self.real_n
    }
    pub fn w(&self) -> u32 {
        self.params.w as u32
    }
    pub fn t(&self) -> u32 {
        self.params.t as u32
    }
    pub fn m(&self) -> u32 {
        self.params.m as u32
    }
    pub fn max_queries(&self) -> u32 {
        self.params.max_queries as u32
    }
    pub fn prp_backend(&self) -> u8 {
        self.prp_backend
    }
}

// ─── Private helpers ────────────────────────────────────────────────────────

impl HarmonyGroup {
    fn relocate_and_update_hints(
        &mut self,
        s: usize,
        r: usize,
        entries: &[&[u8]],
        answer: &[u8],
    ) -> Result<(), JsError> {
        let t = self.params.t;
        let n = self.params.n;
        let m = self.ds.relocated_segment_count();

        self.ds.relocate_segment(s)
            .map_err(|e| JsError::new(&format!("relocate failed: {e:?}")))?;

        // Track relocated segment for serialization.
        self.relocated_segments.push(s as u32);

        // Build position → entry index mapping from the sorted response.
        let mut pos_to_entry: Vec<Option<usize>> = vec![None; t];
        for (entry_idx, &pos) in self.last_position_map.iter().enumerate() {
            pos_to_entry[pos] = Some(entry_idx);
        }

        for i in 0..t {
            let empty_value = n + m * t + i;
            let dest_cell = self.ds.locate_extended(empty_value)
                .map_err(|e| JsError::new(&format!("locate_extended failed: {e:?}")))?;
            let d_i = dest_cell / t;
            if i == r {
                // Position r held the query target — use the recovered answer.
                xor_into(&mut self.hints[d_i], answer);
            } else if let Some(entry_idx) = pos_to_entry[i] {
                // Non-empty position — use the corresponding server entry.
                xor_into(&mut self.hints[d_i], entries[entry_idx]);
            }
            // Empty positions contribute zeros — XOR with zero is a no-op.
        }
        Ok(())
    }

}

/// XOR src into dst in place.
fn xor_into(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

// ─── Utility exports ────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn compute_balanced_t(n: u32) -> u32 {
    find_best_t(n)
}

#[wasm_bindgen]
pub fn verify_protocol(n: u32, w: u32) -> bool {
    verify_protocol_impl(n, w, PRP_HOANG)
}

/// Internal: run protocol test with simulated server, optionally with serialize round-trip.
pub fn verify_protocol_impl(n: u32, w: u32, backend: u8) -> bool {
    let real_n = n as usize;
    let w_usize = w as usize;
    let t_val = find_best_t(n);
    let (padded_n, t_val) = pad_n_for_t(n, t_val);
    let padded_n_usize = padded_n as usize;
    let t = t_val as usize;

    // DB has real_n entries; indices in [real_n, padded_n) return zeros.
    let db: Vec<Vec<u8>> = (0..real_n)
        .map(|i| {
            let mut entry = vec![0u8; w_usize];
            let bytes = (i as u64).to_le_bytes();
            entry[..bytes.len().min(w_usize)].copy_from_slice(&bytes[..bytes.len().min(w_usize)]);
            entry
        })
        .collect();

    let key = [0x42u8; 16];
    let group_id: u32 = 0;
    let derived_key = derive_group_key(&key, group_id);
    let domain = 2 * padded_n_usize;

    // Server-side: compute hints using padded_n.
    let prp_server = build_prp(backend, &derived_key, domain, padded_n, &[]);
    let params = match Params::new(padded_n_usize, w_usize, t) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let ds_server = match RelocationDS::new(padded_n_usize, t, prp_server) {
        Ok(ds) => ds,
        Err(_) => return false,
    };

    let m = params.m;
    let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w_usize]).collect();
    // Hint for real rows: XOR DB entry. Virtual rows (>= real_n): zero, no XOR needed.
    for k in 0..padded_n_usize {
        let cell = match ds_server.locate(k) {
            Ok(c) => c,
            Err(_) => return false,
        };
        if k < real_n {
            xor_into(&mut hints[cell / t], &db[k]);
        }
        // k >= real_n: entry is zero, XOR with zero is no-op.
    }

    // Client creates group with real_n — padding happens internally.
    let mut group = match HarmonyGroup::new_with_backend(n, w, t_val, &key, group_id, backend) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let flat_hints: Vec<u8> = hints.iter().flat_map(|h| h.iter().copied()).collect();
    if group.load_hints(&flat_hints).is_err() { return false; }

    // Simulate server: sorted non-empty indices → individual entries.
    let simulate = |req: &HarmonyRequest, db: &[Vec<u8>], real_n: usize, w: usize, _t: usize| -> Vec<u8> {
        let count = req.request_bytes.len() / 4;
        let mut response = Vec::with_capacity(count * w);
        for j in 0..count {
            let off = j * 4;
            let idx = u32::from_le_bytes(req.request_bytes[off..off + 4].try_into().unwrap());
            if idx as usize >= real_n {
                response.extend(std::iter::repeat(0u8).take(w));
            } else {
                response.extend_from_slice(&db[idx as usize]);
            }
        }
        response
    };

    let max_q = params.max_queries;
    let queries_phase1: Vec<usize> = vec![0, real_n / 2];
    let queries_phase2: Vec<usize> = vec![1, real_n - 1];

    for (i, &q) in queries_phase1.iter().enumerate() {
        if i >= max_q { break; }
        let req = match group.build_request(q as u32) { Ok(r) => r, Err(_) => return false };
        let resp = simulate(&req, &db, real_n, w_usize, t);
        let result = match group.process_response(&resp) { Ok(r) => r, Err(_) => return false };
        if result != db[q] { return false; }
    }

    // Serialize and deserialize.
    let serialized = group.serialize();
    let mut group = match HarmonyGroup::deserialize(&serialized, &key, group_id) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Verify state survived.
    if group.queries_used() != queries_phase1.len() as u32 { return false; }

    for (i, &q) in queries_phase2.iter().enumerate() {
        if queries_phase1.len() + i >= max_q { break; }
        let req = match group.build_request(q as u32) { Ok(r) => r, Err(_) => return false };
        let resp = simulate(&req, &db, real_n, w_usize, t);
        let result = match group.process_response(&resp) { Ok(r) => r, Err(_) => return false };
        if result != db[q] { return false; }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_best_t_and_pad() {
        let t = find_best_t(64);
        // T is approximately sqrt(128) ≈ 11
        assert!(t >= 8 && t <= 16, "T={t} not in expected range");

        // After padding, 2*padded_n must be divisible by T.
        let (padded_n, t2) = pad_n_for_t(64, t);
        assert_eq!(t2, t);
        assert!((2 * padded_n as u64) % t as u64 == 0,
            "2*padded_n={} not divisible by T={}", 2 * padded_n, t);
        assert!(padded_n >= 64, "padded_n={} < original n=64", padded_n);

        // Test with a non-power-of-2 (realistic case).
        let t_chunk = find_best_t(1596681);
        let (padded, _) = pad_n_for_t(1596681, t_chunk);
        assert!((2 * padded as u64) % t_chunk as u64 == 0);
        assert!(padded >= 1596681);
        // T should be near sqrt(2*1596681) ≈ 1787
        assert!(t_chunk >= 1700 && t_chunk <= 1900, "T_chunk={t_chunk}");
    }

    #[test]
    fn test_derive_group_key() {
        let key = [0xAA; 16];
        let k0 = derive_group_key(&key, 0);
        let k1 = derive_group_key(&key, 1);
        assert_ne!(k0, k1);
        assert_eq!(k0, key);
    }

    #[test]
    fn test_verify_protocol_small() {
        assert!(verify_protocol(64, 32));
    }

    #[test]
    fn test_verify_protocol_medium() {
        assert!(verify_protocol(256, 42));
    }

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        // This test is embedded in verify_protocol_impl:
        // queries → serialize → deserialize → more queries → verify all correct.
        assert!(verify_protocol_impl(256, 42, PRP_HOANG));
    }

    #[test]
    fn test_group_lifecycle() {
        let n = 64u32;
        let w = 32u32;
        let key = [0x42u8; 16];
        let group_id = 5u32;

        let mut group = HarmonyGroup::new(n, w, 0, &key, group_id).unwrap();
        assert_eq!(group.real_n(), n);
        assert!(group.n() >= n); // padded_n >= n
        assert_eq!(group.w(), w);
        assert!(group.queries_remaining() > 0);

        let m = group.m() as usize;
        let hints = vec![0u8; m * w as usize];
        group.load_hints(&hints).unwrap();

        let req = group.build_request(0).unwrap();
        assert_eq!(req.request_bytes.len(), group.t() as usize * 4);
    }

    #[test]
    fn test_serialize_empty_group() {
        let key = [0x42u8; 16];
        let mut group = HarmonyGroup::new(64, 32, 0, &key, 0).unwrap();
        let m = group.m() as usize;
        group.load_hints(&vec![0u8; m * 32]).unwrap();

        let data = group.serialize();
        let restored = HarmonyGroup::deserialize(&data, &key, 0).unwrap();
        assert_eq!(restored.real_n(), 64);
        assert!(restored.n() >= 64); // padded
        assert_eq!(restored.w(), 32);
        assert_eq!(restored.queries_used(), 0);
        assert_eq!(restored.queries_remaining(), group.queries_remaining());
    }
}
