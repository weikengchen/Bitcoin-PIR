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

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub mod state;

// ─── PRP backend constants ──────────────────────────────────────────────────

pub const PRP_HMR12: u8 = 0;
pub const PRP_FASTPRP: u8 = 1;
// PRP_ALF (= 2) was removed 2026-05-12: ALF panicked on domain<65536
// (sibling Merkle tables hit this), causing pir-vpsbg crash loops.
// The constant is intentionally NOT defined here so any caller still
// using it gets a compile error.

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
        PRP_HMR12 => {
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
        _ => {
            // Fallback to HMR12 for unknown backends (including the
            // removed PRP_ALF=2; old clients hit this branch silently).
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

// ─── In-flight state for pipelined pair queries ─────────────────────────────

/// Per-call state bridging [`HarmonyGroup::build_request_pair`] and
/// [`HarmonyGroup::process_response_pair`].
///
/// Mirrors the upstream `harmonypir::PendingPair` pattern (in
/// `harmonypir/src/protocol.rs`) but adapted to the wrapper's
/// privacy-padded wire format. Holds the segment / position metadata
/// for both queries plus the cached destination segments for q_1's
/// relocation (already applied to DS' by `build_request_pair`).
///
/// **State invariant**: while a `PendingPair` is outstanding, the
/// client's DS' has been advanced past q_1's relocation, but the
/// hint parities have NOT been updated. Calling another mutating
/// method on the same group before `process_response_pair` would
/// corrupt state. All mutating methods on `HarmonyGroup`
/// (`build_request`, `build_request_pair`, `build_dummy_request`,
/// `process_response`, `process_response_xor_only`,
/// `finish_relocation`, `load_hints`) check this and return an
/// error if called while a pair is in flight.
struct PendingPair {
    s_1: usize,
    r_1: usize,
    /// `position_map_1[k]` = original segment position (in `[0, T)`)
    /// of the k-th REAL entry of q_1's response, in sorted-merged
    /// order. Same shape as `last_position_map`.
    position_map_1: Vec<usize>,
    /// `is_dummy_1[k]` = true iff slot k of q_1's response is a
    /// padding dummy (XOR-cancelled out of A_1). Same shape as
    /// `last_is_dummy`.
    is_dummy_1: Vec<bool>,
    /// `d_1[i]` = segment containing the destination cell of q_1's
    /// i-th per-cell relocation, computed POST-`relocate_segment(s_1)`
    /// inside `build_request_pair` (same construction as
    /// `relocate_and_update_hints`). Length T.
    d_1: Vec<usize>,
    s_2: usize,
    r_2: usize,
    position_map_2: Vec<usize>,
    is_dummy_2: Vec<bool>,
}

/// Output of the private `build_request_inner` helper.
///
/// Carries all per-call state (segment / position / sorted position
/// map / dummy flags) that the caller must stash somewhere (either
/// the persistent `last_*` fields for single-query, or a
/// [`PendingPair`] for pair-pipelined). Keeps the privacy-padding
/// logic in one place — `build_request` and `build_request_pair`
/// both consume this output.
struct BuildRequestOutput {
    request_bytes: Vec<u8>,
    s: usize,
    r: usize,
    q: usize,
    position_map: Vec<usize>,
    is_dummy: Vec<bool>,
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

/// Pair of [`HarmonyRequest`]s produced by
/// [`HarmonyGroup::build_request_pair`].
///
/// wasm-bindgen doesn't accept tuple returns; this struct is the
/// transport. Use the `request_1` / `request_2` getters from JS or
/// destructure on the Rust side via `pair.into_parts()`.
#[wasm_bindgen]
pub struct HarmonyRequestPair {
    request_1: HarmonyRequest,
    request_2: HarmonyRequest,
}

#[wasm_bindgen]
impl HarmonyRequestPair {
    #[wasm_bindgen(getter)]
    pub fn request_1(&self) -> HarmonyRequest {
        HarmonyRequest {
            request_bytes: self.request_1.request_bytes.clone(),
            segment: self.request_1.segment,
            position: self.request_1.position,
            query_index: self.request_1.query_index,
        }
    }
    #[wasm_bindgen(getter)]
    pub fn request_2(&self) -> HarmonyRequest {
        HarmonyRequest {
            request_bytes: self.request_2.request_bytes.clone(),
            segment: self.request_2.segment,
            position: self.request_2.position,
            query_index: self.request_2.query_index,
        }
    }
}

impl HarmonyRequestPair {
    /// Native-only: destructure into the two [`HarmonyRequest`]s. Used
    /// by tests and by Rust-side callers that don't go through the JS
    /// boundary.
    pub fn into_parts(self) -> (HarmonyRequest, HarmonyRequest) {
        (self.request_1, self.request_2)
    }
}

/// Pair of recovered DB rows produced by
/// [`HarmonyGroup::process_response_pair`].
///
/// wasm-bindgen doesn't accept tuple returns; this struct is the
/// transport. Use the `answer_1` / `answer_2` getters from JS, or
/// `into_parts()` on the Rust side.
#[wasm_bindgen]
pub struct HarmonyAnswerPair {
    answer_1: Vec<u8>,
    answer_2: Vec<u8>,
}

#[wasm_bindgen]
impl HarmonyAnswerPair {
    #[wasm_bindgen(getter)]
    pub fn answer_1(&self) -> Vec<u8> {
        self.answer_1.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn answer_2(&self) -> Vec<u8> {
        self.answer_2.clone()
    }
}

impl HarmonyAnswerPair {
    /// Native-only: destructure into the two answer byte vectors.
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.answer_1, self.answer_2)
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
    /// PRP backend identifier (0=HMR12, 1=FastPRP).
    prp_backend: u8,
    /// Cached PRP data (for FastPRP). Empty for HMR12.
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
    /// One entry per REAL (non-dummy) slot in the last sorted request,
    /// in the same sorted-merged order. Each entry is that real value's
    /// original position-in-segment (0..T, excluding `r`).  Used by
    /// process_response() to reconstruct per-position entries for
    /// relocation.  Length = number of real non-empty segment cells at
    /// the time of the last `build_request` call (may be less than T-1
    /// when some cells were empty and padded with dummies).
    last_position_map: Vec<usize>,
    /// Per-sorted-slot dummy flag for the last `build_request` call.
    /// `last_is_dummy[i] = true` means slot `i` of the sorted request is
    /// a padding index (draw from `[0, real_n) \ real`) that must be
    /// XOR-cancelled out of the server's response before returning the
    /// recovered row.  Length = `params.t - 1` after every call.
    ///
    /// Round-local scratch — never serialized.  See
    /// `PLAN_HARMONY_COUNT_LEAK_FIX.md` for the privacy rationale.
    last_is_dummy: Vec<bool>,
    /// Stashed state for deferred relocation (set by process_response_xor_only).
    deferred_entries: Option<Vec<Vec<u8>>>,
    deferred_answer: Option<Vec<u8>>,
    /// In-flight state for pipelined pair queries (set by
    /// `build_request_pair`, cleared by `process_response_pair`).
    /// While `Some(_)`, all mutating methods reject calls — see the
    /// in-flight invariant on [`PendingPair`].
    ///
    /// Round-local scratch — never serialized.
    pending_pair: Option<PendingPair>,
}

#[wasm_bindgen]
impl HarmonyGroup {
    /// Create a new HarmonyGroup with HMR12 PRP (default).
    #[wasm_bindgen(constructor)]
    pub fn new(n: u32, w: u32, t: u32, prp_key: &[u8], group_id: u32) -> Result<HarmonyGroup, JsError> {
        Self::new_with_backend(n, w, t, prp_key, group_id, PRP_HMR12)
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
            last_is_dummy: Vec::new(),
            deferred_entries: None,
            deferred_answer: None,
            pending_pair: None,
        })
    }

    /// Load pre-computed hint parities (M × w bytes, flat).
    pub fn load_hints(&mut self, hints_data: &[u8]) -> Result<(), JsError> {
        self.check_pair_not_in_flight("load_hints")?;
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
    /// Emits exactly `T - 1` sorted distinct u32 indices drawn from
    /// `[0, real_n)`.  Real non-empty segment cells contribute their
    /// actual DB index; empty slots are padded with fresh random
    /// indices (distinct from each other and from the real indices).
    /// The dummy indices are tracked in `last_is_dummy` so that
    /// `process_response` can XOR-cancel their server responses out
    /// of the recovered row.
    ///
    /// Fixed-count invariant: every call emits `(T - 1) * 4` bytes,
    /// regardless of segment state, query count, or round.  See
    /// `PLAN_HARMONY_COUNT_LEAK_FIX.md` and the "HarmonyPIR Per-Group
    /// Request-Count Symmetry" section of `CLAUDE.md` — do NOT change
    /// this to a variable count.
    pub fn build_request(&mut self, q: u32) -> Result<HarmonyRequest, JsError> {
        self.check_pair_not_in_flight("build_request")?;
        let out = self.build_request_inner(q)?;
        // Stash per-call state into the persistent single-query slots.
        // `process_response` / `process_response_xor_only` will read it.
        self.last_segment = out.s;
        self.last_position = out.r;
        self.last_query = out.q;
        self.last_position_map = out.position_map;
        self.last_is_dummy = out.is_dummy;
        Ok(HarmonyRequest {
            request_bytes: out.request_bytes,
            segment: out.s as u32,
            position: out.r as u32,
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
        // The inner build_request would catch this transitively, but
        // checking explicitly gives a better error message and a
        // guarantee independent of the inner refactor.
        self.check_pair_not_in_flight("build_dummy_request")?;
        let q = self.rng.next_u32() % self.real_n as u32;

        // Save state that build_request will overwrite.
        let saved_segment = self.last_segment;
        let saved_position = self.last_position;
        let saved_query = self.last_query;
        let saved_map = std::mem::take(&mut self.last_position_map);
        let saved_is_dummy = std::mem::take(&mut self.last_is_dummy);

        let result = self.build_request(q);

        // Restore — the dummy never happened as far as client state is concerned.
        self.last_segment = saved_segment;
        self.last_position = saved_position;
        self.last_query = saved_query;
        self.last_position_map = saved_map;
        self.last_is_dummy = saved_is_dummy;

        result
    }

    /// Build a **synthetic** dummy request that is byte-for-byte
    /// indistinguishable on the wire from a real `build_request`.
    ///
    /// Emits exactly `T - 1` sorted distinct u32 indices drawn
    /// uniformly at random from `[0, real_n)` — the same fixed count
    /// that `build_request` produces after padding.  Because the
    /// count is deterministic, the server cannot tell synthetic
    /// dummies apart from real queries, nor can it tell real queries
    /// with many empty segment cells apart from real queries with
    /// few.  See `PLAN_HARMONY_COUNT_LEAK_FIX.md`.
    ///
    /// Returns raw bytes: `(T - 1) × 4B u32 LE` (same format as
    /// `HarmonyRequest.request`).
    ///
    /// **No state mutation**: hints, DS', query count, and
    /// RNG-derived segment state are untouched.  (The RNG *is*
    /// advanced, which is fine.)
    pub fn build_synthetic_dummy(&mut self) -> Vec<u8> {
        let t = self.params.t;
        // Match the domain used by build_request: dummies must come from
        // [0, padded_n), not [0, real_n), because real segment values
        // can include virtual row indices in [real_n, padded_n) and any
        // restriction would be a wire-visible distinguisher.
        let domain = self.params.n as u32;
        if t < 2 || domain == 0 {
            return Vec::new();
        }
        let target = t - 1;

        // Sample `target` unique values from [0, padded_n), sort.
        // Rejection sampling terminates quickly because target << domain
        // for all realistic Params (target ≈ sqrt(2n)).
        let mut indices: Vec<u32> = Vec::with_capacity(target);
        let mut seen = std::collections::HashSet::with_capacity(target);
        while indices.len() < target {
            let v = self.rng.next_u32() % domain;
            if seen.insert(v) {
                indices.push(v);
            }
        }
        indices.sort_unstable();

        let mut bytes = Vec::with_capacity(target * 4);
        for &idx in &indices {
            bytes.extend_from_slice(&idx.to_le_bytes());
        }
        bytes
    }

    /// Process the Query Server's response and recover the target entry.
    ///
    /// Response contains exactly `T - 1` entries of w bytes each, in
    /// the same sorted order as the padded request indices.  Dummy
    /// slots (tracked in `last_is_dummy`) are XOR-cancelled out of
    /// the final answer so only real segment entries contribute:
    /// `answer = H[s] ⊕ XOR(entries[i] for i where !last_is_dummy[i])`.
    pub fn process_response(&mut self, response: &[u8]) -> Result<Vec<u8>, JsError> {
        self.check_pair_not_in_flight("process_response")?;
        let w = self.params.w;
        let target = self.last_is_dummy.len();
        let expected = target * w;
        if response.len() != expected {
            return Err(JsError::new(&format!(
                "expected {} bytes response ({} entries × {}B), got {}",
                expected, target, w, response.len()
            )));
        }

        let s = self.last_segment;
        let r = self.last_position;

        // Split response into individual entries (sorted order).
        let entries: Vec<&[u8]> = (0..target)
            .map(|i| &response[i * w..(i + 1) * w])
            .collect();

        // answer = H[s] ⊕ XOR(real entries only).
        // Dummy entries are XOR-cancelled by skipping them here.
        let mut answer = self.hints[s].clone();
        for (i, entry) in entries.iter().enumerate() {
            if !self.last_is_dummy[i] {
                xor_into(&mut answer, entry);
            }
        }

        // Collect real entries in sorted-merged order for relocation.
        // `last_position_map[k]` gives the segment position of the k-th
        // real entry — which matches the order we iterate here.
        let real_entries: Vec<&[u8]> = entries.iter().enumerate()
            .filter_map(|(i, e)| if !self.last_is_dummy[i] { Some(*e) } else { None })
            .collect();
        debug_assert_eq!(real_entries.len(), self.last_position_map.len());

        self.relocate_and_update_hints(s, r, &real_entries, &answer)?;
        self.query_count += 1;
        Ok(answer)
    }

    /// Build BOTH server requests for a pipelined pair query.
    ///
    /// This is the wrapper-side mirror of upstream
    /// `harmonypir::Client::build_pair_requests` (see
    /// `bitcoin-pir/harmonypir/src/protocol.rs`), adapted to the
    /// privacy-padded wire format. It constructs requests for both
    /// `q_1` and `q_2` and advances DS' past q_1's relocation, but
    /// does NOT touch the hint parities. The caller then sends both
    /// requests over the network (in parallel, ideally) and feeds
    /// both responses to [`Self::process_response_pair`].
    ///
    /// # Output
    ///
    /// Two [`HarmonyRequest`]s, each independently emitting exactly
    /// `(T - 1) * 4` bytes (the per-group request-count symmetry
    /// invariant — see `PLAN_HARMONY_COUNT_LEAK_FIX.md`). The
    /// in-flight state is stashed on the group as
    /// `Option<PendingPair>` and consumed by
    /// `process_response_pair`.
    ///
    /// # In-flight invariant
    ///
    /// Between this call and `process_response_pair`, the group is
    /// in an in-flight state — DS' is one segment ahead of H. All
    /// other mutating methods (`build_request`, `build_dummy_request`,
    /// `process_response`, `process_response_xor_only`,
    /// `finish_relocation`, `load_hints`, and a second
    /// `build_request_pair`) reject calls with an error until
    /// `process_response_pair` returns. `build_synthetic_dummy` is
    /// safe to call (it only advances the RNG).
    ///
    /// # Equivalence
    ///
    /// `build_request_pair(q_1, q_2)` followed by
    /// `process_response_pair(...)` produces the same final group
    /// state and the same answers as two sequential
    /// `build_request(q_1) + process_response(...)` then
    /// `build_request(q_2) + process_response(...)` calls with the
    /// same RNG seed (see `test_split_pair_api_*` and
    /// `test_query_pair_equiv_sequential_*` below). Mirrors the
    /// upstream eight-step soundness argument; the only differences
    /// are wire format (sorted padded indices) and the answer
    /// formula (XOR of REAL entries, dummies cancelled by
    /// exclusion).
    pub fn build_request_pair(
        &mut self,
        q_1: u32,
        q_2: u32,
    ) -> Result<HarmonyRequestPair, JsError> {
        self.check_pair_not_in_flight("build_request_pair")?;
        // Reserve budget for both queries up front — matches upstream
        // `build_pair_requests` semantics.
        if self.query_count + 2 > self.params.max_queries {
            return Err(JsError::new(
                "not enough query budget remaining for a pair (need 2)",
            ));
        }

        // ── Step 1: Build req_1 from current DS' ──
        let out_1 = self.build_request_inner(q_1)?;

        // ── Step 2: RelocateSegment(s_1); cache q_1's destination segments ──
        // m_1 captured BEFORE relocate_segment; locate_extended uses the
        // POST-relocation DS' state. Same construction as
        // `relocate_and_update_hints` so single-query and pair paths agree
        // bit-for-bit on what the destination segments are.
        let t = self.params.t;
        let n = self.params.n;
        let m_1 = self.ds.relocated_segment_count();
        self.ds
            .relocate_segment(out_1.s)
            .map_err(|e| JsError::new(&format!("relocate s_1 failed: {e:?}")))?;
        self.relocated_segments.push(out_1.s as u32);

        let mut d_1 = vec![0usize; t];
        for i in 0..t {
            let empty_value = n + m_1 * t + i;
            let dest_cell = self
                .ds
                .locate_extended(empty_value)
                .map_err(|e| JsError::new(&format!("locate_extended (q_1) failed: {e:?}")))?;
            d_1[i] = dest_cell / t;
        }

        // ── Step 3: Build req_2 from updated DS' ──
        // ds.locate(q_2) chain-walks through the relocation we just
        // applied, so q_2 lands at its post-relocation cell — same as
        // sequential mode would see between query 1 and query 2.
        let out_2 = self.build_request_inner(q_2)?;

        // Stash all per-call state for the finish half. last_* fields
        // are intentionally untouched — the pair path runs through
        // `pending_pair` exclusively to keep the two state machines
        // separate.
        self.pending_pair = Some(PendingPair {
            s_1: out_1.s,
            r_1: out_1.r,
            position_map_1: out_1.position_map,
            is_dummy_1: out_1.is_dummy,
            d_1,
            s_2: out_2.s,
            r_2: out_2.r,
            position_map_2: out_2.position_map,
            is_dummy_2: out_2.is_dummy,
        });

        Ok(HarmonyRequestPair {
            request_1: HarmonyRequest {
                request_bytes: out_1.request_bytes,
                segment: out_1.s as u32,
                position: out_1.r as u32,
                query_index: q_1,
            },
            request_2: HarmonyRequest {
                request_bytes: out_2.request_bytes,
                segment: out_2.s as u32,
                position: out_2.r as u32,
                query_index: q_2,
            },
        })
    }

    /// Finish a pipelined pair query: compute both answers and complete
    /// state updates.
    ///
    /// Consumes the in-flight `PendingPair` produced by
    /// `build_request_pair` along with the two server responses. Each
    /// response must be exactly `(T - 1) * w` bytes, matching the
    /// sorted-padded request length.
    ///
    /// On success, `H` and DS' are advanced as if two sequential
    /// `process_response` calls had completed (`query_count += 2`,
    /// `relocated_segments` extended with `[s_1, s_2]`).
    ///
    /// On a wrong-length response error, the in-flight state is
    /// already taken — the group is no longer pair-in-flight, but
    /// q_1's relocation has been committed to DS' (matching upstream
    /// `finish_pair` failure semantics: errored pair leaves the
    /// client in a degraded but recoverable state).
    pub fn process_response_pair(
        &mut self,
        response_1: &[u8],
        response_2: &[u8],
    ) -> Result<HarmonyAnswerPair, JsError> {
        let pending = self.pending_pair.take().ok_or_else(|| {
            JsError::new("process_response_pair called with no pending pair in flight")
        })?;

        let w = self.params.w;
        let t = self.params.t;
        let n = self.params.n;
        let target_1 = pending.is_dummy_1.len();
        let target_2 = pending.is_dummy_2.len();
        let expected_1 = target_1 * w;
        let expected_2 = target_2 * w;

        if response_1.len() != expected_1 {
            return Err(JsError::new(&format!(
                "expected {} bytes for response_1 ({} entries × {}B), got {}",
                expected_1,
                target_1,
                w,
                response_1.len()
            )));
        }
        if response_2.len() != expected_2 {
            return Err(JsError::new(&format!(
                "expected {} bytes for response_2 ({} entries × {}B), got {}",
                expected_2,
                target_2,
                w,
                response_2.len()
            )));
        }

        // ── Step 5: A_1 = H[s_1] ⊕ XOR(real entries from response_1) ──
        let entries_1: Vec<&[u8]> = (0..target_1)
            .map(|i| &response_1[i * w..(i + 1) * w])
            .collect();
        let mut answer_1 = self.hints[pending.s_1].clone();
        for (i, entry) in entries_1.iter().enumerate() {
            if !pending.is_dummy_1[i] {
                xor_into(&mut answer_1, entry);
            }
        }

        // Real entries in sorted-merged order, for q_1's hint update.
        let real_entries_1: Vec<&[u8]> = entries_1
            .iter()
            .enumerate()
            .filter_map(|(i, e)| if !pending.is_dummy_1[i] { Some(*e) } else { None })
            .collect();
        debug_assert_eq!(real_entries_1.len(), pending.position_map_1.len());

        // ── Step 6: Part B for q_1 — H ⊕= R_1 (real positions), A_1 (position r_1) ──
        // Uses cached d_1 (computed in build_request_pair after RelocateSegment(s_1)).
        let mut pos_to_entry_1: Vec<Option<usize>> = vec![None; t];
        for (entry_idx, &pos) in pending.position_map_1.iter().enumerate() {
            pos_to_entry_1[pos] = Some(entry_idx);
        }
        for i in 0..t {
            let d_i = pending.d_1[i];
            if i == pending.r_1 {
                xor_into(&mut self.hints[d_i], &answer_1);
            } else if let Some(entry_idx) = pos_to_entry_1[i] {
                xor_into(&mut self.hints[d_i], real_entries_1[entry_idx]);
            }
            // Empty positions contribute zeros — no XOR needed.
        }

        // ── Step 7: A_2 (uses POST-step-6 H[s_2] — q_1's update may have written it) ──
        let entries_2: Vec<&[u8]> = (0..target_2)
            .map(|i| &response_2[i * w..(i + 1) * w])
            .collect();
        let mut answer_2 = self.hints[pending.s_2].clone();
        for (i, entry) in entries_2.iter().enumerate() {
            if !pending.is_dummy_2[i] {
                xor_into(&mut answer_2, entry);
            }
        }

        let real_entries_2: Vec<&[u8]> = entries_2
            .iter()
            .enumerate()
            .filter_map(|(i, e)| if !pending.is_dummy_2[i] { Some(*e) } else { None })
            .collect();
        debug_assert_eq!(real_entries_2.len(), pending.position_map_2.len());

        // ── Step 8: RelocateSegment(s_2) + Part B for q_2 ──
        // d_2 is computed here (not cached in build_request_pair) — q_2's
        // relocation happens after both answers are computed, mirroring
        // upstream finish_pair.
        let m_2 = self.ds.relocated_segment_count();
        self.ds
            .relocate_segment(pending.s_2)
            .map_err(|e| JsError::new(&format!("relocate s_2 failed: {e:?}")))?;
        self.relocated_segments.push(pending.s_2 as u32);

        let mut pos_to_entry_2: Vec<Option<usize>> = vec![None; t];
        for (entry_idx, &pos) in pending.position_map_2.iter().enumerate() {
            pos_to_entry_2[pos] = Some(entry_idx);
        }
        for i in 0..t {
            let empty_value = n + m_2 * t + i;
            let dest_cell = self
                .ds
                .locate_extended(empty_value)
                .map_err(|e| JsError::new(&format!("locate_extended (q_2) failed: {e:?}")))?;
            let d_i = dest_cell / t;
            if i == pending.r_2 {
                xor_into(&mut self.hints[d_i], &answer_2);
            } else if let Some(entry_idx) = pos_to_entry_2[i] {
                xor_into(&mut self.hints[d_i], real_entries_2[entry_idx]);
            }
        }

        self.query_count += 2;
        Ok(HarmonyAnswerPair { answer_1, answer_2 })
    }

    /// Fast path: recover the answer via XOR only, deferring relocation.
    ///
    /// Call `finish_relocation()` before the next query on this group.
    pub fn process_response_xor_only(&mut self, response: &[u8]) -> Result<Vec<u8>, JsError> {
        self.check_pair_not_in_flight("process_response_xor_only")?;
        let w = self.params.w;
        let target = self.last_is_dummy.len();
        let expected = target * w;
        if response.len() != expected {
            return Err(JsError::new(&format!(
                "expected {} bytes response ({} entries × {}B), got {}",
                expected, target, w, response.len()
            )));
        }

        // Retain only REAL entries — dummies are XOR-cancelled by not
        // being included at all. `deferred_entries` thus matches
        // `last_position_map` in length + order, exactly what
        // `finish_relocation` / `relocate_and_update_hints` expects.
        let mut real_entries: Vec<Vec<u8>> = Vec::with_capacity(self.last_position_map.len());
        let mut answer = self.hints[self.last_segment].clone();
        for i in 0..target {
            let slot = &response[i * w..(i + 1) * w];
            if !self.last_is_dummy[i] {
                xor_into(&mut answer, slot);
                real_entries.push(slot.to_vec());
            }
        }
        debug_assert_eq!(real_entries.len(), self.last_position_map.len());

        // Stash for deferred relocation.
        self.deferred_entries = Some(real_entries);
        self.deferred_answer = Some(answer.clone());
        Ok(answer)
    }

    /// Complete the deferred relocation from a prior `process_response_xor_only` call.
    pub fn finish_relocation(&mut self) -> Result<(), JsError> {
        self.check_pair_not_in_flight("finish_relocation")?;
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
    ///
    /// **Pre-condition:** no pipelined pair query is in flight. Calling
    /// `serialize()` while `pending_pair.is_some()` would persist a
    /// state where DS' is one segment ahead of H — `deserialize` cannot
    /// recover that intermediate state because the pending pair's
    /// pre-update H[s_2] and the cached d_1 are round-local scratch.
    /// Callers must complete (or abandon and reconstruct) the pair
    /// first. Asserted in debug builds; in release builds the contract
    /// is documented but not enforced (the resulting bytes are
    /// well-formed but reflect a corrupted state).
    pub fn serialize(&self) -> Vec<u8> {
        debug_assert!(
            self.pending_pair.is_none(),
            "serialize() called while a pipelined pair is in flight; \
             call process_response_pair first"
        );
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
            last_is_dummy: Vec::new(),
            deferred_entries: None,
            deferred_answer: None,
            pending_pair: None,
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
    /// Reject a mutating call if a pair query is in flight.
    ///
    /// See [`PendingPair`] for the in-flight invariant. The check is
    /// a logical contract — the borrow checker won't catch you, this
    /// will.
    fn check_pair_not_in_flight(&self, method: &str) -> Result<(), JsError> {
        if self.pending_pair.is_some() {
            return Err(JsError::new(&format!(
                "{method} called while a pipelined pair query is in flight; \
                 call process_response_pair first to complete the pair"
            )));
        }
        Ok(())
    }

    /// Core privacy-padded request builder.
    ///
    /// Returns the per-call state in [`BuildRequestOutput`]; the
    /// caller decides where to stash it (the persistent `last_*`
    /// fields for single-query, or a [`PendingPair`] for the
    /// pipelined pair). Keeps the privacy-padding logic in one
    /// place so `build_request` and `build_request_pair` cannot
    /// drift apart.
    ///
    /// Mutates `self.rng` (advances by however many random
    /// candidates were drawn for dummy padding) and reads `self.ds`
    /// + `self.params`. Does NOT touch hints, query_count,
    /// relocated_segments, or any of the `last_*` / `pending_pair`
    /// fields.
    fn build_request_inner(&mut self, q: u32) -> Result<BuildRequestOutput, JsError> {
        let q_usize = q as usize;
        if q_usize >= self.params.n {
            return Err(JsError::new(&format!("query index {q} >= N={}", self.params.n)));
        }
        if self.query_count >= self.params.max_queries {
            return Err(JsError::new("no more queries available; rehint needed"));
        }

        let t = self.params.t;
        if t < 2 {
            return Err(JsError::new(&format!("t={t} must be >= 2 for padded request")));
        }
        let target = t - 1;
        // Dummies are drawn from the same [0, padded_n) domain that
        // real non-empty segment values can take — virtual rows in
        // [real_n, padded_n) are valid PRP outputs too, so restricting
        // dummies to [0, real_n) would leak padded_n - real_n virtual
        // values on the wire.
        let domain = self.params.n as u32;
        if (target as u64) > (domain as u64) {
            return Err(JsError::new(&format!(
                "T-1={} exceeds padded_n={}, cannot pad to fixed count",
                target, domain
            )));
        }

        let c = self.ds.locate(q_usize)
            .map_err(|e| JsError::new(&format!("locate failed: {e:?}")))?;
        let s = c / t;
        let r = c % t;

        // Batch-access all cells in the segment except position r.
        // Uses 4-way PRP pipelining internally.
        let mut cells: Vec<usize> = Vec::with_capacity(t - 1);
        let mut cell_positions: Vec<usize> = Vec::with_capacity(t - 1); // original position in segment
        for i in 0..t {
            if i != r {
                cells.push(s * t + i);
                cell_positions.push(i);
            }
        }
        let values = self.ds.batch_access(&cells)
            .map_err(|e| JsError::new(&format!("batch_access failed: {e:?}")))?;

        // Collect real (non-empty) cells: (db_index, segment_position).
        let mut real: Vec<(u32, usize)> = Vec::with_capacity(target);
        for (k, &val) in values.iter().enumerate() {
            if val != EMPTY {
                real.push((val as u32, cell_positions[k]));
            }
        }

        // Pad with distinct random indices from [0, padded_n) that are
        // not already in `real`. The count of dummies brings the total
        // up to `target = t - 1` — independent of how many real cells
        // were non-empty, which is the key privacy property.
        let real_by_idx: std::collections::HashMap<u32, usize> =
            real.iter().map(|&(idx, pos)| (idx, pos)).collect();
        let need = target - real.len();
        let mut chosen: std::collections::HashSet<u32> =
            real_by_idx.keys().copied().collect();
        let mut dummies: Vec<u32> = Vec::with_capacity(need);
        while dummies.len() < need {
            let cand = self.rng.next_u32() % domain;
            if chosen.insert(cand) {
                dummies.push(cand);
            }
        }

        // Merge real + dummies, sort ascending for cache-friendly
        // server lookups. All `target` indices are distinct by
        // construction (dummies rejected against `chosen`).
        let mut merged: Vec<u32> = real_by_idx.keys().copied()
            .chain(dummies.iter().copied())
            .collect();
        merged.sort_unstable();
        debug_assert_eq!(merged.len(), target);

        // Build per-slot dummy flag + position map over real slots in
        // sorted-merged order. `position_map[k]` = segment position of
        // the k-th REAL entry when iterating `merged` in sorted order.
        let mut is_dummy: Vec<bool> = Vec::with_capacity(target);
        let mut position_map: Vec<usize> = Vec::with_capacity(real.len());
        for &idx in &merged {
            match real_by_idx.get(&idx) {
                Some(&pos) => {
                    is_dummy.push(false);
                    position_map.push(pos);
                }
                None => {
                    is_dummy.push(true);
                }
            }
        }

        // Serialize sorted indices.
        let mut request_bytes = Vec::with_capacity(target * 4);
        for &idx in &merged {
            request_bytes.extend_from_slice(&idx.to_le_bytes());
        }

        Ok(BuildRequestOutput {
            request_bytes,
            s,
            r,
            q: q_usize,
            position_map,
            is_dummy,
        })
    }

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
    verify_protocol_impl(n, w, PRP_HMR12)
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
        assert!(verify_protocol_impl(256, 42, PRP_HMR12));
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

        // Fixed-count invariant: every request is exactly (T - 1) * 4 bytes.
        let req = group.build_request(0).unwrap();
        assert_eq!(
            req.request_bytes.len(),
            (group.t() as usize - 1) * 4,
            "request must contain exactly T-1 sorted u32 indices"
        );
    }

    /// Exercise a full query lifecycle and collect request byte lengths.
    fn collect_request_sizes(
        n: u32, w: u32, queries: usize, backend: u8,
    ) -> Vec<usize> {
        let real_n = n as usize;
        let w_usize = w as usize;
        let t_val = find_best_t(n);
        let (padded_n, t_val) = pad_n_for_t(n, t_val);
        let padded_n_usize = padded_n as usize;
        let t = t_val as usize;

        let db: Vec<Vec<u8>> = (0..real_n)
            .map(|i| {
                let mut entry = vec![0u8; w_usize];
                let bytes = (i as u64).to_le_bytes();
                entry[..bytes.len().min(w_usize)]
                    .copy_from_slice(&bytes[..bytes.len().min(w_usize)]);
                entry
            })
            .collect();

        let key = [0x42u8; 16];
        let group_id: u32 = 0;
        let derived_key = derive_group_key(&key, group_id);
        let domain = 2 * padded_n_usize;

        let prp_server = build_prp(backend, &derived_key, domain, padded_n, &[]);
        let params = Params::new(padded_n_usize, w_usize, t).unwrap();
        let ds_server = RelocationDS::new(padded_n_usize, t, prp_server).unwrap();

        let m = params.m;
        let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w_usize]).collect();
        for k in 0..padded_n_usize {
            let cell = ds_server.locate(k).unwrap();
            if k < real_n {
                xor_into(&mut hints[cell / t], &db[k]);
            }
        }

        let mut group =
            HarmonyGroup::new_with_backend(n, w, t_val, &key, group_id, backend).unwrap();
        let flat_hints: Vec<u8> = hints.iter().flat_map(|h| h.iter().copied()).collect();
        group.load_hints(&flat_hints).unwrap();

        let simulate = |req: &HarmonyRequest, db: &[Vec<u8>], real_n: usize, w: usize| -> Vec<u8> {
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

        let max_q = params.max_queries.min(queries);
        let mut sizes = Vec::with_capacity(max_q);
        for i in 0..max_q {
            let q = (i * 7 + 3) % real_n;
            let req = group.build_request(q as u32).unwrap();
            sizes.push(req.request_bytes.len());
            let resp = simulate(&req, &db, real_n, w_usize);
            let result = group.process_response(&resp).unwrap();
            assert_eq!(result, db[q], "wrong row at query {i}");
        }
        sizes
    }

    #[test]
    fn test_request_is_fixed_length() {
        let n = 256u32;
        let w = 32u32;
        let key = [0x42u8; 16];
        let mut group = HarmonyGroup::new(n, w, 0, &key, 0).unwrap();
        let m = group.m() as usize;
        group.load_hints(&vec![0u8; m * w as usize]).unwrap();
        let t = group.t() as usize;
        let expected = (t - 1) * 4;

        // Fresh group (no relocation yet).
        let req = group.build_request(0).unwrap();
        assert_eq!(req.request_bytes.len(), expected);
    }

    #[test]
    fn test_synthetic_dummy_is_fixed_length() {
        let n = 256u32;
        let w = 32u32;
        let key = [0x42u8; 16];
        let mut group = HarmonyGroup::new(n, w, 0, &key, 0).unwrap();
        let t = group.t() as usize;
        let expected = (t - 1) * 4;
        for _ in 0..16 {
            let bytes = group.build_synthetic_dummy();
            assert_eq!(bytes.len(), expected);
        }
    }

    #[test]
    fn test_dummies_distinct_from_reals_and_each_other() {
        let n = 256u32;
        let w = 32u32;
        let key = [0x42u8; 16];
        let mut group = HarmonyGroup::new(n, w, 0, &key, 7).unwrap();
        let m = group.m() as usize;
        group.load_hints(&vec![0u8; m * w as usize]).unwrap();
        let padded_n = group.n();

        for q in [0u32, 17, 100, 250] {
            let req = group.build_request(q).unwrap();
            let bytes = &req.request_bytes;
            let count = bytes.len() / 4;
            let orig: Vec<u32> = (0..count)
                .map(|i| u32::from_le_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap()))
                .collect();

            // Sorted ascending + distinct.
            let mut dedup = orig.clone();
            dedup.sort_unstable();
            dedup.dedup();
            assert_eq!(dedup.len(), orig.len(), "duplicate indices in request");
            let mut sorted_copy = orig.clone();
            sorted_copy.sort_unstable();
            assert_eq!(orig, sorted_copy, "indices must be sorted ascending");

            // All within the padded_n PRP domain.
            for &idx in &orig {
                assert!(
                    idx < padded_n,
                    "index {idx} out of range [0, {padded_n})"
                );
            }
        }
    }

    #[test]
    fn test_correctness_survives_padding() {
        // Full protocol + many queries. verify_protocol_impl covers this,
        // but also run a longer lifecycle that stresses relocation.
        assert!(verify_protocol_impl(128, 32, PRP_HMR12));
        let sizes = collect_request_sizes(256, 32, 16, PRP_HMR12);
        let expected = sizes[0];
        for (i, &sz) in sizes.iter().enumerate() {
            assert_eq!(sz, expected, "size drift at query {i}: {sz} != {expected}");
        }
    }

    #[test]
    fn test_count_constant_across_aging() {
        // Request size must be identical across every query, regardless
        // of how hint/DS state has evolved (fresh → aged).
        let n = 256u32;
        let w = 32u32;
        // Run enough queries to cover a substantial fraction of max_queries.
        let sizes = collect_request_sizes(n, w, 24, PRP_HMR12);
        assert!(!sizes.is_empty());
        let expected = sizes[0];
        for (i, &sz) in sizes.iter().enumerate() {
            assert_eq!(sz, expected, "size drift at query {i}: {sz} != {expected}");
        }
    }

    #[test]
    fn test_serialize_deserialize_roundtrip_with_aging() {
        // Queries before serialize + queries after deserialize must all
        // succeed and maintain the fixed-count invariant. The verify
        // helper runs this end-to-end.
        assert!(verify_protocol_impl(256, 42, PRP_HMR12));

        // Additionally, assert that scratch state (last_is_dummy) is
        // NOT persisted — a fresh deserialize should have an empty
        // last_is_dummy until the first build_request call.
        let key = [0x42u8; 16];
        let mut group = HarmonyGroup::new(64, 32, 0, &key, 0).unwrap();
        let m = group.m() as usize;
        group.load_hints(&vec![0u8; m * 32]).unwrap();
        let data = group.serialize();
        let restored = HarmonyGroup::deserialize(&data, &key, 0).unwrap();
        assert!(restored.last_is_dummy.is_empty(),
            "last_is_dummy must not be persisted across serialize/deserialize");
        assert!(restored.last_position_map.is_empty(),
            "last_position_map must not be persisted across serialize/deserialize");
    }

    #[test]
    fn test_dummy_collision_budget_small() {
        // Edge case: T - 1 approaches real_n. Ensure the rejection
        // sampling loop terminates and produces distinct indices.
        // We force a small configuration via find_best_t.
        let n = 64u32;
        let w = 32u32;
        let key = [0x42u8; 16];
        let mut group = HarmonyGroup::new(n, w, 0, &key, 0).unwrap();
        let m = group.m() as usize;
        group.load_hints(&vec![0u8; m * w as usize]).unwrap();
        let t = group.t() as usize;
        assert!((t - 1) <= n as usize, "T-1={} must not exceed real_n={}", t - 1, n);
        let req = group.build_request(5).unwrap();
        assert_eq!(req.request_bytes.len(), (t - 1) * 4);
    }

    // ================================================================
    // Pipelined pair API — mirrors upstream test_split_pair_api_* and
    // test_query_pair_equiv_sequential_* tests in
    // harmonypir/src/protocol.rs.
    // ================================================================

    /// Build a server + populated hints from a deterministic DB.
    /// Returns (db, hints_flat, t_val, padded_n) for use with
    /// `pair_simulate` and `HarmonyGroup::new_with_backend`.
    fn pair_test_setup(
        n: u32, w: u32, backend: u8, master_key: &[u8; 16], group_id: u32,
    ) -> (Vec<Vec<u8>>, Vec<u8>, u32, u32) {
        let real_n = n as usize;
        let w_usize = w as usize;
        let t_val = find_best_t(n);
        let (padded_n, t_val) = pad_n_for_t(n, t_val);
        let padded_n_usize = padded_n as usize;
        let t = t_val as usize;

        let db: Vec<Vec<u8>> = (0..real_n)
            .map(|i| {
                let mut entry = vec![0u8; w_usize];
                let bytes = (i as u64).to_le_bytes();
                entry[..bytes.len().min(w_usize)]
                    .copy_from_slice(&bytes[..bytes.len().min(w_usize)]);
                entry
            })
            .collect();

        let derived_key = derive_group_key(master_key, group_id);
        let domain = 2 * padded_n_usize;
        let prp_server = build_prp(backend, &derived_key, domain, padded_n, &[]);
        let params = Params::new(padded_n_usize, w_usize, t).unwrap();
        let ds_server = RelocationDS::new(padded_n_usize, t, prp_server).unwrap();

        let m = params.m;
        let mut hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w_usize]).collect();
        for k in 0..padded_n_usize {
            let cell = ds_server.locate(k).unwrap();
            if k < real_n {
                xor_into(&mut hints[cell / t], &db[k]);
            }
            // k >= real_n: virtual row, contributes zeros.
        }
        let flat_hints: Vec<u8> = hints.iter().flat_map(|h| h.iter().copied()).collect();
        (db, flat_hints, t_val, padded_n)
    }

    /// Simulate the Query Server: parse `T - 1` sorted u32 indices from
    /// `req_bytes`, return concatenated DB entries (zeros for indices
    /// >= real_n). Mirrors the inline `simulate` closure used in
    /// `verify_protocol_impl` / `collect_request_sizes`.
    fn pair_simulate(req_bytes: &[u8], db: &[Vec<u8>], real_n: usize, w: usize) -> Vec<u8> {
        let count = req_bytes.len() / 4;
        let mut response = Vec::with_capacity(count * w);
        for j in 0..count {
            let off = j * 4;
            let idx = u32::from_le_bytes(req_bytes[off..off + 4].try_into().unwrap());
            if idx as usize >= real_n {
                response.extend(std::iter::repeat(0u8).take(w));
            } else {
                response.extend_from_slice(&db[idx as usize]);
            }
        }
        response
    }

    /// Run a pair via `build_request_pair` + simulated server +
    /// `process_response_pair`. Returns (a_1, a_2).
    fn run_pair(
        group: &mut HarmonyGroup, q_1: u32, q_2: u32, db: &[Vec<u8>], real_n: usize, w: usize,
    ) -> (Vec<u8>, Vec<u8>) {
        let pair = group.build_request_pair(q_1, q_2).unwrap();
        let (req_1, req_2) = pair.into_parts();
        let resp_1 = pair_simulate(&req_1.request_bytes, db, real_n, w);
        let resp_2 = pair_simulate(&req_2.request_bytes, db, real_n, w);
        let answers = group.process_response_pair(&resp_1, &resp_2).unwrap();
        answers.into_parts()
    }

    /// Run two queries sequentially via `build_request` + simulated
    /// server + `process_response`. Returns (a_1, a_2).
    fn run_sequential(
        group: &mut HarmonyGroup, q_1: u32, q_2: u32, db: &[Vec<u8>], real_n: usize, w: usize,
    ) -> (Vec<u8>, Vec<u8>) {
        let req_1 = group.build_request(q_1).unwrap();
        let resp_1 = pair_simulate(&req_1.request_bytes, db, real_n, w);
        let a_1 = group.process_response(&resp_1).unwrap();
        let req_2 = group.build_request(q_2).unwrap();
        let resp_2 = pair_simulate(&req_2.request_bytes, db, real_n, w);
        let a_2 = group.process_response(&resp_2).unwrap();
        (a_1, a_2)
    }

    #[test]
    fn test_pair_request_lengths() {
        // Each request in a pair must independently emit (T-1)*4 bytes
        // — the per-group request-count symmetry invariant. Mirror of
        // upstream `test_split_pair_api_request_length`.
        let n = 256u32;
        let w = 32u32;
        let key = [0xAAu8; 16];
        let (_db, hints, _t_val, _pn) = pair_test_setup(n, w, PRP_HMR12, &key, 0);
        let mut group = HarmonyGroup::new(n, w, 0, &key, 0).unwrap();
        group.load_hints(&hints).unwrap();
        let t = group.t() as usize;
        let expected = (t - 1) * 4;

        let pair = group.build_request_pair(3, 30).unwrap();
        let (req_1, req_2) = pair.into_parts();
        assert_eq!(req_1.request_bytes.len(), expected, "req_1 wrong length");
        assert_eq!(req_2.request_bytes.len(), expected, "req_2 wrong length");
    }

    /// Helper: assert the closure errors. The wrapper's error type is
    /// `JsError`, whose constructor calls into js_sys and panics on
    /// non-wasm targets. We catch the panic and treat it as
    /// "the error path was reached" — exactly what we want to assert.
    /// On wasm, the JsError is returned normally and `is_err()` checks
    /// directly. Either way the assertion fires only if the success
    /// path ran.
    fn assert_errors<R>(label: &str, f: impl FnOnce() -> Result<R, JsError>) {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let outcome = catch_unwind(AssertUnwindSafe(f));
        match outcome {
            Err(_) => {} // panicked constructing JsError on native — treated as Err
            Ok(Ok(_)) => panic!("{label} should have errored but returned Ok"),
            Ok(Err(_)) => {} // returned Err normally (wasm path)
        }
    }

    #[test]
    fn test_pair_rejects_wrong_response_length() {
        // Mirror of upstream `test_split_pair_api_rejects_wrong_response_length`.
        let n = 256u32;
        let w = 32u32;
        let key = [0xBBu8; 16];
        let (_db, hints, _t_val, _pn) = pair_test_setup(n, w, PRP_HMR12, &key, 0);
        let mut group = HarmonyGroup::new(n, w, 0, &key, 0).unwrap();
        group.load_hints(&hints).unwrap();
        let t = group.t() as usize;
        let target = t - 1;
        let w_usize = w as usize;

        // Wrong-length response_1 must error rather than corrupt state.
        // Note: the upstream contract is that an errored pair leaves
        // pending_pair taken (consumed by the take() at the top of
        // process_response_pair) — matching upstream finish_pair.
        let _pair = group.build_request_pair(0, 1).unwrap();
        let bad = vec![0u8; (target - 1) * w_usize]; // T-2 entries instead of T-1
        let good = vec![0u8; target * w_usize];
        assert_errors("wrong-length response_1", || {
            group.process_response_pair(&bad, &good)
        });
        // After the error, pending_pair has been taken — a follow-up
        // call also errors with "no pending pair".
        assert_errors("no pending pair after error", || {
            group.process_response_pair(&good, &good)
        });
    }

    #[test]
    fn test_pair_in_flight_invariant() {
        // While a pair is in flight, all mutating methods must reject.
        let n = 256u32;
        let w = 32u32;
        let key = [0xCCu8; 16];
        let (_db, hints, _t_val, _pn) = pair_test_setup(n, w, PRP_HMR12, &key, 0);
        let mut group = HarmonyGroup::new(n, w, 0, &key, 0).unwrap();
        group.load_hints(&hints).unwrap();

        let _pair = group.build_request_pair(0, 1).unwrap();
        assert_errors("build_request", || group.build_request(2));
        assert_errors("build_dummy_request", || group.build_dummy_request());
        assert_errors("second build_request_pair", || group.build_request_pair(2, 3));
        assert_errors("process_response", || group.process_response(&[]));
        assert_errors("process_response_xor_only", || group.process_response_xor_only(&[]));
        assert_errors("finish_relocation", || group.finish_relocation());
        assert_errors("load_hints", || group.load_hints(&[]));
        // build_synthetic_dummy is exempt (only RNG advances, no state mutation).
        let _ = group.build_synthetic_dummy();
    }

    #[test]
    fn test_pair_split_api_matches_query_pair_smoke() {
        // Sanity: pair returns the right DB rows. Mirror of upstream
        // `test_split_pair_api_matches_query_pair` (smoke half).
        let n = 256u32;
        let w = 32u32;
        let key = [0xDDu8; 16];
        let (db, hints, _t_val, _pn) = pair_test_setup(n, w, PRP_HMR12, &key, 0);
        let mut group = HarmonyGroup::new(n, w, 0, &key, 0).unwrap();
        group.load_hints(&hints).unwrap();

        let q_1 = 5u32;
        let q_2 = 17u32;
        let real_n = n as usize;
        let w_usize = w as usize;

        let (a_1, a_2) = run_pair(&mut group, q_1, q_2, &db, real_n, w_usize);
        assert_eq!(a_1, db[q_1 as usize], "pair returned wrong row for q_1");
        assert_eq!(a_2, db[q_2 as usize], "pair returned wrong row for q_2");
    }

    /// Helper: assert pair API and sequential API agree on answers AND
    /// on internal state across a sequence of pairs. Mirrors upstream
    /// `assert_query_pair_equiv_sequential`.
    fn assert_pair_equiv_sequential(
        n: u32, w: u32, backend: u8, master_key: &[u8; 16], pairs: &[(u32, u32)],
    ) {
        let real_n = n as usize;
        let w_usize = w as usize;
        let (db, hints, _t_val, _pn) = pair_test_setup(n, w, backend, master_key, 0);

        // Sequential client.
        let mut client_seq =
            HarmonyGroup::new_with_backend(n, w, 0, master_key, 0, backend).unwrap();
        client_seq.load_hints(&hints).unwrap();

        // Paired client (same construction → same RNG seed).
        let mut client_pair =
            HarmonyGroup::new_with_backend(n, w, 0, master_key, 0, backend).unwrap();
        client_pair.load_hints(&hints).unwrap();

        for (i, &(q_1, q_2)) in pairs.iter().enumerate() {
            let (a1_seq, a2_seq) = run_sequential(&mut client_seq, q_1, q_2, &db, real_n, w_usize);
            let (a1_pair, a2_pair) = run_pair(&mut client_pair, q_1, q_2, &db, real_n, w_usize);

            assert_eq!(a1_seq, db[q_1 as usize], "seq pair {i}: A_1 wrong");
            assert_eq!(a2_seq, db[q_2 as usize], "seq pair {i}: A_2 wrong");
            assert_eq!(a1_pair, db[q_1 as usize], "pair pair {i}: A_1 wrong");
            assert_eq!(a2_pair, db[q_2 as usize], "pair pair {i}: A_2 wrong");
            assert_eq!(a1_seq, a1_pair, "pair {i}: A_1 differs seq vs pair");
            assert_eq!(a2_seq, a2_pair, "pair {i}: A_2 differs seq vs pair");
        }

        // Internal-state equivalence: hints, query_count, relocated_segments.
        assert_eq!(client_seq.hints, client_pair.hints, "hints diverge");
        assert_eq!(
            client_seq.query_count, client_pair.query_count,
            "query_count diverges"
        );
        assert_eq!(
            client_seq.relocated_segments, client_pair.relocated_segments,
            "relocated_segments diverge"
        );
    }

    #[test]
    fn test_pair_equiv_sequential_basic() {
        // Mirror of upstream `test_query_pair_equiv_sequential_basic`.
        // Distinct pairs across various combinations.
        let pairs = [(0u32, 1u32), (5, 17), (3, 30), (60, 7)];
        assert_pair_equiv_sequential(256, 32, PRP_HMR12, &[0xABu8; 16], &pairs);
    }

    #[test]
    fn test_pair_equiv_sequential_chained() {
        // Many pairs in sequence — exercises state evolution across pairs.
        // Mirror of upstream `test_query_pair_equiv_sequential_chained`.
        let pairs: Vec<(u32, u32)> = (0..4u32).map(|i| (i, 255 - i)).collect();
        assert_pair_equiv_sequential(256, 32, PRP_HMR12, &[0x33u8; 16], &pairs);
    }

    #[test]
    fn test_pair_same_index() {
        // q_1 == q_2: edge case — both answers must equal db[q].
        // q is relocated twice, hints updated correspondingly. Mirror
        // of upstream `test_query_pair_same_index`.
        let pairs = [(7u32, 7u32), (42, 42)];
        assert_pair_equiv_sequential(256, 32, PRP_HMR12, &[0xCDu8; 16], &pairs);
    }

    #[test]
    fn test_pair_budget_check() {
        // Pair must reserve 2 slots up front. With max_queries M = 8,
        // we should be able to do 4 pairs but not 5.
        let n = 64u32; // small N → small max_queries
        let w = 32u32;
        let key = [0xEEu8; 16];
        let (db, hints, _t_val, _pn) = pair_test_setup(n, w, PRP_HMR12, &key, 0);
        let mut group = HarmonyGroup::new(n, w, 0, &key, 0).unwrap();
        group.load_hints(&hints).unwrap();
        let max_q = group.max_queries() as usize;
        let real_n = n as usize;
        let w_usize = w as usize;

        // Issue floor(max_q / 2) pairs.
        let n_pairs = max_q / 2;
        for i in 0..n_pairs {
            let q_1 = (i % real_n) as u32;
            let q_2 = ((i + 7) % real_n) as u32;
            let (a_1, a_2) = run_pair(&mut group, q_1, q_2, &db, real_n, w_usize);
            assert_eq!(a_1, db[q_1 as usize], "pair {i}: A_1 wrong");
            assert_eq!(a_2, db[q_2 as usize], "pair {i}: A_2 wrong");
        }
        // One more pair would overflow the budget.
        if max_q % 2 == 0 {
            assert_errors("budget exhausted", || group.build_request_pair(0, 1));
        }
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
