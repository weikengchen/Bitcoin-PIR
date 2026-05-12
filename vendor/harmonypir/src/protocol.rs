//! HarmonyPIR client protocol (Algorithm 3 + Algorithm 7).
//!
//! # Protocol overview
//!
//! ## Offline phase (PIR.Offline)
//!
//! 1. Initialize the restricted relocation data structure DS' with 2N cells
//!    and segment size T. The permutation P determines the initial layout.
//! 2. Compute M = 2N/T hint parities. Hint parity H[i] is the XOR of all
//!    database entries whose indices appear in segment i of DS'.
//!    - Stream the database entry by entry.
//!    - For each entry DB[k], find its cell via Locate(k), determine its
//!      segment s = ⌊cell/T⌋, and XOR DB[k] into H[s].
//!
//! ## Online phase (PIR.Online) — one query
//!
//! Given a query index q:
//!
//! ### Request construction (Algorithm 3, lines 4-10)
//! 1. Locate q in DS': cell c = Locate(q), segment s = ⌊c/T⌋, position r = c mod T.
//! 2. Build request Q of size T:
//!    - For each position i ≠ r: Q[i] = Access(s·T + i) (the values in segment s).
//!    - For position r: sample a random cell l not in the relocated set C and not in
//!      segment s, and set Q[r] = Access(l).
//!    - This hides which position in the segment contains the query.
//!
//! ### Response + answer (line 11-12)
//! 3. Send Q to the server. Receive response R = [DB[Q[0]], DB[Q[1]], ...].
//! 4. Compute the answer: A = H[s] ⊕ XOR_{i≠r} R[i].
//!    Since H[s] = XOR of all DB entries at indices in segment s, and R gives us
//!    all of them except DB[q], the result A = DB[q].
//!
//! ### Relocation + hint update (Algorithm 7)
//! 5. RelocateSegment(s): the T values in segment s move to random empty cells.
//! 6. Update hint parities: for each relocated value, find its new segment
//!    and XOR the corresponding DB entry into the new segment's hint.
//!    Algorithm 7 optimizes this by locating the destination empty-value cells
//!    rather than re-locating each original value.
//!
//! After M/2 queries, all empty cells are used up. Re-run the offline phase.

use rand::Rng;

use crate::error::{HarmonyPirError, Result};
use crate::params::Params;
use crate::prp::Prp;
use crate::relocation::{RelocationDS, EMPTY};
use crate::server::Server;
use crate::util::{xor_bytes_into, zero_entry};

/// The HarmonyPIR client.
///
/// Holds the relocation data structure DS' and the hint parities H.
pub struct Client {
    /// Protocol parameters.
    params: Params,
    /// The restricted relocation data structure.
    ds: RelocationDS,
    /// Hint parities: M entries, each of w bytes.
    /// H[i] = XOR of DB[v] for all values v in segment i of DS'.
    hints: Vec<Vec<u8>>,
    /// Number of queries executed since the last offline phase.
    query_count: usize,
}

/// Per-call state bridging [`Client::build_pair_requests`] and [`Client::finish_pair`].
///
/// Holds the segment/position metadata and the destination segments for q_1's
/// relocation (already applied to DS' by `build_pair_requests`). Opaque to the
/// caller — just thread the value from build to finish.
///
/// **State invariant**: while a `PendingPair` is outstanding, the client's DS'
/// has been advanced past q_1's relocation, but the hint parities have NOT
/// been updated. Calling another query method on the same client before
/// `finish_pair` would corrupt state. Treat the pair as in-flight until
/// finish_pair returns.
#[must_use = "the PendingPair must be passed to Client::finish_pair to complete the pair query"]
pub struct PendingPair {
    s_1: usize,
    r_1: usize,
    /// d_1[i] = segment containing the destination cell of q_1's i-th
    /// per-cell relocation (computed post-RelocateSegment(s_1)).
    d_1: Vec<usize>,
    s_2: usize,
    r_2: usize,
}

impl Client {
    /// Run the offline phase: initialize DS' and compute hint parities by
    /// streaming the database from the server.
    ///
    /// # Arguments
    /// - `params`: protocol parameters (N, w, T, etc.).
    /// - `prp`: a PRP over domain [2N], used to initialize DS'.
    /// - `server`: the server holding the database.
    pub fn offline(params: Params, prp: Box<dyn Prp>, server: &Server) -> Result<Self> {
        // Step 1: Initialize DS' with 2N cells and segment size T.
        let ds = RelocationDS::new(params.n, params.t, prp)?;

        // Step 2: Initialize M hint parities to zero.
        let mut hints: Vec<Vec<u8>> = (0..params.m).map(|_| zero_entry(params.w)).collect();

        // Step 3: Stream the database and compute hint parities.
        // For each entry DB[k], find its cell, determine its segment, XOR into hint.
        server.stream_db(|k, entry| {
            let cell = ds.locate(k).expect("Locate should succeed during offline");
            let segment = cell / params.t;
            xor_bytes_into(&mut hints[segment], entry);
        });

        Ok(Client {
            params,
            ds,
            hints,
            query_count: 0,
        })
    }

    /// Execute a single online query for database index `q`.
    ///
    /// Returns the retrieved database entry DB[q].
    pub fn query(&mut self, q: usize, server: &Server, rng: &mut impl Rng) -> Result<Vec<u8>> {
        if q >= self.params.n {
            return Err(HarmonyPirError::InvalidIndex {
                index: q,
                max: self.params.n - 1,
            });
        }
        if self.query_count >= self.params.max_queries {
            return Err(HarmonyPirError::NoMoreQueries);
        }

        let t = self.params.t;

        // === Request construction (Algorithm 3, lines 4-10) ===

        // Locate q: find its cell, segment, and position within the segment.
        let c = self.ds.locate(q)?;
        let s = c / t; // segment index
        let r = c % t; // position within segment

        // Build request Q of size T.
        let mut request = vec![EMPTY; t];

        // For i ≠ r: Q[i] = Access(s·T + i), the other values in segment s.
        for i in 0..t {
            if i != r {
                request[i] = self.ds.access(s * t + i)?;
            }
        }

        // For position r: sample a random cell NOT in relocated set C and NOT in segment s.
        // Use rejection sampling.
        let l = self.sample_random_cell(s, rng)?;
        request[r] = self.ds.access(l)?;

        // === Send request to server and receive response (line 11) ===
        let response = server.answer(&request);

        // === Compute the answer (line 12) ===
        // A = H[s] ⊕ XOR_{i ∈ [T]\{r}} R[i]
        let mut answer = self.hints[s].clone();
        for i in 0..t {
            if i != r {
                xor_bytes_into(&mut answer, &response[i]);
            }
        }
        // `answer` now equals DB[q].

        // === Relocation + hint update (Algorithm 7) ===
        self.relocate_and_update_hints(s, r, &response, &answer)?;

        self.query_count += 1;
        Ok(answer)
    }

    /// Build both server requests for a pipelined pair query.
    ///
    /// This is the **build half** of the pair-pipelined online phase. It
    /// constructs requests for both `q_1` and `q_2` and advances DS' past
    /// q_1's relocation, but does NOT touch the hint parities. The caller
    /// then sends both requests over the network (in parallel, ideally)
    /// and feeds both responses to [`Client::finish_pair`] together with
    /// the returned [`PendingPair`].
    ///
    /// # Output
    ///
    /// - `request_1`, `request_2`: each a `Vec<usize>` of length T, with
    ///   entries in `[0, N)` for real database indices or [`EMPTY`] for
    ///   empty cells. The caller passes these through whatever wire format
    ///   the server expects, and feeds back two `&[Vec<u8>]` responses of
    ///   exactly T entries each.
    /// - [`PendingPair`]: opaque state to thread to `finish_pair`.
    ///
    /// # In-flight state
    ///
    /// Between `build_pair_requests` and `finish_pair`, the client is in
    /// an **in-flight** state — DS' is advanced but H is stale. Do not
    /// call `query`, `query_pair`, `apply_modification`, etc. on the same
    /// client until `finish_pair` returns. The borrow checker won't catch
    /// this — it's a logical invariant.
    ///
    /// # Equivalence
    ///
    /// `build_pair_requests(q_1, q_2, rng)` followed by `finish_pair(...)`
    /// produces the same final client state and same answers as two
    /// sequential `query(q_1)` then `query(q_2)` calls with the same RNG
    /// (proof: see test suite, `test_query_pair_equiv_sequential_*`).
    ///
    /// # Why this is sound
    ///
    /// `RelocateSegment(s)` is purely local — it appends to the relocation
    /// history and does not touch H. Only the *hint update* (H[d_i] ⊕= R[i]
    /// and H[d_r] ⊕= A) depends on the server's response. So we can:
    ///
    /// 1. Build Q_1 from DS'_0.
    /// 2. Apply `RelocateSegment(s_1)` locally → DS'_1. (No server data needed.)
    /// 3. Build Q_2 from DS'_1. `Locate(q_2)`, `Access` calls, and the fake
    ///    position l_2 all use the post-step-2 DS' — same as what sequential
    ///    would see between query 1 and query 2.
    /// 4. (caller) Send both requests; receive both responses.
    /// 5. (`finish_pair`) Compute A_1 from pre-update H[s_1] and R_1.
    /// 6. Apply Part B for q_1: H ⊕= R_1, A_1.
    /// 7. Compute A_2 from post-Part-B H[s_2] and R_2.    ← H[s_2] may have
    ///    been just updated by step 6 if q_1 relocated a value into segment
    ///    s_2; this is exactly what sequential would do too.
    /// 8. RelocateSegment(s_2) + Part B for q_2.
    pub fn build_pair_requests(
        &mut self,
        q_1: usize,
        q_2: usize,
        rng: &mut impl Rng,
    ) -> Result<(Vec<usize>, Vec<usize>, PendingPair)> {
        if q_1 >= self.params.n {
            return Err(HarmonyPirError::InvalidIndex {
                index: q_1,
                max: self.params.n - 1,
            });
        }
        if q_2 >= self.params.n {
            return Err(HarmonyPirError::InvalidIndex {
                index: q_2,
                max: self.params.n - 1,
            });
        }
        if self.query_count + 2 > self.params.max_queries {
            return Err(HarmonyPirError::NoMoreQueries);
        }

        let t = self.params.t;
        let n = self.params.n;

        // ── Step 1: Build Q_1 from current DS' ──
        let c_1 = self.ds.locate(q_1)?;
        let s_1 = c_1 / t;
        let r_1 = c_1 % t;

        let mut request_1 = vec![EMPTY; t];
        for i in 0..t {
            if i != r_1 {
                request_1[i] = self.ds.access(s_1 * t + i)?;
            }
        }
        let l_1 = self.sample_random_cell(s_1, rng)?;
        request_1[r_1] = self.ds.access(l_1)?;

        // ── Step 2: RelocateSegment(s_1); cache q_1's destination segments ──
        let m_1 = self.ds.relocated_segment_count();
        self.ds.relocate_segment(s_1)?;

        let mut d_1 = vec![0usize; t];
        for i in 0..t {
            let empty_value = n + m_1 * t + i;
            let dest_cell = self.ds.locate_extended(empty_value)?;
            d_1[i] = dest_cell / t;
        }

        // ── Step 3: Build Q_2 from updated DS' ──
        let c_2 = self.ds.locate(q_2)?;
        let s_2 = c_2 / t;
        let r_2 = c_2 % t;

        let mut request_2 = vec![EMPTY; t];
        for i in 0..t {
            if i != r_2 {
                request_2[i] = self.ds.access(s_2 * t + i)?;
            }
        }
        let l_2 = self.sample_random_cell(s_2, rng)?;
        request_2[r_2] = self.ds.access(l_2)?;

        Ok((
            request_1,
            request_2,
            PendingPair {
                s_1,
                r_1,
                d_1,
                s_2,
                r_2,
            },
        ))
    }

    /// Finish a pipelined pair query: compute both answers and complete state updates.
    ///
    /// Consumes the [`PendingPair`] returned by `build_pair_requests` and the
    /// two server responses. Each response must be exactly T entries of w
    /// bytes (matching the request length).
    ///
    /// On success, the client's H and DS' are advanced as if two sequential
    /// `query` calls had completed.
    pub fn finish_pair(
        &mut self,
        pending: PendingPair,
        response_1: &[Vec<u8>],
        response_2: &[Vec<u8>],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let t = self.params.t;
        let n = self.params.n;
        if response_1.len() != t || response_2.len() != t {
            return Err(HarmonyPirError::InvalidParams(
                "response length must equal T (segment size)",
            ));
        }

        let PendingPair { s_1, r_1, d_1, s_2, r_2 } = pending;

        // ── Step 5: A_1 (uses pre-update H[s_1]) ──
        let mut answer_1 = self.hints[s_1].clone();
        for i in 0..t {
            if i != r_1 {
                xor_bytes_into(&mut answer_1, &response_1[i]);
            }
        }

        // ── Step 6: Part B for q_1 — advance H using R_1, A_1 ──
        for i in 0..t {
            if i != r_1 {
                xor_bytes_into(&mut self.hints[d_1[i]], &response_1[i]);
            } else {
                xor_bytes_into(&mut self.hints[d_1[i]], &answer_1);
            }
        }

        // ── Step 7: A_2 (uses post-step-6 H[s_2]) ──
        let mut answer_2 = self.hints[s_2].clone();
        for i in 0..t {
            if i != r_2 {
                xor_bytes_into(&mut answer_2, &response_2[i]);
            }
        }

        // ── Step 8: RelocateSegment(s_2) + Part B for q_2 ──
        let m_2 = self.ds.relocated_segment_count();
        self.ds.relocate_segment(s_2)?;
        for i in 0..t {
            let empty_value = n + m_2 * t + i;
            let dest_cell = self.ds.locate_extended(empty_value)?;
            let e_i = dest_cell / t;
            if i != r_2 {
                xor_bytes_into(&mut self.hints[e_i], &response_2[i]);
            } else {
                xor_bytes_into(&mut self.hints[e_i], &answer_2);
            }
        }

        self.query_count += 2;
        Ok((answer_1, answer_2))
    }

    /// Execute two online queries with pipelined server roundtrips.
    ///
    /// All-in-one convenience wrapper around [`Client::build_pair_requests`]
    /// and [`Client::finish_pair`] for users that have a local [`Server`].
    /// Real deployments with a remote server should call the two halves
    /// directly so the network roundtrip can be parallelized.
    ///
    /// The observable result is identical to two sequential `query()` calls
    /// for `q_1` then `q_2` (same answers, same final H, same final DS').
    pub fn query_pair(
        &mut self,
        q_1: usize,
        q_2: usize,
        server: &Server,
        rng: &mut impl Rng,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (request_1, request_2, pending) =
            self.build_pair_requests(q_1, q_2, rng)?;
        // In a real deployment these two `answer` calls would be issued in
        // parallel over the network. Here they're sequential because the
        // server is in-process.
        let response_1 = server.answer(&request_1);
        let response_2 = server.answer(&request_2);
        self.finish_pair(pending, &response_1, &response_2)
    }

    /// Algorithm 7: Optimized hint relocation.
    ///
    /// After querying segment s, relocate its values to random empty cells
    /// and update the hint parities accordingly.
    ///
    /// Instead of calling Locate on each value in Q to find its new segment,
    /// we use the knowledge that the j-th cell relocated from segment s goes to
    /// cell Locate(N + m·T + j), where m is the count of previously relocated segments.
    fn relocate_and_update_hints(
        &mut self,
        s: usize,
        r: usize,
        response: &[Vec<u8>],
        answer: &[u8],
    ) -> Result<()> {
        let t = self.params.t;
        let n = self.params.n;

        // m = number of segments relocated before this one.
        let m = self.ds.relocated_segment_count();

        // Step 1: RelocateSegment(s).
        self.ds.relocate_segment(s)?;

        // Step 2: Update hint parities.
        // The i-th cell of segment s has relocated to cell Locate(N + m·T + i).
        for i in 0..t {
            // Find the destination segment for the i-th cell of segment s.
            let empty_value = n + m * t + i;
            let dest_cell = self.ds.locate_extended(empty_value)?;
            let d_i = dest_cell / t;

            if i != r {
                // This cell held a request value Q[i]. The DB entry is response[i].
                xor_bytes_into(&mut self.hints[d_i], &response[i]);
            } else {
                // This cell held the query index q. The DB entry is `answer` (= DB[q]).
                xor_bytes_into(&mut self.hints[d_i], answer);
            }
        }

        Ok(())
    }

    /// Sample a random cell that is:
    /// - Not in the relocated set C.
    /// - Not in segment s (except we exclude only non-r positions, but for simplicity
    ///   we exclude the entire segment s).
    ///
    /// Uses rejection sampling. Expected O(1) attempts since at most half the cells
    /// are relocated after M/2 queries.
    fn sample_random_cell(
        &self,
        excluded_segment: usize,
        rng: &mut impl Rng,
    ) -> Result<usize> {
        let domain = 2 * self.params.n;
        let t = self.params.t;

        for _ in 0..10_000 {
            let cell = rng.gen_range(0..domain);
            let cell_segment = cell / t;

            // Skip if in the excluded segment.
            if cell_segment == excluded_segment {
                continue;
            }

            // Skip if the cell's segment has been relocated.
            if self.ds.is_cell_in_relocated_segment(cell) {
                continue;
            }

            return Ok(cell);
        }

        // Should never happen with correct parameters.
        Err(HarmonyPirError::InvalidParams(
            "rejection sampling failed to find a valid cell",
        ))
    }

    /// Handle a database modification at index `i`.
    ///
    /// The server sends `diff = DB_old[i] ⊕ DB_new[i]`.
    /// The client updates the hint parity of the segment containing index i.
    pub fn apply_modification(&mut self, i: usize, diff: &[u8]) -> Result<()> {
        let cell = self.ds.locate(i)?;
        let segment = cell / self.params.t;
        xor_bytes_into(&mut self.hints[segment], diff);
        Ok(())
    }

    /// Number of queries executed since the last offline phase.
    pub fn queries_used(&self) -> usize {
        self.query_count
    }

    /// Number of queries remaining before the offline phase must be re-run.
    pub fn queries_remaining(&self) -> usize {
        self.params.max_queries - self.query_count
    }

    /// The protocol parameters.
    pub fn params(&self) -> &Params {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alf")]
    use crate::prp::alf::AlfPrp;
    #[cfg(feature = "fastprp-prp")]
    use crate::prp::fast::FastPrpWrapper;
    use crate::prp::hoang::HoangPrp;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Create a test database of N entries, each w bytes.
    fn make_test_db(n: usize, w: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                // Deterministic but distinct entries.
                let mut entry = vec![0u8; w];
                let bytes = (i as u64).to_le_bytes();
                let copy_len = bytes.len().min(w);
                entry[..copy_len].copy_from_slice(&bytes[..copy_len]);
                // Add some variation.
                if w > 8 {
                    entry[8] = (i * 37) as u8;
                    entry[w - 1] = (i * 53) as u8;
                }
                entry
            })
            .collect()
    }

    #[test]
    fn test_single_query_correctness() {
        let n = 64;
        let w = 32;
        let t = 8; // 2*64/8 = 16 segments, max_queries = 8
        let key = [0x42u8; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let server = Server::new(db.clone());
        let params = Params::new(n, w, t).unwrap();
        let prp = Box::new(HoangPrp::new(2 * n, r, &key));
        let mut client = Client::offline(params, prp, &server).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(123);

        // Query index 0.
        let result = client.query(0, &server, &mut rng).unwrap();
        assert_eq!(result, db[0], "query(0) returned wrong entry");
    }

    #[test]
    fn test_multiple_queries_correctness() {
        let n = 64;
        let w = 32;
        let t = 8;
        let key = [0xAB; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let server = Server::new(db.clone());
        let params = Params::new(n, w, t).unwrap();
        let prp = Box::new(HoangPrp::new(2 * n, r, &key));
        let mut client = Client::offline(params, prp, &server).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(456);

        // Query several different indices.
        let queries = [0, 10, 63, 1, 32, 7, 50, 20];
        for &q in &queries[..client.params().max_queries.min(queries.len())] {
            let result = client.query(q, &server, &mut rng).unwrap();
            assert_eq!(result, db[q], "query({q}) returned wrong entry");
        }
    }

    #[test]
    fn test_repeated_queries_same_index() {
        let n = 64;
        let w = 32;
        let t = 8;
        let key = [0xCD; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let server = Server::new(db.clone());
        let params = Params::new(n, w, t).unwrap();
        let max_q = params.max_queries;
        let prp = Box::new(HoangPrp::new(2 * n, r, &key));
        let mut client = Client::offline(params, prp, &server).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(789);

        // Query the same index repeatedly.
        for _ in 0..max_q {
            let result = client.query(5, &server, &mut rng).unwrap();
            assert_eq!(result, db[5]);
        }
    }

    #[test]
    fn test_no_more_queries_error() {
        let n = 8;
        let w = 4;
        let t = 4; // max_queries = 8/4 = 2
        let key = [0xEF; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let server = Server::new(db);
        let params = Params::new(n, w, t).unwrap();
        let prp = Box::new(HoangPrp::new(2 * n, r, &key));
        let mut client = Client::offline(params, prp, &server).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(0);

        // Use all queries.
        for _ in 0..2 {
            client.query(0, &server, &mut rng).unwrap();
        }

        // Next query should fail.
        let result = client.query(0, &server, &mut rng);
        assert!(matches!(result, Err(HarmonyPirError::NoMoreQueries)));
    }

    #[test]
    fn test_database_modification() {
        let n = 64;
        let w = 32;
        let t = 8;
        let key = [0x11; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let mut server = Server::new(db.clone());
        let params = Params::new(n, w, t).unwrap();
        let prp = Box::new(HoangPrp::new(2 * n, r, &key));
        let mut client = Client::offline(params, prp, &server).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(999);

        // Modify entry 10.
        let new_entry = vec![0xFF; w];
        let diff = server.modify_entry(10, new_entry.clone());
        client.apply_modification(10, &diff).unwrap();

        // Query index 10 should return the new entry.
        let result = client.query(10, &server, &mut rng).unwrap();
        assert_eq!(result, new_entry);
    }

    // ================================================================
    // End-to-end protocol tests for all PRP implementations
    // ================================================================

    /// Helper: run full protocol (offline + multiple queries) with any PRP.
    fn run_protocol_test(prp: Box<dyn crate::prp::Prp>, n: usize, w: usize, t: usize) {
        let db = make_test_db(n, w);
        let server = Server::new(db.clone());
        let params = Params::new(n, w, t).unwrap();
        let mut client = Client::offline(params, prp, &server).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let max_q = client.params().max_queries;

        // Query every index we can (up to max_queries), cycling through the database.
        for i in 0..max_q {
            let q = i % n;
            let result = client.query(q, &server, &mut rng).unwrap();
            assert_eq!(
                result, db[q],
                "query({q}) returned wrong entry on iteration {i}"
            );
        }
    }

    // --- FastPRP protocol tests ---

    #[cfg(feature = "fastprp-prp")]
    #[test]
    fn test_fastprp_protocol_small() {
        // N=64, domain=128
        let n = 64;
        let prp = Box::new(FastPrpWrapper::new(&[0x42u8; 16], 2 * n));
        run_protocol_test(prp, n, 32, 8);
    }

    #[cfg(feature = "fastprp-prp")]
    #[test]
    fn test_fastprp_protocol_medium() {
        // N=1024, domain=2048, 40-byte entries
        let n = 1024;
        let w = 40;
        let t = 32; // sqrt(1024) = 32
        let prp = Box::new(FastPrpWrapper::new(&[0xABu8; 16], 2 * n));
        run_protocol_test(prp, n, w, t);
    }

    #[cfg(feature = "fastprp-prp")]
    #[test]
    fn test_fastprp_protocol_with_group_key() {
        let n = 512;
        let prp = Box::new(FastPrpWrapper::with_group(&[0x42u8; 16], 7, 2 * n));
        run_protocol_test(prp, n, 32, 16);
    }

    // --- ALF protocol tests ---

    #[cfg(feature = "alf")]
    #[test]
    fn test_alf_protocol() {
        // ALF minimum domain is 65536, so N >= 32768.
        let n = 32768;
        let w = 40;
        let t = 128; // ~sqrt(32768) ≈ 181, use 128 for clean segments
        let domain = 2 * n; // 65536
        let prp = Box::new(AlfPrp::new(&[0x42u8; 16], domain, &[0u8; 16], 0));
        run_protocol_test(prp, n, w, t);
    }

    #[cfg(feature = "alf")]
    #[test]
    fn test_alf_protocol_different_tweaks() {
        // Two different tweaks produce valid but different protocol runs.
        let n = 32768;
        let w = 32;
        let t = 128;
        let domain = 2 * n;
        let key = [0x42u8; 16];

        let db = make_test_db(n, w);
        let server = Server::new(db.clone());

        for tweak_byte in [0u8, 1u8, 2u8] {
            let mut tweak = [0u8; 16];
            tweak[0] = tweak_byte;
            let prp = Box::new(AlfPrp::new(&key, domain, &tweak, 0));
            let params = Params::new(n, w, t).unwrap();
            let mut client = Client::offline(params, prp, &server).unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(100 + tweak_byte as u64);

            // Each tweak should still produce correct query results.
            for q in [0, 1, 100, 1000, n - 1] {
                let result = client.query(q, &server, &mut rng).unwrap();
                assert_eq!(result, db[q], "tweak={tweak_byte} query({q}) wrong");
            }
        }
    }

    // --- Hoang protocol test at larger size ---

    #[test]
    fn test_hoang_protocol_medium() {
        let n = 1024;
        let w = 40;
        let t = 32;
        let r = 44;
        let prp = Box::new(HoangPrp::new(2 * n, r, &[0xCDu8; 16]));
        run_protocol_test(prp, n, w, t);
    }

    // ================================================================
    // Pipelined `query_pair` — equivalence to sequential `query`
    // ================================================================

    /// Compare `query_pair(q_1, q_2)` against `query(q_1); query(q_2)` on two
    /// independently-built clients seeded identically. Equivalence means
    /// (a) same answers and (b) same internal state (H, query_count, and
    /// `relocated_segment_count` of DS').
    fn assert_query_pair_equiv_sequential(
        n: usize,
        w: usize,
        t: usize,
        prp_factory: impl Fn() -> Box<dyn crate::prp::Prp>,
        rng_seed: u64,
        pairs: &[(usize, usize)],
    ) {
        let db = make_test_db(n, w);
        let server = Server::new(db.clone());

        // -- Sequential mode: run query(q_1) then query(q_2) for each pair --
        let mut client_seq = {
            let params = Params::new(n, w, t).unwrap();
            Client::offline(params, prp_factory(), &server).unwrap()
        };
        let mut rng_seq = ChaCha20Rng::seed_from_u64(rng_seed);
        let mut answers_seq: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for &(q_1, q_2) in pairs {
            let a1 = client_seq.query(q_1, &server, &mut rng_seq).unwrap();
            let a2 = client_seq.query(q_2, &server, &mut rng_seq).unwrap();
            answers_seq.push((a1, a2));
        }

        // -- Pipelined mode: run query_pair(q_1, q_2) for each pair --
        let mut client_pipe = {
            let params = Params::new(n, w, t).unwrap();
            Client::offline(params, prp_factory(), &server).unwrap()
        };
        let mut rng_pipe = ChaCha20Rng::seed_from_u64(rng_seed);
        let mut answers_pipe: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for &(q_1, q_2) in pairs {
            let pair = client_pipe
                .query_pair(q_1, q_2, &server, &mut rng_pipe)
                .unwrap();
            answers_pipe.push(pair);
        }

        // (1) answers per-pair must match between modes,
        //     and each answer must equal db[q].
        for (i, &(q_1, q_2)) in pairs.iter().enumerate() {
            let (a1_seq, a2_seq) = &answers_seq[i];
            let (a1_pipe, a2_pipe) = &answers_pipe[i];

            assert_eq!(a1_seq, &db[q_1], "seq pair {i}: A_1 wrong");
            assert_eq!(a2_seq, &db[q_2], "seq pair {i}: A_2 wrong");
            assert_eq!(a1_pipe, &db[q_1], "pipe pair {i}: A_1 wrong");
            assert_eq!(a2_pipe, &db[q_2], "pipe pair {i}: A_2 wrong");

            assert_eq!(a1_seq, a1_pipe, "pair {i}: A_1 differs seq vs pipe");
            assert_eq!(a2_seq, a2_pipe, "pair {i}: A_2 differs seq vs pipe");
        }

        // (2) internal client state must match.
        assert_eq!(client_seq.hints, client_pipe.hints, "hints diverge");
        assert_eq!(
            client_seq.query_count, client_pipe.query_count,
            "query_count diverges"
        );
        assert_eq!(
            client_seq.ds.relocated_segment_count(),
            client_pipe.ds.relocated_segment_count(),
            "DS' relocated_segment_count diverges"
        );
    }

    #[test]
    fn test_split_pair_api_matches_query_pair() {
        // Exercise the split (build_pair_requests + finish_pair) API directly
        // and verify it produces the same result as query_pair.
        let n = 64;
        let w = 32;
        let t = 8;
        let key = [0x99u8; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let server = Server::new(db.clone());

        let q_1 = 5;
        let q_2 = 17;

        // Path A: Client::query_pair (all-in-one).
        let mut client_a = {
            let params = Params::new(n, w, t).unwrap();
            let prp = Box::new(HoangPrp::new(2 * n, r, &key));
            Client::offline(params, prp, &server).unwrap()
        };
        let mut rng_a = ChaCha20Rng::seed_from_u64(11);
        let (a1_a, a2_a) = client_a.query_pair(q_1, q_2, &server, &mut rng_a).unwrap();

        // Path B: build_pair_requests, manual server.answer calls, finish_pair.
        let mut client_b = {
            let params = Params::new(n, w, t).unwrap();
            let prp = Box::new(HoangPrp::new(2 * n, r, &key));
            Client::offline(params, prp, &server).unwrap()
        };
        let mut rng_b = ChaCha20Rng::seed_from_u64(11);
        let (req_1, req_2, pending) = client_b
            .build_pair_requests(q_1, q_2, &mut rng_b)
            .unwrap();
        // Caller-side network roundtrip — could be parallel in a real deployment.
        let resp_1 = server.answer(&req_1);
        let resp_2 = server.answer(&req_2);
        let (a1_b, a2_b) = client_b.finish_pair(pending, &resp_1, &resp_2).unwrap();

        assert_eq!(a1_a, db[q_1]);
        assert_eq!(a2_a, db[q_2]);
        assert_eq!(a1_a, a1_b, "split A_1 differs from all-in-one");
        assert_eq!(a2_a, a2_b, "split A_2 differs from all-in-one");
        assert_eq!(client_a.hints, client_b.hints, "hints diverge");
        assert_eq!(client_a.query_count, client_b.query_count);
    }

    #[test]
    fn test_split_pair_api_request_length() {
        // Each returned request is exactly T entries.
        let n = 64;
        let w = 32;
        let t = 8;
        let db = make_test_db(n, w);
        let server = Server::new(db);
        let params = Params::new(n, w, t).unwrap();
        let prp = Box::new(HoangPrp::new(2 * n, 44, &[0x12u8; 16]));
        let mut client = Client::offline(params, prp, &server).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(99);

        let (req_1, req_2, _pending) = client.build_pair_requests(3, 30, &mut rng).unwrap();
        assert_eq!(req_1.len(), t);
        assert_eq!(req_2.len(), t);
    }

    #[test]
    fn test_split_pair_api_rejects_wrong_response_length() {
        let n = 64;
        let w = 32;
        let t = 8;
        let db = make_test_db(n, w);
        let server = Server::new(db);
        let params = Params::new(n, w, t).unwrap();
        let prp = Box::new(HoangPrp::new(2 * n, 44, &[0x34u8; 16]));
        let mut client = Client::offline(params, prp, &server).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(7);

        let (_, _, pending) = client.build_pair_requests(0, 1, &mut rng).unwrap();
        // Wrong-length responses must error out, not silently corrupt state.
        let bad_resp: Vec<Vec<u8>> = vec![vec![0u8; w]; t - 1]; // T-1 instead of T
        let good_resp: Vec<Vec<u8>> = vec![vec![0u8; w]; t];
        let result = client.finish_pair(pending, &bad_resp, &good_resp);
        assert!(result.is_err());
    }

    #[test]
    fn test_query_pair_equiv_sequential_basic() {
        // 8 distinct pairs with various combinations.
        let pairs = vec![(0, 1), (5, 17), (3, 30), (60, 7)];
        assert_query_pair_equiv_sequential(
            64,
            32,
            8,
            || Box::new(HoangPrp::new(2 * 64, 44, &[0xAB; 16])),
            0xDEADBEEF,
            &pairs,
        );
    }

    #[test]
    fn test_query_pair_equiv_sequential_chained() {
        // Many pairs in sequence — exercises state evolution across pairs.
        let n = 128;
        let t = 16;
        // max_queries = 2n/t / 2 = n/t = 8. So 4 pairs max.
        let pairs: Vec<(usize, usize)> = (0..4).map(|i| (i, n - 1 - i)).collect();
        assert_query_pair_equiv_sequential(
            n,
            32,
            t,
            || Box::new(HoangPrp::new(2 * n, 44, &[0x33; 16])),
            0x1234_5678,
            &pairs,
        );
    }

    #[test]
    fn test_query_pair_same_index() {
        // q_1 == q_2: edge case — query_pair must still return DB[q] twice.
        let pairs = vec![(7, 7), (42, 42)];
        assert_query_pair_equiv_sequential(
            64,
            32,
            8,
            || Box::new(HoangPrp::new(2 * 64, 44, &[0xCD; 16])),
            0xCAFE_BABE,
            &pairs,
        );
    }

    #[test]
    fn test_query_pair_finds_same_segment_pair() {
        // Build a DS' with the test PRP, find a (q_1, q_2) pair that lands in
        // the same original segment, then verify query_pair handles it.
        let n = 64;
        let w = 32;
        let t = 8;
        let key = [0x77u8; 16];
        let r = 44;

        // Probe to find a same-segment pair.
        let probe_prp: Box<dyn crate::prp::Prp> = Box::new(HoangPrp::new(2 * n, r, &key));
        let probe_ds = RelocationDS::new(n, t, probe_prp).unwrap();
        let mut same_seg_pair: Option<(usize, usize)> = None;
        'outer: for q_1 in 0..n {
            let s_1 = probe_ds.locate(q_1).unwrap() / t;
            for q_2 in (q_1 + 1)..n {
                let s_2 = probe_ds.locate(q_2).unwrap() / t;
                if s_1 == s_2 {
                    same_seg_pair = Some((q_1, q_2));
                    break 'outer;
                }
            }
        }
        let pair = same_seg_pair.expect("expected at least one same-segment pair");

        assert_query_pair_equiv_sequential(
            n,
            w,
            t,
            || Box::new(HoangPrp::new(2 * n, r, &key)),
            0xABCD_EF00,
            &[pair],
        );
    }

    #[cfg(feature = "fastprp-prp")]
    #[test]
    fn test_query_pair_equiv_sequential_fastprp() {
        let pairs = vec![(0, 50), (200, 800), (1, 1023)];
        assert_query_pair_equiv_sequential(
            1024,
            32,
            32,
            || Box::new(FastPrpWrapper::new(&[0x55u8; 16], 2 * 1024)),
            0x4242_4242,
            &pairs,
        );
    }

    #[cfg(feature = "alf")]
    #[test]
    fn test_query_pair_equiv_sequential_alf() {
        let n = 32768;
        let pairs = vec![(0, 12345), (n - 1, 7), (1024, 5000)];
        assert_query_pair_equiv_sequential(
            n,
            32,
            128,
            || Box::new(AlfPrp::new(&[0xAA; 16], 2 * n, &[0u8; 16], 0)),
            0xF00D_F00D,
            &pairs,
        );
    }

    // --- Cross-PRP consistency test ---

    #[test]
    fn test_all_prps_produce_correct_queries() {
        // Same database, available PRPs should return correct results.
        let n = 512;
        let w = 32;
        let t = 16;
        let db = make_test_db(n, w);
        let server = Server::new(db.clone());

        let prps: Vec<(&str, Box<dyn crate::prp::Prp>)> = vec![
            ("Hoang", Box::new(HoangPrp::new(2 * n, 44, &[1u8; 16]))),
            #[cfg(feature = "fastprp-prp")]
            ("FastPRP", Box::new(FastPrpWrapper::new(&[2u8; 16], 2 * n))),
            // ALF skipped — domain 1024 < 65536 minimum.
        ];

        for (name, prp) in prps {
            let params = Params::new(n, w, t).unwrap();
            let mut client = Client::offline(params, prp, &server).unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(77);

            for q in [0, 1, n / 2, n - 1] {
                let result = client.query(q, &server, &mut rng).unwrap();
                assert_eq!(result, db[q], "{name}: query({q}) returned wrong entry");
            }
        }
    }
}
