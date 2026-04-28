(* ---------------------------------------------------------------------- *
 * Simulator.ec — `Sim(L, $)`: a transcript generator that has access
 * only to L(q) and uniform randomness, NOT to q itself.
 *
 * The construction:
 *
 *   1. Read the admitted leakage record `L(q)` — that's the only
 *      query-dependent input.
 *   2. Sample fresh uniform bytes for every cryptographic envelope
 *      (DPF keys, FHE ciphertexts, PRP outputs). These are the same
 *      distributions the ideal primitives would produce.
 *   3. Emit a transcript whose round-sequence shape is deterministic
 *      per backend (matches `Real(b).query` step-for-step) and whose
 *      payload bytes are the fresh uniform samples from (2).
 *
 * The simulator-property theorem (Theorem.ec) shows
 *   Real(b).query(q) ≡  Sim(b, L q)
 * as distributions, in the ideal-primitives world. So a server-side
 * adversary observing the transcript can compute at most L(q) — any
 * additional information would distinguish Real from Sim.
 *
 * Crucially, the simulator does NOT receive q. If we accidentally
 * encoded a query-dependent axis in the transcript that L doesn't
 * admit, the simulator can't reproduce it from L(q) alone — the
 * `equiv` lemma fails and we know the protocol leaks more than the
 * spec admits. This is the *completeness* check no other tool gives
 * us.
 * --------------------------------------------------------------------- *)

require import Common Leakage Protocol.
require import AllCore List Distr Int.

module Sim : ProtocolRunner = {
  proc query(b : backend, q : query) : transcript = {
    var t : transcript;
    var leak : leakage;
    (* The simulator extracts the leakage record. The proof obligation
     * is that everything that follows is a function of `leak` and
     * uniform randomness — the simulator must NEVER re-read `q`. *)
    leak <- L q;
    (* TODO: emit the same round-sequence shape as Real(b).query(q),
     * with payload bytes drawn fresh from `dunifin` (the uniform
     * distribution over byte-strings of the appropriate length).
     *
     * Per the modelling discussion in Protocol.ec:
     *
     *   - Info / OnionKeyRegister: deterministic shape, fixed bytes
     *     (catalog content is public).
     *
     *   - Index: K groups × index_items_per_group, each item is a
     *     fresh uniform key. Number of Index rounds is fixed per
     *     backend (DPF: 2 — one per server; OnionPIR: 1; Harmony: 1)
     *     and is independent of any axis in `leak`.
     *
     *   - Chunk: K_chunk groups, fresh uniform per slot. By the
     *     CHUNK Round-Presence Symmetry invariant, every query
     *     emits at least one Chunk round regardless of found vs
     *     not-found — round count is fixed, not a function of
     *     leak. Bytes are uniform.
     *
     *   - MerkleTreeTops: deterministic, public bytes.
     *
     *   - IndexMerkleSiblings × per-level passes:
     *     Pass count per Merkle level = leak.index_max_items_per_group_per_level.
     *     For single-query batches this is the constant 2 (the two
     *     INDEX cuckoo positions both fall in `assigned_group`); for
     *     multi-query batches the simulator reads it from `leak`.
     *     Each pass emits K (or K_merkle for OnionPIR) queries with
     *     fresh uniform bytes.
     *
     *   - ChunkMerkleSiblings × per-level passes:
     *     Pass count per Merkle level = leak.chunk_max_items_per_group_per_level.
     *     Determined by the admitted CHUNK-Merkle distribution axis;
     *     simulator reads it from `leak`. Each pass emits K_chunk
     *     queries with fresh uniform bytes.
     *
     *   - HarmonyHintRefresh: appears only when
     *     leak.session_query_index hits a HarmonyPIR-specific
     *     `max_queries` boundary. For DPF and OnionPIR this round
     *     never fires; for Harmony it is gated on the session-level
     *     position. Simulator reads `leak.session_query_index` to
     *     decide whether to emit.
     *
     * Key invariant: the simulator NEVER reads `q` after the
     * `leak <- L q` line. Any function of the transcript-shape
     * that the body computes must be expressible from `leak` and
     * fresh randomness alone. If a future maintainer re-introduces
     * a `q`-dependent branch here that is not visible in `leak`,
     * `simulator_property_constructive` (Theorem.ec) becomes
     * unprovable — that's the proof's purpose. *)
    t <- empty_transcript;
    return t;
  }
}.
