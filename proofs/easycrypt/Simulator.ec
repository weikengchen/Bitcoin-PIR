(* ---------------------------------------------------------------------- *
 * Simulator.ec — `Sim(L, $)`: a transcript generator that has access
 * only to `L q` and (by hypothesis) ideal-primitive uniform randomness,
 * NOT to `q` itself.
 *
 * The construction:
 *
 *   1. Read the admitted leakage record `L q` — that's the only
 *      query-dependent input. After this line, `q` is FORBIDDEN.
 *      Any subsequent read from `q` would invalidate the simulator-
 *      property argument.
 *   2. Compose the same per-section transcript fragments declared in
 *      `Protocol.ec`, but feed each fragment its needed inputs from
 *      `leak` (db_id, session_query_index, index_max, chunk_max)
 *      instead of from `q`.
 *
 * Because byte content is not modelled in this spec, no actual
 * sampling step is needed in `Sim`. The `transcript` value the
 * simulator returns is determined entirely by `(b, leak)`. The
 * cryptographic ideal-primitive assumptions live in the byte-level
 * protocol papers we cite in `Common.ec`'s preamble, not in this
 * spec.
 *
 * Simulator-property statement (Theorem.ec):
 *
 *   forall (b : backend) (q : query),
 *     Real.query(b, q) ≡  Sim.query(b, q)        (* same distribution *)
 *
 * Combined with `simulator_property_per_query` (also Theorem.ec) this
 * yields:
 *
 *   forall (b : backend) (q1 q2 : query), L_eq q1 q2 =>
 *     Real.query(b, q1) ≡ Real.query(b, q2)
 *
 * — i.e. transcript distribution depends on `q` only through `L q`.
 * --------------------------------------------------------------------- *)

require import Common Leakage Protocol.
require import AllCore List Distr Int.

(* ---------- Sim_op : the deterministic simulator transcript-builder ---------- *
 * This `op` reads ONLY from the leakage record (no `query` arg).
 * The `Sim.query` procedure below delegates to it after extracting
 * the leakage. Per the discipline above, the simulator's only
 * `q`-touching line is `L q` — everything downstream depends on
 * `b` and `leak` alone.
 *)
op sim_transcript (b : backend) (leak : leakage) : transcript =
     info_segment b
  ++ onion_key_register_segment b leak.`query_db_id
  ++ harmony_hint_refresh_segment b leak.`query_db_id leak.`session_query_index
  ++ index_segment b leak.`query_db_id
  ++ merkle_tree_tops_segment b leak.`query_db_id
  ++ index_merkle_segment b leak.`query_db_id leak.`index_max_items_per_group_per_level
  ++ chunk_segment b leak.`query_db_id
  ++ chunk_merkle_segment b leak.`query_db_id leak.`chunk_max_items_per_group_per_level.

module Sim : ProtocolRunner = {
  proc query(b : backend, q : query) : transcript = {
    return sim_transcript b (L q);
  }
}.

(* ---------- Sim_batch : multi-query batch simulator ---------- *
 * Mirrors `Real_batch` from Protocol.ec: the batch simulator is the
 * concatenation of per-query simulator outputs, where each query's
 * leakage is read once via `L q` and then the simulator composes the
 * per-section fragments from `leak`-fields only.
 *
 * Equational view:
 *
 *   sim_batch_transcript b leaks = flatten (map (sim_transcript b) leaks)
 *
 * The `Sim_batch.query_batch` procedure binds `leaks = map L qs` and
 * delegates to the op. The Real_batch ≡ Sim_batch theorem
 * (`simulator_property_multi_query_constructive` in Theorem.ec)
 * follows from the per-query `real_eq_sim_op` lifted over the list.
 *)
op sim_batch_transcript (b : backend) (leaks : leakage list) : transcript =
  flatten (map (sim_transcript b) leaks).

module Sim_batch : ProtocolBatchRunner = {
  proc query_batch(b : backend, qs : query list) : transcript = {
    return sim_batch_transcript b (map L qs);
  }
}.
