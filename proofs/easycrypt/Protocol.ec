(* ---------------------------------------------------------------------- *
 * Protocol.ec — the `Real` model: an abstract description of what
 * the BitcoinPIR client emits on the wire for a single query, in the
 * ideal-primitives world.
 *
 * Modelling choices:
 *
 *  - Cryptographic primitives (DPF.gen, FHE.encrypt, PRP.eval) are
 *    treated as black boxes. We model only the *wire shape* — round
 *    kind, server id, db id, byte counts, item counts. By hypothesis
 *    the byte content within each fixed-length envelope is uniform
 *    randomness, so transcript indistinguishability reduces to shape
 *    equality. This matches the user's stated preference ("I tend to
 *    avoid verifying actual cryptography but prefer to treat them as
 *    black boxes").
 *
 *  - Because byte content is not modelled, `Real.query` is a
 *    *deterministic* function of `(b, q)`. The simulator-property
 *    proof (Theorem.ec) reduces to functional equality, not pRHL —
 *    which makes proof closure much more tractable than full pRHL.
 *
 *  - The protocol is parameterised by a backend tag
 *    (BDpf / BHarmony / BOnion) because the round-sequence shape
 *    differs (DPF emits per-server x2; OnionPIR is single-server;
 *    Harmony has a hint-server side band). The body branches on
 *    `b` and reads from `q` only via the four query accessors
 *    declared in Common.ec / Leakage.ec; that disciplined access is
 *    what `simulator_property_per_query` turns into a proof.
 * --------------------------------------------------------------------- *)

require import Common Leakage.
require import AllCore List Distr Int.

(* ---------- Per-round-shape parameters ---------- *
 * Each `op` declares a wire-shape parameter as a deterministic function
 * of (backend, server, [level]). Concrete values are pinned by the
 * integration tests in pir-sdk-client/tests/leakage_integration_test.rs
 * — we treat them as axioms here.
 *)

(* Info round (catalog handshake). Single server (server_id = 0). *)
op info_request_bytes  : backend -> int.
op info_response_bytes : backend -> int.

(* OnionKeyRegister round (Onion only). Server-id 0; db_id-tagged. *)
op onion_key_register_request_bytes  : int.
op onion_key_register_response_bytes : int.

(* HarmonyHintRefresh round (Harmony only). Server-id 1 (hint server). *)
op harmony_hint_refresh_request_bytes  : int.
op harmony_hint_refresh_response_bytes : int.

(* Index round. Two servers for DPF, one for the others. *)
op index_request_bytes    : backend -> int -> int.   (* (b, server) *)
op index_response_bytes   : backend -> int -> int.
op index_items_per_group  : backend -> int.

axiom index_items_per_group_pos :
  forall (b : backend), 1 <= index_items_per_group b.

(* Chunk round. Same server-count semantics as Index. *)
op chunk_request_bytes   : backend -> int -> int.
op chunk_response_bytes  : backend -> int -> int.
op chunk_items_per_group : backend -> int.

(* MerkleTreeTops. Single fetch per query. *)
op merkle_tree_tops_request_bytes  : backend -> int.
op merkle_tree_tops_response_bytes : backend -> int.

(* Per-Merkle-level sibling pass. *)
op merkle_index_pass_request_bytes  : backend -> int -> int -> int.  (* (b, server, level) *)
op merkle_index_pass_response_bytes : backend -> int -> int -> int.
op merkle_chunk_pass_request_bytes  : backend -> int -> int -> int.
op merkle_chunk_pass_response_bytes : backend -> int -> int -> int.

(* Number of Merkle levels (depends on database depth — fixed per
 * backend × db; we model it as a function of backend only since the
 * concrete database depths are pinned in the runtime configuration). *)
op n_index_merkle_levels : backend -> int.
op n_chunk_merkle_levels : backend -> int.

axiom n_index_merkle_levels_nonneg : forall (b : backend), 0 <= n_index_merkle_levels b.
axiom n_chunk_merkle_levels_nonneg : forall (b : backend), 0 <= n_chunk_merkle_levels b.

(* Per-Merkle-level pass count = max items per group at that level
 * (admitted leakage axes). Uniform across levels in the current
 * implementation — see CLAUDE.md "Merkle INDEX Item-Count Symmetry". *)
op index_merkle_items_for_pass : backend -> int.   (* = INDEX_CUCKOO_NUM_HASHES = 2 *)
op chunk_merkle_items_for_pass : backend -> int.   (* per-level uniform; depends on UTXO layout *)

(* Per-server emission for round-types: DPF emits on both server 0 and
 * server 1; Onion and Harmony emit on a single server. The server set
 * is itself a function of backend, encoded as a list. *)
op pir_server_ids : backend -> int list.
axiom pir_server_ids_dpf     : pir_server_ids BDpf     = [0; 1].
axiom pir_server_ids_harmony : pir_server_ids BHarmony = [0].
axiom pir_server_ids_onion   : pir_server_ids BOnion   = [0].

(* Whether the HarmonyPIR hint-refresh round fires given the session
 * position. Modelled as an abstract op so the protocol-design choice
 * (e.g. "every Q queries") stays out of the simulator-property
 * statement; the only thing the simulator argument needs is that this
 * decision is a function of `query_session_query_index q`, not of any
 * other query property. *)
op harmony_refresh_due : int -> bool.

(* ---------- Round-profile constructors ---------- *
 * Convenience ops that build a `round_profile` value from its
 * shape parameters. Body code below uses these to keep the
 * round-by-round emission readable.
 *)
op build_payload_round
   (k : round_kind) (server : int) (db : db_id)
   (req resp : int) (items : int list) : round_profile =
  {| kind = k; server_id = server; db_id_opt = Some db;
     request_bytes = req; response_bytes = resp; items = items; |}.

op build_meta_round
   (k : round_kind) (server : int) (db_opt : db_id option)
   (req resp : int) : round_profile =
  {| kind = k; server_id = server; db_id_opt = db_opt;
     request_bytes = req; response_bytes = resp; items = []; |}.

(* ---------- Per-section transcript fragments ---------- *
 * Each helper builds the segment of the transcript for a specific
 * protocol section. Composing them in order yields the full per-query
 * transcript. The fragments do NOT take a `query` argument — they
 * take only the wire-shape inputs that vary per query (db_id and
 * the admitted leakage axes). This is the central discipline that
 * makes `Real ≡ Sim` provable: each fragment of the transcript is a
 * function of `(b, db_id, leak)` only, never of `q` directly.
 *)

(* Info round: deterministic, no query content. *)
op info_segment (b : backend) : transcript =
  [build_meta_round RInfo 0 None (info_request_bytes b) (info_response_bytes b)].

(* OnionKeyRegister: only Onion, once per session × db. We model the
 * always-fires case (no-prior-state). *)
op onion_key_register_segment (b : backend) (db : db_id) : transcript =
  if b = BOnion
  then [build_payload_round ROnionKeyRegister 0 db
          onion_key_register_request_bytes
          onion_key_register_response_bytes
          []]
  else [].

(* HarmonyHintRefresh: only Harmony, gated on session position. *)
op harmony_hint_refresh_segment (b : backend) (db : db_id) (sess_idx : int) : transcript =
  if b = BHarmony /\ harmony_refresh_due sess_idx
  then [build_payload_round RHarmonyHintRefresh 1 db
          harmony_hint_refresh_request_bytes
          harmony_hint_refresh_response_bytes
          []]
  else [].

(* Index round per server. Items vector: K-padded, uniform. *)
op index_round_one (b : backend) (s : int) (db : db_id) : round_profile =
  build_payload_round RIndex s db
    (index_request_bytes b s)
    (index_response_bytes b s)
    (mkseq (fun _ => index_items_per_group b) K).

op index_segment (b : backend) (db : db_id) : transcript =
  map (fun s => index_round_one b s db) (pir_server_ids b).

(* Chunk round per server. Items vector: K_CHUNK-padded, uniform.
 * CHUNK Round-Presence Symmetry guarantees at least one such round
 * per query regardless of found/not-found/whale. *)
op chunk_round_one (b : backend) (s : int) (db : db_id) : round_profile =
  build_payload_round RChunk s db
    (chunk_request_bytes b s)
    (chunk_response_bytes b s)
    (mkseq (fun _ => chunk_items_per_group b) K_chunk).

op chunk_segment (b : backend) (db : db_id) : transcript =
  map (fun s => chunk_round_one b s db) (pir_server_ids b).

(* MerkleTreeTops: one round per query, single server. *)
op merkle_tree_tops_segment (b : backend) (db : db_id) : transcript =
  [build_payload_round RMerkleTreeTops 0 db
     (merkle_tree_tops_request_bytes b)
     (merkle_tree_tops_response_bytes b)
     []].

(* Per-Merkle-level pass for the INDEX tree, per server.
 * For a given level L: emit `index_max` passes per server.
 * Items list per pass = mkseq (... index_merkle_items_for_pass b) batch_size;
 * batch_size is 1 in the per-query model (single-query scope). *)
op index_merkle_pass_one (b : backend) (s : int) (db : db_id) (level : int) : round_profile =
  build_payload_round (RIndexMerkleSiblings level) s db
    (merkle_index_pass_request_bytes b s level)
    (merkle_index_pass_response_bytes b s level)
    [index_merkle_items_for_pass b].

(* For one level: index_max passes × len(pir_server_ids). *)
op index_merkle_passes_for_level
   (b : backend) (db : db_id) (level : int) (index_max : int) : transcript =
  flatten (mkseq (fun _ =>
    map (fun s => index_merkle_pass_one b s db level) (pir_server_ids b)
  ) index_max).

(* For all levels: concatenate per-level. *)
op index_merkle_segment (b : backend) (db : db_id) (index_max : int) : transcript =
  flatten (mkseq (fun (l : int) =>
    index_merkle_passes_for_level b db l index_max
  ) (n_index_merkle_levels b)).

(* CHUNK Merkle: same shape, with chunk-specific parameters. *)
op chunk_merkle_pass_one (b : backend) (s : int) (db : db_id) (level : int) : round_profile =
  build_payload_round (RChunkMerkleSiblings level) s db
    (merkle_chunk_pass_request_bytes b s level)
    (merkle_chunk_pass_response_bytes b s level)
    [chunk_merkle_items_for_pass b].

op chunk_merkle_passes_for_level
   (b : backend) (db : db_id) (level : int) (chunk_max : int) : transcript =
  flatten (mkseq (fun _ =>
    map (fun s => chunk_merkle_pass_one b s db level) (pir_server_ids b)
  ) chunk_max).

op chunk_merkle_segment (b : backend) (db : db_id) (chunk_max : int) : transcript =
  flatten (mkseq (fun (l : int) =>
    chunk_merkle_passes_for_level b db l chunk_max
  ) (n_chunk_merkle_levels b)).

(* ---------- The Real protocol module ---------- *
 * `Real(b).query(q)` runs a full PIR query and returns the
 * server-observable transcript. The body is a deterministic
 * concatenation of the per-section helpers above, each of which
 * reads from `q` only via the four declared accessors:
 *   query_db_id, query_index_max, query_chunk_max, query_session_query_index.
 *
 * Whenever you add a Real-side branch on some other query property,
 * you MUST first add the property as an accessor (Common.ec) and to
 * the leakage record (Leakage.ec); otherwise `Sim.query` (which only
 * sees `L q`) cannot reproduce the resulting transcript and the
 * simulator-property proof will fail to close.
 *)
module type ProtocolRunner = {
  proc query(b : backend, q : query) : transcript
}.

(* ---------- Real_op : the deterministic transcript-builder ---------- *
 * This `op` IS the meaningful definition. The `Real.query` procedure
 * below delegates to it. Keeping the protocol body in `op` form
 * (rather than in `proc`) makes the simulator-property proof a
 * one-line equational fact instead of a pRHL exercise.
 *)
op real_transcript (b : backend) (q : query) : transcript =
     info_segment b
  ++ onion_key_register_segment b (query_db_id q)
  ++ harmony_hint_refresh_segment b (query_db_id q) (query_session_query_index q)
  ++ index_segment b (query_db_id q)
  ++ merkle_tree_tops_segment b (query_db_id q)
  ++ index_merkle_segment b (query_db_id q) (query_index_max q)
  ++ chunk_segment b (query_db_id q)
  ++ chunk_merkle_segment b (query_db_id q) (query_chunk_max q).

module Real : ProtocolRunner = {
  proc query(b : backend, q : query) : transcript = {
    return real_transcript b q;
  }
}.

(* ---------- Real_batch : multi-query batch transcript ---------- *
 * `Real_batch(b).query_batch(qs)` runs a sequence of PIR queries and
 * concatenates their per-query transcripts. The op-form
 * `real_batch_transcript` is the meaningful definition; the procedure
 * delegates so the multi-query simulator-property reduces to a
 * functional equality on lists, just like the per-query case did via
 * `real_transcript`.
 *
 * # Modelling notes
 *
 * - The batch transcript is `flatten (map (real_transcript b) qs)`.
 *   This composes with the per-query proof: equality at every position
 *   lifts to equality of the maps, then `flatten` preserves equality.
 *
 * - HarmonyPIR's hint-state evolution across queries is captured
 *   per-query via `query_session_query_index q` — that axis is admitted
 *   in `Leakage.ec` and propagates through the per-query
 *   `harmony_hint_refresh_segment`. As long as L_eq holds pairwise
 *   between the two batches, the hint-refresh decisions agree
 *   per-position, so the batch transcripts agree.
 *
 * - For DPF / OnionPIR the per-query independence assumption (fresh
 *   DPF / FHE keys per query, no cross-query state) is what makes the
 *   `flatten (map ...)` decomposition sound. That assumption is part
 *   of the cryptographic black-box hypothesis the spec already relies
 *   on for the per-query case.
 *)
op real_batch_transcript (b : backend) (qs : query list) : transcript =
  flatten (map (real_transcript b) qs).

module type ProtocolBatchRunner = {
  proc query_batch(b : backend, qs : query list) : transcript
}.

module Real_batch : ProtocolBatchRunner = {
  proc query_batch(b : backend, qs : query list) : transcript = {
    return real_batch_transcript b qs;
  }
}.
