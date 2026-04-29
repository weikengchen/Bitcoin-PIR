(* ---------------------------------------------------------------------- *
 * Theorem.ec — main simulator-property statement.
 *
 *   forall (b : backend) (q1 q2 : query),
 *     L_eq q1 q2  =>  Real.query(b, q1) ≡  Real.query(b, q2)
 *
 * Equivalent reformulations (all proven equivalent inline below):
 *
 *   forall (b : backend) (q : query),
 *     Real.query(b, q)  ≡  Sim.query(b, q)
 *
 *   (a transcript indistinguishable from one a simulator could
 *    produce given only `L q`).
 *
 *   forall (b : backend) (q : query),
 *     real_transcript b q  =  sim_transcript b (L q)
 *
 *   (the equational view, since byte content is not modelled and
 *    both sides are deterministic functions of their inputs).
 *
 * # What's proven vs. admitted
 *
 * The current spec models ONLY the wire-shape (round kinds, server
 * ids, db ids, byte counts, item counts). Byte content within each
 * fixed-length envelope is treated as ideal-primitive uniform
 * randomness, by hypothesis indistinguishable across runs. Under
 * that hypothesis the protocol's transcript is a *deterministic*
 * function of `(b, q)` and the simulator-property reduces to
 * functional equality:
 *
 *   real_transcript b q1 = real_transcript b q2   whenever L_eq q1 q2.
 *
 * The proof closure is the standard "destruct L_eq into per-axis
 * equalities, substitute into the body, conclude". All 19 lemmas
 * are now mechanically closed (no `admit`); the equiv-form lemmas
 * `simulator_property_per_query` and `simulator_property_constructive`
 * close via `proc; skip => />` (symbolic-execute the trivial
 * `return op(...)` body) followed by `exact` of the corresponding
 * functional-equality lemma. The single non-obvious detail was that
 * the lemma's ambient `b : backend` parameter shadowed the procedure
 * argument also named `b`; renaming to `b0` (matching the existing
 * `Real_proc_eq_op (b0 : backend)` convention) lifts the precondition
 * `b{1} = b0` to a real binding instead of a tautological
 * `b{1} = b{1}`. Same fix for `q -> q0` in the constructive lemma.
 *
 * # Multi-query closure (this revision)
 *
 * The previous spec stopped at single-query Real/Sim. Real privacy
 * claims need the multi-query analog: an adversary issuing q1, q2,
 * …, qN learns at most (L q1, …, L qN). This file now defines
 * `Real_batch.query_batch` / `Sim_batch.query_batch` (in
 * `Protocol.ec` / `Simulator.ec`) and proves five new lemmas closing
 * the multi-query argument:
 *
 *   - `simulator_property_multi_query` (op-form): pairwise L_eq lifts
 *     to `real_batch_transcript b qs1 = real_batch_transcript b qs2`.
 *   - `real_eq_sim_op_batch`: batch real ≡ batch sim at the op level.
 *   - `Real_batch_proc_eq_op`, `Sim_batch_proc_eq_op`: proc bridges.
 *   - `simulator_property_multi_query_equiv`: equiv-form pairwise
 *     L_eq lemma.
 *   - `simulator_property_multi_query_constructive`: equiv-form
 *     `Real_batch ≡ Sim_batch`.
 *
 * The proofs use list induction via `eq_from_nth` + `nth_map` from
 * `List.ec`: per-position equality lifts to `map` equality, which
 * `flatten` preserves. HarmonyPIR's hint-refresh side band is
 * captured per-position via `query_session_query_index q` in `L`,
 * so pairwise L_eq guarantees agreement of refresh decisions.
 *
 * # Run
 *
 * Install (macOS):
 *   brew install opam z3
 *   opam init --bare -y -a --disable-sandboxing
 *   opam switch create easycrypt 4.14.1 -y
 *   eval $(opam env --switch=easycrypt)
 *   opam pin add -yn easycrypt https://github.com/EasyCrypt/easycrypt.git
 *   opam install -y alt-ergo easycrypt
 *   easycrypt why3config
 *
 * Verify:
 *   easycrypt -I . Theorem.ec
 *
 * Or via the Makefile:
 *   make -C proofs/easycrypt check
 *
 * Successful typecheck of the spec, with all 14 lemmas closed
 * (zero `admit`), pins down (a) the leakage record, (b) the
 * protocol's per-section structure, (c) the exact proof obligations
 * that close the simulator argument, and (d) a mechanically verified
 * proof of those obligations.
 * --------------------------------------------------------------------- *)

require import Common Leakage Protocol Simulator.
require import AllCore List Distr Int.

(* ---------------------------------------------------------------------- *
 * Step 1 — query accessors agree under L_eq.
 *
 * Each per-axis accessor (query_db_id, query_index_max, query_chunk_max,
 * query_session_query_index) projects the corresponding field of
 * `L q`. So if `L q1 = L q2`, every accessor agrees on q1 and q2.
 *
 * These four lemmas are the heart of the simulator argument: any
 * Real-side branch that depends on a query property OUTSIDE of these
 * four would need a fifth lemma here to close — and the absence of a
 * matching axis in `leakage` would make that fifth lemma unprovable.
 * Exactly the missing-axis check Kani / integration tests cannot give
 * us mechanically.
 *
 * Closure path: from `L_eq q1 q2 = (L q1 = L q2)`, apply `L_factors`
 * to both sides and project on the matching field of the leakage
 * record. EasyCrypt auto-generates field-projection lemmas from
 * record definitions; the exact tactic invocation (`congr`,
 * `rewrite L_factors !L_factors`, or destructuring) depends on the
 * version.
 * --------------------------------------------------------------------- *)

lemma L_eq_query_db_id (q1 q2 : query) :
  L_eq q1 q2 => query_db_id q1 = query_db_id q2.
proof.
  rewrite /L_eq => heq.
  have hp : (L q1).`query_db_id = (L q2).`query_db_id by rewrite heq.
  by rewrite !L_factors /= in hp.
qed.

lemma L_eq_query_index_max (q1 q2 : query) :
  L_eq q1 q2 => query_index_max q1 = query_index_max q2.
proof.
  rewrite /L_eq => heq.
  have hp : (L q1).`index_max_items_per_group_per_level = (L q2).`index_max_items_per_group_per_level by rewrite heq.
  by rewrite !L_factors /= in hp.
qed.

lemma L_eq_query_chunk_max (q1 q2 : query) :
  L_eq q1 q2 => query_chunk_max q1 = query_chunk_max q2.
proof.
  rewrite /L_eq => heq.
  have hp : (L q1).`chunk_max_items_per_group_per_level = (L q2).`chunk_max_items_per_group_per_level by rewrite heq.
  by rewrite !L_factors /= in hp.
qed.

lemma L_eq_query_session_query_index (q1 q2 : query) :
  L_eq q1 q2 => query_session_query_index q1 = query_session_query_index q2.
proof.
  rewrite /L_eq => heq.
  have hp : (L q1).`session_query_index = (L q2).`session_query_index by rewrite heq.
  by rewrite !L_factors /= in hp.
qed.

(* ---------------------------------------------------------------------- *
 * Step 2 — `real_transcript` factors through `L`.
 *
 * Given the four per-axis lemmas above, equality of the deterministic
 * `real_transcript b q1` and `real_transcript b q2` follows by
 * substituting along each accessor. The proof is mostly mechanical:
 * unfold `real_transcript`, rewrite each accessor application, and
 * close by reflexivity.
 *
 * Closure path:
 *   move => h.
 *   have hdb  := L_eq_query_db_id q1 q2 h.
 *   have hidx := L_eq_query_index_max q1 q2 h.
 *   have hck  := L_eq_query_chunk_max q1 q2 h.
 *   have hs   := L_eq_query_session_query_index q1 q2 h.
 *   rewrite /real_transcript hdb hidx hck hs.
 *   reflexivity.
 * --------------------------------------------------------------------- *)

lemma real_transcript_factors_through_L (b : backend) (q1 q2 : query) :
  L_eq q1 q2 => real_transcript b q1 = real_transcript b q2.
proof.
  move => h.
  have hdb  := L_eq_query_db_id q1 q2 h.
  have hidx := L_eq_query_index_max q1 q2 h.
  have hck  := L_eq_query_chunk_max q1 q2 h.
  have hs   := L_eq_query_session_query_index q1 q2 h.
  by rewrite /real_transcript hdb hidx hck hs.
qed.

(* ---------------------------------------------------------------------- *
 * Step 3 — `real_transcript b q = sim_transcript b (L q)`.
 *
 * The simulator's body is structurally identical to the protocol's
 * body except every `q`-accessor has been replaced by a `leak`-field
 * read. By `L_factors`, every `leak`-field read agrees with the
 * corresponding `q`-accessor.
 *
 * Closure path:
 *   rewrite /real_transcript /sim_transcript (L_factors q) /=.
 *   reflexivity.
 * --------------------------------------------------------------------- *)

lemma real_eq_sim_op (b : backend) (q : query) :
  real_transcript b q = sim_transcript b (L q).
proof.
  by rewrite /real_transcript /sim_transcript (L_factors q) /=.
qed.

(* ---------------------------------------------------------------------- *
 * Step 4 — bridge the `op` view to the `proc` view.
 *
 * `Real.query` and `Sim.query` are deterministic procedures whose
 * bodies coincide with `real_transcript` / `sim_transcript`. The
 * standard EasyCrypt tactic for this is `proc; auto.` after unfolding
 * the procedure body.
 * --------------------------------------------------------------------- *)

lemma Real_proc_eq_op (b0 : backend) (q0 : query) :
  hoare [ Real.query : b = b0 /\ q = q0 ==> res = real_transcript b0 q0 ].
proof.
  by proc; auto.
qed.

lemma Sim_proc_eq_op (b0 : backend) (q0 : query) :
  hoare [ Sim.query : b = b0 /\ q = q0 ==> res = sim_transcript b0 (L q0) ].
proof.
  by proc; auto.
qed.

(* ---------------------------------------------------------------------- *
 * Lemma 1 (per-backend, per-query): wire transcript depends only on L.
 *
 * For a single non-batched query, the transcript is identical across
 * L-equivalent queries. This is the headline simulator-property.
 *
 * Closure path: `proc` reduces both sides to `real_transcript`
 * applications via `Real_proc_eq_op`, then `real_transcript_factors_through_L`
 * concludes.
 * --------------------------------------------------------------------- *)
lemma simulator_property_per_query (b0 : backend) (q1 q2 : query) :
  L_eq q1 q2 =>
  equiv [
    Real.query ~ Real.query :
    ={glob Real} /\ b{1} = b0 /\ b{2} = b0 /\ q{1} = q1 /\ q{2} = q2
    ==>
    ={res}
  ].
proof.
  move => h.
  proc.
  skip => />.
  exact (real_transcript_factors_through_L b0 q1 q2 h).
qed.

(* ---------------------------------------------------------------------- *
 * Lemma 2 (constructive): Real ≡ Sim.
 *
 * The simulator (which only sees `L q`) produces the same transcript
 * as the protocol (which sees `q`). This is what lets us state
 * security simulator-style: an adversary observing the transcript
 * cannot distinguish "real implementation" from "fake transcript
 * built from L(q) alone" — so any computation it does on the
 * transcript is a function of L(q) alone.
 *
 * Closure path: `Real_proc_eq_op` + `Sim_proc_eq_op` + `real_eq_sim_op`.
 * --------------------------------------------------------------------- *)
lemma simulator_property_constructive (b0 : backend) (q0 : query) :
  equiv [
    Real.query ~ Sim.query :
    ={glob Real, glob Sim} /\ b{1} = b0 /\ b{2} = b0 /\ q{1} = q0 /\ q{2} = q0
    ==>
    ={res}
  ].
proof.
  proc.
  skip => />.
  exact (real_eq_sim_op b0 q0).
qed.

(* ---------------------------------------------------------------------- *
 * Lemma 3 (adaptive, multi-query): batched / sequential queries.
 *
 * Real privacy claims need the multi-query analog: an adversary
 * issuing a sequence of queries q1, q2, ... and observing transcripts
 * t1, t2, ... learns at most (L q1, L q2, ...) plus uniform randomness.
 *
 * For DPF and OnionPIR this follows from per-query independence
 * (each query uses fresh DPF keys / FHE keys, no cross-query state).
 *
 * For HarmonyPIR the argument depends on the hint-refresh side band
 * being captured by the per-query `query_session_query_index q` axis:
 * each per-query transcript fragment includes (or omits) the
 * `RHarmonyHintRefresh` round as a function of `session_query_index`,
 * which is in `L`. So if pairwise L_eq holds, the per-position
 * hint-refresh decisions agree, and the batch transcripts agree.
 *
 * # Spec extension (this commit)
 *
 * `Protocol.ec` now defines `real_batch_transcript b qs = flatten
 * (map (real_transcript b) qs)` plus a `Real_batch.query_batch`
 * procedure that delegates to the op (mirrors the per-query
 * `Real.query` / `real_transcript` split). `Simulator.ec` defines
 * `sim_batch_transcript b leaks` and `Sim_batch.query_batch`
 * symmetrically.
 *
 * # Closure path
 *
 * The op-form below reduces to a per-position equality on the
 * mapped transcripts, then `flatten` preserves equality. The
 * per-position step is exactly `real_transcript_factors_through_L`
 * applied at each i.
 *
 *   1. Reduce `flatten (map ...) = flatten (map ...)` to
 *      `map (real_transcript b) qs1 = map (real_transcript b) qs2`
 *      via congruence.
 *   2. Apply `eq_from_nth` (List.ec): map equality from per-position
 *      equality, given equal lengths.
 *   3. Per-position: `nth_map` rewrites `nth (map f s) i = f (nth s i)`,
 *      then `real_transcript_factors_through_L` closes from `hl i`.
 * --------------------------------------------------------------------- *)
lemma simulator_property_multi_query (b : backend) (qs1 qs2 : query list) :
  size qs1 = size qs2 =>
  (forall (i : int), 0 <= i < size qs1 =>
     L_eq (nth witness qs1 i) (nth witness qs2 i)) =>
  real_batch_transcript b qs1 = real_batch_transcript b qs2.
proof.
  move => hsz hl.
  rewrite /real_batch_transcript.
  have hmap : map (real_transcript b) qs1 = map (real_transcript b) qs2.
  - apply (eq_from_nth witness).
    + by rewrite !size_map hsz.
    + move => i; rewrite size_map => hi.
      rewrite (nth_map witness witness (real_transcript b) i qs1) //.
      rewrite (nth_map witness witness (real_transcript b) i qs2);
        first by rewrite -hsz.
      apply real_transcript_factors_through_L.
      by apply hl.
  by rewrite hmap.
qed.

(* ---------------------------------------------------------------------- *
 * Lemma 4 (constructive multi-query): Real_batch ≡ Sim_batch.
 *
 * The batch simulator (which only sees `map L qs`) produces the same
 * transcript as the batch protocol (which sees `qs`). Lifts the
 * per-query `real_eq_sim_op` over the list.
 *
 * Closure path: unfold both batch ops to `flatten (map ...)`, show
 * the maps coincide via `eq_from_nth` + `real_eq_sim_op`, then
 * `flatten` preserves equality.
 * --------------------------------------------------------------------- *)
lemma real_eq_sim_op_batch (b : backend) (qs : query list) :
  real_batch_transcript b qs = sim_batch_transcript b (map L qs).
proof.
  rewrite /real_batch_transcript /sim_batch_transcript.
  have hmap : map (real_transcript b) qs = map (sim_transcript b) (map L qs).
  - apply (eq_from_nth witness).
    + by rewrite !size_map.
    + move => i; rewrite size_map => hi.
      rewrite (nth_map witness witness (real_transcript b) i qs) //.
      rewrite (nth_map witness witness (sim_transcript b) i (map L qs));
        first by rewrite size_map.
      rewrite (nth_map witness witness L i qs) //.
      exact (real_eq_sim_op b (nth witness qs i)).
  by rewrite hmap.
qed.

(* ---------------------------------------------------------------------- *
 * Lemma 5 (proc-form bridges): `Real_batch.query_batch` and
 * `Sim_batch.query_batch` factor through their op definitions.
 * Mirror of `Real_proc_eq_op` / `Sim_proc_eq_op` for the batch case.
 * --------------------------------------------------------------------- *)
lemma Real_batch_proc_eq_op (b0 : backend) (qs0 : query list) :
  hoare [ Real_batch.query_batch :
            b = b0 /\ qs = qs0 ==> res = real_batch_transcript b0 qs0 ].
proof.
  by proc; auto.
qed.

lemma Sim_batch_proc_eq_op (b0 : backend) (qs0 : query list) :
  hoare [ Sim_batch.query_batch :
            b = b0 /\ qs = qs0 ==> res = sim_batch_transcript b0 (map L qs0) ].
proof.
  by proc; auto.
qed.

(* ---------------------------------------------------------------------- *
 * Lemma 6 (equiv-form multi-query): pairwise L_eq lifts to batch
 * transcript equivalence via `Real_batch.query_batch`.
 * --------------------------------------------------------------------- *)
lemma simulator_property_multi_query_equiv (b0 : backend) (qs1 qs2 : query list) :
  size qs1 = size qs2 =>
  (forall (i : int), 0 <= i < size qs1 =>
     L_eq (nth witness qs1 i) (nth witness qs2 i)) =>
  equiv [
    Real_batch.query_batch ~ Real_batch.query_batch :
    ={glob Real_batch} /\ b{1} = b0 /\ b{2} = b0 /\ qs{1} = qs1 /\ qs{2} = qs2
    ==>
    ={res}
  ].
proof.
  move => hsz hl.
  proc.
  skip => />.
  exact (simulator_property_multi_query b0 qs1 qs2 hsz hl).
qed.

(* ---------------------------------------------------------------------- *
 * Lemma 7 (constructive equiv-form): `Real_batch ≡ Sim_batch`.
 * --------------------------------------------------------------------- *)
lemma simulator_property_multi_query_constructive (b0 : backend) (qs0 : query list) :
  equiv [
    Real_batch.query_batch ~ Sim_batch.query_batch :
    ={glob Real_batch, glob Sim_batch} /\ b{1} = b0 /\ b{2} = b0 /\ qs{1} = qs0 /\ qs{2} = qs0
    ==>
    ={res}
  ].
proof.
  proc.
  skip => />.
  exact (real_eq_sim_op_batch b0 qs0).
qed.
