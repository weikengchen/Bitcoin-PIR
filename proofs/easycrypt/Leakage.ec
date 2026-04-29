(* ---------------------------------------------------------------------- *
 * Leakage.ec — the leakage function L : query -> leakage.
 *
 * `L(q)` enumerates every axis the protocol *admits* to leak. The
 * security theorem in `Theorem.ec` says: any two queries q1, q2 with
 * L(q1) = L(q2) produce indistinguishable transcripts. So the more
 * `L` admits, the weaker the privacy claim — and any axis missing
 * from `L` becomes an unprovable lemma later (catching it at proof
 * time is the irreducible benefit of formal verification we couldn't
 * get from Kani / integration tests / cross-language diff alone).
 *
 * --------------------------------------------------------------------- *
 *  ADMITTED AXES
 * --------------------------------------------------------------------- *
 *
 * (Wire-shape axes the server is allowed to learn. Each of these
 * SHOULD eventually be closed via additional padding; current spec
 * admits them and documents the closure path inline.)
 *
 *   1. index_max_items_per_group_per_level : int
 *      Pre-closure: for a batched query of N script-hashes, each
 *      script-hash contributed INDEX_CUCKOO_NUM_HASHES (= 2) INDEX
 *      Merkle items whose `pbc_group` equalled
 *      `derive_groups_3(scripthash, K)[0]`. Two script-hashes that
 *      collided on the same assigned_group accumulated 4 items (vs.
 *      2 for the no-collision case); the wire revealed this via the
 *      per-Merkle-level *pass count*.
 *
 *      Post-closure (commits `606fddb` DPF, follow-up Harmony): the
 *      DPF and Harmony INDEX paths now route each scripthash to its
 *      `pbc_plan_rounds`-assigned group instead of always to `[0]`.
 *      Each scripthash's two INDEX Merkle items inherit a UNIQUE-per-
 *      batch `pbc_group`, so `max_items_per_group_per_level = 2`
 *      independently of the batch's collision pattern. OnionPIR was
 *      structurally trivial on this axis from the start (`pbc_plan_rounds`
 *      packs ≤4 unique Merkle gids into 1 round at batch=2 because
 *      ARITY=120 and `level_info.k=25` for the DPF/Harmony backends'
 *      ARITY=8 trees, OnionPIR's INDEX Merkle is differently
 *      parameterised — see below).
 *
 *      The axis is retained in the leakage record `L` for spec
 *      stability across DB and batch parameters; empirically every
 *      query with the same `n_pbc_rounds` produces the same value
 *      (= 2 for typical batches with `N ≤ K`). The simulator-property
 *      proof in `Theorem.ec` is unchanged: `L_eq` still implies
 *      transcript equality, and the field's constancy under the new
 *      placement scheme is what makes the existing collision-test
 *      witness (DPF A=B=C=12, Harmony A=B=C=6) byte-identical.
 *
 *      OnionPIR realises the same axis as `pbc_rounds.len()` per
 *      Merkle level, computed over unique gids
 *      `(group * bins + bin) / arity` re-routed via
 *      `derive_int_groups_3(gid, level_info.k)`. The wire-observable
 *      axis (count of `IndexMerkleSiblings` rounds per level) is
 *      identical across backends; the per-backend computation
 *      differs because XOR-PIR (DPF, Harmony) uses sequential
 *      sibling passes within a single PBC group, while batched-FHE
 *      (OnionPIR) uses one round per PBC slot of unique gids and a
 *      different ARITY (120 vs. 8). At batch=2 with typical
 *      `level_info.k = 25`, the OnionPIR axis is structurally
 *      trivial: at most 4 unique gids, so `pbc_plan_rounds` always
 *      packs into 1 round. After the DPF/Harmony closure the
 *      empirical witnesses agree across all three backends:
 *
 *        - `dpf_simulator_property_multi_query_collision` —
 *          `total rounds A=B=C=19, IndexMerkleSiblings A=B=C=12`
 *          (= 2 max × 2 servers × 3 levels).
 *        - `harmony_simulator_property_multi_query_collision` —
 *          `total rounds A=B=C=20, IndexMerkleSiblings A=B=C=6`
 *          (= 2 max × 1 server × 3 levels).
 *        - `onion_simulator_property_multi_query_collision` —
 *          `total rounds A=B=C=7, IndexMerkleSiblings A=B=C=1`
 *          (structural triviality).
 *
 *   2. chunk_max_items_per_group_per_level : int
 *      Number of CHUNK Merkle items concentrated in any single
 *      chunk-PBC group. For a found query producing M total chunk
 *      Merkle items the wire reveals the per-level pass count =
 *      max items in any single group, which depends on how the
 *      chunk-IDs distribute across chunk groups. Two queries with
 *      the same total M can have different transcripts if their
 *      chunk-IDs collide differently. (Strictly more precise than
 *      the previous `chunk_merkle_item_count : int` axis the spec
 *      first declared; updated to match what the wire actually
 *      reveals.)
 *      Closure path: pad chunk Merkle items to a fixed M per query
 *      and distribute across chunk-PBC groups uniformly. This is
 *      the most expensive padding to add — the marginal CHUNK PIR
 *      round count scales with M.
 *
 *   3. session_query_index : int
 *      Position of `q` within a session of queries from the same
 *      client connection. Mostly relevant to HarmonyPIR: the client
 *      issues a `HarmonyHintRefresh` round on the wire when its
 *      per-group `query_count` reaches `max_queries`, so the
 *      session-level timing of refresh rounds is observable. For
 *      DPF and OnionPIR this axis reduces to public session
 *      metadata (server already counts requests).
 *      Closure path: not closable in general — refresh timing is
 *      intrinsic to HarmonyPIR's protocol design. The argument is
 *      that this axis is a function of session length, which is
 *      already public, not of the queries' content.
 *
 *   4. query_db_id : db_id
 *      The database the query targets — wire-observable on every
 *      PIR round (RoundProfile.db_id_opt = Some). Trivially admitted:
 *      the user explicitly chose to query this database, so the
 *      server's awareness of it is by design, not a privacy
 *      violation. Included in `L` because the simulator must
 *      reproduce the transcript's `db_id_opt` field; without this
 *      axis the simulator-property statement is vacuous (any
 *      multi-DB session is distinguishable). Added during the
 *      proof-body fleshout phase (the absence was caught precisely
 *      by trying to write `Sim.query` and noticing it had no way to
 *      reproduce the per-round `db_id_opt`).
 *      Closure path: none required — this is intentional public
 *      protocol metadata, not a side channel.
 *
 * --------------------------------------------------------------------- *
 *  CLOSED AXES (must be obligations the proof discharges)
 * --------------------------------------------------------------------- *
 *
 *   - script-hash bytes (closed by ideal-primitive assumption)
 *   - found-vs-not-found at round-presence (closed by CHUNK Round-
 *     Presence Symmetry, 2026)
 *   - cuckoo position of a match (closed by Merkle INDEX Item-Count
 *     Symmetry, 2026 — INDEX Merkle items are always 2 per query)
 *   - which PBC group contains the real query (closed by K-padding;
 *     Kani-verified for INDEX in `build_index_alphas`)
 *   - HarmonyPIR per-group request shape (closed by T-1 padding,
 *     verified by integration test against Hetzner; out of Kani's
 *     reach due to the PRP/HashSet/RNG-rejection-sampling structure)
 *
 * --------------------------------------------------------------------- *
 *  EXPLICIT NON-CLAIMS (out of scope)
 * --------------------------------------------------------------------- *
 *
 *   (a) Timing channels.
 *       The transcript modelled here is wire-shape only. Wall-clock
 *       latency, packet inter-arrival, and CPU side channels are not
 *       part of `transcript`, so the security claim is timing-
 *       oblivious. An adversary who measures latency learns strictly
 *       more than `L`. Closure: separate timing analysis (e.g.
 *       constant-time crypto primitives, padding to fixed wall-
 *       clock duration). Out of scope here.
 *
 *   (b) OnionPIR server-side LRU eviction retries.
 *       `onionpir_batch_rpc` re-issues the request after the server
 *       LRU-evicts the client's keys (one `OnionKeyRegister` plus a
 *       repeat `Index` / `Chunk` round). Whether this happens
 *       depends on the server's eviction policy, not on `q` — so
 *       it is *server-controlled*, not query-controlled, and not a
 *       per-query leak. The proof models eviction-free runs; a
 *       full proof would either factor the retry path into a
 *       separate adversary-state lemma or assume server cache
 *       capacity ≥ session size.
 *
 *   (c) Connection-level metadata.
 *       TCP / TLS / WebSocket framing, IP, TLS handshake. By
 *       hypothesis the adversary observes only the binary message
 *       payloads (`transcript` above), not the network layer.
 *       Closure: separate network-traffic analysis; wrap in Tor /
 *       VPN / mixing-net for resistance.
 *
 *   (d) Compression artifacts.
 *       Per-message-deflate is OFF in the production WebSocket
 *       configuration; TLS compression is OFF. By hypothesis no
 *       size-side-channel from compression. Closure: keep
 *       compression off, asserted at the connection layer.
 * --------------------------------------------------------------------- *)

require import Common.
require import AllCore Int.

(* ---------- Leakage record ---------- *
 * The simulator gets exactly this; nothing else. Each field
 * corresponds to an admitted axis above; widening the record means
 * weakening the privacy claim. Closing an axis means narrowing
 * the record (and re-running `L_eq`-equivalence proofs).
 *)
type leakage = {
  index_max_items_per_group_per_level : int;
  chunk_max_items_per_group_per_level : int;
  session_query_index                 : int;
  query_db_id                         : db_id;
}.

(* The leakage function. Declared abstractly: the proof obligation
 * is "for any concrete L satisfying the constraints below, the
 * simulator argument holds". Wire-level invariants (K-padding,
 * INDEX_CUCKOO_NUM_HASHES, T-1, CHUNK round-presence) are encoded
 * as preconditions on the protocol's abstract behaviour, not on
 * `L` itself. `L` is just the projection of "what the wire reveals"
 * onto the admitted axes.
 *)
op L : query -> leakage.

(* ---------- Per-axis projection axioms ---------- *
 * The query has accessors that produce each leakage component
 * directly. `L_factors` says `L` projects through these accessors.
 * The Real protocol module reads via the accessors; the Sim module
 * reads via `L`. The simulator-property proof reduces to "per-axis
 * agreement" via these projections, so a future maintainer who adds
 * a Real-side branch on a query-property not covered by `L` will
 * find no axiom to reduce to and will be forced to either (a) add
 * the property as a new admitted axis, or (b) prove the branch is
 * unreachable.
 *
 * The query-side accessors `query_db_id`, `query_index_max`, etc.
 * are declared abstractly in Common.ec / here; their semantics are
 * pinned by L_factors.
 *)
op query_index_max : query -> int.
op query_chunk_max : query -> int.
op query_session_query_index : query -> int.

axiom L_factors :
  forall (q : query),
    L q = {| index_max_items_per_group_per_level = query_index_max q;
             chunk_max_items_per_group_per_level = query_chunk_max q;
             session_query_index                 = query_session_query_index q;
             query_db_id                         = query_db_id q;
          |}.

(* ---------- Range axioms ---------- *
 * All admitted-axis values are non-negative integers. Tighter
 * bounds are protocol-specific (e.g. index_max_items_per_group_per_level
 * <= 2 * batch_size) but we don't need them for the simulator
 * argument; loose non-negativity suffices.
 *)
axiom L_index_max_per_group_nonneg :
  forall (q : query),
    0 <= (L q).`index_max_items_per_group_per_level.

axiom L_chunk_max_per_group_nonneg :
  forall (q : query),
    0 <= (L q).`chunk_max_items_per_group_per_level.

axiom L_session_query_index_nonneg :
  forall (q : query),
    0 <= (L q).`session_query_index.

(* No range axiom on query_db_id — it is an abstract type with no
 * arithmetic structure. Equality is the only operation we need. *)

(* ---------- Equivalence relation on leakage ---------- *
 * Two queries are L-equivalent iff their leakage records are equal.
 * The simulator argument's quantification: forall q1 q2,
 * L_eq q1 q2 ==> Real(q1) ~= Real(q2).
 *)
op L_eq (q1 q2 : query) : bool =
  (L q1) = (L q2).

lemma L_eq_refl (q : query) : L_eq q q.
proof.
  by rewrite /L_eq.
qed.

lemma L_eq_sym (q1 q2 : query) : L_eq q1 q2 => L_eq q2 q1.
proof.
  by rewrite /L_eq => ->.
qed.

lemma L_eq_trans (q1 q2 q3 : query) :
  L_eq q1 q2 => L_eq q2 q3 => L_eq q1 q3.
proof.
  by rewrite /L_eq => -> ->.
qed.
