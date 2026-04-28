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
 *      For a batched query of N script-hashes, each script-hash
 *      contributes INDEX_CUCKOO_NUM_HASHES (= 2) INDEX Merkle items
 *      whose `pbc_group` equals `derive_groups_3(scripthash, K)[0]`.
 *      If two script-hashes in the batch collide on the same
 *      assigned_group, that group accumulates 4 items (vs. 2 for
 *      the no-collision case); the wire reveals this via the per-
 *      Merkle-level *pass count* (= max_items_per_group). For
 *      single-query batches (the only case the integration tests
 *      currently exercise) this value is always 2 and the leak is
 *      vacuous; for multi-query batches it reveals the assigned-
 *      group collision pattern, which is a function of the script-
 *      hashes themselves.
 *      Closure path: pad INDEX Merkle items to a fixed M per query
 *      and distribute into PBC groups uniformly (analogous to the
 *      pending fix for chunk Merkle below).
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

(* ---------- Equivalence relation on leakage ---------- *
 * Two queries are L-equivalent iff their leakage records are equal.
 * The simulator argument's quantification: forall q1 q2,
 * L_eq q1 q2 ==> Real(q1) ~= Real(q2).
 *)
op L_eq (q1 q2 : query) : bool =
  (L q1) = (L q2).

lemma L_eq_refl (q : query) : L_eq q q
proof.
  by rewrite /L_eq.
qed.

lemma L_eq_sym (q1 q2 : query) : L_eq q1 q2 => L_eq q2 q1
proof.
  by rewrite /L_eq.
qed.

lemma L_eq_trans (q1 q2 q3 : query) :
  L_eq q1 q2 => L_eq q2 q3 => L_eq q1 q3
proof.
  by rewrite /L_eq => -> ->.
qed.
