# BitcoinPIR EasyCrypt — Simulator-Property Spec

This directory contains the EasyCrypt formal-verification scaffolding
for the BitcoinPIR leakage argument. The deliverable is a **spec** —
a precise, mechanically-checked statement of what the protocol leaks
and what it does not. The proofs are partly closed and partly stubbed
with `admit`, in the structure described below.

The primary value is **catching missing leakage axes**: if a maintainer
adds a query-dependent branch to the protocol that is not covered by
the leakage record, the proof of `simulator_property_per_query` cannot
close — the missing axis becomes a visible, mechanical failure rather
than a privacy bug nobody notices.

## What's modelled, what's not

**Modelled:** wire-shape — round kinds, server ids, db ids, byte
counts, item counts. The transcript is the ordered list of these
per-round shape descriptors.

**Not modelled (by design):**
- **Byte content within fixed-length envelopes.** Bytes are treated
  as ideal-primitive uniform randomness, by hypothesis indistinguish-
  able across runs. The cryptographic ideal-primitive assumptions
  (DPF privacy, FHE IND-CPA, PRP indistinguishability) live in the
  primitives' own papers, not here.
- **Timing channels.** Wall-clock latency, packet inter-arrival, CPU
  side channels are not part of `transcript`. An adversary who
  measures latency learns strictly more than `L`.
- **Network-layer metadata.** TCP / TLS / WebSocket framing, IP, TLS
  handshake. By hypothesis the adversary observes only message
  payloads.
- **Compression artifacts.** Per-message-deflate and TLS compression
  are off in production; size side channels from compression are
  excluded by hypothesis.
- **OnionPIR LRU eviction retries.** Server-controlled, not
  query-controlled — modelled as no-eviction.

See the full list of "explicit non-claims" in [Leakage.ec](Leakage.ec)
section *EXPLICIT NON-CLAIMS*.

Because byte content is not modelled, `Real.query` and `Sim.query`
are *deterministic* functions of `(b, q)` and `(b, leak)` respectively.
The simulator-property proof reduces to functional equality, not
full pRHL. This is the framing introduced in the 2026-04-29 spec
revision; it dramatically reduces proof-closure cost compared to a
fully randomised pRHL formulation.

## File map

| File | Role | Lines |
|---|---|---|
| [Common.ec](Common.ec) | Shared abstract types (`query`, `db_id`, `transcript`, `round_kind`, `round_profile`, `backend`); protocol parameters (K=75, K_chunk=80, INDEX_CUCKOO_NUM_HASHES=2). | ~95 |
| [Leakage.ec](Leakage.ec) | The leakage record `L : query → leakage` with four admitted axes (`index_max_items_per_group_per_level`, `chunk_max_items_per_group_per_level`, `session_query_index`, `query_db_id`); query-side accessors; the `L_factors` axiom relating accessors to `L`. Documents 4 explicit non-claims and 5 closed axes. | ~210 |
| [Protocol.ec](Protocol.ec) | The `Real` model — abstract description of what the client emits on the wire. Per-section transcript fragments (info, key-register, hint-refresh, index, chunk, merkle-tops, index-merkle, chunk-merkle), each a deterministic function of backend + db_id + leakage axes. `Real.query` body composes the fragments in order. Pure-functional view `real_transcript` provided for proofs that prefer equational reasoning. The `Real_batch.query_batch` module + `real_batch_transcript = flatten ∘ map (real_transcript b)` op extends the per-query model to multi-query batches. | ~290 |
| [Simulator.ec](Simulator.ec) | The `Sim` model — same per-section composition as `Real`, but reads exclusively from `L q`. Once the body executes `leak <- L q`, every subsequent computation is a function of `leak` and `b` alone — no further reads of `q`. Pure-functional view `sim_transcript`. The `Sim_batch.query_batch` module + `sim_batch_transcript b leaks = flatten ∘ map (sim_transcript b)` op extends to multi-query batches; the procedure binds `leaks = map L qs` as the only `q`-touching step. | ~85 |
| [Theorem.ec](Theorem.ec) | The simulator-property statement, decomposed into per-axis lemmas: (1) `L_eq` implies each accessor agrees, (2) `real_transcript` factors through `L`, (3) `real_transcript b q = sim_transcript b (L q)`, (4) bridge to `proc` view, (5) headline per-query simulator-property, (6) **multi-query closure** (this revision): `simulator_property_multi_query` op-form + `real_eq_sim_op_batch` + proc bridges + equiv-form analog + `Real_batch ≡ Sim_batch`. | ~340 |

## Status: proven vs. admitted

The spec **typechecks cleanly with all 19 lemmas closed** (`make check` exits 0; zero `admit` tactics; zero warnings).

**19 of 19 lemmas mechanically closed:**

In `Leakage.ec`:
- `L_eq_refl`, `L_eq_sym`, `L_eq_trans` — equivalence-relation axioms.

In `Theorem.ec`:
- **Per-axis projection (4 lemmas)** — `L_eq_query_db_id`, `L_eq_query_index_max`, `L_eq_query_chunk_max`, `L_eq_query_session_query_index`. **These are the heart of the simulator argument** — they say `L`-equivalent queries agree on every accessor that `Real` reads. Proof: rewrite via `L_factors` and conclude.
- `real_transcript_factors_through_L` — wire transcript depends only on `L`. Proof: substitute the four per-axis equalities, conclude by reflexivity.
- `real_eq_sim_op` — equational simulator construction `real_transcript b q = sim_transcript b (L q)`. Proof: rewrite via `L_factors` and simplify.
- `Real_proc_eq_op`, `Sim_proc_eq_op` — bridge from `proc` view to `op` view. Proof: `proc; auto.` (the procs delegate to the deterministic ops).
- `simulator_property_per_query` — headline `equiv [ Real ~ Real : L_eq q1 q2 ==> ={res} ]`. Proof: `proc; skip => />.` symbolically executes the trivial `return real_transcript b q` body, leaving `real_transcript b0 q1 = real_transcript b0 q2`, closed by `exact (real_transcript_factors_through_L b0 q1 q2 h)`.
- `simulator_property_constructive` — headline `equiv [ Real ~ Sim : ... ==> ={res} ]`. Same pattern, closed by `exact (real_eq_sim_op b0 q0)`.
- **Multi-query closure (5 lemmas)**:
  - `simulator_property_multi_query` (op-form) — pairwise `L_eq` lifts to `real_batch_transcript b qs1 = real_batch_transcript b qs2`. Proof: list induction via `eq_from_nth` + `nth_map` from `List.ec`. Per-position equality reduces to `real_transcript_factors_through_L`.
  - `real_eq_sim_op_batch` — batch real ≡ batch sim at the op level: `real_batch_transcript b qs = sim_batch_transcript b (map L qs)`. Same list-induction shape, per-position closes via `real_eq_sim_op`.
  - `Real_batch_proc_eq_op`, `Sim_batch_proc_eq_op` — proc bridges. Proof: `proc; auto.`
  - `simulator_property_multi_query_equiv` — equiv-form `equiv [ Real_batch ~ Real_batch : pairwise L_eq ==> ={res} ]`. Proof: `proc; skip => />` + exact of the op-form.
  - `simulator_property_multi_query_constructive` — equiv-form `Real_batch ≡ Sim_batch`. Proof: `proc; skip => />` + exact of `real_eq_sim_op_batch`.

**Subtle gotcha caught while closing the per-query equiv lemmas.** The lemma signatures originally used parameter names `b` and `q`, which shadow the procedure parameters `b` and `q` of `Real.query` / `Sim.query`. EasyCrypt parses the unmarked `b` in the precondition `b{1} = b` as `b{1}` (defaulting to memory `&1`), making the precondition `b{1} = b{1}` — tautological. The fix is to rename the lemma parameters to `b0` and `q0`, matching the convention already established by `Real_proc_eq_op (b0 : backend)`. The same `b0` / `qs0` naming convention applies to the new multi-query equiv lemmas.

**Out of scope:**
- Closing the cryptographic ideal-primitive reductions (DPF, FHE, PRP). Those live in the primitives' papers; we cite by hypothesis.

## How the simulator-property proof catches a missing axis

The discipline is encoded in the body structure:

1. `Real.query` reads `q` ONLY through the four declared accessors
   (`query_db_id`, `query_index_max`, `query_chunk_max`,
   `query_session_query_index`). All other reads of `q` are syntactic
   errors at typecheck time (the accessors are the only `op`s with
   signature `query → _`).

2. `Sim.query` executes `leak <- L q` as its first statement, then
   uses **only `leak` and `b`**. Any read of `q` after this line
   would surface as a missing parameter to a per-section helper.

3. The `simulator_property_constructive` lemma asserts equality of
   the transcripts produced by `Real` and `Sim`. The proof obligation
   per-section is "the helper produces the same transcript when fed
   `query_X q` vs `(L q).X`". `L_factors` discharges each.

If a future maintainer adds a Real-side branch on, say,
`query_some_new_property q`, then:
- They must declare `query_some_new_property : query → _` as an `op`.
- They must extend `leakage` with the corresponding field (otherwise
  the simulator has no way to feed the `Sim`-side helper).
- They must extend `L_factors` to relate `L q`'s new field to the
  accessor.
- They must extend the per-axis agreement lemmas in Theorem.ec.

Any one of these omissions makes `simulator_property_per_query`
fail to close. **That's the intended semantic of the proof:** every
query-dependent fact on the wire MUST appear in `L`, on pain of
proof failure.

## Running the typecheck

### macOS install (one-time, ~15-20 min)

```bash
brew install opam z3
opam init --bare -y -a --disable-sandboxing
opam switch create easycrypt 4.14.1 -y
eval $(opam env --switch=easycrypt)
opam pin add -yn easycrypt https://github.com/EasyCrypt/easycrypt.git
opam install -y alt-ergo easycrypt
easycrypt why3config
```

### Verify

```bash
cd proofs/easycrypt
eval $(opam env --switch=easycrypt)
easycrypt -I . Theorem.ec
```

A successful typecheck prints no errors and no warnings. The spec
contains zero `admit` tactics; any `Error:` line (typically a
syntactic mismatch with the EasyCrypt version) needs fixing.

### CI

This directory is gitignored from CI by design — proof closure is
multi-step and the install pulls a recent EasyCrypt from GitHub which
makes CI slow and brittle. The spec's commit-and-PR-review of the
*scaffolding* is the meaningful artefact today; CI integration is a
follow-up if the proof closure progresses.

## How to extend

**Adding a new admitted leakage axis** (e.g. when a wire feature is
added that the simulator cannot reproduce from the existing record):

1. Add an `op query_X : query → T` accessor to Common.ec or Leakage.ec.
2. Add an `X : T` field to `leakage` in Leakage.ec.
3. Extend `L_factors` to `L q = {| ... ; X = query_X q |}`.
4. Add a new per-axis agreement lemma `L_eq_query_X` to Theorem.ec
   (admit-stubbed initially).
5. Update Real.query to read `query_X q` where needed; update
   Sim.query to read `leak.`X` in the matching place.
6. Update the lemma comment block in Leakage.ec's preamble.

**Closing an admitted axis** (e.g. when the protocol is hardened
to no longer leak it):

1. Update the protocol's per-section helper(s) to be independent of
   the axis.
2. Update Real.query / Sim.query to no longer feed the axis through
   to the helper.
3. Remove the field from `leakage` and the corresponding entry from
   `L_factors`.
4. Remove the per-axis agreement lemma from Theorem.ec.
5. Update [PLAN_LEAKAGE_VERIFICATION.md](../../PLAN_LEAKAGE_VERIFICATION.md)
   and [CLAUDE.md](../../CLAUDE.md) "What the Server Learns" sections.

## Engineering closures pending

The two highest-priority engineering closures (which would narrow
`L`):

- `chunk_max_items_per_group_per_level` — see [PLAN_CHUNK_MAX_CLOSURE.md](../../PLAN_CHUNK_MAX_CLOSURE.md). 4-5 weeks across 3 backends. Highest privacy impact.
- `index_max_items_per_group_per_level` — analogous, ~1 week. Easier because per-query items are fixed.

Once both land, `L` shrinks to `{ session_query_index; query_db_id }`,
and the simulator-property proof tightens correspondingly.

## Provenance

Initial scaffolding: 2026-04-29 (commit `771b925`).
L-spec amendment (3 admitted axes, 4 explicit non-claims): commit `0909bb0`.
Body fleshout + deterministic-shape framing + `query_db_id` axis: 2026-04-29
(this commit).
