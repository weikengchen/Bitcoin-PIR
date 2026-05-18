# BitcoinPIR Leakage Verification — Final State (2026-04-29)

This is the consolidated, source-of-truth document for what's verified
about Bitcoin PIR's wire-shape privacy. Written when the multi-session
verification effort wrapped, with future contributors and an upcoming
educational-website session in mind.

## TL;DR

For any backend `b ∈ {DPF, HarmonyPIR, OnionPIR}` and any two queries
q₁, q₂ that agree on the four leakage axes admitted in the spec, the
wire transcripts `Real(b, q₁)` and `Real(b, q₂)` are
**byte-shape-identical**. The same holds for batches of queries
(`Real_batch`). This is mechanized in EasyCrypt (31 lemmas, zero
admits), empirically witnessed against the live Hetzner staging
deployment, and pinned cross-language between the Rust reference
implementation and the standalone TypeScript `OnionPirWebClient`.

A determined adversary observing the wire learns at most:
- `query_db_id` — which database the user queried (intentional
  public metadata).
- `session_query_index` — position in the session for HarmonyPIR
  hint-refresh timing (function of session length, already public).
- `index_max_items_per_group_per_level` — empirically constant `= 2`
  after the [INDEX Merkle Group-Symmetry](#invariant-3-index-merkle-group-symmetry-index_max)
  closure.
- `chunk_max_items_per_group_per_level` — the approximate per-query
  UTXO count. An admitted, documented leak: the M=16 pad that pinned
  it to `1` was removed in Phase 4 / WS-A (see *CHUNK Merkle
  Item-Count — a documented trade-off* below). Mild — ~99 % of
  addresses have exactly 1 chunk.

In particular, the wire **does not reveal**:
- Which scripthash was queried.
- Whether the scripthash was found, not-found, or whale.
- The cuckoo position the lookup matched at.
- The collision pattern of `derive_groups_3[0]` across a multi-query
  batch.

It **does** admit (Phase 4 / WS-A trade-off) the approximate per-query
UTXO count — the `chunk_max` axis above. Found-vs-not-found itself
stays hidden via CHUNK Round-Presence Symmetry, but a found query's
chunk-Merkle item count tracks its UTXO count.

## What's mechanized vs cited-by-hypothesis

This section matters because it draws the honest scope line. Future
sessions should preserve this distinction in any external-facing
write-up.

### Mechanized in this repo

1. **Wire-shape simulator-property** (`proofs/easycrypt/`). 31
   lemmas, zero `admit` tactics, 415 verification points. The proof
   says: any two queries with equal `L(q)` produce byte-shape-equal
   transcripts under the abstract per-section model defined in
   `Protocol.ec`. Includes the multi-query analog over batches via
   `Real_batch.query_batch` + list induction.

2. **Pure-helper correctness via Kani** (`pir-sdk-client/src/{dpf,harmony,onion}.rs`,
   `#[cfg(kani)] mod kani_harnesses`). 14+ harnesses verifying:
   - `build_index_alphas` / `build_index_alphas_batched` K-padding
     invariants.
   - `items_from_trace` per-query item-count symmetry.
   - `classify_chunk_slots` round-presence symmetry (P1/P2).

   (The 4 `pad_chunk_ids_to_m` harnesses were deleted in Phase 4 /
   WS-A together with the M=16 pad they covered — see the CHUNK
   Merkle Item-Count trade-off below.)
   Each harness verifies in seconds; run one at a time per
   `feedback_kani_style.md`.

3. **Implementation-vs-spec correspondence (empirical)**. The
   spec's per-section ops (`info_segment`, `index_segment`,
   `chunk_segment`, `index_merkle_segment`, etc.) mirror the
   per-section structure of `pir-sdk-client/src/{dpf,harmony,onion}.rs::execute_step`.
   This correspondence is not proved formally (would require
   extracting Rust → EasyCrypt code, currently out of scope) but
   is checked at every commit by:
   - 30+ integration tests against live Hetzner servers
     (`pir-sdk-client/tests/leakage_integration_test.rs`).
   - 138 vitest unit tests in `web/src/__tests__/`.
   - Cross-language equivalence test (`onion_leakage_diff.test.ts`)
     comparing Rust reference output byte-for-byte to TS
     standalone implementation.

### Cited from the underlying primitives' papers

- **DPF security** — that two random DPF keys are computationally
  indistinguishable from uniform. Cited from
  [`libdpf`](https://github.com/weikengchen/libdpf).
- **OnionPIR semantic security** — BFV/SEAL FHE indistinguishability.
  Cited from [`OnionPIRv2-fork`](https://github.com/Bitcoin-PIR/OnionPIRv2-fork).
- **HarmonyPIR PRP indistinguishability**. Cited from the
  [`harmonypir`](https://github.com/Bitcoin-PIR/harmonypir) repo.

The bridge from "wire SHAPE matches" to "wire BYTES indistinguishable"
relies on the ideal-primitive hypothesis modelled abstractly in
`proofs/easycrypt/Common.ec`: byte content within each fixed-length
envelope is treated as ideal-primitive uniform randomness. Closing
this gap formally would be a multi-year research project per
primitive; not pursued here.

## The four privacy invariants

All four are documented as MANDATORY in `CLAUDE.md` and enforced by
integration tests + Kani harnesses + the EasyCrypt simulator argument.

### Invariant 1: Merkle INDEX Item-Count Symmetry

Every INDEX query emits exactly `INDEX_CUCKOO_NUM_HASHES = 2` Merkle
items regardless of outcome (found at h=0, found at h=1, not-found,
whale). Pre-closure: a found-at-h=0 query could emit 1 item; the
asymmetry leaked the cuckoo position.

- Spec: `pir-core/src/params.rs:154` (`INDEX_CUCKOO_NUM_HASHES`).
- Doc: `CLAUDE.md` § "Merkle INDEX Item-Count Symmetry".
- Code: `pir-sdk-client/src/{dpf,harmony,onion}.rs::items_from_trace`
  (each scripthash contributes both probed positions to the trace
  unconditionally).

### Invariant 2: CHUNK Round-Presence Symmetry

Every query (found / not-found / whale) emits at least one
K_CHUNK-padded CHUNK PIR round. Pre-closure: not-found and whale
skipped CHUNK rounds, exposing presence.

- Doc: `CLAUDE.md` § "CHUNK Round-Presence Symmetry".
- Code: `pir-sdk-client/src/{dpf,harmony}.rs::query_chunk_level`
  (forces a dummy round when `chunk_ids` is empty);
  `pir-sdk-client/src/onion.rs::query_chunk_level` and
  `web/src/onionpir_client.ts::queryBatch` (an all-not-found batch
  substitutes a single empty round, so one all-dummy K_CHUNK CHUNK
  round still goes out).
- After the Phase 4 M=16 removal this is a fully **independent**
  invariant — no longer "subsumed" by the (now-deleted) CHUNK Merkle
  Item-Count pad. CHUNK-Merkle round-presence is supplied by the
  Merkle verifier's ≥1 all-dummy DATA pass; CHUNK *PIR* round-presence
  by the empty-round fallback above.

### Invariant 3: INDEX Merkle Group-Symmetry (`index_max`)

Multi-query INDEX Merkle items distribute across PBC groups via
`pbc_plan_rounds`, not via `derive_groups_3[0]` directly. Pre-closure:
two scripthashes whose `[0]`s collided accumulated 4 items in one
group (`max_items_per_group = 4`); post-closure the planner spreads
them so `max_items_per_group = 2` regardless of input.

- Spec: `proofs/easycrypt/Leakage.ec` axis 1.
- Doc: `CLAUDE.md` § "INDEX Merkle Group-Symmetry".
- Helper: `pir-sdk-client/src/dpf.rs::plan_index_pbc_rounds` +
  `build_index_alphas_batched` (3 Kani harnesses).
- Closure commits: `606fddb` (DPF), `632cfd2` (Harmony). OnionPIR
  was structurally trivial pre-closure (its INDEX layer already
  used `pbc_plan_rounds`).

### CHUNK Merkle Item-Count — a documented trade-off (`chunk_max`)

**Not a closed invariant.** An M=16 chunk-Merkle item-count pad once
made every query contribute exactly 16 chunk Merkle items, pinning the
wire-observable `max_items_per_group_per_level` to `1`. Phase 4 / WS-A
(PLAN_MERKLE_CODING.md, `[HUMAN decision, 2026-05-17]`) **removed that
pad**: it forced even a 1-UTXO address to fetch and verify 16 chunk
entries (~16× chunk-layer cost) to hide a count that is `1` for ~99 %
of mainnet addresses.

A query now contributes its *real* chunk count of chunk Merkle items,
so the server learns the approximate per-query UTXO count — the
`chunk_max` axis is an admitted, documented leak again.

**Found-vs-not-found stays closed** by a *separate* mechanism — CHUNK
Round-Presence Symmetry — which does not depend on M-padding: the
Merkle verifier (`verify_bucket_merkle_batch_generic` for DPF /
Harmony; `verify_sub_tree` / `verifySubTree` for OnionPIR) issues ≥1
all-dummy CHUNK-Merkle pass even for a 0-chunk query, so a not-found
query emits the same ChunkMerkleSiblings + DATA tree-top traffic as a
found query.

- Spec: `proofs/easycrypt/Leakage.ec` axis 2 (re-opened, admitted).
- Doc: `CLAUDE.md` § "CHUNK Merkle Item-Count — Documented Trade-off".
- History: closed by `565ea47` (DPF), `08ec736` (Harmony), `f915a65`
  (OnionPIR), `eb5128c` (standalone TS); re-opened in Phase 4 — the
  `pad_chunk_ids_to_m` / `CHUNK_MERKLE_ITEMS_PER_QUERY` /
  `padChunkIdsToM` code, the 4 Kani harnesses, and the
  `onion_pad_chunk_ids` vitest suite were deleted.

## Verification layers — the test pyramid

Stronger guarantees on top, broader coverage on bottom. Each layer
gates the next at commit / PR / release time.

| Layer | What it pins | Cost |
|---|---|---|
| EasyCrypt simulator-property (31 lemmas) | Wire-shape factors through `L(q)`. Per-query AND multi-query. | One-time + `make check` (~30s) |
| Kani harnesses (18+) | Pure-helper invariants exhaustively under bounded models. | Run one at a time, ≤15s each |
| Rust unit tests (151) | Per-helper correctness on concrete inputs. | <10s, every PR via `pir-sdk-integration.yml` |
| Rust integration tests (live Hetzner, ~30) | End-to-end byte-shape against the production server. | 30-300s per test, daily cron + PR |
| TypeScript unit tests (138 vitest) | TS port helper correctness; corpus-shape validation. | <1s, every PR via `web-build.yml` |
| Cross-language live diff | Rust reference ≡ TS standalone, byte-for-byte against Hetzner. | ~60s, manual `RUN_LIVE_DIFF=1` before releases |

## Empirical witnesses — the byte-identity claim

The strongest single empirical statement:

> A FOUND query and a NOT-FOUND query, run through the same client
> against the live Hetzner deployment, produce **byte-identical
> leakage profiles** — same total round count, same per-round kind /
> server / db / request_bytes / response_bytes / items vector.

Encoded in:

| Test | Backend | Profile |
|---|---|---|
| `dpf_found_vs_not_found_have_byte_identical_profiles` | DPF | 23 rounds, 6 ChunkMerkleSiblings |
| `harmony_found_vs_not_found_have_byte_identical_profiles` | HarmonyPIR | 23 rounds, 3 ChunkMerkleSiblings |
| `onion_found_vs_not_found_have_byte_identical_profiles` | OnionPIR | 9 rounds, 1 ChunkMerkleSiblings |

Each uses `assert_profiles_equivalent` — the strictest comparator
in the test framework. All three pass.

## Pre-closure → post-closure deltas (for context)

| Backend | Pre-closure FOUND vs NOT-FOUND | Post-closure FOUND vs NOT-FOUND |
|---|---|---|
| DPF | 23 rounds / 17 rounds; ChunkMerkleSiblings 6 vs 0 | 23 rounds (byte-identical); 6 vs 6 |
| HarmonyPIR | (no per-query test pre-closure) | 23 rounds; 3 vs 3 |
| OnionPIR | 9 rounds / 7 rounds; ChunkMerkleSiblings 1 vs 0 | 9 rounds; 1 vs 1 |

Multi-query (curated colliding scripthash batches):

| Backend | Pre-closure (collision drives `index_max`) | Post-closure |
|---|---|---|
| DPF | A=B=33 / C=21 rounds; IndexMerkleSiblings 24 / 12 | A=B=C=19; IndexMerkleSiblings 12 |
| HarmonyPIR | A=B=28 / C=22 rounds; IndexMerkleSiblings 12 / 6 | A=B=C=20; IndexMerkleSiblings 6 |
| OnionPIR | A=B=C=7 (already structurally trivial) | unchanged |

## Key files & commits

### Code
- `pir-core/src/params.rs` — privacy-relevant constants.
- `pir-sdk-client/src/{dpf,harmony,onion}.rs` — per-backend Rust
  client, including the per-helper Kani harnesses inline.
- `pir-sdk-client/src/merkle_verify.rs` — bucket-Merkle verification.
- `pir-sdk-client/src/onion_merkle.rs` — OnionPIR-specific Merkle.
- `pir-sdk-client/tests/leakage_integration_test.rs` — Rust live
  integration tests + curated-collision multi-query tests.
- `web/src/onionpir_client.ts` — standalone TS Onion client.
- `web/src/leakage.ts` — TS port of the leakage profile types.
- `web/src/__tests__/` — vitest unit tests including the live diff.

### Spec
- `proofs/easycrypt/Common.ec` — abstract types.
- `proofs/easycrypt/Leakage.ec` — leakage record `L(q)`, four axes,
  `L_factors` axiom.
- `proofs/easycrypt/Protocol.ec` — abstract `Real` model.
- `proofs/easycrypt/Protocol_{DPF,Harmony,Onion}.ec` — per-backend
  concrete bindings + specialisation lemmas.
- `proofs/easycrypt/Simulator.ec` — `Sim` model.
- `proofs/easycrypt/Theorem.ec` — 16 theorem-side lemmas including
  per-query + multi-query simulator-property.
- `proofs/easycrypt/README.md` — full file map and proof status.

### Docs
- `CLAUDE.md` — project memory, with all four invariant sections.
- `docs/VERIFICATION_OVERVIEW.md` — this file.
- `proofs/easycrypt/README.md` — EasyCrypt verification recipe.

### Notable commits (newest first)
- `f087685` — CI release-readiness gate (wasm-pack + tsc + vitest).
- `3488a90` — TypeScript hygiene (3 pre-existing tsc errors fixed).
- `eb5128c` — chunk_max closure for standalone TS OnionPirWebClient.
- `f915a65` — chunk_max closure for OnionPIR + spec/CLAUDE.md update.
- `08ec736` — chunk_max closure for HarmonyPIR.
- `565ea47` — chunk_max closure for DPF (helper + 4 Kani harnesses).
- `632cfd2` — index_max closure for HarmonyPIR.
- `606fddb` — index_max closure for DPF.
- `dfe3508` — multi-query simulator-property test for OnionPIR
  (structural-triviality argument).
- `6eda18a` — multi-query simulator-property test for DPF + HarmonyPIR
  (curated colliding scripthashes).
- `691afc4` — closed the 2 remaining EasyCrypt admits.
- `af2e5c9` — initial EasyCrypt body fleshout, 12/14 lemmas.
- `0909bb0` — L-spec amendment (3 admitted axes + 4 explicit
  non-claims).
- `3ab3f1a` — multi-query EasyCrypt closure (5 new lemmas).
- `140c87f` — EasyCrypt per-backend Protocol split.

## For the next contributor

If you're picking this up cold:

1. Start with `proofs/easycrypt/README.md` — it's the most
   self-contained explanation of the verification approach.
2. Run `make check` from `proofs/easycrypt/` to confirm the spec
   typechecks (one-time install via opam; ~30s on a warm cache).
3. Run `cargo test -p pir-sdk-client --lib` to confirm 151
   unit tests pass.
4. Run `cd web && npm test` to confirm 138 vitest tests pass.
5. (Optional) Run `cargo test -p pir-sdk-client --test
   leakage_integration_test -- --ignored --test-threads=1` against
   live Hetzner — takes ~10 minutes total.

Adding a new privacy axis to the leakage record:

1. Add the axis to `proofs/easycrypt/Leakage.ec` with prose
   describing what the wire reveals.
2. Add a corresponding accessor `query_X` and a per-axis projection
   lemma `L_eq_query_X` in `Theorem.ec`.
3. If the axis is non-trivial, add an integration test that
   empirically witnesses what it captures.
4. Update `CLAUDE.md`'s "What the Server Learns" section.

Closing an admitted axis:

1. Land the wire-shape change in the Rust client (and TS standalone
   if applicable).
2. Add a Kani harness for any new pure helper.
3. Update the integration test to assert byte-identity instead of
   the previous distinguishability.
4. Update `Leakage.ec` axis prose to flip from "admitted" to
   "constant post-closure" (don't remove the axis — keep it for
   spec stability across DB/batch parameters).
5. Update `CLAUDE.md` to add a new "MANDATORY for Privacy"
   invariant section.

## For the educational website

The website lives at `~/bitcoin-pir/website/` (Astro + MDX). It has
a `CONTENT-AUDIT.md` style requiring every factual claim to cite
`file:line` in the upstream codebase. When writing verification
content, useful claim families:

- **Privacy invariants** (4 of them) — cite from this file's
  "The four privacy invariants" section, which itself cites
  `CLAUDE.md` and source files.
- **Empirical witnesses** — the byte-identity table above; each
  row maps to an integration test path you can `file:line`-cite.
- **Verification layers** — the test-pyramid table above; each
  layer maps to a tooling story (Kani for helpers, EasyCrypt for
  spec, Hetzner for end-to-end).
- **Honest scope split** — what's mechanized vs cited; the
  one-paragraph "ideal-primitive hypothesis" explanation.

Suggested narrative shape for a single "How we verify privacy" page:

1. **The threat model in one sentence** — what an adversary
   *actually* sees on the wire (round counts, byte sizes, item
   vectors), not what they have to break to attack.
2. **The leakage record** — show `L(q)` as a small struct with
   four labelled fields. The point: these four are *all* the wire
   reveals, post-closure.
3. **The byte-identity demo** — visual showing two queries (one
   found, one not-found) producing literally the same wire
   transcript. Cite the byte-identity test.
4. **What's mechanized** — three layers: pure helpers (Kani),
   spec proof (EasyCrypt), end-to-end (Hetzner integration tests).
5. **What's cited** — the primitive-layer hypothesis. Be honest;
   don't oversell.
6. **Why this matters for users** — practical implication: a
   server that wants to fingerprint a wallet can't do it via wire
   shape, even with adversarial scripthash patterns.

Don't claim full cryptographic verification. Don't claim
zero-leakage. Do claim "every wire-observable axis is either
structurally constant or in the leakage record by design".
