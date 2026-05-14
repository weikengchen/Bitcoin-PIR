# Feature request to OnionPIRv2: runtime-variable `target_num_pt` in `PirParams`

**Status:** authored 2026-05-14 from a downstream consumer (BitcoinPIR) hitting
a hard storage / latency wall in the post-port architecture. The pre-port
implementation supported this shape natively; the post-port refactor moved
the parameter to `constexpr`, which is the source of the blocker.

**Audience:** the AI agent (or human) working in
`/Users/cusgadmin/bitcoin-pir/OnionPIRv2/`. No BitcoinPIR-side context is
required to act on this — every claim below is grounded in upstream source
paths and concrete numbers.

**TL;DR:** `num_plaintexts` is currently derived from `constexpr size_t
DBConsts::DB_SIZE_MB` at C++ compile time. Downstream consumers that
instantiate many `PirServer` objects with different data scales (e.g.
BitcoinPIR's 75-group cuckoo-PIR architecture: 75 per-group servers, each
holding only ~10 K plaintexts of actual data) get forced into the maximum
shape across all servers, even though each individual server only needs a
fraction of it. The fix is to thread `target_num_pt` through `PirParams`
as a constructor argument while keeping the other shape constants
(`PolyDegree`, `PlainMod`, `L_EP`, `L_KEY`, `L_KS`, `TREE_HEIGHT`) as
constexpr — they're genuinely part of the lattice config and shouldn't
move.

---

## 1. The symptom (concrete numbers)

The downstream consumer (BitcoinPIR) builds an index PIR with 75 cuckoo
groups, each containing `bins_per_table ≈ 10,239` plaintext slots of
actual data (the rest of the compiled-in `num_plaintexts` is unused). Pre-
port, each per-group `PirServer` was constructed with `num_entries =
bins_per_table`, so its `PirParams` shape was tightly fit to ~10 K
plaintexts. Post-port, the same code path produces servers sized at the
compile-time `num_plaintexts = 968,192`.

Concrete measured impact during the rebuild:

```
gen_3_onion run, 2026-05-14:

  OnionPIR params: padded=968192, entry_size=3328, fst_dim=512, other_dim=1891
  Physical size per group: 3072.88 MB                    ← from params_info().physical_size_mb
  Total for 75 groups: 225.06 GB                         ← projected from above (also misleading)

  Saved preprocessed DB to .../onion_index_pir/group_0.bin (15128 MB)   ← actual save_db output
  Group 1/75 preprocessed in 33.37s
```

- The `physical_size_mb` field reports `num_plaintexts × entry_size = 968192 × 3328 ≈ 3,073 MB`
  (the pre-NTT plaintext byte budget).
- The actual `save_db` output is `num_plaintexts × coeff_val_cnt × rns_mod_count × 8 bytes =
  968,192 × 2,048 × 1 × 8 = 15,861,121,024 B ≈ 15,128 MiB` per group.
- 75 groups × 15.13 GiB = **1.11 TiB** total INDEX storage.
- The downstream consumer's filesystem has 813 GB free. We hit OOD at
  ~group 53 and aborted the build.
- Pre-port the same architecture produced 75 × ~150 MB = ~10 GB total. **The
  port introduced a 100× storage blowup for this use case.**

Bonus: `params_info().physical_size_mb` reporting the pre-NTT size while
`save_db` writes the post-NTT level-major store (4.92× expansion at
`CONFIG_N2048_K1`) is a documentation footgun — it bit me, and it'll bite
the next downstream consumer. Probably worth a separate small commit
clarifying that field's semantics in either the doc-comment or the
INTEGRATION.md table.

## 2. Root cause

`src/includes/database_constants.h`:

```cpp
namespace DBConsts {
  // ...
  constexpr size_t DB_SIZE_MB = 128;   // line 39 (now 3072 in BitcoinPIR's
                                       // fork-specific commit, but the issue
                                       // is structural — see below)
  // ...
}
```

`src/pir.cpp`:

```cpp
size_t target_num_pt = DBConsts::DB_SIZE_MB * 1024 * 1024 / get_pt_size();
// ...flows into PirParams ctor / utils::calculate_db_shape...
```

So every `PirServer` instance in the process gets the same `target_num_pt`,
which is then frozen at the value derived from the constexpr `DB_SIZE_MB`.
There's no per-instance escape hatch:

- `PirServer::new(num_entries)` accepts a `num_entries` parameter, but it
  is ignored (per the Rust binding's own doc-comment: "currently ignored
  (the upstream PirParams reads its shape from build-time constants); kept
  in the signature for forward compatibility"). That comment hints the
  contract was meant to be runtime; the constexpr DB_SIZE_MB closed the door.

Bumping `DB_SIZE_MB` to satisfy the largest downstream consumer (e.g. our
946 K chunk-side data) makes the smallest consumer (our 10 K per-group
index) pay the same shape cost — a classic shared-config trap.

## 3. Why the "shared store" workaround isn't sufficient

Upstream's "Indirect DB mode" (§2.3 of INTEGRATION.md, the
`set_shared_database` API) is genuinely a clean workaround for the storage
problem: pack all 75 groups' bins into one shared NTT store at unique slot
IDs, then attach each per-group server via `set_shared_database(slice,
num_plaintexts, &index_table)`. Total storage drops back to ~12 GB.

But the workaround pays a real runtime cost — every per-query
`answer_query` against the shared store works on the full `num_plaintexts`-
shaped matmul, not the per-group `bins_per_table`-shaped one the pre-port
code did:

| | Pre-port (per-group own DB) | Post-port + shared-store workaround |
|---|---|---|
| `num_plaintexts` per query | 10,239 (`= bins_per_table`) | 968,192 (full DB shape) |
| First-dim matmul size | 10,239 × 2,048 ≈ 21 M ops | 968,192 × 2,048 ≈ 2 G ops, **~95× more** |
| Expansion levels (`log fst_dim_sz`) | ~14 | ~20 |
| Per-query `answer_query` wall (estimated, scaled) | baseline | **~10× slower (lower-bound)** |

For pir1's deployment (single i7-8700), a baseline INDEX query is already
~10 s of FHE work. The shared-store workaround would push that to
~30-50 s per probed bin. Not unusable, but a measurable regression and
hard to justify when the pre-port architecture demonstrably handled this
case correctly.

## 4. What we'd like upstream to do

**Make `target_num_pt` a runtime parameter of `PirParams`, accepted via
`PirServer::new(num_entries)`.** Keep `PolyDegree`, `PlainMod`, `L_EP`,
`L_KEY`, `L_KS`, `TREE_HEIGHT`, `FST_DIM_POW2`, `NoiseStdDev` as constexpr
(they really are the lattice config — moving them runtime would lose the
codegen win that motivated the constexpr regime in the first place, and
no downstream consumer is asking for that).

After this change, downstream code like:

```rust
let server = PirServer::new(small_per_group_size as u64);
// server now has a PirParams shaped for `small_per_group_size`, not the
// global DB_SIZE_MB-derived default
```

…produces a small per-server DB. `set_shared_database` still works as it
does today (its `shared_num_entries` parameter is independent of
`PirParams.num_pt`). `save_db` writes a file whose header `num_pt` field
already exists (per INTEGRATION.md §1.3) — `load_db` just needs to honor
the loaded value instead of asserting against the compile-time default.

## 5. Implementation sketch

The change is concentrated in a handful of files. Suggested ordering:

### 5.1 `src/includes/database_constants.h`

- Demote `DB_SIZE_MB` from `constexpr` to a **default value** that
  `PirParams`' default constructor uses when no explicit `target_num_pt`
  is passed. The test harness and `run.py` paths keep working unchanged.
- The rest of the constexprs (`PolyDegree`, `PlainMod`, `L_*`,
  `TREE_HEIGHT`, `FST_DIM_POW2`, `NoiseStdDev`) stay.

### 5.2 `src/pir.cpp` / `src/includes/pir.h`

- Add a `PirParams` constructor (or extend the existing one) that takes
  `size_t target_num_pt` and threads it into `utils::calculate_db_shape`
  in place of the `DBConsts::DB_SIZE_MB`-derived value.
- Keep the no-arg constructor as a default that uses `DBConsts::DB_SIZE_MB`,
  so the existing test harness keeps working.
- All `PirServer` / `PirClient` members that cache PirParams-derived
  dimensions (e.g. `fst_dim_sz_`, `other_dim_sz_`, `num_pt_`) stay; they
  just get computed from the runtime `target_num_pt` now.

### 5.3 `src/onion_ffi.cpp` / `src/includes/onion_ffi.h`

- `onion_server_new(num_entries)`: today this comment says
  `placeholder; PirParams ignores`. After the change, pass `num_entries`
  into a `PirParams(num_entries)` ctor and use that for the Server's
  internal state. The Rust binding's
  `Client::from_secret_key(num_entries, client_id, sk)` signature
  doesn't change; it just stops being a no-op.

### 5.4 `utils::calculate_db_shape`

- This function already takes `target_num_pt` as a parameter — no change
  needed beyond making sure all call sites pass the runtime value.

### 5.5 `save_db` / `load_db` / `load_db_from_borrowed`

- The 48-byte header (per INTEGRATION.md §1.3) already carries the saved
  DB's `num_pt`. `load_db` currently (I'd guess from the symptom) trusts
  that the loaded value matches the compile-time constant. Change it to
  use the loaded value to build the Server's `PirParams`. Reject loads
  where `num_pt > some-sane-bound` if a defensive limit is desired
  (e.g. `≤ 2^28` to bound memory at construction).

### 5.6 `set_shared_database`

- No change needed. `shared_num_entries` is already a runtime parameter
  (per `src/onion_ffi.cpp:onion_server_set_shared_database`), and the
  validation rule `index_table.len() == params_info().num_plaintexts`
  generalizes naturally — the validation is against the receiving
  Server's `PirParams.num_pt`, which is now per-instance.

### 5.7 NTT / scratch-buffer paths

- Any `std::array<uint64_t, N>` or fixed-size stack array sized by
  `target_num_pt` (likely a few in `src/server.cpp` matmul kernels)
  converts to `std::vector<uint64_t>` per-`PirParams`-instance. This is
  the codegen-quality concern — runtime sizes mean dynamic loop bounds.
  For BitcoinPIR's use case (`num_pt ~10 K per group`), the inner-loop
  unrolling is still effective; the outer loop's iteration count just
  becomes dynamic. Expect ≤ 5% throughput hit relative to the
  fully-constexpr build, easily worth the per-server right-sizing.

### 5.8 Optional: keep the constexpr fast path for benchmarks

If preserving the upstream test harness's codegen quality matters, the
`PirParams` ctor could be templated on `constexpr_num_pt`-vs-`runtime`,
with the test path picking the templated version and the FFI exposing
only the runtime one. Two flavors of the inner loops. More work — not
required for BitcoinPIR's correctness or for unblocking the rebuild;
just an optimization the upstream maintainers may want.

## 6. Acceptance criteria

A green run of all three of the following, against a host with this
upstream change applied and BitcoinPIR's
`worktree-feat+onionpir-port-migration` branch:

1. **Upstream integration tests still pass.**
   `cargo test -p onionpir -- --test-threads=1`
   in OnionPIRv2/rust/onionpir/. Especially the
   `shared_database_identity_index_table` test — that's the closest
   upstream test to BitcoinPIR's INDEX use case, and a regression there
   means a wire-format slip.

2. **Per-instance `num_pt` actually varies.**
   A small test that creates two `Server` instances with different
   `num_entries` parameters, runs one query against each, confirms the
   `params_info()` returned by each reports the per-instance shape.
   (Today, both would report the same compile-time `num_pt`.)

3. **BitcoinPIR's gen_3_onion run completes.**
   Each per-group `save_db` output sizes to the actual per-group
   `bins_per_table × coeff_val_cnt × 8` (~150 MB at our shape), not
   to the global `DB_SIZE_MB`-derived value. 75 groups × ~150 MB ≈ 11 GB
   total — fits on the build host and within Hetzner pir1's disk budget.

## 7. Out of scope (explicitly NOT asking for)

- Don't change `PolyDegree`, `PlainMod`, `L_EP`, `L_KEY`, `L_KS`,
  `TREE_HEIGHT`, `FST_DIM_POW2`, or `NoiseStdDev` to runtime. Those are
  the lattice config and there's no downstream need to vary them per
  instance.
- Don't remove `DB_SIZE_MB` outright. Keep it as the default that the
  no-arg `PirParams` constructor uses, so the test harness and `run.py`
  keep working unmodified.
- Don't change the wire format of queries / responses. `num_pt` only
  affects shape sizes inside the server; the client emits queries shaped
  for whatever PirParams it was constructed with, and the server's
  response matches.

## 8. Cross-references

- BitcoinPIR's migration plan:
  `BitcoinPIR/docs/ONIONPIR_PORT_MIGRATION.md`
  — describes the 7-commit migration from pre-port to post-port; commits
  1-7 are all landed except for the rebuild blocker described here.
- BitcoinPIR's branch with the migration:
  `BitcoinPIR/.claude/worktrees/feat+onionpir-port-migration/` on branch
  `worktree-feat+onionpir-port-migration`, 11 commits ahead of d6c333de.
- Upstream INTEGRATION.md:
  `/Users/cusgadmin/bitcoin-pir/OnionPIRv2/INTEGRATION.md`
  — sections §1.3 (preprocessed DB format), §2.3 (Indirect DB mode), §3
  (build configuration) are the most relevant context.
- Upstream commit that introduced the constexpr `DB_SIZE_MB`:
  probably part of the Phase-2 FFI-layer commit (`87f1ebc`) or the
  earlier port (`3f72540`). A `git log -p src/includes/database_constants.h`
  in OnionPIRv2 would pin down the exact commit.

## 9. The workaround if upstream punts

If for any reason the upstream maintainer doesn't want to do this
refactor (codegen-quality concerns, scope, etc.), BitcoinPIR's fallback
plan is to refactor its own gen_3 + unified_server to use
`set_shared_database` for the INDEX side too — same pattern the CHUNK
side already uses. Costs ~10× per-query FHE wall time per INDEX probe
(quantified in §3 above) but unblocks the rebuild today. We'd rather
not, but it's an option if the runtime-num_pt change is too disruptive.

---

*Authored from BitcoinPIR's worktree by the AI agent driving the
post-port migration. Concrete numbers in §1 reflect a live `gen_3_onion`
run against the height-948454 chainstate snapshot on 2026-05-14.*
