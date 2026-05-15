# OnionPIRv2 Port Migration — BitcoinPIR side

Companion to upstream's [`INTEGRATION.md`](../../bitcoin-pir/OnionPIRv2/INTEGRATION.md)
(absolute path: `/Users/cusgadmin/bitcoin-pir/OnionPIRv2/INTEGRATION.md`).

The upstream `onionpir` crate was rebuilt to track the SEAL-free upstream
fix for the GHS / "special prime" key-switching issue
(ePrint 2025/1142 revision).

This doc maps the integration spec onto BitcoinPIR's actual call sites so
the migration can be done one ordered commit at a time. It does **not**
describe the post-port API itself — read upstream's `INTEGRATION.md` for
that. This is the BitcoinPIR-specific punch list.

## Status at 2026-05-14

  ✅ §0  operator push   — OnionPIRv2/main pushed to GitHub at 92fceb01
  ✅ §2 Commit 1         — rev bump + mechanical renames (4e12d0d9)
  ✅ §2 Commit 2         — bit-unpack helper + every decrypt_response wired (0cf7ac21)
  ✅ §2 Commit 3         — gen_2/3/4 push_plaintexts + save_db + runtime num_plaintexts (8e3dcddf)
  ✅ §2 Commit 4         — audit (no persistence to invalidate) + TS bit-unpack helper + diagnostic-friendly error messages
  ✅ §2 Commit 5a        — client-side PACKED_ENTRY_SIZE → runtime params (f0399024)
  ✅ §2 Commit 5b        — gen_1/3/4 hardcoded constants → runtime params (2bf2b3da; truncation gone)
  ✅ §2 Commit 6         — SharedKeyStore audited (no-code-change); QueryQueue declined
  ✅ §2 Commit 7         — WASM swap (post-port .mjs) + TS API rename + unpack wiring (8dab8e29)
  ✅ Cleanup             — test_merkle_verify_onion runtime-arity polish
  ✅ Upstream feature    — runtime-variable `target_num_pt` in PirParams (OnionPIRv2 fb14f4e)
  ✅ Rebuild verified    — gen_1→gen_2→gen_3→gen_4 PASS end-to-end on chainstate at height 948454

Branch: `worktree-feat+onionpir-port-migration` at
`.claude/worktrees/feat+onionpir-port-migration/`. **The migration is
done, the post-port rebuild ran clean, and verification PASSED at every
stage.**

## Final rebuild numbers (chainstate height 948,454, 2026-05-15)

| Step | Wall time | Output | Verification |
|---|---|---|---|
| gen_1_onion | 59 s | 946,287 entries × 3,328 B = 3.15 GB packed | — |
| gen_2_onion | 166 s | `onion_shared_ntt.bin` 15.51 GB (num_pt = 946,688) | PASS (decrypted matches original entry, noise budget 1) |
| gen_3_onion | 59 s | `onion_index_all.bin` 12.58 GB (75 × 160 MB per-group; padded num_pt = 10,240 PER GROUP) | PASS (tag match at slot 0, noise budget 1) |
| gen_4_build_merkle_onion | 2 s | INDEX-MERKLE root + DATA-MERKLE root + 0.6 GB sibling NTT stores (ARITY = 104) | — |
| **Total pipeline** | **~5 min** | **44 GB checkpoint** (onion ~28 GB + DPF/Harmony non-onion ~16 GB preserved) | — |

Pre-port (for comparison): same workload took ~10 GB onion artifacts;
post-port with per-instance num_pt: ~28 GB. The growth comes from
needing slightly larger per-group DBs to hold the same data (entry_size
3840 → 3328 → more entries → larger NTT store), partially offset by
ARITY 120 → 104 reducing Merkle sibling sizes. End result: comfortably
under Hetzner pir1's 954 GB budget; ~30 GB rsync to deploy.

Pre-port preserved at `/Volumes/Bitcoin/data/preport_backup_2026-05-14/`
(56 GB) for rollback.

## Deployment status (2026-05-15)

**Deploy steps DONE on Hetzner pir1:**

1. ✅ Branch `feat/onionpir-port-migration` pushed to origin.
2. ✅ `unified_server` rebuilt on pir1 from the post-port branch
   (`cargo build --release -p runtime --bin unified_server`).
3. ✅ Checkpoint rsync'd: `/Volumes/Bitcoin/.../checkpoints/948454/`
   (44 GB) → `/home/pir/data/checkpoints/948454/`, atomic swap
   completed (pre-port preserved as `948454.preport-2026-05-15/`).
4. ✅ `MANIFEST.toml` regenerated to match the new onion files
   (`scripts/build_db_manifest.sh`).
5. ✅ Pre-port delta `delta_940611_948454` dropped from
   `/home/pir/data/databases.toml` (post-port delta rebuild
   pending — see below).
6. ✅ `pir-primary` + `pir-secondary` restarted, both `active`,
   listening on `:8091` + `:8092`.
7. ✅ End-to-end OnionPIR query (`test_onion_client_query_batch`)
   **PASSES via direct SSH tunnel `ws://127.0.0.1:18091`** in
   400.16 s. Server worker reports `empty=0/N` for every
   `AnswerBatch` (INDEX, CHUNK, all sibling levels); the WASM /
   FFI plaintext-decryption pipeline reconstructs the expected
   "not-found" result for the test scripthash. The diagnostic
   logging added in this commit prints
   `empty=…/…, nonempty_total=…B, resp_len=…B, client_id=…` per
   batch, so future client-side `SessionEvicted("…all-empty
   batch…")` reports can be triaged from server logs alone.

**Known gap: Cloudflare idle-timeout on `wss://pir1.chenweikeng.com`.**

The same test against the public CF-fronted URL fails after ~127 s
with `ConnectionClosed("Connection reset without closing handshake")`.
The OnionPIR INDEX phase on pir1 currently takes **~162 s of
server-side matmul** for the K=75 INDEX-bin DB (the per-group
servers process queries sequentially in the worker thread). That
exceeds Cloudflare Free's ~100 s WebSocket idle timeout.

Two independent fixes will close this gap:

(a) **Parallelize the per-group `answer_query` calls inside the
    worker thread.** pir1 is an i7-8700 with 6 cores; sequential
    processing of 75 INDEX groups × ~1.1 s each ≈ 80 s, dropping
    to ~14 s with a `rayon::par_iter()` fan-out. CHUNK (80 ×
    ~2 s ≈ 160 s sequential) drops similarly. Below the 100 s
    threshold without any protocol change.

(b) **Server-side keepalive while processing long batches** — emit
    a `Message::Pong(empty)` from the unified-server WS loop every
    ~30 s while a `PirCommand::AnswerBatch` is outstanding. CF
    sees activity, keeps the tunnel open. No client change.

Either fix unblocks `wss://pir1.chenweikeng.com`. (a) is the
better one — wall-time improvement benefits every client, not just
CF-fronted ones. Tracked as a separate follow-up so it doesn't
blow up the migration commit.

**Delta rebuild pending.** `delta_gen_1_onion.rs` already builds
under the post-port shape (verified in commit 5b's build-pipeline
sweep), but the on-disk `delta_940611_948454/` files were the
pre-port format and have been dropped from `databases.toml`.
Re-running `scripts/build_delta_onion.sh` (locally, then rsync to
pir1) will regenerate the post-port delta; restore the
`[[database]]` entry in `databases.toml` and `systemctl restart
pir-primary`. The pre-port `databases.toml` is saved as
`databases.toml.preport-2026-05-15` on pir1 for reference.

`cargo check --workspace` is green. `cargo test -p pir-sdk-client
--features onion --test integration_test test_onion_client_query_batch
-- --ignored --nocapture` passes against pir1 via SSH tunnel.

## 0. Blocking step (operator) — DONE

Local OnionPIRv2 HEAD at push time: `92fceb01` (`docs: INTEGRATION.md
for downstream consumers`). BitcoinPIR's three Cargo.toml refs are
pinned at that commit.

---

## 1. Files BitcoinPIR has to update

Surface measured by `rg "onionpir|push_database_chunk|decrypt_response"
--type rust`:

| File | What it does | Touches integration §§ |
|---|---|---|
| `pir-sdk-client/src/onion.rs` | Native + WASM client logic; per-level `onionpir::Client`, batched INDEX/CHUNK PIR | 1.1, 1.2, 1.5, 2.1, 2.4 |
| `pir-sdk-client/src/onion_merkle.rs` | Sibling-level OnionPIR Merkle verification | 1.1, 1.2, 1.5, 2.4 |
| `runtime/src/bin/unified_server.rs` | Production server (pir-primary on Hetzner) | 1.1, 1.3, 1.4, 2.1, 2.5, 2.6 |
| `runtime/src/bin/onionpir_client.rs` | Standalone client binary | 1.1, 1.2, 1.5 |
| `runtime/src/bin/onionpir_bench.rs` | Benchmark; tiny test DB | 1.1, 1.4, 1.5 |
| `runtime/src/onionpir.rs` | Re-exports + shims (`runtime::onionpir::*`) | 1.1 |
| `build/src/gen_2_onion.rs` | Phase-2 of the DB build pipeline | 1.3, 1.4 |
| `build/src/gen_3_onion.rs` | Phase-3 (write `preprocessed_db.bin`) | 1.3, 1.4 |
| `build/src/gen_4_build_merkle_onion.rs` | Build the OnionPIR Merkle tree-tops | 1.3, 1.4 |
| `web/src/onionpir_client.ts` | Hand-rolled TS client (SEAL doesn't compile to wasm32) | **§2.6 + special** — see §4 below |
| `web/public/wasm/onionpir_client.{js,d.ts}` | Currently a stub | possibly replaced by upstream's new WASM client (`bitcoin-pir/OnionPIRv2/wasm/`) |
| `web/src/__tests__/onion_*.ts` | Vitest fixtures around the TS client | shape-changes only |
| `explorer/src/{utxo-provider,types}.ts` | Explorer adapter glue | none if `onionpir_client.ts` API stays stable |
| `pir-sdk-wasm/src/{lib,client}.rs` | WASM bindings; **no `WasmOnionClient` today** | 2.4 may unlock `WasmOnionClient` post-port |
| `pir-sdk-client/tests/leakage_integration_test.rs` | Privacy invariants (M-padding, Merkle item count) | check §1.5 doesn't break invariants |

Cargo.toml refs to bump (all currently `350ccc43`):

* `build/Cargo.toml:164`
* `pir-sdk-client/Cargo.toml:69`
* `runtime/Cargo.toml:78`

---

## 2. Order of attack — lowest-risk first

The cheapest sequencing is "compile-time changes first, semantic changes
second, capacity-math last." Each commit below is independently
mergeable into a `feat/onionpir-port` branch.

### Commit 1 — Bump dep + mechanical renames (compile-only) — **LANDED `4e12d0d9`**

Per §1.1 of upstream:

| Old | New |
|---|---|
| `onion_get_params_info` | `onion_params_info` |
| `onion_client_generate_galois_keys` | `onion_client_galois_keys` |
| `onion_client_generate_gsw_keys` | `onion_client_gsw_key` |
| `onion_server_set_galois_key` | `onion_server_set_galois_keys` |
| `CPirParamsInfo` | `OnionPirParamsInfo` |

BitcoinPIR's Rust call surface is almost entirely through the high-level
`onionpir::{Client, Server, KeyStore, params_info}` rather than raw
`onion_*` C symbols, so the rename impact at the Rust level is small.
The compile errors will fall out of `cargo check`. Expected fix scope:
< 20 sed-style edits across `pir-sdk-client/src/onion*.rs`,
`runtime/src/bin/{unified_server,onionpir_client,onionpir_bench}.rs`.

Note `OnionPirParamsInfo` has a new `rns_mod_count` field between
`poly_degree` and `coeff_val_cnt`. Read it but don't pretend it doesn't
exist — pattern-matches on the struct will need to be updated.

### Commit 2 — Wire format helpers (silent-bug danger zone) — **LANDED `0cf7ac21`**

Resolved by adding `pir-core::onion_unpack` with
`pack_bytes_into_coefficients` / `unpack_onion_plaintext` /
`bits_per_coeff` (45 lib tests; 8 cover the new module). Every
`decrypt_response` call site now goes through `unpack_onion_plaintext`.
The `bits_per_coeff` derivation lives at the helper level
(`entry_size * 8 / poly_degree`) so no upstream `PlainMod` field is
required.

Original notes below for historical context:


Per §1.2: SEAL `Serializable` is gone; all blobs are hand-rolled LE.
Affects every site that sends/receives query / key / response bytes —
the high-level Rust API shields most of this, but anything that
hand-builds a wire frame needs auditing.

Spots in BitcoinPIR that touch raw bytes:
* `runtime/src/bin/unified_server.rs` — INDEX / CHUNK answer payloads
  pushed over WS. The wire shape is set by `PirServer::save_resp_to_stream`
  (internal); BitcoinPIR doesn't need to know the inner format, but the
  byte count and frame boundaries matter for `[harmony-hint-*]`-style
  logging.
* `pir-sdk-client/src/onion.rs` (~line 1354, 1579) — calls
  `decrypt_response(bin, &batch[qi])`.
* `pir-sdk-client/src/onion_merkle.rs` (~line 922) —
  `sib_client.decrypt_response(target_bin, &batch[pbc_group])`.

§1.5 is the silent-bug landmine. `decrypt_response` no longer returns
unpacked bytes — it returns a raw plaintext encoded as
`[u32 N][u64 coeff_0]…[u64 coeff_{N-1}]`. BitcoinPIR's existing call sites
treat the return as `Vec<u8>` of entry bytes. **These will compile
unchanged but decode garbage.** Inverse bit-unpacking with
`bits_per_coeff = PlainMod - 1` (read `PlainMod` from `params_info`) must
be added in app code — likely a new helper in `runtime/src/onionpir.rs`
or `pir-core/src/`.

The integration doc gives the packing recipe at lines 80-94; the
unpacking is the same loop inverted.

### Commit 3 — Server-side DB build pipeline — **LANDED `8e3dcddf`**

Replaced the gen_2/3/4 `ntt_expand_entry` / `push_chunk` / `preprocess`
stubs (left by Commit 1) with the post-port flow:

  1. Pack entry bytes → `poly_degree` pre-NTT u64 coeffs via
     `pir_core::onion_unpack::pack_bytes_into_coefficients`.
  2. `Server::push_plaintexts(coeffs_flat, count, offset, &[])` (NTT
     runs internally).
  3. `Server::save_db(temp_path)` → strip the 48-byte upstream header
     into the canonical NTT-store file.
  4. Runtime adapts via `set_shared_database(slice, num_plaintexts as u64,
     index_table)` — sized for the compile-time DB shape (40448 slots),
     not the dataset-dependent `num_packed_entries`. Empty slots stay at
     `Server::new` initial state; cuckoo planner never lands on them.

**Caveat carried into commit 5b**: when `entry_size_pt (3328) <
ONIONPIR_ENTRY_SIZE / PACKED_ENTRY_SIZE (3840)`, gen_2/3/4 truncate
the tail bytes when packing. Production data is built off
`PACKED_ENTRY_SIZE = 3840`-aligned `packed.bin` files from gen_1, and
that's still the case here. The truncation loses cuckoo slots 222-255
per INDEX bin at the default config. A clean fix requires gen_1's
`PACKED_ENTRY_SIZE` to also become runtime-derived (see commit 5b
below).

Original design notes below:


§1.3 (preprocessed DB header changed) + §1.4 (`push_database_chunk` →
`push_plaintexts`).

`build/src/gen_2_onion.rs` and `build/src/gen_3_onion.rs` are the
primary touch points. They currently:
1. Build a Vec of byte-packed entries per cuckoo bin.
2. Hand them to `Server::push_database_chunk`.
3. Persist whatever the server wrote to `preprocessed_db.bin`.

Under the new API:
1. The byte→plaintext-coeff packing moves into BitcoinPIR's build code
   (recipe in upstream §1.4). `bits_per_coeff` is `PlainMod - 1` and must
   be read from `params_info` at build time, not hardcoded.
2. Call `Server::push_plaintexts(pt_flat, num_plaintexts, offset, &[])`
   instead of `push_database_chunk`.
3. `Server::save_db(path)` replaces whatever ad-hoc persistence existed.

**Once this lands, every cached `preprocessed_db.bin` is invalid.** The
6×u64 header (was 4×u64) means `load_db` returns false on pre-port
files. Production rebuild required — affects:

* `/home/pir/data/checkpoints/948454/<bins>.bin`
* `/home/pir/data/deltas/940611_948454/<bins>.bin`
* The OnionPIR Merkle tree-tops in the same dirs

Re-run the build pipeline before deploying.

### Commit 4 — Re-key clients — **LANDED**

The plan was concerned with persisted galois / GSW / secret-key blobs
becoming unparseable across the port. The audit showed that **no
component in the BitcoinPIR codebase actually persists those blobs
across a process or page lifecycle**:

| Layer | Persistence | Impact |
|---|---|---|
| `pir-sdk-client::onion::FheState` | in-memory `Vec<u8>`, dropped on session close | none |
| `runtime/src/bin/onionpir_client.rs` | freshly generated per CLI invocation | none |
| `web/src/onionpir_client.ts::fheSecretKey` | in-memory only; not written to localStorage / IndexedDB / sessionStorage | none |
| `pir-sdk-client/tests/` | tests generate keys at runtime; no committed blob fixtures | none |
| `web/src/__tests__/` | same — no committed key fixtures | none |

So the original "design a re-key UX" task is structurally moot. What
actually shipped in this commit:

1. **Diagnostic-friendly error messages** at the two `from_secret_key`
   sites (`pir-sdk-client/src/onion.rs::get_level_client` and
   `pir-sdk-client/src/onion_merkle.rs`). The post-commit-1 messages
   said only "secret key may be from a different fork rev"; commit 4
   spells out the three likely causes (ACTIVE_CONFIG drift, blob
   truncation, stale persisted key) plus a recovery procedure
   ("drop FheState + restart the session") so a future debugger of
   a failing `OnionPIR Client::from_secret_key returned None ...`
   doesn't have to retrace this audit.

2. **TS port of `pir_core::onion_unpack`** at `web/src/onion-unpack.ts`.
   The web client's WASM module is currently pre-port and ships its
   own `decryptResponse(idx, response) → entry bytes` API; when
   Commit 7 rebuilds that WASM from upstream's post-port
   `wasm/bindings.cpp`, `decryptResponse` will start returning the raw
   `[u32 N][u64 coeff_i...]` plaintext and this helper takes over the
   unpack-to-bytes step. Using BigInt for the rolling buffer (39-bit
   coefficient case requires >53 bits of state, which JS `number`
   cannot hold). Eight vitest cases mirror the eight Rust unit tests
   in `pir-core/src/onion_unpack.rs` — both pass green.

3. **Migration plan updated** to capture the audit findings so a
   future session doesn't re-design re-key flows that aren't needed.

Anything web-side that ISN'T touched here (notably the
`web/src/onionpir_client.ts` API rename from `generateGaloisKeys()` →
`galoisKeys()`, the wire-format switch, and the `.wasm` rebuild) is
explicitly Commit 7 work.

Original design notes below:


Per §1.2: all SEAL-serialized galois / GSW / secret-key blobs are
unparseable. Persisted client state must be discarded.

Spots:
* `web/src/onionpir_client.ts` exports `export_secret_key` / restore via
  `createClientFromSecretKey`. Web clients with cached secret keys (per
  `project_reconnection_work.md` in memory) will fail to restore — design
  needs a version field on the persisted blob and a "re-keying needed"
  path.
* `runtime/src/bin/onionpir_client.rs` standalone client — easy: just
  generate fresh.
* `pir-sdk-client/tests/leakage_integration_test.rs` and the wasm test
  fixtures — regenerate, no production impact.

### Commit 5 — Capacity math sweep — **CLIENT-SIDE LANDED `f0399024`**

Client-side hardcoded `PACKED_ENTRY_SIZE = 3840` constants replaced
with `packed_entry_size()` helpers that read
`onionpir::params_info(0).entry_size` at runtime. Touched
`pir-sdk-client/src/onion.rs` (the public client) and
`runtime/src/bin/onionpir_client.rs` (the standalone CLI). After commit
2's `onion_unpack` lands, the decoded bin is exactly
`pinfo.entry_size` bytes, so the pre-port "if len ≥ PACKED_ENTRY_SIZE
then trim else full" guard collapses to just hashing the full slice.

### Commit 5b — Build-pipeline capacity math — **LANDED**

Removed the four hardcoded `3840` constants from the build pipeline
and replaced them with runtime reads of
`onionpir::params_info(0).entry_size`. After this commit, every
on-disk artifact (`onion_packed_entries.bin`,
`onion_shared_ntt.bin`, per-group `preprocessed_db.bin`, Merkle
tree-tops, sibling level NTT stores) is sized for whatever
`ACTIVE_CONFIG` the linked `onionpir` crate was built with:

  CONFIG_N2048_K1 (default post-port): 3328 B/entry, 221 slots/INDEX bin, ARITY=104
  pre-port (PlainMod=15):              3840 B/entry, 256 slots/INDEX bin, ARITY=120

Specific changes:

* **gen_1_onion.rs** — `const PACKED_ENTRY_SIZE: usize = 3840` →
  `fn onion_entry_size()` helper. `Packer` gained an `entry_size`
  field plumbed through its ctor; all internal slicing /
  flush-on-full logic uses `self.entry_size`. Display strings
  updated.

* **gen_3_onion.rs** — `const ONIONPIR_ENTRY_SIZE` + `SLOTS_PER_BIN`
  removed. `serialize_cuckoo_bin` return type flipped from
  `[u8; ONIONPIR_ENTRY_SIZE]` (fixed-size array, needs const) to
  `Vec<u8>` (length = `entry_size`). `build_index_cuckoo` now takes
  `slots_per_bin` as a parameter. Metadata file writes the runtime
  `slots_per_bin` value (downstream readers — runtime + sdk-client —
  already consume this as runtime data).

* **gen_4_build_merkle_onion.rs** — `const ARITY: usize = 120` →
  `fn onion_merkle_arity()` (= `entry_size / 32`). Pinning ARITY to
  the OnionPIR plaintext size ensures each internal Merkle node's
  ARITY × 32 child hashes fit in exactly one plaintext. Default
  config: ARITY=104. Tree depth, sibling-proof shape, and
  tree-top cache layout all flow from the new arity. The metadata
  writeout publishes the runtime arity so client-side
  `parse_onionpir_merkle` picks it up automatically.

* **gen_2_onion.rs** — commit-3's truncation guard
  (`take_bytes_per_entry = entry_size_pt.min(PACKED_ENTRY_SIZE)`)
  removed. Replaced with an `assert_eq!(packed_entry_size,
  entry_size_pt)` cross-check; a mismatch means a stale `packed.bin`
  from a different `onionpir` rev is being read. Same hardening
  applied to gen_4's push loop.

Surviving hardcoded 3840 / ARITY=120:

  build/src/test_merkle_verify_onion.rs — test-only binary that
  verifies pre-built Merkle output. It still has
  `const ARITY: usize = 120` + `const PACKED_ENTRY_SIZE: usize = 3840`.
  Reading those from the tree-top metadata file (which `gen_4` now
  writes correctly with the runtime arity) is a future tidy-up;
  outside the production cut-over critical path.

Verification:

  cargo check --workspace                     ✅
  cargo test -p pir-core --lib                45/45 ok
  cargo check -p build --bin {gen_1,gen_2,gen_3,gen_4_build_merkle}_onion ✅
  npx vitest run in web/                      158/160 ok

Production rollout (what to do once this branch merges):

  1. Build the post-port `unified_server` on Hetzner pir1 via the
     existing `pir-hetzner` skill's deploy recipe.
  2. On a build host (NOT pir1 — needs the Bitcoin chainstate),
     re-run gen_1 → gen_2 → gen_3 → gen_4 to produce a fresh
     `checkpoints/<height>/` tree with entry_size=3328 artifacts.
  3. `rsync` the new tree to pir1; edit
     `/home/pir/data/databases.toml` to point at the new checkpoint.
  4. `systemctl restart pir-primary pir-secondary`.
  5. Smoke a known-good scripthash via pir.chenweikeng.com against
     the post-port WASM (already deployed by commit 7).

Original design notes below:

Per §4-§5 of upstream. New defaults:

| | Old | New |
|---|---|---|
| `entry_size` | 3840 B | 3328 B |
| `num_plaintexts` | 65536 (2¹⁶) | 40448 (not pow2) |
| `fst_dim_sz` | 256 | 512 |
| `other_dim_sz` | 256 | 79 |
| `db_size_mb` | ~245 MB | ~128 MB |

Action items:
1. `docs/onionpir_plan.md` references `EntrySize = 3840 bytes` in the
   first global-constant section. Refresh once `params_info(0)` is the
   single source of truth.
2. `rg "3840|65536|2 \*\* 16|1 << 16"` in `build/src/gen_*onion.rs` —
   replace any hardcoded constants with reads from
   `onionpir::params_info(num_entries)`. Initial grep is clean
   (no hardcoded `65536` in onion-related files today), but verify
   per-file once the rev bumps.
3. Cuckoo planner load-factor / hash-count tuning. The pre-port build
   used `6 hashes, 65536 bins, load ~0.65`. With the new ~40 K bin
   count at the same load factor, insertion-failure rate rises. Re-fit
   empirically via the existing build pipeline. Touches:
   * `build/src/gen_1_onion.rs` (or wherever the cuckoo plan lives)
   * `pir-core/src/cuckoo*.rs` if the constants are shared with the
     client.
4. **Verify no bitmask modular reduction.** Initial grep
   (`entry_id & (num_bins - 1)`-style patterns) over onion files came
   back clean, but re-audit after rev bump — anything that compiled
   under power-of-2 assumptions is a silent-decode bug.

### Commit 6 — SharedKeyStore audited / QueryQueue declined — **LANDED**

**SharedKeyStore (§2.1):** zero code change required. Commit 1's
mechanical-rename sweep already updated every `KeyStore` call site
in `runtime/src/bin/unified_server.rs` to the post-port shape:

  Old (pre-port)                        New (post-port, in tree today)
  -------------------------------       -----------------------------------
  KeyStore::new(0)                      KeyStore::new()
  key_store.set_galois_key(id, &g)      key_store.set_galois_keys(id, &g)
  key_store.set_gsw_key(id, &g)         key_store.set_gsw_key(id, &g)   (no rename — singular kept)
  server.set_key_store(&store)          server.set_key_store(Some(&store))

Upstream KeyStore (`/Users/cusgadmin/.cargo/git/checkouts/.../92fceb0/rust/onionpir/src/lib.rs:392-440`)
exposes additional methods that BitcoinPIR doesn't currently use:

  has_client(id) -> bool                — proactive existence check
  remove(id)                            — explicit eviction
  size() -> u64                         — for telemetry / capacity alarms

These would be useful additions for telemetry once the 100-client LRU
cap becomes visible in production traffic. Not adopted now because the
existing tracing instrumentation doesn't surface KeyStore-level
metrics; deferring until profile data justifies the wiring.

**QueryQueue (§2.2): declined.** Cost-benefit assessment:

  Benefit: parallelize multiple concurrent OnionPIR queries through
           one Server handle, replacing the per-DB worker-thread
           mpsc serialization in unified_server.rs.

  Cost:    non-trivial restructuring of the OnionPIR worker loop;
           introduces internal worker-thread management (the upstream
           QueryQueue spawns its own worker pool, separate from
           tokio's runtime); changes how cancellation + back-pressure
           work; requires careful coexistence with the existing
           `tokio::task::spawn_blocking` paths.

  When it pays off:
           - High concurrent-client count per OnionPIR DB.
           - Server CPU underutilized when a single client query is
             stalled on I/O.

  When it doesn't:
           - pir1 today (single i7-8700, low concurrent OnionPIR
             client count). The FHE compute itself (~10 s/query at
             INDEX level, ~5 s at CHUNK) dominates wall time; serial
             dispatch through mpsc is a rounding error.
           - Pre-existing tokio + per-DB worker thread model already
             handles multi-client serialization correctly; QueryQueue
             would be parallel-redundant with that.

QueryQueue stays available in the dep for future use — the upstream
crate's public API is unchanged. If pir1's concurrent client count
grows enough to make the per-DB serialization a bottleneck, the
migration is straightforward (one place to change in
unified_server.rs's PIR worker thread).

Original design notes below:

Per §2.1-§2.3. BitcoinPIR's `unified_server.rs` already uses
`onionpir::KeyStore` (`[SharedKeyStore]` log lines visible in prod).
After the port that import becomes upstream's *new* `SharedKeyStore`
which is more polished — verify behavior, then optionally migrate to
the async `QueryQueue` for the unified-server hot path. Not a
correctness requirement; an optimization.

### Commit 7 — WASM client A/B — **LANDED (Option B)**

Picked Option B (port the hand-rolled TS to the new wire formats)
because `web/src/onionpir_client.ts` carries BitcoinPIR-specific
cuckoo-planning + protocol-encode logic layered on top of the
OnionPIR primitive. Option A ("replace TS entirely with upstream
WASM") would have required reimplementing all of that.

What landed:

1. **WASM artifact swap.** `web/public/wasm/onionpir_client.js` (pre-
   port, UMD with `globalThis.createOnionPirModule` factory) replaced
   by `onionpir_client.mjs` (post-port, ES module with default-export
   factory). `.wasm` blob refreshed. `.d.ts` swapped to match
   upstream's hand-written declarations (post-port `OnionPirClient`,
   `paramsInfo()`, `createClientFromSecretKey`).

2. **Module loader rewrite.** The `<script src="/wasm/onionpir_client.js">`
   tag in `web/index.html` is gone; `web/src/onionpir_client.ts::loadWasmModule`
   now dynamic-imports the `.mjs` at runtime (with a
   `globalThis.__onionpirWasmFactory` test hook for node tests).

3. **API-rename sweep across `web/src/onionpir_client.ts`** (~14 sites):
   * `new OnionPirClient(numEntries)` → `new OnionPirClient()` (3 sites)
   * `createClientFromSecretKey(numEntries, clientId, sk)` → `createClientFromSecretKey(clientId, sk)` (3 sites — now `OnionPirClient | null`, with explicit null-check at each call)
   * `paramsInfo(numEntries)` → `paramsInfo()` (3 fresh calls inside the decrypt loops)
   * `generateGaloisKeys()` → `galoisKeys()`
   * `generateGswKeys()` → `gswKey()`
   * `decryptResponse(idx, response)` → `decryptResponse(response)` (3 sites — caller now bit-unpacks)

4. **Cuckoo key encoding flip.** Upstream's post-port
   `buildCuckooBs1` accepts `Float64Array` (treated as u64 bytes)
   instead of `Uint32Array` lo/hi pairs. New helper
   `buildCuckooKeysFloat64()` writes via `BigUint64Array` over a
   shared `ArrayBuffer`, returns a `Float64Array` view of the same
   bytes. The Merkle sibling cuckoo block uses the same idiom inline.

5. **`unpackOnionPlaintext` wired into all three `decryptResponse`
   sites** (INDEX bin, CHUNK bin, sibling Merkle bin) using the
   TS port from commit 4. The runtime
   `wasmParams.polyDegree` / `wasmParams.entrySize` are read fresh
   per-round so the byte-stream interpretation tracks whatever
   ACTIVE_CONFIG the WASM was built with. The legacy
   `PACKED_ENTRY_SIZE = 3840` constant is retained as a defensive
   upper bound: actual slice lengths are `min(entryBytes.length,
   PACKED_ENTRY_SIZE)`, so e.g. `CONFIG_N2048_K1`'s 3328-byte
   bins don't read past the end.

6. **Node-test loader update.**
   `web/src/__tests__/onion_leakage_diff.test.ts` switched from
   `createRequire()` + `globalThis.createOnionPirModule` to
   `await import(file://...)` + `globalThis.__onionpirWasmFactory`
   (matching the runtime hook). Test is still skipped without
   `RUN_LIVE_DIFF=1` — same skip semantics as pre-port.

Verification:
  `cargo check --workspace`           ✅
  `npx tsc --noEmit` in web/          ✅
  `npx vitest run` in web/             158/160 ok (2 skipped: live diff)

Not touched in this commit (still open):

  * **Commit 5b**: build-pipeline capacity math sweep (gen_1's
    hardcoded `PACKED_ENTRY_SIZE = 3840` + gen_3's fixed-size
    array). Truncation issue remains.
  * **Commit 6**: SharedKeyStore / QueryQueue migration on the
    server side — optional.
  * **WASM rebuild on Hetzner-deployed binary**: the runtime crate
    is already on post-port via the cargo dep bump in commit 1; the
    .wasm copied here is for the web client only.

Original design notes below:


Pre-port the situation was: SEAL didn't compile to wasm32, so BitcoinPIR
shipped a hand-rolled TS reimplementation at `web/src/onionpir_client.ts`.
After the port, upstream ships a real WASM client at
`bitcoin-pir/OnionPIRv2/wasm/` (Phase 3, commit `b048ca9`).

Two choices:

* **A — Replace `onionpir_client.ts` with upstream's WASM module.**
  Eliminates a several-thousand-line hand-rolled crypto path that's been
  a maintenance burden. Loses any BitcoinPIR-specific tweaks layered on
  top; needs an adapter shim to match `web/src/types.ts`.
* **B — Port `onionpir_client.ts` to the new wire formats.** Keep the
  hand-rolled client, just teach it the new LE serialization + raw-
  plaintext decrypt output. Less churn, but the hand-rolled crypto stays.

Recommend **A** if the WASM module's `paramsInfo`, `OnionPirClient`,
`createClientFromSecretKey` cover BitcoinPIR's needs. The migration cost
of A is higher up-front but pays back in halved code maintenance and
zero risk of TS / Rust crypto drift.

---

## 3. Risk classification

| Class | Behavior | Examples | Mitigation |
|---|---|---|---|
| Compile-fail | Rust compiler refuses to build until call sites match | C ABI rename mismatches | `cargo check`; sed-style fixes |
| Silent decode bug | Compiles + sends/receives the right shape but decodes garbage | `decrypt_response` returning raw plaintext but treated as entry bytes | Integration test against a known-good UTXO; assert decoded bytes match expected |
| Server-rejects | New protocol; old binaries answer with garbage / error | `preprocessed_db.bin` version-bump | `load_db` returns false → easy to detect at startup |
| Privacy invariant | Wire shape changed → previously-padded queries leak metadata | CHUNK Merkle item count if M-padding shifts | Run the leakage integration tests (§ in `CLAUDE.md`) post-port |

Every commit should pass:
* `cargo build -p pir-sdk-client --features onion --tests`
* `cargo test -p pir-sdk-client --features onion --lib`
* `cargo test -p pir-sdk-client --features onion --test leakage_integration_test`
* `cargo build --release -p runtime --bin unified_server`

before going to Hetzner.

---

## 4. Production rollout

After the rev bump lands on `main`:

1. Rebuild every `preprocessed_db.bin` on a build host (not on pir1 —
   the rebuild needs a full Bitcoin chainstate and is too disruptive
   to mix with prod traffic). Verify by `Server::load_db()` returning
   `true`.
2. `rsync` the new DB dirs to Hetzner:
   * `/home/pir/data/checkpoints/<height>/` (new)
   * `/home/pir/data/deltas/<base>_<tip>/` (new)
3. Edit `/home/pir/data/databases.toml` to point at the new dirs
   (per `.claude/skills/hetzner-pir/SKILL.md`'s "Swap databases" recipe).
4. `cargo build --release -p runtime --bin unified_server` on pir1.
5. `systemctl restart pir-primary pir-secondary`. Verify
   `journalctl -u pir-primary --since now | grep "Loaded"` shows the
   new DBs and that V2 hint pool initialises against them.
6. Verify the web client at `pir.chenweikeng.com` decodes correctly
   — pick a known-good scripthash (one whose UTXO set is independently
   verifiable via mempool.space).

The web client deployment to GitHub Pages happens automatically via the
existing GH Actions, but make sure the WASM bundle that ships matches
the rev of `pir-sdk-wasm` that was built.

---

## 5. Open questions

1. **`KeyStore` collision** — `runtime/src/bin/unified_server.rs:42`
   already imports `KeyStore` from the pre-port `onionpir` crate. Does
   that name still exist in the post-port API, or is the symbol
   `SharedKeyStore` now? Re-check after rev bump.
2. **Tagging strategy** — `v2.1.0` in the upstream fork is *pre-port*
   (commit `e28d300`, before Phase 1). The next post-port tag will need
   a new major (`v3.0.0`-ish). Coordinate the tag name before BitcoinPIR
   pins it.
3. **Cuckoo re-tuning** — the new `num_pt ≈ 40448` may push hash count
   from 6 → 7 or 8 to maintain >99% insertion success at the existing
   load factor. Empirical fit needed; document the chosen parameters in
   `docs/onionpir_plan.md` once decided.
4. **WASM client decision** — A vs. B in §2 Commit 7. Pick before
   starting work; the integration tests differ.

---

*This doc is the BitcoinPIR-side migration map. Read upstream
`INTEGRATION.md` first for the OnionPIRv2 API spec — that's the source
of truth, this is the call-site overlay.*
