# OnionPIRv2 Port Migration — BitcoinPIR side

Companion to upstream's [`INTEGRATION.md`](../../bitcoin-pir/OnionPIRv2/INTEGRATION.md)
(absolute path: `/Users/cusgadmin/bitcoin-pir/OnionPIRv2/INTEGRATION.md`).

The upstream `onionpir` crate was rebuilt to track the SEAL-free upstream
fix for the GHS / "special prime" key-switching issue
(ePrint 2025/1142 revision). BitcoinPIR currently pins
`350ccc43e41338264aefabf80f639f23ea34f3ee`, which is the upstream
`pre-port` tag — i.e. **BitcoinPIR is still on the old SEAL-based code.**
The 77 post-port commits exist only in the user's local OnionPIRv2 working
copy and have not been pushed to the GitHub fork.

This doc maps the integration spec onto BitcoinPIR's actual call sites so
the migration can be done one ordered commit at a time. It does **not**
describe the post-port API itself — read upstream's `INTEGRATION.md` for
that. This is the BitcoinPIR-specific punch list.

---

## 0. Blocking step (operator)

Push the local OnionPIRv2 work to the GitHub fork before any of the
code-side migration below can land.

```
cd /Users/cusgadmin/bitcoin-pir/OnionPIRv2
git push origin main
# Optional but recommended: tag a fresh release so the BitcoinPIR dep
# can pin something stable instead of a moving HEAD.
git tag v3.0.0   # next available tag — v2.1.0 is pre-port
git push origin v3.0.0
```

Local OnionPIRv2 HEAD at time of writing: `92fceb01` (`docs:
INTEGRATION.md for downstream consumers`).

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

### Commit 1 — Bump dep + mechanical renames (compile-only)

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

### Commit 2 — Wire format helpers (silent-bug danger zone)

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

### Commit 3 — Server-side DB build pipeline

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

### Commit 4 — Re-key clients

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

### Commit 5 — Capacity math sweep

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

### Commit 6 — Wire up SharedKeyStore / QueryQueue (optional)

Per §2.1-§2.3. BitcoinPIR's `unified_server.rs` already uses
`onionpir::KeyStore` (`[SharedKeyStore]` log lines visible in prod).
After the port that import becomes upstream's *new* `SharedKeyStore`
which is more polished — verify behavior, then optionally migrate to
the async `QueryQueue` for the unified-server hot path. Not a
correctness requirement; an optimization.

### Commit 7 — WASM client decision (special)

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
