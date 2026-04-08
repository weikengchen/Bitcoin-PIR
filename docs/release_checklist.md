# Release Checklist — Whitepaper

> **Status (2026-04-08):** OnionPIR delta support landed in `f699d79`.
> All 12 backend × mode cells (DPF / HarmonyPIR / OnionPIR × MAIN / MAIN-MERKLE
> / DELTA / DELTA-MERKLE) are green and validated end-to-end against
> `delta_940611_944000`, scripthash `20d920103ecb721638eb43f3e7a27c7b8ed3925b`.
> Known remaining issues are listed at the bottom of this file.


## Factual accuracy (high priority)
- [ ] **Merkle construction details.** Verify the leaf formula `SHA256(u32le(i) || bin_content)` matches `pir-core/src/merkle.rs` (or wherever `computeBinLeafHash` lives) — in particular, confirm endianness, that the index really is `u32` not `u64`, and that there is no separator byte between index and bin content.
- [ ] **Merkle arity = 8.** Confirm `BUCKET_MERKLE_ARITY` in `web/src/constants.ts` and the matching Rust constant.
- [ ] **Sibling row size = 256 B = 8 × 32 B.** Cross-check against the slot_size in `runtime/src/table.rs` per-bucket Merkle loaders.
- [ ] **Tree-tops = 9.1 MB, sibling data = 4.6 GB.** These are quoted numbers — re-measure against the current on-disk files before release. `ls -la /Volumes/Bitcoin/data/.../merkle_bucket_*`.
- [ ] **INDEX ~565K bins, CHUNK ~1.06M bins.** Check current actual bin counts — the whitepaper now cites these for HarmonyPIR hint budget.
- [ ] **HarmonyPIR hint budget ~530 / ~730** per group. Recompute `M = N/T = N/floor(sqrt(2N).round())` for both current bin counts.
- [ ] **Dust threshold `≤ 576`** and `MAX_UTXOS_PER_SPK = 100`. Confirm they still match `build/src/gen_1_onion.rs`.
- [ ] **OnionPIR numbers** (3840 B entry, ~815K entries, ~95.9% packing, 24 GB with shared store). These weren't touched in this pass, but they are easy to let drift — worth re-verifying against the current build output.

## Protocol & wire format
- [ ] **Wire codes table.** The deployment section now lists every code `0x01, 0x02, 0x04, 0x11, 0x21, 0x33, 0x34, 0x40–0x43, 0x51–0x56`. Grep `runtime/src/protocol.rs` and `runtime/src/onionpir.rs` for any new codes added since and update.
- [ ] **`db_id` byte backward compatibility.** The paper claims "requests without the trailing byte are routed to `db_id=0`". Verify this is actually true for all relevant handlers in `unified_server.rs` (INDEX_BATCH, CHUNK_BATCH, `0x33`, `0x34`).
- [ ] **Catalog entry fields.** Make sure the paper's list of `DatabaseCatalogEntry` fields matches `runtime/src/protocol.rs` exactly (and matches `web/src/server-info.ts`).
- [ ] **`GET_INFO` `"databases"` array.** Re-read `server_info_json()` in `unified_server.rs` and confirm the field names (arity, level sizes, per-group roots, super-root, tree-top hash) are what the paper says.

## Section 6 (Merkle) — content pass
- [ ] **Read Section 6 end-to-end.** Confirm the verification walk (steps 1–5) matches the actual code path in `web/src/merkle-verify-bucket.ts::verifyBucketMerkleBatchDpf` and `runtime/src/bin/client.rs`. Specifically: is the tree-top cache fetched *before* the leaf is computed, or lazily? Does the client verify the `tree_tops_hash` from `GET_INFO` or from another source?
- [ ] **"Walk the tree, one level at a time."** Verify that the number of levels and the fetch granularity match — does the client really issue one DPF-PIR batch *per level*, or is it batched across levels?
- [ ] **Synthetic dummies for Merkle queries.** The paper says "synthetic dummies for unused groups, exactly as in the main protocol" — confirm this is what the code does.
- [ ] **"DPF as uniform integrity primitive."** The paper says sibling verification uses DPF even when the main data was retrieved via HarmonyPIR. Double-check this in the web HarmonyPIR path.
- [ ] **Selective failure coverage.** Think once more about whether per-group Merkle + DPF-queried siblings actually defeat selective failure, or only the weaker "honest-server malicious-data" case. The paper currently implies the former — if that's an overclaim, soften it.

## Section 7 (Delta) — content pass
- [ ] **Read Section 7 end-to-end.** Especially the wire format: does the code serialize `[num_spent][spent entries][num_new][new entries]` in that order? (Cross-check `decodeDeltaData` in `web/src/codec.ts` and the Rust build pipeline.)
- [ ] **"Spent list omits amount."** Verify — this is a design claim worth double-checking in `build/src/delta_gen_0_compute_delta.rs`.
- [ ] **Dust filter applied to both sides of delta.** The paper claims this — confirm the code path.
- [ ] **Catalog `name` format.** The paper uses "`delta_940611_944000`" as an example; confirm the naming convention in a current `databases.toml`.

## Section 8 (Deployment) — content pass
- [ ] **Figure 3.** Visually check that the new primary/secondary diagram renders correctly and the caption still makes sense.
- [ ] **Sync planner BFS with cap=5.** Confirm `MAX_DELTA_CHAIN_LENGTH = 5` in `web/src/sync.ts` hasn't moved.
- [ ] **"95 seconds to rebuild NTT".** Re-measure if you can; otherwise just mark it as "approximately".
- [ ] **Electrum plugin backends.** Verify the three backend names ("DPF 2-Server", "HarmonyPIR 2-Server", "OnionPIRv2 1-Server") match what the actual settings dialog shows.

## Terminology consistency
- [ ] **Global grep for `bucket`.** After the rename pass, only a small number of legitimate references should remain (e.g., `HarmonyBucket` class name, `merkle_bucket_*` file names, the history note in Section 6). Scan the final PDF text for any I missed.
- [ ] **`bin` vs `slot` vs `group`.** Particularly in figures and table captions. The terminology is now load-bearing, so a reader who conflates the three will be confused.
- [ ] **"Group" meaning** — ensure it always means "PBC group" in the paper. If it ever means "grouped UTXOs under one script hash" (old use in part 1), reword.

## Citations & bibliography
- [ ] **`refs.bib`.** No new references were added in this pass, but if you plan to cite any of the ALF/FastPRP papers in the Merkle section, double-check they're in there.
- [ ] **Broken cites.** Run the build once and confirm no `LaTeX Warning: Citation X undefined` survives the final pass.
- [ ] **Broken refs.** Same for `\ref{...}` — every new label (`sec:merkle`, `sec:delta-db`, `sec:deployment-catalog`) should resolve.

## Presentation & build
- [ ] **Page count and flow.** 29 pages now — skim the whole PDF once to catch section-break pages and awkward figure placements.
- [ ] **Overfull hboxes.** Four small ones remain (≤ 8 pt), all from unbreakable `\texttt{}` identifiers. Probably fine, but if you want them gone, either add `\allowbreak` inside the identifiers or wrap the paragraphs in `\sloppy`.
- [ ] **Figure 1 and Figure 3.** Recompile and visually check both — I changed labels in Figure 1 and redrew Figure 3.
- [ ] **Table 1.** Column header was renamed "Buckets → Groups" and cuckoo column text changed from `bs=4` to `4 slots/bin`. Verify the table still fits the page width.
- [ ] **Date on the title page.** `\date{March 2026}` — update before release.
- [ ] **Author list & affiliation** — still just you? Any co-authors to add for this version?
- [ ] **Acknowledgments** — anyone new to thank for the Merkle or delta work?

## Scope honesty / "deferred" items
- [x] **OnionPIR + per-group Merkle.** ✓ Landed earlier; per-bin two-tree design with `merkle_onion_{index,data}_*` files (eccdf36 and earlier).
- [x] **OnionPIR for delta DBs.** ✓ Landed in `f699d79` (2026-04-08) — full e2e including per-DB Merkle. Paper's Section 7 should be updated to describe this; currently silent or deferred.
- [x] **HarmonyPIR multi-DB routing.** ✓ Landed in `0839b8d` + `4fd54f6` + `737bb90` — `handle_harmony_*` threads `db_id` correctly, web tab has a selector, delta Merkle verification works.
- [ ] **Web UI auto-sync.** `computeSyncPlan` exists + is tested + wired into the DPF tab (`d5d1b07`). There is still a **page-refresh persistence bug**: if the user reloads mid-sync, the map of merged snapshots is empty but `localStorage` still has `lastSyncedHeight`, so `computeSyncPlan` returns a delta-only plan that merges onto nothing. Cleanest fix: detect empty in-memory snapshot in `planSync()` and force a full-checkpoint + delta-chain plan.
- [ ] **Merkle for delta DBs not built by default.** Paper says so — make sure the default is genuinely "off" in the pipeline scripts.

## Code release readiness (if the paper release is tied to a code tag)
- [x] **`git status` is clean.** OnionPIR delta work committed as `f699d79` (2026-04-08).
- [ ] **`cargo build --release` succeeds** for all binaries, not just `unified_server`.
- [ ] **`cd web && npm test` — all tests pass.** (Last confirmed before the OnionPIR delta work; two pre-existing errors in `ws.test.ts` and `harmonypir_worker.ts` are unchanged.)
- [x] **`databases.toml` in the example data dir** — has both main + delta entries; `start_pir_servers.sh` auto-detects it.
- [ ] **README or CHANGELOG** entry for the release, if you maintain one.

## Final sanity passes
- [ ] **Read the abstract-ish paragraph at the start of the introduction** and ask: if I only read this, would I know the system supports Merkle integrity and incremental sync? If not, add one sentence.
- [ ] **Read the "When to Use Which Protocol" subsection** and ask: does the guidance still hold now that incremental sync is an option? Maybe a fourth bullet: "**Returning clients with existing state:** regardless of protocol, use the delta sync path (Section 7) to avoid re-downloading the full UTXO view."
- [ ] **Read the acknowledgments.** Still accurate? Any advice received on Merkle or deltas worth crediting?
- [ ] **Open the final PDF on the device a reviewer would use.** Fonts, hyperlinks, figure legibility.

---

## Known Remaining Issues (2026-04-08, post `f699d79`)

These are the rough edges a tester opening the GitHub Pages web client against
a production server might hit. None of them block the deploy — the system is
safe to expose for external testing.

### Deployment steps
1. **Web client** — auto-deployed by `.github/workflows/deploy-web.yml` on every
   push to `main`. `f699d79` is already published via GitHub Pages (run
   succeeded in ~1 min). No manual action needed.
2. **Production PIR server(s)** — on the host serving `pir1.chenweikeng.com`:
   ```bash
   git pull
   ./scripts/start_pir_servers.sh
   ```
   `start_pir_servers.sh` auto-rebuilds via `cargo build --release`, kills any
   stale servers on ports 8091/8092, and auto-picks up `databases.toml` if
   present in the default data dir. After a rebuild from `f699d79`, the new
   binary serves OnionPIR delta via `db_id != 0` without the old Merkle gates.
3. **Delta OnionPIR data files** — if they don't already exist on the
   production host, run `./scripts/build_delta_onion.sh 940611 944000` (after
   `build_delta.sh` for the same range). Produces ~2.6 GB of
   `onion_*.bin` + `merkle_onion_*.bin` under
   `/Volumes/Bitcoin/data/deltas/940611_944000/`. Server boot will log
   `[OnionPIR:delta_940611_944000] ... servers ready (bins=...)` when they're
   loaded.

### Non-blocking UX issues
- **DPF sync page-refresh bug.** If a user reloads the DPF tab mid-sync, the
  in-memory snapshot map is empty but `localStorage.bitcoinpir.dpf.lastSync:*`
  still holds `lastSyncedHeight`, causing `computeSyncPlan` to return a
  delta-only plan that merges onto nothing. Fix: detect empty in-memory
  snapshot in `planSync()` and force a full-checkpoint + delta-chain plan. Does
  not affect HarmonyPIR or OnionPIR tabs.
- **Delta queries look empty for random inputs.** The delta database only
  holds scripthashes that were *spent or funded* between heights 940,611 and
  944,000, so pasting a random unrelated address against the delta DB will
  correctly return 0 results — which may look like a bug to a first-time
  tester. The main DB at height 940,611 is the right target for general "does
  this address have UTXOs" exploration.
- **`window.opClient` dev hook shipped in production.** Added to
  `web/index.html` in `f699d79` so `preview_eval` / DevTools can drive the
  OnionPIR client directly (`setDbId`, `setScriptHashOverrideForNextQuery`,
  etc.). Harmless — no production UI depends on it — but should eventually be
  gated behind `import.meta.env.DEV` before a formal release.
- **Housekeeping.** 4 leftover worktrees under `.claude/worktrees/agent-*`
  from the multi-agent merge session. Agent B's worktree (`agent-a8c68f41`)
  has uncommitted leftovers already on main so removal needs
  `discard_changes: true`. Other three are clean apart from `web/node_modules`.

### Browser yield pitfall (fixed in `f699d79` but noted for future work)
`onionpir_client.ts` originally yielded via
`await new Promise(r => setTimeout(r, 0))` in nine places. Chromium throttles
`setTimeout(0)` in background / hidden tabs to ≥1 s (measured 10+ s), turning a
52 ms tight loop into a 20+ minute stall. Fixed by replacing all nine yield
sites with a `yieldToMain()` helper that uses `MessageChannel.postMessage`,
which is not subject to timer throttling. `harmonypir_client.ts` and
`client.ts` do **not** have this pattern (verified 2026-04-08) — but any new
hot-loop yield point should use `yieldToMain()` / a similar helper, not
`setTimeout(0)`.
