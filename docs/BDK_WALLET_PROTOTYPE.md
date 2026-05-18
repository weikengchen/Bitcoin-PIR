# BDK-Based PIR Wallet — Design Notes & Prototype Plan

> Status: design notes drafted 2026-05-08. No code yet. Successor to the
> Electrum plugin path.

## Background

The existing `electrum_plugin/` is hitting structural friction:

- Electrum's plugin API isn't designed for "the network layer is something
  completely different." `pir_synchronizer.py:260-267` has to fake an
  Electrum-server-style flow to inject discovered UTXOs via
  `adb.receive_tx_callback()`, which is an internal API plugins shouldn't
  really drive.
- HarmonyPIR's per-session consumed-hint state has no natural home in
  Electrum's wallet lifecycle. `pir_harmony_client.py:518`
  (`restore_hints_from_cache`) silently drops per-group state, which
  violates HarmonyPIR's invariants.
- The plugin is Python-with-Rust-FFI and the Cargo path is broken
  (`electrum_plugin/harmonypir-python/Cargo.toml:17` references a path
  that doesn't exist).

The structural problem in one sentence: Electrum's plugin model assumes
**per-scripthash request/response**, which is exactly what PIR is
designed *not* to do (we batch into K-padded rounds for privacy). Every
integration point fights this assumption.

## Decision: pivot to BDK

[BDK 1.0+](https://bitcoindevkit.org) is data-source-agnostic by design:
the `Blockchain` trait was removed in the 1.0 redesign, replaced by a
request/response pattern in `bdk_chain::spk_client`. The wallet author
implements their own client; the wallet calls `apply_update(update)`
when they have one.

For our case this means:

- Same language as `pir-sdk-client` (Rust). No FFI boundary.
- Lifecycle of the chain client is fully under our control —
  HarmonyPIR's hint state lives where it should.
- We get HD descriptors, BIP-compliant coin selection (BnB,
  oldest-first, largest-first), PSBT v0, fee bumping, Taproot, and
  multisig out of the box.
- Wasm path is proven (MetaMask ships a `bdk-wasm` snap), so the
  existing `web/` frontend remains a viable target.

What we lose: PSBT v2 (not yet in `bdk_wallet`), the existing
Electrum-user audience, and any reference desktop wallet to fork. None
of these matter for a research/test wallet.

## BDK integration model — what to know before coding

### The `SyncRequest` / `FullScanRequest` pattern

The integration contract is in `bdk_chain::spk_client`:

```text
SyncRequest<I>     ─┐                    ┌─ SyncResponse { tx_update, chain_update }
                    ├─→  PirChainClient ─┤
FullScanRequest<K> ─┘                    └─ FullScanResponse { tx_update, last_active_indices, chain_update }
```

We implement methods like `client.full_scan(request, stop_gap)` and
`client.sync(request)`; the call site mirrors
`bdk_esplora::EsploraExt::full_scan(...)` exactly. The reference
implementation is
[`bitcoindevkit/bdk/crates/esplora/src/blocking_ext.rs`](https://github.com/bitcoindevkit/bdk/blob/master/crates/esplora/src/blocking_ext.rs).

`TxUpdate<A>` is the contract: `txs`, `txouts`, `anchors` (chain
positions), `seen_ats` (mempool sightings — leave empty for confirmed-only),
`evicted_ats`. `CheckPoint` is the chain-tip update.

### The architectural rule: don't fan out per-script

`bdk_esplora` and `bdk_electrum` both fan out per-scripthash — one
HTTP/Electrum call per script, parallelized. **Do not template off
this.** If our `PirChainClient` calls the PIR transport once per
scripthash inside `iter_spks_with_expected_txids()`, we burn one PIR
session per scripthash and shred the K-padded privacy budget.

Correct shape:

1. Drain `iter_spks_with_expected_txids()` to a buffer.
2. Run all scripthashes through PIR's K-padded batched rounds (existing
   `pir-sdk-client::query_index_phase_batched` etc).
3. Assemble `TxUpdate` once at the end.

The request iterators are synchronous + in-memory, so this is
straightforward — just resist the urge to call the transport in the
iterator loop.

This is structurally the same impedance that makes the Electrum plugin
awkward, but BDK gives us the buffer-then-batch escape hatch cleanly.

### Headers, fees, mempool — all decoupled

- `chain_update: Option<CheckPoint>` is populated independently of
  script work. Headers can come from a separate cheap oracle.
- Fees come through `TxBuilder::fee_rate()`, application-driven. No
  `FeeEstimator` trait in 1.0.
- Mempool is opt-in: leaving `seen_ats` empty puts the wallet in
  confirmed-only mode and the UI degrades gracefully. PIR snapshots are
  inherently confirmed-only, so this fits.

## Reuse from `bdk_kyoto`

`bdk_kyoto` is the closest privacy-oriented precedent — a thin glue
layer over `bip157` (the renamed kyoto core) that exposes a
typestate-builder + channel-based update pattern.

### Worth copying (with file references)

| Pattern | Location | Adapt to |
|---|---|---|
| Typestate progression `Idle → Subscribed → Active` | `src/lib.rs:127-138` | `Idle → Connected → Querying` |
| `update().await -> bdk_wallet::Update` channel | `src/lib.rs:298-305` | Same shape, fewer emissions per snapshot |
| `build_with_wallet(self, &wallet, ScanType)` | `src/builder.rs:38-42` | Replace `ScanType` with `SnapshotAnchor::Latest \| AtHeight(u32)` |
| Multi-wallet via `DescriptorId` | `src/lib.rs:308-320` | Direct reuse |
| `start()` (auto-spawn) / `managed_start()` (return raw runner) | `src/lib.rs:148-171` | Direct reuse — escape hatch for wasm + custom executors |
| Test layout (tempdir-per-test, builder-with-injected-transport) | `tests/client.rs` | Swap `bdk_testenv::TestEnv` for our `MockTransport` |

Critically: the emitted type IS `bdk_wallet::Update` directly, not a
custom type that gets converted. We reuse this exact construction so
wallet authors switching backends see no API change.

### Do NOT copy

- `pub extern crate bip157` — re-exporting kyoto wholesale would tie
  our public API to CBF semantics that don't apply.
- `HeaderCheckpoint` + `ChainState::Checkpoint(...)` — PIR snapshot
  anchoring is a single height + Merkle root, not a header chain.
  Modeling it with `HeaderCheckpoint` would mislead users into expecting
  reorg-following.
- `ScanType::Sync` "walk back 7 blocks for reorg protection" — wrong
  mental model. PIR queries are point-in-time against an attested
  snapshot; reorgs are the snapshot-builder's problem.
- `LoggingSubscribers` — our existing `tracing` + `PirMetrics` is
  already richer.

## Headers / chain-tip / recent blocks — recommendation

**Skip `bip157`/`kyoto` for the prototype.** Reasons:

1. **It's overkill.** `bip157` brings a full P2P stack (peer
   management, handshake, filter downloads, peer rotation, DoS
   protection). For a snapshot-anchored PIR wallet we need exactly two
   things from the chain side: the current tip height (for staleness
   display) and maybe a tip header (for the wallet's `CheckPoint`).
2. **The privacy gain doesn't matter here.** BIP157's privacy story is
   for *script-level* discovery — clients download all filters and
   match locally so the server learns nothing about which scripts you
   care about. For *header-only* queries ("what's the current tip?"),
   there's nothing to leak — every wallet on Earth asks the same
   question.
3. **PIR is already the privacy-preserving discovery channel.** Adding
   bip157 on top is double-paying for privacy on a channel that already
   has it.
4. **Operationally simpler.** A bip157 client requires open peer slots,
   long-lived TCP connections, and a tokio runtime managing peers. A
   tip-oracle is a single HTTP call.

### What to do instead

For the prototype, three layers, ordered by effort:

**Layer A (MVP — pick one):**

- **PIR server's reported snapshot tip.** The simplest possible answer:
  the wallet's `CheckPoint` is the snapshot height the PIR server
  attests to. Confirmations display as "≥ N (as of snapshot)". No
  external dependency, no privacy leak. **Recommend this for the
  prototype.**

**Layer B (real-time tip — when you outgrow Layer A):**

- **mempool.space REST** (`/api/blocks/tip/height`,
  `/api/blocks/tip/hash`). One HTTP GET. Public, cached, no auth.
  Privacy: header-only queries reveal nothing personal. Use this for
  staleness comparison ("snapshot is 47 blocks behind tip").
- **blockstream.info** as fallback. Same shape.
- **Personal bitcoind RPC** if the user runs one. Maximum privacy, but
  requires the user to operate a node — not a prototype concern.

**Layer C (header chain, only if needed for proof verification):**

- If we ever need a full header chain client-side (currently we don't —
  the PIR snapshot's Merkle root is attested independently), the right
  answer is `bdk_bitcoind_rpc::Emitter` against a personal node, OR a
  cheap REST endpoint (`/api/block/<hash>/header`). `bip157`/`kyoto` is
  still wrong because we don't need filters; we'd be paying for the P2P
  stack to get something a single GET could deliver.

### Mempool / unconfirmed transactions

Out of scope for the PIR wallet by construction. PIR snapshots are
inherently after-block. The wallet's `seen_ats` map stays empty;
unconfirmed coins simply don't surface. Document this clearly in the UI
("Mempool: not tracked. Unconfirmed transactions become visible at the
next snapshot.").

## Persistence — design our own `HintStore`

`bdk_kyoto` does **not** give us a template here. `bip157::Builder::data_dir`
is a stringly-typed path pass-through; there's no `Persister` trait, no
`save_state()`/`load_state()` API, no checkpoint-export hook.

We need our own. Sketch:

```rust
pub trait HintStore: Send + Sync {
    fn load(&self, scope: &DescriptorId) -> Result<Option<HintCacheState>>;
    fn save(&self, scope: &DescriptorId, state: &HintCacheState) -> Result<()>;
    fn clear(&self, scope: &DescriptorId) -> Result<()>;
}
```

Reference implementations:

- `MemoryHintStore` (tests, default for prototype)
- `SqliteHintStore` (production, alongside BDK's own SQLite wallet
  persistence)
- `BrowserStorageHintStore` (wasm: IndexedDB)

Expose this on the builder as `.hint_store(impl HintStore)` rather than
hiding behind a path. Critical because consumed-hint correctness is the
HarmonyPIR invariant that quietly breaks in the current Electrum plugin.

## Prototype plan

Goal: a runnable demo that takes a descriptor, scans against the live
PIR server, and shows discovered UTXOs.

### Phase 1 — Rust core CLI (estimate: 2–3 days)

New workspace crate: `pir-bdk-wallet/` (or similar; reuse existing
naming convention).

**Deliverables:**

1. `PirChainClient` struct with:
   - `pub fn new(transport: Arc<dyn PirTransport>, hint_store: impl HintStore) -> Self`
   - `pub async fn full_scan<K>(&self, request: FullScanRequest<K>, stop_gap: u32) -> Result<FullScanResponse<K>>`
   - `pub async fn sync<I>(&self, request: SyncRequest<I>) -> Result<SyncResponse>`
2. `cargo run -p pir-bdk-wallet --bin scan -- --descriptor "<descriptor>" --backend harmony` binary that:
   - Connects to the live PIR server (`wss://weikeng1.bitcoinpir.org`)
   - Runs `wallet.full_scan()` with stop_gap=20
   - Prints discovered UTXOs as a table (txid, vout, value, script, height)
   - Optionally writes a JSON dump for downstream consumption
3. Integration test: feed it the test scripthashes from
   `web/public/example_spks.json`, assert all known UTXOs are
   discovered.

**Acceptance criteria:**

- Compiles against `bdk_wallet 1.x` and `pir-sdk-client` without
  modification to either.
- One PIR session per `full_scan()` call, not one per script. Verified
  via `PirMetrics` (existing recorder) — should see one connect/scan
  pair, not N.
- HarmonyPIR hint state loads from `MemoryHintStore` at start and
  saves at end. Test that running scan twice doesn't violate
  consumed-hint invariant.

**Backend choice:** start with **DPF** (simplest — no per-session hint
state). Once the integration shape works, migrate to **HarmonyPIR** to
exercise the `HintStore`. OnionPIR third (uses `pir-sdk-client`'s
`onion` feature flag).

### Phase 2 — Web frontend (estimate: 1–2 days, after Phase 1 works)

Two options, ordered by simplicity:

**Option 2a (recommend): Rust binary serves HTTP + thin HTML page.**

- `pir-bdk-wallet` gains a `--serve` flag that exposes:
  - `POST /scan { descriptor, backend, stop_gap }` → JSON of UTXOs
  - `GET /tip` → snapshot height + staleness
- New static page at `web/wallet-prototype/index.html`: form for
  descriptor + backend dropdown + scan button + results table. Uses
  existing `web/src/types.ts` for type sharing if useful, but no
  `pir-sdk-wasm` dependency.
- Run: `cargo run -p pir-bdk-wallet --bin scan -- --serve` then open
  `http://localhost:8090/`.

**Option 2b (more work, more reusable): wasm-compile the BDK wallet.**

- Add `pir-bdk-wallet-wasm/` analog of `pir-sdk-wasm/`.
- Verify the same feature-gating MetaMask did
  ([`MetaMask/bdk-wasm`](https://github.com/MetaMask/bdk-wasm)) works
  for our case (no Esplora HTTP client; replace with our wasm
  WebSocket transport).
- Frontend imports the wasm bundle directly. No backend server needed.
- This is the long-term right answer but **not Phase 2** — too many
  moving parts for a first prototype.

**Recommend Option 2a for the first run.** The Rust binary + thin HTML
gets us a runnable demo on `http://localhost:<port>` in a day. Wasm is
a better artifact but worse iteration loop.

### Phase 3 — Future work, not part of first prototype

- `SqliteHintStore` for production-grade persistence.
- Real-time tip oracle (mempool.space) replacing snapshot-tip
  fallback.
- Wasm bundle (Option 2b) so the existing `web/` frontend can drop
  the Rust HTTP server.
- Coin selection + transaction construction + PSBT signing path
  (right now we only do read-side discovery).
- BIP21 / address generation UI.

## Resolved questions (2026-05-08)

### 1. BDK version

**Decision: `bdk_wallet 3.0.0` (latest stable on docs.rs).**

User originally picked `2.0-beta` based on the prior research, but at
the time of writing `bdk_wallet 3.0.0` has shipped — newer = better
applies even more strongly. Lock to `bdk_wallet = "3"` and pin
`bdk_chain` to the matching minor.

If 3.0 turns out to have a regression for our use case during Phase 1,
fall back to `bdk_wallet 2.x` (which has the tightened
mempool-eviction logic vs 1.x and is still mature). 1.x is too old to
target for a fresh prototype.

### 2. PIR snapshot tip → `bdk_chain::CheckPoint` mapping

`CheckPoint` is a reference-counted linked list of `BlockId`s
(`{ hash, height }`), traversed via `prev() -> Option<CheckPoint>`.
For a single-point construction:

```rust
use bdk_chain::{BlockId, CheckPoint};
use bitcoin::BlockHash;

let cp = CheckPoint::new(BlockId {
    height: snapshot_height,
    hash: snapshot_block_hash,
});
```

For our case the PIR server's snapshot handshake already exposes
`(snapshot_height, snapshot_block_hash)` (the snapshot is anchored to
a real block). Single-element `CheckPoint::new(BlockId { ... })` is
sufficient — there are no reorgs to follow, and BDK's `LocalChain`
will accept any monotonically advancing checkpoint we hand it.

If we ever want to give the wallet additional history (so the user
sees confirmation counts that don't all collapse to the snapshot
height), we could:

- Extend the PIR handshake to also emit the previous N block hashes
  (cheap, header-only data — no privacy concern).
- Build a longer `CheckPoint` chain with `from_block_ids(iter)` over
  the descending-height list.

Out of scope for Phase 1; single-element CP works.

### 3. `pir-sdk-client` API surface — no changes needed

The existing `PirClient::sync()` is exactly the right shape:

```rust
// pir-sdk/src/client.rs:109-113
async fn sync(
    &mut self,
    script_hashes: &[ScriptHash],
    last_height: Option<u32>,
) -> PirResult<SyncResult>;
```

`SyncResult` returns `results: Vec<Option<QueryResult>>` in the same
order as the input scripthashes, plus `synced_height: u32`. Internally
this already does:

- K-padded INDEX rounds (correct privacy budget — no per-script fan-out).
- K_CHUNK-padded CHUNK rounds (with CHUNK Round-Presence Symmetry —
  every query, found or not, still issues ≥1 CHUNK round).
- Delta vs full-snapshot planning (via `compute_sync_plan`).
- Merkle verification (per-bucket bin Merkle).

`QueryResult.entries` is `Vec<UtxoEntry { txid: [u8; 32], vout: u32, amount_sats: u64 }>` — these are the per-UTXO outputs we'd convert
into BDK `TxOut`s.

**Adapter shape (no new pir-sdk-client methods required):**

```rust
impl PirChainClient {
    pub async fn full_scan<K: Ord + Clone>(
        &mut self,
        request: FullScanRequest<K>,
        stop_gap: u32,
    ) -> Result<FullScanResponse<K>, PirError> {
        // 1. Drain request iterators into Vec<(K, u32, ScriptBuf)>.
        // 2. Convert each ScriptBuf to ScriptHash (HASH160).
        // 3. self.client.sync(&script_hashes, self.last_height).await?
        // 4. Map SyncResult.results back to TxUpdate (txouts + anchors).
        // 5. Build CheckPoint from sync_result.synced_height.
        // 6. Update self.last_height for next call.
    }
}
```

**One known gap to document, not block on:** `UtxoEntry` does not
carry per-UTXO block height — the only height we have is
`SyncResult.synced_height`. For Phase 1, every confirmed UTXO gets
anchored at the snapshot height (technically loses confirmation-count
precision, functionally correct for "confirmed vs unconfirmed"). If
we want precise per-UTXO confirmations later, the path is to extend
`UtxoEntry` (or the chunk Merkle items) to carry the `block_height`
field — it's already on the server side, just not currently surfaced.

### 4. `stop_gap` and the K-budget

**`stop_gap`** is the BIP44 / BIP32 gap-limit concept: scan addresses
sequentially from index 0; when you hit `gap_limit` consecutive unused
addresses, stop. Default in `bdk_wallet` is 20. Each descriptor
typically has two chains (external `m/.../0/*` and internal `m/.../1/*`),
so a fresh wallet's first-scan covers `2 × stop_gap` scripthashes
minimum.

**K=75 budget interaction:**

| Case | Scripthashes per round | Verdict |
|---|---|---|
| Fresh wallet, stop_gap=20, both chains, 0 used | 40 | 1 PBC round, 25 slots padding |
| Fresh wallet, stop_gap=20, both chains, last_active=20 | up to 80 | 2 PBC rounds (just over K) |
| Fresh wallet, stop_gap=50 (paranoid) | 100 | 2 PBC rounds |
| Incremental sync (5 new addresses since last_active) | 5 | 1 PBC round, mostly padding |

Per CLAUDE.md "INDEX Merkle Group-Symmetry," queries are placed via
`pbc_plan_rounds(derive_groups_3, K=75, 3, 500)`. Collision-heavy
batches may add a small number of extra PBC rounds — empirically not a
concern for batches under K, since the planner has slack.

Backend-specific notes:

- **DPF / OnionPIR:** `INDEX_CUCKOO_NUM_HASHES=2` cuckoo positions per
  scripthash, but both bins are XOR'd from the same response — each
  scripthash uses 1 K-slot effectively.
- **HarmonyPIR:** each cuckoo position is a separate K-padded wire
  round (2 wire rounds per PBC round), per the CLAUDE.md
  "Per-Group Request-Count Symmetry" invariant. So a 40-scripthash
  PBC round is 2 wire rounds, each padded to K=75.

**Practical recommendation:** for the prototype, start with
`stop_gap=20` (BDK default). A fresh-wallet first-scan is 40
scripthashes = 1 PBC round. Subsequent syncs are smaller. The K
budget is comfortable; the bottleneck is going to be PIR round latency
(network + crypto), not query-slot exhaustion.

If we want to be rigorous: budget for 2 PBC rounds in the worst case
(stop_gap × 2 chains × 1.x for collision slack). Time-budget against
the existing PIR latency benchmarks before locking the UX.

## Out of scope (explicit non-goals)

- Mempool / unconfirmed transactions (PIR snapshots are confirmed-only
  by construction).
- Reorg following / chain reorg handling (PIR is anchored to attested
  snapshot height).
- Hardware wallet integration.
- Multi-signature flows beyond what BDK gives us for free via
  descriptors.
- Replacing the Electrum plugin for *existing* Electrum users —
  prototype is research/test wallet, not drop-in replacement.

## References

- [BDK feasibility brief (in-session research, 2026-05-08)](#) —
  agent report, summarized above.
- [bdk_kyoto reuse analysis (in-session research, 2026-05-08)](#) —
  agent report, summarized above.
- `.dream/review.md` (audit report from the dream skill run) —
  identified the Electrum plugin gaps that motivated this pivot.
- BDK docs:
  - `bdk_chain` data layer:
    https://docs.rs/bdk_chain/latest/bdk_chain/
  - `SyncResponse`:
    https://docs.rs/bdk_chain/latest/bdk_chain/spk_client/struct.SyncResponse.html
  - `FullScanResponse`:
    https://docs.rs/bdk_chain/latest/bdk_chain/spk_client/struct.FullScanResponse.html
  - `TxUpdate`:
    https://docs.rs/bdk_chain/latest/bdk_chain/struct.TxUpdate.html
- Reference clients (read for shape, do NOT template the per-script
  fan-out):
  - `bdk_esplora`:
    https://github.com/bitcoindevkit/bdk/tree/master/crates/esplora
  - `bdk_electrum`:
    https://github.com/bitcoindevkit/bdk/tree/master/crates/electrum
  - `bdk_kyoto`:
    https://github.com/bitcoindevkit/bdk_kyoto
- Wasm precedent:
  - MetaMask `bdk-wasm`: https://github.com/MetaMask/bdk-wasm
- Prior planning artifact this supersedes:
  - `electrum_plugin/` (existing Electrum plugin path — kept in tree
    for now; deprecate after Phase 1 lands).
