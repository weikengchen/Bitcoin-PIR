# HarmonyPIR Integration Guide

Handoff document for integrating HarmonyPIR into other projects.
This file is at `/Users/cusgadmin/bitcoin-pir/harmonypir/INTEGRATION.md`.

## Quick Start — Cargo Dependency

```toml
# All PRP backends (native)
harmonypir = { path = "../harmonypir" }

# WASM (Hoang + FF1 only, no SIMD/rayon deps)
harmonypir = { path = "../harmonypir", default-features = false }

# Specific backends
harmonypir = { path = "../harmonypir", default-features = false, features = ["alf"] }
harmonypir = { path = "../harmonypir", default-features = false, features = ["fastprp-prp"] }
```

Note: `alf` requires `../ALF` and `fastprp-prp` requires `../fastprp` as sibling directories.

## The Prp Trait

```rust
// src/prp/mod.rs
pub trait Prp: Send + Sync {
    fn forward(&self, x: usize) -> usize;   // Encrypt: P_k(x)
    fn inverse(&self, y: usize) -> usize;   // Decrypt: P_k^{-1}(y)
    fn domain(&self) -> usize;              // Domain size [0, N')
}

pub trait BatchPrp: Prp {
    fn batch_forward(&self) -> Vec<usize>;  // Full table: result[x] = forward(x)
}
```

The protocol accepts `Box<dyn Prp>`. All four backends implement both traits.
Trait objects are `Send + Sync`, so `Box<dyn Prp>` can be held across `.await`
points and shared across threads without extra bounds.

## Creating PRP Instances

### ALF (recommended for online queries)

```rust
use harmonypir::prp::alf::{AlfPrp, AlfEngine};

// Direct construction (one PRP per tweak/group)
let prp = AlfPrp::new(
    &key,          // &[u8; 16] — AES key
    domain_size,   // usize — must be >= 65536
    &tweak,        // &[u8; 16] — per-PBC-group tweak
    app_id,        // u64 — application identifier
);

// Factory for multiple groups (same key, different tweaks)
let engine = AlfEngine::new(key, domain_size, app_id);
let prp_group_0 = engine.create_prp_for_group(0);  // tweak = group_id as LE bytes
let prp_group_1 = engine.create_prp_for_group(1);
```

- Domain must be >= 65536 (ALF bit_width >= 16)
- Native: ~198 ns/op. WASM: ~10.8 us/op (software AES fallback).
- Two internal AlfNt instances (one encrypt, one decrypt).

### FastPRP (recommended for server-side batch generation)

```rust
use harmonypir::prp::fast::FastPrpWrapper;

// Direct construction (builds internal cache, ~60ms at N=6M)
let prp = FastPrpWrapper::new(&key, domain_size);

// Per-group via derived key (no tweak support)
let prp = FastPrpWrapper::with_group(&master_key, group_id, domain_size);

// Cache persistence — save after first build
let cache_bytes: Vec<u8> = prp.save_cache();
std::fs::write("cache_group_0.bin", &cache_bytes).unwrap();

// Reload from cache (skips expensive cache build)
let cache_bytes = std::fs::read("cache_group_0.bin").unwrap();
let prp = FastPrpWrapper::from_cache(&key, domain_size, &cache_bytes);

// Native batch generation (O(N log N), much faster than N × permute())
let table: Vec<usize> = prp.batch_forward();        // via BatchPrp trait
let table_u64: Vec<u64> = prp.batch_permute_raw();  // native u64, no conversion
```

- Domain must be >= 2.
- Cache: ~72 KB per bucket at N=6M. Persist to skip ~60ms rebuild.
- `batch_permute_raw()` is the fast path for offline hint generation.

### Hoang (always available, works in WASM)

```rust
use harmonypir::prp::hoang::HoangPrp;

let prp = HoangPrp::new(
    domain_size,   // usize — must be >= 2
    rounds,        // usize — must be multiple of 4, typically 64
    &key,          // &[u8; 16] — AES key
);

// Per-group: derive key externally, same as FastPRP
```

- Works at any domain size >= 2 (no minimum like ALF).
- Rounds: use `ceil(log2(domain)) + 40`, rounded up to multiple of 4.
- Slowest per-op, but zero external dependencies and compiles for WASM.

## Running the Protocol

```rust
use harmonypir::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// 1. Create database
let db: Vec<Vec<u8>> = /* your data */;
let server = Server::new(db);

// 2. Choose parameters
let n = 262_144;  // 2^18 rows (bucket-size-4 INDEX)
let w = 168;      // 4 × 42 bytes per row
let t = 512;      // segment size
let params = Params::new(n, w, t).unwrap();

// 3. Create PRP (domain = 2N)
let prp: Box<dyn Prp> = Box::new(AlfPrp::new(&key, 2 * n, &tweak, 0));

// 4. Offline phase: stream DB, compute hints
let mut client = Client::offline(params, prp, &server).unwrap();

// 5. Online queries
let mut rng = ChaCha20Rng::from_entropy();
let entry = client.query(42, &server, &mut rng).unwrap();
// entry is Vec<u8> of length w

// 6. DB modification support
let diff = server.modify_entry(42, new_entry);
client.apply_modification(42, &diff).unwrap();
```

## Pipelined Pair Queries (one network round-trip per two queries)

`Client::query` does one server roundtrip per query. When you have two
queries to issue against the same client, the pair API lets you bundle
both requests into a single roundtrip — same answers, same final state,
half the latency.

### Why this is sound

`RelocateSegment(s)` (the DS' update half of post-query bookkeeping) is
purely local — it does not depend on the server's response. Splitting it
from the hint-parity update unlocks pipelining: build Q_1, locally
relocate s_1, build Q_2 from the post-relocation DS', send both, then
update H twice using the two responses. The result is mathematically
identical to two sequential `query()` calls. See the rustdoc on
`Client::build_pair_requests` for the eight-step argument and the
`test_query_pair_equiv_sequential_*` test family for the empirical
equivalence checks (Hoang, FastPRP, ALF — all green).

### All-in-one (local Server)

```rust
let mut rng = ChaCha20Rng::from_entropy();
let (entry_1, entry_2) = client.query_pair(42, 100, &server, &mut rng).unwrap();
```

### Split API (caller manages network roundtrip)

For remote servers — issue both requests in parallel, then process both
responses together:

```rust
use harmonypir::prelude::*;

// Build phase: produces two requests + opaque PendingPair state.
// DS' is advanced past q_1's relocation; H is NOT yet updated.
let (req_1, req_2, pending): (Vec<usize>, Vec<usize>, PendingPair) =
    client.build_pair_requests(42, 100, &mut rng)?;

// Caller-side: send both requests in parallel over the network.
let (resp_1, resp_2): (Vec<Vec<u8>>, Vec<Vec<u8>>) = tokio::join!(
    network.fetch(req_1),
    network.fetch(req_2),
);

// Finish phase: feeds both responses, returns both answers, advances H.
let (entry_1, entry_2) = client.finish_pair(pending, &resp_1, &resp_2)?;
```

Each request is a `Vec<usize>` of exactly T entries (database indices in
`[0, N)` or [`relocation::EMPTY`] for empty cells). Each response must be
a `&[Vec<u8>]` of exactly T entries of w bytes.

### In-flight invariant

Between `build_pair_requests` and `finish_pair`, the client is in an
**in-flight** state — DS' is one segment ahead of H. Do not call other
query methods (`query`, `query_pair`, `apply_modification`) on the same
client until `finish_pair` returns. The borrow checker won't catch this;
it's a logical invariant. The returned `PendingPair` is `#[must_use]` to
nudge callers in the right direction.

### Edge cases (all covered by tests)

- `q_1` and `q_2` in the same original segment: works without special
  handling. After `RelocateSegment(s_1)`, q_2 is chain-walked to its new
  cell and Q_2 targets the new segment normally.
- `q_1 == q_2`: both answers equal `db[q_1]`. q is relocated twice, H is
  updated correspondingly.
- Wrong-length response in `finish_pair`: returns
  `HarmonyPirError::InvalidParams` instead of corrupting state.

## Bitcoin UTXO Parameters (Bucket-Size-4)

```
INDEX: 75 buckets × (N=2^18 rows, w=168B, domain=2^19, T=512)
CHUNK: 80 buckets × (N=2^19 rows, w=352B, domain=2^20, T=1024)

Total hints: ~40 MB (168 KB × 75 + 352 KB × 80)
Max queries before rehint: 512 per bucket
PRP calls per address lookup: 240,640 (75×1024 + 80×2048)
```

## Performance Reference

### Native (Apple Silicon)

| PRP | Forward | Inverse | Batch hint gen (155 buckets, 16t) |
|-----|---------|---------|-----------------------------------|
| ALF | 198 ns | 262 ns | ~0.8 s |
| Hoang | 6.1 us | 6.1 us | ~100 s |
| FastPRP | 35.8 us | 23.8 us | ~1.5 s (batch_permute) |

### WASM (browser, software AES)

| PRP | Forward | Inverse | Full query (8 workers) |
|-----|---------|---------|----------------------|
| ALF | 10.8 us | 8.6 us | ~370 ms |
| Hoang | 14.0 us | 13.8 us | ~720 ms |
| FastPRP | 206 us | 185 us | ~3,000 ms |

### Recommendation

- **Browser client**: ALF (8 workers → 370ms) or Hoang (720ms). Both viable.
- **Server hint generation**: ALF or FastPRP. Both under 2s for all 155 buckets.
- **WASM-only (no SIMD deps)**: Hoang with `--no-default-features`.

## File Layout

```
/Users/cusgadmin/bitcoin-pir/
  harmonypir/          ← this crate
    src/prp/           ← PRP implementations
    src/protocol.rs    ← Client (offline + online)
    src/server.rs      ← Server (holds DB)
    wasm-bench/        ← WASM browser benchmark page
  ALF/                 ← alf-nt crate (SIMD FPE)
  fastprp/             ← fastprp crate (Stefanov & Shi)
```

## Passing Context to Another Claude Session

Add this to the other repo's CLAUDE.md:

```markdown
## HarmonyPIR Dependency

This project depends on HarmonyPIR for stateful PIR.
- Crate: `/Users/cusgadmin/bitcoin-pir/harmonypir/`
- Integration guide: `/Users/cusgadmin/bitcoin-pir/harmonypir/INTEGRATION.md`
- API reference: see `Prp` trait in `src/prp/mod.rs`
- Parameters: see "Bitcoin UTXO Parameters" section in INTEGRATION.md
```

The other session reads INTEGRATION.md to understand the full API, constructors,
parameters, and performance characteristics.
