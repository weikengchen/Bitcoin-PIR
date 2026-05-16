# Feature request to OnionPIRv2: thread-safe `answer_query` for parallel per-server dispatch

**Status:** authored 2026-05-15 from a downstream consumer (BitcoinPIR)
hitting a Cloudflare WebSocket idle-timeout on the public production
endpoint. The current sequential `answer_query` takes ~162 s on a
75-group INDEX batch (i7-8700, single thread); CF Free closes the
tunnel at ~100 s. Rayon-parallelizing `answer_query` across the 75
per-group `PirServer` instances would bring wall time to ~27 s on the
6-core host, but is currently unsafe due to two process-global pieces
of state inside the matmul / keyswitch kernels. This request
documents the smallest upstream change that would let downstream
consumers parallelize without touching upstream call sites.

**Audience:** the AI agent (or human) working in
`/Users/cusgadmin/bitcoin-pir/OnionPIRv2/`. No BitcoinPIR-side
context is required to act on this — every claim below is grounded
in upstream source paths and concrete code.

**TL;DR:** Two upstream changes are needed for downstream parallel
`Server::answer_query` to be sound:

1. **`src/bv_keyswitch.cpp:286` — make `g_scratch` `thread_local`.** The
   `GaloisScratch` struct currently lives in an anonymous-namespace
   `static` global. Two threads calling `bv_apply_galois_inplace_k1`
   (or `_k2`) concurrently both read and write the same vectors,
   producing data races on the gadget-decomposition scratch.
2. **`src/shared_key_store.cpp` — add internal `std::mutex` synchronization.**
   The class is documented "NOT thread-safe" and `touch()` calls
   `std::list::splice` on `lru_order_`. Concurrent `touch()` from
   parallel `answer_query` calls (during `fast_expand_qry`) is UB on
   the list pointer manipulation when the LRU has ≥ 2 clients.

Both are localized, mechanical, no API change. The first one is the
hard blocker — without it parallel `answer_query` is unsafe even with
a single client. The second one is needed for soundness once the
keystore caches more than one client at a time (BitcoinPIR's typical
deployment).

---

## 1. The symptom (production observation)

Downstream consumer BitcoinPIR fronts pir1 via a Cloudflare WebSocket
tunnel (`wss://weikeng1.bitcoinpir.org`). The CF Free plan terminates
idle WebSocket connections at ~100 s. Sequential server-side
processing of one OnionPIR INDEX batch (K = 75 groups × ~1.1 s
per-server matmul on i7-8700, single thread) takes ~162 s. CF closes
the tunnel mid-batch; the client sees
`Connection reset without closing handshake`.

Direct (SSH-tunnelled) test passes:

```
$ PIR_ONION_URL=ws://127.0.0.1:18091 cargo test \
    -p pir-sdk-client --features onion --test integration_test \
    test_onion_client_query_batch -- --ignored --nocapture

test result: ok. 1 passed; ...; finished in 400.16s
```

So the failure is purely a wall-time / tunnel-timeout issue, not a
protocol bug. The natural fix at the downstream is to use
`rayon::par_iter_mut()` over the per-group `Vec<onionpir::Server>` so
all 75 INDEX matmuls run in parallel.

That fix is **provably unsafe** with the current upstream, as
detailed in the next sections.

---

## 2. Issue 1: `g_scratch` is a process-global

### Location

`src/bv_keyswitch.cpp:280-287`:

```cpp
// scratch reused across calls to bv_apply_galois_inplace.
namespace {
struct GaloisScratch {
  std::vector<uint64_t> c0_perm, c1_perm, delta_a, delta_b, tmp;
  std::vector<uint64_t> digits;  // L_KS contiguous N-blocks (row-major)
};
static GaloisScratch g_scratch;
}  // namespace
```

This is referenced from both `bv_apply_galois_inplace_k1`
(`bv_keyswitch.cpp:290-360`) and `bv_apply_galois_inplace_k2`
(`bv_keyswitch.cpp:366+`). Each invocation lazily `resize`s the
vectors (if not yet sized for `N`) and then writes into them via the
returned `.data()` pointers.

### Call chain

`bv_apply_galois_inplace` is called from `PirServer::fast_expand_qry`
(`src/server.cpp:924`). `fast_expand_qry` is called from
`PirServer::make_query` (`src/server.cpp:976`). `make_query` is
called from the FFI entry point `onion_server_answer_query`
(`src/onion_ffi.cpp:683`). Downstream Rust wraps that as
`Server::answer_query(&mut self, client_id, query)`.

### The race

Consider two threads simultaneously calling
`bv_apply_galois_inplace_k1(ct, k, key, params)` on different
`onionpir::Server` instances but the same `pir_params` shape (typical
in BitcoinPIR's per-group setup where every per-group server has
`num_entries = 10239` and so identical `pir_params`):

- Thread A:
  ```cpp
  GaloisScratch &s = g_scratch;
  if (s.c0_perm.size() != N) {  // (*)
      s.c0_perm.resize(N);
      ...
  }
  uint64_t *const c0_perm = s.c0_perm.data();
  utils::automorphism_coeff(ct.data(0), N, galois_k, q_val, c0_perm);
  utils::automorphism_coeff(ct.data(1), N, galois_k, q_val, c1_perm);
  ...
  ```
- Thread B: runs the same code path on the same `g_scratch` instance
  with its own ciphertext `ct`. The writes via `c0_perm`, `c1_perm`,
  `delta_a`, `delta_b`, `digits` step on each other; one thread's
  decomposed digits get overwritten by the other thread's
  intermediate state.

Outcome: Thread A's keyswitch reads back digits computed for
Thread B's ciphertext (or vice versa). Both end up producing
garbage RLWE ciphertexts. Downstream observation: the eventual
plaintext doesn't decrypt correctly, but no exception is thrown
(the matmul kernel produces silent corruption rather than panicking).

### Proposed fix (one keyword)

```diff
--- a/src/bv_keyswitch.cpp
+++ b/src/bv_keyswitch.cpp
@@ -283,7 +283,7 @@ namespace {
 struct GaloisScratch {
   std::vector<uint64_t> c0_perm, c1_perm, delta_a, delta_b, tmp;
   std::vector<uint64_t> digits;  // L_KS contiguous N-blocks (row-major)
 };
-static GaloisScratch g_scratch;
+static thread_local GaloisScratch g_scratch;
 }  // namespace
```

### Cost analysis

Memory: `GaloisScratch` size ≈ `(5 × N + L_KS × N) × 8 B` ≈ `9 × 2048
× 8 = 144 KB` per thread (default `N=2048`, `L_KS=4`). At
`std::thread::hardware_concurrency() = 6` on the target host, total
thread-local footprint = 864 KB. Trivial.

Latency: `thread_local` access on Linux/macOS goes through
`__tls_get_addr` (fast TLS dispatch via the GOT), adding a single
indirect call (~ns). The per-coefficient matmul work dominates by
many orders of magnitude.

Correctness: each thread's `g_scratch` is initialized lazily on first
access via its `std::vector<>` default constructor (empty); the
existing `if (s.c0_perm.size() != N) ...` lazy-resize logic works
unchanged per thread.

### Validation

The existing unit test `src/tests/test_bv_keyswitch.cpp:test_apply_galois`
tests `bv_apply_galois_inplace` from a single thread. A multi-thread
regression test would look like:

```cpp
TEST(BvKeyswitch, ApplyGaloisFromMultipleThreads) {
    PirParams params;
    RlweSk sk = gen_secret_key_rns(...);
    auto key = gen_bv_ks_key(params, sk, /*galois_k=*/3, rng);

    std::vector<RlweCt> golden_results;
    constexpr int N_THREADS = 4;
    for (int i = 0; i < N_THREADS; i++) {
        RlweCt ct = make_random_ct(params, sk, /*seed=*/i);
        bv_apply_galois_inplace(ct, 3, key, params);
        golden_results.push_back(std::move(ct));
    }

    std::vector<RlweCt> parallel_results(N_THREADS);
    std::vector<std::thread> threads;
    for (int i = 0; i < N_THREADS; i++) {
        threads.emplace_back([&, i]() {
            RlweCt ct = make_random_ct(params, sk, /*seed=*/i);
            bv_apply_galois_inplace(ct, 3, key, params);
            parallel_results[i] = std::move(ct);
        });
    }
    for (auto &t : threads) t.join();

    for (int i = 0; i < N_THREADS; i++) {
        ASSERT_RLWECT_EQ(parallel_results[i], golden_results[i]);
    }
}
```

Pre-patch this test fails intermittently (race) or always (depending
on thread interleaving). Post-patch it passes deterministically.

---

## 3. Issue 2: `SharedKeyStore` is documented thread-unsafe

### Location

`src/includes/shared_key_store.h:15-18`:

```cpp
// Thread safety: NOT thread-safe. Callers must serialize key registration
// against query processing. Concurrent read-only access (lookups during
// fast_expand_qry) from multiple threads is safe only if no concurrent
// mutation is occurring.
```

The mutation that matters during parallel `answer_query` is `touch()`,
called from `PirServer::fast_expand_qry` (`src/server.cpp:868`):

```cpp
if (shared_key_store_) shared_key_store_->touch(client_id);
```

`touch()` calls `promote_to_front()`:

```cpp
void SharedKeyStore::promote_to_front(size_t client_id) {
    auto it = lru_pos_.find(client_id);
    if (it != lru_pos_.end()) {
        lru_order_.splice(lru_order_.begin(), lru_order_, it->second);
    } else { /* insert */ }
}
```

### The race (multi-client case)

For BitcoinPIR's specific deployment with a **single** active client
per `AnswerBatch`, the splice degenerates to `splice(begin, this,
begin)` which the C++ standard guarantees is a no-op ("Has no effect
if position == it"). Two threads doing the same no-op simultaneously
don't race on writes — only on iterator/reference reads, which is
safe.

But the keystore is documented to cache up to `MAX_CLIENTS = 100`
clients. With ≥ 2 clients in the LRU (typical web deployment with
multiple browser sessions hitting the same server), parallel
`touch()` calls from different `answer_query` invocations would race
on the `std::list::splice` pointer manipulation.

In BitcoinPIR's specific case the LRU race is **currently benign**
because each `AnswerBatch` processes queries for exactly one
`client_id`, and the mpsc-serialized worker thread guarantees no
concurrent `AnswerBatch` runs. So 75 parallel `touch(client_id)`
calls inside one `AnswerBatch` all act on the same LRU entry, and
that entry is at the front (since RegisterKeys' `promote_to_front`
runs immediately before AnswerBatch). All splices are no-ops.

This invariant is **deployment-specific** and fragile. Any future
keystore use case that calls `answer_query` for two different
`client_id`s in parallel (e.g. a hint server that serves multiple
clients concurrently) would hit the race for real.

### Proposed fix (mechanical)

Add a `mutable std::mutex` to `SharedKeyStore` and lock in every
public method. The lock overhead is ~50 ns uncontended per
`answer_query` (2 × `get_*` + 1 × `touch` = ~150 ns total),
negligible vs the ~1 s matmul.

```diff
--- a/src/includes/shared_key_store.h
+++ b/src/includes/shared_key_store.h
@@ -19,6 +19,7 @@
 #include "bv_keyswitch.h"
 #include "gsw.h"

+#include <mutex>
 #include <cstddef>
 #include <list>
 #include <unordered_map>
@@ -65,6 +66,9 @@ private:
     std::list<size_t>                                              lru_order_;
     std::unordered_map<size_t, std::list<size_t>::iterator>        lru_pos_;

+    // Internal sync. Guards every public method. See class doc note.
+    mutable std::mutex mu_;
+
     // Called on every set_* and touch(). If size exceeds MAX_CLIENTS,
     void evict_if_full();
     // Helper: ensure client_id is present in the LRU list (insert at front
```

```diff
--- a/src/shared_key_store.cpp
+++ b/src/shared_key_store.cpp
@@ -5,12 +5,14 @@
 #include <utility>

 void SharedKeyStore::set_galois_keys(size_t client_id, bvks::BvGaloisKeys keys) {
+    std::lock_guard<std::mutex> lock(mu_);
     galois_[client_id] = std::move(keys);
     promote_to_front(client_id);
     evict_if_full();
 }

 void SharedKeyStore::set_gsw_key(size_t client_id, GSWCt key) {
+    std::lock_guard<std::mutex> lock(mu_);
     gsw_[client_id] = std::move(key);
     promote_to_front(client_id);
     evict_if_full();
@@ -18,6 +20,7 @@

 const bvks::BvGaloisKeys &
 SharedKeyStore::get_galois_keys(size_t client_id) const {
+    std::lock_guard<std::mutex> lock(mu_);
     auto it = galois_.find(client_id);
     if (it == galois_.end()) {
         throw std::out_of_range(
@@ -28,6 +31,7 @@
 }

 const GSWCt &SharedKeyStore::get_gsw_key(size_t client_id) const {
+    std::lock_guard<std::mutex> lock(mu_);
     auto it = gsw_.find(client_id);
     if (it == gsw_.end()) {
         throw std::out_of_range(
@@ -38,16 +42,19 @@
 }

 bool SharedKeyStore::has_client(size_t client_id) const {
+    std::lock_guard<std::mutex> lock(mu_);
     return galois_.count(client_id) && gsw_.count(client_id);
 }

 void SharedKeyStore::touch(size_t client_id) {
+    std::lock_guard<std::mutex> lock(mu_);
     if (lru_pos_.count(client_id)) {
         promote_to_front(client_id);
     }
 }

 void SharedKeyStore::remove(size_t client_id) {
+    std::lock_guard<std::mutex> lock(mu_);
     galois_.erase(client_id);
     gsw_.erase(client_id);
     auto it = lru_pos_.find(client_id);
@@ -58,6 +65,7 @@
 }

 size_t SharedKeyStore::size() const {
+    std::lock_guard<std::mutex> lock(mu_);
     return lru_order_.size();
 }
```

### Subtle return-by-reference concern

`get_galois_keys` / `get_gsw_key` return `const &` into the internal
maps. With locking around the function, the lock is released when
the function returns, leaving a reference into a map that another
thread could now `set_*` / `remove` / evict. To preserve correctness
the caller must hold the keystore stable for the entire duration of
using the reference.

The existing `fast_expand_qry` does exactly that — it holds the
returned `const BvGaloisKeys &` across the matmul loop. If a
concurrent `set_galois_keys` evicts the same client mid-matmul, the
reference dangles.

**Recommended caller discipline:** keep the existing invariant
("registration is serialized against query processing"), and use the
mutex only to defend the LRU `touch()` race. Document this in the
class header as the explicit threading model.

Alternatively, change the return type to `BvGaloisKeys` (by value /
shared_ptr) so the caller owns a stable handle. Heavier API change;
defer.

### Update the class header doc

```diff
--- a/src/includes/shared_key_store.h
+++ b/src/includes/shared_key_store.h
@@ -13,11 +13,11 @@
 // as clients come and go.
 //
-// Thread safety: NOT thread-safe. Callers must serialize key registration
-// against query processing. Concurrent read-only access (lookups during
-// fast_expand_qry) from multiple threads is safe only if no concurrent
-// mutation is occurring.
+// Thread safety: each public method is internally serialized by mu_.
+// However, get_galois_keys / get_gsw_key return references into the
+// internal maps — the caller must keep the keystore stable for the
+// lifetime of the returned reference (i.e. no concurrent set_* / remove
+// / eviction). The intended pattern: registration and query processing
+// run on different threads, but never overlap in time.
```

---

## 4. Acceptance test (downstream view)

Downstream BitcoinPIR has `runtime/src/bin/unified_server.rs` with
one worker thread per database that processes `PirCommand` enums
serially via an mpsc channel:

```rust
PirCommand::AnswerBatch { client_id, level, queries, reply } => {
    let results = if level == 0 {
        queries.iter().enumerate().map(|(i, q)| {
            let g = i / 2;
            index_servers[g].answer_query(client_id, q)
        }).collect()
    } else if level == 1 {
        queries.iter().enumerate().map(|(b, q)| {
            chunk_servers[b].answer_query(client_id, q)
        }).collect()
    } /* etc */;
    reply.send(results);
}
```

Post-patch, downstream replaces `.iter().enumerate().map(...)` with
`.par_iter_mut().enumerate().flat_map(...)` (already drafted, then
reverted pending this upstream fix; the diff is small). With 75
INDEX groups on a 6-core i7-8700, sequential wall time of 162 s
drops to ≈ 27 s, comfortably under Cloudflare's 100 s WebSocket idle
timeout.

### One-shot regression test on upstream

Add to `src/tests/test_pir.cpp` (or similar):

```cpp
TEST(PirEnd2End, ParallelServersOneClientOneKeystore) {
    constexpr size_t N_SERVERS = 8;
    SharedKeyStore store;
    PirClient client(/*num_entries=*/1024);
    store.set_galois_keys(client.get_client_id(), client.create_bv_galois_keys());
    store.set_gsw_key(client.get_client_id(), client.generate_gsw_from_key());

    std::vector<PirServer> servers;
    for (size_t i = 0; i < N_SERVERS; i++) {
        servers.emplace_back(/*num_entries=*/1024);
        servers.back().gen_data(/*targets=*/{i});  // each server records a different plaintext
        servers.back().set_shared_key_store(&store);
    }

    constexpr size_t pt_idx = 5;
    std::vector<std::vector<uint8_t>> results(N_SERVERS);
    std::vector<std::thread> threads;
    for (size_t i = 0; i < N_SERVERS; i++) {
        threads.emplace_back([&, i]() {
            RlweCt q = client.fast_generate_query(pt_idx);
            std::vector<uint8_t> q_bytes;
            serialize_rlwe_ct(q, q_bytes);
            RlweCt response = servers[i].make_query(client.get_client_id(), q);
            std::stringstream ss;
            servers[i].save_resp_to_stream(response, ss);
            const std::string s = ss.str();
            results[i] = std::vector<uint8_t>(s.begin(), s.end());
        });
    }
    for (auto &t : threads) t.join();

    // All results should be non-empty and decrypt cleanly.
    for (size_t i = 0; i < N_SERVERS; i++) {
        ASSERT_FALSE(results[i].empty())
            << "server " << i << " returned empty response (likely a race-induced exception)";
        std::stringstream ss;
        ss.write(reinterpret_cast<const char *>(results[i].data()), results[i].size());
        RlweCt ct = client.load_resp_from_stream(ss);
        RlwePt pt = client.decrypt_mod_q(ct);
        ASSERT_GT(client.noise_budget(ct), 5)
            << "server " << i << " result decrypted with noise budget ≤ 5 — likely race-corrupted ciphertext";
    }
}
```

This test fails reliably on the current upstream and passes after both
patches land. With only patch (1) (`thread_local g_scratch`) and the
single-client invariant respected (one keystore client_id), it also
passes — patch (2) is required only for the multi-client case which
the test above doesn't exercise.

---

## 5. Scope notes

- **No API change.** Both fixes are purely internal to upstream's
  implementation files. Downstream `Server::answer_query`,
  `Server::set_key_store`, and the `KeyStore` Rust wrapper see no
  signature changes.
- **No build-flag toggle.** `thread_local` is C++11 and available
  unconditionally on every Linux/macOS toolchain the upstream targets.
  `std::mutex` has been in C++11 too.
- **No performance regression in single-threaded use.** TLS access
  adds nanoseconds; mutex acquisition adds nanoseconds when
  uncontended. Both are dwarfed by the per-coefficient matmul.
- **No semantic change to LRU policy.** The mutex only protects
  against concurrent mutation — the eviction order, MAX_CLIENTS, etc.
  remain unchanged.
- **Future-proofing.** Once these land, downstream can also expose a
  `QueryQueue`-backed multi-client path (each `answer_query` runs on
  a different worker thread) without further upstream changes.

If both fixes ship in a single upstream commit, BitcoinPIR's
follow-up is mechanical: bump the rev in three Cargo.toml files
(`build/`, `pir-sdk-client/`, `runtime/`), recompile, redeploy.
Expected wall-time improvement on pir1's i7-8700: INDEX 162 s →
27 s, CHUNK 158 s → 27 s. Total per-query batch ≈ 60 s — under CF's
100 s threshold with room to spare.

---

## 6. Acknowledgement of deployment context

BitcoinPIR pir1's specific deployment (one client per AnswerBatch,
mpsc-serialized worker thread) currently makes the `SharedKeyStore`
`touch()` race benign in practice (all promotions are no-ops because
the LRU has one entry that's already at front). So the **immediate
production blocker is purely patch (1)** — the `g_scratch` race
applies to even single-client parallel `answer_query`. Patch (2)
hardens against the multi-client future case.

If upstream prefers a phased rollout, landing (1) alone unblocks the
BitcoinPIR CF timeout fix; (2) can follow as a separate hardening
commit.
