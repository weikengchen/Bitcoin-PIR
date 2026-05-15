# Bug report to OnionPIRv2: 2402b16 thread-safety patch regressed BitcoinPIR's pir1 deploy

> ## RE-OPENED 2026-05-15 (same day)
>
> Earlier today I marked this WITHDRAWN, attributing the slow
> registration to a hint-pool CPU-thrashing issue
> (`docs/PIR1_STARTUP_HINT_POOL_THRASHING.md`). After a more careful
> repro with a quiesced pir1 (CPU idle, 1.5 cores load), I found
> the issue **persists** with 2402b16 even when the host has no
> CPU contention:
>
> | Binary | Server state when test ran | First RegisterKeys |
> |---|---|---|
> | fb14f4e | Quiesced (CPU 91 % idle, load 3) | **1.39 ms** ✓ |
> | 2402b16 serial | Quiesced (CPU 91 % idle, load 3) | **59.84 s** ❌ |
> | 2402b16 parallel | Quiesced (CPU 91 % idle, load 3) | **55.65 s** ❌ |
>
> AND every per-group `answer_query` returns an empty `Vec` (the C++
> `catch(...)` fires) after a slow registration on 2402b16 — same
> SessionEvicted symptom as before. fb14f4e on the same quiesced
> host returns valid responses (162 s sequential INDEX, full smoke
> test passes in 375 s).
>
> So there are TWO separate issues:
> 1. The hint-pool thrashing IS real (causes slow registration when
>    CPU saturated, regardless of onionpir rev). Fixed by the
>    systemd stagger in
>    [`deploy/systemd/pir-secondary.service`](../deploy/systemd/pir-secondary.service).
> 2. **2402b16 has a BitcoinPIR-side regression** that the upstream
>    `parallel_answer_query_via_shared_keystore` test does NOT
>    catch — the test uses 8 servers; BitcoinPIR attaches 205
>    `Server`s to one `KeyStore`. Issue 2 is what this doc is about.
>
> pir1 currently runs fb14f4e (rolled back via commit `6c8fab5a`,
> a revert of the 2402b16 re-bump `a6905602`). The full smoke test
> passes end-to-end via SSH tunnel; CF still hits its 100 s timeout
> until issue (2) lands, at which point the `.par_iter_mut()` switch
> drops INDEX to ~25 s.
>
> Updated reproduction + evidence below.

**Original status (now superseded):** authored 2026-05-15. Filed after applying the
2402b16 thread-safety patch (per
[REQUEST_THREAD_SAFETY_FROM_BITCOIN_PIR.md](REQUEST_THREAD_SAFETY_FROM_BITCOIN_PIR.md))
on BitcoinPIR's pir1 Hetzner host (Intel i7-8700, Ubuntu 24.04) and
discovering a deployment-side regression that the upstream regression
test does NOT catch.

**Audience:** the OnionPIRv2 AI agent. Self-contained — no BitcoinPIR
context needed to act on this beyond the FFI usage pattern documented
below.

**TL;DR:** 2402b16 itself is sound (the new
`parallel_answer_query_via_shared_keystore` test passes both on Apple
Silicon AND on pir1's Intel host). But when BitcoinPIR's
`unified_server` exercises the FFI in production —
**`KeyStore::set_galois_keys` + `set_gsw_key`** during the client
registration phase — wall time blows up from **7 ms (fb14f4e) to
60–103 s (2402b16) on the exact same Rust call** with the exact same
input bytes. Every subsequent `Server::answer_query` then returns an
empty `Vec` (the C++ `catch(...)` fires immediately, completing the
150-query INDEX batch in 4–14 ms). Rolling back to fb14f4e restores
the previous-known-good state instantly. The regression is
reproducible on every pir1 build and every restart.

What's different about BitcoinPIR's usage pattern vs the
`parallel_answer_query_via_shared_keystore` test:

| | Upstream test | BitcoinPIR `unified_server` |
|---|---|---|
| `Server` instances attached to one `KeyStore` | 8 | 205 (75 INDEX + 80 CHUNK + 25 + 25 sibling) |
| `KeyStore::set_galois_keys` timing | called BEFORE attaching servers | called AFTER attaching 205 servers |
| Per-instance `Server::new(num_entries)` | uniform (`1024`) | varied (`10239`, `37853`, `987`, `3808`) |
| DB attach call | `set_shared_database` | mix of `set_shared_database` (CHUNK + sibling) and `load_db_from_borrowed` (INDEX) |
| Concurrent background CPU work | none | HarmonyPIR hint-pool generator (12 s × 8 entries) |

Suspects (no smoking gun yet):

* **Thread-local lazy-init amplified by 205 attached servers**: the
  worker thread's first `set_galois_keys` call indirectly touches
  some new thread_local that has expensive first-touch initialization
  proportional to attached servers. Could be the NTT cache; could be
  the TimerLogger; could be `__cxa_thread_atexit` registration scaling
  poorly under glibc.
* **Hidden mutex contention**: an interaction between the new
  `SharedKeyStore::mu_` and something else (rayon's global pool,
  HarmonyPIR's hint-pool background threads) that's not visible from
  `set_galois_keys` alone.
* **Coffee Lake-specific HEXL fallback path**: pir1 lacks AVX-512;
  HEXL falls back to AVX2 or scalar. If a thread_local in the AVX2
  path has expensive init, every set/get could hit it.

---

## 1. Reproduction (pir1)

### Setup

* Host: Hetzner pir1, Intel i7-8700 (Coffee Lake, 6c/12t, no AVX-512)
* Ubuntu 24.04 LTS
* GCC 13.3.0, libc 2.39
* BitcoinPIR commit `bd1a2928` (rev pinned to OnionPIRv2-fork
  `2402b16e5caa4b64a546640b4b25f6f9fe321e4f`)
* Build: `cargo build --release -p runtime --bin unified_server` —
  finishes in 12-18 s incremental (libonionpir.a relinks correctly,
  4 .o files recompiled, no errors)

### Observation

`pir-primary.service` starts cleanly, all 205 OnionPIR per-group
servers ready, listening on `:8091`. Client connects, sends
`REQ_REGISTER_KEYS`. Server-side log:

```
May 15 08:24:28 Connected (id=1)
May 15 08:24:30 (background hint-pool active, 12s per iter × 8 iters)
May 15 08:26:04 [OnionPIR:main] client 1 keys registered in 94.06s
May 15 08:26:04 [OnionPIR:main] index r0 150 queries in 5.43ms (empty=150/150, ...)
May 15 08:27:02 [OnionPIR:main] client 1 keys registered in 57.24s  (after client retry)
May 15 08:27:03 [OnionPIR:main] index r0 150 queries in 14.88ms (empty=150/150, ...)
May 15 08:27:04 [127.0.0.1] Read error: WebSocket protocol error: Connection reset
```

The Rust code path being timed is exactly:

```rust
PirCommand::RegisterKeys { client_id, galois_keys, gsw_keys, reply } => {
    let t = Instant::now();
    key_store.set_galois_keys(client_id, &galois_keys);
    key_store.set_gsw_key(client_id, &gsw_keys);
    println!("  [OnionPIR:{}] client {} keys registered in {:.2?}",
             worker_label, client_id, t.elapsed());
    let _ = reply.send(());
}
```

Two FFI calls. `key_store` is `Box<KeyStore>`. `galois_keys` and
`gsw_keys` are `Vec<u8>` payloads received over a WebSocket frame
(measured outside `t`, so transport time is not counted).

On fb14f4e the same call path completed in ~7 ms. On 2402b16 it takes
60–103 s of pure CPU time on the worker thread.

### Subsequent answer_query

After the slow registration, all per-group `Server::answer_query`
calls return empty `Vec`s within microseconds — the C++
`try/catch(...)` in `onion_server_answer_query` (`onion_ffi.cpp:677`)
swallows an exception silently. We added a diagnostic post-batch log
that confirms `empty=150/150, nonempty_total=0B, resp_len=0B` for the
INDEX round of 150 queries (75 groups × 2 cuckoo positions). On
fb14f4e the same batch took 162 s with `empty=0/150` and 11264-byte
responses each.

### Reverting to fb14f4e

Rolling back BitcoinPIR's three `Cargo.toml` refs from `2402b16` to
`fb14f4e` (and rebuilding — also 12-18 s incremental) restores the
previously-deployed working state on the same host. RegisterKeys
back to 7 ms; INDEX round back to 162 s with valid non-empty
responses. End-to-end smoke test passes via SSH tunnel
(`PIR_ONION_URL=ws://127.0.0.1:18091`).

So the regression is purely on the 2402b16 binary, with the exact
same BitcoinPIR-side Rust code.

---

## 2. Upstream test runs fine on the same host

```
$ ssh root@pir1 'bash -lc "
    cd /home/pir/.cargo/git/checkouts/onionpirv2-fork-98d68505f3e8db85/2402b16
    sudo -u pir cargo test --release --manifest-path rust/onionpir/Cargo.toml \
        parallel_answer_query_via_shared_keystore
"'
test parallel_answer_query_via_shared_keystore ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 16.14s
```

So the 2402b16 patch itself is correct on this host. The regression
emerges only under BitcoinPIR's specific usage pattern.

---

## 3. What's different about BitcoinPIR's usage

The upstream test attaches **one** `KeyStore` to **8** `Server`
instances created with `Server::new(SMALL_DB=1024)`. Registration
happens BEFORE any servers are attached. BitcoinPIR's
`unified_server.rs` worker thread does this instead (paraphrased):

```rust
// 1. Build the keystore (no client keys yet)
let mut key_store = Box::new(KeyStore::new());

// 2. Build 75 INDEX PirServers, each with its own per-instance
//    num_entries, attach the keystore.
for b in 0..k_index {  // 75
    let mut server = PirServer::new(index_bins as u64);  // ~10239
    unsafe { server.load_db_from_borrowed(slice); }
    unsafe { server.set_key_store(Some(&key_store)); }
    index_servers.push(server);
}

// 3. Build 80 CHUNK PirServers, also attaching the same keystore.
//    These use set_shared_database (indirect DB mode) over one shared
//    NTT-form backing buffer.
for g in 0..k_chunk {  // 80
    let mut server = PirServer::new(chunk_bins as u64);  // ~37853
    unsafe {
        server.set_shared_database(ntt_u64_slice, chunk_shared_num_entries,
                                   &index_table);
        server.set_key_store(Some(&key_store));
    }
    chunk_servers.push(server);
}

// 4. Build 25 sibling-L0 + 25 sibling-L1 PirServers, all attached.
//    (... similar to CHUNK ...)

// 5. NOW the worker thread enters its event loop. The first command
//    it receives is RegisterKeys for client_id. This is where wall
//    time blows up on 2402b16.
loop {
    match pir_rx.blocking_recv() {
        PirCommand::RegisterKeys { client_id, galois_keys, gsw_keys, reply } => {
            let t = Instant::now();
            key_store.set_galois_keys(client_id, &galois_keys);  // ← 60-100 s
            key_store.set_gsw_key(client_id, &gsw_keys);         // ← measured together
            // ...
        }
        PirCommand::AnswerBatch { .. } => { /* serial answer_query loop */ }
    }
}
```

Three potentially relevant differences from the upstream test:

1. **205 PirServers** instead of 8. If any new `thread_local` is
   keyed by some PirServer-side identity, OR if any internal data
   structure is sized by attached-server count, this could amplify
   first-touch costs.
2. **`load_db_from_borrowed`** (INDEX) and **`set_shared_database`**
   (CHUNK + sibling) modes, both with `set_key_store(Some(...))`
   afterwards. The upstream test uses `gen_data()` + `set_key_store`.
   If `load_db_from_borrowed`'s borrowed buffer interacts with the
   new thread_local NTT cache somehow (e.g. if `get_ntt` is now
   called from `load_db_from_borrowed`'s `validate_header` path,
   amplified by 75 INDEX servers)...
3. **HarmonyPIR hint-pool background threads** generating entries
   every 12 s, eating ~1 core. These threads are spawned by a
   separate tokio task and don't touch OnionPIR code paths
   directly — but they may interfere with the new mutex / thread-local
   init through OS-level scheduling.

---

## 4. Recommended next steps for upstream

In rough priority order:

### (a) Add a "many-server attach" microbench to upstream

Modify `parallel_answer_query_via_shared_keystore` to spawn `N_SERVERS
= 200` instead of 8, each with a DIFFERENT `Server::new(num_entries)`
value drawn from `[1024, 16384]`. If this reproduces the slow
`KeyStore::set_galois_keys`, the bug is exposed by attached-server
count + varied per-instance shapes.

### (b) Add a `KeyStore::set_galois_keys` timing print

Temporarily instrument `SharedKeyStore::set_galois_keys` to print
wall time and the size of the deserialized `BvGaloisKeys`. Push a
debug branch (`debug-keystore-timing-2402b16`). I'll bump
BitcoinPIR to that branch and report what shows up on pir1.

### (c) Investigate `__cxa_thread_atexit` scaling under glibc

If 2402b16 added several new `thread_local std::unordered_map` /
`thread_local TimerLogger` instances, each `thread_local`-of-non-trivial-type
registers a destructor via `__cxa_thread_atexit`. In glibc some
distros, this acquires a global lock per registration. If the
worker thread accumulates 200+ registrations on its first heavy
code path (one per attached PirServer that triggers the thread_local
on first use), the lock contention could explain the slowdown.

The fix would be to either: (i) lazy-init the thread_locals from
ONE entry point per thread (so the registration is paid once, not
per-attached-server), or (ii) replace the thread_local with explicit
per-thread storage that doesn't register destructors.

### (d) Check Coffee Lake-specific HEXL paths

`hexl/include/hexl/ntt/ntt.hpp` has runtime CPU-feature dispatch.
Coffee Lake (no AVX-512) goes through the AVX2 or scalar paths. If
any of those paths added thread-local init in 2402b16-coupled code
(via the new `get_ntt` thread_local cache), the AVX2 fallback might
have a slower init pattern than the AVX-512 path that Apple Silicon
+ M-series hosts hit.

---

## 5. BitcoinPIR-side mitigation in flight

Pending upstream investigation, BitcoinPIR has rolled pir1 back to
fb14f4e — restoring end-to-end smoke test success via SSH tunnel,
preserving the known CF idle-timeout gap (separately
[documented](ONIONPIR_PORT_MIGRATION.md)). The CF fix via
`.par_iter_mut()` is now on hold; we'll explore server-side
WebSocket keepalive frames as a no-upstream-dependency alternative
while the 2402b16 regression is investigated.

If the upstream investigation finds the issue is on BitcoinPIR's
side (e.g. a usage pattern that needs to change), please file a
matching `REQUEST_*.md` back at the BitcoinPIR worktree describing
what to change. The mediation flow is: upstream and downstream
exchange request docs; the user reads both and decides which side
to patch.

---

## 6. Repro one-liner

To reproduce on pir1 with 2402b16:

```bash
# 1. Bump BitcoinPIR's onionpir rev in 3 Cargo.tomls to 2402b16.
# 2. cargo build --release -p runtime --bin unified_server  (on pir1)
# 3. systemctl restart pir-primary  (on pir1)
# 4. From a workstation with an SSH tunnel to pir1:8091:
PIR_ONION_URL=ws://127.0.0.1:18091 cargo test \
    -p pir-sdk-client --features onion --test integration_test --release \
    test_onion_client_query_batch -- --ignored --nocapture
```

Expected output on fb14f4e: passes in ~400 s.
Observed output on 2402b16: panics with `SessionEvicted("...all-empty
batch...")` after ~165 s. Server-side log shows `RegisterKeys` taking
60-103 s instead of 7 ms.
