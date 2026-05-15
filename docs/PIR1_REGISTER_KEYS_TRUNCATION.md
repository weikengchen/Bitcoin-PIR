# RESOLVED: the OnionPIR "2402b16 regression" was a contaminated incremental C++ build

**Status:** RESOLVED 2026-05-15. This file previously theorised a
"transport truncation" bug. **That was wrong.** The real cause —
proven with end-to-end byte-level instrumentation — is a contaminated
incremental build of the `onionpir` crate's C++ library
(`libonionpir.a`). The filename is kept for git continuity; treat the
content below as the authoritative post-mortem.

## TL;DR

Flipping the `onionpir` git rev in the three `Cargo.toml`s back and
forth (`fb14f4e` ↔ `2402b16`, ~5 times in one debugging session)
left the cargo/cmake **incremental** build of `libonionpir.a` in an
inconsistent state. A contaminated `libonionpir.a` made the *client's*
`Client::galois_keys()` emit a **malformed, undersized** BV-galois-key
blob (379 KB of garbage instead of the correct 2,621,564 B). The
server's `deserialize_bv_galois_keys` then read a bogus `num_keys`
(`0x0410a15e` ≈ 68 M) from the garbage and spent ~60 s in a
memset/malloc/free loop — the "60 s key registration" symptom.

**Fix:** wipe the onionpir build artifacts and rebuild clean whenever
the pinned rev changes:

```bash
rm -rf target/release/build/onionpir-* \
       target/release/deps/*onionpir* \
       target/release/.fingerprint/onionpir-*
cargo build --release -p pir-sdk-client --features onion   # or -p runtime
```

(`cargo clean -p onionpir` is the tidy equivalent but the explicit
`rm -rf` is what was verified.)

## Proof

End-to-end instrumentation (client `register_keys` + server WS-loop),
two consecutive test runs against the *same* pir1 server:

| Run | Client `onionpir` build | `ws_bin` at server | `body_head` (galois_len) | Registration |
|---|---|---|---|---|
| contaminated | incremental, after rev-flips | 710,595 B | `8e c8 05 00` = 379,022 (garbage) | **56 s** ❌ |
| clean | `rm -rf onionpir-*` + rebuild | 3,145,873 B | `7c 00 28 00` = 2,621,564 ✓ | **1.12 ms** ✓ |

The server code, the transport, and the WebSocket layer never
changed between those two runs — only the client's `libonionpir.a`
was rebuilt clean. `3,145,873 B` is exactly the well-formed
`encode_register_keys` size (`4 + 1 + 4 + 2,621,564 + 4 + 524,296`);
`710,595 B` is exactly the *garbage-consistent* size the contaminated
build produced. The bug was 100 % client-side key serialization.

## Why earlier theories were wrong

* **"2402b16 thread-safety patch regressed it"** — no. The macOS repro
  agent built a *clean* `2402b16` and registration was 0.21 ms. The
  patch is sound; `parallel_answer_query_via_shared_keystore` passes.
* **"Hint-pool CPU thrashing"** — that *is* a real, separate startup
  issue (fixed by the systemd stagger in
  [`deploy/systemd/pir-secondary.service`](../deploy/systemd/pir-secondary.service)),
  but it only slowed registration to ~100 s *while the CPU was
  saturated*; the 55–60 s on a *quiesced* host was the contaminated
  build.
* **"Transport truncates the 3.1 MB message"** — no. The full
  3,145,873 B arrives intact (`ws_bin=3145873B` above). The
  contaminated build simply made the client *construct* a smaller,
  garbage message.

## Process lesson

The `onionpir` crate wraps a CMake C++ build via `build.rs`. CMake
incremental builds key off file mtimes and a configured build dir.
When cargo switches the git rev, it uses a *different* checkout but
can reuse build-script fingerprints / output dirs in ways that don't
always force a full C++ recompile. The symptom (silently-wrong
serialization, no compile error) is nasty. **Any change to the
`onionpir` pinned rev must be followed by a clean rebuild of that
crate** — add this to the migration runbook.

## Residual hardening (low priority)

A robust `deserialize_bv_galois_keys` should never spend 60 s on
malformed input. The optional upstream bounds-check ask in
[`UPSTREAM_REQUEST_2402b16_REGRESSION.md`](UPSTREAM_REQUEST_2402b16_REGRESSION.md)
still stands as defense-in-depth — had it been there, this would have
been a 1-second "deserialize threw: implausible num_keys" instead of
a multi-hour hunt — but it is no longer urgent, because no real
(clean-built) client ever emits a malformed blob.
