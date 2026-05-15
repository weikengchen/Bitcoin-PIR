# OnionPIR `RegisterKeys` over Cloudflare: the 3.1 MB key upload is corrupted in transit

**Status:** root cause confirmed 2026-05-16. This doc went through
several wrong drafts during a long debugging session; this is the
final, correct, consolidated version.

## The short version

OnionPIR key registration sends a **single ~3.1 MB WebSocket message**
(2.6 MB BV-galois keys + 0.5 MB GSW key + framing). That message:

- **survives a raw TCP / SSH-tunnel transport intact** → server
  registers keys in ~1 ms, full query smoke test passes in 79 s;
- **is corrupted when proxied through Cloudflare**
  (`wss://pir1.chenweikeng.com`) → the server's
  `deserialize_bv_galois_keys` reads a garbage length and burns
  ~55–60 s, then every `answer_query` returns empty → client sees
  `SessionEvicted`.

Proven by elimination: the **same** clean-built test binary
(`integration_test-3399053ae28c1fbd`, verified clean by a 994 µs
registration over the SSH tunnel) fails with a 55.9 s registration
when the only thing changed is `PIR_ONION_URL` from
`ws://127.0.0.1:18091` to `wss://pir1.chenweikeng.com`.

## Three distinct issues were found (don't conflate them)

This single symptom — "slow registration, empty queries" — had
**three independent causes**, discovered one at a time:

1. **Contaminated incremental `onionpir` C++ build.** Flipping the
   `onionpir` pinned git rev fb14f4e↔2402b16 repeatedly without a
   clean rebuild left `libonionpir.a` inconsistent → the *client*
   emitted a malformed galois blob. Fixed by always doing a clean
   rebuild of the `onionpir` crate after a rev change (`cargo clean`
   or `rm -rf target/release/build/onionpir-*`). Affected both
   transports. **Resolved.**

2. **Hint-pool startup CPU thrashing.** `pir-primary` +
   `pir-secondary` both run `--pool-size 8` HarmonyPIR V2 hint
   generation at boot, saturating the 6-core host for ~2 min. A
   client connecting in that window starves the OnionPIR worker
   thread. Fixed by the systemd stagger
   (`deploy/systemd/pir-secondary.service`:
   `After=pir-primary.service` + `ExecStartPre=/bin/sleep 90`).
   **Resolved.**

3. **Cloudflare corrupts the 3.1 MB `RegisterKeys` message.** The
   subject of this doc. **OPEN.**

The original Cloudflare problem this whole effort started from — the
OnionPIR INDEX *query* taking 162 s, exceeding CF's ~100 s WebSocket
idle timeout — **is fixed**: the rayon-parallel `AnswerBatch`
(`unified_server.rs`, rev 2402b16) drops INDEX to ~20 s and CHUNK to
~36 s, each well under 100 s. Issue 3 is a *separate* CF limitation
on a single large *message*, not idle time.

## Evidence for issue 3

| transport | client binary | registration | result |
|---|---|---|---|
| `ws://127.0.0.1:18091` (SSH tunnel) | 3399053a (clean) | **0.99 ms** | full smoke PASS, 79 s |
| `wss://pir1.chenweikeng.com` (CF) | 3399053a (clean, *same binary*) | **55.9 s / 58.1 s** | SessionEvicted |

Server-side instrumentation on the SSH-tunnel path showed the
message arriving intact (`ws_bin=3145873B`, galois_len=2,621,564,
`body_head=[7c 00 28 00 0a 00 00 00 …]` — a correct
`encode_register_keys` frame). cloudflared's own logs show nothing —
the corruption is silent.

`pir-channel::seal` (the encrypted-channel layer) does **not** chunk:
it AEAD-encrypts the whole plaintext into one
`[magic][seq:8][ct+tag]` frame → still one giant WebSocket message.
So routing `RegisterKeys` through the encrypted channel would not
help.

## Recommended fix: chunk the key upload

`encode_register_keys` (`pir-sdk-client/src/onion.rs:2170`) currently
builds one `[payload_len][REQ_REGISTER_KEYS][galois_len][galois][gsw_len][gsw][db_id?]`
buffer and `conn.roundtrip()`s it as a single WebSocket message.
Split it into a sequence of bounded (e.g. 256 KB) chunk messages:

- New wire ops: `REQ_REGISTER_KEYS_CHUNK { seq, total, bytes }` +
  a terminal `REQ_REGISTER_KEYS_COMMIT`.
- Server (`unified_server.rs`) accumulates chunks per connection,
  then assembles + dispatches the existing
  `PirCommand::RegisterKeys` once `COMMIT` arrives.
- Mirror the chunking in `web/src/onionpir_client.ts` (the
  standalone TS client — SEAL doesn't compile to wasm32) so browser
  clients work through CF.

Precedent: HarmonyPIR already streams its large V2 hint payloads in
pieces (recent `perf(harmony): V2-half protocol — split V2 main
hint stream across 2 sockets` / `feed+flush` commits). OnionPIR's
`RegisterKeys` is the one remaining un-chunked multi-MB upload.

256 KB is a safe chunk size — well under any plausible CF WebSocket
message limit, and the existing OnionPIR query/response messages
(~11 KB each, batched ≤ ~1 MB) already traverse CF fine.

A defense-in-depth companion (already filed upstream in
[`UPSTREAM_REQUEST_2402b16_REGRESSION.md`](UPSTREAM_REQUEST_2402b16_REGRESSION.md)):
`deserialize_bv_galois_keys` should bounds-check its length fields so
a corrupt blob throws instantly instead of looping 60 s.

## Current production state

`pir1` (Hetzner) runs `2402b16 + rayon-parallel` (commit
`37957a86`), serving 2 databases (`main` + `delta_940611_948454`).
OnionPIR works end-to-end **directly** (SSH tunnel: 79 s full smoke
PASS). OnionPIR over **`wss://pir1.chenweikeng.com`** is broken at
the key-registration step until the chunked upload lands. DPF and
HarmonyPIR over CF are unaffected (their messages are small / already
chunked).
