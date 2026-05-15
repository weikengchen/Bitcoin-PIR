# OnionPIRv2 `2402b16`: EXONERATED — optional deserializer hardening only

**Status:** 2026-05-15, final. This file went through three wrong
drafts (blamed the `2402b16` thread-safety patch; then hint-pool
thrashing; then a transport truncation). **All wrong.** The actual
root cause was a contaminated incremental build of `libonionpir.a` on
the *downstream* (BitcoinPIR) side — full post-mortem in
[`PIR1_REGISTER_KEYS_TRUNCATION.md`](PIR1_REGISTER_KEYS_TRUNCATION.md).

**`2402b16` is sound.** No action is required for correctness:

- The thread-safety patch (`thread_local` g_scratch / NTT cache /
  TimerLogger + `SharedKeyStore` mutex) is correct.
- `parallel_answer_query_via_shared_keystore` passes.
- A clean `2402b16` build registers keys in ~1 ms and answers
  queries correctly, on both Apple Silicon and pir1's Intel host.

## Optional ask (low priority): bounds-check the deserializers

The one thing worth doing upstream — purely defense-in-depth, not a
correctness fix:

`deserialize_bv_galois_keys` (`src/onion_ffi.cpp:156`) and
`deserialize_gsw_ct` (`:190`) read `num_keys` / `num_cts` / `poly` /
`num_rows` / `row_size` as raw `u32`s and loop on them with no
sanity check. When fed a malformed blob (which is exactly what a
contaminated downstream build produced — a galois blob whose first
`u32` was `0x0410a15e` ≈ 68 million), the function spends ~60 s in
`vector::assign` (memset) + `malloc`/`free` before the `Reader`'s
short-read guard finally throws.

Had a cheap up-front bounds-check been present, this would have
surfaced as an instant `throw std::runtime_error("implausible
num_keys")` instead of a 60 s silent stall — turning a multi-hour
debugging session into a one-line log.

Suggested guard (drop into `deserialize_bv_galois_keys`, mirror for
`deserialize_gsw_ct`):

```cpp
const uint32_t num_keys = r.u32();
if (num_keys > 1024)                       // TREE_HEIGHT is ~10
    throw std::runtime_error("deserialize_bv_galois_keys: implausible num_keys");
// ... per key:
if (num_cts > 64 || poly > (1u << 20))     // L_KS ~8, poly = N*K
    throw std::runtime_error("deserialize_bv_galois_keys: implausible num_cts/poly");
const size_t need = size_t(num_cts) * poly * 2 * sizeof(uint64_t);
if (!r.has(need))
    throw std::runtime_error("deserialize_bv_galois_keys: truncated key body");
```

All caps are >50× the real values for every shipped `ACTIVE_CONFIG`,
so no well-formed input is ever rejected. The existing `catch (...)`
in `onion_key_store_set_galois_keys` already swallows the throw, so
there is no API/behaviour change for good input.

**This is genuinely optional** — no real (clean-built) client emits a
malformed blob. File it as a hardening nice-to-have, not a bug fix.
If you do land it, reply with the SHA; BitcoinPIR will pick it up at
the next routine rev bump.

## What is NOT being asked

- No change to `serialize_*` / the wire format — fine.
- No change to the thread-safety patch — sound.
- No urgency. `2402b16` can be deployed downstream as-is.
