# Anonymous Rate-Limiting Demo (ARC + Cashu)

A self-contained, browser-runnable demo of the two anonymous rate-limiting
schemes, end-to-end: **mint → obtain → present → verify**, with a live quota
meter, exhaustion, and replay/double-spend rejection.

It exists so the headline claim — *rate-limit queries without deanonymizing
the user* — can be seen working, not just asserted. Every byte boundary is
also covered by automated tests (see "What's tested" below); the demo is the
human-visible capstone.

## Run it

Two processes, no Lightning, no PIR database:

```bash
cargo run -p dev-issuer            # issuer + verify gate on http://127.0.0.1:5601
npm --prefix web run dev           # Vite on http://localhost:3001
# open http://localhost:3001/ratelimit-demo.html
```

The page checks issuer reachability on load (green banner = good; red banner
tells you to start the dev-issuer).

## What you'll see

**ARC column (multi-show):** one credential authorises *N* unlinkable
presentations.
- **Mint credential** → blinds a request in WASM (226 B), sends it to the
  issuer, finalises the 454 B response into a 131 B credential.
- **Present once** → each presentation is accepted by the gate; the quota
  meter ticks 8→0; at 0 the button disables (exhausted).
- **Replay last (rejected)** → re-sends the previous presentation; the gate
  rejects it (`duplicate ARC tag — nonce reused`). Each nonce is single-use
  even though the credential is multi-show.
- **Run to exhaustion** → mints then presents until the meter empties.

**Cashu column (single-show):** a pool of one-time Blind Auth Tokens (BATs).
- **Mint BAT pool** → for each BAT: blind a fresh secret (WASM), batch the
  blinded points to the mint, unblind each returned signature.
- **Spend one** → each BAT is accepted once; the meter drains.
- **Replay last (double-spend)** → re-spends a used BAT; the gate rejects it
  (`BAT already spent`).
- **Mint + spend all** → mints then spends the whole pool.

## ARC vs Cashu

| | ARC | Cashu Blind Auth |
|---|---|---|
| Shape | One credential, *N* presentations | Pool of *N* one-time tokens |
| Crypto | Algebraic MAC (P-256) + range proof | BDHKE (secp256k1) |
| Rate limit | Range proof bounds the nonce to `[0, limit)`; tags dedup per context | One token = one query; spent-set dedup |
| Unlinkability | Presentations are mutually unlinkable | Tokens are unlinkable to issuance |
| Wire (present) | `REQ_CREDENTIAL_PRESENT` (0x08) | `REQ_CASHU_BAT_PRESENT` (0x09), `authA…` |
| Issued blob | 131-byte credential | `{id, secret, C}` per BAT |
| Best when | Many queries per credential, fixed budget | Simple pay-per-query metering |

Both are redundant for the basic goal; the project ships both so the
trade-off can be demonstrated.

## Architecture

```
mint ── dev-issuer ── obtain ── browser (WASM) ── present ── dev-issuer gate ── verify
        (free, HTTP)            blind / finalize             (same crypto as the
                                                              PIR server's gate)
```

- **mint / obtain** — `WasmArcCredentialRequest` (`pir-sdk-wasm/src/arc.rs`) and
  `WasmCashuBlind` (`pir-sdk-wasm/src/cashu.rs`) do the blinding/finalising in
  WASM so secrets never reach JS; `web/src/payment-client.ts` +
  `web/src/cashu-bat.ts` orchestrate the HTTP calls.
- **present / verify** — `presentArc` / `presentCashu` post the *exact*
  `0x08` / `0x09` frame payloads (built by `ArcCredentialManager` /
  `CashuBatPool`) to the dev-issuer's `/dev/arc/verify` /
  `/dev/cashu/verify`.

> **Demo vs production.** The dev-issuer co-locates the verify gate so the demo
> needs no PIR database. The gate runs the *identical* crypto to
> `pir_runtime_core::{arc_verifier, cashu_verifier}` (the same
> `arc::verify_presentation`; the same Cashu `C == k·hash_to_curve(secret)` +
> spent-set). In production the same present frames go over **WebSocket** to
> the PIR server's gate (`unified_server --require-arc --arc-key … --require-cashu
> --cashu-keyset …`, which the dev-issuer prints a launch line for); only the
> transport differs.

The credential issuer here is **free** (no payment). In production the same
endpoints would be served by a Lightning-backed mint after a paid invoice.

## What's tested (no browser required)

- `cargo test -p pir-runtime-core --lib arc_verifier` — full ARC issue →
  present → verify loop with a shared key; wrong-key + replay rejection.
- `cargo test -p pir-sdk-wasm --lib` — WASM ARC obtain leg; a WASM-blinded
  Cashu BAT verified under the real `CashuVerifier` (h2c + BDHKE cross-check).
- `cargo test -p dev-issuer` — HTTP round-trips for ARC + Cashu, and the
  verify gate (present → accept, replay → reject) for both schemes.
- `npm --prefix web test` — `payment-client` HTTP + present helpers.

## Files

| Area | File |
|---|---|
| Issuer + gate | [`dev-issuer/`](../dev-issuer/) (`README.md` has endpoint details) |
| WASM obtain | [`pir-sdk-wasm/src/arc.rs`](../pir-sdk-wasm/src/arc.rs), [`pir-sdk-wasm/src/cashu.rs`](../pir-sdk-wasm/src/cashu.rs) |
| HTTP client | [`web/src/payment-client.ts`](../web/src/payment-client.ts) |
| BAT pool | [`web/src/cashu-bat.ts`](../web/src/cashu-bat.ts), [`web/src/credential-manager.ts`](../web/src/credential-manager.ts) |
| Demo page | [`web/ratelimit-demo.html`](../web/ratelimit-demo.html), [`web/src/ratelimit-demo.ts`](../web/src/ratelimit-demo.ts) |
| Server gate (prod) | [`runtime/src/bin/unified_server.rs`](../runtime/src/bin/unified_server.rs) (`--require-arc` / `--require-cashu`) |
