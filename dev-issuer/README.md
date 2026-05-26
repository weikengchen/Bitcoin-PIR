# dev-issuer

**DEV-ONLY** free credential issuer **and** verifier gate for the anonymous
rate-limiting demo (ARC + Cashu Blind Auth). No payment, no Lightning, no PIR
database. **Do not deploy to production.**

It stands in for the Lightning-backed payment service *and* the PIR server's
credential gate so the whole `mint → obtain → present → verify` loop runs as a
single process. The verify endpoints use the exact same crypto as
`pir_runtime_core::{arc_verifier, cashu_verifier}`; the present-frame bytes are
byte-identical to the PIR server's WebSocket `REQ_CREDENTIAL_PRESENT` (0x08) /
`REQ_CASHU_BAT_PRESENT` (0x09) frames — only the transport differs (HTTP here,
WebSocket in production).

## Run the demo

```bash
# 1. Start the issuer + gate (writes arc_key.bin + cashu_key.bin in CWD).
cargo run -p dev-issuer
#    → listening on http://127.0.0.1:5601

# 2. Serve the demo page.
cd web && npm run dev
#    → open http://localhost:3001/ratelimit-demo.html
```

Click **Mint** then **Present** in either column. ARC shows one credential
spending down N presentations; Cashu shows a pool of single-use BATs, with a
"Replay last" button to demonstrate double-spend rejection.

## Endpoints (CORS-open)

| Method | Path                  | In                          | Out                         |
|--------|-----------------------|-----------------------------|-----------------------------|
| GET    | `/dev/arc/pubkey`     | —                           | 99-byte `ServerPublicKey`   |
| POST   | `/dev/arc/issue`      | 226-byte `CredentialRequest`| 454-byte `CredentialResponse`|
| POST   | `/dev/arc/verify`     | `[0x08]…` present payload   | 200 ok / 400 reason         |
| GET    | `/dev/cashu/keyset`   | —                           | JSON `{id, pubkey}`         |
| POST   | `/dev/cashu/mint`     | `N×33` blinded points       | `N×33` blind signatures     |
| POST   | `/dev/cashu/verify`   | `[0x09]authA…` payload      | 200 ok / 400 reason         |

## Flags

- `--arc-key <path>` (default `arc_key.bin`) — 128-byte ARC key.
- `--cashu-key <path>` (default `cashu_key.bin`) — 32-byte secp256k1 scalar.
- `--port <n>` (default `5601`).

## Presenting against a real PIR server instead

The issuer prints a ready-to-run launch line on startup, e.g.:

```
unified_server --require-arc --arc-key arc_key.bin \
    --require-cashu --cashu-keyset <id>:<hex>
```

A client then presents the same frames over WebSocket
(`web/src/arc-present.ts::sendArcPresentation`, or `cashu-bat`'s
`buildPresentFrame` via `ManagedWebSocket.sendRaw`). The dev-issuer's
`/dev/*/verify` endpoints exist only so the demo needs no PIR database.
