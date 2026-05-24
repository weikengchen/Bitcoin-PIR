# Operator-Signed Identity (REQ_ANNOUNCE)

How a BitcoinPIR operator publishes a signed identity for each server, and
exactly what a client learns when it verifies one. This covers the
end-to-end **operator runbook** (generate → sign → deploy) and the
**client trust model** (what each check proves, and what it does not).

> **Status (2026-05-24).** The full path is wired and live-verified
> end-to-end (`bpir-admin` → `unified_server --identity-*` → client
> `announce()`), but **not yet deployed on pir1/pir2** and the pinned
> operator pubkey in `web/src/attest-pin.ts` is currently a **DEV
> stand-in** (the e2e test key), not a real published key. See
> [Current status](#current-status).

---

## 1. Keys and tiers

Three keypairs are involved. Keep them straight — the whole trust
argument depends on which key signs what.

| Tier | Key | Algo | Lives | Signs | Rotation |
|------|-----|------|-------|-------|----------|
| **1** | Operator key | Ed25519 | **Offline**, operator workstation only | `IdentityCert` | Rare (root of trust) |
| **2** | Server identity key | Ed25519 | Server filesystem (inside the SEV guest on pir2) | `ChannelManifest` | Per server, occasional |
| — | Channel key | X25519 | Generated **per boot** inside the (SEV) guest; secret never on disk | the encrypted-channel handshake (ECDH) | Every reboot |

- **`IdentityCert`** (Tier-1 signed): `{ operator_pubkey, server_id,
  identity_pubkey, valid_from, valid_until, signature }`. The operator
  asserts: "for `server_id`, the legitimate Tier-2 identity key is
  `identity_pubkey`, valid in this window."
- **`ChannelManifest`** (Tier-2 signed): `{ identity_pubkey, server_id,
  channel_pub, binary_sha256, git_rev, manifest_roots, issued_at,
  signature }`. The server asserts: "this boot's channel key is
  `channel_pub`, running binary `binary_sha256` / `git_rev` over these
  DB `manifest_roots`."
- **`AnnouncementBundle`** = `{ cert, manifest }`, returned verbatim by
  `REQ_ANNOUNCE` (opcode `0x07`).

The channel key (`channel_pub`) is the hinge: attestation
(SEV-SNP `REPORT_DATA`, V2 layout) commits to it from the **hardware**
side, and the `ChannelManifest` commits to it from the **operator**
side. The client checks they're the same key, and that it's the key the
session actually handshook against.

Source: `pir-identity/src/lib.rs`.

---

## 2. What each client check proves

A client fetches the bundle with `announce()` and then layers checks. In
ascending order of assurance:

| Check | API | Proves | Does NOT prove |
|-------|-----|--------|----------------|
| In-bundle chain | `AnnounceVerification::chain_verified` | Manifest is signed by the `identity_pubkey` the cert names; `server_id` / `identity_pubkey` cross-refs agree. **Internal consistency.** | Authenticity. A MITM with its *own* operator+identity keys produces a self-consistent bundle. |
| Operator pin | `check_pinned_operator(pinned, now)` | Cert is signed by the **pinned operator key** (`cert.verify()`), within validity, and the chain check passed. **The operator you trust vouches for this identity key.** | That you're on the right *session* (see channel binding). |
| Channel binding | `check_channel_binding(expected)` | `manifest.channel_pub == expected` (the **attested** `server_static_pub` you handshook against). **Binds the bundle to the live encrypted session.** | Operator endorsement (orthogonal). |
| All three | `announce_bound(transport, pinned, expected_channel_pub, now)` | The full-trust path: operator-endorsed identity, bound to the attested channel key of the live session. | — |

> ⚠️ **Do not** hand-roll the operator check as a string compare of
> `operatorPubkeyHex == pin`. That checks only the *pubkey*, not the
> cert's operator **signature** — which neither `chain_verified` nor
> `check_channel_binding` covers. Use `check_pinned_operator` /
> `checkPinnedOperator`, which calls `cert.verify()`.

### The combined chain (when all checks pass, SEV server e.g. pir2)

1. **Hardware → channel key.** The SEV-SNP report, verified through the
   AMD VCEK chain (`verifyFull` / `bpir-admin attest`), attests that a
   genuine SEV-SNP guest running `binary_sha256` generated the X25519
   key `server_static_pub` (bound into `REPORT_DATA`, V2 layout).
2. **Channel binding.** `manifest.channel_pub == server_static_pub` →
   the announce bundle describes *this* session's channel key, not some
   other server's.
3. **Chain.** The manifest is signed by the identity key the cert names,
   for the same `server_id`.
4. **Operator pin.** The cert is signed by the operator key the client
   pinned out-of-band → the operator vouches that this identity key is
   the legitimate one for `server_id`, within the validity window.

Net: the client is talking to a server whose channel key is both
**chip-attested to a known binary** *and* **operator-endorsed**, bound
to the live session.

### Caveats / not proven

- **Trust bottoms out at the pin.** Operator-pin assurance is only as
  good as the out-of-band pin in `attest-pin.ts` (today a DEV stand-in).
- **Freshness/replay** (`manifest.issued_at`) and **validity**
  (`now` arg) are caller policy. `announce_bound` enforces validity when
  you pass a real `now`; replay-bounding via `issued_at` is not yet
  enforced (backlog item F).
- **pir1 has no SEV.** Step 1 (hardware attestation) is absent;
  `binary_sha256` there is self-reported and pinned only for drift
  detection. Channel binding + operator endorsement still hold.
- The client must supply `expected_channel_pub` itself — this crate
  doesn't track handshake state. Use the attested
  `AttestVerification.response.server_static_pub`.

Source: `pir-sdk-client/src/announce.rs`, `pir-sdk-wasm/src/client.rs`.

---

## 3. Operator runbook

All commands use `bpir-admin` (build: `cargo build --release -p bpir-admin`).

### Step 1 — Generate the operator key (offline, once for the fleet)

On your workstation, **never on a server**:

```bash
bpir-admin generate-identity --purpose operator --out ~/.config/bpir-admin/operator.key
# stdout: the 64-char operator PUBKEY hex (keep the .key secret offline)
```

One operator key signs the whole fleet; per-server certs differ only by
`server_id`.

### Step 2 — Publish + pin the operator pubkey

Publish the operator **pubkey** out-of-band so clients can pin it, and
record it in the client pin:

- `web/src/attest-pin.ts` → `PIR_OPERATOR_PUBKEY_HEX` (build-time pin —
  the current MVP mechanism; DNSSEC/Nostr can layer on later). Replace
  the DEV stand-in value and follow the provenance-comment convention
  used by `PIR1_PIN` / `AMD_TURIN_ARK_FINGERPRINT_HEX`.
- Native SDK clients pass the pubkey bytes to `announce_bound` /
  `check_pinned_operator` directly (there is no Rust-side pin module).

### Step 3 — Generate the server identity key (per server)

On (or for) each server host:

```bash
bpir-admin generate-identity --purpose server --out /path/to/server-identity.key
# stdout: the server's identity PUBKEY hex → hand to Step 4
```

For **pir2 (SEV-SNP / UKI Tier 3)** the key lives inside the guest;
provisioning it is part of the image/deploy flow (see the UKI build/deploy
section of `CLAUDE.md` → Operations and `scripts/build_uki_tier3.sh`). The
key file is *not* measured into `MEASUREMENT` (it's passed via
`--identity-key-path`, not the cmdline-pubkey path).

### Step 4 — Sign the cert (offline, operator)

```bash
bpir-admin sign-identity \
  --operator-key-path ~/.config/bpir-admin/operator.key \
  --server-id pir1 \
  --identity-pubkey-hex <server identity pubkey from Step 3> \
  --valid-until <unix-seconds>           # REQUIRED; 0 = indefinite (deliberate)
  # --valid-from <unix-seconds>          # optional, default 0
  # --out <path>                          # default ./<server_id>.cert
```

`sign-identity` verifies the signature after generating (catches a
typo'd `--identity-pubkey-hex`). Repeat per `server_id` (pir1, pir2, …).

### Step 5 — Deploy

Place the identity key + cert on the server and start `unified_server`
with all three flags (all-or-none):

```bash
unified_server --serve-queries \
  --data-dir <checkpoint> \
  --identity-key-path  /path/to/server-identity.key \
  --identity-cert-path /path/to/pir1.cert \
  --identity-server-id pir1
```

On success the startup log shows:

```
  Identity announce: enabled (server_id=pir1, identity_pub=<8 hex>…, issued_at=<ts>)
```

If a flag is missing, the key/cert disagree, or bundle-build fails, the
server logs `Identity announce: DISABLED — …` (or `not configured`) and
`REQ_ANNOUNCE` returns `RESP_ERROR` "announce not configured" — the rest
of the protocol (attest / handshake / queries) is unaffected.

`--identity-server-id` **must** equal the cert's `--server-id`.

### Step 6 — Verify the deploy

```bash
# Channel pubkey (== the value clients cross-check manifest.channel_pub against):
bpir-admin attest wss://weikeng1.bitcoinpir.org      # prints "channel pubkey: <hex>"

# Full client-side announce check (the durable integration test):
PIR_ANNOUNCE_URL=wss://weikeng1.bitcoinpir.org \
PIR_ANNOUNCE_OPERATOR_PUB=<operator pubkey hex> \
  cargo test -p pir-sdk-client --test integration_test \
    test_announce_operator_identity_end_to_end -- --ignored --nocapture
```

The binary is unchanged by the identity flags, so attestation pins
(`binarySha256Hex` / `measurementHex`) do **not** change on enabling
announce.

---

## 4. Client usage

### Native SDK (`pir-sdk-client`)

```rust
// after attest + handshake, with `server_static_pub` = the attested key:
let v = client.announce(/* server_index */ 0).await?;       // DpfClient::announce
v.check_pinned_operator(&PINNED_OPERATOR_PUBKEY, now_unix)?; // operator endorsement
v.check_channel_binding(&server_static_pub)?;                // bind to this session
// …or the all-in-one over a raw transport:
let v = announce_bound(&mut conn, &PINNED_OPERATOR_PUBKEY, &server_static_pub, now_unix).await?;
```

### Web / WASM (`pir-sdk-wasm`)

```ts
import { PIR_OPERATOR_PUBKEY } from './attest-pin';
const v = await wasmDpfClient.announce(0);         // WasmAnnounceVerification (serverIndex 0|1)
v.checkPinnedOperator(PIR_OPERATOR_PUBKEY, nowUnixSeconds);   // throws on failure
v.checkChannelBinding(attestVerification.serverStaticPub);    // throws on mismatch
// getters for display: v.serverId, v.operatorPubkeyHex, v.gitRev, v.validUntil, v.chainVerified
```

Or let `BatchPirClientAdapter` do it during `connect()` and read the
gated snapshot (this is what a badge should consume):

```ts
const adapter = new BatchPirClientAdapter({
  server0Url, server1Url,
  useSecureChannel: true,        // required — binds against the attested key
  verifyOperatorIdentity: true,  // default false (prod not configured + DEV pin)
  // pinnedOperatorPubkey defaults to PIR_OPERATOR_PUBKEY
  onOperatorIdentity: (i, info) => renderBadge(i, info),
});
await adapter.connect();
// adapter.operatorIdentity.server0.state ∈
//   'verified' | 'unconfigured' | 'unverified' | 'error' | 'not-checked'
// Gate the "verified operator" badge on === 'verified' ONLY.
```

---

## Current status

- ✅ Crypto, protocol (`0x07`), server build helpers, `unified_server`
  dispatch arm, `PirServerBuilder::with_announcement_bundle`, admin CLI,
  client `announce` / `announce_with_pinned_operator` / `announce_bound`
  / `check_pinned_operator` / `check_channel_binding`, WASM bindings.
- ✅ Live-verified e2e (`test_announce_operator_identity_end_to_end`).
- ✅ Build-time operator-pubkey pin scaffold (`attest-pin.ts`).
- ⏳ **Pin value is a DEV stand-in** — replace with a real published key.
- ⏳ **Not deployed** on pir1/pir2 (`--identity-*` flags unset → announce
  returns "not configured").
- ✅ `BatchPirClientAdapter` exposes a gated `operatorIdentity` snapshot
  (opt-in via `verifyOperatorIdentity`); `gateOperatorIdentity` unit-tested.
- ⏳ Playground still needs to render the badge from the snapshot;
  `issued_at` freshness policy not enforced; standalone TS
  `OnionPirWebClient` has no `announce()`.

### Remaining work

- **C** — generate the real operator key + deploy `--identity-*` to
  pir1/pir2 (replaces the DEV stand-in pin; flips `verifyOperatorIdentity`
  default to on once live).
- **D (playground)** — render the badge from
  `adapter.operatorIdentity.serverN.state` / `onOperatorIdentity`. The
  gating already lives in the adapter; the badge is the only remaining
  piece, in the playground repo.
- **E** — add `announce()` to the standalone TS `OnionPirWebClient`.
- **F** — enforce `valid_until` / `issued_at` freshness policy in clients.
