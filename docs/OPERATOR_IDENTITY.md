# Operator-Signed Identity (REQ_ANNOUNCE)

How a BitcoinPIR operator publishes a signed identity for each server, and
exactly what a client learns when it verifies one. This covers the
end-to-end **operator runbook** (generate → sign → deploy) and the
**client trust model** (what each check proves, and what it does not).

> **Status (2026-05-28).** **LIVE.** Deployed and live-verified end-to-end
> on both production servers: pir1 + pir2 serve REQ_ANNOUNCE on the
> announce-enabled binary (v22 `f7df82d0…` → current v23 `57ac525b…`). The
> pinned operator pubkey in `web/src/attest-pin.ts` is the **real**
> published key (`256fb106…`), and the "verified operator" badge is wired
> into the www client (DPF + HarmonyPIR cards) and the playground, gated on
> `state === 'verified'`. See [Current status](#current-status).

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
- **Validity** (`valid_from` / `valid_until`) is enforced by
  `check_pinned_operator` / `announce_bound` whenever you pass a real
  `now` (≠ 0). **Replay/staleness** is `check_freshness(now, max_age)` —
  but `issued_at` is the server's *boot time* (the bundle is built once
  at startup), so set `max_age` ≥ expected uptime, and lean on
  `check_channel_binding` (per-boot `channel_pub`) as the real
  anti-replay for DPF/Harmony. `check_freshness` always rejects
  future-dated bundles (300 s skew) and is the main staleness guard for
  the channel-binding-less OnionPIR path.
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
- ✅ Live-verified e2e (`test_announce_operator_identity_end_to_end`) — ok
  against pir1 (weikeng1) AND pir2 (weikeng2).
- ✅ Real operator key minted (2026-05-25) + pinned in `attest-pin.ts`
  (`PIR_OPERATOR_PUBKEY_HEX = 256fb106…`; secret offline at
  `~/.config/bpir-admin/operator.key`).
- ✅ **Deployed (2026-05-28):** pir1 + pir2 both run the announce-enabled
  binary (v22 `f7df82d0…` → v23 `57ac525b…`); both answer REQ_ANNOUNCE and
  verify under the pinned operator key.
- ✅ `BatchPirClientAdapter` (DPF) and `HarmonyPirClientAdapter` expose a
  gated `operatorIdentity` snapshot (opt-in via `verifyOperatorIdentity`);
  `gateOperatorIdentity` unit-tested.
- ✅ Standalone TS `OnionPirWebClient.announce()` — reuses the Rust
  parser/chain check via the WASM `verifyAnnounceResponse` binding
  (operator-pin + chain; channel-binding N/A — no attest/channel there).
- ✅ **"Verified operator" badge wired** into the www client (DPF +
  HarmonyPIR cards, `web/index.html`) and the playground
  (`OperatorIdentityBadge.tsx`), gated on `state === 'verified'`. OnionPIR
  excluded (single-server, no secure channel → channel binding N/A).

## Deployment status — RESOLVED (2026-05-28)

**Done.** The announce-enabled binary was deployed to **both** servers
(v22 `f7df82d0…`, then current v23 `57ac525b…` = v22 + the DPF/Harmony
anchor-offset fix) and the shared `binarySha256Hex` + pir2 `measurementHex`
re-pinned in `attest-pin.ts`. `announce()` against both
`wss://weikeng1.bitcoinpir.org` and `wss://weikeng2.bitcoinpir.org` returns
an operator-endorsed bundle that verifies under the pinned operator key
(`256fb106…`). The original coordinated-deploy checklist is retained below
as a historical record.

Done:
- Operator key + pir1/pir2 `IdentityCert`s signed (valid to 2029).
- pir1: identity key/cert at `/home/pir/data/pir1-{identity.key,.cert}`;
  `pir-primary` + `pir-secondary` carry `--identity-*` via systemd drop-in
  overrides (`/etc/systemd/system/pir-{primary,secondary}.service.d/override.conf`).
  Both restarted + verified `Identity announce: enabled (server_id=pir1)`.
- Operator pubkey pinned in `attest-pin.ts`.

**Steps 1–2 are DONE** (PR #9, merged to main `fda3eb47`):
- The dispatch arm is on main. `nix build .#unified-server` at `fda3eb47`
  reproduces (verified twice) to
  **`f7df82d04fb4a02fa51f6d595f04ea302fefece7da15b33bd30c7102f9729101`**
  (old deployed: `71a041ae…`). This is the binary to deploy + re-pin.
- The pir2 Tier-3 run script (`scripts/dracut/97bpir-tier3-init/unified-server-run.sh`)
  now carries `--identity-{key-path,cert-path,server-id pir2}` (key/cert
  read from the bind-mounted rootfs `/home/pir/data`, not baked/measured).

> **Shared-pin constraint:** `PIR1_PIN` and `PIR2_TIER3_PIN` share
> `binarySha256Hex`. The new binary must be live on **both** pir1 and
> pir2 *before* the pin flips, or clients reject whichever still runs the
> old one. Do the binary swap on both, then update the pin in one commit.

Remaining (operator-executed) — steps 3–5:

**3a. pir1 binary swap** (SSH; ~3 min cold-load each service):
```bash
ssh pir-hetzner
sudo -u pir bash -c 'cd /home/pir/BitcoinPIR && git fetch origin main && git checkout fda3eb47 && nix build .#unified-server && sha256sum result/bin/unified_server'
# expect f7df82d0…; then swap the binary the services exec:
cp -f /home/pir/BitcoinPIR/result/bin/unified_server /home/pir/BitcoinPIR/target/release/unified_server
systemctl restart pir-primary pir-secondary
journalctl -u pir-primary -n40 | grep -E 'Identity announce|Listening'   # expect "enabled (server_id=pir1)"
```
(pir1 identity key/cert + `--identity-*` are already staged from this session.)

**3b. pir2 Tier-3 UKI rebuild + provision** (Hetzner build host + VPSBG portal):
```bash
# provision the pir2 identity files into pir2's rootfs (Slice 2 first):
#   VPSBG portal → Measured Boot → UKI: None → Save & Reboot (boots Slice 2 w/ sshd)
scp ~/.config/bpir-admin/pir2-identity.key ~/.config/bpir-admin/pir2.cert vpsbg-pir:/home/pir/data/
ssh vpsbg-pir 'chmod 600 /home/pir/data/pir2-identity.key'
# build the new UKI (embeds f7df82d0 binary + the updated run script):
ssh pir-hetzner 'cd /home/pir/BitcoinPIR && git checkout fda3eb47 && nix build --impure .#tier3-uki'
scp pir-hetzner:.../bpir-tier3.efi deploy/uki/bpir-tier3-vNN.efi
#   VPSBG portal → upload UKI → Save & Reboot (back into Tier 3)
```

**4. Capture pins + re-pin** (after BOTH servers run f7df82d0):
```bash
./target/release/bpir-admin attest wss://weikeng2.bitcoinpir.org   # new measurement + binary_sha256
```
In `web/src/attest-pin.ts`: set `PIR1_PIN.binarySha256Hex` and
`PIR2_TIER3_PIN.binarySha256Hex` to `f7df82d0…`, and
`PIR2_TIER3_PIN.measurementHex` to the captured value. Commit.

**5. Verify announce live:**
```bash
PIR_ANNOUNCE_URL=wss://weikeng1.bitcoinpir.org \
PIR_ANNOUNCE_OPERATOR_PUB=256fb106c039f8009d3caa431a9634ff3fe5db3b9e4d9ae7282bbde66772c97a \
PIR_ANNOUNCE_SERVER_ID=pir1 \
  cargo test -p pir-sdk-client --test integration_test \
    test_announce_operator_identity_end_to_end -- --ignored --nocapture
# repeat for weikeng2 with PIR_ANNOUNCE_SERVER_ID=pir2
```

**6.** Flip web `verifyOperatorIdentity` on / wire the playground badge.

### Remaining work

- ✅ **C (binary release) — DONE (2026-05-28).** Announce-enabled binary
  (v23 `57ac525b…`) live on pir1 + pir2; pins updated.
- ✅ **D (UI badge) — DONE (2026-05-28).** "Verified operator" badge wired
  into the www client (DPF + HarmonyPIR cards) and the playground
  (`OperatorIdentityBadge.tsx` ← `BatchPirClientAdapter.operatorIdentity` /
  the `attestAndUpgrade` operator-identity verdict), gated on
  `state === 'verified'`. OnionPIR excluded (no secure channel).
- _Nothing outstanding._
