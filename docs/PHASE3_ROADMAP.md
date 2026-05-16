# Phase 3 (Attested Lockdown) — Roadmap

Snapshot of work that landed across the 2026-05-02 / 2026-05-03
deployment cycle:
- Slices 1–4 of the dynamic attestation surface (DB manifests,
  `/attest`, ed25519 admin auth, DB upload protocol, `bpir-admin` CLI)
- VPSBG as the second non-collusion server + `weikeng2.bitcoinpir.org`
  Cloudflare tunnel
- Phase 3 Slice 1 (UKI builder + `--expect-measurement` verifier flag)
- Phase 3 Slice 2 (dracut hook enforces the binary pin at pre-pivot
  — operator tamper-tested end-to-end on VPSBG 2026-05-02)
- Encrypted channel (Slices A–C, deployed 2026-05-03): X25519 long-
  lived server keypair generated inside the SEV-SNP guest at boot,
  bound into REPORT_DATA via the V2 layout. Per-session ECDH +
  ChaCha20-Poly1305 AEAD frame wrapping. cloudflared sees only
  ciphertext for any client that runs the handshake. End-to-end
  verified via `bpir-admin channel-test wss://weikeng2.bitcoinpir.org`.
- **Phase 3 Slice 3 — Tier 3 Lockdown** (deployed 2026-05-03 evening):
  unified_server now runs from inside the UKI's initramfs (binary
  bytes directly in MEASUREMENT, not just transitively pinned).
  sshd is gone. Operator access is `bpir-admin` over WSS only. See
  [PHASE3_SLICE3_PLAN.md](PHASE3_SLICE3_PLAN.md) for the
  architectural decisions + post-mortem and
  [PHASE3_SLICE3_RECOVERY.md](PHASE3_SLICE3_RECOVERY.md) for operator
  recovery if a future Tier 3 UKI bricks the box.

This document is the canonical to-do for the next sessions on this
work. Pick up by re-reading the "Current state" summary, then jumping
to whichever slice you want to start on.

---

## Current state (as of 2026-05-03 evening, Slice 3 Tier 3 deployed)

### Production deployment

| | |
|---|---|
| `weikeng1.bitcoinpir.org` | Hetzner i7-8700, role=primary, DPF + OnionPIR + HarmonyPIR query, 125 GB RAM, 944 GB disk. Cloudflared tunnel terminates here. **Not** SEV-attested (Intel chip). |
| `weikeng2.bitcoinpir.org` | VPSBG EPYC 9745 (Zen 5), role=secondary, DPF + HarmonyPIR hint, **SEV-SNP active** at VMPL0, **Tier 3 UKI loaded**: `unified_server` runs from initramfs, no rootfs pivot for the service, sshd gone. cloudflared also runs from initramfs (supervised by runit alongside unified_server). Rootfs is mounted (rw) only to expose `/home/pir/data` for DBs + VCEK chain. 48 GB disk, 22 GB used. |
| Cloudflare tunnels | Two: Hetzner (existing) for pir1, VPSBG (new) for pir2. Both healthy. |
| DBs in production | `main` (height 940611), `delta_940611_944000`. Both have `MANIFEST.toml`. |
| Hetzner `pir-secondary.service` | Stopped + disabled (port 8092 free). Unit file kept for hot-spare revival via `systemctl start pir-secondary`. |

### Attested values published (operator: weikengchen) — Tier 3 (Slice 3) baseline

These are live values from the running pir2 — anyone can verify with `bpir-admin attest`.

```
Server: wss://weikeng2.bitcoinpir.org

Launch MEASUREMENT (covers OVMF + Tier 3 UKI bytes — UKI now contains
the unified_server BINARY itself in initramfs, NOT just a cmdline hash
pin. So this digest authenticates the literal binary bytes the box is
running, not "a binary the box claims matches a hash"):
  2ad9490a64a48d7ab9af1045c5a5abe2b8308edcb13f966a9c95eea3709c4018faf161f52eb3c6063c1e241f19fd6fe5

UKI bytes sha256 (built by scripts/build_uki_tier3.sh on vpsbg-pir;
includes initramfs with unified_server + cloudflared + runit + the
sev-guest/ccp/tsm_report kernel modules baked in):
  afbc07f8ea8df7f24e0d92980184bcc61e8762dbe3bbf0e161ef08bdf8b8fe90

unified_server binary sha256 (computed at build time AND attested at
runtime via /proc/self/exe — the two match because dracut was invoked
with --nostrip; verifiers pin via --expect-binary on bpir-admin attest):
  324c3883510c56a344221ec379a6466c3089099f51e566e7ad9b1356156eee7e

ARK fingerprint (AMD Turin family root certificate — pinned in
web/src/attest-pin.ts and used by --expect-ark-fingerprint to anchor
the ARK→ASK→VCEK chain):
  1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a

DB manifest roots (db_id order):
  main (940611):              8911588dde20282726b5f2ae8e2c3152c673d636dc6a10295d9b9037e36fba11
  delta_940611_944000:        b1822802cfb193b80c57974e43388d2389c11715eb7b3d56fcd062c348f03f3a

Server git rev (per /attest, captured at unified_server build time):
  616f7839dcc6744638f9451f0489a79aa6947329
```

NOTE on the X25519 channel pubkey: it's "long-lived" relative to per-
session ECDH (which is fresh per handshake), but it IS regenerated on
every server-process start (i.e. every reboot). Verifiers should NOT
pin it across reboots — they observe it dynamically via attest and
cross-check the REPORT_DATA binding. The current value as of last
boot is `08224ddcc2288cb5fec9a7cd2c9d5a69bca6287d9da34203ad231f6b9d739e05`
but it'll be different next reboot.

Verifiers can cross-check end-to-end with:
```bash
# Static checks: report binding + binary + measurement + ARK chain
bpir-admin attest wss://weikeng2.bitcoinpir.org \
    --expect-measurement 2ad9490a64a48d7ab9af1045c5a5abe2b8308edcb13f966a9c95eea3709c4018faf161f52eb3c6063c1e241f19fd6fe5 \
    --expect-binary 324c3883510c56a344221ec379a6466c3089099f51e566e7ad9b1356156eee7e

# Live encrypted channel + AMD VCEK chain validation
bpir-admin channel-test wss://weikeng2.bitcoinpir.org \
    --expect-ark-fingerprint 1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a
```

### Full Layer 3 reproducibility — verified 2026-05-03

The published MEASUREMENT can now be **independently reproduced from
public artifacts** — no need to trust any operator-published value.
Verified bit-for-bit against pir2's chip-reported MEASUREMENT for
both the Tier 3 v2 production UKI and the Slice 2 revert UKI.

Recipe:

```bash
# 1. Get VPSBG's Measured Boot OVMF (custom EDK2 build with the
#    SNP_KERNEL_HASHES section that the stock Proxmox OVMF lacks).
#    Fetched via VPSBG support; binary ships with sha256:
#      e4ac90be71f3b455922ebc7106c5630536bf67027de585e34319b0a42fcd716e
#    To request a fresh download link, file a ticket asking for
#    OVMF_SEV_MEASUREDBOOT_4M.fd. (VPSBG also offered to publish the
#    exact EDK2 commit + build flags for full source reproducibility.)

# 2. Get the UKI being attested (operator-published bytes).
#    For Tier 3 v2 the published bytes are at:
#      uki sha256:    afbc07f8ea8df7f24e0d92980184bcc61e8762dbe3bbf0e161ef08bdf8b8fe90
#    Anyone with the operator-side build environment can reproduce
#    via `scripts/build_uki_tier3.sh` (operator binary + Proxmox
#    + Ubuntu deps required for full bit-equivalence).

# 3. Compute predicted MEASUREMENT.
sev-snp-measure --mode snp \
    --vcpus 2 --vcpu-sig 0x00B10F10 \
    --ovmf OVMF_SEV_MEASUREDBOOT_4M.fd \
    --kernel bpir-tier3-phase32-v2.efi \
    --guest-features 0x1
# expected output: 2ad9490a64a48d7ab9af1045c5a5abe2b8308edcb13f966a9c95eea3709c4018faf161f52eb3c6063c1e241f19fd6fe5

# 4. Cross-check against the chip's signed report.
bpir-admin attest wss://weikeng2.bitcoinpir.org \
    --expect-measurement 2ad9490a64a48d7ab9af1045c5a5abe2b8308edcb13f966a9c95eea3709c4018faf161f52eb3c6063c1e241f19fd6fe5
```

Trust chain after this verification: a verifier who accepts AMD's
ARK as the silicon-rooted trust anchor (and accepts that VPSBG's
disclosed OVMF is the binary they actually use — confirmable by the
above hash matching the chip-signed MEASUREMENT) can establish that
pir2 is running the specific (OVMF + UKI + binary) tuple operator-
published. No trust in the operator's MEASUREMENT claim is required;
the operator's MEASUREMENT is independently computable.

Launch parameters (constants for sev-snp-measure):

| Parameter | Value | Source |
|---|---|---|
| --vcpus | 2 | `nproc` inside guest, also in SEV-SNP report |
| --vcpu-sig | 0x00B10F10 | AMD EPYC 9745 Turin: family=26, model=17, stepping=0 |
| --ovmf | OVMF_SEV_MEASUREDBOOT_4M.fd | VPSBG-disclosed custom build (sha256 e4ac90be…d716e) |
| --kernel | the .efi UKI uploaded via VPSBG portal | operator-published bytes |
| --guest-features | 0x1 | SNP_FEATURES_SNP_ACTIVE only |
| (no --initrd, no --append) | — | UKI carries its own initrd + cmdline |

### Previous (Slice 2) attested values — superseded 2026-05-03

The Slice 2 baseline (rootfs-resident binary + cmdline hash pin via
dracut bpir-verify hook) has been retired. Old values for historical
reference:
- MEASUREMENT: `e522983f0d595b99157c9612cb623522044110c5154807df8b5f700da33c09932f14137c8afef2e53127b61b6402ce0a`
- UKI sha256: `8449585e863397dadf7ee55a3af88e9fb52494466ac61bd7edd69bb9e72e1cef`

### Slices 1–4 of the dynamic attestation work

All landed and deployed. See commits `2858f54`, `c167579`, `ab9c0dc`,
`dcbcd2b`, `f2fafcd`. Tooling in `bpir-admin/`.

### Phase 3 Slice 1 (UKI builder)

Landed (`f7a308b`). `scripts/build_uki.sh` produces a UKI that bakes
the binary's SHA-256 into the kernel cmdline. `bpir-admin attest
--expect-measurement` cross-checks the chip-signed launch digest.

### Phase 3 Slice 2 (dracut hook — landed + tamper-tested)

Landed in code (`e81ad56`) plus the determinism follow-up (`d8cb85c`).
Tamper-tested live on vpsbg-pir 2026-05-02:

- Tampered `/home/pir/BitcoinPIR/target/release/unified_server`
  (`b338434f…` → `0abacfa4…`) and rebooted.
- Dracut bpir-verify hook fired at pre-pivot, detected hash mismatch
  vs cmdline pin, dropped to `emergency_shell`.
- Both probes confirmed boot was halted before any systemd service
  started: `ssh vpsbg-pir` → connection timeout (sshd never started),
  `bpir-admin attest` → cloudflare 530 (cloudflared never started).
- Recovery via VPSBG portal "None" UKI fallback → cp .bak back →
  re-upload Slice 2 UKI → clean reboot. New MEASUREMENT
  `8d60b7dc…` published above.

`scripts/dracut/95bpir-verify/{module-setup.sh, bpir-verify.sh}`
defines the pre-pivot hook. `scripts/build_uki.sh` installs the
module to `/usr/lib/dracut/modules.d/95bpir-verify/` and pulls it
into a freshly-generated `/tmp/bpir-initrd.img` via `dracut --force
--no-hostonly --reproducible --add bpir-verify` (with
`SOURCE_DATE_EPOCH=0`). The custom initrd is the one packed into
the UKI by ukify.

The module is opt-in via `--add bpir-verify` only — there is no entry
in `/etc/dracut.conf.d/`, so future kernel-update autogenerated initrds
(triggered by `apt install linux-image-*`) will not pick up the hook.
Only build_uki.sh does.

---

## Operational reference (Tier 3 in production)

### Binary update flow

Every `unified_server` rebuild requires a fresh Tier 3 UKI bake +
portal upload + reboot. The new binary's bytes are inside the UKI's
initramfs (and therefore in MEASUREMENT), so any binary update changes
both the published binary sha256 AND the published MEASUREMENT.

WARNING: Tier 3 has no SSH. The build host is pir2 itself — to
re-bake you have to revert to Slice 2 first (so SSH works), build,
swap back to Tier 3. Or maintain a separate build host with the same
toolchain. Path below assumes operator handles the revert manually
via portal.

```bash
# 1. Revert pir2 to Slice 2 via VPSBG portal (upload bpir-slice2-revert.efi).
#    Wait ~90s for sshd.
# 2. Build the new binary on pir2.
ssh vpsbg-pir 'sudo -u pir bash -lc "
    source ~/.cargo/env && cd /home/pir/BitcoinPIR &&
    git fetch origin && git reset --hard origin/main &&
    CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release -p runtime --bin unified_server
"'
# 3. Re-bake the Tier 3 UKI.
ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki_tier3.sh'
scp vpsbg-pir:/tmp/bpir-tier3.efi ./deploy/uki/bpir-tier3-vNNN.efi
# 4. Upload via VPSBG portal → Measured Boot → UKI → Save & Reboot.
# 5. After reboot, capture + republish the new MEASUREMENT + binary sha.
./target/release/bpir-admin channel-test wss://weikeng2.bitcoinpir.org \
    --expect-ark-fingerprint 1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a
./target/release/bpir-admin attest wss://weikeng2.bitcoinpir.org
```

### Recovery — Tier 3 UKI bricks the box

See **[PHASE3_SLICE3_RECOVERY.md](PHASE3_SLICE3_RECOVERY.md)** for the
full step-by-step. TL;DR: VPSBG portal → upload `bpir-slice2-revert.efi`
→ Save & Reboot, or fall through to "None" → stock Ubuntu boot → SSH
back in.

---

## Slice 3 — Tier 3 lockdown — SHIPPED 2026-05-03 evening

✅ **Done.** `unified_server` runs from inside the UKI's initramfs
(MEASUREMENT covers the binary bytes directly), sshd is gone, operator
access is `bpir-admin` over WSS only. New MEASUREMENT
`2ad9490a…3709c4018faf161f52eb3c6063c1e241f19fd6fe5` published above.

For the architectural decisions + four-iteration post-mortem (cloudflared
arg-order bug, cloudflared env-var bug, missing DNS, VPSBG-uses-static-IP
discovery, dracut-strips-binaries, sev-guest needs explicit modprobe),
see [PHASE3_SLICE3_PLAN.md](PHASE3_SLICE3_PLAN.md). For operator
recovery if a future Tier 3 UKI bricks the box, see
[PHASE3_SLICE3_RECOVERY.md](PHASE3_SLICE3_RECOVERY.md).

The original architectural sketch below is retained for historical
context; the actual implementation diverged in places (notably:
runit not s6-overlay, static IP not DHCP, ephemeral logs ok).

### Original sketch (superseded — see PHASE3_SLICE3_PLAN.md)


**Goal**: the UKI itself contains everything needed to run
`unified_server` — kernel + initramfs (with binary, libs, configs) +
cmdline (admin pubkey, listen port). No rootfs needed for the service
to start. Drop sshd entirely.

### What changes from Slice 2

| | Slice 2 (Hybrid) | Slice 3 (Lockdown) |
|---|---|---|
| Binary location | rootfs `/home/pir/...`, verified by initramfs | initramfs `/usr/local/bin/unified_server`, runs from there |
| MEASUREMENT covers binary | Transitively (cmdline pins hash) | Directly (binary bytes are in UKI) |
| sshd | available | **gone** — no rootfs, no sshd |
| Operator access | SSH to box | `bpir-admin` over WSS only |
| DB upload | `bpir-admin upload` (already wired) | unchanged |
| Binary update | Rebuild → upload UKI → reboot | unchanged |

### Architectural decisions to make before coding

- **Networking**: dhcp via dhclient in initramfs, or static IP from
  cmdline? Recommend dhcp (dynamic IP from VPSBG). Need
  `dracut --add-drivers " virtio_net "` and dhcp client in initramfs.
- **Persistent storage**: where do the DBs live? Two options:
  - (a) Separate ext4 partition on `/dev/sda2` mounted at `/data` in initramfs.
  - (b) Reuse the existing rootfs partition for `/data/` only — initramfs
    mounts the existing rootfs read-only-except-/data.
  Recommend (a) for clean isolation, but (b) if disk repartitioning
  is operationally painful on VPSBG.
- **Logs**: where do they go? Without a rootfs, `journalctl` storage
  is gone. Options:
  - (a) Send to console only (VNC visible).
  - (b) Set up a small writable volume just for `/var/log/journal`.
  - (c) Forward via a journal-remote sidecar to Hetzner.
  Recommend (a) for MVP.
- **DNS resolution**: needed for cloudflared if we keep that on VPSBG
  (which we do — weikeng2.bitcoinpir.org routes through it). cloudflared
  resolves AMD's KDS endpoint and Cloudflare's edge. Bake systemd-resolved
  + /etc/resolv.conf pointing at 1.1.1.1 in the initramfs.
- **cloudflared in the UKI?**: yes, otherwise weikeng2.bitcoinpir.org goes
  dark. Add cloudflared binary + token + supervisor (s6-overlay or
  similar) into initramfs.
- **Admin key rotation**: the admin pubkey lives in the UKI cmdline.
  Rotating means rebuilding + reuploading the UKI, then rebooting.
  Document this in the operator README.

### Tools/deps needed

- `mkosi` or rich `dracut` config (probably mkosi for the
  binary+supervisor packaging; dracut to build the initrd itself).
- A small runit/s6 supervisor to manage two long-running processes
  inside the initramfs (`unified_server` + `cloudflared`).
- `cloudflared` static binary (already shipped by Cloudflare).
- All `unified_server`'s dynamic deps: `ldd
  target/release/unified_server` to enumerate. Roughly: libssl,
  libcrypto, libpthread, libgcc_s, libstdc++ (from SEAL static link),
  libc, ld-linux.

### Acceptance criteria

1. After UKI upload and reboot, `bpir-admin attest
   wss://weikeng2.bitcoinpir.org` returns ReportDataMatch with the new
   MEASUREMENT (different from Slice 1+2's value because the UKI
   bytes now include the binary).
2. `ssh vpsbg-pir 'echo hi'` fails (no sshd).
3. The VPSBG VNC console shows `unified_server` and `cloudflared`
   running supervised.
4. `bpir-admin upload <name> <dir> --target-path … --server
   wss://weikeng2.bitcoinpir.org` still works.

### Estimate

~1.5 to 2 weeks. Significant new ground: initramfs as full OS,
supervised processes, in-initramfs networking, mkosi/dracut tuning,
testing rollback paths over VPSBG VNC.

### Risk: rollback complexity

If a Tier 3 UKI fails to boot, the operator's only fallback is the
VPSBG portal: re-upload a previous-known-good UKI (or the vanilla
"None" option to revert to stock Ubuntu boot). Make sure to keep at
least one known-good UKI checked in so this is one command:
```bash
scp known_good_bpir.efi vpsbg-pir:/tmp/...   # via... wait, no SSH after Slice 3.
# Actually: re-upload via the VPSBG portal from the laptop.
```

So the operator README must include a "if Tier 3 UKI bricks the box"
recovery checklist.

---

## Web frontend updates

The web client (`web/`) has two relevant concerns this work introduces:

### 1. Display attestation status in the UI

Right now the SDK has the attestation primitives
(`pir_sdk_client::attest::attest`) but the web wrapper doesn't expose
them. Add a small UI element to the existing client page (`web/src/`):

- Periodic background `/attest` against pir1 + pir2.
- For pir1 (Hetzner, no SEV): green badge "self-reported attestation
  (no hardware backing)" with binary_sha256 + git_rev visible.
- For pir2 (VPSBG, SEV-SNP): green badge "✓ Verified via SEV-SNP"
  showing the launch MEASUREMENT and a tooltip explaining what was
  attested. Cross-check against operator-published values baked into
  the page bundle at build time (so any divergence is immediately
  visible).

Implementation surface:
- New `web/src/attest-badge.ts` (or similar) — runs the attest call
  via the existing `WasmDpfClient` connection, parses the response,
  renders status.
- Add a build-time constant for expected MEASUREMENT (like
  `VITE_BPIR_EXPECTED_MEASUREMENT_PIR2=f568fc1f…`).
- Document the publication flow: when the operator uploads a new UKI
  to VPSBG, they:
  1. Re-bake UKI, capture new MEASUREMENT.
  2. Update `VITE_BPIR_EXPECTED_MEASUREMENT_PIR2` in `.env`.
  3. Rebuild + redeploy the web client.

### 2. AMD VCEK chain verification (optional, deferred)

Currently `bpir-admin attest` (and the analogous browser flow) trust
that the SEV-SNP report's signature is valid. To be truly
independent, the verifier should:
- Fetch AMD's ARK + ASK + VCEK for the chip from
  `https://kdsintf.amd.com/vcek/v1/Turin/<chip-id>?...`
- Verify the cert chain: ARK self-signed → ARK signs ASK → ASK signs VCEK.
- Verify the SEV report's ECDSA-P384 signature against the VCEK.

Doing this in browser context requires either:
- A WASM build of the verification code (cleanest; reuses
  `pir_core::attest` + ed25519/ECDSA crates compiled to wasm32).
- A Cloudflare Worker that does the verification and returns a
  signed assertion (more centralized, less ideal).

Recommend: WASM build, ship as part of the SDK. Estimate ~3 days.

### 3. Confirm `--role secondary` doesn't break existing client flows

The web client expects:
- pir1 (Hetzner primary) handles `REQ_HARMONY_QUERY` and `REQ_HARMONY_BATCH_QUERY` (online).
- pir2 (VPSBG, now also primary's-equivalent in topology) handles `REQ_HARMONY_HINTS` (offline).

This is the existing topology. `--role secondary` on VPSBG matches.

After today's `e68df9b` dual-stack bind fix, the connection should
succeed. **Open**: actually run the web client end-to-end with a real
HarmonyPIR query and confirm.

---

## Quick-reference command index

In Tier 3, pir2 has no SSH and no systemd. All operator interaction is
via `bpir-admin` over WSS. SSH-using commands below assume you've
reverted to Slice 2 first (see PHASE3_SLICE3_RECOVERY.md).

```bash
# === Tier 3 (current production state) — works without SSH ===

# Attest VPSBG (verifies SEV-SNP report + binds X25519 channel pubkey)
./target/release/bpir-admin attest wss://weikeng2.bitcoinpir.org \
    --expect-binary 324c3883510c56a344221ec379a6466c3089099f51e566e7ad9b1356156eee7e

# End-to-end channel test with ARK-rooted chain validation
./target/release/bpir-admin channel-test wss://weikeng2.bitcoinpir.org \
    --expect-ark-fingerprint 1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a

# Upload a new DB (admin auth + chunked upload + activate). The
# --activate flag triggers an in-process hot reload — no restart.
./target/release/bpir-admin upload main_944321 ./build/output/main_944321 \
    --target-path checkpoints/944321 \
    --server wss://weikeng2.bitcoinpir.org

# === Slice 2 (after reverting via portal — restores SSH) ===

# Build a fresh Tier 3 UKI on pir2 (must run as root)
ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki_tier3.sh'
scp vpsbg-pir:/tmp/bpir-tier3.efi ./deploy/uki/bpir-tier3-vNNN.efi

# Build a fresh Slice 2 UKI on pir2 (revert artifact)
ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki.sh'
scp vpsbg-pir:/tmp/bpir.efi ./deploy/uki/bpir-slice2-revert.efi
# then upload via VPSBG portal → reboot → re-attest → republish

# Re-deploy code change (rebuild binary, then re-bake Tier 3 UKI)
ssh vpsbg-pir 'sudo -u pir bash -lc "
    source ~/.cargo/env && cd /home/pir/BitcoinPIR &&
    git fetch origin && git reset --hard origin/main &&
    CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release -p runtime --bin unified_server
"'
ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki_tier3.sh'

# Check live state under Slice 2
ssh vpsbg-pir 'systemctl status pir-vpsbg cloudflared --no-pager | head -20'
ssh vpsbg-pir 'journalctl -u pir-vpsbg -p err --no-pager -n 20'

# === Hetzner pir1 (Slice 2 only — no SEV) ===

# Hot-spare revival (Hetzner secondary)
ssh pir-hetzner 'systemctl start pir-secondary'
```

## Reproducibility status (2026-05-03 evening, post-investigation)

**Layer 2 (operator-trusted) is what we ship today** — browsers enforce
the operator-published MEASUREMENT pin via Web #3. Closing the gap to
**Layer 3 (independently reproducible)** has progressed substantially
this session:

### What's now solved

1. **OVMF identified.** VPSBG uses Proxmox's `pve-edk2-firmware-ovmf
   4.2025.05-2 → OVMF_SEV_4M.fd` (sha256
   `3f60a393e556580fbe45f085c2b2b035c2ded4d5ce3ed96c9c83faaa1b9c8cc3`).
   Verified by reproducing the chip's "None"-UKI baseline MEASUREMENT
   (`cc68b431b5399cb3…`) exactly via `sev-snp-measure` with the launch
   parameters: 2 vCPUs, AMD EPYC 9745 Turin sig `0x00B10F10`,
   guest-features `0x1`, vmm-type QEMU. Anyone can `apt install
   pve-edk2-firmware-ovmf` from `download.proxmox.com/debian/pve trixie`
   to obtain the byte-identical blob.
2. **VPSBG is on Proxmox VE 9** (their public GitHub forks `pve-manager`
   and `qemu-server` are essentially clones with only a README added,
   indicating they don't customize Proxmox itself; their UKI portal
   feature is layered on top).
3. **Both kernel-hashes mechanisms are inactive in Proxmox's OVMF**:
   `SNP_KERNEL_HASHES` section is absent and `SEV_HASH_TABLE_RV`
   resolves to gpa 0 (`is_sev_hashes_table_supported: False`). So the
   standard QEMU `-kernel <UKI>` path can't be what VPSBG uses.
4. **Brute-force eliminated the simple `-device loader` model**: 1233
   addresses (1 MB-aligned, 1 MB to 4 GB) × 3 chain positions = 3699
   `sev-snp-measure` attempts, none matched the chip's
   `2ad9490a…` MEASUREMENT. So the UKI isn't loaded as a contiguous
   NORMAL-page block at any 1 MB-aligned address.
5. **VMPL0 confirmed**: `dmesg` reports "SNP running at VMPL0", which
   means there is NO Coconut-SVSM running above us. The `SVSM_CAA`
   metadata section in OVMF is just OVMF being SVSM-compatible, not an
   indication SVSM is in active use.

### Strong remaining hypothesis: Proxmox VE 9 IGVM

Per Proxmox VE 9 docs + QEMU IGVM docs, the *natural* Proxmox-stack way
to launch a SEV-SNP guest with a custom UKI loaded into measured memory
is via QEMU's `-object igvm-cfg,file=<file.igvm>`. IGVM declaratively
describes every initial memory page (OVMF + UKI + standard SEV-SNP
pages + per-vCPU VMSA) in one binary. EFI disks are explicitly NOT
supported with SEV-SNP per Proxmox docs, so disk-based UKI loading is
ruled out — IGVM is the documented path.

If correct: with VPSBG's IGVM file, we run `igvmmeasure <file.igvm>`
and get the chip-matching MEASUREMENT directly. No more guessing about
addresses, page types, or chain positions — IGVM is fully self-describing.

### Pending VPSBG support response

Drafted question: "Does my VM launch via Proxmox VE 9's IGVM
(`-object igvm-cfg,file=...`)? If so, can you share the IGVM file?
Otherwise, which mechanism puts the UKI bytes into measured memory?"

When VPSBG responds:
- **If IGVM**: run `igvmmeasure` to verify; publish the verification
  recipe (download IGVM + run measurement tool + compare to chip).
- **If `-device loader,addr=X`**: extend brute-force at 4 KB granularity
  near the answered address; should match within minutes.
- **If something else**: re-evaluate.

## Other open questions worth pinging VPSBG support about

1. **Tier of EPYC**: confirm the VM stays on the same physical chip
   across reboots (chip ID is in the report; if it changes, the VM
   was migrated). Currently chip ID = `00 36 42 73 5D DC 6E 02`.
2. **TCB updates**: SEV-SNP firmware version (FMC=1, SNP=4 in current
   report). When AMD publishes a new TCB, what's VPSBG's update
   cadence?
3. **HOST_DATA conventions**: the SEV-SNP report's HOST_DATA[32] field
   is host-set; do they use it for anything (launch ID, customer ID,
   per-VM nonce)? If yes, having that documented helps verifiers
   correlate published values with specific reports.
