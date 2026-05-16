# Phase 3 Slice 3 — Tier 3 Lockdown (Plan + Post-Mortem)

**Status (2026-05-03 evening)**: ✅ **SHIPPED**. pir2 is running Tier 3
v2 UKI in production. SEV-SNP attestation works end-to-end (channel-test
returns ARK-verified chain), unified_server runs from the initramfs,
sshd is gone. New MEASUREMENT
`2ad9490a64a48d7ab9af1045c5a5abe2b8308edcb13f966a9c95eea3709c4018faf161f52eb3c6063c1e241f19fd6fe5`
captured + published in [docs/PHASE3_ROADMAP.md](PHASE3_ROADMAP.md).

This doc was the canonical to-do *during* development. The acceptance
status of each phase is annotated inline. The "Discovered constraints"
section has been updated in-place with what we actually found
(several original assumptions were wrong — see the corrections marked
with **UPDATE**).

For operator recovery if a future Tier 3 UKI bricks the box, see
[docs/PHASE3_SLICE3_RECOVERY.md](PHASE3_SLICE3_RECOVERY.md).

---

## Goal

Bake `unified_server` directly into the UKI's initramfs so:

- Binary bytes are committed *directly* to MEASUREMENT (not just
  transitively via a cmdline pin).
- There's no on-disk binary to atomic-replace + restart.
- sshd is gone — whole categories of "shell, modify, restart" attacks
  vanish.
- Operator access is `bpir-admin` over WSS only.

This closes the "atomic-replace + lie + systemctl restart" attack
window that Slice 2 leaves open until next reboot.

---

## Current production baseline (DO NOT BREAK)

End-to-end encrypted channel + AMD VCEK chain validation are LIVE on
both servers. Slice 3 must preserve all of these properties:

```
weikeng2.bitcoinpir.org:
  binary_sha256:    324c3883510c56a344221ec379a6466c3089099f51e566e7ad9b1356156eee7e
  MEASUREMENT:      e522983f… (will change once Slice 3 UKI ships)
  channel pubkey:   8f8e48dbd14e4ff0619e21dbacb70b1b1912388748b401774c61f2a7c9c1f437
  ARK fingerprint:  1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a
                    (Turin family root — pinned in web/src/attest-pin.ts)
  vcek chain:       bundled (operator-fetched via snpguest, in /home/pir/data/vcek/)

weikeng1.bitcoinpir.org:
  binary_sha256:    8fec274b9089a5defaec5825920e662af771a3cbd542968c6fdba93ab3f7d0f6
  No SEV — V2 binding only, no chain validation.
```

End-to-end smoke (must keep passing post-Slice-3):
```bash
bpir-admin channel-test wss://weikeng2.bitcoinpir.org \
    --expect-ark-fingerprint 1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a
# Expected: ✓ vcek chain verified + handshake + encrypted ping/pong + get_info
```

Browser auto-flips to `verified-vcek` on connect — see
`web/src/dpf-adapter.ts::attestAndUpgrade`.

---

## What changes from Slice 2

| | Slice 2 (today, live) | Slice 3 (planned) |
|---|---|---|
| Binary location | `/home/pir/BitcoinPIR/target/release/unified_server` (rootfs) | `/usr/local/bin/unified_server` (initramfs) |
| MEASUREMENT covers binary | Transitively via cmdline pin + dracut hook (`scripts/dracut/95bpir-verify/`) | **Directly** — binary bytes inside UKI |
| sshd | available | **gone** |
| Operator access | `ssh vpsbg-pir` | `bpir-admin` over WSS only (cf. `bpir-admin upload` for DBs) |
| DB storage | `/home/pir/data/checkpoints/`, `/home/pir/data/deltas/` (rootfs, mutable) | Same — DBs (~14 GB) can't be in UKI; need a writable mount |
| VCEK chain | `/home/pir/data/vcek/{cert_chain.pem,vcek.pem}` (rootfs) | Same — operator-refreshable on TCB updates |
| Binary update cadence | `cargo build && systemctl restart pir-vpsbg` | `cargo build → re-bake UKI → upload via portal → reboot` (every change) |
| Recovery if UKI bricks | Portal "None" UKI fallback + SSH back in + cp .bak | **Portal "None" UKI fallback only** — no SSH to recover from |

---

## Discovered constraints (since prior planning)

1. **VPSBG VNC doesn't work** on this SEV-SNP guest. Discovered
   2026-05-02 during the Slice 2 tamper test — VNC console was
   unable to connect. The framebuffer is likely disabled with
   measured boot.
   - **UPDATE 2026-05-03**: the VPSBG portal **does** expose a
     console-output / serial-scrollback view that works on SEV-SNP
     guests. Used heavily during Phase 3.1/3.2 dev to diagnose
     boot failures (cloudflared arg-order, missing DNS, no DHCP,
     binary SHA mismatch, NoSevHost). It's read-only text, no
     interactive shell, but combined with `set -x` in our takeover
     init it gives full visibility into what failed and where.
     The earlier "operate blind" assumption was wrong.
   - Recovery if a Tier 3 UKI bricks the box: still via the VPSBG
     portal (re-upload known-good Slice 2 UKI, or "None" to boot
     stock Ubuntu). See
     [docs/PHASE3_SLICE3_RECOVERY.md](PHASE3_SLICE3_RECOVERY.md).

2. **The dracut hook at `scripts/dracut/95bpir-verify/`** is the
   existing pattern. Slice 3's bigger initramfs additions follow
   the same dracut-module-add-and-rebuild flow.

3. **AMD VCEK is per-chip+TCB**. When TCB changes (kernel update,
   microcode update), the operator must re-fetch via `snpguest fetch
   vcek -p turin pem . report.bin` and replace `vcek.pem`. In Slice 3
   the cert dir is still on the writable mount (operator can swap
   without rebuilding the UKI).

4. **The reproducible-UKI commit** (`d8cb85c`) made dracut deterministic
   via `--reproducible` + `SOURCE_DATE_EPOCH=0`, but file mtimes from
   `git pull` still leak in. Fresh-clone reproducibility isn't there
   yet. Slice 3 makes this matter more (verifiers want to reproduce
   the UKI from source); revisit `cp -fp` plus a touch-to-epoch
   pre-pass before dracut.

5. **MASK_CHIP_ID-like behavior**: pir2's chip ID is only 8 meaningful
   bytes (`003642735DDC6E02`) followed by 56 zero bytes. AMD KDS
   accepts the truncated form (`snpguest fetch vcek` handles this
   automatically). Don't hand-craft the URL — let snpguest do it
   (we tried hand-crafting with `current_tcb` instead of
   `reported_tcb` and got a wrong-TCB cert that didn't validate).

6. **VPSBG uses STATIC IP, not DHCP** (discovered Phase 3.1 v3 via
   netplan inspection). `/etc/netplan/50-cloud-init.yaml` is generated
   by cloud-init from VPSBG's instance metadata service at first boot
   — the IP `87.120.8.198/32` and gateway `172.16.0.1` (with
   `on-link: true` because the gateway isn't in our /32 subnet) are
   hardcoded there. There is no DHCP server on VPSBG's L2; udhcpc
   never gets a lease, eth0 stays IP-less, every outbound packet hits
   "network unreachable". Tier 3's takeover init must hardcode the
   same static config (see Architectural decision #1 below — REVERSED
   from the original DHCP recommendation).

7. **dracut's `inst` strips binaries by default** (discovered Phase 3.2 v1
   via attest binary_sha256 mismatch). The on-disk binary's SHA differs
   from the in-initramfs binary's SHA after dracut copies it. Pass
   `--nostrip` (NOT `--no-strip`) to dracut to disable. Cost: ~few
   hundred KB extra. Without this, the value `build_uki_tier3.sh`
   computes from the on-disk binary doesn't match what `attest` reports
   from `/proc/self/exe` at runtime — verifiers can't pin the binary.

8. **sev-guest, ccp, tsm_report are kernel modules on this kernel**
   (not built-in, discovered Phase 3.2 v1 via NoSevHost attest result).
   Slice 2 has them auto-loaded via udev on PCI ID match; Tier 3 has
   no udev so we both bake the .kos in via `--add-drivers` AND
   explicitly `modprobe` them in the takeover init. Without this,
   `/dev/sev-guest` doesn't exist, unified_server's attest call returns
   `Status: NoSevHost` and the SEV-SNP report has 0 bytes — the entire
   point of Tier 3 is defeated.

---

## Architectural decisions (pre-coding)

Each has a recommendation. Confirm or override before coding.

### 1. Networking inside initramfs — **REVERSED to STATIC IP**

Original recommendation: DHCP via dracut's `network-legacy` module.
**REVERSED 2026-05-03 (Phase 3.1 v3)**: VPSBG runs no DHCP server;
the IP is delivered via cloud-init metadata at first boot and persisted
in `/etc/netplan/50-cloud-init.yaml`. udhcpc gets no lease.

Tier 3 takeover init now hardcodes the static config matching netplan:
- IP `87.120.8.198/32` on eth0
- Default route via `172.16.0.1` with `onlink` (the gateway is not in
  our /32 subnet — `onlink` tells the kernel to treat it as directly
  attached on eth0 anyway)
- DNS `9.9.9.9` (Quad9) + `208.67.222.222` (OpenDNS) — same as netplan

Trade-off: the IP is now baked into MEASUREMENT. If VPSBG re-IPs the
VM (rare for paid VPSes — happens only on instance migration), the
UKI breaks until rebuilt with the new IP. Acceptable cost in practice;
operator just re-bakes via `build_uki_tier3.sh`.

The dracut flag `--add-drivers " virtio_net "` is still passed for
defense in depth but is a no-op on this kernel — virtio_net is
compiled `=y` not `=m`.

### 2. Persistent storage for DBs + cert chain

Two viable shapes:

(a) **Separate ext4 partition** on `/dev/sda2`, mounted at `/data` by
    the initramfs.
  - Pro: clean isolation; / is RAM-only.
  - Con: requires repartitioning the VPSBG VM disk (operationally
    painful — fresh install or careful resize).

(b) **Reuse existing rootfs partition for `/data/` only** — the
    initramfs mounts the existing rootfs r/o at `/sysroot` and
    bind-mounts `/sysroot/home/pir/data` at `/data` r/w.
  - Pro: no repartitioning; uses existing /home/pir/data layout.
  - Con: rootfs is still mounted, just not used as `/`. An
    attacker who escalates to root in the guest could remount it
    rw and tamper.

**Recommended**: (b) for MVP. The threat we're closing is
"binary-on-disk swap"; DBs are independently verified via
manifest roots. Repartitioning is a real operational cost we don't
have a strong reason to pay yet.

### 3. Logs

Without a rootfs as the systemd journal home, journald has nowhere
to persist.

- (a) Console-only (would have used VNC, but we just learned VNC
      doesn't work — kill this option).
- (b) Small writable volume just for `/var/log/journal`.
- (c) Forward via systemd-journal-remote sidecar to Hetzner.
- (d) **No persistent logs** — use `bpir-admin attest`'s liveness
      signal + cloudflared's tunnel health as out-of-band evidence
      that the server is alive. Logs live only in tmpfs and are
      gone at reboot.

**Recommended**: (d) for MVP. Closest to the "minimal attack surface"
spirit. (c) is the right answer once we want post-mortem debugging
on production issues; defer until needed.

### 4. cloudflared inside the UKI

- Bake `cloudflared` static binary into initramfs.
- Token + tunnel config: in initramfs (cmdline parameter, or a
  small read-only file under `/etc/cloudflared/`).
- Token rotation = UKI re-bake. Acceptable since cert/binary
  updates already require re-bakes.

**Recommended**: yes, bake it in. Otherwise weikeng2.bitcoinpir.org
goes dark on every Slice 3 boot.

### 5. Process supervisor

Need to manage two long-running processes (`unified_server` +
`cloudflared`) inside an initramfs (no systemd).

Options:
- (a) `s6-overlay` — small, mature, well-suited.
- (b) `runit` — even smaller, single binary.
- (c) Hand-rolled bash supervisor with traps.
- (d) Use systemd inside the initramfs — possible (dracut has a
      `systemd` module) but defeats the "minimal" goal.

**Recommended (originally)**: (a) s6-overlay.

**Chosen 2026-05-03**: **runit** (option b). Operator preference for
the smaller / simpler binary footprint. Single `apt install runit` on
pir2 + bake `/usr/bin/{runit,runsvdir,runsv,sv,chpst}` into the
initramfs. Service tree at `/etc/sv/{cloudflared,unified_server}/run`,
symlinked into `/etc/service/` by the takeover init, supervised by
`exec /usr/bin/runsvdir /etc/service` as PID 1. Restart-on-crash works
out of the box; graceful shutdown propagates SIGTERM correctly.

### 6. Admin key + cmdline params

Today the admin pubkey + listen port + role are CLI flags on
`unified_server` set by the systemd unit. Without systemd, they
need to come from somewhere.

- Bake into the supervisor's invocation script inside initramfs.
- Operator changes = UKI re-bake.

**Recommended**: hardcoded in the supervisor's invocation script.
Admin key rotation is rare (we generated it once); UKI re-bake
is the price of immutability.

### 7. Recovery rehearsal

Before going live:
- Build a Slice 3 UKI but DO NOT swap the active one.
- Manually upload via portal, reboot.
- Verify: `bpir-admin attest` succeeds, channel-test passes.
- If anything is wrong, revert via portal "None".
- ONLY after one successful boot+attest+channel-test cycle,
  consider it the new active UKI.

Slice 2 had a portal "None" recovery path because we still had SSH
after recovery. Slice 3 doesn't — recovery means going through "None"
and rebuilding from scratch on a fresh Ubuntu boot. Test this on a
non-production host first if possible.

---

## Phased implementation

### Phase 3.1 — initramfs networking + cloudflared (~2 days)

Goal: prove we can boot into an initramfs that has working WAN
connectivity + a cloudflared tunnel.

- Extend `scripts/build_uki.sh` (or new `scripts/build_uki_tier3.sh`)
  with:
  - `dracut --add network --add-drivers " virtio_net "`
  - Bake `cloudflared` static binary into the initramfs via a new
    dracut module `scripts/dracut/96bpir-cloudflared/`
  - Bake the tunnel token into a file dracut copies in
- Boot test: UKI loads, initramfs has IP, cloudflared connects to
  Cloudflare, tunnel is up.
- Use the existing `bpir-verify` dracut hook unchanged (it'll
  short-circuit when there's no rootfs binary to check against the
  cmdline pin — confirm this works).
- The "rootfs" doesn't need to be mounted yet for this phase —
  just enough to prove network + tunnel work from initramfs.

Acceptance: `cloudflared tunnel info <tunnel-id>` shows the tunnel
connected from the new boot.

### Phase 3.2 — bake unified_server + supervisor (~3 days)

- Add a dracut module that pulls in:
  - `target/release/unified_server` (the binary)
  - All dynamic deps from `ldd target/release/unified_server`
    (probably libc, libgcc_s, libstdc++ from SEAL link, libssl,
    libcrypto, libpthread). Use `inst_simple` or `dracut_install`.
  - s6-overlay binaries
  - A small s6 service definition for unified_server +
    cloudflared
- Mount `/sysroot/home/pir/data` r/w as `/data` (the bind-mount
  approach from decision 2).
- Server starts, listens on port 8091 (or whatever cmdline says),
  runs against `/data/checkpoints/940611` etc.
- The `bpir-verify` dracut hook can drop entirely — there's no
  longer an on-disk binary to check.
- Update `pir_runtime_core::attest::self_exe_sha256()` semantics:
  it'll now return SHA-256 of `/proc/self/exe` which is the binary
  loaded from initramfs. The hash should match what's in the UKI.

Acceptance: `bpir-admin attest wss://weikeng2.bitcoinpir.org` returns
a fresh MEASUREMENT (different from current `e522983f…`) and the
self-reported `binary_sha256` matches the new initramfs binary.

### Phase 3.3 — drop sshd + tighten (~1 day)

- Don't include sshd in the initramfs (default — nothing to remove,
  it just wasn't there).
- Verify `ssh vpsbg-pir 'echo hi'` fails with connection refused.
- Verify `bpir-admin upload` still works (DB upload over the
  encrypted channel).
- Verify the dracut emergency-shell behavior on init failure (if
  the supervisor crashes, what happens? — probably a kernel panic;
  we want graceful recovery to the portal).

Acceptance: SSH dead, all bpir-admin operations work, channel-test
passes with `--expect-ark-fingerprint`.

### Phase 3.4 — recovery rehearsal + docs (~half day)

- Walk through a fresh "if Tier 3 UKI bricks the box" recovery via
  the VPSBG portal. Document the exact sequence in
  `docs/PHASE3_SLICE3_RECOVERY.md`.
- Re-run `bpir-admin channel-test --expect-ark-fingerprint …`
  after recovery to confirm the chain still validates against the
  rebuilt server.

Acceptance: a printed/saved recovery checklist that the operator
can follow without prior context.

### Phase 3.5 — production deploy + republish

- Build new Slice 3 UKI on vpsbg-pir.
- Upload via portal, reboot.
- Capture new MEASUREMENT.
- Update `docs/PHASE3_ROADMAP.md` published values.
- Browser-verify `verified-vcek` still flips correctly.

---

## Acceptance log (2026-05-03 evening session)

All five phases shipped in one session via four iterative UKI builds.

| Phase | Status | Notes |
|---|---|---|
| 3.1 v1 | ❌ | cloudflared got `tunnel --token X run` arg-order, bailed to help (visible on portal console — earlier "operate blind" assumption corrected here) |
| 3.1 v2 | ❌ | env-var pattern fixed cloudflared, but `/etc/resolv.conf` empty → `[::1]:53` connection refused |
| 3.1 v3 | ❌ | added defensive resolv.conf (1.1.1.1 / 8.8.8.8), but `network is unreachable` to 8.8.8.8 — eth0 has no IP because VPSBG doesn't run DHCP |
| 3.1 v4 | ✅ | static IP config matching VPSBG netplan; tunnel UP, Cloudflare dashboard shows connector connected |
| 3.2 v1 | ⚠️ | unified_server boots, DBs load, listens on 8091, but `Status: NoSevHost` (sev-guest not loaded) + binary SHA mismatch (dracut stripped binary) + missing `--vcek-dir` flag |
| 3.2 v2 | ✅ | `--nostrip` + bake ccp/sev-guest/tsm_report .kos + `--vcek-dir` — channel-test passes with ARK fingerprint pin, attest matches expected binary, fresh MEASUREMENT captured |
| 3.3 | ✅ | `ssh vpsbg-pir` returns `Connection refused` (Tier 3 has no sshd) |
| 3.4 | ✅ | [docs/PHASE3_SLICE3_RECOVERY.md](PHASE3_SLICE3_RECOVERY.md) written |
| 3.5 | ✅ | new MEASUREMENT `2ad9490a64a48d7ab9af1045c5a5abe2b8308edcb13f966a9c95eea3709c4018faf161f52eb3c6063c1e241f19fd6fe5` published in PHASE3_ROADMAP.md; UKI sha256 `afbc07f8ea8df7f24e0d92980184bcc61e8762dbe3bbf0e161ef08bdf8b8fe90` |

Browser `verified-vcek` smoke test: deferred to operator (one click in
the live web client at `https://www.bitcoinpir.org` against pir2 →
the badge should auto-flip to `verified-vcek`).

---

## Tools / deps / files to leverage

Existing assets (don't reinvent):
- `scripts/build_uki.sh` — UKI build pipeline, deterministic-ish
- `scripts/dracut/95bpir-verify/` — dracut module template
  (`module-setup.sh` + `bpir-verify.sh`)
- `pir-runtime-core::admin` — DB upload protocol (already wired,
  works over the encrypted channel)
- `pir-channel` — handshake + AEAD (no change needed)
- `pir-attest-verify` — chain validator (no change needed)
- `bpir-admin` — operator CLI (already has `attest`, `channel-test`,
  `upload`, `show-vcek-url`, `keygen`)
- `deploy/systemd/pir-vpsbg.service` — current systemd unit (to be
  replaced by s6 supervisor inside initramfs)

New tools to acquire:
- `cloudflared` Linux static binary (download from Cloudflare
  releases page; ~30 MB)
- `s6-overlay` binaries (or `runit`, depending on decision 5)
- `dracut --list-modules` to confirm `network`, `network-legacy`,
  `network-manager` are available on the build host

To enumerate what the binary needs:
```bash
ssh vpsbg-pir 'ldd /home/pir/BitcoinPIR/target/release/unified_server'
```
That output is the list of `.so` files dracut needs to copy into the
initramfs alongside the binary itself.

---

## What this slice does NOT change

- SEV-SNP attestation (Slices A-D) — channel pubkey still bound to
  REPORT_DATA, ARK→ASK→VCEK chain validated server-side and
  browser-side.
- Encrypted channel (Slice B) — handshake protocol + AEAD frame
  layer unchanged.
- DB integrity — manifest roots in attestation already cover this;
  DBs continue to live on the writable mount with the same upload
  path (`bpir-admin upload`).
- VCEK chain refresh — operator workflow stays the same
  (`snpguest fetch vcek` + replace files in `/data/vcek/`).
- Web bundle / browser — `verified-vcek` flow keeps working; the
  browser doesn't care that the server's binary moved.

---

## Risks + open questions

- **VNC unavailable** for live debugging during Slice 3 development.
  Plan to test on a throwaway VPSBG instance first if possible
  (since "boot fails → recover via portal None → start over" is the
  only iteration loop on the prod box).
- **Disk re-partitioning**: if decision 2 picks (a) instead of (b),
  this is a one-time migration that needs careful sequencing.
- **Initramfs size**: today's UKI is ~83 MB (binary not yet in it).
  Adding the binary (~3.7 MB) + cloudflared (~30 MB) + s6 (~500 KB)
  + a few `.so`s pushes it to ~120 MB. VPSBG's portal might cap UKI
  upload size — confirm before going too far.
- **Reproducibility**: if we want third-party verifiers to rebuild
  the UKI from source, we need full reproducibility. Currently the
  initramfs cpio leaks file mtimes. Worth fixing before Slice 3
  production deploy.
- **Database upgrade cadence**: today the operator uploads new DBs
  via `bpir-admin upload` periodically. Slice 3 doesn't change this
  path — DBs still go to the writable mount. Confirm the existing
  upload flow works against an initramfs-rooted server.

---

## Quick-reference commands (post-Slice-3 operator usage)

```bash
# Build new Slice 3 UKI on vpsbg-pir
ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki_tier3.sh'
scp vpsbg-pir:/tmp/bpir-tier3.efi ./bpir.efi
# Upload via VPSBG portal → Measured Boot → UKI → Save & Reboot.

# After reboot, verify everything still works
bpir-admin attest wss://weikeng2.bitcoinpir.org
bpir-admin channel-test wss://weikeng2.bitcoinpir.org \
    --expect-ark-fingerprint 1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a
# Note: NO SSH after Slice 3 deploys — `ssh vpsbg-pir` is dead.

# DB upload (unchanged from Slice 2)
bpir-admin upload main_944321 ./build/output/main_944321 \
    --target-path checkpoints/944321 \
    --server wss://weikeng2.bitcoinpir.org
# Then to activate the new DB: rebuild + reupload UKI? Or
# implement an in-supervisor reload signal? Decide during Phase 3.2.

# VCEK refresh after a TCB update
# (need to figure out HOW operator places new files without SSH —
# perhaps a `bpir-admin upload-vcek` command, or wire it into the
# existing upload protocol)
```

The "how does the operator update VCEK without SSH" question is
worth resolving before Phase 3.4. Options:

- New `bpir-admin upload-vcek <ark.pem> <ask.pem> <vcek.pem>`
  command (extend the admin upload protocol).
- Bake a default chain into the UKI; operator must rebuild +
  reupload UKI to refresh certs (matches the immutability spirit
  but increases TCB-update friction).
