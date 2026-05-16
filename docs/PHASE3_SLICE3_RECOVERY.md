# Phase 3 Slice 3 — Recovery Checklist

**When to use this**: a Tier 3 UKI you uploaded to VPSBG bricks pir2.
Symptoms: `bpir-admin channel-test` fails (HTTP 530 from cloudflared,
or connection times out), `ssh vpsbg-pir` fails with "Connection
refused" or "Network unreachable", VPSBG portal console shows kernel
panic / `[bpir-tier3-init] FATAL` / a `/bin/sh` prompt / nothing.

There is no SSH access in Tier 3 (sshd is gone), and VPSBG VNC does
not work for SEV-SNP guests. The portal console-output view (text-
only, like a serial scrollback) is the only diagnostic channel while
Tier 3 is active. Recovery is via the VPSBG portal exclusively.

---

## Prereq: revert artifacts

You need TWO files on your laptop before you can recover:

1. **A known-good Slice 2 UKI** (e.g. `deploy/uki/bpir-slice2-revert.efi`).
   This is the fastest revert path — boots straight back to the
   Slice 2 systemd-managed shape with sshd alive.
2. **Optional: a known-good Tier 3 UKI** (e.g. `deploy/uki/bpir-tier3-phase32-v2.efi`).
   Useful if you want to revert a NEWER broken Tier 3 to a previous
   working Tier 3 without going all the way back to Slice 2.

Both files live under `deploy/uki/` which is gitignored — keep them
in your own laptop backup. To regenerate either from scratch, see
"Rebuild a UKI from source" below.

---

## Path A: revert to Slice 2 (fastest, restores SSH)

This is the recommended first move. Restores the pre-Tier-3 production
shape. PIR is back online within ~2 minutes.

1. **Open the VPSBG dashboard** → your VM → Confidentiality &
   Protection → Advanced: Measured Boot.
2. **UKI dropdown → Upload** → select your local
   `bpir-slice2-revert.efi` (or whatever your Slice 2 UKI file is).
3. **Save & Reboot**.
4. Wait ~90 seconds for the VM to come up + systemd to start
   `pir-vpsbg.service` + cloudflared to register the tunnel.
5. **Verify SSH is back**:
   ```bash
   ssh vpsbg-pir 'echo alive'
   ```
   Should print `alive`. If you get "Connection refused" the box is up
   but sshd hasn't started yet — wait another 30s.
6. **Verify the encrypted channel works end-to-end**:
   ```bash
   bpir-admin channel-test wss://weikeng2.bitcoinpir.org \
       --expect-ark-fingerprint 1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a
   ```
   Expect all green: ReportDataMatch, vcek chain verified, encrypted
   ping/pong + get_info ok.

If steps 5+6 pass, recovery is complete. Now you can iterate the Tier
3 build at leisure (rsync new module files, rebuild via
`scripts/build_uki_tier3.sh`, scp the new UKI locally, then re-attempt).

---

## Path B: portal "None" → stock Ubuntu (Slice 2 UKI also broken)

If your local Slice 2 UKI is missing/corrupt OR uploading it doesn't
boot either, fall through to "None" — the VPSBG portal lets you boot
the stock Ubuntu cloud-image kernel (no measured boot, no UKI
enforcement). The rootfs is unchanged from any prior boot, so sshd +
the `pir` user + `/home/pir/BitcoinPIR/` are all there.

1. **VPSBG dashboard → Measured Boot → UKI dropdown → "None"** →
   Save & Reboot.
2. Wait ~90 seconds. The box boots the stock Ubuntu kernel from
   `/boot/vmlinuz-*` via grub. Whatever was the original boot path
   before any UKI was uploaded.
3. **SSH should work** (sshd is in the rootfs, untouched by UKI swaps):
   ```bash
   ssh vpsbg-pir 'echo alive'
   ```
4. **Optional: confirm Slice 2 services start cleanly under stock kernel**:
   ```bash
   ssh vpsbg-pir 'systemctl is-active pir-vpsbg cloudflared'
   ```
   Both should report `active`.
5. **Rebuild a Slice 2 UKI** to have a fresh revert artifact going
   forward (see below).

NOTE: under "None" the box runs WITHOUT the dracut `bpir-verify`
binary-pin enforcement. The MEASUREMENT will be different (covers
just OVMF, no UKI). This is fine for recovery and short-term operation
but leaves the binary unattested — get back to a UKI'd boot ASAP.

---

## Rebuild a UKI from source

If you've lost both UKI files locally, regenerate them on pir2 (you
need to be on Slice 2 or stock Ubuntu — anything with SSH).

### Slice 2 UKI (known-good revert artifact)

```bash
ssh vpsbg-pir 'sudo /home/pir/BitcoinPIR/scripts/build_uki.sh'
scp vpsbg-pir:/tmp/bpir.efi ./deploy/uki/bpir-slice2-revert.efi
shasum -a 256 ./deploy/uki/bpir-slice2-revert.efi
```

The build is reproducible-ish: same binary on disk + same
`build_uki.sh` script → same UKI sha256 (modulo file-mtime drift
across fresh git clones).

### Tier 3 UKI

```bash
ssh vpsbg-pir 'sudo /home/pir/BitcoinPIR/scripts/build_uki_tier3.sh'
scp vpsbg-pir:/tmp/bpir-tier3.efi ./deploy/uki/bpir-tier3-phaseXX-vYY.efi
shasum -a 256 ./deploy/uki/bpir-tier3-phaseXX-vYY.efi
```

Build deps the script verifies: `runit` (`apt install runit`),
`/usr/local/bin/cloudflared`, `/etc/cloudflared/tunnel.env`, and the
production binary at `/home/pir/BitcoinPIR/target/release/unified_server`.

---

## Common failure modes — what the portal console will show

When debugging a fresh Tier 3 UKI boot failure, the VPSBG portal
console-output view shows the boot trace. The takeover init runs with
`set -x` so every command is echoed. Look for these patterns:

| Console message | Likely cause | Fix |
|---|---|---|
| `[bpir-tier3-init] FATAL: eth0 never appeared` | virtio_net not loaded | unlikely on this kernel (built-in); check kernel version match |
| `[bpir-tier3-init] WARN: rootfs mount failed` | `cloudimg-rootfs` label missing or virtio_blk not loaded | `--add-drivers virtio_blk` in build_uki_tier3.sh; check `/proc/partitions` dump above the FATAL |
| cloudflared printing `tunnel run --help` | argv-order bug in cloudflared-run.sh | rare regression — see git log on cloudflared-run.sh |
| cloudflared `lookup ... [::1]:53: connection refused` | `/etc/resolv.conf` empty | bpir-tier3-init.sh writes a fallback after udhcpc; if missing, hardcoded values broke |
| cloudflared `lookup ... 8.8.8.8:53: network is unreachable` | eth0 has no IP / no default route | static-IP config in bpir-tier3-init.sh broke (VPSBG doesn't run DHCP) |
| unified_server `Status: NoSevHost` | sev-guest .ko not loaded | `--add-drivers ccp sev-guest tsm_report` in build_uki_tier3.sh |
| attest `binary_sha256 mismatch` | dracut stripped the binary | `--nostrip` in build_uki_tier3.sh's dracut invocation |

If the console shows a `/bin/sh` prompt, the takeover init hit a
`exec /bin/sh` FATAL path and runsvdir never started — cloudflared is
not running, so HTTP 530 from the frontdoor. The console-output view
will show which line bailed (the previous lines via `set -x`).

---

## Last-resort: VPSBG support ticket

If "None" boot also fails (rare — would mean the rootfs is corrupt,
not just the UKI), file a ticket with VPSBG asking for a recovery
console or ISO boot. They have an out-of-band recovery path
(physical-host operator) but it's slow and manual.

Live values for filing the ticket:
- VM hostname: `pir-server-vpsbg`
- VM IP: `87.120.8.198` (static, assigned via cloud-init at first boot)
- Chip ID: `00 36 42 73 5D DC 6E 02` (from earlier SEV-SNP attestation)

---

## What gets lost in recovery

- **No DBs are lost** — `/home/pir/data/checkpoints/` and `/deltas/`
  live in the rootfs, untouched by UKI swaps.
- **The encrypted channel pubkey changes** on every reboot (it's
  ephemeral per server-process). Verifiers re-fetch on next attest;
  they don't pin it.
- **MEASUREMENT changes** between Slice 2 and Tier 3 UKIs. The published
  value in `docs/PHASE3_ROADMAP.md` reflects whatever is currently
  active — update it after recovery if you've reverted.
