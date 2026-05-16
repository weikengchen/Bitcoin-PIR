#!/usr/bin/env bash
# Build a Tier 3 UKI for BitcoinPIR Phase 3 Slice 3.
#
# Phase 3.1 scope (this script): bake an initramfs that brings up the
# network and runs cloudflared, with no rootfs pivot. Acceptance:
# Cloudflare dashboard shows the tunnel connecting from the new boot.
#
# Phase 3.2 will extend this script to also bake `unified_server` +
# its .so deps + a runit service for it + a /sysroot bind-mount for
# /home/pir/data (so DBs are reachable). Phase 3.1 deliberately stays
# minimal so we can validate the runit-takeover-init shape on its own
# before piling more in.
#
# Differences vs scripts/build_uki.sh (Slice 2):
# - Adds `--add network --add-drivers " virtio_net virtio_pci "` so
#   the initramfs has the virt NIC driver + DHCP tooling.
# - Adds `--add bpir-cloudflared` and `--add bpir-tier3-init` (the
#   modules at scripts/dracut/{96bpir-cloudflared,97bpir-tier3-init}/).
# - Drops `--add bpir-verify` — no on-disk binary to pin in Phase 3.1.
# - Cmdline drops `root=...` (no rootfs pivot) and replaces with
#   `rdinit=/sbin/bpir-tier3-init`. The kernel exec's our takeover
#   script as PID 1 directly, completely bypassing dracut's /init.
# - Output goes to /tmp/bpir-tier3.efi (not /tmp/bpir.efi) so this
#   doesn't clobber the live Slice 2 UKI build artifact.
#
# Operator usage (must run as root — /boot/vmlinuz-* is mode 0600):
#   ssh vpsbg-pir 'apt install -y runit'   # one-time build dep
#   ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki_tier3.sh'
#   scp vpsbg-pir:/tmp/bpir-tier3.efi ./bpir-tier3.efi
#
# Recovery if Tier 3 boot fails: VPSBG portal → Measured Boot → UKI
# → set to "None" → reboot → stock Ubuntu rootfs comes up with sshd.

set -euo pipefail

if [ "$EUID" != "0" ]; then
    echo "error: build_uki_tier3.sh must run as root — /boot/vmlinuz-* is" >&2
    echo "       not readable by the pir user. Re-run as:" >&2
    echo "         ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki_tier3.sh'" >&2
    exit 1
fi

# ─── Defaults (override via env) ───────────────────────────────────────────
KERNEL=${KERNEL:-}
OUT=${OUT:-/tmp/bpir-tier3.efi}
CUSTOM_INITRD=/tmp/bpir-tier3-initrd.img

# Resolve dracut module dir relative to this script.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DRACUT_MODULE_DIR="$SCRIPT_DIR/dracut"

# ─── Sanity checks ─────────────────────────────────────────────────────────

for tool in ukify dracut sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool not installed (apt install systemd-ukify dracut)" >&2
        exit 1
    }
done

# Phase 3.1 build dep: runit. The 97bpir-tier3-init module's check()
# fails the build if these aren't present, but check up-front for a
# clearer error than dracut's.
for b in runit runsvdir runsv sv chpst; do
    command -v "$b" >/dev/null 2>&1 || {
        echo "error: $b not in \$PATH" >&2
        echo "  install with: apt install runit" >&2
        exit 1
    }
done

# Cloudflared static binary must be on the build host. The tunnel
# token does NOT need to be on the build host — it is loaded at
# runtime from /home/pir/data/cloudflared/tunnel.env on the target's
# rootfs partition (see PHASE3_SLICE3_REPRO_PLAN.md sub-task 3 / option b).
# Operator one-time setup before deploying Tier 3:
#   ssh <slice2-host> 'mkdir -p /home/pir/data/cloudflared && \
#       cp /etc/cloudflared/tunnel.env /home/pir/data/cloudflared/'
[ -x /usr/local/bin/cloudflared ] || {
    echo "error: /usr/local/bin/cloudflared not executable" >&2
    exit 1
}

# Phase 3.2: unified_server binary must be built and present.
BINARY=${BINARY:-/home/pir/BitcoinPIR/target/release/unified_server}
[ -x "$BINARY" ] || {
    echo "error: $BINARY not executable" >&2
    echo "       run: cargo build --release -p unified_server" >&2
    exit 1
}

# ─── Kernel auto-detection ──────────────────────────────────────────────────
# Prefer explicit KERNEL=/boot/vmlinuz-<ver> in the environment.
# Otherwise, auto-detect the latest installed kernel (highest sort order under
# /boot/vmlinuz-*). This adapts to unattended-upgrades replacing the kernel
# and apt autoremove cleaning stale modules without manual pin maintenance.
if [ -z "$KERNEL" ]; then
    KERNEL=$(ls -1 /boot/vmlinuz-*-generic 2>/dev/null | sort -V | tail -1)
    if [ -z "$KERNEL" ]; then
        echo "error: no kernel found under /boot/vmlinuz-*-generic — set KERNEL= explicitly" >&2
        exit 1
    fi
    echo "auto-detected kernel: $KERNEL"
fi
[ -r "$KERNEL" ] || { echo "error: $KERNEL not readable" >&2; exit 1; }

# Derive kernel version from KERNEL filename.
KVER=$(basename "$KERNEL" | sed 's/^vmlinuz-//')
[ -d "/usr/lib/modules/$KVER" ] || {
    echo "error: /usr/lib/modules/$KVER missing — kernel modules not installed?" >&2
    echo "  apt autoremove may have cleaned modules for the pinned kernel." >&2
    echo "  Reinstall: apt install --reinstall linux-modules-$KVER" >&2
    exit 1
}

# Validate SEV-SNP kernel modules exist BEFORE building the initramfs.
# Dracut silently skips modules it cannot find, producing a UKI that boots
# but whose /dev/sev-guest is never created → noSevHost in the web frontend.
# Fail early with an actionable message.
#
# ccp + sev-guest are always required. tsm_report exists only on kernel ≥6.10
# (it's the unified TEE Security Manager interface that sev-guest depends on
# in newer kernels). On 6.8.x, sev-guest handles the ioctl directly.
SEV_MODULES_DIR="/usr/lib/modules/$KVER/kernel/drivers"
REQUIRED_SEV_MODS="ccp sev-guest"
OPTIONAL_SEV_MODS="tsm_report"
# Build the driver list and the validation set.
SEV_DRIVER_LIST="ccp sev-guest"
for mod in $OPTIONAL_SEV_MODS; do
    if find "$SEV_MODULES_DIR" -name "${mod}.ko*" -print -quit 2>/dev/null | grep -q .; then
        REQUIRED_SEV_MODS="$REQUIRED_SEV_MODS $mod"
        SEV_DRIVER_LIST="$SEV_DRIVER_LIST $mod"
    fi
done
MISSING_REQUIRED=""
for mod in $REQUIRED_SEV_MODS; do
    found=$(find "$SEV_MODULES_DIR" -name "${mod}.ko*" -print -quit 2>/dev/null)
    if [ -z "$found" ]; then
        MISSING_REQUIRED="$MISSING_REQUIRED $mod"
    fi
done
if [ -n "$MISSING_REQUIRED" ]; then
    echo "error: SEV kernel module(s) not found under $SEV_MODULES_DIR:$MISSING_REQUIRED" >&2
    echo "  These are REQUIRED for SEV-SNP attestation (/dev/sev-guest)." >&2
    echo "  Fix: apt install --reinstall linux-modules-$KVER" >&2
    exit 1
fi
echo "SEV modules: $REQUIRED_SEV_MODS — all found in $SEV_MODULES_DIR"

# ─── Install dracut modules ────────────────────────────────────────────────
# Same pattern as build_uki.sh: copy module dirs into dracut's search
# path with mtime preservation so --reproducible can produce a
# byte-deterministic cpio.
#
# Note: 95bpir-verify is intentionally NOT installed in Tier 3 — its
# job (verify on-disk binary against cmdline pin) is moot when the
# binary lives inside the UKI itself (covered directly by MEASUREMENT,
# no transitive pin needed).
for mod in 96bpir-cloudflared 96bpir-unified-server 97bpir-tier3-init; do
    src="$DRACUT_MODULE_DIR/$mod"
    dst="/usr/lib/dracut/modules.d/$mod"
    [ -d "$src" ] || { echo "error: dracut module dir missing: $src" >&2; exit 1; }
    mkdir -p "$dst"
    # -p preserves mtimes so --reproducible builds are deterministic.
    # Copy ALL files (not just *.sh) — 97bpir-tier3-init ships a
    # non-.sh udhcpc-default.script that needs to come along.
    cp -fp "$src"/* "$dst/"
    chmod 0755 "$dst"/*
    # Normalize mtimes to epoch 0. Without this the operator's `git clone`
    # time propagates through `cp -fp` into the cpio archive — two operators
    # with fresh clones at different times produce different UKI bytes (and
    # therefore different MEASUREMENT) even with --reproducible +
    # SOURCE_DATE_EPOCH=0. See docs/PHASE3_SLICE3_REPRO_PLAN.md sub-task 1.
    find "$dst" -type f -exec touch -d @0 {} +
    echo "dracut module installed:  $dst"
done

# Compute binary SHA-256 for operator visibility (NOT pinned via
# cmdline in Tier 3 — the binary's bytes are already directly in
# MEASUREMENT via the initramfs cpio).
if command -v sha256sum >/dev/null 2>&1; then
    BIN_HASH=$(sha256sum "$BINARY" | awk '{print $1}')
else
    BIN_HASH=$(shasum -a 256 "$BINARY" | awk '{print $1}')
fi

echo "kernel:                   $KERNEL"
echo "kernel version:           $KVER"
echo "cloudflared:              /usr/local/bin/cloudflared ($(/usr/local/bin/cloudflared --version 2>&1 | head -1))"
echo "unified_server:           $BINARY"
echo "binary sha256:            $BIN_HASH"

# ─── Generate initramfs ────────────────────────────────────────────────────
# --add network            : pulls in dracut's network plumbing (mostly
#                            for the udhcpc + ip + dhclient binaries we
#                            inherit; the actual DHCP is invoked from
#                            our takeover init, not via dracut hooks).
# --add bpir-cloudflared   : 96bpir-cloudflared — bakes cloudflared + token.
# --add bpir-tier3-init    : 97bpir-tier3-init — bakes runit + takeover init.
# --add-drivers virtio_*   : KVM virt NIC + bus drivers (.ko's).
# --no-hostonly            : generic across re-boots / kernel updates.
# --reproducible           : strip mtimes / stamps from the cpio so a
#                            re-run of this script with the same inputs
#                            produces byte-identical output.
# SOURCE_DATE_EPOCH=0      : force every fallback timestamp to 1970-01-01.
echo "generating tier3 initrd…"
# --no-strip: dracut's default is to `strip` binaries on copy to save
# initramfs space. That MUTATES the binary, so /proc/self/exe at
# runtime no longer matches the on-disk binary's sha256. For Tier 3
# we want bake-time and run-time SHAs identical so the value the
# operator publishes (computed from `cargo build --release` output)
# is the value attest reports. Cost: ~few hundred KB extra in initramfs.
#
# --add-drivers virtio_net,virtio_pci,virtio_blk: KVM virt NIC + bus
# + block drivers (NIC + bus may be built-in on this kernel; safe).
# --add-drivers ccp,sev-guest,tsm_report: SEV-SNP attestation stack.
# udev auto-loads these on Slice 2 via PCI matching; in Tier 3 we
# have no udev so we both bake them in here AND explicitly modprobe
# in bpir-tier3-init.sh. tsm_report is a dep of sev-guest on kernel ≥6.10
# (modprobe pulls it transitively, but listing it makes intent explicit).
DRIVER_LIST="virtio_net virtio_pci virtio_blk $SEV_DRIVER_LIST"
SOURCE_DATE_EPOCH=0 dracut --force --no-hostonly --reproducible --nostrip \
    --add "network bpir-cloudflared bpir-unified-server bpir-tier3-init" \
    --add-drivers " $DRIVER_LIST " \
    --kver "$KVER" \
    "$CUSTOM_INITRD"
echo "initrd:                   $CUSTOM_INITRD ($(du -h "$CUSTOM_INITRD" | cut -f1))"

# Post-build validation: verify SEV-SNP kernel modules actually landed in the
# initramfs. Dracut silently skips modules it cannot find; the pre-build check
# guards against missing source .ko files, but this second gate catches
# dependency-resolution failures, dracut bugs, or accidental filter changes.
echo "verifying SEV modules in initramfs…"
# lsinitrd handles all compression formats (zstd/gzip/raw).
# Capture listing and check for the three SEV-SNP modules.
INITRD_LISTING=$(/usr/bin/lsinitrd "$CUSTOM_INITRD" 2>/dev/null)
if [ -z "$INITRD_LISTING" ]; then
    echo "ERROR: lsinitrd failed — cannot inspect initramfs" >&2
    exit 1
fi
MISSING_MODS=""
for mod in $REQUIRED_SEV_MODS; do
    # Use here-string instead of pipe to avoid SIGPIPE under set -o pipefail:
    # grep -q exits on first match, closing the pipe, echo gets SIGPIPE (141),
    # pipefail propagates that as the pipeline's exit status.
    if ! grep -q "${mod}\.ko" <<< "$INITRD_LISTING"; then
        MISSING_MODS="$MISSING_MODS $mod"
    fi
done
if [ -n "$MISSING_MODS" ]; then
    echo "ERROR: SEV kernel module(s) MISSING from initramfs:$MISSING_MODS" >&2
    echo "  /dev/sev-guest will NOT be created at boot → noSevHost." >&2
    echo "  Check: dracut warnings above, kernel module dir /usr/lib/modules/$KVER" >&2
    echo "  Hint:  find /usr/lib/modules/$KVER -name 'ccp.ko*' -o -name 'sev-guest.ko*'" >&2
    exit 1
fi
echo "SEV modules confirmed in initramfs: $REQUIRED_SEV_MODS"

# ─── Build the cmdline ─────────────────────────────────────────────────────
# rdinit=/sbin/bpir-tier3-init  : kernel exec's OUR script as PID 1
#                                 from the initramfs, bypassing dracut /init.
#                                 Bash equivalent of "init=" but for
#                                 initramfs (vs post-pivot rootfs).
# console=ttyS0,115200          : serial console — VPSBG portal may
#                                 expose this even though VNC doesn't work.
# console=tty1                  : framebuffer console (probably blank
#                                 under SEV-SNP but cheap to keep).
# loglevel=7                    : Phase 3.1 verbose dmesg for
#                                 first-boot diagnosis. Drop in 3.3.
#
# NOTE: no `root=` parameter — we don't pivot to a rootfs. dracut /init
# would refuse to proceed without it, but rdinit= bypasses /init entirely.
CMDLINE="rdinit=/sbin/bpir-tier3-init console=ttyS0,115200 console=tty1 quiet loglevel=3"

echo "cmdline:                  $CMDLINE"
echo

# ─── Build the UKI ─────────────────────────────────────────────────────────
ukify build \
    --linux="$KERNEL" \
    --initrd="$CUSTOM_INITRD" \
    --cmdline="$CMDLINE" \
    --output="$OUT"

# ─── Report ────────────────────────────────────────────────────────────────
SIZE=$(du -h "$OUT" | cut -f1)
UKI_SHA=$(sha256sum "$OUT" | awk '{print $1}')
echo
echo "wrote tier3 UKI:          $OUT (${SIZE})"
echo "tier3 uki sha256:         $UKI_SHA"
echo
echo "Next steps (Phase 3.2 acceptance):"
echo "  0. (One-time, before first deploy of this Tier 3 variant) provision"
echo "     the tunnel token on the target's rootfs partition. The token is"
echo "     no longer baked into the initramfs (sub-task 3 / option b of"
echo "     PHASE3_SLICE3_REPRO_PLAN.md), so cloudflared-run.sh sources it"
echo "     from /home/pir/data/cloudflared/tunnel.env at boot. Provision via"
echo "     Slice 2 SSH access:"
echo "       ssh <slice2-host> 'mkdir -p /home/pir/data/cloudflared && \\"
echo "           cp /etc/cloudflared/tunnel.env /home/pir/data/cloudflared/'"
echo "     Without this, the Tier 3 boot will FATAL-loop cloudflared and"
echo "     the tunnel will never come up."
echo
echo "  1. Download $OUT to your laptop:"
echo "       scp vpsbg-pir:$OUT ./bpir-tier3.efi"
echo
echo "  2. VPSBG dashboard → Confidentiality & Protection →"
echo "     Advanced: Measured Boot → UKI → Upload → Save & Reboot."
echo
echo "  3. Phase 3.2 acceptance — channel-test should now succeed end-to-end:"
echo "       bpir-admin channel-test wss://weikeng2.bitcoinpir.org \\"
echo "           --expect-ark-fingerprint 1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a"
echo "     The reported MEASUREMENT will be NEW (Tier 3 UKI ≠ Slice 2 UKI)."
echo "     Capture it and publish it as the new pinned MEASUREMENT."
echo
echo "  4. Verify the binary hash baked in matches what attest reports:"
echo "       bpir-admin attest wss://weikeng2.bitcoinpir.org \\"
echo "           --expect-binary $BIN_HASH"
echo
echo "  Recovery if Tier 3 bricks the box: VPSBG portal → Measured Boot →"
echo "  UKI → \"None\" → Save & Reboot. Stock Ubuntu rootfs boots; sshd is"
echo "  still installed there. Then re-build Slice 2 UKI via build_uki.sh."
