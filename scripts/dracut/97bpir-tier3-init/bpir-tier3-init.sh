#!/bin/sh
# Tier 3 PID 1 takeover.
#
# Runs as PID 1 inside the initramfs. The kernel exec's this script
# directly via the `rdinit=/sbin/bpir-tier3-init` cmdline parameter
# (set by scripts/build_uki_tier3.sh in the UKI cmdline that goes into
# MEASUREMENT). Dracut's /init never runs.
#
# Responsibilities:
#   1. Mount kernel pseudo-fs (/proc, /sys, /dev, /run).
#   2. Bring up the network: load virtio_net + DHCP via udhcpc.
#   3. Wire up the runit service tree.
#   4. exec runsvdir as the long-lived PID 1.
#
# If anything fails before runsvdir takes over, we drop to a /bin/sh
# loop on the console — no other recovery path exists (no SSH from
# initramfs, no VNC on this host). Operator recovery = portal "None"
# UKI fallback → boot stock Ubuntu rootfs → SSH back in → fix.

# shellcheck shell=sh

set -x  # Phase 3.1: verbose console logging for debugging the first boot.
        # Drop this in Phase 3.3 once the path is stable.

PATH=/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin
export PATH

# ── 1. Kernel pseudo-fs ────────────────────────────────────────────
# These come from the initramfs's empty mount points; kernel doesn't
# auto-populate them when we use rdinit= (vs going through dracut's
# /init which does the equivalent). idempotent: skip if already mounted.
mount -t proc     proc     /proc     2>/dev/null || true
mount -t sysfs    sysfs    /sys      2>/dev/null || true
mount -t devtmpfs devtmpfs /dev      2>/dev/null || true
[ -d /dev/pts ] || mkdir -p /dev/pts
mount -t devpts   devpts   /dev/pts  2>/dev/null || true
[ -d /run ] || mkdir -p /run
mount -t tmpfs    tmpfs    /run      2>/dev/null || true

# ── 2. Network bring-up (STATIC, matching VPSBG netplan) ───────────
# DISCOVERED Phase 3.1 v3: VPSBG uses STATIC IP via cloud-init / netplan,
# NOT DHCP. Slice 2's /etc/netplan/50-cloud-init.yaml hardcodes:
#   addresses: 87.120.8.198/32
#   gateway:   172.16.0.1 (on-link)
#   DNS:       9.9.9.9, 208.67.222.222
# udhcpc was getting no lease (no DHCP server to respond), eth0 stayed
# IP-less, every outbound packet failed with "network unreachable".
# Mirror netplan exactly here.
#
# Trade-off: the IP is now baked into MEASUREMENT. If VPSBG re-IPs us
# (rare for paid VMs, happens only on instance migration), the UKI
# needs rebuilding. Acceptable cost for Phase 3.1; revisit if VPSBG
# IP rotation becomes a regular thing.

modprobe virtio_net 2>/dev/null || true
modprobe virtio_pci 2>/dev/null || true

ip link set lo up 2>/dev/null || true

# Wait for eth0 to enumerate (virtio_pci probe is async).
i=0
while [ ! -d /sys/class/net/eth0 ] && [ "$i" -lt 60 ]; do
    sleep 0.2
    i=$((i + 1))
done
if [ ! -d /sys/class/net/eth0 ]; then
    echo "[bpir-tier3-init] FATAL: eth0 never appeared after 12s" >&2
    echo "[bpir-tier3-init] available interfaces:" >&2
    ls /sys/class/net/ >&2
    exec /bin/sh
fi

# Bring eth0 up + assign static IP.
# The /32 mask means "no local subnet" — gateway 172.16.0.1 is not
# in our address range, so we need `onlink` to tell the kernel
# "treat this gateway as directly attached on eth0 even though it
# isn't in our subnet." This is what netplan's `on-link: true` does.
ip link set eth0 up
ip addr add 87.120.8.198/32 dev eth0
ip route add default via 172.16.0.1 dev eth0 onlink

# DNS: same servers as netplan (Quad9 + OpenDNS).
mkdir -p /etc
cat > /etc/resolv.conf <<'EOF'
nameserver 9.9.9.9
nameserver 208.67.222.222
EOF

# Sanity: dump network state to console.
ip addr show
echo "--- /etc/resolv.conf ---"
cat /etc/resolv.conf 2>/dev/null || echo "[bpir-tier3-init] WARN: still no /etc/resolv.conf"
echo "--- routes ---"
ip route show

# ── 3. Mount rootfs + bind /home/pir/data ──────────────────────────
# Phase 3.2: unified_server reads /home/pir/data/databases.toml and
# mmaps the per-DB checkpoint files referenced from there. The DBs
# (~14 GB) can't live in the initramfs, so we mount the existing
# rootfs and expose /home/pir/data via a bind.
#
# Mount RW: unified_server writes to /home/pir/data/.staging/ for
# admin DB uploads, and may also write VCEK chain refreshes there.
# Future hardening (Phase 3.3+): mount /sysroot ro and overlay-bind
# only /home/pir/data rw, so an attacker compromising unified_server
# cannot scribble on /usr/, /etc/, /home/pir/.ssh/, etc.
#
# IMPORTANT: this section MUST NOT exit-or-shell on failure. If the
# rootfs mount fails, we still want runsvdir → cloudflared to start,
# so the tunnel comes up (giving us a HTTP 502 we can observe) instead
# of leaving the box in HTTP 530 silent-black-hole mode. Phase 3.2 v1
# learned this the hard way.

echo "--- mounting rootfs ---"
modprobe virtio_blk 2>/dev/null || true   # KVM virt block driver
modprobe ext4       2>/dev/null || true   # likely built-in; safe no-op

# Wait briefly for block devices to enumerate.
i=0
while [ "$i" -lt 30 ] && ! grep -qE "(vda|sda|nvme)" /proc/partitions; do
    sleep 0.2
    i=$((i + 1))
done
echo "--- /proc/partitions ---"
cat /proc/partitions
echo "--- blkid ---"
blkid 2>&1 || true

mkdir -p /sysroot
mounted=false
# Try LABEL first (matches Slice 2's /etc/netplan and build_uki.sh's
# ROOT_LABEL default). Fall back to common device paths.
for src in "LABEL=cloudimg-rootfs" /dev/vda1 /dev/sda1 /dev/vda /dev/sda; do
    case "$src" in LABEL=*) flag="-L ${src#LABEL=}" ;; *) flag="$src" ;; esac
    if mount $flag -o rw /sysroot 2>/dev/null; then
        echo "[bpir-tier3-init] rootfs mounted at /sysroot via $src"
        mounted=true
        break
    fi
done

if [ "$mounted" = "true" ]; then
    mkdir -p /home/pir/data
    if mount --bind /sysroot/home/pir/data /home/pir/data 2>&1; then
        echo "[bpir-tier3-init] /home/pir/data bind-mounted (rw)"
        if [ ! -r /home/pir/data/databases.toml ]; then
            echo "[bpir-tier3-init] WARN: /home/pir/data/databases.toml missing — unified_server will fail to start" >&2
        fi
    else
        echo "[bpir-tier3-init] WARN: bind mount of /home/pir/data failed; unified_server will fail to start, cloudflared will still come up" >&2
    fi
else
    echo "[bpir-tier3-init] WARN: rootfs mount failed — no /home/pir/data available, unified_server will not run, but cloudflared will still come up so we keep observability" >&2
fi

# ── 4. /dev/sev-guest ─────────────────────────────────────────────
# Required by unified_server for SEV-SNP attestation. The kernel
# modules `ccp` (AMD Crypto Coprocessor) + `sev-guest` (which depends
# on tsm_report) auto-load via udev on Slice 2; Tier 3 has no udev,
# so load explicitly. The .kos are baked in via build_uki_tier3.sh's
# --add-drivers list; modprobe finds them under /lib/modules/.
#
# Order: ccp first (provides the SEV interface), then sev-guest
# (modprobe pulls tsm_report transitively as a dep). Once sev-guest
# loads, the kernel auto-creates /dev/sev-guest in devtmpfs.
#
# In Tier 3 we run unified_server as root, so the default
# root:root 0600 perms on /dev/sev-guest are sufficient — no chgrp/
# chmod equivalent of the Slice 2 systemd ExecStartPre is needed.
    echo "--- loading SEV-SNP kernel modules ---"
    modprobe ccp        || echo "[bpir-tier3-init] WARN: modprobe ccp failed"
    modprobe sev-guest  || echo "[bpir-tier3-init] WARN: modprobe sev-guest failed"
    modprobe tsm_report || echo "[bpir-tier3-init] WARN: modprobe tsm_report failed"
    echo "--- sev modules + device ---"
    lsmod 2>/dev/null | grep -E "sev|ccp|tsm" || echo "[bpir-tier3-init] WARN: no sev/ccp modules loaded"
    if [ -c /dev/sev-guest ]; then
        ls -la /dev/sev-guest
        echo "[bpir-tier3-init] /dev/sev-guest ready — SEV-SNP attestation enabled"
    else
        echo "[bpir-tier3-init] WARN: /dev/sev-guest missing — SEV-SNP attest will return NoSevHost"
        echo "[bpir-tier3-init] modules may not have been baked into initramfs — check UKI build log"
    fi

# ── 5. Service tree ────────────────────────────────────────────────
mkdir -p /etc/service
ln -sf /etc/sv/unified_server /etc/service/unified_server
ln -sf /etc/sv/cloudflared    /etc/service/cloudflared

# ── 6. Hand off to runsvdir ────────────────────────────────────────
# runsvdir watches /etc/service/, spawns runsv per service, restarts
# them on exit. As PID 1 it also reaps zombies. Replaces this script.
# unified_server starts immediately; cloudflared waits on port 8091
# in its own run script (so the tunnel doesn't come up to a dead origin).
echo "[bpir-tier3-init] handing off to runsvdir"
exec /usr/bin/runsvdir /etc/service
