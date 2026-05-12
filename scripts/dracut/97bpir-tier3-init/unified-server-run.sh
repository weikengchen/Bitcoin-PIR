#!/bin/sh
# runit service: BitcoinPIR unified_server.
#
# Lives at /etc/sv/unified_server/run inside the initramfs. runsvdir
# starts this; runit restarts on exit (1s default backoff).
#
# Flags mirror deploy/systemd/pir-vpsbg.service:
#   --port 8091
#   --role secondary   (DPF queries + HarmonyPIR hint, no OnionPIR)
#   --config /home/pir/data/databases.toml   (loaded from rootfs via
#                                             bpir-tier3-init's bind mount)
#   --admin-pubkey-hex <op key>   (auth for REQ_ADMIN_DB_UPLOAD etc.)
#
# Runs as root — Tier 3 initramfs has no /etc/passwd, so dropping
# privs to a `pir` user via chpst -u would need an `/etc/passwd`
# file with a numeric UID. Punted to a future hardening pass.
# /dev/sev-guest is owned root:root 0600 by default, so root access
# is required to read attestation reports anyway.

# shellcheck shell=sh

# Wait for the bind-mounted /home/pir/data to actually be available.
# The takeover init mounts it before starting runsvdir, but runit
# might race on cold-start. Give it a few seconds.
i=0
while [ ! -r /home/pir/data/databases.toml ] && [ "$i" -lt 30 ]; do
    sleep 0.5
    i=$((i + 1))
done
if [ ! -r /home/pir/data/databases.toml ]; then
    echo "[unified-server-run] FATAL: /home/pir/data/databases.toml missing — bind mount failed?" >&2
    sleep 5
    exit 1
fi

exec /usr/local/bin/unified_server \
    --port 8091 \
    --role secondary \
    --pool-size 8 \
    --pool-dir /home/pir/data/hint_pool \
    --config /home/pir/data/databases.toml \
    --admin-pubkey-hex 87d454db85266e10e55ed8b68417de9d79ceb1d5d944bae831a7877627efdad3 \
    --vcek-dir /home/pir/data/vcek \
    2>&1
