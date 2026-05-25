#!/bin/sh
# runit service: BitcoinPIR unified_server.
#
# Lives at /etc/sv/unified_server/run inside the initramfs. runsvdir
# starts this; runit restarts on exit (1s default backoff).
#
# Flags mirror deploy/systemd/pir-vpsbg.service:
#   --port 8091
#   --role secondary   (DPF queries + HarmonyPIR query phase, no OnionPIR)
#   --serve-queries    (pir2 is queries-only per the production topology
#                       — see memory: project_pir1_hint_pir2_query_split.md.
#                       No --serve-hints, no --pool-size: hints come from
#                       pir1/Hetzner instead. Required by the startup
#                       validation in unified_server::main since 2026-05-13;
#                       without it the binary exits code 2 → runit crash-loop.)
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
    --serve-queries \
    --config /home/pir/data/databases.toml \
    --admin-pubkey-hex 87d454db85266e10e55ed8b68417de9d79ceb1d5d944bae831a7877627efdad3 \
    --vcek-dir /home/pir/data/vcek \
    --identity-key-path /home/pir/data/pir2-identity.key \
    --identity-cert-path /home/pir/data/pir2.cert \
    --identity-server-id pir2 \
    2>&1
# --identity-* (operator-signed identity / REQ_ANNOUNCE): key + cert live
# in the bind-mounted rootfs /home/pir/data — NOT baked into the measured
# initramfs (only this run script + the binary are measured). Missing or
# inconsistent files are non-fatal (unified_server logs "Identity
# announce: DISABLED" and serves everything else), so this is safe to ship
# ahead of provisioning the files. server_id MUST be "pir2" to match the
# operator-signed cert.
