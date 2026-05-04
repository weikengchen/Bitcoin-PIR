# PIR Fix Status — 2026-05-04

## Completed

### HarmonyPIR V2 Hint Pool
- **Protocol**: Added `REQ_HARMONY_HINTS_V2 = 0x44` — server generates PRP key per client, pre-computes hints offline
- **Hint pool manager**: `runtime/src/hint_pool.rs` — background thread generates pool entries (key-at-a-time, rayon over 155 groups), disk persistence with `HMPOOL\x01` magic
- **Server dispatch**: `unified_server.rs` — V2 arm serves pre-serialized frames from pool in <1ms
- **Client**: `harmony.rs` — `ensure_groups_ready_v2()` with V1 fallback
- **Deployed to Hetzner** (pir-primary + pir-secondary, both with `--pool-size 8`)
- **Deployed to VPSBG** (new UKI built with `--pool-size 8` in runit script, uploaded via portal, rebooted)
- **V2 protocol verified working** on both servers (WebSocket test confirmed preamble + 155 hint frames)

### Binary SHA256 Pins Updated
- `PIR1_PIN.binarySha256Hex` → `11f0860bee3c00da478ecddb43a9431393b27c78952a0bd69f0561d7d509452d`
- `PIR2_TIER3_PIN.binarySha256Hex` → `eb625c68afc81d8d81e3d2a8bea9363282c32477c26c34093b41b918b9c678b6`

### 2. Fix `noSevHost` for pir2 — build-time hardening (2026-05-04)
**Root cause:** The UKI build script hardcoded `KERNEL=/boot/vmlinuz-7.0.0-15-generic`. If `apt autoremove` cleaned the matching kernel modules, dracut silently skipped the `ccp`/`sev-guest`/`tsm_report` modules → UKI boots but `/dev/sev-guest` never appears → `noSevHost`.

**Fixes applied to `scripts/build_uki_tier3.sh`:**
- Auto-detect the latest installed kernel if `KERNEL=` is unset (`ls -1v /boot/vmlinuz-*-generic | tail -1`)
- Validate SEV kernel modules exist at `/usr/lib/modules/$KVER/kernel/drivers/` before running dracut (fail early with actionable message)
- Post-build validation: verify `ccp.ko`, `sev-guest.ko`, `tsm_report.ko` landed in the initramfs via `lsinitrd` (fail if missing)

**Fixes applied to `scripts/dracut/97bpir-tier3-init/bpir-tier3-init.sh`:**
- Removed `2>/dev/null` from modprobe calls — errors are now visible on serial console
- Added `|| echo "[bpir-tier3-init] WARN: ..."` for each modprobe failure (no silent success `|| true`)
- Added `[ -c /dev/sev-guest ]` check after loading to confirm the device node exists

**To complete the fix:** rebuild and redeploy the UKI on VPSBG:
```
ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki_tier3.sh'
scp vpsbg-pir:/tmp/bpir-tier3.efi ./bpir-tier3.efi
# Upload via VPSBG portal → Measured Boot → UKI → Save & Reboot
```

### 3. Add V2 dispatch to `harmonypir_hint_server.rs` (2026-05-04)
The standalone hint server now handles `REQ_HARMONY_HINTS_V2`:
- Generates a fresh random PRP key per request
- Builds and sends the key preamble frame (`RESP_HARMONY_HINTS_KEY = 0x44`)
- Computes and streams all INDEX groups (0..K-1) + all CHUNK groups (0..K_CHUNK-1) via rayon
- Uses the same `compute_hints_for_group` as the V1 path; ALF PRP backend by default

### 4. Clean up warnings (2026-05-04)
- Removed unused `config: HintPoolConfig` field from `HintPool` struct
- Removed unused `tag_seed: u64` field from `DbParams` struct

## Pending

### 1. Capture new pir2 MEASUREMENT
The VPSBG UKI initramfs changed (`--pool-size 8` added to runit script + SEV module hardening), so the SEV-SNP MEASUREMENT changed. After rebuilding and redeploying the UKI:
```
bpir-admin attest wss://pir2.chenweikeng.com
```
This will return the new 96-char measurement hex. Then update `PIR2_TIER3_PIN.measurementHex` in `web/src/attest-pin.ts`.

### 5. Rebuild UKI on VPSBG
Pull the updated scripts, rebuild, and deploy:
```
ssh vpsbg-pir 'cd /home/pir/BitcoinPIR && git pull'
ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki_tier3.sh'
scp vpsbg-pir:/tmp/bpir-tier3.efi ./bpir-tier3.efi
# VPSBG portal → Measured Boot → UKI → Upload → Save & Reboot
```
