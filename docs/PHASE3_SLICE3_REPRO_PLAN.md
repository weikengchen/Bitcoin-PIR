# Phase 3 Slice 3 — UKI Reproducible-Build Plan (L4 polish)

**Status (2026-05-04)**: All five sub-tasks shipped. Sub-tasks 1+2+3b+4
deployed to pir2 as Tier 3 v4 (MEASUREMENT `f6aa2915…` chip-verified).
Sub-task 5 Phase 1 (Nix dev shell) + Phase 2 (`nix build .#unified-server`
derivation) both ship: the latter produces byte-identical binaries
across host paths inside a strict Nix sandbox (`f5ea19dc…` from any
clone path), closing the cross-path leak that the convention-based
recipe could only paper over. Open follow-ups: pre-fetch HEXL into
Nix to re-enable USE_HEXL=ON; extend Phase 2 to a `tier3-uki`
derivation that also produces the .efi (currently unified_server only). Slice 3 is shipped and Layer 3 reproducibility is
achieved (verifiers can compute MEASUREMENT given operator-published
UKI bytes + VPSBG's custom OVMF — see
[PHASE3_ROADMAP.md::Full Layer 3 reproducibility — verified 2026-05-03](PHASE3_ROADMAP.md)).

Progress log:
- ✅ Cargo.lock now tracked (commit 54078f2 — prerequisite for sub-tasks 2+4).
- ✅ Sub-task 1 — dracut module mtime normalization (commit dcad127).
  Empirical finding: dracut-060's `--reproducible` + `SOURCE_DATE_EPOCH=0`
  on Ubuntu 24.04 already neutralizes source-mtime variance, but the
  `touch -d @0` is kept as defense-in-depth. Validated on pir-hetzner
  with source mtimes a year apart → identical UKI sha 1f686ac4...
- ✅ Sub-task 3 (option b) — token off the initramfs (commit c4a3513).
  Token loaded at runtime from `/home/pir/data/cloudflared/tunnel.env`
  on the rootfs partition, no longer in MEASUREMENT. Validated on
  pir-hetzner with `/etc/cloudflared/tunnel.env` present vs absent
  → byte-identical UKI sha 81ae3e16... — operator-agnostic.
- ✅ Sub-task 4 — cargo vendor (commit 96a9753f). 313 crates / 6 git deps /
  261 MB in `vendor/`. Slightly over the plan's "~50-200 MB" estimate
  due to multiple windows-sys versions pulled transitively + SEAL/libdpf
  source. Validated `cargo check --offline -p pir-core` succeeds
  without network access.
- ✅ Sub-task 5 Phase 2 — `nix build .#unified-server` works end-to-end
  with **cross-path determinism**. Two upstream OnionPIR fork patches
  unblocked it:
    - `5cca228` → `c669da0`: bundle CMake setup into rust/onionpir/
      (move CMakeLists.txt + cpp/ + extern/SEAL inside the rust crate;
      drop submodule, commit SEAL as plain tracked tree so cargo vendor
      includes it).
    - `350ccc4`: drop hardcoded /usr/bin/{gcc,g++} from CMakeLists.txt;
      respect CMAKE_C_COMPILER if set, fall back to find_program.
  BitcoinPIR rev pin bumped to 350ccc4. Spike accepts USE_HEXL=OFF
  (slower SEAL paths) so we don't need network in the strict Nix
  sandbox; pre-fetching HEXL via fetchFromGitHub + patching SEAL's
  FetchContent_Declare is a follow-up.
  Validated on pir-hetzner: `nix build .#unified-server` from
  /home/pir/BitcoinPIR vs /tmp/bpir_alt (different host paths, same
  content) → both produce binary sha
  f5ea19dcea883ec9c99de8c906e1f6be3efc3c67e758c0dfe9fd725ef2126fce.
  This closes the cross-path leak that the convention papered over.
  Both Phase 2 follow-ups now closed:
  - ✅ **HEXL pre-fetch via Nix** (commit f4e20093): bundled
    `google/cpu_features` at the rev HEXL pins (32b49eb5...), patched
    HEXL's `cmake/third-party/cpu-features/CMakeLists.txt` to use
    `file(COPY)` from the Nix-fetched source instead of
    `ExternalProject_Add`. HEXL itself injected via
    `-DFETCHCONTENT_SOURCE_DIR_HEXL=$writable_hexl` into the vendored
    onionpir build.rs's CMake configure. USE_HEXL=ON works inside
    strict Nix sandbox; binary sha 1d684db1d0489271197b3e2e44f746f0ac
    5a57333a3ec28b5632b28061d98881; cross-path determinism verified.
  - ✅ **`packages.tier3-uki` derivation**: replaced dracut with
    NixOS's `makeInitrdNG` (handles Nix-store paths natively, no
    inst_simple symlink farm). `bpir-*` module install logic
    translated into a `contents` list of `{ source, target }` items.
    UKI assembly bypasses ukify (broken in current nixpkgs
    systemdUkify) and uses `objcopy` directly on the
    `linuxx64.efi.stub` from `pkgs.systemd`. `nix build .#tier3-uki`
    produces a 39MB `bpir-tier3.efi`; cross-path determinism verified
    (UKI sha 64845c92b2e308f62937dd69e95f9173318084ab10be04470c0f132a8b7aaad4
    from /home/pir/BitcoinPIR vs /tmp/bpir_alt6).

  Caveats on the Nix-built UKI (not blockers for L4 reproducibility,
  but worth flagging before any v6 deploy attempt):
  - Kernel: Nix `linuxPackages_6_12.kernel` (6.12.85), not Ubuntu's
    7.0.0-15-generic. Different kernel → different UKI sha → would
    require a fresh `web/src/attest-pin.ts` MEASUREMENT pin.
  - bpir-tier3-init.sh hardcodes paths like `/usr/bin/runsvdir`,
    `/sbin/udhcpc` from the dracut-style layout; these need patching
    to use Nix-store binaries (or PATH) before the UKI actually boots.
  - Kernel modules (virtio_*, ccp, sev-guest, tsm_report) aren't
    bundled — Nix kernel needs to be configured with =y for these
    drivers, or a modules tree added to `contents`.
  Phase 2 acceptance is "deterministic across operators", which is
  proven; "boots end-to-end on production" is a separate v6
  productionization step.
- ✅ Sub-task 2 — cargo bit-determinism (partial). Pinned via:
    1. `rust-toolchain.toml` → channel = "1.94.1"
    2. `Cargo.toml [profile.release]` → codegen-units = 1, incremental = false
    3. `.cargo/config.toml [env]` → SOURCE_DATE_EPOCH = 0 (forced)
    4. `scripts/build_unified_server.sh` → wraps `cargo build --release
       --frozen`, sets RUSTFLAGS with `--remap-path-prefix` for
       `$WORKSPACE_ROOT` and `$HOME` (TOML can't interpolate, so this
       lives in the wrapper rather than .cargo/config.toml), strips
       debug info reproducibly. `OFFLINE=1` env enables `--offline`.
  Validated on pir-hetzner: same-path rebuilds (delete target/, rerun)
  produce byte-identical binary sha e940d8f5...
  **Cross-path test FAILS**: build at /home/pir/BitcoinPIR vs build at
  /tmp/foo_repo with same source produces different binaries (e940d8f5
  vs 720fa2e3). Root cause: OnionPIR's CMake-built libonionpir.a +
  libseal-4.1.a contain C++ source paths via `__FILE__` macros that
  rustc's `--remap-path-prefix` doesn't reach (CMake would need
  `-ffile-prefix-map=` / `-fdebug-prefix-map=` in CXXFLAGS, but onionpir's
  build.rs deliberately env-removes CXXFLAGS to keep cargo from injecting
  Clang-specific flags). Practical consequence: operators must clone
  to the same canonical path (/home/pir/BitcoinPIR) for byte-identical
  binaries. Full path-independence requires either upstream OnionPIR
  fix (add `-ffile-prefix-map` to CMakeLists.txt) or sub-task 5
  (hermetic env normalises paths via mountpoint conventions).

This plan covers the L4 sub-gap: making the **UKI binary itself
bit-deterministic from source**, so that any verifier with the
git tree can rebuild byte-identical UKI bytes (and therefore the
same MEASUREMENT) without trusting the operator's published .efi.

The OVMF reproducibility sub-gap (asking VPSBG for their custom EDK2
build commit + flags) is **out of scope** for this plan — it's a
separate single-email task.

---

## Goal

Two operators on different machines, both starting from a fresh
`git clone` of the same commit + identical Cargo.lock + Ubuntu/Proxmox
package versions, produce **byte-identical** Tier 3 UKI bytes:

```bash
# Operator A:
git clone <repo> && cd <repo> && git checkout <commit>
sudo scripts/build_uki_tier3.sh
shasum -a 256 /tmp/bpir-tier3.efi

# Operator B (different machine, same inputs):
git clone <repo> && cd <repo> && git checkout <commit>
sudo scripts/build_uki_tier3.sh
shasum -a 256 /tmp/bpir-tier3.efi

# These two sha256 values must match.
```

When this works, MEASUREMENT can be predicted purely from source +
declared dependency versions. No "trust the operator's UKI bytes"
step in the verification chain.

---

## Current state — known divergence sources

The existing builds are **not** bit-deterministic. Empirically, two
back-to-back builds on the SAME machine produce identical UKI bytes
(thanks to `--reproducible` + `SOURCE_DATE_EPOCH=0` already passed to
dracut), but two builds on DIFFERENT machines or fresh clones
diverge. The known divergence sources, in rough order of impact:

1. **Dracut cpio mtimes leak in.** dracut reads our module-setup
   scripts from `scripts/dracut/96bpir-cloudflared/` etc.; their
   mtimes (set by `git clone` to the clone time) end up in the cpio
   archive. Two fresh clones at different times → different mtimes
   → different cpio bytes → different initrd → different UKI sha →
   different MEASUREMENT.

2. **`cargo build --release` is not bit-deterministic.** Stock cargo
   embeds the build path (`/home/pir/BitcoinPIR/target/...`),
   timestamps in dependency metadata, and parallel-compilation
   ordering quirks. Two builds on different hosts, even with
   identical Cargo.lock, produce different `unified_server` binaries.

3. **`TUNNEL_TOKEN` is baked into the initramfs.** Each operator has
   their own Cloudflare tunnel token; the token bytes live at
   `/etc/cloudflared/tunnel.env` inside the cpio. Even two operators
   running the same source produce different UKIs because the tokens
   differ. Beyond reproducibility, this also means the token is
   committed to MEASUREMENT — minor secrecy concern.

4. **Build-host package versions.** The build pulls binaries from
   `/usr/lib/`: kernel image, modules, busybox, runit, libstdc++,
   libgomp, libgcc_s, libm, libc, ld-linux. Two operators on
   different Ubuntu versions (or even the same version with
   different package update windows) produce different cpio
   contents.

5. **Dependency drift in cargo.** `Cargo.lock` pins versions but
   `cargo build` may re-fetch from crates.io with potentially
   different bytes (rare but possible if the mirror diverged).
   Vendored deps eliminate this.

---

## Sub-tasks (ordered by ROI: easy + high-impact first)

### 1. `touch -d @0` pre-pass on dracut module sources

**Effort**: 1 line.
**Impact**: closes the most common divergence (mtime leakage).

In `scripts/build_uki_tier3.sh`, before invoking dracut, force all
module-setup files to epoch 0:

```bash
find "$DRACUT_MODULE_DIR" -type f -exec touch -d @0 {} \;
# OR if cp -fp also propagates mtimes from elsewhere:
find /usr/lib/dracut/modules.d/96bpir-* /usr/lib/dracut/modules.d/97bpir-* \
    -type f -exec touch -d @0 {} \; 2>/dev/null
```

Same change in `scripts/build_uki.sh` (Slice 2 build) for revert
artifact reproducibility.

**Acceptance**: two consecutive builds on the same machine, with the
build dir wiped between runs (`rm -rf /usr/lib/dracut/modules.d/96bpir-*
/usr/lib/dracut/modules.d/97bpir-* /tmp/bpir-tier3-initrd.img
/tmp/bpir-tier3.efi`), produce identical UKI sha.

---

### 2. `cargo build --release` bit-determinism

**Effort**: medium (1-2 days, mostly testing).
**Impact**: the binary is the most observable divergence. Without
this fix, the operator-published `binary_sha256` only matches builds
on operator's specific machine.

Recipe (canonical Rust reproducibility):

```bash
# Set in the build environment OR add to .cargo/config.toml [build]:
RUSTFLAGS="--remap-path-prefix=$HOME=/build --remap-path-prefix=$PWD=/build/repo"

# Lock toolchain to a specific stable version via rust-toolchain.toml:
echo '[toolchain]
channel = "1.84.0"
components = ["rustfmt", "clippy"]
' > rust-toolchain.toml

# Set SOURCE_DATE_EPOCH for any timestamp embedding:
export SOURCE_DATE_EPOCH=0

# Build with single-codegen-unit + frozen deps:
cargo build --release --frozen -p runtime --bin unified_server \
    --config 'build.codegen-units=1'

# Strip debug info + reproducibly:
strip --strip-debug -g target/release/unified_server
```

Test by cloning into two different paths on the same machine, building
both, comparing sha. Then test on a different machine.

If pure cargo flags aren't enough (some deps have non-deterministic
build.rs), the next step is vendoring + a hermetic build container —
see sub-task 4 + 5.

**Acceptance**: two operators on different machines (same Ubuntu
version + same Rust toolchain) produce byte-identical
`unified_server` binaries.

---

### 3. Move `TUNNEL_TOKEN` out of the initramfs

**Effort**: medium-high (architectural decision required).
**Impact**: removes per-operator divergence + tightens the secrecy
of the token.

Currently the token sits in `/etc/cloudflared/tunnel.env` baked into
the cpio. The takeover init's runit service sources it. Options:

(a) **Pass via cmdline parameter.** Read from `/proc/cmdline` in the
    cloudflared service. Token IS still in MEASUREMENT (cmdline is
    measured), but moves out of the initramfs cpio bytes —
    operator-specific divergence shifts to the cmdline only, which
    can be templated cleanly.

(b) **Load from a runtime-mounted partition.** The runit service
    reads the token from `/data/cloudflared/tunnel.env` (on the
    bind-mounted rootfs partition, NOT in measured memory). Token
    is no longer in MEASUREMENT — UKI is operator-agnostic, anyone
    with the same git commit can rebuild byte-identical bytes.
    Trade-off: cloudflared no longer covered by MEASUREMENT in any
    sense (the token is data, not code, so this is mostly fine).

(c) **External cloudflared (separate service).** Run cloudflared
    on the host or a sidecar VM, not inside the SEV-SNP guest at all.
    Maximum reproducibility for the guest; loses the property that
    cloudflared sees only ciphertext (which is preserved by the
    Slice C encrypted channel anyway).

**Recommendation**: (a) for minimum churn. (b) is cleanest but means
re-thinking the runit service. (c) is a Slice 4 conversation.

**Acceptance**: the same git commit produces byte-identical UKI bytes
for two different operators with two different cloudflared tokens.

---

### 4. Vendor cargo dependencies

**Effort**: low (~1 hour).
**Impact**: removes dependency-fetch drift; required for fully
hermetic builds in sub-task 5.

```bash
# In the repo root:
cargo vendor vendor
cat >> .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored"
[source.vendored]
directory = "vendor"
EOF
git add vendor .cargo/config.toml
```

The `vendor/` dir adds ~50-200 MB to the repo. Consider Git LFS if
size matters.

**Acceptance**: `cargo build --release --offline` succeeds without
network access.

---

### 5. Hermetic build environment

**Effort**: medium-high (3-5 days).
**Impact**: closes the build-host divergence (kernel, packages,
toolchain). Required for full third-party reproducibility.

Two paths:

(a) **Nix flake**: `flake.nix` declares pinned nixpkgs + Rust
    toolchain + all build deps (dracut, ukify, runit, busybox,
    cloudflared). Operator runs `nix develop` then
    `scripts/build_uki_tier3.sh`. Anyone with Nix gets bit-identical
    binaries.

(b) **Pinned distroless container**: `Dockerfile.build` based on a
    fixed Ubuntu image (or distroless), with all deps installed at
    pinned versions. Operator runs
    `docker run --rm -v $PWD:/repo build-image
    /repo/scripts/build_uki_tier3.sh`.

(a) is the gold standard for reproducibility but requires Nix
proficiency. (b) is more accessible but Ubuntu's apt repo can drift
silently — would need to also pin via `apt-get install
package=version` and snapshot the package mirror.

**Acceptance**: two operators with no shared build infrastructure
(different OS, different Rust install) but same git commit produce
byte-identical UKI bytes.

---

## Validation strategy

For each sub-task, the test is: two builds, different machines/clones,
bit-identical output. The test SUITE for the whole plan:

```bash
# Operator A
git clone <repo> /tmp/repo-A && cd /tmp/repo-A
git checkout <commit>
<set up reproducible build env per sub-tasks 4+5>
sudo scripts/build_uki_tier3.sh
SHA_A=$(shasum -a 256 /tmp/bpir-tier3.efi | cut -d' ' -f1)

# Operator B (different host)
... same recipe ...
SHA_B=$(shasum -a 256 /tmp/bpir-tier3.efi | cut -d' ' -f1)

[ "$SHA_A" = "$SHA_B" ] && echo "✓ reproducible" || echo "✗ diverged"

# Cross-check against chip:
sev-snp-measure --mode snp --vcpus 2 --vcpu-sig 0x00B10F10 \
    --ovmf OVMF_SEV_MEASUREDBOOT_4M.fd \
    --kernel /tmp/bpir-tier3.efi \
    --guest-features 0x1
# matches what bpir-admin attest reports from pir2?
```

Sub-tasks land incrementally; each one closes a divergence source.
Sub-task 1 alone may already make 2 builds on the same machine
identical. Sub-tasks 1+2 may close most cases. Sub-task 5 is the
"belt and suspenders" final layer.

---

## Out of scope

- VPSBG OVMF source build commit + flags. One-line email to VPSBG
  support; not part of this plan.
- IGVM-based reproducibility. Proxmox uses `-kernel` not IGVM for
  the UKI case (per VPSBG response 2026-05-03), so IGVM tooling
  isn't needed.
- L5 ("trust no one including AMD"). AMD ARK fingerprint pinning
  is the trust anchor; this plan stays under that anchor.
- TCB / microcode reproducibility. SEV-SNP firmware version is
  AMD's responsibility; we pin via the published REPORTED_TCB in
  bpir-admin attest.

---

## Estimate

| Sub-task | Effort | Cumulative | What it unlocks |
|---|---|---|---|
| 1. dracut mtime fix | 1 line | 5 min | Same-machine determinism |
| 2. cargo reproducibility | 1-2 days | 1-2 days | Same-OS, different-machine binary determinism |
| 3. TUNNEL_TOKEN extraction | medium-high | 3-5 days | Different-operator UKI determinism |
| 4. cargo vendor | 1 hour | ~1-2 days | Offline-buildable deps |
| 5. hermetic build env | 3-5 days | ~1-2 weeks | Different-OS, different-distro full L4 |

Realistic full timeline: ~2 weeks of focused work. Sub-tasks 1+4 are
quick wins regardless of whether the whole plan ships.

---

## Reproducibility recipe (post sub-tasks 1 + 2 + 3b + 4)

This is the operator-facing recipe for reproducing the production
Tier 3 UKI from source as of commit `d0ff6f40`. Following it on a
clean Ubuntu 24.04 host produces a byte-identical
`unified_server` binary and Tier 3 UKI to the production deploy.

**Two paths to reproducibility:**

1. **Convention-based (default)**: clone to `/home/pir/BitcoinPIR`,
   run `./scripts/build_unified_server.sh` + `sudo
   ./scripts/build_uki_tier3.sh`. Recipe steps below assume this path.
   Cross-path determinism is convention-only here — different clone
   paths produce different binaries because OnionPIR's CMake-built
   C++ libs leak source paths via `__FILE__`.

2. **Nix flake (`unified_server` only, fully path-independent)**: with
   the OnionPIR upstream restructure (rev `350ccc4+`), `nix build
   .#unified-server` produces byte-identical bytes from any clone path
   (sub-task 5 Phase 2 / commit `88691dfc`). Replaces step 2 of the
   recipe below with `nix build .#unified-server && cp result/bin/
   unified_server target/release/unified_server`. The UKI build (step 3)
   still uses the convention-path-rooted scripts — `nix build` for
   `tier3-uki` is a tracked follow-up (dracut-Nix integration gap).

**Step 0 — host setup** (one-time per build host):

```bash
# Ubuntu 24.04, kernel 6.8.x or 7.0.x
sudo apt install -y \
    rustup git cmake gcc g++ \
    systemd-ukify dracut dracut-network systemd-boot-efi runit busybox-static
# Cloudflared static binary at /usr/local/bin/cloudflared (download from
# Cloudflare and chmod +x).
```

**Step 1 — clone to the canonical path**:

```bash
sudo mkdir -p /home/pir
sudo chown $USER:$USER /home/pir
git clone https://github.com/Bitcoin-PIR/Bitcoin-PIR.git /home/pir/BitcoinPIR
cd /home/pir/BitcoinPIR
git checkout <target commit>
# rustup auto-installs the toolchain pinned by rust-toolchain.toml (1.94.1)
```

**Step 2 — build unified_server with deterministic flags**:

```bash
./scripts/build_unified_server.sh
# First-time fetch of the OnionPIRv2-fork git dep happens here (online).
# Subsequent rebuilds: OFFLINE=1 ./scripts/build_unified_server.sh works.
# Output: target/release/unified_server  +  printed sha256.
```

**Step 3 — build the Tier 3 UKI**:

```bash
sudo ./scripts/build_uki_tier3.sh
# Output: /tmp/bpir-tier3.efi  +  printed sha256.
```

**Step 4 — verify against the published artifacts**:

```bash
# Operator-published triple: (binary sha, UKI sha, MEASUREMENT)
# Verifier compares the operator's printed shas to their own:
[ "$LOCAL_BIN_SHA"  = "$PUBLISHED_BIN_SHA"  ] && echo "✓ binary"
[ "$LOCAL_UKI_SHA"  = "$PUBLISHED_UKI_SHA"  ] && echo "✓ UKI"

# Independently compute MEASUREMENT from the UKI bytes:
sev-snp-measure --mode snp --vcpus 2 --vcpu-sig 0x00B10F10 \
    --ovmf OVMF_SEV_MEASUREDBOOT_4M.fd \
    --kernel /tmp/bpir-tier3.efi \
    --guest-features 0x1
# Should match the published MEASUREMENT, which should match the chip-
# reported MEASUREMENT from `bpir-admin attest wss://weikeng2.bitcoinpir.org`.
```

**Pre-deploy operator checklist** (one-time, before booting a new
Tier 3 UKI):

```bash
# Provision the cloudflared tunnel token on the rootfs partition,
# since sub-task 3(b) takes it out of MEASUREMENT. The Tier 3 init
# bind-mounts /sysroot/home/pir/data → /home/pir/data, where
# cloudflared-run.sh sources tunnel.env at boot.
ssh <slice2-host> '
    mkdir -p /home/pir/data/cloudflared && \
    cp /etc/cloudflared/tunnel.env /home/pir/data/cloudflared/'

# Then portal-upload /tmp/bpir-tier3.efi and Save & Reboot.
```

**Recovery if the new UKI bricks the box** — VPSBG portal → Measured
Boot → UKI → "None" → Save & Reboot. Stock Ubuntu rootfs comes up
with sshd; rebuild Slice 2 UKI via `scripts/build_uki.sh` if needed
(which is also bit-deterministic post sub-task 1).
