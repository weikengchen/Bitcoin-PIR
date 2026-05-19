#!/usr/bin/env bash
# Build unified_server with bit-deterministic settings.
#
# Sub-task 2 of docs/PHASE3_SLICE3_REPRO_PLAN.md. The unified_server binary
# baked into the Tier 3 UKI must be byte-identical across operators so
# the resulting MEASUREMENT is independently predictable. This wrapper
# enforces every input that affects binary bytes:
#
#   - rust-toolchain.toml pins the rustc version (rustup auto-installs).
#   - Cargo.toml [profile.release] sets codegen-units = 1 (parallel
#     compilation orderings are otherwise non-deterministic) and
#     incremental = false (incremental cache state varies across runs).
#   - .cargo/config.toml [env] forces SOURCE_DATE_EPOCH = 0 (any
#     timestamp-embedding build.rs uses 1970-01-01 instead of wall clock).
#   - --remap-path-prefix (set here) strips $WORKSPACE_ROOT and $HOME
#     from any source-path strings rustc embeds in debuginfo / panic
#     messages, so two operators cloning to /home/dave/BitcoinPIR vs
#     /home/pir/BitcoinPIR produce identical bytes.
#   - --frozen + --offline pin the dep set to vendor/ + Cargo.lock; any
#     drift fails fast instead of silently producing different bytes.
#   - strip --strip-debug removes any residual debuginfo (release builds
#     generally have none, but defense-in-depth).
#
# What this does NOT cover (those need sub-task 5 / hermetic env):
#   - Build-host glibc / linker version
#   - Build-host system rustc/cargo binaries (rust-toolchain.toml only
#     pins the rustc selected via rustup; the rustup harness itself
#     can vary)
#
# Note (2026-05): the hermetic Nix flake `nix build .#unified-server`
# is now the canonical, content-addressed build — it is what is
# deployed to pir1/pir2 and pinned in web/src/attest-pin.ts, and it
# links Intel HEXL into OnionPIR's C++ engine. This convention recipe
# instead builds that engine with the in-crate scalar/SIMD shim:
# onionpir's build.rs emits no HEXL link flags, so a system-installed
# HEXL would fail the link (which is why /usr/local HEXL is not kept
# on the build host). Prefer the flake where Nix is available; keep
# this script as the non-Nix fallback.
#
# Operator usage:
#   ./scripts/build_unified_server.sh
# Output: target/release/unified_server  +  printed sha256.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
WORKSPACE_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$WORKSPACE_ROOT"

# Order of --remap-path-prefix matters: rustc applies the first matching
# prefix for each source path, so the LONGER (more-specific) prefix must
# come first. $WORKSPACE_ROOT is typically inside $HOME, so list it first
# to avoid /home/pir/BitcoinPIR/src/foo.rs becoming /build/BitcoinPIR/src/foo.rs.
export RUSTFLAGS="--remap-path-prefix=$WORKSPACE_ROOT=/build/repo --remap-path-prefix=$HOME=/build ${RUSTFLAGS:-}"

# Redundant with .cargo/config.toml [env], but stated here for transparency.
export SOURCE_DATE_EPOCH=0

echo "==> building target/release/unified_server with deterministic flags"
echo "    rustc:             $(rustc --version 2>&1)"
echo "    workspace:         $WORKSPACE_ROOT"
echo "    RUSTFLAGS:         $RUSTFLAGS"
echo "    SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
echo

# --locked enforces "Cargo.lock is the truth, never auto-update", which is
# what we want for reproducibility, but unlike --frozen it still allows
# fetching deps from the network. We need that because the OnionPIRv2-fork
# git dep isn't vendored (see .cargo/config.toml note) — first build on a
# fresh cargo cache must hit github to populate the git checkout. After
# the initial fetch, builds can run offline by passing OFFLINE=1
# (combines --locked + --offline = same effect as --frozen).
if [ "${OFFLINE:-0}" = "1" ]; then
    cargo build --release --locked --offline -p runtime --bin unified_server
else
    cargo build --release --locked -p runtime --bin unified_server
fi

# Strip debug info reproducibly. GNU strip on Linux; macOS strip has
# different flags but macOS isn't a supported reproducible-build target
# (the UKI bakes a Linux ELF). On macOS we just skip with a warning.
case "$(uname -s)" in
    Linux*)
        strip --strip-debug target/release/unified_server
        ;;
    *)
        echo "WARN: skipping strip on $(uname -s) — sub-task 2 reproducibility is Linux-only" >&2
        ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
    BIN_HASH=$(sha256sum target/release/unified_server | awk '{print $1}')
else
    BIN_HASH=$(shasum -a 256 target/release/unified_server | awk '{print $1}')
fi

echo
echo "wrote:    target/release/unified_server"
echo "sha256:   $BIN_HASH"
echo
echo "Pin this sha256 alongside the UKI sha256 + MEASUREMENT for verifiers."
