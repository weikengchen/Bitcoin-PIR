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
# Note (2026-05-20): for any binary whose sha256 you intend to PUBLISH
# or PIN — including the one baked into the Tier 3 UKI and the one
# pinned in web/src/attest-pin.ts — use the hermetic Nix flake:
#
#   nix build .#unified-server
#
# Empirically bit-reproducible (verified 2026-05-20 via
# `nix-store --realise --check` on the unified-server, hexl, and onionpir
# derivations — all three rebuilt byte-identical to existing store
# outputs), links Intel HEXL into OnionPIR's C++ engine, and is what
# pir1/pir2 actually run.
#
# This script is a no-Nix DEVELOPMENT convenience. By default it builds
# OnionPIR's C++ engine with the in-crate scalar/SIMD shim
# (cpp/hexl_shim.cpp). Since onionpir rev 3f815ba (re-pin in 835791e6),
# the crate's build.rs auto-emits HEXL link flags when CMake finds an
# HEXL install — so if you've run scripts/install_hexl.sh to pin
# HEXL 1.2.6 (+ google/cpu_features 0.10.1) on the host, this script
# switches to the HEXL-accelerated build path automatically. The auto-
# detection probes $HEXL_PREFIX (default /usr/local) and, on Apple
# Silicon, falls back to /opt/homebrew. Override either by setting
# HEXL_PREFIX explicitly, or set HEXL_PREFIX=none to force the shim.
#
# Even with HEXL pinned, this script is NOT bit-reproducible across
# hosts: system gcc/clang, libc, cmake, and linker versions are not
# pinned. Use it to iterate locally; do not pin its sha256 anywhere.
#
# Operator usage:
#   ./scripts/install_hexl.sh                            # one-time, optional
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

# ─── HEXL preflight (since onionpir 3f815ba) ─────────────────────────────
# onionpir's build.rs runs `find_package(HEXL CONFIG)` and emits the
# linker flags when it locates an HEXL install. CMake's default search
# path includes /usr/local; we additionally probe /opt/homebrew for
# Apple Silicon and respect $HEXL_PREFIX as an explicit override. If
# HEXL_PREFIX=none, skip detection entirely (force shim).
#
# Version check: we look for the literal directory name `hexl-1.2.6`
# under <prefix>/lib/cmake/, which is HEXL's CMake-installed config
# layout. A mismatched version (e.g. hexl-1.2.5/) simply won't match
# and we fall back to the shim — never link against an unpinned HEXL.
HEXL_FOUND=""
if [ "${HEXL_PREFIX:-}" = "none" ]; then
    echo "    HEXL:              skipped (HEXL_PREFIX=none)"
else
    # Build a list of candidate prefixes to probe.
    HEXL_CANDIDATES=()
    [ -n "${HEXL_PREFIX:-}" ] && HEXL_CANDIDATES+=("$HEXL_PREFIX")
    HEXL_CANDIDATES+=("/usr/local")
    # Apple Silicon Homebrew default. Harmless on other platforms (dir
    # won't exist).
    [ -d /opt/homebrew ] && HEXL_CANDIDATES+=("/opt/homebrew")

    for candidate in "${HEXL_CANDIDATES[@]}"; do
        if [ -f "$candidate/lib/cmake/hexl-1.2.6/HEXLConfig.cmake" ]; then
            HEXL_FOUND="$candidate"
            break
        fi
    done

    if [ -n "$HEXL_FOUND" ]; then
        echo "    HEXL:              1.2.6 at $HEXL_FOUND (accelerated build)"
        # Pass to the onionpir CMake invocation. Defense-in-depth — the
        # default search path already includes /usr/local; this also
        # covers /opt/homebrew + $HEXL_PREFIX overrides.
        export CMAKE_PREFIX_PATH="$HEXL_FOUND${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
    else
        echo "    HEXL:              not found (building in-crate scalar/SIMD shim)"
        echo "                       run ./scripts/install_hexl.sh for HEXL acceleration"
    fi
fi
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
