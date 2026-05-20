#!/usr/bin/env bash
# Build + install Intel HEXL 1.2.6 + google/cpu_features (HEXL's CMake
# dependency) to ${PREFIX:-/usr/local}. Bare-metal twin of the `hexl`
# derivation in flake.nix:37-66 — same git tag (v1.2.6), same six CMake
# flags — so a unified_server built afterwards via
# ./scripts/build_unified_server.sh links HEXL identical (at the
# source/flag level) to the flake's HEXL build.
#
# Cross-host byte-reproducibility is still NOT achieved: the system
# gcc/clang, libc, cmake, and linker versions are not pinned. The Nix
# flake `nix build .#unified-server` remains the canonical bit-
# reproducible build path. This script is a dev convenience for non-Nix
# Linux + macOS hosts that want HEXL acceleration locally.
#
# Supported:
#   Linux x86_64     — full AVX-512-IFMA / AVX-512-DQ / AVX2 dispatch
#   macOS x86_64     — Intel Mac dev box
#   macOS arm64      — Apple Silicon (HEXL 1.2.5+ adds NEON paths;
#                      slower than x86_64 but works)
#
# Usage:
#   ./scripts/install_hexl.sh                            # → /usr/local (will sudo)
#   PREFIX=$HOME/.local ./scripts/install_hexl.sh        # user-local, no sudo
#   PREFIX=/opt/homebrew ./scripts/install_hexl.sh       # Apple Silicon brew prefix
#
# After install, ./scripts/build_unified_server.sh detects the install
# via ${HEXL_PREFIX:-/usr/local} (auto-checks /opt/homebrew on Apple
# Silicon) and switches to the HEXL-accelerated build path.
#
# Pin rationale: HEXL v1.2.6 is what flake.nix pins (line 43). The Nix
# build verifies the source via a content-addressed sha256 hash; here
# we rely on git tag immutability (enforced by GitHub for released
# tags). If intel/hexl ever rewrote v1.2.6 (extremely unlikely for a
# released tag), the produced binary would silently change.

set -euo pipefail

# ─── Pinned versions (must match flake.nix) ──────────────────────────────
HEXL_TAG="v1.2.6"
# cpu_features is HEXL's runtime CPU-feature-detection dep. nixpkgs pins
# 0.10.1; pin the matching upstream tag here for parity.
CPU_FEATURES_TAG="v0.10.1"

HEXL_REPO="https://github.com/intel/hexl.git"
CPU_FEATURES_REPO="https://github.com/google/cpu_features.git"

PREFIX="${PREFIX:-/usr/local}"

# ─── Platform detection ──────────────────────────────────────────────────
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux*|Darwin*) ;;
    *)
        echo "ERROR: unsupported platform $OS (need Linux or macOS)" >&2
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|aarch64|arm64) ;;
    *)
        echo "ERROR: unsupported architecture $ARCH" >&2
        exit 1
        ;;
esac

echo "==> install_hexl.sh"
echo "    platform:  $OS $ARCH"
echo "    HEXL tag:  $HEXL_TAG"
echo "    cpu_feat:  $CPU_FEATURES_TAG"
echo "    PREFIX:    $PREFIX"

# ─── Toolchain checks ────────────────────────────────────────────────────
for tool in cmake git; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: $tool not found in PATH" >&2
        case "$OS" in
            Darwin*) echo "       brew install $tool" >&2 ;;
            Linux*)  echo "       apt install $tool   # or your distro equivalent" >&2 ;;
        esac
        exit 1
    fi
done

# CMake auto-detects the C++ compiler — clang++ on macOS (Xcode CLT),
# g++ on Linux. Just check at least one is present.
if ! command -v c++ >/dev/null 2>&1 \
   && ! command -v clang++ >/dev/null 2>&1 \
   && ! command -v g++ >/dev/null 2>&1; then
    echo "ERROR: no C++ compiler (c++, clang++, or g++) in PATH" >&2
    case "$OS" in
        Darwin*) echo "       xcode-select --install" >&2 ;;
        Linux*)  echo "       apt install build-essential" >&2 ;;
    esac
    exit 1
fi

# ─── Determine if sudo is needed for PREFIX ──────────────────────────────
SUDO=""
# Probe writability: PREFIX may not exist yet; parent must be writable.
if [ -d "$PREFIX" ]; then
    [ ! -w "$PREFIX" ] && SUDO=sudo
else
    PARENT=$(dirname "$PREFIX")
    [ ! -w "$PARENT" ] && SUDO=sudo
fi
if [ -n "$SUDO" ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: $PREFIX not writable and sudo not available" >&2
        echo "       Either run as root, or set PREFIX to a writable location:" >&2
        echo "         PREFIX=\$HOME/.local ./scripts/install_hexl.sh" >&2
        exit 1
    fi
    echo "    (will sudo for install to $PREFIX)"
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ─── [1/2] google/cpu_features ───────────────────────────────────────────
echo
echo "==> [1/2] building google/cpu_features $CPU_FEATURES_TAG"
cd "$WORK"
git clone --depth 1 --branch "$CPU_FEATURES_TAG" "$CPU_FEATURES_REPO" cpu_features
cd cpu_features
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DBUILD_TESTING=OFF \
    -DCMAKE_INSTALL_PREFIX="$PREFIX"
cmake --build build --parallel
$SUDO cmake --install build

# ─── [2/2] Intel HEXL ────────────────────────────────────────────────────
echo
echo "==> [2/2] building intel/hexl $HEXL_TAG"
cd "$WORK"
git clone --depth 1 --branch "$HEXL_TAG" "$HEXL_REPO" hexl
cd hexl

# CMake flags must match flake.nix:51-65 exactly. Adding/removing one
# would silently produce a different libhexl.a → a different
# unified_server binary on this host vs the flake's.
cmake -B build \
    -DCMAKE_INSTALL_INCLUDEDIR=include \
    -DHEXL_BENCHMARK=OFF \
    -DHEXL_TESTING=OFF \
    -DHEXL_SHARED_LIB=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_PREFIX_PATH="$PREFIX"
cmake --build build --parallel
$SUDO cmake --install build

# ─── Verify ──────────────────────────────────────────────────────────────
echo
echo "==> verifying installation"
HEXL_CONFIG="$PREFIX/lib/cmake/hexl-1.2.6/HEXLConfig.cmake"
CF_CONFIG="$PREFIX/lib/cmake/CpuFeatures/CpuFeaturesConfig.cmake"
if [ ! -f "$HEXL_CONFIG" ]; then
    echo "ERROR: HEXLConfig.cmake not found at $HEXL_CONFIG after install" >&2
    exit 1
fi
if [ ! -f "$CF_CONFIG" ]; then
    echo "ERROR: CpuFeaturesConfig.cmake not found at $CF_CONFIG after install" >&2
    exit 1
fi
echo "    HEXL:         $HEXL_CONFIG"
echo "    cpu_features: $CF_CONFIG"
echo
echo "✓ HEXL 1.2.6 + cpu_features 0.10.1 installed to $PREFIX"
echo
echo "Next: ./scripts/build_unified_server.sh    # will now build HEXL-accelerated"
