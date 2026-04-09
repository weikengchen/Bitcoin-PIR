#!/bin/bash
# Build OnionPIR artifacts for an EXISTING delta UTXO database.
#
# Prerequisite: scripts/build_delta.sh has already been run for the same
# <start_height> <end_height>, producing the grouped delta at
# /Volumes/Bitcoin/data/intermediate/delta_grouped_<A>_<B>.bin and the
# DPF/HarmonyPIR delta dir at /Volumes/Bitcoin/data/deltas/<A>_<B>/.
#
# Pipeline:
#   1. delta_gen_1_onion           — pack delta into 3840B entries + 27B index
#   2. gen_2_onion   --data-dir …  — build NTT store, chunk cuckoo, DATA bin hashes
#   3. gen_3_onion   --data-dir …  — build K per-group index PIR databases,
#                                    consolidate them into onion_index_all.bin
#                                    (single-file layout consumed by the server
#                                    via load_db_from_bytes), and emit INDEX
#                                    bin hashes. The scratch onion_index_pir/
#                                    directory is removed after consolidation.
#   4. gen_4_build_merkle_onion
#        --data-dir …              — build per-bin Merkle trees (INDEX + DATA)
#
# Usage:
#   ./scripts/build_delta_onion.sh <start_height> <end_height>
#
# Example:
#   ./scripts/build_delta_onion.sh 940611 944000
#
# Output files (in /Volumes/Bitcoin/data/deltas/940611_944000/):
#   onion_packed_entries.bin
#   onion_index.bin
#   onion_shared_ntt.bin            — shared NTT store (chunk level)
#   onion_chunk_cuckoo.bin
#   onion_data_bin_hashes.bin
#   onion_index_all.bin             — consolidated per-group INDEX PIR databases
#                                     (32B master header + K × per_group_bytes)
#   onion_index_meta.bin
#   onion_index_bin_hashes.bin
#   merkle_onion_index_root.bin
#   merkle_onion_data_root.bin
#   merkle_onion_index_tree_top.bin
#   merkle_onion_data_tree_top.bin
#   merkle_onion_{index,data}_sib_L*.{ntt,cuckoo,packed}.bin

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <start_height> <end_height>" >&2
    echo "" >&2
    echo "Example: $0 940611 944000" >&2
    exit 1
fi

START_HEIGHT="$1"
END_HEIGHT="$2"

# Layout matches scripts/build_delta.sh.
DATA_DIR="/Volumes/Bitcoin/data"
INTERMEDIATE_DIR="$DATA_DIR/intermediate"
DELTA_OUT_DIR="$DATA_DIR/deltas/${START_HEIGHT}_${END_HEIGHT}"

DELTA_GROUPED_FILE="$INTERMEDIATE_DIR/delta_grouped_${START_HEIGHT}_${END_HEIGHT}.bin"

if [[ ! -f "$DELTA_GROUPED_FILE" ]]; then
    echo "ERROR: grouped delta file not found: $DELTA_GROUPED_FILE" >&2
    echo "Run scripts/build_delta.sh first." >&2
    exit 1
fi

if [[ ! -d "$DELTA_OUT_DIR" ]]; then
    echo "ERROR: delta output dir not found: $DELTA_OUT_DIR" >&2
    echo "Run scripts/build_delta.sh first (it creates the DPF/HarmonyPIR artifacts)." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo "========================================"
echo "Bitcoin PIR — OnionPIR Delta Build"
echo "========================================"
echo "Range:      $START_HEIGHT -> $END_HEIGHT"
echo "Input:      $DELTA_GROUPED_FILE"
echo "Output dir: $DELTA_OUT_DIR"
echo ""

# Build all binaries up front so timing reflects work, not compilation.
echo "[build] Compiling OnionPIR delta build binaries..."
cargo build --release -p build \
    --bin delta_gen_1_onion \
    --bin gen_2_onion \
    --bin gen_3_onion \
    --bin gen_4_build_merkle_onion
echo ""

# ── Step 1: pack delta into 3840B entries + 27B index ──────────────────────
echo "[1/4] delta_gen_1_onion — packing delta into OnionPIR 3840B entries..."
./target/release/delta_gen_1_onion "$START_HEIGHT" "$END_HEIGHT" \
    --data-dir "$DELTA_OUT_DIR"
echo ""

# ── Step 2: NTT store + chunk cuckoo + DATA bin hashes ─────────────────────
echo "[2/4] gen_2_onion — building NTT store + chunk cuckoo..."
./target/release/gen_2_onion --data-dir "$DELTA_OUT_DIR"
echo ""

# ── Step 3: per-group index PIR databases + INDEX bin hashes ───────────────
echo "[3/4] gen_3_onion — building index PIR databases..."
./target/release/gen_3_onion --data-dir "$DELTA_OUT_DIR"
echo ""

# ── Step 4: per-bin Merkle trees (INDEX + DATA sub-trees) ──────────────────
echo "[4/4] gen_4_build_merkle_onion — building per-bin Merkle trees..."
./target/release/gen_4_build_merkle_onion --data-dir "$DELTA_OUT_DIR"
echo ""

echo "========================================"
echo "Delta OnionPIR build complete."
echo "========================================"
echo "OnionPIR files in $DELTA_OUT_DIR:"
ls -lh "$DELTA_OUT_DIR" | grep -E 'onion_|merkle_onion_' || true
