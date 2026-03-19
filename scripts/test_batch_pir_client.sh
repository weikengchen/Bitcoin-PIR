#!/bin/bash
# Test the two-level Batch PIR client
#
# Queries a script hash through both servers and recovers UTXO data.
#
# Usage:
#   ./scripts/test_batch_pir_client.sh [script_hash_hex]
#
# If no hash is given, uses a default test address.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo "Building batch PIR client..."
cargo build --release -p batch_pir --bin client2

echo ""
echo "========================================"
echo "Two-Level Batch PIR Client Test"
echo "========================================"
echo ""

SERVER0="ws://127.0.0.1:8091"
SERVER1="ws://127.0.0.1:8092"

# Use argument or default whale address
HASH="${1:-20d920103ecb721638eb43f3e7a27c7b8ed3925b}"

echo "Server 0: $SERVER0"
echo "Server 1: $SERVER1"
echo "Hash:     $HASH"
echo ""

./target/release/client2 \
  --server0 "$SERVER0" \
  --server1 "$SERVER1" \
  --hash "$HASH"

echo ""
echo "========================================"
echo "Test completed!"
echo "========================================"
