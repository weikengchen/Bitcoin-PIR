#!/bin/bash
# Start Gen2 DPF-PIR WebSocket servers for UTXO lookups
#
# This script starts two WebSocket servers using the gen2 database:
#   - Server 1 on port 8093
#   - Server 2 on port 8094
#
# Usage:
#   ./scripts/start_pir_servers2.sh [--small]
#
# The --small flag uses the smaller database variant that excludes whale addresses.

set -e

# WebSocket Ports (different from gen1 to allow both to run simultaneously)
SERVER1_PORT=8091
SERVER2_PORT=8092

# Parse --small flag
SMALL_FLAG=""
for arg in "$@"; do
    if [ "$arg" = "--small" ]; then
        SMALL_FLAG="--small"
    fi
done

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Build the servers first
echo "Building Gen2 WebSocket servers..."
cargo build --release --bin server2

echo ""
echo "========================================"
echo "Gen2 DPF-PIR WebSocket Server Startup"
echo "========================================"
echo ""
echo "Databases configured in dpf_pir/src/server_config2.rs:"
echo "  - gen2_utxo_cuckoo_index (cuckoo hash)"
echo "  - gen2_utxo_chunks_data (direct index)"
if [ -n "$SMALL_FLAG" ]; then
    echo "  Mode: SMALL (whale addresses excluded)"
else
    echo "  Mode: FULL (all addresses included)"
fi
echo ""

# Kill any existing servers on these ports
echo "Checking for existing servers..."
pkill -f "server2 --port $SERVER1_PORT" 2>/dev/null || true
pkill -f "server2 --port $SERVER2_PORT" 2>/dev/null || true
sleep 1

# Start Server 1 in background
echo "Starting Gen2 WebSocket Server 1 on port $SERVER1_PORT..."
RUST_LOG=info ./target/release/server2 --port $SERVER1_PORT $SMALL_FLAG > /tmp/pir_server2_1.log 2>&1 &
SERVER1_PID=$!
echo "Server 1 PID: $SERVER1_PID"

# Start Server 2 in background
echo "Starting Gen2 WebSocket Server 2 on port $SERVER2_PORT..."
RUST_LOG=info ./target/release/server2 --port $SERVER2_PORT $SMALL_FLAG > /tmp/pir_server2_2.log 2>&1 &
SERVER2_PID=$!
echo "Server 2 PID: $SERVER2_PID"

# Wait for servers to initialize
sleep 2

echo ""
echo "========================================"
echo "All Gen2 servers started!"
echo "========================================"
echo ""
echo "WebSocket Servers:"
echo "  Server 1: ws://localhost:$SERVER1_PORT (PID: $SERVER1_PID)"
echo "  Server 2: ws://localhost:$SERVER2_PORT (PID: $SERVER2_PID)"
echo ""
echo "Logs:"
echo "  Server 1: /tmp/pir_server2_1.log"
echo "  Server 2: /tmp/pir_server2_2.log"
echo ""
echo "To test with CLI client:"
echo "  ./target/release/lookup_pir2 <script_hex>"
echo ""
echo "Press Ctrl+C to stop all servers..."

# Trap Ctrl+C to kill all servers
trap "echo ''; echo 'Stopping servers...'; kill $SERVER1_PID $SERVER2_PID 2>/dev/null; exit 0" SIGINT SIGTERM

# Wait for servers
wait
