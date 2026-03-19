#!/bin/bash
# Start two-level Batch PIR WebSocket servers
#
# This script starts two servers (one per DPF share):
#   - Server 0 on port 8091
#   - Server 1 on port 8092
#
# Usage:
#   ./scripts/start_batch_pir_servers.sh

set -e

SERVER0_PORT=8091
SERVER1_PORT=8092

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

echo "Building batch PIR server..."
cargo build --release -p batch_pir --bin server2

echo ""
echo "========================================"
echo "Two-Level Batch PIR Server Startup"
echo "========================================"
echo ""
echo "Data files:"
echo "  Index cuckoo:  /Volumes/Bitcoin/data/batch_pir_cuckoo.bin"
echo "  Index data:    /Volumes/Bitcoin/data/utxo_chunks_index_nodust.bin"
echo "  Chunk cuckoo:  /Volumes/Bitcoin/data/chunk_pir_cuckoo.bin"
echo "  Chunks data:   /Volumes/Bitcoin/data/utxo_chunks_nodust.bin"
echo ""

# Kill any existing servers on these ports
echo "Checking for existing servers..."
pkill -f "server2 --port $SERVER0_PORT" 2>/dev/null || true
pkill -f "server2 --port $SERVER1_PORT" 2>/dev/null || true
sleep 1

# Start Server 0 in background
echo "Starting Server 0 (share 0) on port $SERVER0_PORT..."
./target/release/server2 --port $SERVER0_PORT > /tmp/batch_pir_server0.log 2>&1 &
SERVER0_PID=$!
echo "  PID: $SERVER0_PID"

# Start Server 1 in background
echo "Starting Server 1 (share 1) on port $SERVER1_PORT..."
./target/release/server2 --port $SERVER1_PORT > /tmp/batch_pir_server1.log 2>&1 &
SERVER1_PID=$!
echo "  PID: $SERVER1_PID"

# Wait for servers to load data
echo ""
echo "Waiting for servers to load data (this may take a minute)..."
sleep 5

echo ""
echo "========================================"
echo "Both servers started!"
echo "========================================"
echo ""
echo "  Server 0: ws://localhost:$SERVER0_PORT (PID: $SERVER0_PID)"
echo "  Server 1: ws://localhost:$SERVER1_PORT (PID: $SERVER1_PID)"
echo ""
echo "Logs:"
echo "  Server 0: /tmp/batch_pir_server0.log"
echo "  Server 1: /tmp/batch_pir_server1.log"
echo ""
echo "To query:"
echo "  ./target/release/client2 --hash <40-char hex script hash>"
echo ""
echo "Press Ctrl+C to stop all servers..."

trap "echo ''; echo 'Stopping servers...'; kill $SERVER0_PID $SERVER1_PID 2>/dev/null; exit 0" SIGINT SIGTERM

wait
