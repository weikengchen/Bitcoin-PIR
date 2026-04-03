#!/bin/bash
# Start PIR WebSocket servers for UTXO lookups
#
# This script starts two processes:
#   - Primary server on port 8091: DPF server 0 + OnionPIR + HarmonyPIR query server
#   - Secondary server on port 8092: DPF server 1 + HarmonyPIR hint server
#
# Usage:
#   ./scripts/start_pir_servers.sh [--data-dir /path/to/data]

set -e

# Default ports
PRIMARY_PORT=8091
SECONDARY_PORT=8092

# Default data directory
DATA_DIR="/Volumes/Bitcoin/data"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --data-dir|-d)
            DATA_DIR="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Build the unified server
echo "Building unified PIR server..."
cargo build --release -p runtime --bin unified_server

echo ""
echo "========================================"
echo "PIR WebSocket Server Startup"
echo "========================================"
echo ""
echo "Data directory: $DATA_DIR"
echo ""

# Kill any existing servers on these ports
echo "Checking for existing servers..."
pkill -f "unified_server.*--port $PRIMARY_PORT" 2>/dev/null || true
pkill -f "unified_server.*--port $SECONDARY_PORT" 2>/dev/null || true
pkill -f "server --port $PRIMARY_PORT" 2>/dev/null || true
pkill -f "server --port $SECONDARY_PORT" 2>/dev/null || true
sleep 1

# Start primary server (all protocols)
echo "Starting primary server on port $PRIMARY_PORT..."
./target/release/unified_server --port $PRIMARY_PORT --role primary --data-dir "$DATA_DIR" > /tmp/pir_primary.log 2>&1 &
PRIMARY_PID=$!
echo "Primary server PID: $PRIMARY_PID"

# Start secondary server (DPF only)
echo "Starting secondary server on port $SECONDARY_PORT..."
./target/release/unified_server --port $SECONDARY_PORT --role secondary --data-dir "$DATA_DIR" > /tmp/pir_secondary.log 2>&1 &
SECONDARY_PID=$!
echo "Secondary server PID: $SECONDARY_PID"

# Wait for servers to initialize
sleep 3

echo ""
echo "========================================"
echo "All servers started!"
echo "========================================"
echo ""
echo "Primary server (DPF-0 + OnionPIR + HarmonyPIR query):"
echo "  ws://localhost:$PRIMARY_PORT (PID: $PRIMARY_PID)"
echo ""
echo "Secondary server (DPF-1 + HarmonyPIR hint):"
echo "  ws://localhost:$SECONDARY_PORT (PID: $SECONDARY_PID)"
echo ""
echo "Logs:"
echo "  Primary:   /tmp/pir_primary.log"
echo "  Secondary: /tmp/pir_secondary.log"
echo ""
echo "To test:"
echo "  DPF:      ./target/release/client --server0 ws://localhost:$PRIMARY_PORT --server1 ws://localhost:$SECONDARY_PORT --hash <hex>"
echo "  OnionPIR: ./target/release/onionpir_client --server ws://localhost:$PRIMARY_PORT --hash <hex>"
echo "  Web:      http://localhost:3001 → connect to ws://localhost:$PRIMARY_PORT + ws://localhost:$SECONDARY_PORT"
echo ""
echo "Press Ctrl+C to stop all servers..."

# Trap Ctrl+C to kill all servers
trap "echo ''; echo 'Stopping servers...'; kill $PRIMARY_PID $SECONDARY_PID 2>/dev/null; exit 0" SIGINT SIGTERM

# Wait for servers
wait
