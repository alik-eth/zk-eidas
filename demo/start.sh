#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Starting zk-eidas demo..."
echo ""

# Check prerequisites
command -v cargo >/dev/null 2>&1 || { echo "Error: cargo not found. Install Rust."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Error: npm not found. Install Node.js."; exit 1; }

# Kill stale processes on demo ports
for port in 3000 3001; do
    pid=$(lsof -ti:$port 2>/dev/null || true)
    if [ -n "$pid" ]; then
        echo "Killing stale process on port $port (PID $pid)..."
        kill $pid 2>/dev/null || true
        sleep 1
    fi
done

# Start frontend first (port 3000)
echo "Starting frontend on http://localhost:3000..."
cd "$SCRIPT_DIR/web"
npm run dev &
WEB_PID=$!

# Start API server (port 3001)
echo "Starting API server on http://localhost:3001..."
cd "$SCRIPT_DIR/api"
CIRCUITS_PATH="../../circuits/predicates" cargo run --release &
API_PID=$!

# Wait for API to be ready
echo "Waiting for API server..."
for i in $(seq 1 30); do
    if curl -s http://localhost:3001/issuer/issue -X POST -H "Content-Type: application/json" -d '{}' > /dev/null 2>&1; then
        echo "API server ready."
        break
    fi
    sleep 1
done

echo ""
echo "Demo running!"
echo "  Frontend: http://localhost:3000"
echo "  API:      http://localhost:3001"
echo ""
echo "Press Ctrl+C to stop."

trap "kill $API_PID $WEB_PID 2>/dev/null" EXIT
wait
