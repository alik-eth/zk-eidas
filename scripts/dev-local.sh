#!/bin/sh
set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="zk-eidas-demo"
CONTAINER="zk-eidas-dev"
PORT="${1:-8080}"

# Stop existing container if running
podman rm -f "$CONTAINER" 2>/dev/null || true

echo "==> Building image..."
podman build -t "$IMAGE" "$REPO_ROOT"

echo "==> Starting container on http://127.0.0.1:$PORT"
podman run --name "$CONTAINER" -p "$PORT:8080" --rm "$IMAGE"
