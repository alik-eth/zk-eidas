#!/bin/bash
# Download large circuit artifacts not stored in git.
# Run from the circuits/ directory.

set -euo pipefail
cd "$(dirname "$0")"

ECDSA_ZKEY_URL="https://ruvpd2ka1g.ufs.sh/f/vsKUhXCDRm2gdJHCBAy98S2pwmsQRHlcezCxNXyWGkh4qFL1"
PTAU_URL="https://ruvpd2ka1g.ufs.sh/f/vsKUhXCDRm2gdYslgUy98S2pwmsQRHlcezCxNXyWGkh4qFL1"

mkdir -p build/ecdsa_verify

if [ ! -f "build/ecdsa_verify/ecdsa_verify.zkey" ]; then
  echo "Downloading ecdsa_verify.zkey (1.2 GB)..."
  curl -L -o build/ecdsa_verify/ecdsa_verify.zkey "$ECDSA_ZKEY_URL"
  echo "Done."
else
  echo "ecdsa_verify.zkey already exists, skipping."
fi

if [ ! -f "pot21.ptau" ]; then
  echo "Downloading pot21.ptau (2.3 GB)..."
  curl -L -o pot21.ptau "$PTAU_URL"
  echo "Done."
else
  echo "pot21.ptau already exists, skipping."
fi

echo "All artifacts ready."
