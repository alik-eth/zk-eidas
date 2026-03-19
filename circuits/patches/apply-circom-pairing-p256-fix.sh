#!/bin/bash
# Fix circom-pairing's curve.circom for P-256 curve compatibility with Circom 2.1+
#
# Problem: circom-pairing was written for BLS12-381 (a=0). For P-256, the curve
# parameter `a = -3 mod p` is a multi-limb array. Two templates need fixes:
#
# 1. PointOnCurve: use BigMultShortLong for proper multi-limb a*x multiplication,
#    and lift template params a,b to signals (required by Circom >= 2.1).
#
# 2. PointOnTangent: add a[i] for all k limbs (not just index 0),
#    and lift template param a to signal.
#
# 3. EllipticCurveDouble: use a[i] loop instead of scalar a assignment.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET="node_modules/circom-pairing/circuits/curve.circom"
PATCHED="$SCRIPT_DIR/curve.circom.patched"

if [ ! -f "$TARGET" ]; then
    echo "SKIP: $TARGET not found (run npm install first)"
    exit 0
fi

if [ ! -f "$PATCHED" ]; then
    echo "ERROR: $PATCHED not found"
    exit 1
fi

# Check if already patched
if grep -q "sig_a\[k\]" "$TARGET" 2>/dev/null; then
    echo "SKIP: curve.circom already patched"
    exit 0
fi

echo "Applying P-256 patch to $TARGET..."
cp "$PATCHED" "$TARGET"
echo "Done."
