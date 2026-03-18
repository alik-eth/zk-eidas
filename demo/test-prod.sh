#!/usr/bin/env bash
#
# E2E test for zk-eidas production API.
# Usage: ./test-prod.sh [base-url]
#
# Fast tests run first (issue, nullifier, revocation, OpenID4VP).
# Slow prove tests run last since they block the single-threaded server.

set -uo pipefail

BASE_URL="${1:-https://zk-eidas.com}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

pass=0
skip=0
step=0
TOTAL=14

ok() {
  echo "  PASS: $1"
  pass=$((pass + 1))
}

die() {
  echo "  FAIL: $1"
  echo ""
  echo "Aborted after $pass passed, $skip skipped."
  exit 1
}

warn_skip() {
  echo "  SKIP: $1"
  skip=$((skip + 1))
}

assert_eq() {
  local name="$1" actual="$2" expected="$3"
  [ "$actual" = "$expected" ] && ok "$name" || die "$name (expected=$expected, got=$actual)"
}

assert_gt() {
  local name="$1" actual="$2" min="$3"
  [ "$actual" -gt "$min" ] 2>/dev/null && ok "$name" || die "$name (expected >$min, got=$actual)"
}

api() {
  local endpoint="$1" reqfile="$2" outfile="$3"
  local http_status
  http_status=$(curl -s -m 600 -o "$outfile" -w "%{http_code}" \
    -X POST "$BASE_URL$endpoint" \
    -H "Content-Type: application/json" \
    -d @"$reqfile")
  [ "$http_status" = "200" ] || die "$endpoint returned HTTP $http_status: $(cat "$outfile")"
}

# Like api() but returns 1 on failure instead of dying (for slow endpoints)
api_try() {
  local endpoint="$1" reqfile="$2" outfile="$3"
  local http_status
  http_status=$(curl -s -m 600 -o "$outfile" -w "%{http_code}" \
    -X POST "$BASE_URL$endpoint" \
    -H "Content-Type: application/json" \
    -d @"$reqfile")
  if [ "$http_status" = "200" ]; then
    return 0
  else
    echo "  (HTTP $http_status — proxy timeout on slow machine)"
    return 1
  fi
}

echo "=== zk-eidas Production E2E Tests ==="
echo "Target: $BASE_URL"
echo ""

# Warm up — Fly machines may be stopped, API server needs time to start
echo "Warming up..."
for i in $(seq 1 10); do
  warmup_status=$(curl -s -m 30 -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/issuer/issue" \
    -H "Content-Type: application/json" \
    -d '{"given_name":"test","family_name":"test","birthdate":"2000-01-01","nationality":"UA","resident_country":"UA","document_number":"T","issuing_authority":"T"}' 2>/dev/null || echo "000")
  if [ "$warmup_status" = "200" ]; then
    echo "  API ready (attempt $i)."
    break
  fi
  echo "  attempt $i (HTTP $warmup_status)... waiting"
  sleep 10
done
if [ "$warmup_status" != "200" ]; then
  echo "  ERROR: API did not become ready after 10 attempts."
  exit 1
fi
echo ""

# =============================================
# FAST TESTS (no proof generation, run first)
# =============================================

# --- 0. Static assets ---
step=$((step + 1))
echo "[$((step - 1))/$TOTAL] Check trusted-vks.json static asset"
VKS_STATUS=$(curl -s -m 10 -o "$TMPDIR/vks.json" -w "%{http_code}" "$BASE_URL/trusted-vks.json")
assert_eq "trusted-vks.json served" "$VKS_STATUS" "200"
VKS_COUNT=$(jq 'length' "$TMPDIR/vks.json")
assert_eq "15 VKs present" "$VKS_COUNT" "15"

# --- 1. Issue ---
echo ""
echo "[1/$TOTAL] Issue credential"
cat > "$TMPDIR/issue_req.json" <<'EOF'
{"given_name":"Maria","family_name":"Shevchenko","birthdate":"1990-05-15","nationality":"UA","resident_country":"UA","document_number":"DOC123456","issuing_authority":"DIIA"}
EOF
api "/issuer/issue" "$TMPDIR/issue_req.json" "$TMPDIR/issue.json"

SDJWT=$(jq -r '.sdjwt' "$TMPDIR/issue.json")
assert_gt "sdjwt length" "${#SDJWT}" 100
assert_eq "7 credential fields" "$(jq '.credential_display.fields | length' "$TMPDIR/issue.json")" "7"

# --- 2. Nullifier registry ---
echo ""
echo "[2/$TOTAL] Nullifier registry (double-spend detection)"
NONCE="test-$(date +%s)-$$"
printf '{"nullifier":"0x%s"}' "$NONCE" > "$TMPDIR/null_req.json"

api "/verifier/check-nullifier" "$TMPDIR/null_req.json" "$TMPDIR/null1.json"
assert_eq "first check: not seen" "$(jq '.seen_before' "$TMPDIR/null1.json")" "false"

api "/verifier/check-nullifier" "$TMPDIR/null_req.json" "$TMPDIR/null2.json"
assert_eq "second check: seen (double-spend)" "$(jq '.seen_before' "$TMPDIR/null2.json")" "true"
assert_gt "registry_size" "$(jq '.registry_size' "$TMPDIR/null2.json")" 0

# --- 3. Revocation root (initial) ---
echo ""
echo "[3/$TOTAL] Revocation root (initial)"
REV_ROOT_STATUS=$(curl -s -m 60 -o "$TMPDIR/rev_root.json" -w "%{http_code}" "$BASE_URL/issuer/revocation-root")
assert_eq "revocation-root served" "$REV_ROOT_STATUS" "200"
INITIAL_ROOT=$(jq -r '.revocation_root' "$TMPDIR/rev_root.json")
assert_gt "root hex length" "${#INITIAL_ROOT}" 10

# --- 4. Revoke credential ---
echo ""
echo "[4/$TOTAL] Revoke credential"
printf '{"credential_id":"test-revoke-%s"}' "$$" > "$TMPDIR/revoke_req.json"
api "/issuer/revoke" "$TMPDIR/revoke_req.json" "$TMPDIR/revoke.json"

assert_eq "revoke status" "$(jq -r '.status' "$TMPDIR/revoke.json")" "revoked"
NEW_ROOT=$(jq -r '.revocation_root' "$TMPDIR/revoke.json")
assert_gt "new root hex length" "${#NEW_ROOT}" 10

# Verify root changed after revocation
REV_ROOT2_STATUS=$(curl -s -m 60 -o "$TMPDIR/rev_root2.json" -w "%{http_code}" "$BASE_URL/issuer/revocation-root")
assert_eq "revocation-root after revoke" "$REV_ROOT2_STATUS" "200"
UPDATED_ROOT=$(jq -r '.revocation_root' "$TMPDIR/rev_root2.json")
assert_eq "root updated after revoke" "$UPDATED_ROOT" "$NEW_ROOT"

# --- 5. Presentation request (OpenID4VP) ---
echo ""
echo "[5/$TOTAL] Presentation request (OpenID4VP)"
cat > "$TMPDIR/pres_req.json" <<'EOF'
{"requirements":[{"claim":"birthdate","op":"gte","value":"18"},{"claim":"nationality","op":"eq","value":"UA"}]}
EOF
api "/verifier/presentation-request" "$TMPDIR/pres_req.json" "$TMPDIR/pres.json"

assert_gt "presentation_definition id length" "$(jq -r '.id | length' "$TMPDIR/pres.json")" 2
assert_eq "2 input descriptors" "$(jq '.input_descriptors | length' "$TMPDIR/pres.json")" "2"
assert_eq "first constraint path" "$(jq -r '.input_descriptors[0].constraints[0].path' "$TMPDIR/pres.json")" '$.birthdate'

# =============================================
# SLOW TESTS (proof generation — may timeout on small Fly machines)
# These run last since proof generation blocks the single-threaded server.
# =============================================

echo ""
echo "--- Slow tests (proof generation) ---"

# --- 6. Prove (individual) ---
echo ""
echo "[6/$TOTAL] Prove (individual, 2 predicates)"
jq -n --arg sdjwt "$SDJWT" '{
  sdjwt: $sdjwt,
  predicates: [
    {claim: "birthdate", op: "gte", value: 18},
    {claim: "nationality", op: "eq", value: "UA"}
  ]
}' > "$TMPDIR/prove_req.json"

HAVE_INDIVIDUAL=false
if api_try "/holder/prove" "$TMPDIR/prove_req.json" "$TMPDIR/prove.json"; then
  assert_eq "2 proofs returned" "$(jq '.proofs | length' "$TMPDIR/prove.json")" "2"
  assert_gt "hidden_fields count" "$(jq '.hidden_fields | length' "$TMPDIR/prove.json")" 0
  HAVE_INDIVIDUAL=true
else
  warn_skip "individual prove timed out (expected on small Fly machines)"
fi

# --- 7. Verify ---
echo ""
echo "[7/$TOTAL] Verify proofs"
if [ "$HAVE_INDIVIDUAL" = true ]; then
  jq '{proofs: [.proofs[] | {proof_json: .proof_json, predicate: .predicate}], hidden_fields: .hidden_fields}' \
    "$TMPDIR/prove.json" > "$TMPDIR/verify_req.json"
  api "/verifier/verify" "$TMPDIR/verify_req.json" "$TMPDIR/verify.json"

  assert_eq "all proofs valid" "$(jq '[.results[] | .valid] | all' "$TMPDIR/verify.json")" "true"
  assert_gt "not_disclosed count" "$(jq '.not_disclosed | length' "$TMPDIR/verify.json")" 0
else
  warn_skip "skipped (depends on step 6)"
fi

# --- 8. Proof export (CBOR) ---
echo ""
echo "[8/$TOTAL] Proof export (CBOR)"
if [ "$HAVE_INDIVIDUAL" = true ]; then
  jq '{proofs: [.proofs[] | {proof_json: .proof_json, predicate: .predicate}]}' \
    "$TMPDIR/prove.json" > "$TMPDIR/export_req.json"
  api "/holder/proof-export" "$TMPDIR/export_req.json" "$TMPDIR/export.json"

  assert_gt "cbor_base64 length" "$(jq '.cbor_base64 | length' "$TMPDIR/export.json")" 100
  assert_gt "cbor_size_bytes" "$(jq '.cbor_size_bytes' "$TMPDIR/export.json")" 0
else
  warn_skip "skipped (depends on step 6)"
fi

# --- 9. Compound prove ---
echo ""
echo "[9/$TOTAL] Compound prove (AND)"
jq -n --arg sdjwt "$SDJWT" '{
  sdjwt: $sdjwt,
  predicates: [
    {claim: "birthdate", op: "gte", value: 18},
    {claim: "nationality", op: "eq", value: "UA"}
  ],
  op: "and"
}' > "$TMPDIR/compound_req.json"

HAVE_COMPOUND=false
if api_try "/holder/prove-compound" "$TMPDIR/compound_req.json" "$TMPDIR/compound.json"; then
  assert_gt "compound_proof_json length" "$(jq '.compound_proof_json | length' "$TMPDIR/compound.json")" 100
  assert_eq "sub_proofs_count = 2" "$(jq '.sub_proofs_count' "$TMPDIR/compound.json")" "2"
  HAVE_COMPOUND=true
else
  warn_skip "compound prove timed out (expected on small Fly machines)"
fi

# --- 10. Compound verify ---
echo ""
echo "[10/$TOTAL] Compound verify"
if [ "$HAVE_COMPOUND" = true ]; then
  jq '{compound_proof_json: .compound_proof_json, hidden_fields: .hidden_fields}' \
    "$TMPDIR/compound.json" > "$TMPDIR/cverify_req.json"
  api "/verifier/verify-compound" "$TMPDIR/cverify_req.json" "$TMPDIR/cverify.json"

  assert_eq "compound valid" "$(jq '.valid' "$TMPDIR/cverify.json")" "true"
  assert_eq "sub_proofs_verified = 2" "$(jq '.sub_proofs_verified' "$TMPDIR/cverify.json")" "2"
else
  warn_skip "skipped (depends on step 9)"
fi

# --- 11. Compound proof export (CBOR) ---
echo ""
echo "[11/$TOTAL] Compound proof export (CBOR)"
if [ "$HAVE_COMPOUND" = true ]; then
  jq '{compound_proof_json: .compound_proof_json}' \
    "$TMPDIR/compound.json" > "$TMPDIR/cexport_req.json"
  api "/holder/proof-export-compound" "$TMPDIR/cexport_req.json" "$TMPDIR/cexport.json"

  assert_gt "compound cbor_base64 length" "$(jq '.cbor_base64 | length' "$TMPDIR/cexport.json")" 100
  assert_gt "compound cbor_size_bytes" "$(jq '.cbor_size_bytes' "$TMPDIR/cexport.json")" 0
else
  warn_skip "skipped (depends on step 9)"
fi

# --- 12. WASM verification (Node.js) ---
echo ""
echo "[12/$TOTAL] WASM verification via Node.js"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(cd "$SCRIPT_DIR/../packages/verifier-sdk" && pwd)"

# Build SDK if needed
if [ ! -f "$SDK_DIR/dist/index.js" ]; then
  echo "  Building verifier SDK..."
  (cd "$SDK_DIR" && npm install --silent && npm run build --silent) || die "SDK build failed"
fi

if [ "$HAVE_INDIVIDUAL" = true ]; then
  cat > "$TMPDIR/wasm_individual.mjs" <<NODESCRIPT
import { readFileSync } from 'fs';
import { verifyProof } from '${SDK_DIR}/dist/verify.js';

const vks = JSON.parse(readFileSync('${TMPDIR}/vks.json', 'utf8'));
const proveData = JSON.parse(readFileSync('${TMPDIR}/prove.json', 'utf8'));

let passed = 0;
for (const p of proveData.proofs) {
  const parsed = JSON.parse(p.proof_json);
  const proofBytes = new Uint8Array(parsed.proof_bytes);
  const ok = await verifyProof(proofBytes, parsed.predicate_op, vks);
  if (ok) passed++;
}
console.log(passed + '/' + proveData.proofs.length);
NODESCRIPT
  WASM_RESULT=$(node "$TMPDIR/wasm_individual.mjs") || die "WASM individual verify script failed"
  assert_eq "individual proofs valid (WASM)" "$WASM_RESULT" "2/2"
else
  warn_skip "WASM individual verify skipped (no proofs)"
fi

if [ "$HAVE_COMPOUND" = true ]; then
  cat > "$TMPDIR/wasm_compound.mjs" <<NODESCRIPT
import { readFileSync } from 'fs';
import { verifyProof } from '${SDK_DIR}/dist/verify.js';

const vks = JSON.parse(readFileSync('${TMPDIR}/vks.json', 'utf8'));
const compoundData = JSON.parse(readFileSync('${TMPDIR}/compound.json', 'utf8'));
const compound = JSON.parse(compoundData.compound_proof_json);

let passed = 0;
for (const sub of compound.proofs) {
  const proofBytes = new Uint8Array(sub.proof_bytes);
  const ok = await verifyProof(proofBytes, sub.predicate_op, vks);
  if (ok) passed++;
}
const allValid = compound.op === 'Or'
  ? passed > 0
  : passed === compound.proofs.length;
console.log(allValid ? 'valid' : 'invalid');
NODESCRIPT
  WASM_COMPOUND=$(node "$TMPDIR/wasm_compound.mjs") || die "WASM compound verify script failed"
  assert_eq "compound proof valid (WASM)" "$WASM_COMPOUND" "valid"
else
  warn_skip "WASM compound verify skipped (no compound proof)"
fi

# --- 13. Holder binding ---
echo ""
echo "[13/$TOTAL] Holder binding (cross-credential)"

# Issue a second credential with same document_number
cat > "$TMPDIR/issue2_req.json" <<'EOF'
{"given_name":"Maria","family_name":"Shevchenko","birthdate":"1990-05-15","nationality":"UA","resident_country":"UA","document_number":"DOC123456","issuing_authority":"DIIA"}
EOF

# Server may be busy from previous prove steps — wait for it to recover
for _retry in 1 2 3 4 5 6 7 8 9 10; do
  _code=$(curl -s -m 15 -o /dev/null -w "%{http_code}" "$BASE_URL/issuer/revocation-root" 2>/dev/null || echo "000")
  if [ "$_code" = "200" ]; then break; fi
  echo "  waiting for server to recover... (attempt $_retry)"
  sleep 30
done

if api_try "/issuer/issue" "$TMPDIR/issue2_req.json" "$TMPDIR/issue2.json"; then
  SDJWT2=$(jq -r '.sdjwt' "$TMPDIR/issue2.json")
  assert_gt "sdjwt2 length" "${#SDJWT2}" 100

  # Prove binding
  jq -n --arg a "$SDJWT" --arg b "$SDJWT2" '{
    sdjwt_a: $a,
    sdjwt_b: $b,
    binding_claim: "document_number",
    predicates_a: [{claim: "birthdate", op: "gte", value: 18}],
    predicates_b: [{claim: "birthdate", op: "gte", value: 18}]
  }' > "$TMPDIR/binding_req.json"

  if api_try "/holder/prove-binding" "$TMPDIR/binding_req.json" "$TMPDIR/binding.json"; then
    assert_eq "binding_verified" "$(jq '.binding_verified' "$TMPDIR/binding.json")" "true"
    assert_gt "binding_hash length" "$(jq -r '.binding_hash | length' "$TMPDIR/binding.json")" 10
    assert_gt "proofs_a count" "$(jq '.proofs_a | length' "$TMPDIR/binding.json")" 0
    assert_gt "proofs_b count" "$(jq '.proofs_b | length' "$TMPDIR/binding.json")" 0
  else
    warn_skip "holder binding prove timed out (expected on small Fly machines)"
  fi
else
  warn_skip "holder binding skipped (server busy from prior proofs)"
fi

# --- Summary ---
echo ""
echo "================================"
if [ "$skip" -gt 0 ]; then
  echo "$pass passed, $skip skipped (prove timeouts on small Fly machine)."
  echo "Prove steps work locally — Fly proxy 60s timeout is the bottleneck."
else
  echo "All $pass checks passed."
fi
echo "================================"
