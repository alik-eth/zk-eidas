# On-Device Proving for /contracts Page

**Date:** 2026-03-22
**Status:** Approved

## Motivation

Showcase that contract proving can work entirely on the user's device — no server infrastructure required. Users prove credentials in the browser via snarkjs + WASM, producing the same output (compound proof + CBOR envelope + QR codes) as the server path. This demonstrates that the system doesn't require a large cluster; clients can prove offline if they want.

## Scope

- Add on-device proving to the `/contracts` page, including nullifier and holder binding circuits
- SD-JWT credentials only (mdoc deferred — WASM parser doesn't support mdoc yet)
- Reuse existing `ProveMethodToggle` UI (already rendered in contracts page)
- Same elapsed timer UX — no granular per-stage progress indicators

## Architecture

```
Browser (contracts.tsx)
  ├─ proveMethod === 'server' → existing /holder/contract-prove API (unchanged)
  └─ proveMethod === 'device' → proveContractInBrowser()
       ├─ For each credential:
       │   ├─ WASM: prepare_inputs(credential, claim) → ecdsa circuit inputs
       │   ├─ snarkjs: proveInBrowser('ecdsa_verify', inputs) → ECDSA proof (~2-5 min)
       │   │   └─ publicSignals[0]=commitment, [1]=sd_array_hash, [2]=message_hash
       │   ├─ snarkjs: proveInBrowser(predicateCircuit, inputs) → predicate proofs (<1s each)
       │   │   └─ uses commitment from ECDSA publicSignals[0]
       │   ├─ WASM: generate_nullifier_inputs(credential, contract_terms, timestamp,
       │   │        ecdsa_public_signals) → nullifier circuit inputs + metadata
       │   │   └─ only for first credential (ci === 0)
       │   ├─ snarkjs: proveInBrowser('nullifier', inputs) → nullifier proof (<1s)
       │   ├─ WASM: build_compound_proof(proofs_json, 'And') → compound proof JSON
       │   └─ WASM: export_to_envelope(compound_proof_json, true) → compressed CBOR bytes
       │       └─ decomposes CompoundProof → extracts sub-proofs → ProofEnvelope → CBOR
       ├─ For each holder binding (after all credentials proved):
       │   ├─ WASM: generate_holder_binding_inputs(credential_a, claim_a, credential_b,
       │   │        claim_b, ecdsa_signals_a, ecdsa_signals_b) → binding circuit inputs
       │   └─ snarkjs: proveInBrowser('holder_binding', inputs) → binding proof (<1s)
       └─ QR chunking (existing client-side logic) → QR codes
```

## Data Flow Detail

### snarkjs proof → ZkProof serialization

snarkjs `groth16.fullProve()` returns `{ proof: { pi_a, pi_b, pi_c, protocol }, publicSignals: string[] }`. These must be converted to the Rust `ZkProof` format:

- `proof_bytes`: The snarkjs proof JSON (`{ pi_a, pi_b, pi_c }`) serialized as UTF-8 JSON bytes. This matches the existing `/demo` on-device flow and is compatible with snarkjs verification.
- `public_inputs`: Each public signal string converted to a `Vec<u8>` (decimal string → BigInt → big-endian bytes).
- `verification_key`: Loaded from `/circuits/{name}/vk.json` and stored as UTF-8 JSON bytes.
- `predicate_op`: Derived from `circuitName` mapping (e.g., `"gte"` → `PredicateOp::Gte`).

### CompoundProof → ProofEnvelope conversion

The server's `/holder/proof-export-compound` endpoint decomposes a `CompoundProof` and creates a `ProofEnvelope`. The WASM `export_to_envelope` function replicates the exact same logic:

1. Parse `CompoundProof` from JSON
2. Extract only `compound.proofs()` — the **predicate sub-proofs**. ECDSA proofs (in the `ecdsa_proofs` HashMap) and the contract nullifier (separate field) are **not** included in the envelope. This matches the server behavior at `main.rs:1037`.
3. Map each predicate proof to `EnvelopeProof { predicate, op, proof_bytes, public_inputs }`
4. Construct `ProofEnvelope::from_proofs(proofs, descriptions)`
5. Set `envelope.set_logical_op(Some(compound.op()))` — required to match server output (`main.rs:1038`)
6. Serialize to CBOR via `envelope.to_bytes()`
7. Optionally compress with deflate

This produces byte-compatible output with the server path.

### ECDSA public signals threading

ECDSA proofs produce 3 critical public outputs that downstream circuits consume:
- `publicSignals[0]` → `commitment` (Poseidon hash of claim data)
- `publicSignals[1]` → `sd_array_hash`
- `publicSignals[2]` → `message_hash`

These must be passed to:
- **Predicate circuits**: `commitment` as input
- **Nullifier circuit**: all three (`commitment`, `sd_array_hash`, `message_hash`)
- **Holder binding circuit**: `commitment`, `sd_array_hash`, `message_hash` from both credentials

The orchestration in `proveContractInBrowser()` captures these from each ECDSA proof result and threads them to subsequent circuit calls.

### Nullifier: first credential only

On the server, the nullifier is generated only for the first credential (`ci === 0`). The on-device flow matches: `generate_nullifier_inputs` is called only for `ci === 0`. Other credentials get compound proofs without nullifiers.

### ECDSA cache: per-credential, not cross-credential

ECDSA proofs are cached per (credential, claim_name) pair. Different credentials (e.g., seller PID vs buyer PID) have different signatures and cannot share ECDSA proofs, even if they reference the same claim name. The cache only avoids re-proving when the same credential's claim is used by multiple predicates.

## Changes

### 1. WASM Crate (`crates/zk-eidas-wasm/src/lib.rs`)

Four new `#[wasm_bindgen]` functions:

#### `build_compound_proof(proofs_json: &str, op: &str) -> Result<String, JsError>`

Takes an array of snarkjs proof results and a logical operator. Each entry has `circuitName`, `proof` (snarkjs JSON), `publicSignals` (string array), and `vk` (verification key JSON). Constructs a `CompoundProof` by:

1. Serializing each snarkjs proof as UTF-8 JSON bytes → `proof_bytes`
2. Converting public signal strings to byte vectors → `public_inputs`
3. Serializing vk as UTF-8 JSON bytes → `verification_key`
4. Mapping `circuitName` to `PredicateOp` → `predicate_op`
5. Assembling `ZkProof` objects into `CompoundProof` (separating ECDSA, predicate, and nullifier proofs by circuit name)

Returns compound proof JSON — same format as server output.

Input JSON schema:
```json
{
  "proofs": [
    {
      "circuitName": "ecdsa_verify",
      "proof": { "pi_a": [...], "pi_b": [...], "pi_c": [...] },
      "publicSignals": ["..."],
      "vk": { ... }
    },
    {
      "circuitName": "gte",
      "proof": { ... },
      "publicSignals": ["..."],
      "vk": { ... }
    },
    {
      "circuitName": "nullifier",
      "proof": { ... },
      "publicSignals": ["..."],
      "vk": { ... }
    }
  ],
  "op": "And"
}
```

#### `export_to_envelope(compound_proof_json: &str, compress: bool) -> Result<Vec<u8>, JsError>`

Takes compound proof JSON and replicates the server's `export_compound_proof` logic:
1. Parse `CompoundProof` from JSON
2. Extract only `compound.proofs()` (predicate sub-proofs) — ECDSA proofs and nullifier are **not** included in the envelope
3. Map to `EnvelopeProof` entries with predicate descriptions
4. Create `ProofEnvelope::from_proofs(proofs, descriptions)`
5. Set `envelope.set_logical_op(Some(compound.op()))`
6. Serialize to CBOR via `envelope.to_bytes()`
7. If `compress` is true, apply deflate compression

Returns raw bytes. Note: Uses `flate2` for compression — must verify it compiles to `wasm32-unknown-unknown`. If not, skip compression in WASM and let JS handle it (e.g., via `pako`).

#### `generate_nullifier_inputs(credential: &str, contract_terms: &str, timestamp: &str, ecdsa_public_signals: &str) -> Result<String, JsError>`

Parses the SD-JWT credential and computes:
- `credential_id = SHA256(document_number as string) → u64` (big-endian first 8 bytes)
- `salt = random u64` (via `getrandom` with `js` feature for WASM compatibility)
- `contract_hash = SHA256(contract_terms || timestamp || salt) → u64`

Takes `ecdsa_public_signals` as a JSON array of 3 strings (commitment, sd_array_hash, message_hash) — these come from the ECDSA proof's public outputs, not re-derived from the credential.

Returns JSON with:
```json
{
  "inputs": {
    "credential_id": "12345",
    "contract_hash": "67890",
    "salt": "11111",
    "commitment": "...",
    "sd_array_hash": "...",
    "message_hash": "..."
  },
  "credential_id": 12345,
  "nullifier_hex": "0x...",
  "contract_hash_hex": "0x...",
  "salt_hex": "0x..."
}
```

#### `generate_holder_binding_inputs(credential_a: &str, claim_a: &str, credential_b: &str, claim_b: &str, ecdsa_signals_a: &str, ecdsa_signals_b: &str) -> Result<String, JsError>`

Parses both SD-JWT credentials, extracts claim values. Takes `ecdsa_signals_a` and `ecdsa_signals_b` as JSON arrays of 3 strings each (commitment, sd_array_hash, message_hash from each credential's ECDSA proof). Returns circuit inputs for `holder_binding` including both commitments and claim values.

### 2. snarkjs Prover (`demo/web/app/lib/snarkjs-prover.ts`)

New function `proveContractInBrowser()`:

```typescript
export async function proveContractInBrowser(params: {
  credentials: Array<{
    credential: string
    format: 'sdjwt' | 'mdoc'
    predicates: Array<{ claim: string; op: string; value: string | number }>
  }>
  contractTerms: string
  timestamp: string
  bindings?: Array<{
    credIndexA: number; claimA: string
    credIndexB: number; claimB: string
  }>
  onProgress?: (msg: string) => void
}): Promise<{
  compoundProofs: string[]        // per-credential compound proof JSON
  envelopeBytes: Uint8Array[]     // per-credential compressed CBOR
  nullifier: string               // hex (from first credential only)
  contractHash: string            // hex
  salt: string                    // hex
  bindingResults: Array<{         // one per binding
    bindingHash: string
    verified: boolean
  }>
  totalTimeMs: number
}>
```

Orchestration per credential:
1. For each unique claim in predicates: `prepare_inputs()` → `proveInBrowser('ecdsa_verify', ...)` → cache ECDSA result
2. For each predicate: `proveInBrowser(circuitName, { commitment: ecdsaSignals[0], ... })`
3. If `ci === 0`: `generate_nullifier_inputs(cred, terms, timestamp, ecdsaSignals)` → `proveInBrowser('nullifier', ...)`
4. Collect all proofs + vks → `build_compound_proof(proofsJson, 'And')`
5. `export_to_envelope(compoundJson, true)` → CBOR bytes

After all credentials: for each binding, `generate_holder_binding_inputs(...)` → `proveInBrowser('holder_binding', ...)`.

ECDSA cache is per (credential, claim_name) — not shared across different credentials.

### 3. Contracts Page (`demo/web/app/routes/contracts.tsx`)

Branch `handleProve()` on `proveMethod`:

- `proveMethod === 'server'`: existing flow (unchanged)
- `proveMethod === 'device'`:
  - Guard: if any credential is mdoc format, show error toast and abort
  - Build `credentials` array from `state.credentials` with their predicates
  - Build `bindings` array from `template.bindings` (map roles to credential indices)
  - Call `proveContractInBrowser({ credentials, contractTerms, timestamp, bindings, onProgress })`
  - For each returned `envelopeBytes[i]`: run QR chunking (same existing logic)
  - Set `nullifier`, `contractHash`, `salt` from returned metadata
  - Set per-credential `compoundProofJson`, `hiddenFields`, `predicateDescriptions`
  - Set `bindingResults` from returned binding data
  - Same `currentProvingIndex`, `elapsed` timer, `setProved(true)` flow

### 4. WASM Package Rebuild

After WASM crate changes:
1. `cd crates/zk-eidas-wasm && wasm-pack build --target web --out-dir ../../demo/web/pkg`
2. Verify `getrandom` has `js` feature enabled in `Cargo.toml` (needed for random salt in WASM)
3. Verify `flate2` compiles to wasm32 (or fall back to JS compression)

## Not Changing

- `ProveMethodToggle` component — already works, already rendered in contracts page
- `/demo` page — untouched, its on-device flow stays as-is
- Server endpoints — untouched, server proving path unchanged
- Circuit hosting — server already serves all circuits including nullifier and holder_binding
- Verify flow — on-device proofs produce identical format, existing verification works

## Constraints

- **SD-JWT only** for on-device mode. mdoc credentials require `MdocParser` in WASM which is not yet implemented. Show error if user tries on-device with mdoc.
- **ECDSA bottleneck** — still ~2-5 minutes per unique claim in browser. This is inherent to the 2M-constraint circuit.
- **Circuit downloads** — ECDSA .zkey is ~1.2GB, downloaded once and cached in IndexedDB. Predicate/nullifier/binding .zkey files are small (KB range).
- **No server calls** after circuit files are cached — fully offline capable.
- **`flate2` WASM compatibility** — if deflate compression doesn't compile to wasm32, fall back to JS-side compression via `pako` before QR chunking.
- **`getrandom` WASM compatibility** — needs `js` feature flag for random salt generation in browser.

## Testing

- Unit tests for new WASM functions (in `crates/zk-eidas-wasm`)
- Manual E2E: toggle to "On Device" on contracts page, prove single-credential contract (age verification), verify output matches server path
- Manual E2E: prove multi-credential contract (vehicle sale) with holder binding on-device
- Verify QR codes from on-device proofs scan and verify correctly
- Verify nullifier is only generated for the first credential
- Verify mdoc guard shows error toast when on-device is selected with mdoc credential
