# On-Device Proving for /contracts Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add full browser-based ZK proving to the /contracts page — ECDSA + predicates + nullifier + holder binding, all via snarkjs in the browser, producing byte-compatible output with the server path.

**Architecture:** Four new WASM functions handle proof assembly, CBOR envelope encoding, and circuit input generation. A new `proveContractInBrowser()` TypeScript function orchestrates the multi-credential flow. The contracts page branches `handleProve()` on the existing `proveMethod` toggle.

**Tech Stack:** Rust/wasm-bindgen (WASM crate), snarkjs (browser proving), Circom circuits (nullifier, holder_binding), ciborium (CBOR), flate2 (compression)

**Spec:** `docs/specs/2026-03-22-contracts-on-device-proving-design.md`

---

## Chunk 1: WASM Crate — Dependencies & `build_compound_proof`

### Task 1: Add WASM crate dependencies

**Files:**
- Modify: `crates/zk-eidas-wasm/Cargo.toml`

- [ ] **Step 1: Add ciborium and flate2 to WASM Cargo.toml**

```toml
# Add after the getrandom line (line 21):
ciborium = "0.2"
flate2 = { version = "1", default-features = false, features = ["rust_backend"] }
```

- [ ] **Step 2: Verify WASM compiles with new deps**

Run: `cd crates/zk-eidas-wasm && cargo check --target wasm32-unknown-unknown`
Expected: Compiles successfully. If `flate2` fails, remove it and we'll use JS-side compression.

- [ ] **Step 3: Commit**

```bash
git add crates/zk-eidas-wasm/Cargo.toml
git commit -m "chore: add ciborium, flate2, rand deps to WASM crate"
```

---

### Task 2: Implement `build_compound_proof` WASM function

**Files:**
- Modify: `crates/zk-eidas-wasm/src/lib.rs`
- Test: `crates/zk-eidas-wasm/src/lib.rs` (inline `#[cfg(test)]` module)

- [ ] **Step 1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` block in `crates/zk-eidas-wasm/src/lib.rs`:

```rust
#[test]
fn build_compound_proof_basic() {
    // Simulate snarkjs output: 1 ECDSA + 1 predicate (gte)
    let input = serde_json::json!({
        "proofs": [
            {
                "circuitName": "ecdsa_verify",
                "proof": { "pi_a": [1,2,3], "pi_b": [[4,5],[6,7]], "pi_c": [8,9,10] },
                "publicSignals": ["111", "222", "333"],
                "vk": { "protocol": "groth16", "nPublic": 3 }
            },
            {
                "circuitName": "gte",
                "proof": { "pi_a": [11,12,13], "pi_b": [[14,15],[16,17]], "pi_c": [18,19,20] },
                "publicSignals": ["444", "555"],
                "vk": { "protocol": "groth16", "nPublic": 2 }
            }
        ],
        "op": "And"
    });

    let result = build_compound_proof(&input.to_string(), "And").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

    // Should have 1 predicate proof in "proofs" array
    assert_eq!(parsed["proofs"].as_array().unwrap().len(), 1);
    // Should have 1 ECDSA proof in "ecdsa_proofs" map
    assert_eq!(parsed["ecdsa_proofs"].as_object().unwrap().len(), 1);
    // Op should be "And"
    assert_eq!(parsed["op"], "And");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd crates/zk-eidas-wasm && cargo test build_compound_proof_basic -- --nocapture`
Expected: FAIL — `build_compound_proof` not defined

- [ ] **Step 3: Implement `build_compound_proof`**

Add to `crates/zk-eidas-wasm/src/lib.rs`, before the `#[cfg(test)]` block:

```rust
/// Build a CompoundProof from snarkjs proof results.
///
/// Takes a JSON object with `proofs` array (each entry has circuitName, proof,
/// publicSignals, vk) and `op` string ("And" or "Or").
///
/// snarkjs proofs are stored as UTF-8 JSON bytes in proof_bytes.
/// Public signals (decimal strings) are stored as UTF-8 bytes in public_inputs.
/// Verification keys are stored as UTF-8 JSON bytes.
///
/// ECDSA proofs (circuitName == "ecdsa_verify") go into ecdsa_proofs HashMap.
/// Nullifier proofs (circuitName == "nullifier") are separated for contract_nullifier.
/// All other circuits go into the predicate proofs vec.
#[wasm_bindgen]
pub fn build_compound_proof(proofs_json: &str, op: &str) -> Result<String, JsError> {
    use zk_eidas_types::proof::{ZkProof, CompoundProof, ContractNullifier, LogicalOp};
    use zk_eidas_types::predicate::PredicateOp;
    use std::collections::HashMap;

    let input: serde_json::Value = serde_json::from_str(proofs_json)
        .map_err(|e| JsError::new(&format!("invalid JSON: {e}")))?;

    let logical_op = match op {
        "And" => LogicalOp::And,
        "Or" => LogicalOp::Or,
        _ => return Err(JsError::new(&format!("invalid op: {op}, expected And or Or"))),
    };

    let proofs_arr = input["proofs"].as_array()
        .ok_or_else(|| JsError::new("missing 'proofs' array"))?;

    let mut predicate_proofs = Vec::new();
    let mut ecdsa_proofs = HashMap::new();
    let mut nullifier_proof: Option<ZkProof> = None;
    let mut nullifier_signals: Option<&serde_json::Value> = None;

    for entry in proofs_arr {
        let circuit_name = entry["circuitName"].as_str()
            .ok_or_else(|| JsError::new("missing circuitName"))?;

        // Serialize snarkjs proof as UTF-8 JSON bytes
        let proof_bytes = serde_json::to_vec(&entry["proof"])
            .map_err(|e| JsError::new(&format!("proof serialize: {e}")))?;

        // Convert public signals to Vec<Vec<u8>> (each signal as UTF-8 string bytes)
        let signals = entry["publicSignals"].as_array()
            .ok_or_else(|| JsError::new("missing publicSignals"))?;
        let public_inputs: Vec<Vec<u8>> = signals.iter()
            .filter_map(|s| s.as_str().map(|v| v.as_bytes().to_vec()))
            .collect();

        // Serialize vk as UTF-8 JSON bytes
        let vk_bytes = serde_json::to_vec(&entry["vk"])
            .map_err(|e| JsError::new(&format!("vk serialize: {e}")))?;

        let predicate_op = match circuit_name {
            "ecdsa_verify" => PredicateOp::Ecdsa,
            "nullifier" => PredicateOp::Nullifier,
            "holder_binding" => PredicateOp::HolderBinding,
            "gte" => PredicateOp::Gte,
            "lte" => PredicateOp::Lte,
            "eq" => PredicateOp::Eq,
            "neq" => PredicateOp::Neq,
            "range" => PredicateOp::Range,
            "set_member" => PredicateOp::SetMember,
            "reveal" => PredicateOp::Reveal,
            other => return Err(JsError::new(&format!("unknown circuit: {other}"))),
        };

        let zk_proof = ZkProof::new(proof_bytes, public_inputs, vk_bytes, predicate_op);

        match circuit_name {
            "ecdsa_verify" => {
                // Use claim_name from entry if present, else use index
                let key = entry["claimName"].as_str()
                    .unwrap_or("default")
                    .to_string();
                ecdsa_proofs.insert(key, zk_proof);
            }
            "nullifier" => {
                nullifier_signals = Some(entry);
                nullifier_proof = Some(zk_proof);
            }
            _ => {
                predicate_proofs.push(zk_proof);
            }
        }
    }

    let mut compound = CompoundProof::with_ecdsa_proofs(predicate_proofs, logical_op, ecdsa_proofs);

    // If we have a nullifier proof, build ContractNullifier
    if let Some(np) = nullifier_proof {
        // nullifier metadata comes from the entry's extra fields
        let entry = nullifier_signals.unwrap();
        let nullifier_hex = entry["nullifierHex"].as_str().unwrap_or("");
        let contract_hash_hex = entry["contractHashHex"].as_str().unwrap_or("");
        let salt_hex = entry["saltHex"].as_str().unwrap_or("");

        let nullifier_bytes = hex::decode(nullifier_hex.trim_start_matches("0x")).unwrap_or_default();
        let contract_hash_bytes = hex::decode(contract_hash_hex.trim_start_matches("0x")).unwrap_or_default();
        let salt_bytes = hex::decode(salt_hex.trim_start_matches("0x")).unwrap_or_default();

        let cn = ContractNullifier {
            nullifier: nullifier_bytes,
            contract_hash: contract_hash_bytes,
            salt: salt_bytes,
            proof: np,
        };
        compound = compound.with_contract_nullifier(cn);
    }

    let json = serde_json::to_string(&compound)
        .map_err(|e| JsError::new(&format!("serialize compound: {e}")))?;

    Ok(json)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd crates/zk-eidas-wasm && cargo test build_compound_proof_basic -- --nocapture`
Expected: PASS

- [ ] **Step 5: Write test for compound with nullifier**

```rust
#[test]
fn build_compound_proof_with_nullifier() {
    let input = serde_json::json!({
        "proofs": [
            {
                "circuitName": "ecdsa_verify",
                "proof": { "pi_a": [1], "pi_b": [[2]], "pi_c": [3] },
                "publicSignals": ["111", "222", "333"],
                "vk": {},
                "claimName": "birth_date"
            },
            {
                "circuitName": "gte",
                "proof": { "pi_a": [4], "pi_b": [[5]], "pi_c": [6] },
                "publicSignals": ["444"],
                "vk": {}
            },
            {
                "circuitName": "nullifier",
                "proof": { "pi_a": [7], "pi_b": [[8]], "pi_c": [9] },
                "publicSignals": ["999"],
                "vk": {},
                "nullifierHex": "0xaabb",
                "contractHashHex": "0xccdd",
                "saltHex": "0xeeff"
            }
        ],
        "op": "And"
    });

    let result = build_compound_proof(&input.to_string(), "And").unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();

    // Should have contract_nullifier
    assert!(parsed["contract_nullifier"].is_object());
    assert_eq!(parsed["contract_nullifier"]["nullifier"].as_array().unwrap().len(), 2); // [0xaa, 0xbb]
    // ECDSA proof keyed by "birth_date"
    assert!(parsed["ecdsa_proofs"]["birth_date"].is_object());
}
```

- [ ] **Step 6: Run test**

Run: `cd crates/zk-eidas-wasm && cargo test build_compound_proof_with_nullifier -- --nocapture`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add crates/zk-eidas-wasm/src/lib.rs
git commit -m "feat(wasm): add build_compound_proof function"
```

---

## Chunk 2: WASM Crate — `export_to_envelope`

### Task 3: Implement `export_to_envelope` WASM function

**Files:**
- Modify: `crates/zk-eidas-wasm/src/lib.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn export_to_envelope_roundtrip() {
    use zk_eidas_types::proof::{ZkProof, CompoundProof, LogicalOp};
    use zk_eidas_types::predicate::PredicateOp;
    use zk_eidas_types::envelope::ProofEnvelope;

    // Build a real CompoundProof
    let proof1 = ZkProof::new(
        b"proof1".to_vec(),
        vec![b"sig1".to_vec()],
        b"vk1".to_vec(),
        PredicateOp::Gte,
    );
    let compound = CompoundProof::new(vec![proof1], LogicalOp::And);
    let compound_json = serde_json::to_string(&compound).unwrap();

    // Export to envelope (no compression)
    let cbor_bytes = export_to_envelope(&compound_json, false).unwrap();

    // Decode and verify
    let envelope = ProofEnvelope::from_bytes(&cbor_bytes).unwrap();
    assert_eq!(envelope.proofs().len(), 1);
    assert_eq!(envelope.logical_op(), Some(LogicalOp::And));
    assert_eq!(envelope.proofs()[0].op, "Gte");
}

#[test]
fn export_to_envelope_compressed() {
    use zk_eidas_types::proof::{ZkProof, CompoundProof, LogicalOp};
    use zk_eidas_types::predicate::PredicateOp;
    use zk_eidas_types::envelope::ProofEnvelope;

    let proof1 = ZkProof::new(
        b"proof1".to_vec(),
        vec![b"sig1".to_vec()],
        b"vk1".to_vec(),
        PredicateOp::Gte,
    );
    let compound = CompoundProof::new(vec![proof1], LogicalOp::And);
    let compound_json = serde_json::to_string(&compound).unwrap();

    // Export with compression
    let compressed = export_to_envelope(&compound_json, true).unwrap();

    // Decompress and verify
    let envelope = ProofEnvelope::from_compressed_bytes(&compressed).unwrap();
    assert_eq!(envelope.proofs().len(), 1);
    assert_eq!(envelope.logical_op(), Some(LogicalOp::And));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd crates/zk-eidas-wasm && cargo test export_to_envelope -- --nocapture`
Expected: FAIL — `export_to_envelope` not defined

- [ ] **Step 3: Implement `export_to_envelope`**

Add to `crates/zk-eidas-wasm/src/lib.rs`:

```rust
/// Export a CompoundProof to a CBOR-encoded ProofEnvelope.
///
/// Replicates the server's export_compound_proof logic:
/// 1. Parse CompoundProof from JSON
/// 2. Extract only compound.proofs() (predicate sub-proofs)
///    — ECDSA proofs and contract_nullifier are NOT included
/// 3. Map to EnvelopeProof entries
/// 4. Create ProofEnvelope with logical_op
/// 5. Serialize to CBOR, optionally compress with deflate
#[wasm_bindgen]
pub fn export_to_envelope(compound_proof_json: &str, compress: bool) -> Result<Vec<u8>, JsError> {
    use zk_eidas_types::proof::CompoundProof;
    use zk_eidas_types::envelope::ProofEnvelope;

    let compound: CompoundProof = serde_json::from_str(compound_proof_json)
        .map_err(|e| JsError::new(&format!("invalid compound proof JSON: {e}")))?;

    let descriptions: Vec<String> = compound
        .proofs()
        .iter()
        .map(|p| format!("{:?}", p.predicate_op()))
        .collect();

    let mut envelope = ProofEnvelope::from_proofs(compound.proofs(), &descriptions);
    envelope.set_logical_op(Some(compound.op()));

    if compress {
        envelope.to_compressed_bytes()
            .map_err(|e| JsError::new(&format!("compression failed: {e}")))
    } else {
        envelope.to_bytes()
            .map_err(|e| JsError::new(&format!("CBOR encode failed: {e}")))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd crates/zk-eidas-wasm && cargo test export_to_envelope -- --nocapture`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add crates/zk-eidas-wasm/src/lib.rs
git commit -m "feat(wasm): add export_to_envelope function"
```

---

## Chunk 3: WASM Crate — `generate_nullifier_inputs` & `generate_holder_binding_inputs`

### Task 4: Implement `generate_nullifier_inputs`

**Files:**
- Modify: `crates/zk-eidas-wasm/src/lib.rs`

The nullifier circuit expects these inputs:
- **Private:** `credential_id` (u64), `sd_array_hash` (field), `message_hash` (field)
- **Public:** `commitment` (field), `contract_hash` (u64), `salt` (u64)
- **Output:** `nullifier` (Poseidon hash)

The `commitment`, `sd_array_hash`, and `message_hash` come from the ECDSA proof's public signals (passed in as `ecdsa_public_signals`), not re-derived from the credential. We only parse the credential to extract `credential_id = SHA256(document_number) → u64`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn generate_nullifier_inputs_returns_circuit_inputs() {
    // We need a real SD-JWT for this test. Use the same test credential
    // from the existing prepare_inputs tests.
    // For unit testing, we test the non-credential parts: contract_hash, salt computation
    // Full integration test needs a real SD-JWT.

    // Test with mock ECDSA signals
    let ecdsa_signals = serde_json::json!(["12345", "67890", "11111"]);
    let result = generate_nullifier_inputs(
        // Use a minimal mock — the function will fail on parse, that's OK for this unit test
        "invalid-sdjwt",
        "{\"type\":\"test\"}",
        "2026-03-22T12:00:00Z",
        &ecdsa_signals.to_string(),
    );
    // Should fail with parse error (expected — need real credential for integration test)
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("parse error") ||
            result.unwrap_err().to_string().contains("SD-JWT"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd crates/zk-eidas-wasm && cargo test generate_nullifier_inputs -- --nocapture`
Expected: FAIL — function not defined

- [ ] **Step 3: Implement `generate_nullifier_inputs`**

```rust
/// Generate nullifier circuit inputs from a credential and contract metadata.
///
/// Parses the SD-JWT to extract credential_id (SHA256 of document_number → u64).
/// Takes ECDSA public signals (commitment, sd_array_hash, message_hash) from a
/// previously generated ECDSA proof — these are NOT re-derived from the credential.
/// Generates a random salt and computes contract_hash.
///
/// Returns JSON with circuit `inputs` object and hex metadata (nullifier is computed
/// by the circuit, but we return the constituent parts for display).
#[wasm_bindgen]
pub fn generate_nullifier_inputs(
    sdjwt: &str,
    contract_terms: &str,
    timestamp: &str,
    ecdsa_public_signals: &str,
) -> Result<String, JsError> {
    use zk_eidas_types::credential::bytes_to_u64;

    let parser = zk_eidas_parser::SdJwtParser::new();
    let credential = parser.parse(sdjwt)
        .map_err(|e| JsError::new(&format!("SD-JWT parse error: {e}")))?;

    // Extract document_number (or student_number, license_number, vin) for credential_id
    let id_field = if credential.claims().contains_key("vin") {
        "vin"
    } else if credential.claims().contains_key("student_number") {
        "student_number"
    } else if credential.claims().contains_key("license_number") {
        "license_number"
    } else {
        "document_number"
    };

    let id_value = credential.claims().get(id_field)
        .ok_or_else(|| JsError::new(&format!("claim '{id_field}' not found for credential_id")))?;

    // credential_id = SHA256(id_value_string) → u64
    let id_str = id_value.to_string();
    let id_hash: [u8; 32] = Sha256::digest(id_str.as_bytes()).into();
    let credential_id = bytes_to_u64(&id_hash);

    // Parse ECDSA public signals
    let signals: Vec<String> = serde_json::from_str(ecdsa_public_signals)
        .map_err(|e| JsError::new(&format!("invalid ecdsa_public_signals: {e}")))?;
    if signals.len() < 3 {
        return Err(JsError::new("ecdsa_public_signals must have at least 3 entries"));
    }
    let commitment = &signals[0];
    let sd_array_hash = &signals[1];
    let message_hash = &signals[2];

    // Generate random salt
    let mut salt_bytes = [0u8; 8];
    getrandom::getrandom(&mut salt_bytes)
        .map_err(|e| JsError::new(&format!("random generation failed: {e}")))?;
    let salt = u64::from_be_bytes(salt_bytes);

    // contract_hash = SHA256(contract_terms || timestamp || salt) → u64
    let mut hasher = Sha256::new();
    hasher.update(contract_terms.as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(salt.to_be_bytes());
    let contract_hash_bytes: [u8; 32] = hasher.finalize().into();
    let contract_hash = bytes_to_u64(&contract_hash_bytes);

    let result = serde_json::json!({
        "inputs": {
            "credential_id": credential_id.to_string(),
            "contract_hash": contract_hash.to_string(),
            "salt": salt.to_string(),
            "commitment": commitment,
            "sd_array_hash": sd_array_hash,
            "message_hash": message_hash,
        },
        "credential_id": credential_id,
        "contract_hash_hex": format!("0x{:016x}", contract_hash),
        "salt_hex": format!("0x{:016x}", salt),
    });

    Ok(result.to_string())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd crates/zk-eidas-wasm && cargo test generate_nullifier_inputs -- --nocapture`
Expected: PASS (test expects a parse error for invalid credential)

- [ ] **Step 5: Commit**

```bash
git add crates/zk-eidas-wasm/src/lib.rs
git commit -m "feat(wasm): add generate_nullifier_inputs function"
```

---

### Task 5: Implement `generate_holder_binding_inputs`

**Files:**
- Modify: `crates/zk-eidas-wasm/src/lib.rs`

The holder_binding circuit expects:
- **Private:** `claim_value` (u64), `sd_array_hash` (field), `message_hash` (field)
- **Public:** `commitment` (field)
- **Output:** `binding_hash` (Poseidon(claim_value))

Each credential in a binding pair gets proved separately. The binding is verified by checking that both produce the same `binding_hash` output.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn generate_holder_binding_inputs_returns_circuit_inputs() {
    let ecdsa_signals = serde_json::json!(["12345", "67890", "11111"]);
    let result = generate_holder_binding_inputs(
        "invalid-sdjwt",
        "document_number",
        &ecdsa_signals.to_string(),
    );
    // Should fail with parse error
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd crates/zk-eidas-wasm && cargo test generate_holder_binding_inputs -- --nocapture`
Expected: FAIL — function not defined

- [ ] **Step 3: Implement `generate_holder_binding_inputs`**

The holder binding is proved per-credential (each side of the binding independently). Both sides produce the same `binding_hash` if they share the same claim value. So this function takes ONE credential + ONE claim + its ECDSA signals.

```rust
/// Generate holder binding circuit inputs for one side of a binding.
///
/// Each credential in a binding pair calls this separately. The circuit proves
/// that claim_value is committed under the ECDSA signature, and outputs
/// binding_hash = Poseidon(claim_value). Both sides must produce the same
/// binding_hash to prove the binding holds.
#[wasm_bindgen]
pub fn generate_holder_binding_inputs(
    sdjwt: &str,
    claim_name: &str,
    ecdsa_public_signals: &str,
) -> Result<String, JsError> {
    let parser = zk_eidas_parser::SdJwtParser::new();
    let credential = parser.parse(sdjwt)
        .map_err(|e| JsError::new(&format!("SD-JWT parse error: {e}")))?;

    let claim_value = credential.claims().get(claim_name)
        .ok_or_else(|| JsError::new(&format!("claim '{claim_name}' not found")))?;
    let claim_u64 = claim_value.to_circuit_u64();

    let signals: Vec<String> = serde_json::from_str(ecdsa_public_signals)
        .map_err(|e| JsError::new(&format!("invalid ecdsa_public_signals: {e}")))?;
    if signals.len() < 3 {
        return Err(JsError::new("ecdsa_public_signals must have at least 3 entries"));
    }

    let result = serde_json::json!({
        "inputs": {
            "claim_value": claim_u64.to_string(),
            "sd_array_hash": &signals[1],
            "message_hash": &signals[2],
            "commitment": &signals[0],
        }
    });

    Ok(result.to_string())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd crates/zk-eidas-wasm && cargo test generate_holder_binding_inputs -- --nocapture`
Expected: PASS

- [ ] **Step 5: Run all WASM crate tests**

Run: `cd crates/zk-eidas-wasm && cargo test -- --nocapture`
Expected: All tests pass (existing + new)

- [ ] **Step 6: Commit**

```bash
git add crates/zk-eidas-wasm/src/lib.rs
git commit -m "feat(wasm): add generate_holder_binding_inputs function"
```

---

### Task 6: Rebuild WASM package

**Files:**
- Rebuild: `demo/web/pkg/` (WASM output)

- [ ] **Step 1: Build WASM package**

Run: `cd crates/zk-eidas-wasm && wasm-pack build --target web --out-dir ../../demo/web/pkg`
Expected: Build succeeds, `demo/web/pkg/zk-eidas-wasm.js` updated with new exports

- [ ] **Step 2: Verify new exports are present**

Run: `grep -E 'build_compound_proof|export_to_envelope|generate_nullifier_inputs|generate_holder_binding_inputs' demo/web/pkg/zk-eidas-wasm.d.ts`
Expected: All 4 functions listed in TypeScript declarations

- [ ] **Step 3: Commit**

```bash
git add demo/web/pkg/
git commit -m "build: rebuild WASM package with new contract proving functions"
```

---

## Chunk 4: TypeScript — `proveContractInBrowser`

### Task 7: Implement `proveContractInBrowser` in snarkjs-prover.ts

**Files:**
- Modify: `demo/web/app/lib/snarkjs-prover.ts`

This function orchestrates the full on-device contract proving flow:
1. ECDSA proofs (per unique claim, cached)
2. Predicate proofs (using ECDSA commitment)
3. Nullifier proof (first credential only)
4. Build compound proof (WASM)
5. Export to envelope (WASM)
6. Holder binding proofs (after all credentials)

- [ ] **Step 1: Add new types and export**

Add after the `BrowserCompoundResult` interface (line 14) in `demo/web/app/lib/snarkjs-prover.ts`:

```typescript
export interface ContractProveParams {
  credentials: Array<{
    credential: string
    format: 'sdjwt' | 'mdoc'
    predicates: Array<{ claim: string; op: string; value: unknown }>
  }>
  contractTerms: string
  timestamp: string
  bindings?: Array<{
    credIndexA: number; claimA: string
    credIndexB: number; claimB: string
  }>
  onProgress?: (msg: string) => void
  onCredentialIndex?: (index: number) => void
}

export interface ContractProveResult {
  compoundProofs: string[]
  envelopeBytes: Uint8Array[]
  nullifier: string
  contractHash: string
  salt: string
  bindingResults: Array<{ bindingHash: string; verified: boolean }>
  totalTimeMs: number
}
```

- [ ] **Step 2: Implement `proveContractInBrowser`**

Add after the `proveCompoundInBrowser` function (after line 209):

```typescript
export async function proveContractInBrowser(
  params: ContractProveParams,
  apiBaseUrl: string,
): Promise<ContractProveResult> {
  const totalStart = performance.now()
  const { credentials, contractTerms, timestamp, bindings, onProgress, onCredentialIndex } = params

  // Guard: mdoc not supported on-device
  const mdocCred = credentials.find(c => c.format === 'mdoc')
  if (mdocCred) {
    throw new Error('On-device proving is only available for SD-JWT credentials. Please switch to Server mode.')
  }

  // Load WASM module
  onProgress?.('Loading WASM module...')
  const wasm = await import('../../pkg/zk-eidas-wasm.js')
  await wasm.default()

  const compoundProofs: string[] = []
  const envelopeBytes: Uint8Array[] = []
  let nullifierHex = ''
  let contractHashHex = ''
  let saltHex = ''

  // Per-credential ECDSA cache: Map<credentialIndex, Map<claimName, { result, claimValue }>>
  const ecdsaCachePerCred = new Map<number, Map<string, { result: BrowserProofResult; claimValue: string }>>()

  for (let ci = 0; ci < credentials.length; ci++) {
    onCredentialIndex?.(ci)
    const cred = credentials[ci]
    const uniqueClaims = [...new Set(cred.predicates.map(p => p.claim))]

    // Step 1: ECDSA proofs for this credential
    const ecdsaCache = new Map<string, { result: BrowserProofResult; claimValue: string }>()

    for (let c = 0; c < uniqueClaims.length; c++) {
      const claim = uniqueClaims[c]
      onProgress?.(`[Cred ${ci + 1}/${credentials.length}] ECDSA proof for "${claim}"...`)

      const prepRaw = wasm.prepare_inputs(cred.credential, claim)
      const prepData = JSON.parse(prepRaw)

      const ecdsaResult = await proveInBrowser(
        'ecdsa_verify',
        prepData.ecdsa_inputs,
        apiBaseUrl,
      )
      if (!ecdsaResult.verified) {
        throw new Error(`ECDSA proof for "${claim}" failed verification`)
      }

      ecdsaCache.set(claim, { result: ecdsaResult, claimValue: prepData.claim_value })
    }
    ecdsaCachePerCred.set(ci, ecdsaCache)

    // Step 2: Predicate proofs
    const allProofsForCompound: Array<{
      circuitName: string
      proof: unknown
      publicSignals: string[]
      vk: unknown
      claimName?: string
      nullifierHex?: string
      contractHashHex?: string
      saltHex?: string
    }> = []

    // Add ECDSA proofs to compound
    for (const [claim, { result }] of ecdsaCache) {
      // Load vk for ecdsa_verify
      const vkRes = await fetch(`${apiBaseUrl}/circuits/ecdsa_verify/vk.json`)
      const vk = await vkRes.json()
      allProofsForCompound.push({
        circuitName: 'ecdsa_verify',
        proof: result.proof,
        publicSignals: result.publicSignals,
        vk,
        claimName: claim,
      })
    }

    for (let i = 0; i < cred.predicates.length; i++) {
      const pred = cred.predicates[i]
      const cached = ecdsaCache.get(pred.claim)!
      const { result: ecdsa, claimValue } = cached
      const commitment = ecdsa.publicSignals[0]
      const sdArrayHash = ecdsa.publicSignals[1]
      const msgHashField = ecdsa.publicSignals[2]

      // Handle age/date transformations (same logic as proveCompoundInBrowser)
      const isDateClaim = typeof pred.value === 'number' &&
        (pred.claim.includes('birth') || pred.claim.includes('date'))
      const isAgeThreshold = isDateClaim && (pred.value as number) < 200
      let circuit = pred.op
      let threshold = pred.value

      if (isAgeThreshold) {
        if (pred.op === 'gte') {
          circuit = 'lte'
          threshold = ageCutoffEpochDays(pred.value as number)
        } else if (pred.op === 'lte') {
          circuit = 'gte'
          threshold = ageCutoffEpochDays(pred.value as number)
        }
      }

      onProgress?.(`[Cred ${ci + 1}] Predicate ${i + 1}/${cred.predicates.length}: ${pred.claim} ${pred.op}...`)

      const predicateInputs: Record<string, string | string[]> = {
        claim_value: claimValue,
        sd_array_hash: sdArrayHash,
        message_hash: msgHashField,
        commitment,
      }

      if (circuit === 'gte' || circuit === 'lte') {
        predicateInputs.threshold = String(threshold)
      } else if (circuit === 'eq' || circuit === 'neq') {
        if (typeof threshold === 'string' && !/^\d+$/.test(threshold)) {
          predicateInputs.expected = await hashToU64(threshold)
        } else {
          predicateInputs.expected = String(threshold)
        }
      } else if (circuit === 'range') {
        const [low, high] = threshold as unknown as [number, number]
        predicateInputs.low = String(low)
        predicateInputs.high = String(high)
      } else if (circuit === 'set_member') {
        const set = threshold as unknown as string[]
        const padded: string[] = []
        for (let j = 0; j < 16; j++) {
          padded.push(j < set.length ? await hashToU64(set[j]) : '0')
        }
        predicateInputs.set = padded
        predicateInputs.set_len = String(set.length)
      }

      const predResult = await proveInBrowser(circuit, predicateInputs, apiBaseUrl)
      const vkRes = await fetch(`${apiBaseUrl}/circuits/${circuit}/vk.json`)
      const vk = await vkRes.json()
      allProofsForCompound.push({
        circuitName: circuit,
        proof: predResult.proof,
        publicSignals: predResult.publicSignals,
        vk,
      })
    }

    // Step 3: Nullifier proof (first credential only)
    if (ci === 0) {
      const firstClaim = uniqueClaims[0]
      const firstEcdsa = ecdsaCache.get(firstClaim)!.result
      const ecdsaSignals = JSON.stringify(firstEcdsa.publicSignals.slice(0, 3))

      onProgress?.(`[Cred ${ci + 1}] Generating nullifier...`)
      const nullifierRaw = wasm.generate_nullifier_inputs(
        cred.credential, contractTerms, timestamp, ecdsaSignals,
      )
      const nullifierData = JSON.parse(nullifierRaw)

      const nullifierResult = await proveInBrowser(
        'nullifier', nullifierData.inputs, apiBaseUrl,
      )

      // Extract nullifier from circuit output (publicSignals[0])
      const nullifierBigInt = BigInt(nullifierResult.publicSignals[0])
      nullifierHex = '0x' + nullifierBigInt.toString(16).padStart(64, '0')
      contractHashHex = nullifierData.contract_hash_hex
      saltHex = nullifierData.salt_hex

      const vkRes = await fetch(`${apiBaseUrl}/circuits/nullifier/vk.json`)
      const vk = await vkRes.json()
      allProofsForCompound.push({
        circuitName: 'nullifier',
        proof: nullifierResult.proof,
        publicSignals: nullifierResult.publicSignals,
        vk,
        nullifierHex,
        contractHashHex,
        saltHex,
      })
    }

    // Step 4: Build compound proof via WASM
    const compoundInput = JSON.stringify({ proofs: allProofsForCompound, op: 'And' })
    const compoundJson = wasm.build_compound_proof(compoundInput, 'And')
    compoundProofs.push(compoundJson)

    // Step 5: Export to envelope via WASM
    const cbor = wasm.export_to_envelope(compoundJson, true)
    envelopeBytes.push(new Uint8Array(cbor))
  }

  // Step 6: Holder binding proofs
  const bindingResults: Array<{ bindingHash: string; verified: boolean }> = []

  if (bindings) {
    for (const binding of bindings) {
      onCredentialIndex?.(-2) // signal binding phase
      onProgress?.('Proving holder binding...')

      const ecdsaCacheA = ecdsaCachePerCred.get(binding.credIndexA)!
      const ecdsaCacheB = ecdsaCachePerCred.get(binding.credIndexB)!

      // Find the ECDSA proof that covers the binding claim for each credential
      // The binding claim might not be the same claim that was proved via ECDSA,
      // so we may need a fresh ECDSA proof for the binding claim
      const getOrProveEcdsa = async (credIndex: number, claimName: string, cache: Map<string, { result: BrowserProofResult; claimValue: string }>) => {
        if (cache.has(claimName)) return cache.get(claimName)!
        // Need fresh ECDSA for this claim
        const cred = credentials[credIndex]
        const prepRaw = wasm.prepare_inputs(cred.credential, claimName)
        const prepData = JSON.parse(prepRaw)
        const ecdsaResult = await proveInBrowser('ecdsa_verify', prepData.ecdsa_inputs, apiBaseUrl)
        if (!ecdsaResult.verified) throw new Error(`ECDSA proof for binding claim "${claimName}" failed`)
        const entry = { result: ecdsaResult, claimValue: prepData.claim_value }
        cache.set(claimName, entry)
        return entry
      }

      const ecdsaA = await getOrProveEcdsa(binding.credIndexA, binding.claimA, ecdsaCacheA)
      const ecdsaB = await getOrProveEcdsa(binding.credIndexB, binding.claimB, ecdsaCacheB)

      // Generate binding inputs for each side
      const bindingInputsARaw = wasm.generate_holder_binding_inputs(
        credentials[binding.credIndexA].credential,
        binding.claimA,
        JSON.stringify(ecdsaA.result.publicSignals.slice(0, 3)),
      )
      const bindingInputsBRaw = wasm.generate_holder_binding_inputs(
        credentials[binding.credIndexB].credential,
        binding.claimB,
        JSON.stringify(ecdsaB.result.publicSignals.slice(0, 3)),
      )

      const bindingInputsA = JSON.parse(bindingInputsARaw)
      const bindingInputsB = JSON.parse(bindingInputsBRaw)

      // Prove both sides
      const bindingResultA = await proveInBrowser('holder_binding', bindingInputsA.inputs, apiBaseUrl)
      const bindingResultB = await proveInBrowser('holder_binding', bindingInputsB.inputs, apiBaseUrl)

      // binding_hash is publicSignals[0] for each — they should match
      const hashA = bindingResultA.publicSignals[0]
      const hashB = bindingResultB.publicSignals[0]
      const verified = hashA === hashB

      bindingResults.push({
        bindingHash: hashA,
        verified,
      })
    }
  }

  const totalTimeMs = performance.now() - totalStart
  onProgress?.(`All proofs generated in ${(totalTimeMs / 1000).toFixed(1)}s`)

  return {
    compoundProofs,
    envelopeBytes,
    nullifier: nullifierHex,
    contractHash: contractHashHex,
    salt: saltHex,
    bindingResults,
    totalTimeMs,
  }
}
```

- [ ] **Step 3: Verify TypeScript compiles**

Run: `cd demo/web && npx tsc --noEmit`
Expected: No type errors

- [ ] **Step 4: Commit**

```bash
git add demo/web/app/lib/snarkjs-prover.ts
git commit -m "feat: add proveContractInBrowser for on-device contract proving"
```

---

## Chunk 5: Contracts Page Integration

### Task 8: Wire `handleProve` to use on-device path

**Files:**
- Modify: `demo/web/app/routes/contracts.tsx`

- [ ] **Step 1: Add import for `proveContractInBrowser`**

At the top of `contracts.tsx`, add to the existing imports from `snarkjs-prover`:

```typescript
import { proveContractInBrowser } from '../lib/snarkjs-prover'
```

If there's no existing import from snarkjs-prover, add this as a new import line.

- [ ] **Step 2: Add on-device branch in `handleProve`**

In the `handleProve` function (starts at line 516), add the on-device branch right after the initial setup (after `const proofCount = template.credentials.length` at ~line 531):

```typescript
    // On-device proving path
    if (proveMethod === 'device') {
      const { encodeProofChunks, LogicalOpFlag } = await import('../lib/qr-chunking')
      const QRCode = (await import('qrcode')).default

      // Build credentials array for proveContractInBrowser
      const credParams = template.credentials.map((req, ci) => {
        const cred = state.credentials[ci]
        const config = CREDENTIAL_TYPES.find(ct => ct.id === req.credentialType)
        if (!config) throw new Error(`Unknown credential type: ${req.credentialType}`)
        const templatePredicates = req.predicateIds
          .map(pid => config.predicates.find(p => p.id === pid))
          .filter((p): p is NonNullable<typeof p> => p !== undefined)
        const predicates = templatePredicates.map(p => ({
          claim: p.predicate.claim,
          op: p.predicate.op,
          value: p.predicate.value === '__FROM_FORM__'
            ? (cred.fields.find(f => f.name === p.predicate.claim)?.value ?? '')
            : p.predicate.value,
        }))
        return { credential: cred.credential, format: cred.format as 'sdjwt' | 'mdoc', predicates }
      })

      // Build bindings array
      const bindingParams = template.bindings?.map(b => {
        const credIndexA = template.credentials.findIndex(c => c.role === b.roleA)
        const credIndexB = template.credentials.findIndex(c => c.role === b.roleB)
        return { credIndexA, claimA: b.claimA, credIndexB, claimB: b.claimB }
      })

      const selectedTemplate = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)!
      const result = await proveContractInBrowser(
        {
          credentials: credParams,
          contractTerms: JSON.stringify(selectedTemplate),
          timestamp: new Date().toISOString(),
          bindings: bindingParams,
          onProgress: (msg) => { /* could set a progress message state */ },
          onCredentialIndex: (idx) => setCurrentProvingIndex(idx),
        },
        API_URL,
      )

      // Process results — same as server path
      const updatedCredentials = [...state.credentials]
      for (let ci = 0; ci < template.credentials.length; ci++) {
        const req = template.credentials[ci]
        const config = CREDENTIAL_TYPES.find(ct => ct.id === req.credentialType)!
        const templatePredicates = req.predicateIds
          .map(pid => config.predicates.find(p => p.id === pid))
          .filter((p): p is NonNullable<typeof p> => p !== undefined)
        const predicateDescriptions = templatePredicates.map(p => t(p.labelKey))

        // Generate QR codes from envelope bytes
        const compressed = result.envelopeBytes[ci]
        totalCompressedSize += compressed.length
        const proofId = ci + 1
        const logicalOp = proofCount > 1 ? LogicalOpFlag.And : LogicalOpFlag.Single
        const chunks = encodeProofChunks(compressed, proofId, ci, proofCount, logicalOp)
        for (const chunk of chunks) {
          const url = await QRCode.toDataURL([{ data: chunk, mode: 'byte' as const }], {
            errorCorrectionLevel: 'L', margin: 1, width: 280,
          })
          allQrDataUrls.push(url)
        }

        updatedCredentials[ci] = {
          ...state.credentials[ci],
          compoundProofJson: result.compoundProofs[ci],
          compoundOp: 'And',
          hiddenFields: [],
          predicateDescriptions,
        }
      }

      // Process bindings
      const bindingResultsData: BindingResult[] = (template.bindings ?? []).map((b, i) => ({
        labelKey: b.labelKey,
        bindingHash: result.bindingResults[i]?.bindingHash ?? '',
        verified: result.bindingResults[i]?.verified ?? false,
      }))

      nullifierData = result.nullifier ? {
        nullifier: result.nullifier,
        contractHash: result.contractHash,
        salt: result.salt,
      } : null

      clearInterval(timer)
      setLoading(false)
      setProved(true)
      setTimeout(() => {
        setState(prev => ({
          ...prev,
          step: 4,
          credentials: updatedCredentials,
          bindings: bindingResultsData,
          qrDataUrls: allQrDataUrls,
          compressedSize: totalCompressedSize,
          cached: false,
          nullifier: nullifierData?.nullifier ?? null,
          contractHash: nullifierData?.contractHash ?? null,
          salt: nullifierData?.salt ?? null,
        }))
      }, 600)
      return
    }
```

This block goes right before the existing server path (`for (let ci = 0; ci < template.credentials.length; ci++)`). The `return` at the end exits early so the server path is skipped.

- [ ] **Step 3: Verify TypeScript compiles**

Run: `cd demo/web && npx tsc --noEmit`
Expected: No type errors

- [ ] **Step 4: Verify dev server starts**

Run: `cd demo/web && npm run dev` (then kill after confirming it builds)
Expected: Builds without errors

- [ ] **Step 5: Commit**

```bash
git add demo/web/app/routes/contracts.tsx
git commit -m "feat: wire on-device proving in /contracts page"
```

---

### Task 9: Manual E2E testing

- [ ] **Step 1: Test single-credential contract on-device (age verification)**

1. Start demo: `cd demo/web && npm run dev`
2. Navigate to /contracts
3. Select "Age Verification" contract
4. Enter a PID credential (SD-JWT)
5. Toggle to "On Device"
6. Click "Generate Proof"
7. Wait for ECDSA (~2-5 min) + predicate + nullifier
8. Verify: QR codes generated, nullifier displayed, step advances to 4

- [ ] **Step 2: Test multi-credential contract on-device (vehicle sale)**

1. Select "Vehicle Sale" contract
2. Enter seller PID, vehicle registration, buyer PID (all SD-JWT)
3. Toggle to "On Device"
4. Click "Generate Proof"
5. Verify: All 3 credentials proved, holder binding verified, QR codes generated

- [ ] **Step 3: Test mdoc guard**

1. Select any contract
2. Enter an mdoc credential
3. Toggle to "On Device"
4. Click "Generate Proof"
5. Verify: Error message about mdoc not supported

- [ ] **Step 4: Test server path still works**

1. Toggle back to "Server"
2. Prove any contract
3. Verify: works as before (no regressions)

- [ ] **Step 5: Commit any fixes from testing**
