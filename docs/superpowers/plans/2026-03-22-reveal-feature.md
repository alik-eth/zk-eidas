# Reveal Feature Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow users to selectively reveal actual credential field values with a ZK proof that the value came from a valid issuer-signed credential.

**Architecture:** Reveal reuses the existing `eq` circuit — the builder extracts the claim value and generates an `eq(value)` proof where `expected` is the value itself. A `Predicate::Reveal` / `PredicateOp::Reveal` variant provides clean API semantics. The proof envelope carries plaintext for string claims so scanners can read revealed values from QR codes.

**Tech Stack:** Rust (types/facade/verifier/prover crates), TypeScript/React (demo UI), Circom eq circuit (reused, not modified)

**Spec:** `docs/superpowers/specs/2026-03-22-reveal-feature-design.md`

---

## Chunk 1: Rust Backend (Types, Facade, Verifier, Prover)

### Task 1: Add `PredicateOp::Reveal` to types crate

**Files:**
- Modify: `crates/zk-eidas-types/src/predicate.rs:6-19` (enum)
- Modify: `crates/zk-eidas-types/src/predicate.rs:77-94` (serde roundtrip test)

- [ ] **Step 1: Add Reveal variant to PredicateOp**

In `crates/zk-eidas-types/src/predicate.rs`, add `Reveal` after `HolderBinding`:

```rust
pub enum PredicateOp {
    /// Stage 1: ECDSA signature verification
    Ecdsa,
    /// Stage 2 predicates (all implicitly signed via ECDSA commitment chain)
    Gte,
    Lte,
    Eq,
    Neq,
    Range,
    SetMember,
    /// Special circuits
    Nullifier,
    HolderBinding,
    /// Selective disclosure — reveals claim value using eq circuit
    Reveal,
}
```

- [ ] **Step 2: Update serde roundtrip test**

In the same file, add `PredicateOp::Reveal` to the `predicate_ops_roundtrip_serde` test array:

```rust
let ops = [
    PredicateOp::Ecdsa,
    PredicateOp::Gte,
    PredicateOp::Lte,
    PredicateOp::Eq,
    PredicateOp::Neq,
    PredicateOp::Range,
    PredicateOp::SetMember,
    PredicateOp::Nullifier,
    PredicateOp::HolderBinding,
    PredicateOp::Reveal,
];
```

- [ ] **Step 3: Run test**

Run: `cargo test -p zk-eidas-types predicate_ops_roundtrip_serde`
Expected: PASS

- [ ] **Step 4: Commit**

```
feat(types): add PredicateOp::Reveal variant
```

### Task 2: Add revealed value fields to ProofEnvelope

**Files:**
- Modify: `crates/zk-eidas-types/src/envelope.rs:16-25` (EnvelopeProof struct)
- Modify: `crates/zk-eidas-types/src/envelope.rs:29-46` (from_proofs constructor)

- [ ] **Step 1: Write failing test for envelope roundtrip with revealed values**

Add to `crates/zk-eidas-types/src/envelope.rs` tests module:

```rust
#[test]
fn roundtrip_cbor_with_revealed_value() {
    let proof = ZkProof::new(
        vec![1, 2, 3],
        vec![vec![4, 5]],
        vec![6, 7],
        PredicateOp::Reveal,
    );
    let reveals = vec![Some(("document_number".to_string(), "UA-1234567890".to_string()))];
    let envelope = ProofEnvelope::from_proofs_with_reveals(
        &[proof],
        &["reveal document_number".to_string()],
        &reveals,
    );
    let bytes = envelope.to_bytes().unwrap();
    let decoded = ProofEnvelope::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.proofs().len(), 1);
    assert_eq!(decoded.proofs()[0].revealed_claim.as_deref(), Some("document_number"));
    assert_eq!(decoded.proofs()[0].revealed_value.as_deref(), Some("UA-1234567890"));
}

#[test]
fn from_proofs_has_no_revealed_values() {
    let proof = ZkProof::new(vec![1], vec![], vec![5], PredicateOp::Gte);
    let envelope = ProofEnvelope::from_proofs(&[proof], &["age >= 18".to_string()]);
    assert!(envelope.proofs()[0].revealed_claim.is_none());
    assert!(envelope.proofs()[0].revealed_value.is_none());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zk-eidas-types roundtrip_cbor_with_revealed`
Expected: FAIL — `from_proofs_with_reveals` does not exist, `revealed_claim` field does not exist

- [ ] **Step 3: Add revealed fields to EnvelopeProof and new constructor**

In `crates/zk-eidas-types/src/envelope.rs`, update `EnvelopeProof`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeProof {
    /// Human-readable predicate description (e.g. "age >= 18").
    pub predicate: String,
    /// Raw proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Public inputs for verification.
    pub public_inputs: Vec<Vec<u8>>,
    /// Predicate operation name (e.g. "Gte", "Reveal").
    pub op: String,
    /// Claim name for revealed values (e.g. "document_number").
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revealed_claim: Option<String>,
    /// Plaintext value for revealed claims (e.g. "UA-1234567890").
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revealed_value: Option<String>,
}
```

Add new constructor to `ProofEnvelope`:

```rust
/// Create an envelope from ZkProofs with predicate descriptions and optional revealed values.
pub fn from_proofs_with_reveals(
    proofs: &[ZkProof],
    descriptions: &[String],
    reveals: &[Option<(String, String)>],
) -> Self {
    let entries = proofs
        .iter()
        .zip(descriptions.iter())
        .enumerate()
        .map(|(i, (proof, desc))| {
            let reveal = reveals.get(i).and_then(|r| r.as_ref());
            EnvelopeProof {
                predicate: desc.clone(),
                proof_bytes: proof.proof_bytes().to_vec(),
                public_inputs: proof.public_inputs().to_vec(),
                op: format!("{:?}", proof.predicate_op()),
                revealed_claim: reveal.map(|(c, _)| c.clone()),
                revealed_value: reveal.map(|(_, v)| v.clone()),
            }
        })
        .collect();

    Self {
        version: 1,
        proofs: entries,
        logical_op: None,
    }
}
```

Update existing `from_proofs` to populate the new fields as `None`:

```rust
pub fn from_proofs(proofs: &[ZkProof], descriptions: &[String]) -> Self {
    let entries = proofs
        .iter()
        .zip(descriptions.iter())
        .map(|(proof, desc)| EnvelopeProof {
            predicate: desc.clone(),
            proof_bytes: proof.proof_bytes().to_vec(),
            public_inputs: proof.public_inputs().to_vec(),
            op: format!("{:?}", proof.predicate_op()),
            revealed_claim: None,
            revealed_value: None,
        })
        .collect();

    Self {
        version: 1,
        proofs: entries,
        logical_op: None,
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p zk-eidas-types -- envelope`
Expected: ALL PASS (including existing roundtrip tests — backward compatible via `default`)

- [ ] **Step 5: Commit**

```
feat(types): add revealed_claim/revealed_value to EnvelopeProof
```

### Task 3: Map `Reveal` to `eq` circuit in CircuitLoader

**Files:**
- Modify: `crates/zk-eidas-prover/src/circuit.rs:70-80` (load match)
- Modify: `crates/zk-eidas-prover/src/circuit.rs:148-158` (circuit_name_mapping test)

- [ ] **Step 1: Add Reveal arm to CircuitLoader::load**

In `crates/zk-eidas-prover/src/circuit.rs`, update the match in `load()`:

```rust
let name = match op {
    PredicateOp::Ecdsa => "ecdsa_verify",
    PredicateOp::Gte => "gte",
    PredicateOp::Lte => "lte",
    PredicateOp::Eq | PredicateOp::Reveal => "eq",
    PredicateOp::Neq => "neq",
    PredicateOp::Range => "range",
    PredicateOp::SetMember => "set_member",
    PredicateOp::Nullifier => "nullifier",
    PredicateOp::HolderBinding => "holder_binding",
};
```

- [ ] **Step 2: Update circuit_name_mapping test**

Add to the `ops_and_names` array:

```rust
(PredicateOp::Reveal, "eq"),
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p zk-eidas-prover circuit_name_mapping`
Expected: PASS

- [ ] **Step 4: Commit**

```
feat(prover): map PredicateOp::Reveal to eq circuit
```

### Task 4: Map `Reveal` to `eq` in verifier registry

**Files:**
- Modify: `crates/zk-eidas-verifier/src/registry.rs:27-41` (supported_ops)
- Modify: `crates/zk-eidas-verifier/src/registry.rs:86-92` (RegistryVerifier::verify)
- Modify: `crates/zk-eidas-verifier/src/verifier.rs:42-46` (verify_with_op)

- [ ] **Step 1: Map Reveal to Eq VK in RegistryVerifier::verify**

In `crates/zk-eidas-verifier/src/registry.rs`, update `RegistryVerifier::verify()` to resolve Reveal as Eq:

```rust
pub fn verify(&self, proof: &ZkProof) -> Result<bool, VerifierError> {
    let op = match proof.predicate_op() {
        PredicateOp::Reveal => PredicateOp::Eq,
        other => other,
    };
    let vk_json = self.registry.get(op).ok_or_else(|| {
        VerifierError::CircuitLoadFailed(format!(
            "no trusted circuit for {:?}",
            proof.predicate_op()
        ))
    })?;
```

- [ ] **Step 2: Map Reveal to Eq in Verifier::verify_with_op**

In `crates/zk-eidas-verifier/src/verifier.rs`, update `verify_with_op()` to resolve Reveal:

```rust
pub fn verify_with_op(
    &self,
    proof: &ZkProof,
    op: PredicateOp,
) -> Result<bool, VerifierError> {
    let resolved_op = match op {
        PredicateOp::Reveal => PredicateOp::Eq,
        other => other,
    };
    // 1. Load circuit artifacts to find the vk.json path
    let artifacts = self
        .loader
        .load(resolved_op)
        .map_err(|e| VerifierError::CircuitLoadFailed(e.to_string()))?;
```

- [ ] **Step 3: Update supported_ops count test**

In `crates/zk-eidas-verifier/src/registry.rs`, the `supported_ops_lists_all_9` test does NOT need to include `Reveal` since Reveal reuses the Eq circuit and does not have its own VK. No change needed unless the test hardcodes the count — update the assertion comment if needed.

- [ ] **Step 4: Run tests**

Run: `cargo test -p zk-eidas-verifier`
Expected: PASS

- [ ] **Step 5: Commit**

```
feat(verifier): map PredicateOp::Reveal to Eq circuit for verification
```

### Task 5: Add `Predicate::Reveal` to facade builder

**Files:**
- Modify: `crates/zk-eidas/src/builder.rs:9-26` (Predicate enum)
- Modify: `crates/zk-eidas/src/builder.rs:441-448` (prove_single Eq arm — add Reveal arm after it)
- Modify: `crates/zk-eidas/src/builder.rs:484` (And/Or arm — update to include Reveal isn't nested)
- Modify: `crates/zk-eidas/src/lib.rs:27` (re-exports)

- [ ] **Step 1: Write failing test**

Add to `crates/zk-eidas/tests/error_paths.rs`:

```rust
#[test]
fn prove_reveal_with_missing_claim_returns_error() {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({"age": 25}),
        "test-issuer",
    );

    let result = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("nonexistent", Predicate::Reveal)
        .prove();

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ZkError::ClaimNotFound(ref name) if name == "nonexistent"),
        "expected ClaimNotFound for reveal on missing claim"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p zk-eidas prove_reveal_with_missing_claim`
Expected: FAIL — `Predicate::Reveal` does not exist

- [ ] **Step 3: Add Reveal variant to Predicate enum**

In `crates/zk-eidas/src/builder.rs`:

```rust
pub enum Predicate {
    /// Greater-than-or-equal comparison (for numeric/date claims).
    Gte(i64),
    /// Less-than-or-equal comparison (for numeric/date claims).
    Lte(i64),
    /// Equality check (for string/numeric/boolean/date claims).
    Eq(String),
    /// Not-equal check.
    Neq(String),
    /// Range check: low <= claim <= high (for numeric/date claims).
    Range(i64, i64),
    /// Set membership check (claim must match one of the given values).
    SetMember(Vec<String>),
    /// Logical AND over multiple sub-predicates.
    And(Vec<Predicate>),
    /// Logical OR over multiple sub-predicates.
    Or(Vec<Predicate>),
    /// Reveal the actual claim value (uses eq circuit internally).
    Reveal,
}
```

- [ ] **Step 4: Add Reveal match arm in prove_single**

In `prove_single()`, add the Reveal arm right after the Eq arm (after line 448):

```rust
Predicate::Reveal => {
    let claim_u64 = claim_value.to_circuit_u64();
    let mut proof = prover
        .prove_eq(claim_u64, claim_u64, &commitment, &sd_array_hash, &message_hash)
        .map_err(ZkError::from)?;
    proof.set_predicate_op(PredicateOp::Reveal);
    Ok(proof)
}
```

Note: `prove_eq(claim_u64, claim_u64, ...)` — the expected value IS the claim value itself. We then override the predicate_op from Eq to Reveal.

- [ ] **Step 5: Add `set_predicate_op` method to ZkProof if it doesn't exist**

Check if `ZkProof` has a `set_predicate_op` setter. If not, add to `crates/zk-eidas-types/src/proof.rs`:

```rust
/// Override the predicate operation (used by Reveal to tag eq proofs).
pub fn set_predicate_op(&mut self, op: PredicateOp) {
    self.predicate_op = op;
}
```

- [ ] **Step 6: Update re-exports in lib.rs**

In `crates/zk-eidas/src/lib.rs`, ensure `Predicate` is already re-exported (it is at line 27). No change needed since `Reveal` is just a new variant on the existing enum.

- [ ] **Step 7: Run test**

Run: `cargo test -p zk-eidas prove_reveal_with_missing_claim`
Expected: PASS

- [ ] **Step 8: Commit**

```
feat(facade): add Predicate::Reveal — selective disclosure via eq circuit
```

### Task 6: Add `claim_value_plaintext` helper to ClaimValue

**Files:**
- Modify: `crates/zk-eidas-types/src/credential.rs` (add method to ClaimValue)

This method returns the human-readable plaintext for a claim value, used in the envelope's `revealed_value` field.

- [ ] **Step 1: Write failing test**

Add to `crates/zk-eidas-types/src/credential.rs` tests:

```rust
#[test]
fn claim_value_to_plaintext() {
    assert_eq!(ClaimValue::Integer(42).to_plaintext(), "42");
    assert_eq!(ClaimValue::Boolean(true).to_plaintext(), "true");
    assert_eq!(ClaimValue::String("hello".into()).to_plaintext(), "hello");
    let date = ClaimValue::Date { year: 1998, month: 5, day: 14 };
    assert_eq!(date.to_plaintext(), "1998-05-14");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p zk-eidas-types claim_value_to_plaintext`
Expected: FAIL — `to_plaintext` does not exist

- [ ] **Step 3: Implement to_plaintext**

Add to the `impl ClaimValue` block:

```rust
/// Return the human-readable plaintext representation of this claim value.
pub fn to_plaintext(&self) -> String {
    match self {
        ClaimValue::Integer(n) => n.to_string(),
        ClaimValue::Boolean(b) => b.to_string(),
        ClaimValue::String(s) => s.clone(),
        ClaimValue::Date { year, month, day } => {
            format!("{:04}-{:02}-{:02}", year, month, day)
        }
    }
}
```

- [ ] **Step 4: Run test**

Run: `cargo test -p zk-eidas-types claim_value_to_plaintext`
Expected: PASS

- [ ] **Step 5: Commit**

```
feat(types): add ClaimValue::to_plaintext() for reveal display
```

---

## Chunk 2: Demo API

### Task 7: Add `"reveal"` to parse_predicate and both prove handlers

**Files:**
- Modify: `demo/api/src/main.rs:290-356` (parse_predicate)
- Modify: `demo/api/src/main.rs:358-485` (generate_proof — individual prove)
- Modify: `demo/api/src/main.rs:584-698` (generate_compound_proof — compound prove)

- [ ] **Step 1: Add reveal case to parse_predicate**

In `demo/api/src/main.rs`, add before the `other =>` fallthrough in `parse_predicate()`:

```rust
"reveal" => Ok(zk_eidas::Predicate::Reveal),
```

- [ ] **Step 2: Add `revealed_value` field to ProofResult**

Update the `ProofResult` struct:

```rust
#[derive(Serialize, Clone)]
struct ProofResult {
    predicate: String,
    proof_json: String,
    proof_hex: String,
    op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    revealed_value: Option<String>,
}
```

- [ ] **Step 3: Track revealed values in generate_proof handler (individual path)**

In `generate_proof()`, track which claims are reveals. The description-building match block (around line 385-416) needs a `"reveal"` arm:

```rust
"reveal" => format!("reveal {}", pred_req.claim),
```

Inside the `spawn_blocking` closure, after `prove_all()`, extract revealed values:

```rust
let mut revealed_values: Vec<Option<String>> = Vec::new();
for pred_req in &req_predicates {
    if pred_req.op == "reveal" {
        let cv = credential.claims().get(&pred_req.claim);
        revealed_values.push(cv.map(|v| v.to_plaintext()));
    } else {
        revealed_values.push(None);
    }
}
```

Then in the ProofResult construction (around line 460):

```rust
let proofs: Vec<ProofResult> = zk_proofs
    .iter()
    .zip(proof_descriptions.iter())
    .enumerate()
    .map(|(i, (proof, desc))| {
        let op = format!("{:?}", proof.predicate_op());
        ProofResult {
            predicate: desc.clone(),
            proof_json: serde_json::to_string(proof).unwrap(),
            proof_hex: format!("0x{}", hex::encode(proof.proof_bytes())),
            op,
            revealed_value: revealed_values.get(i).cloned().flatten(),
        }
    })
    .collect();
```

- [ ] **Step 4: Compound proof path — no API response changes needed**

The compound prove handler (`generate_compound_proof`, line 584) groups predicates by claim name into `And`/`Or` wrappers. Reveal predicates always target a distinct claim (the UI presents reveal and predicates as separate choices per field), so they get their own claim group. The `CompoundProveResponse` does NOT need a `revealed_values` field because:

1. The compound proof JSON contains the sub-proofs tagged with `PredicateOp::Reveal`
2. The UI already knows which predicates are reveals (from `state.selectedPredicateIds` + credential config)
3. The UI has access to actual field values via `state.fields`

The data flow: UI knows which selections are reveals → reads values from `state.fields` → passes them to export endpoint. No round-trip through the API for revealed values.

However, the compound description-building code (line 1031-1035 in `export_compound_proof`) generates descriptions from `predicate_op()`, which will already produce `"Reveal"` for reveal proofs. This is correct.

- [ ] **Step 5: Run existing tests**

Run: `cargo test -p zk-eidas-demo-api`
Expected: PASS

- [ ] **Step 6: Commit**

```
feat(api): support reveal op in prove handler
```

### Task 8: Pass revealed values through proof-export endpoints

**Files:**
- Modify: `demo/api/src/main.rs:940-1010` (export_proof)
- Modify: `demo/api/src/main.rs:1014-1074` (export_compound_proof)

- [ ] **Step 1: Add revealed fields to ExportProofInput**

```rust
#[derive(Deserialize)]
struct ExportProofInput {
    proof_json: String,
    predicate: String,
    #[serde(default)]
    revealed_claim: Option<String>,
    #[serde(default)]
    revealed_value: Option<String>,
}
```

- [ ] **Step 2: Update export_proof to use from_proofs_with_reveals**

In `export_proof()`, build the reveals list and use the new constructor:

```rust
let mut reveals: Vec<Option<(String, String)>> = Vec::new();
for input in &req.proofs {
    if let (Some(claim), Some(value)) = (&input.revealed_claim, &input.revealed_value) {
        reveals.push(Some((claim.clone(), value.clone())));
    } else {
        reveals.push(None);
    }
}

let envelope = zk_eidas::ProofEnvelope::from_proofs_with_reveals(
    &zk_proofs, &descriptions, &reveals,
);
```

- [ ] **Step 3: Update export_compound_proof similarly**

For compound exports, the reveals need to be extracted from the compound proof's individual proofs. Since compound proofs don't currently carry revealed values, we need to accept them as a separate field in `CompoundExportRequest`:

```rust
#[derive(Deserialize)]
struct CompoundExportRequest {
    compound_proof_json: String,
    #[serde(default)]
    reveals: Vec<Option<RevealInfo>>,
}

#[derive(Deserialize)]
struct RevealInfo {
    claim: String,
    value: String,
}
```

Then convert to the reveals format and use `from_proofs_with_reveals`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p zk-eidas-demo-api`
Expected: PASS

- [ ] **Step 5: Commit**

```
feat(api): pass revealed values through proof-export endpoints into CBOR envelope
```

---

## Chunk 3: Demo UI — Credential Types and Holder Step

### Task 9: Add reveal entries to credential-types.ts

**Files:**
- Modify: `demo/web/app/lib/credential-types.ts`

- [ ] **Step 1: Add reveal predicates to PID**

After the existing predicates array for PID, add reveal entries:

```typescript
// PID predicates array — add these entries:
{ id: 'reveal_doc', labelKey: 'demo.revealDocNumber', descKey: 'demo.revealDocNumberDesc',
  predicate: { claim: 'document_number', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_given_name', labelKey: 'demo.revealGivenName', descKey: 'demo.revealGivenNameDesc',
  predicate: { claim: 'given_name', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_family_name', labelKey: 'demo.revealFamilyName', descKey: 'demo.revealFamilyNameDesc',
  predicate: { claim: 'family_name', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_nationality', labelKey: 'demo.revealNationality', descKey: 'demo.revealNationalityDesc',
  predicate: { claim: 'nationality', op: 'reveal', value: null },
  defaultChecked: false },
```

- [ ] **Step 2: Add reveal predicates to Driver's License**

```typescript
{ id: 'reveal_license', labelKey: 'demo.revealLicenseNumber', descKey: 'demo.revealLicenseNumberDesc',
  predicate: { claim: 'license_number', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_holder', labelKey: 'demo.revealHolderName', descKey: 'demo.revealHolderNameDesc',
  predicate: { claim: 'holder_name', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_category', labelKey: 'demo.revealCategory', descKey: 'demo.revealCategoryDesc',
  predicate: { claim: 'category', op: 'reveal', value: null },
  defaultChecked: false },
```

- [ ] **Step 3: Add reveal predicates to Diploma**

```typescript
{ id: 'reveal_diploma', labelKey: 'demo.revealDiplomaNumber', descKey: 'demo.revealDiplomaNumberDesc',
  predicate: { claim: 'diploma_number', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_student', labelKey: 'demo.revealStudentName', descKey: 'demo.revealStudentNameDesc',
  predicate: { claim: 'student_name', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_university', labelKey: 'demo.revealUniversity', descKey: 'demo.revealUniversityDesc',
  predicate: { claim: 'university', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_degree', labelKey: 'demo.revealDegree', descKey: 'demo.revealDegreeDesc',
  predicate: { claim: 'degree', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_field', labelKey: 'demo.revealFieldOfStudy', descKey: 'demo.revealFieldOfStudyDesc',
  predicate: { claim: 'field_of_study', op: 'reveal', value: null },
  defaultChecked: false },
```

- [ ] **Step 4: Add reveal predicates to Student ID**

```typescript
{ id: 'reveal_student_num', labelKey: 'demo.revealStudentNumber', descKey: 'demo.revealStudentNumberDesc',
  predicate: { claim: 'student_number', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_student_name', labelKey: 'demo.revealStudentName', descKey: 'demo.revealStudentNameDesc',
  predicate: { claim: 'student_name', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_uni', labelKey: 'demo.revealUniversity', descKey: 'demo.revealUniversityDesc',
  predicate: { claim: 'university', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_faculty', labelKey: 'demo.revealFaculty', descKey: 'demo.revealFacultyDesc',
  predicate: { claim: 'faculty', op: 'reveal', value: null },
  defaultChecked: false },
```

- [ ] **Step 5: Add reveal predicates to Vehicle**

```typescript
{ id: 'reveal_vin', labelKey: 'demo.revealVin', descKey: 'demo.revealVinDesc',
  predicate: { claim: 'vin', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_plate', labelKey: 'demo.revealPlateNumber', descKey: 'demo.revealPlateNumberDesc',
  predicate: { claim: 'plate_number', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_owner', labelKey: 'demo.revealOwnerName', descKey: 'demo.revealOwnerNameDesc',
  predicate: { claim: 'owner_name', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_owner_doc', labelKey: 'demo.revealOwnerDocNumber', descKey: 'demo.revealOwnerDocNumberDesc',
  predicate: { claim: 'owner_document_number', op: 'reveal', value: null },
  defaultChecked: false },
```

- [ ] **Step 6: Commit**

```
feat(ui): add reveal entries to all credential types
```

### Task 10: Add i18n keys for reveal entries

**Files:**
- Modify: `demo/web/app/i18n.tsx`

- [ ] **Step 1: Add English translation keys**

Find the English translations section and add keys for all reveal entries. Pattern: `demo.reveal<FieldName>` for labels, `demo.reveal<FieldName>Desc` for descriptions.

```typescript
// Reveal labels
'demo.revealDocNumber': 'Reveal document number',
'demo.revealDocNumberDesc': 'Disclose the actual document number with ZK proof of authenticity',
'demo.revealGivenName': 'Reveal given name',
'demo.revealGivenNameDesc': 'Disclose the given name with ZK proof of authenticity',
'demo.revealFamilyName': 'Reveal family name',
'demo.revealFamilyNameDesc': 'Disclose the family name with ZK proof of authenticity',
'demo.revealNationality': 'Reveal nationality',
'demo.revealNationalityDesc': 'Disclose the nationality with ZK proof of authenticity',
'demo.revealLicenseNumber': 'Reveal license number',
'demo.revealLicenseNumberDesc': 'Disclose the license number with ZK proof of authenticity',
'demo.revealHolderName': 'Reveal holder name',
'demo.revealHolderNameDesc': 'Disclose the holder name with ZK proof of authenticity',
'demo.revealCategory': 'Reveal license category',
'demo.revealCategoryDesc': 'Disclose the license category with ZK proof of authenticity',
'demo.revealDiplomaNumber': 'Reveal diploma number',
'demo.revealDiplomaNumberDesc': 'Disclose the diploma number with ZK proof of authenticity',
'demo.revealStudentName': 'Reveal student name',
'demo.revealStudentNameDesc': 'Disclose the student name with ZK proof of authenticity',
'demo.revealUniversity': 'Reveal university',
'demo.revealUniversityDesc': 'Disclose the university name with ZK proof of authenticity',
'demo.revealDegree': 'Reveal degree',
'demo.revealDegreeDesc': 'Disclose the degree with ZK proof of authenticity',
'demo.revealFieldOfStudy': 'Reveal field of study',
'demo.revealFieldOfStudyDesc': 'Disclose the field of study with ZK proof of authenticity',
'demo.revealStudentNumber': 'Reveal student number',
'demo.revealStudentNumberDesc': 'Disclose the student number with ZK proof of authenticity',
'demo.revealFaculty': 'Reveal faculty',
'demo.revealFacultyDesc': 'Disclose the faculty name with ZK proof of authenticity',
'demo.revealVin': 'Reveal VIN',
'demo.revealVinDesc': 'Disclose the vehicle identification number with ZK proof of authenticity',
'demo.revealPlateNumber': 'Reveal plate number',
'demo.revealPlateNumberDesc': 'Disclose the plate number with ZK proof of authenticity',
'demo.revealOwnerName': 'Reveal owner name',
'demo.revealOwnerNameDesc': 'Disclose the owner name with ZK proof of authenticity',
'demo.revealOwnerDocNumber': 'Reveal owner document number',
'demo.revealOwnerDocNumberDesc': 'Disclose the owner document number with ZK proof of authenticity',
```

- [ ] **Step 2: Add Ukrainian translation keys** (same pattern, translated)

- [ ] **Step 3: Commit**

```
feat(i18n): add reveal translation keys for all credential types
```

### Task 11: Style reveal checkboxes differently in Holder step

**Files:**
- Modify: `demo/web/app/routes/demo.tsx:472-486` (predicate checkbox rendering)

- [ ] **Step 1: Add visual distinction for reveal items**

In the `resolvedPredicates.map(opt => ...)` block (line 472), add a check for `opt.predicate.op === 'reveal'` to render with different styling:

```tsx
{resolvedPredicates.map(opt => {
  const isReveal = opt.predicate.op === 'reveal'
  return (
    <label key={opt.id} className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${
      selected[opt.id]
        ? isReveal ? 'border-emerald-500 bg-emerald-900/30' : 'border-blue-500 bg-slate-700/50'
        : 'border-slate-600 bg-slate-800 hover:border-slate-500'
    }`}>
      <input
        type="checkbox"
        checked={selected[opt.id]}
        onChange={e => setSelected(prev => ({ ...prev, [opt.id]: e.target.checked }))}
        disabled={loading}
        className={`mt-0.5 w-4 h-4 rounded border-slate-500 focus:ring-blue-500 bg-slate-700 ${
          isReveal ? 'text-emerald-600' : 'text-blue-600'
        }`}
      />
      <div className="flex items-center gap-1">
        {isReveal && <span className="text-emerald-400 text-xs mr-1">&#128065;</span>}
        <span className="text-sm font-medium text-white">{t(opt.labelKey)}</span>
        <Tooltip text={t(opt.descKey)} />
      </div>
    </label>
  )
})}
```

The eye emoji (`&#128065;` = 👁) and emerald color distinguish reveal from predicate checkboxes.

- [ ] **Step 2: Commit**

```
feat(ui): style reveal checkboxes with emerald color and eye icon
```

---

## Chunk 4: Print/PDF and QR Support

### Task 12: Update handlePrintProof to pass revealed values

**Files:**
- Modify: `demo/web/app/routes/demo.tsx:857-920` (handlePrintProof)
- Modify: `demo/web/app/routes/demo.tsx:25-31` (PrintPredicate interface)

- [ ] **Step 1: Add revealedValue to PrintPredicate**

```typescript
interface PrintPredicate {
  claim: string
  claimKey?: string
  op: string
  publicValue: string
  disclosed: boolean
  revealedValue?: string  // NEW: actual value for revealed fields
}
```

- [ ] **Step 2: Update handlePrintProof for compound path**

In the compound proof path (line 869-885), update the PrintPredicate construction to detect reveals:

```typescript
if (compound?.proofs && config) {
  const selectedPreds = config.predicates.filter(p => state.selectedPredicateIds.includes(p.id))
  for (let pi = 0; pi < compound.proofs.length; pi++) {
    const matched = selectedPreds[pi]
    if (matched) {
      const isReveal = matched.predicate.op === 'reveal'
      const fieldConfig = config.fields.find(f => f.name === matched.predicate.claim)
      const fieldValue = state.fields.find(f => f.name === matched.predicate.claim)?.value ?? ''
      predicates.push({
        claim: fieldConfig ? t(fieldConfig.labelKey) : matched.predicate.claim,
        claimKey: fieldConfig?.labelKey,
        op: isReveal ? '=' : opSymbol(matched.predicate.op),
        publicValue: isReveal ? fieldValue : resolveValue(matched.predicate),
        disclosed: isReveal,
        revealedValue: isReveal ? fieldValue : undefined,
      })
    }
  }
}
```

- [ ] **Step 3: Update handlePrintProof for individual path**

In the individual proof path (line 896-906), update similarly:

```typescript
proofs = await Promise.all(state.proofs.map(async (p) => {
  const isReveal = p.op === 'Reveal'
  const matchedPred = config?.predicates.find(pr =>
    state.selectedPredicateIds.includes(pr.id) && pr.predicate.claim === p.predicate.split(' ').pop()
  )
  const fieldValue = matchedPred
    ? state.fields.find(f => f.name === matchedPred.predicate.claim)?.value ?? ''
    : ''
  predicates.push({
    claim: p.predicate,
    op: isReveal ? '=' : p.op,
    publicValue: isReveal ? fieldValue : '',
    disclosed: isReveal,
    revealedValue: isReveal ? fieldValue : undefined,
  })
  // ... rest of export fetch
```

- [ ] **Step 4: Pass revealed values to export endpoints**

When calling `/holder/proof-export`, include `revealed_claim` and `revealed_value` in the request body for reveal proofs:

```typescript
body: JSON.stringify({
  proofs: [{
    proof_json: p.proof_json,
    predicate: p.predicate,
    ...(isReveal ? { revealed_claim: matchedPred?.predicate.claim, revealed_value: fieldValue } : {}),
  }]
})
```

For compound exports, add `reveals` to the body:

```typescript
body: JSON.stringify({
  compound_proof_json: state.compoundProofJson,
  reveals: selectedPreds.map(p =>
    p.predicate.op === 'reveal'
      ? { claim: p.predicate.claim, value: state.fields.find(f => f.name === p.predicate.claim)?.value ?? '' }
      : null
  ),
})
```

- [ ] **Step 5: Commit**

```
feat(ui): pass revealed values through print export flow
```

### Task 13: Update print.tsx to render revealed values

**Files:**
- Modify: `demo/web/app/routes/print.tsx:169-190` (predicates table)

- [ ] **Step 1: Update the predicates table**

The table already shows "PUBLIC" vs "PRIVATE" based on `p.disclosed`. For revealed values, also show the value more prominently:

```tsx
{predicates.map((p, i) => (
  <tr key={i} className={`border-b border-gray-100 last:border-0 ${p.disclosed ? 'bg-blue-50' : ''}`}>
    <td className="py-0.5 pr-2 font-medium">{p.claim}</td>
    <td className="py-0.5 pr-2 font-mono text-gray-500">{p.op}</td>
    <td className={`py-0.5 pr-2 ${p.disclosed ? 'font-semibold text-blue-700' : ''}`}>{p.publicValue}</td>
    <td className="py-0.5 text-right">
      {p.disclosed
        ? <span className="text-blue-600 font-semibold">{t('print.public')}</span>
        : <span className="text-gray-400">{t('print.private')}</span>
      }
    </td>
  </tr>
))}
```

Changes: disclosed rows get `bg-blue-50` background and the value is bold blue.

- [ ] **Step 2: Update the same table in demo.tsx PrintStep**

Apply the same styling to the predicates table in `demo.tsx` PrintStep (around lines 1288-1304).

- [ ] **Step 3: Commit**

```
feat(ui): highlight revealed values in print/PDF predicate tables
```

### Task 14: Verify QR flow works with revealed values

**Files:** No code changes — this is a verification task.

The QR flow already works because:
1. The export endpoint now creates envelopes with `revealed_claim`/`revealed_value` via `from_proofs_with_reveals`
2. CBOR serialization includes the new optional fields
3. QR chunking operates on the raw CBOR bytes — no changes needed
4. The scanner/verifier decodes the same CBOR and gets the revealed values

- [ ] **Step 1: Manual verification**

Start the demo locally. Issue a PID credential, select "Reveal document number" + "Age >= 18", prove, and go to print step. Verify:
- Revealed field shows as "PUBLIC" with the actual value in blue
- Predicate field shows as "PRIVATE" with the threshold
- QR codes are generated successfully
- Export/print works

- [ ] **Step 2: Done** — no commit needed, verification only.

---

## Summary of Files Modified

| File | Change |
|---|---|
| `crates/zk-eidas-types/src/predicate.rs` | Add `PredicateOp::Reveal` |
| `crates/zk-eidas-types/src/envelope.rs` | Add `revealed_claim`/`revealed_value` to `EnvelopeProof`, add `from_proofs_with_reveals()` |
| `crates/zk-eidas-types/src/credential.rs` | Add `ClaimValue::to_plaintext()` |
| `crates/zk-eidas-types/src/proof.rs` | Add `set_predicate_op()` method |
| `crates/zk-eidas-prover/src/circuit.rs` | Map `Reveal` to "eq" circuit |
| `crates/zk-eidas-verifier/src/registry.rs` | Map `Reveal` to `Eq` VK in `RegistryVerifier::verify()` |
| `crates/zk-eidas-verifier/src/verifier.rs` | Map `Reveal` to `Eq` in `verify_with_op()` |
| `crates/zk-eidas/src/builder.rs` | Add `Predicate::Reveal`, handle in `prove_single()` |
| `crates/zk-eidas/tests/error_paths.rs` | Add reveal error path test |
| `demo/api/src/main.rs` | Add `"reveal"` to `parse_predicate()`, pass through export |
| `demo/web/app/lib/credential-types.ts` | Add reveal entries for all 5 credentials |
| `demo/web/app/i18n.tsx` | Add reveal translation keys |
| `demo/web/app/routes/demo.tsx` | Reveal checkbox styling, handlePrintProof, PrintStep |
| `demo/web/app/routes/print.tsx` | Highlight revealed values in table |
