# Two-Party Nullifier Support Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Vehicle sale contract generates two independent nullifiers (seller + buyer), each cryptographically binding a party to the document.

**Architecture:** No circuit changes. `ContractNullifier` gains a `role` field, `CompoundProof` migrates from `Option<ContractNullifier>` to `Vec<ContractNullifier>` with custom serde for backward compat. The `contract_prove` API endpoint accepts `nullifier_field` and `role` params. Frontend collects per-party proofs and renders them as separate blocks on the A4 document.

**Tech Stack:** Rust (serde, zk-eidas-types), Axum (demo-api), React 19 + TypeScript (demo-web)

**Spec:** `docs/superpowers/specs/2026-03-23-two-party-nullifiers-design.md`

---

## Chunk 1: Rust Data Model (ContractNullifier + CompoundProof)

### Task 1: Add `role` field to ContractNullifier

**Files:**
- Modify: `crates/zk-eidas-types/src/proof.rs:125-131`

- [ ] **Step 1: Write failing test — ContractNullifier with role field**

Add to the existing `mod tests` block in `proof.rs`:

```rust
#[test]
fn contract_nullifier_with_role_serde_roundtrip() {
    let cn = ContractNullifier {
        role: "seller".to_string(),
        nullifier: vec![1, 2, 3],
        contract_hash: vec![4, 5, 6],
        salt: vec![7, 8, 9],
        proof: ZkProof::new(vec![10], vec![vec![11]], vec![], PredicateOp::Nullifier),
    };
    let json = serde_json::to_string(&cn).unwrap();
    let decoded: ContractNullifier = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.role, "seller");
    assert_eq!(decoded.nullifier, vec![1, 2, 3]);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p zk-eidas-types contract_nullifier_with_role`
Expected: FAIL — `ContractNullifier` has no `role` field.

- [ ] **Step 3: Add `role` field to ContractNullifier**

In `proof.rs`, change the struct definition at line 126:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractNullifier {
    #[serde(default = "default_role")]
    pub role: String,
    pub nullifier: Vec<u8>,
    pub contract_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub proof: ZkProof,
}

fn default_role() -> String {
    "holder".to_string()
}
```

The `#[serde(default = "default_role")]` ensures old JSON without `role` deserializes with `"holder"`.

- [ ] **Step 4: Fix existing test — add `role` to existing ContractNullifier literals**

In the same file, update all existing `ContractNullifier { ... }` in tests to include `role: "holder".to_string()`:

1. `contract_nullifier_serde_roundtrip` (line 222) — add `role: "holder".to_string(),`
2. `compound_proof_with_contract_nullifier_serde` (line 237) — add `role: "holder".to_string(),`

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p zk-eidas-types`
Expected: All tests PASS.

- [ ] **Step 6: Fix builder.rs — add `role` to ContractNullifier construction**

In `crates/zk-eidas/src/builder.rs`, two places construct `ContractNullifier`:

1. `generate_nullifier()` (~line 163):
```rust
Ok(ContractNullifier {
    role: "holder".to_string(),
    nullifier: nullifier_bytes,
    contract_hash: contract_hash.to_be_bytes().to_vec(),
    salt: salt.to_be_bytes().to_vec(),
    proof: nullifier_proof,
})
```

2. `prove_compound()` (~line 326):
```rust
Some(ContractNullifier {
    role: "holder".to_string(),
    nullifier: nullifier_bytes,
    contract_hash: contract_hash.to_be_bytes().to_vec(),
    salt: salt.to_be_bytes().to_vec(),
    proof: nullifier_proof,
})
```

- [ ] **Step 7: Fix main.rs — add `role` to ContractNullifier construction**

In `demo/api/src/main.rs`, the cached path (~line 1199):
```rust
Ok(zk_eidas_types::proof::ContractNullifier {
    role: "holder".to_string(),
    nullifier: nullifier_bytes,
    contract_hash: contract_hash.to_be_bytes().to_vec(),
    salt: salt.to_be_bytes().to_vec(),
    proof: nullifier_proof,
})
```

- [ ] **Step 8: Run full workspace build to verify no compilation errors**

Run: `cargo build --workspace`
Expected: Compiles without errors.

- [ ] **Step 9: Commit**

```bash
git add crates/zk-eidas-types/src/proof.rs crates/zk-eidas/src/builder.rs demo/api/src/main.rs
git commit -m "feat(types): add role field to ContractNullifier"
```

### Task 2: Migrate CompoundProof to Vec<ContractNullifier>

**Files:**
- Modify: `crates/zk-eidas-types/src/proof.rs:133-184`

- [ ] **Step 1: Write failing tests for the new API**

Add to `mod tests` in `proof.rs`:

```rust
#[test]
fn compound_proof_multiple_nullifiers() {
    let cn1 = ContractNullifier {
        role: "seller".to_string(),
        nullifier: vec![1],
        contract_hash: vec![2],
        salt: vec![3],
        proof: ZkProof::new(vec![], vec![], vec![], PredicateOp::Nullifier),
    };
    let cn2 = ContractNullifier {
        role: "buyer".to_string(),
        nullifier: vec![4],
        contract_hash: vec![2],
        salt: vec![5],
        proof: ZkProof::new(vec![], vec![], vec![], PredicateOp::Nullifier),
    };
    let compound = CompoundProof::new(vec![], LogicalOp::And)
        .add_contract_nullifier(cn1)
        .add_contract_nullifier(cn2);

    assert_eq!(compound.contract_nullifiers().len(), 2);
    assert_eq!(compound.contract_nullifiers()[0].role, "seller");
    assert_eq!(compound.contract_nullifiers()[1].role, "buyer");
    // Backward compat accessor returns first
    assert_eq!(compound.contract_nullifier().unwrap().role, "seller");
}

#[test]
fn compound_proof_contract_nullifiers_serde_roundtrip() {
    let cn = ContractNullifier {
        role: "seller".to_string(),
        nullifier: vec![1],
        contract_hash: vec![2],
        salt: vec![3],
        proof: ZkProof::new(vec![], vec![], vec![], PredicateOp::Nullifier),
    };
    let compound = CompoundProof::new(vec![], LogicalOp::And)
        .add_contract_nullifier(cn);
    let json = serde_json::to_string(&compound).unwrap();
    // New format: "contract_nullifiers" key
    assert!(json.contains("contract_nullifiers"), "should serialize as contract_nullifiers");
    let decoded: CompoundProof = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.contract_nullifiers().len(), 1);
    assert_eq!(decoded.contract_nullifiers()[0].role, "seller");
}

#[test]
fn compound_proof_old_format_contract_nullifier_deserialize() {
    // Simulates old JSON with "contract_nullifier": { ... }
    let old_json = r#"{
        "proofs": [],
        "op": "And",
        "contract_nullifier": {
            "nullifier": [1],
            "contract_hash": [2],
            "salt": [3],
            "proof": {
                "proof_bytes": [],
                "public_inputs": [],
                "verification_key": [],
                "predicate_op": "Nullifier",
                "nullifier": null,
                "version": 2
            }
        }
    }"#;
    let decoded: CompoundProof = serde_json::from_str(old_json).unwrap();
    assert_eq!(decoded.contract_nullifiers().len(), 1);
    assert_eq!(decoded.contract_nullifiers()[0].role, "holder");
}

#[test]
fn compound_proof_old_format_null_nullifier_deserialize() {
    let old_json = r#"{"proofs":[],"op":"And","contract_nullifier":null}"#;
    let decoded: CompoundProof = serde_json::from_str(old_json).unwrap();
    assert!(decoded.contract_nullifiers().is_empty());
}

#[test]
fn compound_proof_no_nullifier_fields_deserialize() {
    let json = r#"{"proofs":[],"op":"And"}"#;
    let decoded: CompoundProof = serde_json::from_str(json).unwrap();
    assert!(decoded.contract_nullifiers().is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p zk-eidas-types compound_proof_multiple`
Expected: FAIL — `add_contract_nullifier` doesn't exist, `contract_nullifiers()` doesn't exist.

- [ ] **Step 3: Replace CompoundProof struct and impl with Vec + custom serde**

Replace the entire `CompoundProof` struct and impl (lines 133-184) with:

```rust
/// A compound proof wrapping multiple sub-proofs with a logical operator.
#[derive(Debug, Clone, PartialEq)]
pub struct CompoundProof {
    proofs: Vec<ZkProof>,
    op: LogicalOp,
    ecdsa_proofs: HashMap<String, ZkProof>,
    contract_nullifiers: Vec<ContractNullifier>,
}

impl Serialize for CompoundProof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("CompoundProof", 4)?;
        s.serialize_field("proofs", &self.proofs)?;
        s.serialize_field("op", &self.op)?;
        if !self.ecdsa_proofs.is_empty() {
            s.serialize_field("ecdsa_proofs", &self.ecdsa_proofs)?;
        }
        if !self.contract_nullifiers.is_empty() {
            s.serialize_field("contract_nullifiers", &self.contract_nullifiers)?;
        }
        s.end()
    }
}

impl<'de> Deserialize<'de> for CompoundProof {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            proofs: Vec<ZkProof>,
            op: LogicalOp,
            #[serde(default)]
            ecdsa_proofs: HashMap<String, ZkProof>,
            #[serde(default)]
            contract_nullifiers: Option<Vec<ContractNullifier>>,
            #[serde(default)]
            contract_nullifier: Option<ContractNullifier>,
        }
        let h = Helper::deserialize(deserializer)?;
        let contract_nullifiers = if let Some(vec) = h.contract_nullifiers {
            vec
        } else if let Some(cn) = h.contract_nullifier {
            vec![cn]
        } else {
            vec![]
        };
        Ok(CompoundProof {
            proofs: h.proofs,
            op: h.op,
            ecdsa_proofs: h.ecdsa_proofs,
            contract_nullifiers,
        })
    }
}

impl CompoundProof {
    /// Create a compound proof from sub-proofs joined by a logical operator.
    pub fn new(proofs: Vec<ZkProof>, op: LogicalOp) -> Self {
        Self { proofs, op, ecdsa_proofs: HashMap::new(), contract_nullifiers: Vec::new() }
    }

    /// Create a compound proof with associated ECDSA proofs keyed by claim name.
    pub fn with_ecdsa_proofs(
        proofs: Vec<ZkProof>,
        op: LogicalOp,
        ecdsa_proofs: HashMap<String, ZkProof>,
    ) -> Self {
        Self { proofs, op, ecdsa_proofs, contract_nullifiers: Vec::new() }
    }

    /// Add a contract nullifier to this compound proof.
    pub fn add_contract_nullifier(mut self, cn: ContractNullifier) -> Self {
        self.contract_nullifiers.push(cn);
        self
    }

    /// Attach a contract nullifier (backward-compatible alias for add_contract_nullifier).
    pub fn with_contract_nullifier(self, cn: ContractNullifier) -> Self {
        self.add_contract_nullifier(cn)
    }

    /// Returns all contract nullifiers.
    pub fn contract_nullifiers(&self) -> &[ContractNullifier] {
        &self.contract_nullifiers
    }

    /// Returns the first contract nullifier, if any (backward compat).
    pub fn contract_nullifier(&self) -> Option<&ContractNullifier> {
        self.contract_nullifiers.first()
    }

    /// Returns the sub-proofs.
    pub fn proofs(&self) -> &[ZkProof] {
        &self.proofs
    }

    /// Returns the logical operator (And / Or).
    pub fn op(&self) -> LogicalOp {
        self.op
    }

    /// Returns the ECDSA proofs keyed by claim name.
    pub fn ecdsa_proofs(&self) -> &HashMap<String, ZkProof> {
        &self.ecdsa_proofs
    }
}
```

- [ ] **Step 4: Update existing tests that reference the old API**

The test `compound_proof_with_contract_nullifier_serde` (line 236) — update assertions:
```rust
#[test]
fn compound_proof_with_contract_nullifier_serde() {
    let cn = ContractNullifier {
        role: "holder".to_string(),
        nullifier: vec![1],
        contract_hash: vec![2],
        salt: vec![3],
        proof: ZkProof::new(vec![], vec![], vec![], PredicateOp::Nullifier),
    };
    let compound = CompoundProof::with_ecdsa_proofs(vec![], LogicalOp::And, HashMap::new())
        .with_contract_nullifier(cn);
    let json = serde_json::to_string(&compound).unwrap();
    let decoded: CompoundProof = serde_json::from_str(&json).unwrap();
    assert!(decoded.contract_nullifier().is_some());
    assert_eq!(decoded.contract_nullifier().unwrap().nullifier, vec![1]);
}
```

The test `compound_proof_without_contract_nullifier_backward_compat` (line 252):
```rust
#[test]
fn compound_proof_without_contract_nullifier_backward_compat() {
    let json = r#"{"proofs":[],"op":"And"}"#;
    let decoded: CompoundProof = serde_json::from_str(json).unwrap();
    assert!(decoded.contract_nullifier().is_none());
    assert!(decoded.contract_nullifiers().is_empty());
}
```

- [ ] **Step 5: Run all tests in types crate**

Run: `cargo test -p zk-eidas-types`
Expected: All tests PASS (including old backward compat tests + new multi-nullifier tests).

- [ ] **Step 6: Run workspace build**

Run: `cargo build --workspace`
Expected: Compiles. The facade builder and demo API use `with_contract_nullifier` which still works (alias).

- [ ] **Step 7: Commit**

```bash
git add crates/zk-eidas-types/src/proof.rs
git commit -m "feat(types): migrate CompoundProof to Vec<ContractNullifier> with serde compat"
```

## Chunk 2: API Endpoint Changes

### Task 3: Fix contract_hash computation (remove salt from hash)

**Files:**
- Modify: `demo/api/src/main.rs:1105-1115`

- [ ] **Step 1: Write failing test — same terms + timestamp = same contract_hash**

Add to the test module in `main.rs`:

```rust
#[tokio::test]
#[serial]
async fn contract_prove_same_terms_same_hash() {
    let (url, cred) = issue_test_credential(serde_json::json!({
        "given_name": "Test", "birth_date": "1998-05-14", "document_number": "UA-HASH-001"
    })).await;
    let client = reqwest::Client::new();

    let body = serde_json::json!({
        "credential": cred, "format": "sdjwt",
        "predicates": [{ "claim": "birth_date", "op": "gte", "value": 18 }],
        "contract_terms": "same terms", "timestamp": "2026-03-23T10:00:00Z",
    });

    let res1: serde_json::Value = client
        .post(format!("{url}/holder/contract-prove"))
        .json(&body)
        .send().await.unwrap().json().await.unwrap();

    let res2: serde_json::Value = client
        .post(format!("{url}/holder/contract-prove"))
        .json(&body)
        .send().await.unwrap().json().await.unwrap();

    let h1 = res1["contract_hash"].as_str().unwrap();
    let h2 = res2["contract_hash"].as_str().unwrap();
    assert_eq!(h1, h2, "same (terms, timestamp) must produce same contract_hash");

    // But nullifiers differ (different random salt)
    let n1 = res1["nullifier"].as_str().unwrap();
    let n2 = res2["nullifier"].as_str().unwrap();
    assert_ne!(n1, n2, "different salts must produce different nullifiers");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p demo-api contract_prove_same_terms_same_hash -- --nocapture`
Expected: FAIL — currently salt is mixed into hash, so hashes differ.

- [ ] **Step 3: Remove salt from contract_hash computation**

In `demo/api/src/main.rs`, change lines 1108-1115:

```rust
    // 2. Compute contract_hash = SHA256(terms || timestamp) → u64
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(req.contract_terms.as_bytes());
    hasher.update(req.timestamp.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let contract_hash = u64::from_be_bytes(hash[..8].try_into().unwrap());
```

(Removed the `hasher.update(&salt.to_be_bytes());` line.)

- [ ] **Step 4: Run new test + existing tests**

Run: `cargo test -p demo-api contract_prove -- --nocapture`
Expected: All contract_prove tests PASS. The `contract_prove_different_salt_different_nullifier` test uses different `contract_terms` and `timestamp`, so its contract_hashes will still differ.

- [ ] **Step 5: Commit**

```bash
git add demo/api/src/main.rs
git commit -m "fix(api): remove salt from contract_hash computation for deterministic hashing"
```

### Task 4: Add `nullifier_field` and `role` params to contract_prove

**Files:**
- Modify: `demo/api/src/main.rs:1078-1099` (request/response structs)
- Modify: `demo/api/src/main.rs:1137-1145` (cached path auto-detect)
- Modify: `demo/api/src/main.rs:1267-1272` (full path auto-detect)
- Modify: `demo/api/src/main.rs:1199-1204` (ContractNullifier construction, cached path)

- [ ] **Step 1: Write failing test — nullifier_field and role are echoed back**

Add to the test module in `main.rs`:

```rust
#[tokio::test]
#[serial]
async fn contract_prove_with_nullifier_field_and_role() {
    let (url, cred) = issue_test_credential(serde_json::json!({
        "given_name": "Test", "birth_date": "1998-05-14", "document_number": "UA-ROLE-001"
    })).await;
    let client = reqwest::Client::new();
    let res: serde_json::Value = client
        .post(format!("{url}/holder/contract-prove"))
        .json(&serde_json::json!({
            "credential": cred, "format": "sdjwt",
            "predicates": [{ "claim": "birth_date", "op": "gte", "value": 18 }],
            "contract_terms": "test", "timestamp": "2026-03-23T10:00:00Z",
            "nullifier_field": "document_number",
            "role": "seller",
        }))
        .send().await.unwrap().json().await.unwrap();

    assert_eq!(res["role"].as_str().unwrap(), "seller");
    assert!(res["nullifier"].as_str().unwrap().starts_with("0x"));
}

#[tokio::test]
#[serial]
async fn contract_prove_defaults_role_to_holder() {
    let (url, cred) = issue_test_credential(serde_json::json!({
        "given_name": "Test", "birth_date": "1998-05-14", "document_number": "UA-ROLE-002"
    })).await;
    let client = reqwest::Client::new();
    let res: serde_json::Value = client
        .post(format!("{url}/holder/contract-prove"))
        .json(&serde_json::json!({
            "credential": cred, "format": "sdjwt",
            "predicates": [{ "claim": "birth_date", "op": "gte", "value": 18 }],
            "contract_terms": "test", "timestamp": "2026-03-23T10:00:00Z",
        }))
        .send().await.unwrap().json().await.unwrap();

    assert_eq!(res["role"].as_str().unwrap(), "holder");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p demo-api contract_prove_with_nullifier_field -- --nocapture`
Expected: FAIL — `role` field not in response, `nullifier_field` not in request struct.

- [ ] **Step 3: Update request and response structs**

In `main.rs`, update `ContractProveRequest` (~line 1078):

```rust
#[derive(Deserialize)]
struct ContractProveRequest {
    credential: String,
    #[serde(default = "default_format")]
    format: String,
    predicates: Vec<PredicateRequest>,
    contract_terms: String,
    timestamp: String,
    #[serde(default)]
    skip_cache: bool,
    #[serde(default)]
    nullifier_field: Option<String>,
    #[serde(default)]
    role: Option<String>,
}
```

Update `ContractProveResponse` (~line 1090):

```rust
#[derive(Serialize)]
struct ContractProveResponse {
    compound_proof_json: String,
    op: String,
    sub_proofs_count: usize,
    hidden_fields: Vec<String>,
    nullifier: String,
    contract_hash: String,
    salt: String,
    role: String,
}
```

- [ ] **Step 4: Use nullifier_field in auto-detect logic (cached path)**

In the cached path (~line 1137-1145), replace the auto-detect with:

```rust
        let credential_id_field = if let Some(ref nf) = req.nullifier_field {
            nf.as_str()
        } else {
            let id_field_candidates = ["document_number", "license_number", "diploma_number", "vin", "student_number"];
            *id_field_candidates.iter()
                .find(|f| all_field_names_cached.contains(&f.to_string()))
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "no credential_id field found".to_string()))?
        };
```

- [ ] **Step 5: Use nullifier_field in auto-detect logic (full path)**

In the full proving path (~line 1267-1272), replace:

```rust
    // 5. Set contract nullifier — use nullifier_field if provided, else auto-detect
    let credential_id_field = if let Some(ref nf) = req.nullifier_field {
        nf.as_str()
    } else {
        let id_field_candidates = ["document_number", "license_number", "diploma_number", "vin", "student_number"];
        *id_field_candidates.iter()
            .find(|f| all_field_names.contains(&f.to_string()))
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "no credential_id field found".to_string()))?
    };
    builder = builder.contract_nullifier(credential_id_field, contract_hash, salt);
```

- [ ] **Step 6: Set role on ContractNullifier (cached path)**

In the cached path (~line 1199), add role:

```rust
            Ok(zk_eidas_types::proof::ContractNullifier {
                role: role_str.clone(),
                nullifier: nullifier_bytes,
                contract_hash: contract_hash.to_be_bytes().to_vec(),
                salt: salt.to_be_bytes().to_vec(),
                proof: nullifier_proof,
            })
```

Where `role_str` is defined at the top of `contract_prove` function, after salt generation:

```rust
    let role_str = req.role.clone().unwrap_or_else(|| "holder".to_string());
```

- [ ] **Step 7: Add role to both response paths**

Cached path response (~line 1214):
```rust
        return Ok(Json(ContractProveResponse {
            compound_proof_json,
            op: cached.op.clone(),
            sub_proofs_count: cached.sub_proofs_count,
            hidden_fields: cached.hidden_fields.clone(),
            nullifier: format!("0x{}", hex::encode(&nullifier_bytes)),
            contract_hash: format!("0x{:016x}", contract_hash),
            salt: format!("0x{:016x}", salt),
            role: role_str.clone(),
        }));
```

Full path response (~line 1340):
```rust
    Ok(Json(ContractProveResponse {
        compound_proof_json,
        op: op_label,
        sub_proofs_count,
        hidden_fields,
        nullifier: nullifier_hex,
        contract_hash: format!("0x{:016x}", contract_hash),
        salt: format!("0x{:016x}", salt),
        role: role_str,
    }))
```

- [ ] **Step 8: Set role on ContractNullifier in full proving path**

The full path constructs `ContractNullifier` inside `builder.prove_compound()` which defaults `role` to `"holder"`. After `prove_compound()` returns, we need to update the role on the nullifier. Add a mutable method to `CompoundProof` or update the role post-construction.

Simplest approach — add a setter to `ContractNullifier`:

In `proof.rs`, add:
```rust
impl ContractNullifier {
    /// Set the role for this nullifier.
    pub fn set_role(&mut self, role: String) {
        self.role = role;
    }
}
```

Then in the full path of `main.rs`, after `builder.prove_compound()`:

```rust
    // Set role on contract nullifier if present
    // (builder defaults to "holder", but we want the caller-specified role)
    // CompoundProof needs a mutable accessor for this
```

Actually, cleaner: add `set_nullifier_role` to `CompoundProof`:

In `proof.rs`, add to `impl CompoundProof`:
```rust
    /// Set the role on the first contract nullifier (used by contract_prove API).
    pub fn set_nullifier_role(&mut self, role: &str) {
        if let Some(cn) = self.contract_nullifiers.first_mut() {
            cn.role = role.to_string();
        }
    }
```

Then in `main.rs`, after `prove_compound()` returns (~line 1316):
```rust
    compound_proof.set_nullifier_role(&role_str);
```

Note: `compound_proof` needs to be `mut`. Change line 1284:
```rust
    let (mut compound_proof, proven_claims, all_field_names) =
```

- [ ] **Step 9: Run all contract_prove tests**

Run: `cargo test -p demo-api contract_prove -- --nocapture`
Expected: All tests PASS (old and new).

- [ ] **Step 10: Commit**

```bash
git add crates/zk-eidas-types/src/proof.rs demo/api/src/main.rs
git commit -m "feat(api): add nullifier_field and role params to contract-prove endpoint"
```

## Chunk 3: Frontend Changes

### Task 5: Add nullifierField to contract templates

**Files:**
- Modify: `demo/web/app/lib/contract-templates.ts`

- [ ] **Step 1: Add `nullifierField` to CredentialRequirement interface**

```ts
export interface CredentialRequirement {
  role: string
  roleLabelKey: string
  credentialType: string
  predicateIds: string[]
  disclosedField: string
  nullifierField?: string
}
```

- [ ] **Step 2: Add nullifierField to each template**

For `age_verification`:
```ts
{
  role: 'holder',
  roleLabelKey: 'contracts.role.holder',
  credentialType: 'pid',
  predicateIds: ['age'],
  disclosedField: 'document_number',
  nullifierField: 'document_number',
},
```

For `student_transit`:
```ts
{
  role: 'student',
  roleLabelKey: 'contracts.role.student',
  credentialType: 'student_id',
  predicateIds: ['active_student'],
  disclosedField: 'student_number',
  nullifierField: 'student_number',
},
```

For `driver_employment`:
```ts
{
  role: 'driver',
  roleLabelKey: 'contracts.role.driver',
  credentialType: 'drivers_license',
  predicateIds: ['valid', 'category_b', 'experienced'],
  disclosedField: 'license_number',
  nullifierField: 'license_number',
},
```

For `vehicle_sale`:
```ts
// seller
{
  role: 'seller',
  roleLabelKey: 'contracts.role.seller',
  credentialType: 'pid',
  predicateIds: ['age'],
  disclosedField: 'document_number',
  nullifierField: 'document_number',
},
// vehicle — NO nullifierField (not a party)
{
  role: 'vehicle',
  roleLabelKey: 'contracts.role.vehicleReg',
  credentialType: 'vehicle',
  predicateIds: ['insured', 'vin_active'],
  disclosedField: 'vin',
},
// buyer
{
  role: 'buyer',
  roleLabelKey: 'contracts.role.buyer',
  credentialType: 'pid',
  predicateIds: ['age'],
  disclosedField: 'document_number',
  nullifierField: 'document_number',
},
```

- [ ] **Step 3: Commit**

```bash
git add demo/web/app/lib/contract-templates.ts
git commit -m "feat(web): add nullifierField to contract templates"
```

### Task 6: Update ContractWizardState and prove loop

**Files:**
- Modify: `demo/web/app/routes/contracts.tsx:10-60` (types + initial state)
- Modify: `demo/web/app/routes/contracts.tsx:520-665` (prove loop)

- [ ] **Step 1: Add PartyProof interface and update state**

After the `BindingResult` interface (~line 28), add:

```ts
interface PartyProof {
  role: string
  roleLabelKey: string
  nullifier: string
  salt: string
  issuer: string
  qrDataUrls: string[]
}
```

Update `ContractWizardState` — replace `nullifier`, `contractHash`, `salt` with:

```ts
interface ContractWizardState {
  step: 1 | 2 | 3 | 4 | 5
  templateId: string | null
  credentialIndex: number
  credentials: CredentialData[]
  bindings: BindingResult[]
  qrDataUrls: string[]
  compressedSize: number
  compressedCborBase64: string | null
  cached: boolean
  partyProofs: PartyProof[]
  contractHash: string | null
}
```

Update `INITIAL_STATE`:

```ts
const INITIAL_STATE: ContractWizardState = {
  step: 1,
  templateId: null,
  credentialIndex: 0,
  credentials: [],
  bindings: [],
  qrDataUrls: [],
  compressedSize: 0,
  compressedCborBase64: null,
  cached: false,
  partyProofs: [],
  contractHash: null,
}
```

- [ ] **Step 2: Update the prove loop in ProveStep**

In the `handleProve` function (~line 515), replace the prove loop. Key changes:

1. Compute timestamp once before the loop:
```ts
const timestamp = new Date().toISOString()
```

2. Replace `let nullifierData` with `const partyProofs: PartyProof[] = []` and `let sharedContractHash: string | null = null`.

3. In the fetch body, add new fields:
```ts
body: JSON.stringify({
  credential: cred.credential,
  format: cred.format,
  predicates,
  contract_terms: JSON.stringify(selectedTemplate),
  timestamp,
  nullifier_field: req.nullifierField,
  role: req.role,
  ...(forceSkipCache ? { skip_cache: true } : {}),
}),
```

4. Replace the `ci === 0 && proveData.nullifier` block (~line 607-613) with:
```ts
        if (req.nullifierField && proveData.nullifier) {
          if (!sharedContractHash) {
            sharedContractHash = proveData.contract_hash
          }
          partyProofs.push({
            role: req.role,
            roleLabelKey: req.roleLabelKey,
            nullifier: proveData.nullifier,
            salt: proveData.salt,
            issuer: config?.issuer ?? '',
            qrDataUrls: qrUrlsForThisCredential,
          })
        }
```

Note: `qrUrlsForThisCredential` — extract QR URLs for this credential from the existing QR generation code. Currently QRs are pushed to `allQrDataUrls`. Track the start index before QR generation for this credential, then slice:

```ts
        const qrStartIndex = allQrDataUrls.length
        // ... existing QR generation code (lines 580-592) ...
        const qrUrlsForThisCredential = allQrDataUrls.slice(qrStartIndex)
```

5. In the setState call (~line 654-665), replace `nullifier/contractHash/salt` with:
```ts
          partyProofs,
          contractHash: sharedContractHash,
```

- [ ] **Step 3: Fix any references to old `state.nullifier` or `state.salt`**

Search for `state.nullifier` and `state.salt` in the file. The only references should be in the DocumentStep component (step 4 rendering), which we'll update in the next task.

Also check for reset actions — when template selection changes (~line 177):
```ts
nullifier: null,  // change to: partyProofs: [],
```

- [ ] **Step 4: Build frontend to verify no TS errors**

Run: `cd demo/web && npx tsc --noEmit`
Expected: May have errors in DocumentStep (referencing old `state.nullifier`). That's expected — fixed in next task.

- [ ] **Step 5: Commit**

```bash
git add demo/web/app/routes/contracts.tsx
git commit -m "feat(web): update prove loop for per-party nullifier collection"
```

### Task 7: Update A4 document preview rendering

**Files:**
- Modify: `demo/web/app/routes/contracts.tsx:869-945` (QR + nullifier + signature rendering)
- Modify: `demo/web/app/i18n.tsx` (add shared section key)

- [ ] **Step 1: Add i18n keys**

In `demo/web/app/i18n.tsx`, add near the other `contracts.*` keys (~line 1210):

```ts
"contracts.shared": { en: "SHARED", uk: "СПІЛЬНЕ" },
"contracts.issuer": { en: "Issuer", uk: "Видавець" },
"contracts.date": { en: "Date", uk: "Дата" },
```

- [ ] **Step 2: Replace QR codes section with per-party blocks**

Replace the QR codes section (lines 869-885) and nullifier section (lines 907-931) and signature line (lines 933-939) with per-party rendering:

```tsx
            {/* Per-party proof blocks */}
            {state.partyProofs.map((party, pi) => (
              <div key={party.role} className="mb-5 border border-gray-300 rounded-lg p-4 print:border-black/30">
                <p className="text-xs font-semibold text-gray-500 mb-3 uppercase tracking-wider">
                  {t(party.roleLabelKey)}
                </p>
                <div className="space-y-1.5">
                  <div>
                    <span className="text-[10px] text-gray-400 font-medium">{t('contracts.nullifier')}</span>
                    <p className="text-xs text-gray-700 font-mono break-all">{party.nullifier}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-gray-400 font-medium">{t('contracts.salt')}</span>
                    <p className="text-xs text-gray-700 font-mono break-all">{party.salt}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-gray-400 font-medium">{t('contracts.issuer')}</span>
                    <p className="text-xs text-gray-700 font-mono break-all">{party.issuer}</p>
                  </div>
                </div>
                {/* QR codes for this party */}
                {party.qrDataUrls.length > 0 && (
                  <div className="mt-3">
                    <div className="grid grid-cols-3 gap-2 justify-items-center">
                      {party.qrDataUrls.map((url, qi) => (
                        <div key={qi} className="text-center">
                          <img
                            src={url}
                            alt={`QR ${qi + 1}/${party.qrDataUrls.length}`}
                            className="w-28 h-28 print:w-[50mm] print:h-[50mm]"
                          />
                          <p className="text-[9px] text-gray-400 -mt-0.5">{qi + 1}/{party.qrDataUrls.length}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}

            {/* QR codes for credentials WITHOUT nullifiers (e.g. vehicle) */}
            {(() => {
              const partyQrCount = state.partyProofs.reduce((sum, p) => sum + p.qrDataUrls.length, 0)
              const remainingQrs = state.qrDataUrls.slice(partyQrCount)
              if (remainingQrs.length === 0) return null
              return (
                <div className="mb-5">
                  <div className="grid grid-cols-3 gap-2 justify-items-center">
                    {remainingQrs.map((url, qi) => (
                      <div key={qi} className="text-center">
                        <img
                          src={url}
                          alt={`QR ${partyQrCount + qi + 1}/${state.qrDataUrls.length}`}
                          className="w-28 h-28 print:w-[50mm] print:h-[50mm]"
                        />
                        <p className="text-[9px] text-gray-400 -mt-0.5">{partyQrCount + qi + 1}/{state.qrDataUrls.length}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )
            })()}
```

- [ ] **Step 3: Add shared section (contract hash + date)**

After the per-party blocks, before signature lines:

```tsx
            {/* Shared section */}
            {state.contractHash && (
              <div className="mb-5 border border-gray-300 rounded-lg p-4 print:border-black/30">
                <p className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-wider">{t('contracts.shared')}</p>
                <div className="space-y-1.5">
                  <div>
                    <span className="text-[10px] text-gray-400 font-medium">{t('contracts.contractHash')}</span>
                    <p className="text-xs text-gray-700 font-mono break-all">{state.contractHash}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-gray-400 font-medium">{t('contracts.date')}</span>
                    <p className="text-xs text-gray-700">{today}</p>
                  </div>
                </div>
                <p className="text-[9px] text-gray-400 mt-2 leading-relaxed italic">{t('contracts.nullifierTooltip')}</p>
              </div>
            )}
```

- [ ] **Step 4: Update signature lines — one per party**

Replace the single signature line (lines 933-939) with:

```tsx
            {/* Signature lines — one per party */}
            <div className="border-t border-gray-200 pt-4 mt-4 space-y-3">
              {state.partyProofs.length > 0 ? (
                state.partyProofs.map((party) => (
                  <div key={party.role} className="flex justify-between text-xs text-gray-400">
                    <span>{t(party.roleLabelKey)} {t('contracts.signatureLine')}: ____________________________</span>
                    <span>{today}</span>
                  </div>
                ))
              ) : (
                <div className="flex justify-between text-xs text-gray-400">
                  <span>{t('contracts.signatureLine')}: ____________________________</span>
                  <span>{today}</span>
                </div>
              )}
            </div>
```

- [ ] **Step 5: Build and verify**

Run: `cd demo/web && npx tsc --noEmit`
Expected: No TypeScript errors.

- [ ] **Step 6: Commit**

```bash
git add demo/web/app/routes/contracts.tsx demo/web/app/i18n.tsx
git commit -m "feat(web): render per-party nullifier blocks on A4 document"
```

## Chunk 4: Integration Testing & Verification

### Task 8: Run full test suite and verify

**Files:** None (testing only)

- [ ] **Step 1: Run Rust workspace tests**

Run: `cargo test --workspace -- --test-threads=1`

Note: Use `--test-threads=1` because of the `#[serial]` attribute on API tests and RAM constraints (see memory: feedback_test_ram.md — never run full test suite with ECDSA proving in parallel).

Expected: All tests PASS.

- [ ] **Step 2: Run frontend type check**

Run: `cd demo/web && npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Run frontend build**

Run: `cd demo/web && npm run build`
Expected: Build succeeds.

- [ ] **Step 4: Manual smoke test (if dev server available)**

Start the API and web servers, navigate to `/contracts`, select Vehicle Sale, issue credentials, prove, and verify:
- Two nullifier blocks appear (seller + buyer)
- Contract hash is shared
- QR codes are grouped per party
- Two signature lines
- Single-party templates (e.g., age_verification) still work with one block

- [ ] **Step 5: Final commit if any fixes needed**

Only if smoke test reveals issues that need fixing.
