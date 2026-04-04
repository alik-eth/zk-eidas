# Longfellow Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Longfellow migration — rewire demo-api, add proof blob store, redesign escrow with AES-256-GCM.

**Architecture:** Replace all Circom/Groth16 proving in demo-api with `longfellow_sys::mdoc::prove()`/`verify()`. Add content-addressed proof blob store. Replace Poseidon-CTR escrow encryption with out-of-circuit AES-256-GCM, using the existing in-circuit `binding_hash` for integrity verification.

**Tech Stack:** Rust (axum, longfellow-sys, aes-gcm, ml-kem), TypeScript (WebCrypto AES-GCM, mlkem)

---

## File Map

### New Files
- None — all changes are modifications to existing files

### Modified Files

| File | Changes |
|---|---|
| `demo/api/Cargo.toml` | Add `aes-gcm` dependency |
| `demo/api/src/main.rs` | Proof blob store endpoints, rewire all 6 prove/verify endpoints, escrow redesign |
| `crates/zk-eidas/src/escrow.rs` | Replace `pack_credential_fields` + Poseidon-CTR with AES-256-GCM encrypt/decrypt |
| `crates/zk-eidas/Cargo.toml` | Add `aes-gcm` dependency |
| `crates/zk-eidas-types/src/proof.rs` | Update `IdentityEscrowData` struct for AES-GCM fields |
| `demo/web/app/lib/escrow-decrypt.ts` | Replace Poseidon-CTR with WebCrypto AES-GCM |

---

## Task 1: Proof Blob Store

**Files:**
- Modify: `demo/api/src/main.rs` (AppState, router, 2 new handlers)

- [ ] **Step 1: Add blob store to AppState**

In `demo/api/src/main.rs`, add to the `AppState` struct (after `longfellow_circuit` field):

```rust
/// Content-addressed proof blob store: SHA-256(bytes) hex → proof bytes
proof_blobs: std::sync::RwLock<HashMap<String, Vec<u8>>>,
```

Initialize in `build_app()`:

```rust
proof_blobs: std::sync::RwLock::new(HashMap::new()),
```

- [ ] **Step 2: Add POST /proofs endpoint**

Add handler function:

```rust
async fn store_proof_blob(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use sha2::{Sha256, Digest};
    let cid = hex::encode(Sha256::digest(&body));
    state.proof_blobs.write().unwrap().insert(cid.clone(), body.to_vec());
    Ok(Json(serde_json::json!({ "cid": cid })))
}
```

Add route to router:

```rust
.route("/proofs", post(store_proof_blob))
```

- [ ] **Step 3: Add GET /proofs/:cid endpoint**

Add handler function:

```rust
async fn get_proof_blob(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(cid): axum::extract::Path<String>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let blobs = state.proof_blobs.read().unwrap();
    let bytes = blobs.get(&cid)
        .ok_or((StatusCode::NOT_FOUND, format!("proof {cid} not found")))?;
    Ok(axum::response::Response::builder()
        .header("content-type", "application/octet-stream")
        .body(axum::body::Body::from(bytes.clone()))
        .unwrap())
}
```

Add route:

```rust
.route("/proofs/{cid}", get(get_proof_blob))
```

- [ ] **Step 4: Add blob store test**

Add test at the bottom of main.rs (in the `#[cfg(test)]` module):

```rust
#[tokio::test]
async fn blob_store_round_trip() {
    let app = build_app().await;
    let proof_bytes = vec![0u8; 100];
    let cid_expected = hex::encode(sha2::Sha256::digest(&proof_bytes));

    // Store
    let resp = app.clone().oneshot(
        axum::http::Request::builder()
            .method("POST").uri("/proofs")
            .body(axum::body::Body::from(proof_bytes.clone())).unwrap()
    ).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()
    ).unwrap();
    assert_eq!(body["cid"].as_str().unwrap(), cid_expected);

    // Retrieve
    let resp = app.oneshot(
        axum::http::Request::builder()
            .uri(format!("/proofs/{cid_expected}"))
            .body(axum::body::Body::empty()).unwrap()
    ).await.unwrap();
    assert_eq!(resp.status(), 200);
    let fetched = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert_eq!(fetched.as_ref(), &proof_bytes[..]);
}
```

- [ ] **Step 5: Run test and verify**

Run: `cd /data/Develop/zk-eidas-longfellow && cargo test -p zk-eidas-demo-api blob_store`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add demo/api/src/main.rs
git commit -m "feat(demo-api): add content-addressed proof blob store"
```

---

## Task 2: Longfellow Circuit Cache Upgrade

**Files:**
- Modify: `demo/api/src/main.rs` (AppState circuit caching)

The existing `longfellow_circuit: OnceCell<Vec<u8>>` caches a single 1-attribute circuit. For the full demo (1–4 attributes per contract), we need per-attribute-count caching.

- [ ] **Step 1: Replace single OnceCell with array**

Replace in AppState:

```rust
// OLD:
longfellow_circuit: tokio::sync::OnceCell<Vec<u8>>,

// NEW — cache circuit per attribute count (1-4):
longfellow_circuits: [tokio::sync::OnceCell<longfellow_sys::mdoc::MdocCircuit>; 4],
```

Initialize:

```rust
longfellow_circuits: std::array::from_fn(|_| tokio::sync::OnceCell::new()),
```

- [ ] **Step 2: Add helper to get or generate circuit**

```rust
async fn get_circuit(
    state: &AppState, num_attrs: usize,
) -> Result<&longfellow_sys::mdoc::MdocCircuit, (StatusCode, String)> {
    if num_attrs == 0 || num_attrs > 4 {
        return Err((StatusCode::BAD_REQUEST, format!("num_attrs must be 1-4, got {num_attrs}")));
    }
    state.longfellow_circuits[num_attrs - 1]
        .get_or_try_init(|| async {
            tokio::task::spawn_blocking(move || {
                longfellow_sys::mdoc::MdocCircuit::generate(num_attrs)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("circuit gen: {e}")))
            })
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")))?
        })
        .await
}
```

- [ ] **Step 3: Update longfellow_demo endpoint to use new cache**

Replace the existing `longfellow_demo` circuit caching block to use `get_circuit(state, 1)` instead of the raw `OnceCell<Vec<u8>>` + `gen_circuit(0)` call. The `longfellow_prove_verify_cached` call stays the same for the benchmark endpoint (it uses its own internal test data).

- [ ] **Step 4: Verify build**

Run: `cd /data/Develop/zk-eidas-longfellow && cargo build -p zk-eidas-demo-api`
Expected: Compiles

- [ ] **Step 5: Commit**

```bash
git add demo/api/src/main.rs
git commit -m "feat(demo-api): per-attribute circuit caching for Longfellow"
```

---

## Task 3: Request Translation Helper

**Files:**
- Modify: `demo/api/src/main.rs` (new helper function)

The core bridge: convert demo-api `PredicateRequest` + mdoc token into Longfellow `AttributeRequest` + raw mdoc bytes.

- [ ] **Step 1: Add predicate-to-attribute translation**

```rust
use longfellow_sys::mdoc::{AttributeRequest, MdocProof};
use longfellow_sys::safe::VerifyType;

/// Convert a demo-api predicate request to a Longfellow AttributeRequest.
/// The claim value must be CBOR-encoded (the mdoc parser provides this).
fn predicate_to_attribute(
    claim: &str,
    op: &str,
    cbor_value: &[u8],
) -> AttributeRequest {
    let verify_type = match op {
        "gte" => VerifyType::Geq,
        "lte" => VerifyType::Leq,
        "eq" => VerifyType::Eq,
        "neq" => VerifyType::Neq,
        _ => VerifyType::Eq, // default to equality
    };
    AttributeRequest {
        namespace: "org.iso.18013.5.1".into(),
        identifier: claim.into(),
        cbor_value: cbor_value.to_vec(),
        verify_type,
    }
}
```

- [ ] **Step 2: Add mdoc token to Longfellow input converter**

```rust
/// Parse mdoc token and extract the raw bytes + issuer public key as hex strings
/// suitable for longfellow_sys::mdoc::prove().
fn parse_mdoc_for_longfellow(token: &str) -> Result<(Vec<u8>, String, String), (StatusCode, String)> {
    let (mdoc_bytes, pk_x, pk_y) = parse_mdoc_token(token)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc parse: {e}")))?;
    // Longfellow C API expects "0x"-prefixed hex strings for public keys
    let pkx_hex = format!("0x{}", hex::encode(pk_x));
    let pky_hex = format!("0x{}", hex::encode(pk_y));
    Ok((mdoc_bytes, pkx_hex, pky_hex))
}
```

- [ ] **Step 3: Add CBOR value lookup helper**

The Longfellow circuit needs the actual CBOR-encoded attribute values from the mdoc. The existing `zk_eidas_mdoc::MdocParser` extracts claims as `ClaimValue`, but we need raw CBOR bytes. Add a helper that re-encodes:

```rust
/// Encode a claim value back to CBOR bytes for Longfellow attribute requests.
/// This matches the CBOR encoding in the mdoc IssuerSignedItem.
fn claim_to_cbor(value: &zk_eidas_types::credential::ClaimValue) -> Vec<u8> {
    use zk_eidas_types::credential::ClaimValue;
    match value {
        ClaimValue::Boolean(true) => vec![0xf5],
        ClaimValue::Boolean(false) => vec![0xf4],
        ClaimValue::Integer(n) if *n >= 0 && *n <= 23 => vec![*n as u8],
        ClaimValue::Integer(n) if *n >= 0 && *n <= 255 => vec![0x18, *n as u8],
        ClaimValue::Integer(n) if *n >= 0 => vec![0x19, (*n >> 8) as u8, *n as u8],
        ClaimValue::Integer(n) => {
            // Negative: CBOR major type 1
            let abs = ((-1 - *n) as u64).to_be_bytes();
            let mut v = vec![0x3b];
            v.extend_from_slice(&abs);
            v
        }
        ClaimValue::String(s) => {
            let mut v = Vec::new();
            let len = s.len();
            if len <= 23 { v.push(0x60 + len as u8); }
            else { v.push(0x78); v.push(len as u8); }
            v.extend_from_slice(s.as_bytes());
            v
        }
        ClaimValue::Date { year, month, day } => {
            // fulldate tag 1004 + text
            let s = format!("{year:04}-{month:02}-{day:02}");
            let mut v = vec![0xD9, 0x03, 0xEC]; // tag(1004)
            v.push(0x60 + s.len() as u8); // text header
            v.extend_from_slice(s.as_bytes());
            v
        }
    }
}
```

- [ ] **Step 4: Verify build**

Run: `cd /data/Develop/zk-eidas-longfellow && cargo build -p zk-eidas-demo-api`

- [ ] **Step 5: Commit**

```bash
git add demo/api/src/main.rs
git commit -m "feat(demo-api): add Longfellow request translation helpers"
```

---

## Task 4: Rewire /holder/prove Endpoint

**Files:**
- Modify: `demo/api/src/main.rs` (`generate_proof` function, ~lines 362-491)

- [ ] **Step 1: Rewrite generate_proof() for Longfellow**

Replace the body of `generate_proof()`. The function parses the mdoc token, converts predicates to Longfellow `AttributeRequest`s, calls `longfellow_sys::mdoc::prove()`, and returns the proof in the same JSON shape.

```rust
async fn generate_proof(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, (StatusCode, String)> {
    if req.format != "mdoc" {
        return Err((StatusCode::NOT_IMPLEMENTED, "longfellow branch: mdoc only".into()));
    }

    let (mdoc_bytes, pkx, pky) = parse_mdoc_for_longfellow(&req.credential)?;

    // Parse mdoc to get claim values for CBOR encoding
    let (raw_bytes, pk_x_arr, pk_y_arr) = parse_mdoc_token(&req.credential)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let credential = zk_eidas_mdoc::MdocParser::parse_with_issuer_key(&raw_bytes, pk_x_arr, pk_y_arr)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc parse: {e}")))?;
    let claims = credential.claims();

    // Build Longfellow attributes from predicates
    let attrs: Vec<AttributeRequest> = req.predicates.iter().map(|p| {
        let value = claims.get(&p.claim)
            .ok_or((StatusCode::BAD_REQUEST, format!("claim '{}' not found", p.claim)))
            .unwrap(); // safe: credential was parsed
        let cbor = if p.op == "eq" || p.op == "disclosure" {
            claim_to_cbor(value)
        } else {
            // For gte/lte/neq: encode the threshold value from the request
            claim_to_cbor(&parse_predicate_value(&p.claim, &p.value))
        };
        predicate_to_attribute(&p.claim, &p.op, &cbor)
    }).collect();

    let circuit = get_circuit(&state, attrs.len()).await?;
    let now = req.now.as_deref().unwrap_or("2026-01-01T00:00:00Z");
    let transcript = b"zk-eidas-demo";
    let contract_hash = [0u8; 8]; // no nullifier for simple prove

    let _permit = state.prove_semaphore.acquire().await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "busy".into()))?;

    let proof = tokio::task::spawn_blocking(move || {
        longfellow_sys::mdoc::prove(
            &circuit_clone, &mdoc_bytes, &pkx, &pky,
            transcript, &attrs, now, &contract_hash,
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("prove: {e}")))
    }).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")))??;

    let proof_hex = format!("0x{}", hex::encode(&proof.proof_bytes));
    let results: Vec<ProofResult> = req.predicates.iter().map(|p| ProofResult {
        predicate: format!("{} {} {}", p.claim, p.op, p.value),
        proof_json: serde_json::to_string(&proof).unwrap_or_default(),
        proof_hex: proof_hex.clone(),
        op: p.op.clone(),
    }).collect();

    let hidden: Vec<String> = req.predicates.iter()
        .filter(|p| p.op == "eq" || p.op == "disclosure")
        .map(|p| p.claim.clone()).collect();

    Ok(Json(ProveResponse {
        proofs: results,
        hidden_fields: hidden,
        nullifier: None,
    }))
}
```

Note: This is a simplified version. The actual implementation needs to handle `circuit_clone` correctly (clone the circuit reference for the spawn_blocking closure). The `parse_predicate_value` helper converts threshold strings to `ClaimValue` — this already exists in the codebase as part of the predicate handling.

- [ ] **Step 2: Verify build**

Run: `cargo build -p zk-eidas-demo-api`

- [ ] **Step 3: Commit**

```bash
git add demo/api/src/main.rs
git commit -m "feat(demo-api): rewire /holder/prove to Longfellow"
```

---

## Task 5: Rewire /holder/prove-compound Endpoint

**Files:**
- Modify: `demo/api/src/main.rs` (`generate_compound_proof` function, ~lines 617-789)

Same pattern as Task 4 but with compound predicate grouping, caching, and optional escrow.

- [ ] **Step 1: Rewrite generate_compound_proof()**

Key changes:
1. Parse mdoc + extract claims (same as Task 4)
2. Convert all predicates to `AttributeRequest` list
3. Check proof cache — if hit and no escrow, return cached
4. Call `longfellow_sys::mdoc::prove()` with the attribute list
5. Serialize `MdocProof` to JSON as the compound proof
6. If escrow requested, generate AES-256-GCM escrow data (Task 8) and attach
7. Cache the result

The compound proof JSON format changes: instead of a `CompoundProof` with sub-proofs, it's a single `MdocProof` with all predicates proved at once.

- [ ] **Step 2: Verify build + commit**

---

## Task 6: Rewire /holder/prove-binding Endpoint

**Files:**
- Modify: `demo/api/src/main.rs` (`prove_binding` function, ~lines 889-1034)

- [ ] **Step 1: Rewrite prove_binding()**

Key changes:
1. Parse two mdoc credentials separately
2. Call `longfellow_sys::mdoc::prove()` for each, both with the binding claim as the first attribute
3. Compare `proof_a.binding_hash == proof_b.binding_hash`
4. Return both proofs + binding verification result

- [ ] **Step 2: Verify build + commit**

---

## Task 7: Rewire /holder/contract-prove Endpoint

**Files:**
- Modify: `demo/api/src/main.rs` (`contract_prove` function, ~lines 1206-1520)

- [ ] **Step 1: Rewrite contract_prove()**

Key changes:
1. Compute `contract_hash = SHA256(terms || timestamp)` truncated to 8 bytes (same as current)
2. Parse mdoc + build attribute list (same as Task 4)
3. Call `longfellow_sys::mdoc::prove()` with the `contract_hash` — nullifier is built-in
4. Return proof + `nullifier_hash` + `contract_hash` from the proof output
5. No separate nullifier proving step — it's all one call

This is the simplification win: the current code has a complex multi-stage flow (ECDSA commitment → nullifier proving → compound proving). Longfellow does it in one call.

- [ ] **Step 2: Verify build + commit**

---

## Task 8: Escrow Redesign — AES-256-GCM Encryption

**Files:**
- Modify: `crates/zk-eidas/Cargo.toml` (add `aes-gcm`)
- Modify: `crates/zk-eidas/src/escrow.rs` (replace Poseidon-CTR with AES-GCM)
- Modify: `crates/zk-eidas-types/src/proof.rs` (update `IdentityEscrowData`)

- [ ] **Step 1: Add aes-gcm dependency**

In `crates/zk-eidas/Cargo.toml`:

```toml
aes-gcm = "0.10"
```

- [ ] **Step 2: Update IdentityEscrowData struct**

In `crates/zk-eidas-types/src/proof.rs`, replace the old struct:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEscrowData {
    /// AES-256-GCM encrypted field values (one per field).
    pub ciphertexts: Vec<Vec<u8>>,
    /// AES-256-GCM authentication tags (one per field).
    pub tags: Vec<Vec<u8>>,
    /// K encrypted to the escrow authority via ML-KEM-768.
    pub encrypted_key: Vec<u8>,
    /// Escrow authority's ML-KEM-768 seed (64 bytes).
    pub authority_pubkey: Vec<u8>,
    /// Names of the encrypted credential fields.
    pub field_names: Vec<String>,
}
```

- [ ] **Step 3: Add AES-256-GCM encrypt function**

In `crates/zk-eidas/src/escrow.rs`, add:

```rust
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

/// Encrypt credential field values with AES-256-GCM.
/// Returns (ciphertexts, tags) where each field is encrypted with nonce = counter.
pub fn encrypt_fields_aes_gcm(
    fields: &[(&str, &[u8])],  // (field_name, field_bytes)
    key: &[u8; 32],
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), ZkError> {
    let cipher = Aes256Gcm::new(key.into());
    let mut ciphertexts = Vec::new();
    let mut tags = Vec::new();

    for (i, (_name, value)) in fields.iter().enumerate() {
        // Nonce = counter (12 bytes, big-endian)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[8..12].copy_from_slice(&(i as u32).to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = cipher.encrypt(nonce, value.as_ref())
            .map_err(|e| ZkError::InvalidInput(format!("AES-GCM encrypt: {e}")))?;
        // AES-GCM appends 16-byte tag to ciphertext
        let (ct_only, tag) = ct.split_at(ct.len() - 16);
        ciphertexts.push(ct_only.to_vec());
        tags.push(tag.to_vec());
    }

    Ok((ciphertexts, tags))
}
```

- [ ] **Step 4: Add AES-256-GCM decrypt function**

```rust
/// Decrypt credential field values with AES-256-GCM.
pub fn decrypt_fields_aes_gcm(
    ciphertexts: &[Vec<u8>],
    tags: &[Vec<u8>],
    key: &[u8; 32],
) -> Result<Vec<Vec<u8>>, ZkError> {
    let cipher = Aes256Gcm::new(key.into());
    let mut fields = Vec::new();

    for (i, (ct, tag)) in ciphertexts.iter().zip(tags.iter()).enumerate() {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[8..12].copy_from_slice(&(i as u32).to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Reconstruct ciphertext + tag for aes-gcm
        let mut ct_with_tag = ct.clone();
        ct_with_tag.extend_from_slice(tag);

        let plaintext = cipher.decrypt(nonce, ct_with_tag.as_ref())
            .map_err(|e| ZkError::InvalidInput(format!("AES-GCM decrypt: {e}")))?;
        fields.push(plaintext);
    }

    Ok(fields)
}
```

- [ ] **Step 5: Add escrow round-trip test**

```rust
#[test]
fn aes_gcm_escrow_round_trip() {
    let key = [0x42u8; 32];
    let fields = vec![
        ("name", b"Alice".as_slice()),
        ("dob", b"1990-01-15".as_slice()),
    ];
    let (cts, tags) = encrypt_fields_aes_gcm(&fields, &key).unwrap();
    let decrypted = decrypt_fields_aes_gcm(&cts, &tags, &key).unwrap();
    assert_eq!(decrypted[0], b"Alice");
    assert_eq!(decrypted[1], b"1990-01-15");
}

#[test]
fn aes_gcm_tampered_tag_fails() {
    let key = [0x42u8; 32];
    let fields = vec![("name", b"Alice".as_slice())];
    let (cts, mut tags) = encrypt_fields_aes_gcm(&fields, &key).unwrap();
    tags[0][0] ^= 0xff; // tamper
    assert!(decrypt_fields_aes_gcm(&cts, &tags, &key).is_err());
}
```

- [ ] **Step 6: Run tests**

Run: `cd /data/Develop/zk-eidas-longfellow && cargo test -p zk-eidas aes_gcm`
Expected: 2 tests PASS

- [ ] **Step 7: Commit**

```bash
git add crates/zk-eidas/Cargo.toml crates/zk-eidas/src/escrow.rs crates/zk-eidas-types/src/proof.rs
git commit -m "feat(escrow): replace Poseidon-CTR with AES-256-GCM encryption"
```

---

## Task 9: Rewire Verify Endpoints

**Files:**
- Modify: `demo/api/src/main.rs` (`verify_proof`, `verify_compound_proof`)

- [ ] **Step 1: Rewrite verify_proof()**

```rust
async fn verify_proof(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if req.format != "mdoc" {
        return Err((StatusCode::NOT_IMPLEMENTED, "longfellow branch: mdoc only".into()));
    }

    // Deserialize the MdocProof from the request
    let proof: MdocProof = serde_json::from_str(&req.proof_json)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid proof: {e}")))?;

    // Parse mdoc for issuer public key
    let (mdoc_bytes, pkx, pky) = parse_mdoc_for_longfellow(&req.credential)?;

    // Rebuild attributes from the verification request
    // ... (same predicate_to_attribute conversion)

    let circuit = get_circuit(&state, attrs.len()).await?;
    let contract_hash = [0u8; 8]; // extract from request if present

    let valid = tokio::task::spawn_blocking(move || {
        longfellow_sys::mdoc::verify(
            &circuit_clone, &proof, &pkx, &pky,
            transcript, &attrs, now, doc_type, &contract_hash,
        ).is_ok()
    }).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")))?;

    Ok(Json(serde_json::json!({
        "valid": valid,
        "nullifier_hash": hex::encode(proof.nullifier_hash),
        "binding_hash": hex::encode(proof.binding_hash),
    })))
}
```

- [ ] **Step 2: Rewrite verify_compound_proof() similarly**

Same pattern — deserialize MdocProof, call `longfellow_sys::mdoc::verify()`.

- [ ] **Step 3: Verify build + commit**

---

## Task 10: Escrow Client-Side Decryption Update

**Files:**
- Modify: `demo/web/app/lib/escrow-decrypt.ts`

- [ ] **Step 1: Replace Poseidon-CTR with WebCrypto AES-GCM**

```typescript
export async function decryptEscrow(
  encryptedKey: number[],
  secretKey: string,
  ciphertextFields: number[][],
  tags: number[][],
  fieldNames: string[],
  expectedBindingHash?: string,
): Promise<DecryptResult> {
  // Step 1: ML-KEM-768 decapsulate to recover K (unchanged)
  const { MlKem768 } = await import('mlkem')
  const mlkem = new MlKem768()
  const seedBytes = hexToBytes(secretKey)
  const [_ek, dk] = await mlkem.deriveKeyPair(seedBytes)

  const mlkemCtSize = encryptedKey.length - 32
  const mlkemCt = new Uint8Array(encryptedKey.slice(0, mlkemCtSize))
  const encryptedK = new Uint8Array(encryptedKey.slice(mlkemCtSize))

  const sharedSecret = await mlkem.decap(mlkemCt, dk)
  const mask = new Uint8Array(await crypto.subtle.digest('SHA-256', sharedSecret))
  const keyBytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) keyBytes[i] = encryptedK[i] ^ mask[i]

  // Step 2: AES-256-GCM decrypt each field
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
  )

  const fields: Record<string, string> = {}
  for (let i = 0; i < ciphertextFields.length; i++) {
    const nonce = new Uint8Array(12)
    new DataView(nonce.buffer).setUint32(8, i, false) // big-endian counter

    // Reconstruct ciphertext + tag
    const ctWithTag = new Uint8Array([...ciphertextFields[i], ...tags[i]])

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce }, cryptoKey, ctWithTag
    )
    fields[fieldNames[i]] = new TextDecoder().decode(plaintext)
  }

  // Step 3: Verify binding hash if provided
  let integrityValid = true
  if (expectedBindingHash && fieldNames.length > 0) {
    const bindingField = new TextEncoder().encode(fields[fieldNames[0]])
    const padded = new Uint8Array(32) // zero-padded to 32 bytes
    padded.set(bindingField.slice(0, 32))
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', padded))
    integrityValid = hex(hash) === expectedBindingHash
  }

  return { fields, integrityValid }
}
```

- [ ] **Step 2: Commit**

```bash
git add demo/web/app/lib/escrow-decrypt.ts
git commit -m "feat(web): replace Poseidon-CTR with WebCrypto AES-GCM for escrow decrypt"
```

---

## Task 11: Integration Test

**Files:**
- Modify: `demo/api/src/main.rs` (test module)

- [ ] **Step 1: Add Longfellow prove+verify integration test**

This test exercises the full flow: prove via `/holder/prove-compound` → store blob → retrieve → verify via `/verifier/verify-compound`. Uses a test mdoc credential with age_over_18 predicate.

Note: This test requires a real mdoc credential token. Use the existing test fixtures from the demo's test data or the pre-warm module.

- [ ] **Step 2: Run full test suite**

Run: `cd /data/Develop/zk-eidas-longfellow && cargo test -p zk-eidas-demo-api -- --test-threads=1`
Expected: All tests pass

- [ ] **Step 3: Final commit**

```bash
git add -A
git commit -m "test(demo-api): Longfellow integration test for full prove/verify flow"
```
