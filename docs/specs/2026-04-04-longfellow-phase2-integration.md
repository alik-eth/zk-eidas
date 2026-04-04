# Longfellow Phase 2: Demo Integration, Escrow, Proof Storage

**Date:** 2026-04-04
**Branch:** `longfellow`
**Status:** Approved

## Overview

Three changes to complete the Longfellow migration:

1. **Demo-API rewire** — replace Circom/Groth16 proving with `longfellow_sys::mdoc`
2. **Escrow redesign** — out-of-circuit AES-256-GCM with in-circuit hash binding
3. **Proof blob store** — content-addressed store for 361KB Ligero proofs

## 1. Demo-API Rewire

### Approach

Same 6 API endpoints, different backend. All Circom/rapidsnark calls replaced with `longfellow_sys::mdoc::prove()` and `verify()`.

### Endpoint Mapping

| Endpoint | Current | Longfellow |
|---|---|---|
| `/holder/prove` | `builder.prove_all()` | `mdoc::prove()` with predicates as attributes |
| `/holder/prove-compound` | `builder.prove_compound()` | same `mdoc::prove()` |
| `/holder/prove-binding` | `builder.prove_with_binding()` ×2 | `mdoc::prove()` ×2, compare `binding_hash` |
| `/holder/contract-prove` | `prover.prove_nullifier()` + `builder.prove_compound()` | `mdoc::prove()` with `contract_hash` — nullifier is built-in |
| `/verifier/verify` | `verifier.verify()` | `mdoc::verify()` |
| `/verifier/verify-compound` | `verifier.verify_compound()` | same `mdoc::verify()` |

### State Changes

- `AppState` gains `OnceCell<MdocCircuit>` per attribute count (1–4), replacing `circuits_path`
- Circuit generated once on first request per attribute count, cached in OnceCell
- Proof cache stores serialized `MdocProof` (proof_bytes + nullifier_hash + binding_hash)
- SD-JWT endpoints return 501 on the longfellow branch (mdoc only)

### Request Translation

Each endpoint converts its request into Longfellow's flat model:

```
RequestedAttribute {
    namespace: "org.iso.18013.5.1",
    identifier: "birth_date",
    cbor_value: [0xD9, 0x03, 0xEC, 0x6A, ...],  // CBOR-encoded threshold
    verification_type: VERIFY_LEQ,                 // predicate packed in vlen bits
}
```

For equality (disclosure), `verification_type = VERIFY_EQ` and `cbor_value` is the actual value.
For predicates (gte/lte/neq), the appropriate `VerificationType` is set.

### Response Format

Responses keep the same JSON shape. The proof payload changes from Groth16 proof elements to an opaque proof blob (hex-encoded). Nullifier and binding_hash are returned as top-level fields.

## 2. Escrow Redesign

### Architecture

Two layers:

1. **In-circuit (Longfellow):** The existing `binding_hash = SHA-256(oa[0].v1[0..31])` commits the proof to the binding claim's value. No new circuit additions needed.

2. **Out-of-circuit (Rust):** Standard authenticated encryption of credential fields.

### Encryption Flow

```
Prover side:
  1. Generate random 256-bit key K
  2. For each field i:
       (ct_i, tag_i) = AES-256-GCM(K, nonce=i, field_bytes_i)
  3. encrypted_key = ML-KEM-768.Encapsulate(K, authority_ek)
  4. Bundle: { encrypted_key, ciphertexts[], tags[], field_names[] }

Verifier/Authority side:
  1. K = ML-KEM-768.Decapsulate(encrypted_key, authority_dk)
  2. For each field i:
       field_bytes_i = AES-256-GCM.Decrypt(K, nonce=i, ct_i, tag_i)
  3. Verify: SHA-256(binding_field_bytes) == binding_hash from ZK proof
```

### Trust Model

- **AES-256-GCM tags** guarantee ciphertext integrity (any tampering detected)
- **binding_hash in the ZK proof** commits to the binding claim value inside the circuit
- The authority verifies `SHA-256(decrypted_binding_field) == binding_hash` after decryption
- Other fields are trusted by GCM authentication — same key session, tamper-evident

### Dependencies

- Replace `poseidon` escrow path with `aes-gcm` crate
- ML-KEM-768 stays as-is (already in `crates/zk-eidas/src/escrow.rs`)
- Client-side decryption: replace Poseidon-CTR JS with WebCrypto AES-GCM

### What Gets Removed

- `circuits/identity_escrow/identity_escrow.circom` — no longer used
- `prover.prove_identity_escrow()` — replaced by out-of-circuit encryption
- `ClaimValue::to_escrow_field()` — BN254 packing no longer needed
- Poseidon-CTR keystream logic (Rust + TypeScript)

## 3. Proof Blob Store

### Endpoints

- `POST /proofs` — accepts raw proof bytes, returns `{ "cid": "<sha256-hex>" }`
- `GET /proofs/:cid` — returns raw proof bytes (application/octet-stream)

### Storage

In-memory `HashMap<String, Vec<u8>>` on `AppState`. Demo only, no persistence. Proofs are ~361KB each.

### CID Computation

`SHA-256(proof_bytes)` hex-encoded. Not actual IPFS CID format, but same content-addressing principle. Swappable to real IPFS later by replacing the store backend.

### Integration

After proving, the API stores the proof blob and returns the CID. The QR code on printed documents contains `https://<host>/proofs/<cid>`. The verify page fetches proof bytes from that URL, then calls `/verifier/verify`.

### Deduplication

Same proof bytes → same CID → same entry. Natural dedup from content addressing.

## Implementation Order

1. **Proof blob store** — two simple endpoints, no dependencies
2. **Demo-API rewire** — swap proving backend, update all 6 endpoints
3. **Escrow redesign** — replace Poseidon-CTR with AES-256-GCM, update client decryption

Order rationale: blob store is trivial and unblocks QR testing. API rewire is the core migration. Escrow is the most self-contained change and can be done last.

## Testing

- All existing E2E tests adapted to use Longfellow backend
- Prove + verify round trip for all 4 contract templates
- Escrow encrypt → decrypt → verify binding_hash
- Blob store: upload → retrieve → verify content match
- Performance: prove+verify < 3s (cached circuit)
