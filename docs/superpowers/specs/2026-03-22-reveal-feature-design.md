# Reveal Feature: Selective Disclosure of Credential Fields

**Date:** 2026-03-22
**Status:** Draft

## Summary

Add the ability for users to selectively reveal actual claim values from their credentials alongside ZK predicate proofs. A revealed field produces a ZK proof that the value came from a valid issuer-signed credential, with the value itself exposed as a public circuit input. Reveal and predicates are presented in the same UI list — for each field the user either proves a predicate about it or reveals its actual value.

## Motivation

Currently, all claim values are private in the circuits. The verifier only sees that a predicate was satisfied (e.g., "age >= 18" passed) but never the actual value. Many real-world scenarios require seeing specific fields — document numbers for registry cross-referencing, names for identity confirmation, VINs for vehicle checks — while keeping other fields private.

## Approach: Hybrid (eq circuit reuse)

Reveal uses the existing `eq` circuit under the hood. When the user selects a field to reveal:

1. The builder extracts the claim's value from the credential
2. Generates an `eq(value)` proof — the `expected` public input IS the value
3. The circuit verifies `claim_value == expected` against the ECDSA commitment
4. The value is cryptographically bound to the issuer's signature

A `Predicate::Reveal` variant provides clean API semantics (internally maps to eq). This can later be swapped for a dedicated reveal circuit with fewer constraints — no API changes needed.

### Value encoding by claim type

- **Integer** (`ClaimValue::Integer(n)`): circuit input is `n as u64`, revealed value in envelope is `n.to_string()` (e.g., `"2023"`)
- **Date** (`ClaimValue::Date`): circuit input is epoch days (u64), revealed value in envelope is the original `"YYYY-MM-DD"` string (e.g., `"1998-05-14"`). Verifier converts the date string to epoch days before comparing to the public input.
- **String** (`ClaimValue::String(s)`): circuit input is `bytes_to_u64(&Sha256::digest(s))` (first 8 bytes of SHA-256 as big-endian u64). The envelope carries the plaintext. Verifier checks `bytes_to_u64(&Sha256::digest(plaintext)) == public_input`.
- **Boolean** (`ClaimValue::Boolean(b)`): circuit input is `0` or `1`. Not expected for reveal (booleans are better as predicates).

### Semantic difference from Eq

`Predicate::Eq(String)` requires the caller to supply the expected value — the verifier chooses what to compare against. `Predicate::Reveal` takes no arguments — the builder auto-extracts the value from the credential. This is the key distinction: Eq asks "does this field match X?", Reveal says "show what this field actually is."

## Revealable Fields

Only fields where seeing the actual value is useful. Dates and booleans are better served by predicates.

| Credential | Revealable Fields |
|---|---|
| PID | `document_number`, `given_name`, `family_name`, `nationality` |
| Driver's License | `license_number`, `holder_name`, `category` |
| Diploma | `diploma_number`, `student_name`, `university`, `degree`, `field_of_study` |
| Student ID | `student_number`, `student_name`, `university`, `faculty` |
| Vehicle | `vin`, `plate_number`, `owner_name`, `owner_document_number` |

## Changes by Layer

### 1. Rust Types (`zk-eidas-types`)

Add `Reveal` variant to `PredicateOp`:

```rust
pub enum PredicateOp {
    Gte, Lte, Eq, Neq, Range, SetMember, Nullifier,
    Reveal,  // NEW
}
```

Extend `EnvelopeProof` with optional revealed value fields:

```rust
pub struct EnvelopeProof {
    pub predicate: String,
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<Vec<u8>>,
    pub op: String,
    // NEW: revealed value data (for Reveal proofs)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revealed_claim: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revealed_value: Option<String>,
}
```

These fields are CBOR-serialized into the envelope, so scanners can read the revealed value from QR codes.

### 2. Facade (`zk-eidas`)

Add `Predicate::Reveal` variant:

```rust
pub enum Predicate {
    Gte(i64), Lte(i64), Eq(String), Neq(String),
    Range(i64, i64), SetMember(Vec<String>),
    And(Vec<Predicate>), Or(Vec<Predicate>),
    Reveal,  // NEW
}
```

In `prove_single()`, handle `Reveal`:
- Extract the claim value from the credential
- Convert to circuit representation (u64 for integers/dates, sha256_trunc for strings)
- Generate an eq proof with the extracted value as `expected`
- Tag the resulting `ZkProof` with `PredicateOp::Reveal`

Add `revealed_value()` method on `ZkProof` or expose the plaintext value through the proof result so the API can include it in the envelope.

### Verifier routing

The verifier uses `proof.predicate_op()` to load circuit artifacts. Since there is no `reveal.circom`, the verifier must map `PredicateOp::Reveal` to the `eq` circuit's verification key. In `verify()`, when `op == Reveal`, resolve it as `Eq` for circuit loading purposes.

### Envelope construction

`ProofEnvelope::from_proofs()` currently accepts `&[ZkProof]` and `&[String]` descriptions. To populate `revealed_claim`/`revealed_value`, add a new constructor:

```rust
pub fn from_proofs_with_reveals(
    proofs: &[ZkProof],
    descriptions: &[String],
    reveals: &[Option<(String, String)>],  // (claim_name, plaintext_value)
) -> Self
```

The existing `from_proofs()` remains unchanged (passes empty reveals).

### 3. Demo API (`demo/api`)

Add `"reveal"` to `parse_predicate()`:

```rust
"reveal" => Ok(Predicate::Reveal),
```

In the prove handler, when building the `ProofEnvelope`, populate `revealed_claim` and `revealed_value` for Reveal proofs:
- `revealed_claim`: the claim name (e.g., "document_number")
- `revealed_value`: the plaintext value from the credential (e.g., "UA-1234567890")

In the proof-export endpoint, include revealed values in the response so the frontend can display them in print.

### 4. Demo UI (`demo/web`)

#### credential-types.ts

Add reveal entries alongside existing predicates for each credential. Reveal entries use `op: "reveal"`:

```typescript
// PID example
{ id: 'reveal_doc', labelKey: 'demo.revealDocNumber', descKey: 'demo.revealDocNumberDesc',
  predicate: { claim: 'document_number', op: 'reveal', value: null },
  defaultChecked: false },
{ id: 'reveal_name', labelKey: 'demo.revealGivenName', descKey: 'demo.revealGivenNameDesc',
  predicate: { claim: 'given_name', op: 'reveal', value: null },
  defaultChecked: false },
// ... etc for each revealable field
```

#### demo.tsx (Holder step)

Render reveal entries with distinct visual treatment:
- Different icon (eye icon for reveal vs shield/check for predicates)
- Label like "Reveal: Document Number" vs "Prove: Age >= 18"
- Same checkbox interaction — user toggles each independently

#### demo.tsx (handlePrintProof)

For reveal predicates:
- Set `disclosed: true` on the `PrintPredicate`
- Set `publicValue` to the actual field value (not a threshold)
- Add `revealedValue` field with the plaintext

#### demo.tsx (PrintStep) and print.tsx

Already supports `disclosed` boolean. Changes:
- For `disclosed: true`, show the revealed value prominently in blue
- Column shows actual value instead of threshold
- Status column shows "PUBLIC" in blue (already implemented, just needs `disclosed: true`)

### 5. QR/Envelope

The `EnvelopeProof` CBOR structure gains `revealed_claim` and `revealed_value` optional fields. Since these are `skip_serializing_if = "Option::is_none"`, non-reveal proofs have zero overhead.

Scanner/verifier flow:
1. Decode CBOR envelope from QR chunks
2. For each proof where `revealed_claim` is present:
   - Read `revealed_value` (plaintext)
   - Read the `expected` public input from the eq circuit's public inputs
   - For string claims: verify `bytes_to_u64(&Sha256::digest(revealed_value)) == expected`
   - For date claims: convert `"YYYY-MM-DD"` to epoch days, verify it matches `expected`
   - For integer claims: parse as integer, verify it matches `expected`
3. Verify the Groth16 proof as usual

### 6. i18n

Add translation keys for each reveal option:

```typescript
'demo.revealDocNumber': 'Reveal document number',
'demo.revealDocNumberDesc': 'Disclose the actual document number with ZK proof of authenticity',
// ... etc for each revealable field per credential
```

## What Does NOT Change

- **Circuits**: no new circuits needed — reuses eq
- **ECDSA stage**: unchanged — commitment generation is the same
- **QR chunking protocol**: header format unchanged, only CBOR payload grows slightly
- **Verification logic**: eq verification works as-is
- **Predicate proving**: existing predicates are unaffected

## Testing

- **Unit tests**: `Predicate::Reveal` generates valid eq proof, revealed value matches
- **Integration test**: reveal + predicate combo on same credential
- **Envelope roundtrip**: CBOR encode/decode with revealed values
- **String reveal**: verify `sha256_trunc(plaintext) == public_input`
- **Demo API test**: `/holder/prove` with `op: "reveal"` returns correct response
- **Print rendering**: `disclosed: true` shows value in blue

## Scope: Server-Side Only

This feature covers the server-side Rust proving path and the demo UI. The WASM/browser proving path (snarkjs) is out of scope for this iteration — the browser already uses the eq circuit, so adding Reveal there later is straightforward.

## Future Optimization

Replace eq circuit with a dedicated `reveal.circom` that only verifies the commitment and outputs `claim_value` — fewer constraints, faster proving. The `Predicate::Reveal` API stays the same.
