# zk-eidas Integrator Guide

A comprehensive guide for government integrators deploying zero-knowledge proof
verification of eIDAS 2.0 credentials.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Basic Usage](#basic-usage)
5. [Predicate Types](#predicate-types)
6. [Predicate Templates](#predicate-templates)
7. [Signed Proofs](#signed-proofs)
8. [Compound Proofs](#compound-proofs)
9. [Nullifiers](#nullifiers)
10. [QR Code Encoding](#qr-code-encoding)
11. [mdoc/mDL Support](#mdocmdl-support)
12. [Browser Verification](#browser-verification)
13. [Security Considerations](#security-considerations)

---

## Overview

**zk-eidas** is a Rust library for privacy-preserving verification of
[eIDAS 2.0](https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation)
digital identity credentials using zero-knowledge proofs.

### What it does

- Parses SD-JWT and mdoc/mDL credentials issued under eIDAS 2.0.
- Generates zero-knowledge proofs that a credential claim satisfies a predicate
  (e.g., "age >= 18") **without revealing the actual claim value**.
- Verifies those proofs on the server side, in a registry, or in the browser via
  a WASM SDK.

### Why zero-knowledge proofs?

| Traditional Verification | zk-eidas Verification |
|---|---|
| Verifier sees full birthdate | Verifier learns only "age >= 18" |
| Credential is linkable across services | Scoped nullifiers prevent cross-service tracking |
| All claims exposed to every relying party | Selective disclosure per interaction |

The cryptographic backend uses [Circom](https://docs.circom.io/) circuits with
Groth16 proofs via [ark-circom](https://github.com/gakonst/ark-circom) on the server
and [snarkjs](https://github.com/iden3/snarkjs) in the browser.

---

## Prerequisites

### Rust

Rust 1.75 or later is required.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update stable
rustc --version  # must be >= 1.75.0
```

### Circom

Circom 2.1+ is required for circuit compilation. See
[Circom installation](https://docs.circom.io/getting-started/installation/).

### snarkjs

snarkjs 0.7+ is used for browser-side proving and verification:

```bash
npm install -g snarkjs
```

### Pre-compiled Circuits

The circuits directory (`circuits/`) must contain compiled Circom circuits
(.r1cs, .wasm) and trusted setup files (.zkey) for each predicate type.
These are generated during the project build:

```bash
cd circuits && make
```

---

## Installation

Add `zk-eidas` to your `Cargo.toml`:

```toml
[dependencies]
zk-eidas = { git = "https://github.com/alik-eth/zk-eidas", branch = "main" }
```

For mdoc/mDL support, also add:

```toml
zk-eidas-mdoc = { git = "https://github.com/alik-eth/zk-eidas", branch = "main" }
```

---

## Basic Usage

The core workflow is: **parse credential, add predicate, prove, verify**.

```rust
use zk_eidas::{ZkCredential, ZkVerifier, Predicate};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sdjwt = "eyJ...~disclosure1~disclosure2~";
    let circuits = "circuits/predicates";

    // 1. Parse the SD-JWT and build a proof request
    let proof = ZkCredential::from_sdjwt(&sdjwt, circuits)?
        .predicate("birthdate", Predicate::gte(18))
        .prove()?;

    // 2. Verify the proof
    let valid = ZkVerifier::new(circuits)
        .verify(&proof)?;

    assert!(valid);
    println!("Proof verified: holder is at least 18 years old");
    Ok(())
}
```

### What happens under the hood

1. `from_sdjwt` parses the SD-JWT, extracts claims and ECDSA signature data.
2. `.predicate("birthdate", Predicate::gte(18))` registers a "birthdate >= 18
   years old" check. For date claims, `Gte(n)` automatically converts to an
   epoch-days comparison against today's date minus `n` years.
3. `.prove()` loads the appropriate Circom circuit, prepares witness inputs, and
   generates a Groth16 proof via ark-circom. ECDSA signature verification runs
   in a separate Stage 1 circuit, chained to the predicate circuit via Poseidon commitment.
4. `ZkVerifier::verify()` checks the Groth16 proof against the trusted
   verification key (.zkey).

---

## Predicate Types

zk-eidas supports six predicate types:

| Predicate | Constructor | Description | Example |
|---|---|---|---|
| **gte** | `Predicate::gte(threshold)` | Claim >= threshold (or age >= N for dates) | `Predicate::gte(18)` |
| **lte** | `Predicate::lte(threshold)` | Claim <= threshold | `Predicate::lte(65)` |
| **eq** | `Predicate::eq(value)` | Claim equals value (hash comparison) | `Predicate::eq("DE")` |
| **neq** | `Predicate::neq(value)` | Claim does not equal value | `Predicate::neq("revoked")` |
| **range** | Combine `gte` + `lte` via compound proof | Claim in [low, high] | See [Compound Proofs](#compound-proofs) |
| **set_member** | `Predicate::set_member(values)` | Claim is one of up to 16 values | `Predicate::set_member(vec!["DE", "FR", "IT"])` |

### Date handling

For `ClaimValue::Date` fields (e.g., `birthdate`), `Predicate::gte(n)` is
interpreted as "the holder is at least `n` years old." Internally, the library
computes an epoch-days cutoff (`today - n years`) and proves the birthdate is on
or before that cutoff.

### Numeric claims

For `ClaimValue::Integer` fields, predicates operate directly on the integer
value. Negative values are not supported in circuit inputs.

### String claims

For `eq`, `neq`, and `set_member`, string values are hashed (SHA-256) to 32-byte
field elements before entering the circuit.

---

## Predicate Templates

zk-eidas ships with pre-built templates for common government verification
scenarios. Each template returns a `(claim_name, predicate, description)` tuple.

```rust
use zk_eidas::{ZkCredential, templates};

let sdjwt = "eyJ...~disclosure~";
let circuits = "circuits/predicates";

// Use a built-in template
let (claim, predicate, description) = templates::age_over_18();
println!("Checking: {description}");

let proof = ZkCredential::from_sdjwt(&sdjwt, circuits)?
    .predicate(claim, predicate)
    .prove()?;
```

### Available templates

| Function | Claim | Predicate | Description |
|---|---|---|---|
| `templates::age_over_18()` | `birthdate` | `Gte(18)` | Holder is at least 18 years old |
| `templates::age_over_21()` | `birthdate` | `Gte(21)` | Holder is at least 21 years old |
| `templates::age_over_65()` | `birthdate` | `Gte(65)` | Holder is at least 65 years old |
| `templates::eu_nationality()` | `nationality` | `SetMember([27 EU states])` | Holder is an EU national |
| `templates::credential_not_revoked()` | `credential_status` | `Neq("revoked")` | Credential has not been revoked |
| `templates::schengen_residency()` | `resident_country` | `SetMember([26 Schengen states])` | Holder resides in Schengen area |

List all templates programmatically:

```rust
for (claim, predicate, desc) in templates::all() {
    println!("{claim}: {desc}");
}
```

---

## Signed Proofs

When the parsed credential contains ECDSA signature data (public key
coordinates, signature bytes, message hash, and SD-JWT disclosure hashes), zk-eidas
**automatically** selects the signed circuit variant. No additional API calls are
needed.

### How it works

1. The SD-JWT parser extracts the issuer's ECDSA P-256 public key (`pub_key_x`,
   `pub_key_y`), the signature (normalized to low-S form), and the message hash.
2. When `.prove()` is called, the library checks if ECDSA data is available and
   the disclosure for the requested claim exists.
3. If both are present, the `_signed` circuit variant is used (e.g.,
   `gte_signed` instead of `gte`), which verifies the ECDSA signature
   **inside the ZK circuit**. This binds the proof to a genuine issuer
   credential.
4. If ECDSA data is not available (e.g., opaque signature), the unsigned
   circuit is used, with the issuer public key hash as a public input.

### Verifying issuer binding

The verifier does not need to know which variant was used. `ZkVerifier::verify()`
reads the `predicate_op` field from the proof (e.g., `GteSigned` vs `Gte`) and
loads the correct circuit automatically.

```rust
// The same verification API works for both signed and unsigned proofs
let valid = ZkVerifier::new(circuits).verify(&proof)?;
```

---

## Compound Proofs

Compound proofs combine multiple predicates with AND/OR logic.

### AND: all predicates must hold

```rust
use zk_eidas::{ZkCredential, Predicate};

// Prove: 18 <= age <= 65 (range check via AND)
let compound = ZkCredential::from_sdjwt(&sdjwt, circuits)?
    .predicate("age", Predicate::and(vec![
        Predicate::gte(18),
        Predicate::lte(65),
    ]))
    .prove_compound()?;
```

### OR: at least one predicate must hold

```rust
// Prove: nationality is DE or nationality is FR
let compound = ZkCredential::from_sdjwt(&sdjwt, circuits)?
    .predicate("nationality", Predicate::or(vec![
        Predicate::eq("DE"),
        Predicate::eq("FR"),
    ]))
    .prove_compound()?;
```

### Verifying compound proofs

```rust
use zk_eidas::ZkVerifier;

let verifier = ZkVerifier::new(circuits);
let valid = verifier.verify_compound(&compound)?;
// AND: all sub-proofs must be valid
// OR: at least one sub-proof must be valid
```

### Multiple independent predicates

To prove multiple independent claims at once, use `prove_all()`:

```rust
let proofs = ZkCredential::from_sdjwt(&sdjwt, circuits)?
    .predicate("birthdate", Predicate::gte(18))
    .predicate("nationality", Predicate::set_member(vec!["DE", "FR", "IT"]))
    .prove_all()?;

// Verify each proof independently
let verifier = ZkVerifier::new(circuits);
for proof in &proofs {
    assert!(verifier.verify(proof)?);
}
```

---

## Nullifiers

Nullifiers allow relying parties to detect if the same credential has been
presented before, without learning the holder's identity. They are scoped, so
different services see different nullifiers for the same credential.

### Generating a nullifier

```rust
let proof = ZkCredential::from_sdjwt(&sdjwt, circuits)?
    .predicate("birthdate", Predicate::gte(18))
    .nullifier_scope("store-123:2026-03")
    .prove()?;

// The nullifier is attached to the proof
if let Some(nullifier) = proof.nullifier() {
    println!("Nullifier: {}", hex::encode(nullifier));
}
```

### Properties

- **Deterministic**: the same credential + scope always produces the same
  nullifier.
- **Unlinkable across scopes**: different scopes produce different nullifiers,
  preventing cross-service correlation.
- **Derived from credential secret**: uses the ECDSA message hash (unique per
  credential) as the secret input. For non-ECDSA credentials, the issuer public
  key hash is used as a fallback.

### Suggested scope formats

| Use Case | Scope Format | Example |
|---|---|---|
| Per-service, monthly | `{service-id}:{YYYY-MM}` | `pharmacy-42:2026-03` |
| Per-service, daily | `{service-id}:{YYYY-MM-DD}` | `bar-99:2026-03-11` |
| Per-transaction | `{service-id}:{tx-uuid}` | `gov-portal:550e8400-...` |

---

## QR Code Encoding

`ProofEnvelope` provides compact CBOR serialization and QR code generation for
offline proof transport.

### Creating an envelope

```rust
use zk_eidas::ProofEnvelope;

let proof = ZkCredential::from_sdjwt(&sdjwt, circuits)?
    .predicate("birthdate", Predicate::gte(18))
    .prove()?;

let envelope = ProofEnvelope::from_proofs(
    &[proof],
    &["age >= 18".to_string()],
);
```

### CBOR serialization

```rust
// Serialize to compact CBOR bytes
let cbor_bytes = envelope.to_bytes().unwrap();

// Deserialize
let decoded = ProofEnvelope::from_bytes(&cbor_bytes).unwrap();
assert_eq!(decoded.version(), 1);
assert_eq!(decoded.proofs().len(), 1);
```

### QR code generation

```rust
// Generate a QR code PNG image
let png_bytes = envelope.to_qr().unwrap();
std::fs::write("proof.png", &png_bytes).unwrap();
```

The QR code encodes the CBOR bytes directly. Scanning the QR code yields the raw
bytes that can be decoded with `ProofEnvelope::from_bytes()`.

### Envelope structure

Each envelope contains:

- `version` (u8): protocol version (currently 1).
- `proofs` (array): one or more proof entries, each with:
  - `predicate`: human-readable description (e.g., "age >= 18").
  - `proof_bytes`: raw Groth16 proof bytes.
  - `public_inputs`: circuit public inputs.
  - `op`: predicate operation (e.g., "Gte", "GteSigned").

---

## mdoc/mDL Support

zk-eidas supports ISO 18013-5 mdoc credentials (mobile driving licenses) via the
`zk-eidas-mdoc` crate.

### Parsing an mdoc

```rust
use zk_eidas_mdoc::MdocParser;
use zk_eidas::ZkCredential;

// mdoc_bytes: CBOR-encoded ISO 18013-5 document
let credential = MdocParser::parse(&mdoc_bytes)?;

// Use the parsed credential with the standard builder API
let proof = ZkCredential::from_credential(credential, "circuits/predicates")
    .predicate("birth_date", Predicate::gte(18))
    .prove()?;
```

### Supported claim types

The mdoc parser maps ISO 18013-5 element identifiers to `ClaimValue` types:

| Element Identifier | ClaimValue Type | Example |
|---|---|---|
| `birth_date` | `Date { year, month, day }` | `1998-05-14` |
| `given_name` | `String` | `"Олександр"` |
| `family_name` | `String` | `"Петренко"` |
| Integer elements | `Integer(i64)` | `42` |
| Boolean elements | `Boolean(bool)` | `true` |

### Limitations

- mdoc credentials currently produce `SignatureData::Opaque`, so unsigned circuit
  variants are used. Signed mdoc verification (COSE_Sign1) is planned for a
  future release.
- The parser reads the first document in the `documents` array.

---

## Browser Verification

Two approaches are available for browser-side proof handling:

### 1. Browser Proving & Verification via snarkjs

Full Groth16 proving and verification in the browser using snarkjs:

```bash
npm install snarkjs
```

```typescript
import * as snarkjs from 'snarkjs';

// Verify a Groth16 proof
const valid = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
```

> **Security note:** Verification keys must come from a trusted source (e.g.
> served as static assets from your deployment), not from the proof itself.
> The .zkey files used for proving must also be served from a trusted origin.

### 2. WASM Inspection SDK (`zk-eidas-wasm`)

Lightweight proof inspection and envelope decoding (no full verification):

```bash
cargo install wasm-pack
wasm-pack build crates/zk-eidas-wasm --target web
```

```typescript
import init, {
  parse_proof,
  decode_envelope,
  extract_proof_components,
  check_nullifier_duplicate,
} from './zk-eidas-wasm/pkg/zk_eidas_wasm.js';

await init();

// Parse a proof and inspect metadata
const meta = JSON.parse(parse_proof(proofJson));
console.log(meta.predicateOp);   // "Gte" or "GteSigned"
console.log(meta.hasNullifier);  // true/false
console.log(meta.proofSize);     // number of bytes

// Decode a CBOR envelope
const envelope = JSON.parse(decode_envelope(cborBytes));
console.log(envelope.version);   // 1
console.log(envelope.proofs);    // [{ predicate, op, proofSize }]

// Extract raw components for verification
const components = JSON.parse(extract_proof_components(proofJson));
// components.proof: number[] (proof bytes)
// components.vk: number[] (verification key bytes)
```

### Nullifier deduplication

```typescript
const known = JSON.stringify(["aabb...", "ccdd..."]);
const isDuplicate = check_nullifier_duplicate(known, "aabb...");
// true if the nullifier was already seen
```

---

## Security Considerations

### Verification key derivation

Verification keys (VKs) are derived from the trusted setup (.zkey files).
This means **the verifier must trust the .zkey and verification key files**. If an attacker can
substitute modified keys, they can forge proofs.

Mitigations:

- Ship circuits as part of your deployment artifact; do not load them from
  user-supplied paths.
- Pin circuit bytecode hashes in your configuration.
- Use `TrustedCircuitRegistry` to load circuits once at startup and verify
  against known hashes.

### TrustedCircuitRegistry

For production deployments, use `TrustedCircuitRegistry` instead of loading
circuits from disk on every verification:

```rust
use zk_eidas_verifier::{TrustedCircuitRegistry, RegistryVerifier};

// Load all circuits at startup
let registry = TrustedCircuitRegistry::from_directory("circuits/predicates")?;

// Create a verifier bound to the registry
let verifier = RegistryVerifier::new(registry);

// Verify proofs without filesystem access
let valid = verifier.verify(&proof)?;
```

This approach:

- Loads circuits once, avoiding TOCTOU (time-of-check/time-of-use) races.
- Keeps circuit bytecode in memory, preventing on-disk tampering between loads.
- Allows you to audit exactly which circuits are loaded at startup.

### Issuer binding

When ECDSA signature data is present, the signed circuit variants verify the
issuer's signature **inside the zero-knowledge proof**. This means:

- The proof is bound to a specific issuer public key.
- The verifier can check the issuer public key hash (a public input) against a
  list of trusted issuers.
- Forging a proof would require either breaking ECDSA or finding a collision in
  the circuit.

For unsigned proofs, the issuer public key hash is still included as a public
input, but the signature is not verified in-circuit. Use unsigned proofs only for
testing or when the credential format does not support ECDSA extraction.

### Nullifier scope design

- Choose scopes that prevent cross-service correlation. A scope like
  `"my-service:2026-03"` ensures nullifiers are unique per service per month.
- Never use the same scope across different relying parties.
- Rotate scopes periodically (e.g., monthly) to limit the window for replay
  detection.

### Credential freshness

zk-eidas does not enforce credential expiration. Integrators should:

- Check the credential's `exp` claim (if present) before generating proofs.
- Use time-bound nullifier scopes to limit proof reuse.
- Consider adding an `issued_at` predicate (e.g., `Predicate::gte(recent_epoch)`)
  for freshness checks.

### Transport security

- Always transmit proofs over TLS.
- QR codes are not encrypted; they contain the proof in cleartext CBOR. Use them
  only for in-person verification scenarios.
- For remote verification, prefer transmitting the CBOR envelope over an
  authenticated channel rather than scanning QR codes from photos.

---

## Error Handling

All fallible operations return `Result<T, ZkError>`. The error variants are:

| Variant | Cause |
|---|---|
| `ZkError::Parse(e)` | SD-JWT parsing failed (malformed token, missing claims) |
| `ZkError::Prover(e)` | Circuit loading or proof generation failed |
| `ZkError::Verifier(e)` | Proof verification failed (corrupt proof, wrong circuit) |
| `ZkError::ClaimNotFound(name)` | Requested claim not present in credential |
| `ZkError::UnsupportedPredicate` | Predicate type not supported for claim type (e.g., string with `gte`) |

```rust
use zk_eidas::ZkError;

match result {
    Ok(proof) => { /* use proof */ }
    Err(ZkError::ClaimNotFound(name)) => {
        eprintln!("Credential does not contain claim: {name}");
    }
    Err(e) => {
        eprintln!("Proof generation failed: {e}");
    }
}
```
