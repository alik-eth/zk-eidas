# zk-eidas

Zero-knowledge selective disclosure for eIDAS 2.0 credentials.

An open-source circuit library that takes any eIDAS 2.0 credential (SD-JWT VC or mdoc/mDL) and lets the holder prove predicates about their claims — without revealing the underlying values. A citizen proves "I am over 18" and the verifier learns nothing else. ECDSA P-256 signature verification happens inside the ZK circuit, cryptographically binding proofs to authentic, already-issued government credentials.

**[Live Demo](https://zk-eidas.com)**

## How It Works

```
Credential (SD-JWT VC or mdoc) → Parser → Witness → Circom Circuit → Groth16 Proof → Verifier
```

Two-stage proving architecture:

1. **Stage 1 — ECDSA verification.** The issuer's P-256 signature is verified inside a Circom circuit (~2M constraints). Outputs a Poseidon commitment binding the claim value to the authenticated credential.
2. **Stage 2 — Predicate evaluation.** A lightweight predicate circuit (gte, lte, eq, neq, range, set_member) consumes the commitment and proves the predicate holds, without revealing the claim value.

One proof covers the full chain: **issuer → credential → claim → predicate**.

## Supported Predicates

| Predicate | Description | Example |
|-----------|-------------|---------|
| `gte` | Greater than or equal | `age >= 18` |
| `lte` | Less than or equal | `age <= 65` |
| `eq` | Equality | `status == "active"` |
| `neq` | Not equal | `status != "revoked"` |
| `range` | Range check | `18 <= age <= 25` |
| `set_member` | Set membership (up to 16) | `nationality in {"DE", "FR"}` |
| `nullifier` | Scoped replay prevention | One proof per service per credential |
| `holder_binding` | Cross-credential linking | Same holder, different credentials |

## Quick Start

```rust
use zk_eidas::{ZkCredential, Predicate, ZkVerifier};

// Prove age >= 18 with ECDSA signature verified in-circuit
let proof = ZkCredential::from_sdjwt(&sdjwt, "circuits/predicates")?
    .predicate("birthdate", Predicate::gte(18))
    .prove()?;

// Verifier learns nothing except that the predicate holds
let valid = ZkVerifier::new("circuits/predicates").verify(&proof)?;
```

## Paper Proofs

Groth16 proofs are ~128 bytes. zk-eidas encodes them as QR codes with a chunked binary protocol, so proofs can be printed on paper and verified offline with a phone camera. No internet, no app store, no institutional infrastructure.

The [verify page](https://zk-eidas.com/verify) is a PWA — install it once, verify proofs offline forever.

## Architecture

| Crate | Purpose |
|-------|---------|
| `zk-eidas` | Facade — builder API, predicate templates |
| `zk-eidas-types` | Shared types — credentials, proofs, predicates |
| `zk-eidas-parser` | SD-JWT VC parser — claims, disclosures, key extraction |
| `zk-eidas-mdoc` | mdoc/mDL parser — ISO 18013-5 CBOR credentials |
| `zk-eidas-prover` | Witness generation (C++ binaries) + Groth16 proving (rapidsnark) |
| `zk-eidas-verifier` | Proof verification + trusted circuit registry |
| `zk-eidas-utils` | Date conversion, age calculation, field arithmetic |
| `zk-eidas-wasm` | WASM bindings for browser |
| `cbor-print` | Chunked QR protocol for paper proof transport |

9 Circom circuits. Groth16 proofs. Browser verification via snarkjs.

## Building

```bash
# Prerequisites: Rust 1.93+, Circom 2.1+, snarkjs 0.7+, Node 22+, jq

# Download large circuit artifacts (zkeys, ptau files)
cd circuits && ./download-artifacts.sh

# Build predicate circuits from source (fast, ~30s)
make predicates specials

# Build and test
cd .. && cargo test --workspace
```

## Circuit Artifacts

Large binary files (zkeys, ptau, CVM) are hosted externally. URLs are tracked in `circuits/artifact-urls.json`.

```bash
# Download artifacts for local development
cd circuits && ./download-artifacts.sh

# After recompiling circuits, upload new artifacts
source .env.production && node scripts/upload-artifacts.mjs
```

| File | Size | Host |
|------|------|------|
| `ecdsa_verify.zkey` | 1.2 GB | UploadThing |
| `ecdsa_verify.cvm` | 58 MB | UploadThing |
| `pot21.ptau` | 2.4 GB | Hermez ceremony (Google Storage) |
| `pot22.ptau` | 4.6 GB | Hermez ceremony (Google Storage) |
| Predicate zkeys (8x) | ~2 MB | Git repo |

## Standards

- **eIDAS 2.0** — EU Digital Identity Framework, ARF requirement ZKP_06
- **SD-JWT VC** — RFC 9901, EUDI Wallet credential format
- **mdoc/mDL** — ISO 18013-5 CBOR mobile credentials
- **ECDSA P-256** — secp256r1 / ES256, the curve used by EU member state issuers

## License

Apache 2.0 — see [LICENSE](LICENSE)
