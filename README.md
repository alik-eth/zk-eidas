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
| `identity_escrow` | Encrypted identity recovery | Decrypt only by escrow authority |

## Identity Escrow

ZK proofs remove personal data from documents. But if parties are anonymous, how do you protect rights in court? Identity escrow solves this: credential data is encrypted inside the ZK proof, decryption is only possible by a chosen escrow authority per established procedure.

```
                    INSIDE ZK CIRCUIT                         OUTSIDE CIRCUIT
               ┌─────────────────────────┐
               │                         │
credential[8] ─│  Commitment chain       │
claim_value ──▶│  ECDSA P-256 binding    │──▶ credential_hash  (public)
K ─────────────│  Poseidon-CTR encrypt   │──▶ ciphertext[8]    (public)
               │  Poseidon(K)            │──▶ key_commitment    (public)
               │                         │
               └─────────────────────────┘
                                                     │
                                                     ▼
                                            ML-KEM-768 encrypt(K, authority_key)
                                                     │
                                                     ▼
                                               encrypted_key (1120 bytes)
                                                     │
                               ┌─────────────────────┼──────────────────────┐
                               │                     │                      │
                         ON-CHAIN PROOF        ESCROW ENVELOPE         AUTHORITY
                         ──────────────       ────────────────        ─────────
                         credential_hash       ciphertext[8]          seed (64B)
                         key_commitment        encrypted_key               │
                         Groth16 proof         field_names            court order
                         (nothing to           (post-quantum              │
                          decrypt)              safe: ML-KEM)             ▼
                                                                    decrypt K
                                                                    Poseidon-CTR decrypt
                                                                    recover identity
                                                                    verify hash
```

**Key properties:**

- **Honest encryption** — Poseidon-CTR runs inside the same circuit that verifies the ECDSA signature. A party cannot encrypt garbage because the proof binds ciphertext to government-signed data.
- **Pluggable authority** — the escrow authority is a contract parameter: notary, arbitrator, state registry, or smart contract. Both parties agree at signing.
- **Quantum-safe envelope** — ML-KEM-768 (NIST FIPS 203) replaces ECIES. The escrow blob can be published without fear of future quantum decryption. The ZK proof itself contains no ciphertext — only Poseidon hashes.
- **Minimal overhead** — encryption adds ~2,500 constraints (+0.13% over the ~2M base ECDSA circuit).

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
| `zk-eidas-wasm` | WASM bindings for browser — credential parsing (SD-JWT + mdoc), proof inspection |
| `cbor-print` | Chunked QR protocol for paper proof transport |

10 Circom circuits (6 predicates + ecdsa_verify + nullifier + holder_binding + identity_escrow). Groth16 proofs. Server proving via rapidsnark. On-device browser proving via chunked snarkjs fork (zkey sections loaded from IndexedDB on demand, ~1.5 GB peak memory instead of ~3 GB).

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

## Testing

```bash
# Rust unit + integration tests (252 tests)
cargo test --workspace

# Circom circuit constraint tests (26 tests)
cd circuits && npm test

# WASM browser tests (Chrome + Firefox)
cd crates/zk-eidas-wasm && wasm-pack test --headless --chrome --firefox

# Web unit tests (vitest — QR chunking, nullifier check, chunked zkey loader)
cd demo/web && npx vitest run

# E2E tests — server-side proving (requires running container)
cd demo/web && E2E_BASE_URL=http://127.0.0.1:8080 npx playwright test

# E2E tests — on-device browser proving (slow, ~5-10 min per contract)
cd demo/web && E2E_BASE_URL=http://127.0.0.1:8080 E2E_ON_DEVICE=1 npx playwright test
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
| ECDSA zkey chunks (10 sections) | 1.2 GB total | UploadThing |
| `ecdsa_verify.cvm` | 58 MB | UploadThing |
| `pot21.ptau` | 2.4 GB | Hermez ceremony (Google Storage) |
| `pot22.ptau` | 4.6 GB | Hermez ceremony (Google Storage) |
| Predicate + special zkeys (10x) | ~2 MB | Git repo |

ECDSA chunk files are split per-section (`ecdsa_verify.zkeyb` through `.zkeyk`) for on-device browser proving. The browser downloads them into IndexedDB and the chunked snarkjs fork reads sections on demand during proving.

## Standards

- **eIDAS 2.0** — EU Digital Identity Framework, ARF requirement ZKP_06
- **SD-JWT VC** — RFC 9901, EUDI Wallet credential format
- **mdoc/mDL** — ISO 18013-5 CBOR mobile credentials
- **ECDSA P-256** — secp256r1 / ES256, the curve used by EU member state issuers

## License

Apache 2.0 — see [LICENSE](LICENSE)
