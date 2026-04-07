# System Overview

## Pipeline

```
mdoc Credential → MdocParser → Witness → Longfellow Hash Circuit → Sumcheck+Ligero Proof → Verifier
```

A credential holder submits their ISO 18013-5 mdoc to the prover. The mdoc parser extracts claims and the issuer's ECDSA signature. Longfellow builds a witness from the requested attributes, generates a SHA-256 hash circuit, and produces a proof via the Sumcheck + Ligero protocol. The verifier checks the proof against the same circuit specification and public inputs, learning nothing beyond whether the predicates hold.

## Workspace

The project is a Rust workspace with 7 crates:

| Crate | Responsibility |
|-------|---------------|
| **zk-eidas** | Facade crate. Exports `Predicate` enum, `ZkError`, escrow utilities (`encrypt_fields_aes_gcm`, `encrypt_key_to_authority`), and predicate templates. No proving logic — that moved to `longfellow-sys`. |
| **zk-eidas-types** | Shared types: `Credential`, `ClaimValue` (String/Integer/Date/Boolean), `CompoundProof`, `ProofEnvelope`, `LogicalOp`, `IdentityEscrowData`, `EcdsaCommitment`. |
| **zk-eidas-mdoc** | ISO 18013-5 mdoc parser. Navigates CBOR to `issuerSigned → nameSpaces`, extracts claims, optionally parses COSE_Sign1 for ECDSA signature data (pub_key_x/y, signature, message hash). |
| **zk-eidas-utils** | Date conversion (`date_to_epoch_days`, `epoch_days_to_ymd`), age calculation, field arithmetic helpers. |
| **longfellow-sys** | FFI bindings to the Longfellow C++ library. Wraps circuit generation, proving, and verification. Exports `MdocCircuit` (serializable cached circuits), `AttributeRequest`, `MdocProof`, and the `prove()`/`verify()` functions. |
| **cbor-print** | Chunked QR transport protocol. Splits binary payloads into QR-sized chunks with 8-byte headers, deflate-raw compression, and multi-document support for AND/OR compound proofs. |
| **zk-eidas-demo-api** | Axum-based demo server with 21 API endpoints covering issuance, proving, verification, escrow, TSP attestation, and a content-addressed proof blob store. |

## Data Flow

**Issuance:**
1. Issuer creates an mdoc credential with claims (name, birthdate, nationality, document_number, etc.)
2. Issuer signs with ECDSA P-256, producing COSE_Sign1 IssuerAuth
3. Credential encoded as CBOR per ISO 18013-5

**Proving:**
1. `MdocParser::parse_with_issuer_key()` extracts claims + ECDSA signature data
2. Requested attributes built as `AttributeRequest` structs with `VerifyType` (Eq/Leq/Geq/Neq)
3. `longfellow_sys::mdoc::prove()` generates a single proof covering all predicates + nullifier + binding in one call
4. Returns `MdocProof` with `proof_bytes`, `nullifier_hash`, `binding_hash`
5. If identity escrow is requested: AES-256-GCM encrypts credential fields, ML-KEM-768 encrypts the symmetric key

**Verification:**
1. `longfellow_sys::mdoc::verify()` checks proof against circuit spec + public inputs
2. Server returns validity status for each sub-predicate
3. If contract: verifier cross-checks `SHA-256(terms || timestamp)` against embedded contract_hash
4. If QEAA attestation present: offline ECDSA P-256 signature verification via Web Crypto API

## Configuration

The demo API uses environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | 3001 | API server port |
| `CIRCUIT_CACHE_PATH` | (none) | Directory with pre-generated circuit files for instant startup |

Circuits are either generated at runtime (first prove request, ~4 min) or loaded from disk if `CIRCUIT_CACHE_PATH` is set (0ms startup). The Docker build pre-generates circuits during the build stage.
