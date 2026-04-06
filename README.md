# zk-eidas

Zero-knowledge selective disclosure for eIDAS 2.0 credentials.

An open-source proving system that takes any eIDAS 2.0 credential (mdoc/mDL) and lets the holder prove predicates about their claims — without revealing the underlying values. A citizen proves "I am over 18" and the verifier learns nothing else. Credential authenticity is verified inside the ZK circuit via SHA-256 commitment chains, cryptographically binding proofs to authentic, already-issued government credentials.

Built on [Longfellow](https://github.com/nicoleelias/longfellow), Google's Sumcheck + Ligero proving system with SHA-256 hash circuits. No trusted setup. No ceremony files. ~1.2s proving, ~0.7s verification. Instant startup from serialized circuits.

**[Live Demo](https://zk-eidas.com)** · **[Proposal](https://zk-eidas.com/proposal)** · **[Learn More](https://zk-eidas.com/learn)**

## How It Works

```
mdoc Credential → Parser → Witness → Longfellow Hash Circuit → Sumcheck+Ligero Proof → Verifier
```

Single-stage proving architecture:

1. **Credential issuance.** The issuer signs an mdoc credential containing claims (name, birthdate, nationality, etc.) and CBOR-encodes it per ISO 18013-5.
2. **Witness generation.** The prover extracts requested attributes from the credential and builds a witness for the Longfellow hash circuit. Predicates (gte, lte, eq, etc.) are encoded as circuit constraints with SHA-256 commitment chains binding claim values to the issuer's signature.
3. **Proof generation.** Longfellow's Sumcheck + Ligero protocol produces a proof. No trusted setup — the proof system is transparent.
4. **Verification.** The verifier checks the proof against the circuit specification and public inputs. Learns nothing except that the predicate holds.

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

ZK proofs remove personal data from documents. But if parties are anonymous, how do you protect rights in court? Identity escrow solves this: credential fields are encrypted alongside the ZK proof, decryption is only possible by a chosen escrow authority per established procedure.

```
              ZK PROOF (Longfellow)                    ESCROW ENVELOPE
         ┌─────────────────────────┐
         │                         │
  mdoc ──│  SHA-256 commitment     │──▶ proof_bytes        field_names
 claims  │  chain + predicate      │    nullifier_hash     ciphertexts (AES-256-GCM)
         │  evaluation             │    binding_hash       encrypted_key (ML-KEM-768)
         │                         │
         └─────────────────────────┘
                                                │
                                                ▼
                                      AES-256-GCM encrypt(fields, K)
                                      ML-KEM-768 encrypt(K, authority_key)
                                                │
                              ┌─────────────────┼─────────────────┐
                              │                 │                 │
                        ZK PROOF          ESCROW ENVELOPE     AUTHORITY
                        ────────         ────────────────    ─────────
                        proof_bytes       ciphertexts        seed (64B)
                        nullifier         encrypted_key           │
                        binding           field_names        court order
                        (nothing to       (post-quantum          │
                         decrypt)          safe: ML-KEM)         ▼
                                                           ML-KEM decapsulate
                                                           AES-256-GCM decrypt
                                                           recover identity
```

**Key properties:**

- **Pluggable authority** — the escrow authority is a contract parameter: notary, arbitrator, state registry, or smart contract. Both parties agree at signing.
- **Quantum-safe envelope** — ML-KEM-768 (NIST FIPS 203) protects the symmetric key. The escrow blob can be published without fear of future quantum decryption.
- **Standard encryption** — AES-256-GCM (NIST) encrypts credential fields outside the circuit. Each field gets a unique deterministic nonce (counter mode).

## TSP Attestation

A Trust Service Provider (TSP) co-signs proofs with an ECDSA P-256 DataIntegrityProof, producing a Qualified Electronic Attestation of Attributes (QEAA) per eIDAS 2.0. The TSP keypair lives on the server; the `/tsp/attest` endpoint wraps any proof envelope in a W3C Verifiable Credential with the TSP's signature.

The verify page detects QEAA attestations and verifies the ECDSA P-256 signature offline using the Web Crypto API.

## Paper Proofs

Proofs are encoded as QR codes with a chunked binary protocol (deflate-raw compression, 8-byte header), so proofs can be printed on paper and verified offline with a phone camera. No internet, no app store, no institutional infrastructure.

Large proofs that exceed QR capacity are stored server-side in a content-addressed blob store (SHA-256 CID), with a compact QR pointing to the retrieval URL.

The [verify page](https://zk-eidas.com/verify) is a PWA — install it once, verify proofs offline forever.

## Architecture

| Crate | Purpose |
|-------|---------|
| `zk-eidas` | Facade — predicate types, escrow utilities, templates |
| `zk-eidas-types` | Shared types — credentials, proofs, predicates, envelopes |
| `zk-eidas-mdoc` | mdoc/mDL parser — ISO 18013-5 CBOR credentials |
| `zk-eidas-utils` | Date conversion, age calculation, field arithmetic |
| `longfellow-sys` | FFI bindings to Longfellow C++ — circuit generation, proving, verification |
| `cbor-print` | Chunked QR protocol for paper proof transport |
| `zk-eidas-demo-api` | Axum demo server — issuance, proving, verification, escrow, TSP |

Longfellow hash circuits with SHA-256 commitment chains. Sumcheck + Ligero proofs (transparent — no trusted setup). Server-side proving only. Circuits are pre-generated during Docker build and loaded from disk at startup (0ms cold start).

## Building

```bash
# Prerequisites: Rust 1.93+, CMake, Clang, GMP, NASM, zstd, Node 22+

# The Longfellow C++ library builds automatically via cmake (vendored as git submodule)
git submodule update --init

# Build and test
cargo test --workspace

# Pre-generate circuit cache (optional, for faster startup)
cargo build --release -p longfellow-sys --bin generate-circuits
./target/release/generate-circuits ./circuit-cache
```

## Testing

```bash
# Rust unit + integration tests (145 tests)
cargo test --workspace

# Web unit tests (vitest — QR chunking, nullifier check)
cd demo/web && npx vitest run

# E2E tests (requires running container)
cd demo/web && E2E_BASE_URL=http://127.0.0.1:8080 npx playwright test
```

## Benchmarks

The `benchmark` binary measures the full Longfellow ZK pipeline and identity escrow operations. Run with `--json` for machine-readable output.

```bash
cargo build --release -p longfellow-sys --bin benchmark
./target/release/benchmark
```

Results on Intel 8C/16T @ 2.6GHz, 32GB RAM (median of 5 iterations):

**ZK Proving Pipeline (Longfellow, Geq predicate)**

|                     | 1 attr  | 2 attr  | 3 attr  | 4 attr  |
|---------------------|---------|---------|---------|---------|
| Circuit gen (cold)  | 14.6s   | 15.5s   | 16.1s   | 16.8s   |
| Circuit load (cache)| 0.02ms  | 0.02ms  | 0.02ms  | 0.02ms  |
| Prove               | 1.12s   | 1.22s   | 1.27s   | 1.27s   |
| Verify              | 601ms   | 703ms   | 720ms   | 722ms   |
| Proof size          | 357 KB  | 358 KB  | 360 KB  | 362 KB  |
| RSS (process)       | ~1.1 GB | ~1.2 GB | ~1.2 GB | ~1.3 GB |

**Identity Escrow Pipeline (4 fields)**

| Operation           | Time    |
|---------------------|---------|
| ML-KEM-768 keygen   | 0.06ms  |
| AES-256-GCM encrypt | <0.01ms |
| ML-KEM encrypt K    | 0.12ms  |
| ML-KEM decrypt K    | 0.14ms  |
| AES-256-GCM decrypt | <0.01ms |

Circuit generation is a cold-path operation — circuits are pre-generated at build time and loaded from disk at startup (0.02ms). The RSS reported is absolute process memory, not delta. Escrow operations are negligible (<0.5ms total). CPU utilization is single-threaded (~100%) for all ZK operations.

## Deployment

The project deploys as a single Docker container on Fly.io. The multi-stage Dockerfile:

1. **circuit-builder** — compiles Longfellow C++ and pre-generates all 4 circuit sizes (1–4 attributes). This layer is cached when `vendor/` and `crates/` don't change.
2. **rust-builder** — builds the API binary on top of the cached circuit layer.
3. **web-builder** — builds the React frontend (TanStack Router + Tailwind CSS).
4. **runtime** — Ubuntu 24.04 with nginx + supervisord. Loads pre-generated circuits from disk at startup.

```bash
# Deploy
fly deploy

# The API starts instantly — circuits are loaded from disk, not compiled at runtime
```

## Standards

- **eIDAS 2.0** — EU Digital Identity Framework
- **mdoc/mDL** — ISO 18013-5 CBOR mobile credentials
- **ML-KEM-768** — NIST FIPS 203 post-quantum key encapsulation
- **AES-256-GCM** — NIST symmetric encryption for identity escrow
- **ECDSA P-256** — TSP attestation signatures (DataIntegrityProof)

## License

Apache 2.0 — see [LICENSE](LICENSE)
