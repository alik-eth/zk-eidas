# Migration to Longfellow

## Why Migrate

By March 2026, v1's limitations were clear:

1. **No post-quantum security**: BN254 pairings are broken by Shor's algorithm. Government identity documents need decades of security.
2. **Trusted setup burden**: 7 GB of ceremony files, with no way to verify them independently.
3. **Performance ceiling**: ECDSA verification in Circom hit 2M constraints — fast enough for servers but unusable on mobile.
4. **Google Wallet alignment**: Longfellow was designed for Google Wallet's mDL stack, making it the natural choice for mdoc credentials.

## The Decision

| Criterion | Groth16 | Longfellow |
|-----------|---------|------------|
| Trusted setup | Required | None (transparent) |
| ECDSA proving | ~5s server | ~17ms |
| Quantum resistance | No | Yes (SHA-256 only) |
| Proof size | 192 bytes | ~350 KB |
| Browser proving | Yes | No (C++ native) |

The trade-off: larger proofs for dramatically faster proving, no ceremony, and post-quantum security. Browser proving was sacrificed — a conscious choice given that server-side proving is <100ms.

## Migration Design

The migration was split into two phases:

### Phase 1: Fork + Circuit Extensions + Rust FFI

1. Fork Longfellow as `vendor/longfellow-zk/` git submodule
2. Extend the mdoc hash circuit with predicate evaluation (gte/lte/eq/neq)
3. Add nullifier gadget: `SHA-256(credential_cbor_bytes || contract_hash)`
4. Add holder binding: `SHA-256(first_attribute_v1[0..31])`
5. Build `longfellow-sys` Rust crate with FFI bindings and safe wrappers
6. Smoke test: circuit generation → prove → verify from Rust

### Phase 2: Rewire Demo + Escrow Redesign

1. Replace all Circom-based prove/verify endpoints with Longfellow calls
2. Redesign identity escrow: Poseidon-CTR (in-circuit) → AES-256-GCM (out-of-circuit) + ML-KEM-768
3. Add content-addressed proof blob store for large proofs
4. Add TSP attestation service (QEAA)
5. Remove browser proving, chunked zkey loader, snarkjs dependency

## What Was Deleted

| Component | Reason |
|-----------|--------|
| 9 Circom circuits | Replaced by Longfellow C++ hash circuit |
| `zk-eidas-parser` | SD-JWT support removed (mdoc only) |
| `zk-eidas-prover` | rapidsnark/ark-circom → longfellow-sys |
| `zk-eidas-verifier` | Groth16 verify → Longfellow verify |
| `zk-eidas-wasm` | No browser proving |
| `tools/vk-extract` | No verification keys to extract |
| circomlibjs, snarkjs, buffer | Frontend Poseidon/Groth16 dependencies |
| Chunked zkey loader | No zkey files |
| 4.6 GB ptau files | No trusted setup |

## What Was Preserved

- **Workspace structure**: 7 crates (down from 10), same Cargo workspace
- **Predicate semantics**: all 9 predicate types work identically
- **Contract nullifiers**: same two-party design, SHA-256 instead of Poseidon
- **Identity escrow**: same concept (encrypt fields, ML-KEM key encapsulation), better crypto (AES-GCM, FIPS 203)
- **Paper proofs**: same chunked QR protocol, plus blob store for large proofs
- **Demo frontend**: same React app, TanStack Router, Tailwind CSS
- **Test coverage**: 90 Rust tests + 28 vitest (down from 252 — tests for deleted crates removed)

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Escrow encryption | AES-256-GCM (out-of-circuit) | Standard, auditable. Circuit produces credential_hash for post-decryption integrity. |
| Key encapsulation | ML-KEM-768 | Post-quantum. 64-byte seed simplifies key management. |
| Credential format | mdoc only | Longfellow has production mdoc circuits. SD-JWT deferred. |
| Browser proving | Removed | Longfellow is C++ native. <100ms server proves makes browser proving unnecessary. |
| Circuit caching | Pre-generate in Docker | 0ms startup. Circuit generation takes 4+ min — unacceptable at runtime. |

## Timeline

- **April 4, 2026**: Migration design spec written
- **April 4-5**: Phase 1 complete — Longfellow fork, circuit extensions, Rust FFI, smoke tests
- **April 5-6**: Phase 2 complete — demo rewired, escrow redesigned, TSP added, deployed
- **April 6**: Circuit serialization implemented — 0ms startup
- **April 7**: Cleanup, merge to main, v1.0-circom tagged, deployed to zk-eidas.com
