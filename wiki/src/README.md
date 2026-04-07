# zk-eidas

**Zero-Knowledge Selective Disclosure for eIDAS 2.0 Credentials**

zk-eidas is an open-source proving system that lets holders of government-issued digital credentials prove facts about themselves — without revealing the underlying data. A citizen proves "I am over 18" and the verifier learns nothing else.

Built on [Longfellow](https://github.com/nicoleelias/longfellow), Google's Sumcheck + Ligero proving system with SHA-256 hash circuits. No trusted setup. No ceremony files. Sub-second proving. Post-quantum security.

## What It Does

A government issues a digital credential (mdoc/mDL per ISO 18013-5) containing claims like name, birthdate, nationality, and document number. zk-eidas takes that credential and generates a zero-knowledge proof that specific predicates hold — age >= 18, nationality in {DE, FR, NL}, document not expired — without revealing the actual values.

The proof is cryptographically bound to the issuer's signature. A forged credential cannot produce a valid proof.

## Key Capabilities

- **9 predicate types** — gte, lte, eq, neq, range, set_member, nullifier, holder_binding, identity_escrow
- **Compound proofs** — AND/OR logic over multiple predicates in a single proof
- **Contract nullifiers** — scoped replay prevention for two-party agreements
- **Identity escrow** — encrypted identity recovery via ML-KEM-768 + AES-256-GCM, decryptable only by a designated authority
- **TSP attestation** — ECDSA P-256 DataIntegrityProof wrapping proofs as Qualified Electronic Attestations of Attributes (QEAA)
- **Paper proofs** — QR-encoded proofs printed on paper, verified offline with a phone camera

## Live Demo

**[eidas-longfellow.fly.dev](https://eidas-longfellow.fly.dev)** — issue credentials, generate proofs, verify them, try contract flows with nullifiers and escrow.

## Project Structure

| Crate | Purpose |
|-------|---------|
| [`zk-eidas`](architecture/overview.md) | Facade — predicate types, escrow utilities, templates |
| [`zk-eidas-types`](architecture/overview.md) | Shared types — credentials, proofs, predicates, envelopes |
| [`zk-eidas-mdoc`](integration/credential-formats.md) | mdoc/mDL parser — ISO 18013-5 CBOR credentials |
| [`zk-eidas-utils`](architecture/overview.md) | Date conversion, age calculation, field arithmetic |
| [`longfellow-sys`](architecture/longfellow.md) | FFI bindings to Longfellow C++ — circuit generation, proving, verification |
| [`cbor-print`](architecture/paper-proofs.md) | Chunked QR protocol for paper proof transport |
| [`zk-eidas-demo-api`](integration/api-reference.md) | Axum demo server — issuance, proving, verification, escrow, TSP |
