# v1.0 — Circom / Groth16

> Tagged as `v1.0-circom` in git. This page documents the original architecture for historical reference.

## Architecture

v1 used [Circom](https://docs.circom.io/) circuits with [Groth16](https://eprint.iacr.org/2016/260) proofs over the BN254 curve:

- **10 Circom circuits**: 6 predicate types (gte, lte, eq, neq, range, set_member) + ecdsa_verify + nullifier + holder_binding + identity_escrow
- **Two-stage proving**: Stage 1 verified the issuer's ECDSA P-256 signature (~2M constraints). Stage 2 evaluated the predicate using a Poseidon commitment from Stage 1.
- **Groth16 proofs**: 192-byte proofs, ~1-2ms verification
- **Trusted setup**: Required powers-of-tau ceremony files (pot21.ptau: 2.4 GB, pot22.ptau: 4.6 GB) plus per-circuit zkey generation

## 10 Crates

| Crate | Purpose |
|-------|---------|
| zk-eidas | Facade — `ZkCredential` builder, `ZkVerifier` |
| zk-eidas-types | Shared types |
| zk-eidas-parser | SD-JWT VC parser |
| zk-eidas-mdoc | mdoc/mDL parser |
| zk-eidas-prover | Witness generation (C++ binaries) + Groth16 proving (rapidsnark) |
| zk-eidas-verifier | Proof verification + trusted circuit registry |
| zk-eidas-utils | Date/field utilities |
| zk-eidas-wasm | WASM bindings for browser proving/inspection |
| cbor-print | Chunked QR protocol |
| vk-extract | Verification key extraction tool |

## Browser Proving

v1 supported on-device proving in the browser via a [forked snarkjs](https://github.com/sampritipanda/snarkjs):

- The 1.2 GB ECDSA zkey was split into ~24 compressed chunks (~50 MB each)
- Chunks were stored in IndexedDB via localforage and loaded on demand
- Peak browser memory: ~1.5 GB (down from ~3 GB without chunking)
- ECDSA proving time: ~227 seconds in browser, ~5 seconds on server

This was technically impressive but impractical for mobile devices.

## Identity Escrow (v1)

v1 used **Poseidon-CTR encryption inside the ZK circuit**:

- Symmetric key K encrypted with secp256k1 ECIES
- Credential fields encrypted with Poseidon-CTR: `ciphertext[i] = plaintext[i] XOR Poseidon(K, i)`
- ~2,500 constraints for escrow (0.13% over the 2M ECDSA base)
- The circuit enforced honest encryption — garbage ciphertext couldn't pass

## What Worked

- **Tiny proofs**: 192 bytes fit easily in QR codes — the chunked QR protocol was designed for this
- **Paper proofs**: the entire proof could be printed as 3-4 QR codes
- **Offline verification**: snarkjs could verify in the browser without a server
- **252 tests**: comprehensive test suite covering parsing, proving, verification, and integration

## What Didn't

- **Trusted setup**: Required downloading 7 GB of ceremony files and trusting them
- **ECDSA circuit**: 2M constraints, 5 seconds per proof on server, 4 minutes on-device
- **Proof artifacts**: 1.2 GB zkey for ECDSA alone, plus 2.4 GB ptau
- **Quantum vulnerability**: BN254 pairings are broken by Shor's algorithm
- **Complexity**: 10 Circom circuits, each with separate zkey/r1cs/wasm artifacts, C++ witness generators, rapidsnark FFI

## Performance Numbers

| Operation | Time |
|-----------|------|
| Server ECDSA proving | ~5s |
| Browser ECDSA proving | ~227s |
| Server predicate proving | ~1s |
| Verification | ~1-2ms |
| Proof size | 192 bytes |
| ECDSA zkey | 1.2 GB |
| pot22.ptau | 4.6 GB |
