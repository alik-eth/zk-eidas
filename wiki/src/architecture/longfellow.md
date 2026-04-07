# Longfellow Proving System

## What Is Longfellow

Longfellow is Google's zero-knowledge proving system based on the **Sumcheck + Ligero** protocol. It uses SHA-256 hash circuits to prove statements about data without revealing the data itself.

- **Paper**: [eprint 2024/2010](https://eprint.iacr.org/2024/2010)
- **IETF draft**: [draft-google-cfrg-libzk](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)
- **Repository**: [google/longfellow-zk](https://github.com/google/longfellow-zk)

Longfellow was designed for Google Wallet's mobile document launcher (mDL) stack. zk-eidas extends it with predicate evaluation, nullifiers, holder binding, and identity escrow.

## Why Longfellow

| Property | Groth16 (v1) | Longfellow (v2) |
|----------|-------------|-----------------|
| **Trusted setup** | Required (powers of tau ceremony) | None (transparent) |
| **Proving time** | ~5s server, ~227s browser | <100ms server |
| **Quantum resistance** | No (bilinear pairings, broken by Shor) | Yes (SHA-256 only) |
| **Proof size** | 192 bytes | ~350 KB |
| **Verification time** | ~1-2ms | ~10ms |
| **Browser proving** | Supported (via snarkjs) | Not supported (C++ native) |

The trade-off is clear: much larger proofs, but dramatically faster proving, no ceremony, and post-quantum security. The larger proof size is handled by a content-addressed blob store — proofs too large for QR codes get a compact CID reference instead.

## How It Works

### Sumcheck Protocol

The core interactive proof protocol. A prover claims that a multivariate polynomial sums to a specific value over a Boolean hypercube. The verifier sends random challenges; the prover responds with univariate polynomials. After `n` rounds (one per variable), the verifier checks a single evaluation. Soundness error: `n * deg(p) / |F|`.

### Ligero Commitment

The zero-knowledge layer. The witness is arranged as a matrix, rows are Reed-Solomon encoded, and the result is committed via a Merkle tree (SHA-256). The verifier opens random columns and checks linear/quadratic constraints. This gives both zero-knowledge (witness hidden) and soundness (cheating detected).

### Fiat-Shamir Transform

The interactive protocol is made non-interactive by deriving verifier challenges from a transcript hash (AES256-based FSPRF). The first message includes the commitment, encoded statement, and anti-recursion padding.

## Circuit Architecture

Longfellow uses a **single extended hash circuit** per proof, not separate circuits per predicate (as Circom v1 did). The circuit handles:

1. **CBOR parsing** — extracts attribute values from mdoc `IssuerSignedItem`
2. **ECDSA verification** — verifies the issuer's P-256 signature on the credential
3. **Predicate evaluation** — gte/lte/eq/neq via lexicographic comparison in `assert_attribute()`
4. **Nullifier** — `SHA-256(credential_cbor_bytes || contract_hash)` for replay prevention
5. **Holder binding** — `SHA-256(first_attribute_v1[0..31])` for cross-credential linking

All of this happens in a single prove call. Range and set_member predicates are encoded as multiple attributes (one Leq + one Geq for range; multiple Eq for set_member).

## Predicate Implementation

Predicates are integrated directly into the hash circuit's `assert_attribute()` function:

```cpp
// Lexicographic comparison of CBOR byte values
auto is_leq = CMP.leq(n, val_got, val_want);  // val_got <= val_want
auto is_geq = CMP.leq(n, val_want, val_got);  // val_got >= val_want
auto is_eq  = lc_.land(is_leq, is_geq);        // equality

// Select based on VerifyType enum
auto pass = mux(type, is_eq, is_leq, is_geq, lnot(is_eq));
lc_.assert1(pass);
```

Date strings like `"1998-09-04"` are compared lexicographically — no epoch conversion needed inside the circuit. The `VerifyType` enum maps predicates: `Eq=0, Leq=1, Geq=2, Neq=3`.

## Circuit Caching

Circuit generation takes ~4 minutes and ~1.6 GB RAM. To avoid this at runtime, circuits are pre-generated during the Docker build and serialized to disk (~320-360 KB compressed with zstd). At startup, `MdocCircuit::load()` reads the cached bytes — 0ms cold start.

Four circuit sizes are pre-generated (1-4 attributes). The `generate-circuits` binary in `longfellow-sys` handles this.

## Field and Proof Structure

- **Field**: GF(2^128) binary field for optimal SHA-256 integration
- **Proof output**: `MdocProof { proof_bytes, nullifier_hash: [u8; 32], binding_hash: [u8; 32] }`
- **Circuit indexed by attribute count**: `spec_index = num_attributes - 1` (0-3)
