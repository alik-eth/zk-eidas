# Nullifier (Replay Prevention)

## The Problem

Without nullifiers, a holder could reuse the same ZK proof across multiple transactions. In a vehicle sale, the seller could sell the same car twice — each time producing a valid proof of ownership.

Nullifiers provide **scoped, deterministic, unlinkable replay prevention**. Each (credential, contract) pair produces a unique nullifier. Reusing the credential for the same contract produces the same nullifier, detectable by the verifier. But using the credential in a different context produces a different nullifier — no cross-service correlation.

## How It Works

Longfellow computes nullifiers inside the hash circuit:

```
nullifier = SHA-256(credential_cbor_bytes || contract_hash)
```

- `credential_cbor_bytes`: the raw CBOR attribute value from the mdoc (available during circuit evaluation)
- `contract_hash`: `SHA-256(contract_terms || timestamp)[0..8]` as 8-byte big-endian u64

The nullifier is a 32-byte hash output — opaque, deterministic, and bound to both the credential and the contract.

## Contract Binding

A contract hash binds a nullifier to a specific agreement:

1. Contract terms (JSON) and timestamp are concatenated
2. SHA-256 of the concatenation, first 8 bytes as u64 — this is `contract_hash`
3. The contract_hash is passed as a domain separator to the circuit
4. Anyone can recompute the contract_hash from the terms to verify it matches

## Two-Party Contracts

Each party in a contract gets their own nullifier:

```
Party A: nullifier_a = SHA-256(credential_a_bytes || contract_hash)
Party B: nullifier_b = SHA-256(credential_b_bytes || contract_hash)
```

Both nullifiers share the same `contract_hash` (same contract) but differ because they come from different credentials. Each party proves their predicates independently, and the contract document lists both nullifiers.

## Court Resolution

If a dispute arises, a court can identify a party by their nullifier:

1. The court has the printed document with nullifier values
2. The issuer provides their credential database
3. For each credential in the database, compute `SHA-256(credential_bytes || contract_hash)`
4. Match against the document's nullifier
5. Estimated: 100-500 seconds to search 50M credentials (parallelizable)

This brute-force approach works because the court has access to the issuer's database — something no other party has.

## Verify Page

On the verify page, nullifiers are displayed per-party. The verifier can:

1. **Cross-check the contract hash**: recompute `SHA-256(terms || timestamp)` from the scanned terms QR and verify it matches the embedded contract_hash
2. **Compare nullifiers**: check if a known nullifier matches any party in the document (string comparison — the verifier cannot recompute nullifiers without the original credential)
