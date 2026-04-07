# Threat Model

## What the ZK Proof Guarantees

A valid zk-eidas proof guarantees:

1. **Predicate truth**: The stated predicate holds on the credential's claim value (e.g., age >= 18)
2. **Issuer authenticity**: The credential was signed by the issuer whose public key is embedded in the circuit
3. **Data binding**: The proven claim value matches what the issuer signed — the prover cannot substitute values
4. **Zero knowledge**: The verifier learns nothing beyond the predicate result

## What It Does NOT Guarantee

- **Credential freshness**: The proof doesn't prove the credential hasn't been revoked. Revocation requires a separate check against a status list (`/issuer/revocation-status`). The proof says "this claim was true when the credential was issued" — not "it's true right now."
- **Holder identity**: The proof doesn't prove who is presenting it. Paper proofs are static artifacts — anyone with the paper can present. For eIDAS LoA Substantial/High, the verifier must establish holder identity externally (biometric, interactive challenge, or document number disclosure).
- **Predicate completeness**: The proof only covers requested predicates. A valid "age >= 18" proof says nothing about nationality.

## Adversary Models

### Malicious Prover

A prover who attempts to generate a valid proof for a predicate that doesn't hold on their credential. Longfellow's soundness guarantee (Sumcheck + Ligero) ensures this fails with overwhelming probability: soundness error `n * deg(p) / |F|` where `|F| = 2^128`.

### Malicious Verifier

A verifier who attempts to extract additional information from the proof. Longfellow's zero-knowledge property (Ligero's hiding) ensures the verifier learns only the predicate result and public inputs (nullifier hash, binding hash).

### Compromised Issuer

If the issuer's signing key is compromised, an attacker can forge credentials and produce valid proofs for any predicate. The proof system cannot detect this — issuer key management is outside scope.

## Identity Escrow Security

- **Honest encryption**: AES-256-GCM authentication tags prevent an attacker from modifying encrypted fields. The circuit produces a `credential_hash` binding the plaintext to the signed credential — post-decryption, the authority verifies `hash(decrypted) == credential_hash`.
- **Post-quantum**: ML-KEM-768 (FIPS 203) protects the symmetric key against future quantum computers. An escrow envelope published today remains secure.
- **Authority separation**: The escrow authority's seed is 64 bytes. Without it, decryption is infeasible. The proof itself contains no encrypted data — only hashes.

## Nullifier Privacy

- Nullifiers are deterministic: same (credential, contract) pair → same nullifier. This is by design (replay detection).
- Different contracts produce different nullifiers — no cross-service linkability.
- A verifier cannot recover the credential from a nullifier (SHA-256 preimage resistance).
- A court with access to the issuer's database CAN identify a credential by brute-force matching nullifiers.

## Transport Security

- QR codes are plaintext CBOR — use only in-person or over authenticated channels
- The demo API should run behind TLS in production
- QEAA signatures (ECDSA P-256) protect attestation integrity but not confidentiality
