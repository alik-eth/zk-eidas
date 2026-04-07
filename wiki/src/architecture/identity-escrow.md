# Identity Escrow

## The Problem

Zero-knowledge proofs remove personal data from verification. But if both parties to an agreement are anonymous, how do you protect rights in court? If a seller proves "I own this vehicle" without revealing their name, how does the buyer seek recourse if the vehicle is defective?

Identity escrow bridges this gap: credential fields are encrypted alongside the ZK proof, but decryption is only possible by a designated escrow authority — a notary, arbitrator, or court registry — following established legal procedure.

## How It Works

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

### Encryption (Prover Side)

1. **Field selection**: Up to 8 credential fields chosen for escrow (e.g., given_name, family_name, document_number, birth_date, address)
2. **Symmetric key**: A random 31-byte key K is generated (fits in BN254 scalar field)
3. **Field encryption**: Each field is encrypted with AES-256-GCM using K. Nonces are deterministic — derived from the field index (counter mode). This produces ciphertexts + authentication tags.
4. **Key encryption**: K is encrypted to the escrow authority's ML-KEM-768 public key. The authority's key is a 64-byte seed from which the encapsulation key is derived (NIST FIPS 203).

The escrow envelope (ciphertexts + encrypted_key + field_names) is published alongside the proof. The proof itself contains no decryptable data.

### Decryption (Authority Side)

1. Authority receives the escrow envelope (from paper document, file, or API)
2. ML-KEM-768 decapsulation recovers the shared secret from the ciphertext using the authority's seed
3. SHA-256(shared_secret) produces a mask; XOR with encrypted_k recovers K
4. AES-256-GCM decrypts each field using K + deterministic nonces
5. Authority verifies integrity: authentication tags prevent tampering

### Deterministic Key Derivation

For proof caching, a deterministic variant exists: `K = SHA-256(credential_data || authority_pubkey)[0..31]`. Same inputs always produce the same K, so cached proofs can reuse the same escrow envelope.

## Cryptographic Choices

| Component | Algorithm | Why |
|-----------|-----------|-----|
| Field encryption | AES-256-GCM | Standard, fast, authenticated. Replaced Poseidon-CTR from v1 — AES-GCM is universally understood and auditable. |
| Key encapsulation | ML-KEM-768 (FIPS 203) | Post-quantum secure. An escrow envelope published today cannot be broken by future quantum computers. |
| Key size | 64-byte seed | The ML-KEM-768 decapsulation key is derived from a 64-byte seed. Both encapsulation and decapsulation use this seed. |

### v1 vs v2

In v1 (Circom), escrow used **Poseidon-CTR encryption inside the ZK circuit** — the circuit itself enforced honest encryption. In v2 (Longfellow), encryption moved **outside the circuit** to standard Rust crypto (AES-256-GCM). The circuit still produces a `credential_hash` binding attribute values to the signed credential, so a post-decryption hash check proves the escrowed data matches what was proven.

## Authority Model

The escrow authority is a **contract parameter** — both parties agree on who holds the decryption key before signing. Options:

- **Notary**: traditional legal escrow
- **Arbitrator**: dispute resolution service
- **State registry**: government-operated key custodian
- **Smart contract**: on-chain multi-sig or timelock

The authority's ML-KEM-768 seed (64 bytes) is the secret. The encapsulation key (1184 bytes) can be published. A court order or arbitration ruling authorizes the authority to use the seed.

## Paper Document Integration

On printed documents, escrow data appears as separate QR codes with amber borders, distinct from proof QR codes. The escrow QR uses reserved `proofId` values (`0xFFF0`–`0xFFFD`) in the chunked QR protocol. Each QR encodes the full envelope: encrypted_key, ciphertexts, field_names, authority pubkey, and a SHA-256 fingerprint of the authority key.
