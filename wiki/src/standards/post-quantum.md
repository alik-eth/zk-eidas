# Post-Quantum Cryptography

## Why Post-Quantum Matters

Identity escrow data may need to remain confidential for decades. An escrow envelope published in 2026 must still be secure in 2046. If large-scale quantum computers arrive in that window, any encryption based on RSA, ECDH, or discrete logarithms will be breakable by Shor's algorithm.

zk-eidas addresses this at two levels:

1. **Proof system**: Longfellow uses only SHA-256 — no bilinear pairings or discrete-log assumptions. The proof system is post-quantum secure.
2. **Identity escrow**: ML-KEM-768 (NIST FIPS 203) protects the symmetric key, replacing classical ECIES/secp256k1.

## ML-KEM-768 (FIPS 203)

ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) is NIST's post-quantum standard, finalized in 2024. The 768 parameter set provides:

- **128-bit post-quantum security** (equivalent to AES-128)
- **Encapsulation key**: 1184 bytes (published)
- **Ciphertext**: 1088 bytes
- **Shared secret**: 32 bytes

### How It's Used

In zk-eidas, ML-KEM-768 protects the identity escrow symmetric key:

1. The escrow authority generates a 64-byte **seed**
2. From the seed, a `DecapsulationKey` is derived (used for decryption)
3. The `EncapsulationKey` (1184 bytes) is published or embedded in contracts
4. The prover **encapsulates**: produces (ciphertext, shared_secret) from the EK
5. The shared secret is used to mask the symmetric key K: `encrypted_K = K XOR SHA-256(shared_secret)`
6. The envelope contains: ML-KEM ciphertext (1088 bytes) + encrypted_K (32 bytes) = 1120 bytes

### Decryption

1. The authority uses their 64-byte seed to reconstruct the `DecapsulationKey`
2. **Decapsulation**: recovers the shared secret from the ciphertext
3. `K = encrypted_K XOR SHA-256(shared_secret)` recovers the symmetric key
4. AES-256-GCM decrypts credential fields using K

## AES-256-GCM

Standard authenticated encryption (NIST SP 800-38D) for credential field encryption:

- **Key**: 256-bit symmetric key K
- **Nonce**: 12-byte deterministic nonce derived from field index (counter mode)
- **Authentication**: 16-byte tag per field prevents tampering
- **Post-quantum**: AES-256 provides 128-bit security against Grover's algorithm

Each credential field is encrypted independently with a unique nonce: `nonce[8..12] = field_index.to_be_bytes()`. This allows individual field decryption.

## Comparison with v1

| Component | v1 (Circom) | v2 (Longfellow) |
|-----------|-------------|-----------------|
| Proof system | Groth16 (BN254 pairings — quantum-vulnerable) | Sumcheck+Ligero (SHA-256 only — post-quantum) |
| Escrow encryption | Poseidon-CTR (in-circuit, non-standard) | AES-256-GCM (standard, auditable) |
| Key encapsulation | secp256k1 ECIES (quantum-vulnerable) | ML-KEM-768 FIPS 203 (post-quantum) |
| Key size | 33-byte compressed pubkey | 64-byte seed / 1184-byte encapsulation key |

The v2 design ensures that neither the proofs nor the escrow envelopes are vulnerable to quantum attacks.
