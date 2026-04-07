# TSP Attestation (QEAA)

## What Is a QEAA

A **Qualified Electronic Attestation of Attributes** (QEAA) is an eIDAS 2.0 concept: a digitally signed statement from a qualified trust service provider (QTSP) that specific attributes have been verified. In zk-eidas, the QEAA wraps a zero-knowledge proof — the TSP co-signs the proof envelope, attesting that the ZK verification passed.

This bridges the gap between cryptographic proof validity and legal recognition. A raw ZK proof is mathematically sound but has no legal standing. A QEAA signed by a qualified TSP carries the same legal weight as a handwritten signature under EU law.

## Architecture

The demo server runs a **Trust Service Provider (TSP)** that:

1. Holds an ECDSA P-256 signing keypair (generated at startup)
2. Exposes the public key via `GET /tsp/pubkey`
3. Signs proof envelopes via `POST /tsp/attest`

### Attestation Flow

```
Holder generates proof → POST /tsp/attest { proof_envelope } →
TSP verifies proof → TSP wraps in W3C VC → TSP signs with ECDSA P-256 →
Returns QEAA (VC + DataIntegrityProof)
```

The QEAA output is a W3C Verifiable Credential containing:

- **credentialSubject**: the original proof envelope (predicates, nullifiers, binding)
- **proof**: a `DataIntegrityProof` with the TSP's ECDSA P-256 signature over SHA-256(canonical VC JSON)
- **issuer**: the TSP's identifier
- **issuanceDate**: timestamp of attestation

### Offline Verification

The verify page detects QEAA attestations automatically. When a scanned or uploaded document contains a `DataIntegrityProof`, the browser:

1. Extracts the TSP's public key from `proof.verificationMethod`
2. Imports it via Web Crypto API (`ECDSA, P-256`)
3. Computes SHA-256 of the canonical VC JSON (everything except the proof field)
4. Verifies the ECDSA signature against the hash

This is fully offline — no network request to the TSP. The verifier trusts the TSP's public key (which should be obtained from a trusted registry in production).

## API Endpoints

### `GET /tsp/pubkey`

Returns the TSP's ECDSA P-256 public key as hex-encoded uncompressed point.

### `POST /tsp/attest`

Accepts a proof envelope, verifies it, and returns a signed QEAA.

### `POST /tsp/escrow/decrypt`

Decrypts an identity escrow envelope using the authority's ML-KEM-768 seed. This endpoint is for the escrow authority role, not the TSP role — it's co-located for demo convenience.

## Production Considerations

In the demo, the TSP keypair is ephemeral (generated at startup). For production:

- The signing key should be stored in an HSM or secure enclave
- The public key should be registered in a trusted service list (TSL) per eIDAS
- The TSP should be qualified under eIDAS Article 45 for the attestation to carry legal weight
- Key rotation and certificate management per ETSI EN 319 411-2
