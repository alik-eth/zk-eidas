# API Reference

The demo API server (Axum) exposes 21 endpoints grouped by role.

## Issuer

| Method | Path | Description |
|--------|------|-------------|
| POST | `/issuer/issue` | Issue a signed mdoc credential |
| POST | `/issuer/revoke` | Revoke a credential by index |
| GET | `/issuer/revocation-status` | Get revocation bitstring |
| GET | `/issuer/revocation-root` | Alias for revocation-status |

### POST /issuer/issue

```json
{
  "credential_type": "pid",
  "claims": { "given_name": "Alice", "birth_date": "1998-05-14", ... },
  "issuer": "https://issuer.example.com"
}
```

Returns: `{ "credential": "mdoc:<base64>:<hex_x>:<hex_y>" }`

## Holder (Proving)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/holder/prove` | Single predicate proof |
| POST | `/holder/prove-compound` | Multiple predicates (AND/OR) |
| POST | `/holder/prove-binding` | Two-credential holder binding |
| POST | `/holder/contract-prove` | Contract proof with nullifier |
| POST | `/holder/proof-export` | Export proof as CBOR envelope |
| POST | `/holder/proof-export-compound` | Export compound proof as CBOR |

### POST /holder/prove-compound

```json
{
  "credential": "mdoc:<base64>:<hex_x>:<hex_y>",
  "format": "mdoc",
  "predicates": [
    { "claim": "birth_date", "op": "gte", "value": "2008-04-07" }
  ],
  "op": "and",
  "identity_escrow": {
    "field_names": ["given_name", "family_name", "document_number"],
    "authority_pubkey": "<hex-encoded ML-KEM-768 seed>"
  }
}
```

### POST /holder/contract-prove

```json
{
  "credential": "mdoc:...",
  "format": "mdoc",
  "predicates": [{ "claim": "birth_date", "op": "gte", "value": "2008-04-07" }],
  "contract_terms": "{\"id\":\"vehicle-sale\",\"terms\":\"...\"}",
  "timestamp": "2026-04-07T12:00:00.000Z",
  "role": "seller",
  "identity_escrow": { ... }
}
```

Returns: compound proof JSON with `nullifier`, `contract_hash`, `salt`, `role`.

## Verifier

| Method | Path | Description |
|--------|------|-------------|
| POST | `/verifier/verify` | Verify individual proofs |
| POST | `/verifier/verify-compound` | Verify compound proof |
| POST | `/verifier/presentation-request` | Generate OpenID4VP request |

## Escrow

| Method | Path | Description |
|--------|------|-------------|
| POST | `/escrow/decrypt` | Decrypt escrow envelope with authority seed |

### POST /escrow/decrypt

```json
{
  "encrypted_key": "<hex>",
  "secret_key": "<hex ML-KEM-768 seed>",
  "ciphertext": ["<hex>", ...],
  "field_names": ["given_name", "family_name", ...]
}
```

Returns: `{ "fields": { "given_name": "Alice", ... } }`

## TSP (Trust Service Provider)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tsp/pubkey` | Get TSP's ECDSA P-256 public key |
| POST | `/tsp/attest` | Sign proof envelope as QEAA |
| POST | `/tsp/escrow/decrypt` | Escrow decrypt (alias) |

## Proof Blob Store

| Method | Path | Description |
|--------|------|-------------|
| POST | `/proofs` | Store proof bytes, returns SHA-256 CID |
| GET | `/proofs/{cid}` | Retrieve proof by CID |

## Other

| Method | Path | Description |
|--------|------|-------------|
| GET | `/circuits/{*rest}` | Serve circuit artifacts |
| GET | `/longfellow/demo` | Longfellow benchmark demo |
