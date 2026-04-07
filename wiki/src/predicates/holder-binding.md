# Holder Binding

## Purpose

Holder binding proves that two different credentials belong to the same person — without revealing who that person is. If a contract requires both a PID (personal ID) and a driver's license, holder binding cryptographically links the two proofs to the same holder.

## How It Works

Longfellow computes a binding hash inside the hash circuit:

```
binding_hash = SHA-256(first_attribute_v1[0..31])
```

The binding hash is derived from the first 31 bytes of the first attribute's CBOR value. Two credentials from the same holder (with the same binding claim, e.g., `document_number`) produce the same binding hash.

## Usage

In the demo API, the `/holder/prove-binding` endpoint:

1. Parses two credentials (A and B)
2. Proves predicates on each credential separately
3. Extracts `binding_hash` from each proof
4. Compares: if `binding_hash_a == binding_hash_b`, the credentials share the same holder

The binding claim (which field to use) is specified per-credential in the request. Typically `document_number` or a similar unique identifier.

## Limitations

- Binding works across credentials from the **same issuer** (same binding claim encoding)
- Cross-issuer binding requires a shared identifier format
- The binding hash is deterministic — same credential always produces the same hash — so repeated binding proofs for the same credential are linkable. Use nullifiers alongside binding for unlinkability.
