# Credential Formats (mdoc)

## ISO 18013-5 mdoc/mDL

zk-eidas works with **mdoc** (mobile document) credentials as defined in ISO 18013-5 for mobile driving licenses. This is the credential format used by Google Wallet and the EUDI Wallet.

An mdoc is a CBOR-encoded structure containing:

- **docType**: document type identifier (e.g., `"org.iso.18013.5.1.mDL"`)
- **issuerAuth**: COSE_Sign1 signature over the Mobile Security Object (MSO)
- **nameSpaces**: maps of namespace → array of `IssuerSignedItem` entries
- Each `IssuerSignedItem` contains: `digestID`, `random`, `elementIdentifier`, `elementValue`

## Parsing

The `zk-eidas-mdoc` crate provides two parsing modes:

### Without Issuer Key

```rust
let credential = MdocParser::parse(&mdoc_bytes)?;
// Returns Credential with SignatureData::Opaque (no ECDSA data)
```

### With Issuer Key

```rust
let credential = MdocParser::parse_with_issuer_key(
    &mdoc_bytes, pub_key_x, pub_key_y
)?;
// Returns Credential with SignatureData::Ecdsa { pub_key_x, pub_key_y, signature, message_hash }
```

The issuer key version extracts the ECDSA P-256 signature from the COSE_Sign1 structure and the message hash from the MSO. This data is needed for in-circuit signature verification.

## Claim Type Mapping

| mdoc Element | ClaimValue Type | Notes |
|-------------|----------------|-------|
| `birth_date` | `Date { year, month, day }` | Recognized by field name |
| Fields ending in `_date`, `_expiry` | `Date` | Attempted date parse, string fallback |
| Text strings | `String` | UTF-8 |
| Integers | `Integer(i64)` | With overflow check |
| Booleans | `Boolean(bool)` | |

## Token Format

The demo API uses a composite token format for credential transport:

```
mdoc:<base64(mdoc_bytes)>:<hex(pub_key_x)>:<hex(pub_key_y)>
```

This bundles the raw mdoc CBOR with the issuer's public key coordinates, so the prover can parse and verify in a single step.

## Longfellow Compatibility

The mdoc parser produces a CBOR structure that matches what Longfellow's C++ parser expects:

- 4-element COSE_Sign1 array in issuerAuth
- Tag(24) byte-string wrapping of MSO
- Standard MSO field names (`version`, `digestAlgorithm`, `valueDigests`, `docType`)

A dedicated test (`longfellow_compatible_structure`) validates byte-level compatibility between the Rust parser's output and the C++ circuit's expectations.
