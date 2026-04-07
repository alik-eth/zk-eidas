# mdoc / ISO 18013-5

## What Is mdoc

**mdoc** (mobile document) is the credential format defined by ISO 18013-5 for mobile driving licenses (mDL). It's a CBOR-encoded structure designed for offline presentation via NFC or QR codes.

mdoc is the credential format used by Google Wallet and is one of the two formats supported by the EUDI Wallet (alongside SD-JWT VC).

## Structure

An mdoc credential contains:

```
Document {
  docType: "org.iso.18013.5.1.mDL"
  issuerSigned: {
    issuerAuth: COSE_Sign1 [protected, unprotected, payload(MSO), signature]
    nameSpaces: {
      "org.iso.18013.5.1": [
        IssuerSignedItem { digestID, random, elementIdentifier, elementValue },
        ...
      ]
    }
  }
}
```

### IssuerAuth

A COSE_Sign1 signature (RFC 9052) over the Mobile Security Object (MSO). The MSO contains:

- `version`: MSO version string
- `digestAlgorithm`: hash algorithm for value digests (typically SHA-256)
- `valueDigests`: map of namespace → (digestID → digest) for integrity verification
- `docType`: document type identifier

The issuer signs the MSO with ECDSA P-256, producing a signature that Longfellow verifies inside the ZK circuit.

### Namespaces and Elements

Claims are organized by namespace. The standard namespace `org.iso.18013.5.1` contains:

| Element Identifier | Type | Example |
|-------------------|------|---------|
| `family_name` | string | "Mustermann" |
| `given_name` | string | "Erika" |
| `birth_date` | full-date | "1985-03-15" |
| `issue_date` | full-date | "2024-01-01" |
| `expiry_date` | full-date | "2034-01-01" |
| `issuing_country` | string | "DE" |
| `nationality` | string | "DE" |
| `document_number` | string | "T22000129" |
| `gender` | integer | 2 |

Each element is wrapped in an `IssuerSignedItem` with a random salt and digest ID for selective disclosure.

## Parsing in zk-eidas

The `zk-eidas-mdoc` crate parses raw CBOR bytes:

1. Navigate to `issuerSigned → nameSpaces`
2. For each namespace, iterate `IssuerSignedItem` entries
3. Extract `elementIdentifier` → `elementValue` pairs
4. Map CBOR values to `ClaimValue` types:
   - Date fields → `ClaimValue::Date { year, month, day }`
   - Strings → `ClaimValue::String`
   - Integers → `ClaimValue::Integer(i64)`
   - Booleans → `ClaimValue::Boolean`
5. If issuer key provided: parse COSE_Sign1, extract ECDSA signature + message hash

## CBOR Compatibility

Longfellow's C++ circuit parser expects a specific CBOR byte layout. The Rust mdoc parser is tested for byte-level compatibility:

- 4-element COSE_Sign1 array in issuerAuth
- Tag(24) byte-string wrapping of MSO
- Standard MSO field names

A dedicated integration test (`longfellow_compatible_structure`) validates this.
