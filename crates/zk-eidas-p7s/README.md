# zk-eidas-p7s

PKCS#7 / CMS parser and witness builder for eIDAS 1 qualified-signature credentials. Produces the public outputs that the Longfellow ZK circuit will later prove in-circuit.

## Scope

- **v1:** DIIA (Ukraine) qualified signatures over QKB JSON bindings.
- **v2 (out of scope for this crate):** other EU QTSPs, EUTL ingestion.

## Public outputs

- `pk` — the secp256k1 pubkey declared in the signed JSON (65 B uncompressed).
- `nullifier` = `SHA-256(stable_id ‖ context)` (32 B).
- `binding_hash` = `SHA-256(stable_id)` (32 B).
- `nonce` — 32-byte freshness value from the signed JSON.

## Stable ID semantics

`stable_id` is the raw bytes of the **X.520 serialNumber attribute** (OID 2.5.4.5) inside the signer certificate's subject DN. For DIIA-issued certs this is the Ukrainian state tax ID in the form `TINUA-XXXXXXXXXX` (RNOKPP) — a **life-long identifier** that does not change on cert renewal.

Consequence: two DIIA certs issued to the same person at different times yield the same nullifier and the same binding_hash. This is the **person-level nullifier** property. It is load-bearing for Sybil resistance: a compromised or re-issued cert cannot re-register the same identity.

This is distinct from (and not to be confused with) the certificate's own `serialNumber` field, which *does* change on renewal.

## Signature flow (CMS signedAttrs / CAdES-BES)

Real DIIA p7s documents use CMS `signedAttrs`: the SignerInfo signature does **not** cover the raw eContent directly. Instead:

1. The signer computes `messageDigest = SHA-256(eContent)` and places it in a `signedAttrs` attribute (OID 1.2.840.113549.1.9.4).
2. The signer DER-encodes the `signedAttrs` SET, rewrites the outer tag from `[0]` IMPLICIT (`0xA0`) to SET (`0x31`), and signs `SHA-256` of that.
3. Verification reverses: check `messageDigest == SHA-256(eContent)`, then verify the signature over `SHA-256(rewritten signedAttrs DER)` using the signer's SPKI.

`host_verify` in this crate implements the CAdES-BES flow; the Longfellow circuit will mirror it. See `src/verify.rs::verify_content_signature`.

## KAT vectors

The `fixtures/kat-subject-serial.json` file contains independently-derived subject serialNumber offsets produced by identityescroworg's TypeScript ASN.1 pipeline (`@peculiar/asn1-schema`). Our `tests/fixture_kat.rs` cross-validates our Rust parser (`cms` + `x509-cert`) against these values. Divergence would indicate either an ASN.1-encoding bug or a structural misalignment between the two parsers.

## Trust anchor extraction

The DIIA QTSP root pubkey used in tests (`DIIA_ROOT_PK` in `tests/fixture_diia.rs`) was extracted from `diia-qtsp-2311.der`:

```bash
openssl x509 -in diia-qtsp-2311.der -inform DER -pubkey -noout \
  | python3 -c "import sys, base64; data = sys.stdin.read().replace('-----BEGIN PUBLIC KEY-----','').replace('-----END PUBLIC KEY-----','').strip(); print(base64.b64decode(data)[-65:].hex())"
```

The source cert lives in identityescroworg at `packages/lotl-flattener/fixtures/diia/certs/diia-qtsp-2311.der`. It can also be fetched directly from the Ukrainian Trust List (`ua-msTl.xml` in the same directory).

If DIIA rotates keys, re-run the above on the new cert and update `DIIA_ROOT_PK`.

## Fixtures

- `fixtures/binding.qkb.p7s` — the primary DIIA QKB binding document (TINUA-3627506575).
- `fixtures/admin-binding.qkb.p7s` — a second, independently-signed binding for the same stable_id. Used for the cross-fixture nullifier-equality test.
- `fixtures/kat-subject-serial.json` — KAT vectors for subject serialNumber extraction.

## Tests

- `tests/fixture_diia.rs` — end-to-end: offsets, outputs, context mismatch, host_verify against real DIIA 2311 root.
- `tests/fixture_kat.rs` — parser cross-validation against identityescroworg KAT.
- `tests/fixture_cross.rs` — same stable_id across two p7s files → identical nullifier + binding_hash.

Run all:

```bash
cargo test -p zk-eidas-p7s
```
