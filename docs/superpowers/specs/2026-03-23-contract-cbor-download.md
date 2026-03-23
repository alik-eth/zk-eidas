# Contract Proof Bundle Download

**Date:** 2026-03-23
**Status:** Draft
**Scope:** Add CBOR download to /contracts, update /verify file handler to support bundle format

## Problem

The `/demo` page offers a `.cbor` download for digital proof verification via file drop on `/verify`. The `/contracts` page has no equivalent — proofs are only available via QR scanning. Users need a digital backup option.

## Solution

### Bundle Format

All contract proofs are bundled into a single CBOR file:

```
{
  version: 2,
  proof_envelopes: [ ProofEnvelope, ProofEnvelope, ... ],
  terms: { terms: string, timestamp: string },
  metadata: { contract_hash: string, parties: [{ role: string, nullifier: string, salt: string }] }
}
```

- `version: 2` distinguishes from old-style single ProofEnvelopes (which have `version: 1` and a `proofs` array at the top level).
- `proof_envelopes` contains one decoded ProofEnvelope object per credential (seller, vehicle, buyer for vehicle sale).
- `terms` contains the same data as the terms QR: `JSON.stringify(selectedTemplate)` and the ISO 8601 timestamp.
- `metadata` contains the same data as the metadata QR: contract_hash and per-party nullifier/salt entries.
- Single-party contracts use the same bundle format (one proof_envelope, one party entry).

### Format Detection on /verify

The `/verify` file drop handler (`handleFile`) detects the format:

- If decoded CBOR has `version === 2` → **bundle path**: extract `proof_envelopes`, flatten all proofs, set `contractTerms` from `terms`, set `contractMeta` from `metadata`, run `runVerificationPipeline` (same as QR scan auto-verify).
- If decoded CBOR has a top-level `proofs` array → **legacy path**: existing single-envelope behavior with manual "Verify All" button.

### contracts.tsx Changes

- After proving, collect all per-credential CBOR data (already available as `compressed_cbor_base64` from the export endpoint).
- Decode each compressed CBOR back to ProofEnvelope objects (decompress + CBOR decode).
- Bundle with terms + metadata into the v2 format.
- CBOR-encode the bundle, convert to base64 data URL.
- Store the data URL in `ContractWizardState` as `bundleCborUrl: string | null`.
- Add a "Download .cbor" button next to the "Print" button on the document step (Step 4).
- Download filename: `zk-eidas-contract-{templateId}.cbor` (e.g., `zk-eidas-contract-vehicle_sale.cbor`).

### verify.tsx Changes

- `handleFile` gains a format check at the top: if `envelope.version === 2`, route to bundle handler.
- Bundle handler iterates `envelope.proof_envelopes`, extracts all proofs into `DecodedProof[]` (same extraction logic as legacy path but repeated per envelope).
- Sets `contractTerms` and `contractMeta` state from the bundle's `terms` and `metadata` fields.
- Calls `runVerificationPipeline` for auto-verify (same as QR scan path).
- Sets `fileName` to the uploaded file's name.

### Security

No new trust model. The bundle contains the same data as QR scanning:
- Proofs are cryptographically verified against trusted VKs.
- Contract hash is cross-checked via `SHA256(terms ∥ timestamp)[0..8]`.
- Nullifier binding is checked via Poseidon hash.
- Role labels remain unverified convenience data.

## Out of Scope

- Changing `/demo` download format (stays as single ProofEnvelope)
- Bundle signing or encryption
- Multi-file download
