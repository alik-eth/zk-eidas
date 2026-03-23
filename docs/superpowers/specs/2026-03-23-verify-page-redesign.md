# Verify Page Redesign: Complete Document Verification

**Date:** 2026-03-23
**Status:** Draft
**Scope:** Improve /verify scan UX, add contract integrity check, add nullifier party calculator

## Problem

The current /verify page has three UX issues:

1. **Scan progress is misleading** — shows "1/1" per proof (chunk-level progress) when each proof fits in a single QR. Useless for multi-proof contracts.
2. **Post-verify display is opaque** — shows raw predicate op names ("Lte", "Gte", "Neq") with no public input values. A technical user can't interpret what was proved.
3. **No nullifier verification** — a party to the contract cannot verify that their credential_id matches a nullifier on the document. No way to confirm "I am the seller in this contract."

## Solution

### QR Protocol Extension

Extend the existing chunked QR protocol with two reserved `proofIndex` values for non-proof data:

| proofIndex | Meaning | Content |
|---|---|---|
| 0x00–0xFD | Proof data (existing) | Compressed CBOR ProofEnvelope |
| 0xFE | Contract terms | Compressed CBOR `{ terms: string, timestamp: string }` (timestamp is ISO 8601 UTC, e.g. `"2026-03-23T14:30:00.000Z"`, stored verbatim from the frontend's `new Date().toISOString()` call — no re-formatting) |
| 0xFF | Contract metadata | Compressed CBOR `{ contract_hash: string, parties: [{ role: string, nullifier: string, salt: string }] }` |

All values in metadata/terms QRs are hex strings (contract_hash, nullifier, salt) or plain strings (terms, timestamp, role).

**proofId assignment:** Proof QRs use `proofId = ci + 1` (1-based credential index) as today. Terms QR uses `proofId = 0xFFFE`. Metadata QR uses `proofId = 0xFFFF`. These are distinct from any proof proofId (max 0xFD credentials).

**proofCount semantics:** The `proofCount` field in the QR header counts the total number of distinct `proofId` groups — proof QRs + terms + metadata. For a vehicle sale: 3 proof groups + terms + metadata = `proofCount = 5`.

**Single-chunk expectation:** Terms and metadata payloads are expected to fit in a single QR chunk (max 2945 bytes after compression). The terms QR carries `JSON.stringify(selectedTemplate)` which is typically 500-800 bytes. A runtime assertion should enforce `totalChunks === 1` for these special QRs.

**proofCount ceiling:** The `proofCount` field is a single byte (max 255). No realistic contract approaches this limit.

**Note on terms content:** The `terms` field in the terms QR must carry exactly what the backend hashed — `JSON.stringify(selectedTemplate)` (the template JSON object). This is NOT the human-readable contract body text. The backend computes `contract_hash = SHA256(JSON.stringify(selectedTemplate) || timestamp)` truncated to u64, so the verifier must hash the same input.

On the paper document:
- **Page 1**: contract text + **terms QR** (bottom corner)
- **Page 2**: per-party blocks with proof QRs + **metadata QR** (in the shared section)

Single-party contracts (age_verification, student_transit, driver_employment) get the same treatment — metadata QR has one party entry.

**Party inclusion rule:** Only credentials with a `nullifierField` produce a party entry in the metadata QR. The vehicle credential (no `nullifierField`) is excluded — it contributes proof QRs but no party entry.

### Scan Flow Improvements

Replace per-chunk progress with overall QR progress. The scanner reads `proofCount` from the first scanned QR header and shows:

```
Scanned 2 of 5 QR codes
[████████████░░░░░░░░]
```

A checklist is built dynamically — items are added as each new distinct `proofIndex` is first encountered:

```
✓ Contract terms          (added when first 0xFE chunk scanned)
✓ Proof 1                 (added when first proofIndex=0 chunk scanned)
✓ Proof 2                 (added when first proofIndex=1 chunk scanned)
○ Proof 3                 (added when first proofIndex=2 chunk scanned)
○ Contract metadata       (not yet seen)
```

The checklist never pre-populates unseen entries. For proof QRs, the checklist label uses `verify.proofN` with `n = proofIndex + 1` (1-based display ordinal). The overall progress bar uses `proofCount` from the header for the denominator and `collector.proofIds().length` (distinct completed groups) for the numerator.

**Order-independent** — user can scan in any order. ChunkCollector doesn't care.

**Single-party documents** — same flow, fewer QRs (e.g., 3 total: 1 proof + terms + metadata).

### Post-Scan Verification Pipeline

After all QRs scanned, the verify page runs a three-stage pipeline automatically (no manual "Verify" button click):

**Stage 1: Proof Verification**

Verify each proof against trusted VKs using snarkjs. Show results with public input values:

```
PROOF VERIFICATION
✓ Gte  — public inputs: [6935, 1]          2,147 bytes
✓ Neq  — public inputs: [a7c3f0...]        2,091 bytes
✓ Lte  — public inputs: [19832]            2,103 bytes
```

**Stage 2: Contract Hash Cross-Check**

The `contract_hash` is a truncated SHA-256: `u64_BE(SHA256(terms ∥ timestamp)[0..8])`. This matches the Rust backend's computation in `contract_prove`.

Compute `SHA256(terms_string + timestamp_string)` from the scanned terms QR using Web Crypto API, take the first 8 bytes as big-endian u64, format as `0x` + 16 hex chars. Compare to `contract_hash` from the metadata QR.

```
CONTRACT INTEGRITY
✓ contract_hash matches SHA256(terms ∥ timestamp)[0..8]
  0xf06ae8840d101b71
```

If mismatch: red warning — "Contract hash does not match terms content. Document may be tampered."

**Stage 3: Party Summary**

Display parties from metadata QR:

```
PARTIES
  SELLER   nullifier: 0x7fa39b2e...   salt: 0x4cb4957d...
  BUYER    nullifier: 0x0b711ad4...   salt: 0xa8e3f12c...
```

Single-party contracts show one entry with the role from metadata (e.g., "HOLDER").

No verification in this stage — just displaying scanned data. The nullifier check is user-initiated.

### Nullifier Calculator

Below the automated pipeline results, a collapsible section:

```
▸ VERIFY PARTY IDENTITY
```

Expanded:

```
▾ VERIFY PARTY IDENTITY

  Document number: [________________________]  [Check]

  ✓ Match: SELLER nullifier (0x7fa39b2e...)
    Poseidon(credential_id, contract_hash, salt) = nullifier ✓
```

**How it works:**

1. User enters their credential_id string (e.g., "UA-1234567890")
2. Browser converts to u64: `credential_id = u64_BE(SHA256(utf8_bytes(string))[0..8])`
3. For each party in metadata: parse hex strings to BigInt, compute `poseidon([BigInt(credential_id), BigInt(contract_hash), BigInt(salt)])` using circomlibjs
4. Compare Poseidon output to `BigInt(nullifier)` — if match, show which party matched
5. If no match: "No party in this document matches this credential."
6. If match on multiple parties (same person as buyer and seller): show both matches.

**Type conversions for Poseidon:**
- `credential_id`: `BigInt("0x" + hex(SHA256(string)[0..8]))` — same as Rust `ClaimValue::to_circuit_u64()` for strings
- `contract_hash`: `BigInt("0x" + contract_hash_hex)` — already a hex string from metadata QR
- `salt`: `BigInt("0x" + salt_hex)` — already a hex string from metadata QR
- `nullifier`: `BigInt("0x" + nullifier_hex)` — for comparison

All are u64 values represented as BigInt for circomlibjs.

**String-to-field conversion** mirrors the Rust prover's `ClaimValue::to_circuit_u64()`:
- SHA-256 of the UTF-8 string bytes via `crypto.subtle.digest('SHA-256', ...)`
- Take first 8 bytes as big-endian u64

**Dependencies:**
- `circomlibjs` for Poseidon hash — bundled and cached by service worker for PWA/offline use
- `crypto.subtle.digest('SHA-256', ...)` for string-to-field conversion and contract hash cross-check — native browser API, no dependency

### Security Model

All displayed information is either cryptographically verified or cross-checkable:

- **Predicate type (Gte, Lte, etc.)** — determined by which VK the proof verifies against. Wrong VK = verification fails. Cannot be faked.
- **Public input values** — cryptographically bound to the proof. Extracted after verification.
- **Contract hash** — cross-checked by recomputing `SHA256(terms ∥ timestamp)[0..8]` from the terms QR. Tampering detected.
- **Nullifier binding** — verified by Poseidon hash computation. If metadata QR has fake nullifier/salt, the Poseidon check won't match a real credential_id.
- **Role labels** — NOT cryptographically verified. Displayed from metadata QR as convenience. A tampered metadata QR could swap "SELLER"/"BUYER" labels, but the Poseidon check reveals which nullifier matches YOUR credential_id regardless of label.

No embedded metadata is trusted without cross-check. The verify page derives truth from cryptographic data.

## Frontend Changes

### qr-chunking.ts

- Export constants `TERMS_PROOF_INDEX = 0xFE`, `METADATA_PROOF_INDEX = 0xFF`, `TERMS_PROOF_ID = 0xFFFE`, `METADATA_PROOF_ID = 0xFFFF`
- New function `encodeTermsQr(terms, timestamp, proofCount)` — CBOR-encodes `{ terms, timestamp }`, compresses, wraps with header (`proofIndex=0xFE, proofId=0xFFFE`). Asserts single chunk.
- New function `encodeMetadataQr(contractHash, parties, proofCount)` — CBOR-encodes `{ contract_hash, parties }`, compresses, wraps with header (`proofIndex=0xFF, proofId=0xFFFF`). Asserts single chunk.
- `ChunkCollector` gains methods:
  - `hasTerms(): boolean` — checks if proofId 0xFFFE is complete
  - `hasMetadata(): boolean` — checks if proofId 0xFFFF is complete
  - `getTermsData(): { terms: string, timestamp: string } | null` — reassemble + decompress + CBOR decode
  - `getMetadataData(): { contract_hash: string, parties: [...] } | null` — reassemble + decompress + CBOR decode
  - `isContractDocument(): boolean` — returns `hasTerms() && hasMetadata()` (distinguishes new-style from old-style; requires both to be present)
- `isAllComplete()` unchanged in logic — it already checks `this.chunks.size === firstHeader.proofCount`. Since terms and metadata QRs have their own proofIds (0xFFFE, 0xFFFF), they are counted as distinct entries in `this.chunks`.

### contracts.tsx (QR generation)

- After the prove loop, generate a **terms QR** via `encodeTermsQr(JSON.stringify(selectedTemplate), timestamp, proofCount)` — the `terms` field is exactly `JSON.stringify(selectedTemplate)`, matching what the backend hashed
- Generate a **metadata QR** via `encodeMetadataQr(contractHash, partyProofs.map(p => ({ role: p.role, nullifier: p.nullifier, salt: p.salt })), proofCount)`
- `proofCount` in all QR headers updated to `template.credentials.length + 2` (proofs + terms + metadata)
- Terms QR stored separately for page 1 rendering; metadata QR rendered in the shared section on page 2

### verify.tsx

- **Scan progress**: track overall QR count from `proofCount` header, show "Scanned N of M QR codes" with dynamic checklist
- **Auto-verify**: once all QRs collected, immediately run the three-stage pipeline (no manual button) if `collector.isContractDocument()` is true
- **Stage 1**: existing proof verification with public inputs displayed as hex/decimal values
- **Stage 2**: contract hash cross-check — `SHA256(terms + timestamp)[0..8]` vs metadata contract_hash
- **Stage 3**: party summary from metadata QR
- **Nullifier calculator**: collapsible section, credential_id input, circomlibjs Poseidon check
- **Graceful fallback**: if `collector.isContractDocument()` is false (e.g., old single-proof QR from /demo), fall back to current behavior — show proof verification results with manual "Verify" button

### New dependency

- `circomlibjs` — Poseidon hash implementation for the nullifier calculator. Must be included in service worker cache for PWA/offline.

## i18n

New keys (en / uk):
- `verify.scanOverall` — "Scanned {n} of {total} QR codes" / "Зіскановано {n} з {total} QR-кодів"
- `verify.contractIntegrity` — "CONTRACT INTEGRITY" / "ЦІЛІСНІСТЬ КОНТРАКТУ"
- `verify.hashMatch` — "contract_hash matches SHA256(terms ∥ timestamp)" / "contract_hash збігається з SHA256(умови ∥ мітка часу)"
- `verify.hashMismatch` — "Contract hash does not match terms content. Document may be tampered." / "Хеш контракту не збігається зі змістом умов. Документ міг бути підроблений."
- `verify.parties` — "PARTIES" / "СТОРОНИ"
- `verify.verifyParty` — "VERIFY PARTY IDENTITY" / "ПЕРЕВІРИТИ ОСОБУ СТОРОНИ"
- `verify.documentNumber` — "Document number" / "Номер документа"
- `verify.check` — "Check" / "Перевірити"
- `verify.partyMatch` — "Match: {role} nullifier" / "Збіг: нуліфікатор {role}"
- `verify.noMatch` — "No party in this document matches this credential." / "Жодна сторона в цьому документі не відповідає цьому посвідченню."
- `verify.termsQr` — "Contract terms" / "Умови контракту"
- `verify.metadataQr` — "Contract metadata" / "Метадані контракту"
- `verify.proofN` — "Proof {n}" / "Доказ {n}"

## Out of Scope

- **Non-contract proofs** — `/demo` route and standalone proofs don't get metadata/terms QRs
- **Multi-device scanning** — both parties scanning on separate devices is a future feature
- **Nullifier registry / double-spend check** — no backend tracking
- **Human-readable predicate labels** — verifier sees raw ops + public inputs
- **ECDSA commitment chain display** — ECDSA verification happens inside snarkjs already
- **Print/PDF layout changes beyond adding QRs** — just adding terms QR to page 1 and metadata QR to shared section on page 2
