# Two-Party Nullifier Support for Vehicle Sale

**Date:** 2026-03-23
**Status:** Draft
**Scope:** Vehicle sale contract generates two independent nullifiers (seller + buyer)

## Problem

Current demo generates one nullifier per contract. Only one party is cryptographically bound to the document — equivalent to a contract where one person signed and the other didn't.

A bilateral contract requires both parties to be independently identifiable (via court resolution) and independently provable (via nullifier ownership). Without two nullifiers, the contract is cryptographically one-sided.

## Solution

Each party generates their own ZK proof and nullifier independently, using the same `contract_hash` but their own credential and salt. The existing nullifier circuit is party-agnostic — no circuit changes needed. The contract flow calls the circuit twice, once per human party.

### MVP Approach

Both parties are simulated on the same device in a single-pass prove loop. The frontend iterates over template credentials as today, but generates a nullifier for each role that has a `nullifierField`. No role-selection UI, no two-device flow.

## Data Model Changes

### ContractNullifier (Rust types crate)

Add `role` field:

```rust
pub struct ContractNullifier {
    pub role: String,           // NEW: "seller", "buyer", "holder", etc.
    pub nullifier: Vec<u8>,
    pub contract_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub proof: ZkProof,
}
```

The `role` is set by the caller (demo API or builder). The `contract_prove` endpoint receives `role` as a new optional request field. When absent, defaults to `"holder"` for backward compatibility. The frontend passes `req.role` from the template's `CredentialRequirement`.

### CompoundProof (Rust types crate)

Migrate from `Option<ContractNullifier>` to `Vec<ContractNullifier>`:

```rust
pub struct CompoundProof {
    proofs: Vec<ZkProof>,
    op: LogicalOp,
    ecdsa_proofs: HashMap<String, ZkProof>,
    contract_nullifiers: Vec<ContractNullifier>,  // was Option<ContractNullifier>
}
```

**Serde backward compatibility** — implemented via custom `Deserialize`:

```rust
// Serialization: always writes "contract_nullifiers": [...]
// Deserialization: custom impl that:
//   1. Tries "contract_nullifiers" (new array format) first
//   2. Falls back to "contract_nullifier" (old Option format):
//      - Some(cn) → vec![cn] with role defaulting to "holder"
//      - None/null → vec![]
//   3. If neither field present → vec![]
```

This is a custom `impl<'de> Deserialize<'de> for CompoundProof` (not derive), because standard derive cannot express "try field A, fall back to field B with a transformation." The implementation uses a helper struct with both fields as `Option` and resolves in `deserialize()`.

**Pre-warm cache note:** The `proof-cache.json` file contains serialized `CompoundProof` JSON with `"contract_nullifier": null`. The custom deserializer handles this — `null` maps to empty vec. No pre-warm script changes needed, but the cache file will roundtrip with the new field name (`contract_nullifiers`) after the next re-warm.

Builder API on `CompoundProof`:
- `add_contract_nullifier(cn)` — push to vec (new primary method)
- `with_contract_nullifier(cn)` — alias for `add_contract_nullifier` (backward compat)
- `contract_nullifiers() -> &[ContractNullifier]` — new accessor
- `contract_nullifier() -> Option<&ContractNullifier>` — returns first (backward compat)

### ZkCredential Builder (Rust facade crate)

The `ZkCredential` builder in `builder.rs` currently has:
- `contract_nullifier(field, hash, salt)` — sets `self.contract_nullifier_params = Some(...)`
- `prove_compound()` — generates one nullifier and attaches via `with_contract_nullifier`

For two-party support, the `ZkCredential` builder is NOT changed. It remains a per-credential builder that produces one `CompoundProof` with at most one nullifier. The multi-nullifier assembly happens at the **demo API level**: the `contract_prove` endpoint is called once per credential, each call produces its own `CompoundProof` with its own nullifier, and the frontend collects them into `PartyProof[]`.

The `generate_nullifier()` method on `ZkCredential` is also unchanged — it already works standalone and returns a `ContractNullifier` that the caller can attach to any `CompoundProof`.

### CredentialRequirement (frontend)

Add `nullifierField` to declare which claim is the credential_id for nullifier generation:

```ts
interface CredentialRequirement {
  role: string
  roleLabelKey: string
  credentialType: string
  predicateIds: string[]
  disclosedField: string
  nullifierField?: string   // NEW: e.g. 'document_number'
}
```

Vehicle sale template sets `nullifierField: 'document_number'` on seller and buyer roles, but NOT on vehicle (vehicle is bound via holder binding).

Single-party templates (age_verification, student_transit, driver_employment) also get `nullifierField` on their single credential for unified rendering.

### ContractWizardState (frontend)

Replace single nullifier with per-party array:

```ts
interface PartyProof {
  role: string
  roleLabelKey: string
  nullifier: string
  salt: string
  issuer: string
  qrDataUrls: string[]
}

interface ContractWizardState {
  // ... existing fields ...
  partyProofs: PartyProof[]    // was: nullifier, salt (single)
  contractHash: string | null  // shared across parties
}
```

## API Changes

### contract_prove endpoint

**Request** — two new optional fields:

```rust
struct ContractProveRequest {
    credential: String,
    format: String,
    predicates: Vec<PredicateRequest>,
    contract_terms: String,
    timestamp: String,
    skip_cache: bool,
    nullifier_field: Option<String>,  // NEW: which claim to use as credential_id
    role: Option<String>,             // NEW: party role for the nullifier (e.g. "seller")
}
```

When `nullifier_field` is present, use that claim as the credential_id for nullifier generation. When absent, fall back to current auto-detection (iterates `["document_number", "license_number", "diploma_number", "vin", "student_number"]`). The `nullifier_field` approach is preferred because it is explicit and avoids ambiguity for credentials with multiple candidate fields (e.g., vehicle has both `vin` and `owner_document_number`).

When `role` is present, it is passed through to the `ContractNullifier.role` field. When absent, defaults to `"holder"`.

**Response** — add `role` field:

```rust
struct ContractProveResponse {
    compound_proof_json: String,
    op: String,
    sub_proofs_count: usize,
    hidden_fields: Vec<String>,
    nullifier: String,
    contract_hash: String,
    salt: String,
    role: String,   // NEW: echoes back the role
}
```

**contract_hash computation fix:**

Current code mixes salt into contract_hash: `SHA256(terms || timestamp || salt)`. This makes contract_hash different per call, breaking multi-party support where both parties must share the same contract_hash.

Fix: `contract_hash = SHA256(terms || timestamp)`. Salt remains only as a nullifier circuit input. Chain: `content -> hash -> proof -> nullifier`. No circularity.

The hash is deterministic: same `(terms, timestamp)` pair always produces the same hash. No override parameter needed — the frontend computes the timestamp once before the prove loop and passes the same value to all calls. Both parties' calls produce identical `contract_hash` values naturally.

**Behavioral note on single-party contracts:** This changes existing behavior — currently every call produces a unique contract_hash (because salt was mixed in). After this change, two calls with identical `(terms, timestamp)` produce the same hash. This is semantically more correct: the hash identifies the *contract content*, not the party. Per-party uniqueness is provided by the nullifier (which includes salt). This is an intentional semantic improvement, not a bug.

**Note on old cached proofs:** Any `CompoundProof` JSON containing old-style `contract_hash` values (with salt baked in) will have hashes that cannot be re-derived from `(terms, timestamp)` alone. This only affects the demo's `proof-cache.json`, which does not store contract nullifiers for predicate-only cache entries. The ECDSA commitment cache entries are unaffected (they store commitment data, not contract hashes). No migration concern in practice.

### Pre-warm impact

No pre-warm script changes needed:
- Predicate proof cache is keyed by `format|predicates`, party-agnostic
- ECDSA commitment cache is keyed by `credential_id` (u64). One PID warm covers both seller and buyer (same demo credential values)
- Pre-warm calls `contract-prove` with `skip_cache: true` — only cares about ECDSA commitment extraction, not the nullifier output
- Cached `CompoundProof` JSON in `proof-cache.json` has `"contract_nullifier": null` — the custom deserializer handles this (maps to empty vec). After the next re-warm cycle, the file will use the new `contract_nullifiers` field name

### /demo route impact

Zero changes. `/demo` uses `/holder/prove` (different endpoint, different code path, different state).

## Frontend Flow Changes

### Prove loop (contracts.tsx)

Current: loops over `template.credentials`, generates nullifier only for `ci === 0`.

New: same single-pass loop, but for each credential whose requirement has a `nullifierField`, passes it to the API and collects a `PartyProof`. The timestamp is computed once before the loop to ensure deterministic `contract_hash` across all calls:

```ts
const partyProofs: PartyProof[] = []
let sharedContractHash: string | null = null
const timestamp = new Date().toISOString()  // computed ONCE

for (let ci = 0; ci < template.credentials.length; ci++) {
  const req = template.credentials[ci]
  const config = CREDENTIAL_TYPES.find(ct => ct.id === req.credentialType)

  // Build request with new fields
  const proveRes = await fetch(`${API_URL}/holder/contract-prove`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credential: cred.credential,
      format: cred.format,
      predicates,
      contract_terms: JSON.stringify(selectedTemplate),
      timestamp,                                  // shared across calls
      nullifier_field: req.nullifierField ?? undefined,  // NEW
      role: req.role,                                    // NEW
      ...(forceSkipCache ? { skip_cache: true } : {}),
    }),
  })
  const proveData = await proveRes.json()

  // ... existing QR generation ...

  if (req.nullifierField && proveData.nullifier) {
    if (!sharedContractHash) {
      sharedContractHash = proveData.contract_hash
    }
    partyProofs.push({
      role: req.role,
      roleLabelKey: req.roleLabelKey,
      nullifier: proveData.nullifier,
      salt: proveData.salt,
      issuer: config.issuer,
      qrDataUrls: qrUrlsForThisCredential,
    })
  }
}

setState(prev => ({
  ...prev,
  partyProofs,
  contractHash: sharedContractHash,
}))
```

### A4 Document Preview (contracts.tsx)

Replace single nullifier block with per-party layout:

```
ПРОДАВЕЦЬ / SELLER
Нуліфікатор:    0x7fa39b2e...
Сіль:           0x4cb4957d80cb7c39
Видавець:       Diia / UA QTSP
ZK-докази:      [QR 1/3] [QR 2/3] [QR 3/3]

ПОКУПЕЦЬ / BUYER
Нуліфікатор:    0x0b711ad4...
Сіль:           0xa8e3f12c90bd4517
Видавець:       Diia / UA QTSP
ZK-докази:      [QR 1/3] [QR 2/3] [QR 3/3]

СПІЛЬНЕ / SHARED
Хеш контракту:  0xf06ae8840d101b71
Дата:           23 March 2026
```

Two signature lines instead of one. QR codes grouped per party.

Single-party templates render one block naturally — `partyProofs` has one entry.

## i18n

One new key: shared section header `contracts.shared` → `"SHARED" / "СПІЛЬНЕ"`.

Existing keys reused: `contracts.role.seller`, `contracts.role.buyer`, `contracts.nullifier`, `contracts.salt`, `contracts.contractHash`.

## Edge Cases

- **Different issuers:** Seller has Diia credential, buyer has French QTSP. Each block shows its own issuer. Court sends requests to respective issuers.
- **Same person as buyer and seller:** Different nullifiers (different salt), same credential_id. Issuer identifies the same person. Valid case (e.g., transferring vehicle to own company).
- **One party refuses:** Contract incomplete — equivalent to refusing to sign. PartyProofs array has fewer entries than expected.
- **Credential revocation between parties:** Proofs are valid at time of generation. Revocation is not retroactive.

## Out of Scope

- Two-device flow (separate task, MVP simulates both on one device)
- Vehicle nullifier (3rd nullifier for VIN — can add later via `nullifierField: 'vin'`)
- Nullifier registry / double-spend checking backend
- Static mockup PDF for outreach emails
- Verification endpoint changes (already per-proof)
- Court resolution protocol (institutional, not code)
- `nullifier.circom` circuit changes (already party-agnostic)
- Pre-warm script changes (custom deserializer handles old cache format)
- `/demo` route changes

## Change Summary

1. **`ContractNullifier`** — add `role: String` field
2. **`CompoundProof`** — `Option<ContractNullifier>` → `Vec<ContractNullifier>` with custom `Deserialize` impl for backward compat
3. **`contract_prove` endpoint** — add `nullifier_field` + `role` params, remove salt from contract_hash computation (deterministic hash from shared timestamp)
4. **`ContractTemplate`** — add `nullifierField` to `CredentialRequirement`
5. **`contracts.tsx` prove loop** — compute timestamp once, pass `nullifier_field` + `role` to API, collect `PartyProof[]`
6. **`contracts.tsx` A4 preview** — render per-party nullifier blocks with grouped QRs, two signature lines
7. **1 new i18n key** — shared section header
