# Longfellow Migration Design

**Date:** 2026-04-04
**Status:** Draft
**Branch:** `longfellow`

## Summary

Migrate zk-eidas from Circom/Groth16 (BN254) to Google's Longfellow ZK proving system (Sumcheck + Ligero). This gives us post-quantum security (SHA-256 only, no pairings), ~17ms ECDSA proving (vs minutes), no trusted setup, and alignment with Google Wallet's mDL stack.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Migration strategy | Build on top of Longfellow (Option A) | Preserve Rust workspace, 252 tests, demo. Circuit work is the same as full rewrite. |
| Credential format | mdoc only (SD-JWT later) | Longfellow has production mdoc circuits. EU ARF mandates both but mdoc is primary for mDL. SD-JWT can be added as Phase 2. |
| Identity escrow | Out-of-circuit encryption (Option C) | ZK proof binds plaintext to signed credential. Encryption (ML-KEM + AES-256-GCM) happens in Rust. Same trust model, simpler circuit. |
| Nullifier | Inside hash circuit (Option A) | Attribute value already available during CBOR parsing. One SHA-256 call, no extra MAC composition. |
| Holder binding | SHA-256 binding hash (Option B) | Device key binding is fragile across issuers. Dedicated hash on field value is robust. |
| Proof storage | IPFS with CID QR (Option A) | Ligero proofs are ~350KB — too large for paper QR chunks. IPFS is content-addressed, immutable, zero infrastructure. |
| Browser proving | Removed | Longfellow is native C++ only. Demo switches to server-only proving. |

## Architecture

### Current Stack
```
SD-JWT/mdoc → Rust Parser → Circom Circuits → Groth16 (BN254) → 192-byte proofs → QR chunks
```

### New Stack
```
mdoc → Longfellow C++ Circuits → Sumcheck+Ligero → ~350KB proofs → IPFS → CID QR
```

### Security Properties

| Property | Current (Groth16) | New (Longfellow) |
|---|---|---|
| Proving system | Pairing-based (broken by Shor) | SHA-256 only (post-quantum) |
| Trusted setup | Required (powers of tau + circuit-specific) | None (transparent) |
| Proof size | 192 bytes | ~350 KB |
| ECDSA prove time | ~227s browser, seconds server | ~17ms |
| Verification time | ~1-2ms | ~10ms |

## Circuit Extensions

All extensions go inside Longfellow's existing hash circuit (GF(2^128) field), not as separate composed circuits. The hash circuit already extracts attribute values during mdoc CBOR parsing — we add constraint gadgets on those values.

### Predicate Circuits

| Predicate | Implementation | Public inputs |
|---|---|---|
| gte | `Memcmp::geq(claim_value, threshold)` | threshold |
| lte | `Memcmp::leq(claim_value, threshold)` | threshold |
| eq | `vassert_eq(claim_value, expected)` | expected |
| neq | `lnot(eq(claim_value, expected))` | expected |
| range | `geq(claim, low) AND leq(claim, high)` | low, high |
| set_member | Iterate set, assert `OR(eq(claim, set[i]))` via boolean flags | set[], set_len |

### Nullifier

Computed inside the hash circuit: `SHA-256(credential_id || contract_hash || salt)`.

- `credential_id` is private (extracted from mdoc CBOR during parsing)
- `contract_hash` and `salt` are public inputs
- `nullifier` is a public output
- No extra MAC composition needed — data is already in scope

### Holder Binding

Computed inside the hash circuit: `SHA-256(binding_field)` output as public signal.

- Same holder with same field value across credentials produces matching hashes
- Works regardless of device key or issuer
- Binding hash is public output, field value stays private

### Identity Escrow

Out-of-circuit design:

1. **In-circuit:** Hash circuit commits attribute values to the signed credential (via MAC + ECDSA verification). The proof output includes a `credential_hash = SHA-256(field_0 || ... || field_N)` as public signal.
2. **Out-of-circuit (Rust):** After proving, encrypt selected fields with ML-KEM-768 (key encapsulation) + AES-256-GCM (symmetric encryption). Attach `credential_hash` for integrity verification.
3. **Verification:** Authority decrypts fields, hashes them, compares against `credential_hash` from the ZK proof.

Trust model is identical to current Poseidon-CTR approach: ZK proof guarantees escrowed plaintext matches the ECDSA-signed credential.

## Proof Storage & Paper Document

### Paper Document (1-2 pages)

**Page 1:**
- Contract header (template name, date, parties)
- Contract terms (predicates proven, disclosed fields)
- Per-credential metadata (nullifier, salt, issuer)
- Proof CID QR — single QR containing `ipfs://<CID>` (~60 bytes)

**Page 2 (if escrow enabled):**
- Escrow envelope metadata (authority name, field list)
- Encrypted blob CID QR (separate IPFS object)

### Verification Flow

1. Scan CID QR from paper document
2. Fetch proof from IPFS gateway (e.g., `https://dweb.link/ipfs/<CID>`)
3. Pass to Longfellow verifier
4. Display results (predicates verified, nullifier, bindings)
5. Fallback: direct CBOR download button for offline verification

## Rust FFI & Crate Changes

### New Crate: `longfellow-sys`

Raw FFI bindings to Longfellow's C API. `build.rs` compiles Longfellow from source via CMake, links `libmdoc_extended.a`. Uses `bindgen` for header generation from `mdoc_zk.h`.

### Crate Changes

| Crate | Change |
|---|---|
| `longfellow-sys` | **New.** FFI bindings to extended Longfellow C API. |
| `zk-eidas-prover` | Replace rapidsnark/ark-circom with Longfellow FFI calls. Remove CircuitLoader, C++ witness generators, RAPIDSNARK_LOCK. |
| `zk-eidas-verifier` | Replace Groth16 verify with Longfellow verifier FFI. |
| `zk-eidas-types` | Update `ZkProof`: remove `verification_key`, add `circuit_id`. `CompoundProof` simplifies to one blob per credential. |
| `zk-eidas` (facade) | Replace `prove_*` internals with Longfellow FFI. Keep builder API. Mark `from_sdjwt()` deprecated. Remove ECDSA caching (no separate ECDSA stage). |
| `zk-eidas-parser` | Keep mdoc parsing. SD-JWT preserved but unused. |
| `zk-eidas-utils` | Minimal changes. |
| `zk-eidas-wasm` | **Deleted.** No browser proving. |
| `demo-api` | Add IPFS upload after proving. Update prove/verify endpoints. Remove `spawn_blocking` for ECDSA. |
| `demo-web` | Remove on-device proving. Replace chunked QR with CID QR. Update verify to fetch from IPFS. Escrow uses AES-256-GCM instead of Poseidon-CTR. |

### Builder API

```rust
// Same public interface, different internals
ZkCredential::from_mdoc(mdoc, circuit_config)
    .predicate("birth_date", Predicate::Gte(18))
    .predicate("nationality", Predicate::SetMember(EU_COUNTRIES))
    .contract_nullifier("document_number", contract_hash, salt)
    .identity_escrow(fields, authority_pubkey)  // out-of-circuit encryption
    .prove_compound()  // → single Longfellow proof + escrow envelope
```

## Longfellow Fork

We fork `google/longfellow-zk` and extend the hash circuit in `lib/circuits/mdoc/`:

### Extended Hash Circuit

Add to `mdoc_hash_circuit.h`:
- Predicate gadgets (gte, lte, eq, neq, range, set_member) applied to extracted attribute values
- Nullifier computation: `SHA-256(credential_id || contract_hash || salt)`
- Binding hash computation: `SHA-256(binding_field)`
- Credential hash for escrow: `SHA-256(field_0 || ... || field_N)`

### Extended C API

```c
// Extended structs
typedef struct {
    int predicate_type;     // 0=gte, 1=lte, 2=eq, 3=neq, 4=range, 5=set_member
    const char* claim_name;
    const uint8_t* value;   // threshold, expected, or set elements
    size_t value_len;
} ZkPredicate;

typedef struct {
    const char* nullifier_field;
    uint64_t contract_hash;
    uint64_t salt;
} ZkNullifierConfig;

typedef struct {
    const char* binding_field;
} ZkBindingConfig;

// Extended prover/verifier
int run_mdoc_prover_extended(
    const uint8_t* circuit, size_t circuit_len,
    const uint8_t* mdoc, size_t mdoc_len,
    const uint8_t* issuer_pk, size_t pk_len,
    const uint8_t* transcript, size_t transcript_len,
    const char** attributes, size_t attr_count,
    const ZkPredicate* predicates, size_t pred_count,
    const ZkNullifierConfig* nullifier,   // nullable
    const ZkBindingConfig* binding,       // nullable
    uint64_t current_time,
    uint8_t* proof_out, size_t* proof_len
);
```

## Migration Phases

### Phase 1: Longfellow Fork + Circuit Extensions
- Fork `longfellow-zk`, add predicate/nullifier/binding extensions to hash circuit
- Build `longfellow-sys` Rust crate, verify FFI works
- Test: single mdoc disclosure + gte predicate via C API from Rust

### Phase 2: Rewire Rust Crates
- Replace prover/verifier internals with Longfellow FFI
- Update types, builder, facade
- Adapt existing 252 native tests to new backend

### Phase 3: IPFS + Demo Update
- Add IPFS upload to demo-api
- Update demo-web: CID QR, remove on-device proving, update verify flow
- Update escrow: ML-KEM + AES-256-GCM (replace Poseidon-CTR)
- Adapt e2e tests (4 contracts × server mode + escrow)

## What Gets Deleted

| Deleted | Reason |
|---|---|
| `circuits/` (9 Circom circuits) | Replaced by Longfellow C++ extensions |
| `circuits/build/` (~2GB zkeys + C++ witnesses) | No longer needed |
| `crates/zk-eidas-wasm/` | No browser proving |
| rapidsnark dependency | Replaced by Longfellow |
| ark-circom dependency | Replaced by Longfellow |
| circomlib dependency | Replaced by Longfellow |
| snarkjs (demo-web) | No browser proving |
| Chunked zkey CDN hosting | No browser proving |
| `RAPIDSNARK_LOCK` mutex | Longfellow is thread-safe |

## What Gets Preserved

| Kept | Reason |
|---|---|
| Builder API pattern (`ZkCredential`) | Same public interface |
| Parser crate (mdoc path) | Still needed for pre-proving credential parsing |
| Demo UI (5-step wizard) | Same flow, minor updates |
| Contract templates | Unchanged |
| Credential types + predicate definitions | Unchanged |
| ML-KEM-768 key encapsulation | Still used for escrow key transport |
| E2E test structure | Adapted, not rewritten |
| `verifier-sdk` package | Updated to use Longfellow verifier |

## Performance Expectations

| Metric | Current | After Migration |
|---|---|---|
| ECDSA proving | ~5s server, ~227s browser | ~17ms |
| Predicate proving | ~1s | <1ms |
| Total prove (Age Verification) | ~2.5s server | <100ms |
| Total prove (Vehicle Sale, 3 creds) | ~5.6s server | <300ms |
| Verification | ~1-2ms | ~10ms |
| Proof size | 192 bytes | ~350 KB |
| Paper document | 1-3 pages (QR chunks) | 1-2 pages (CID QR) |
| Trusted setup | Required | None |
| Quantum resistance | No (BN254 pairings) | Yes (SHA-256 only) |
