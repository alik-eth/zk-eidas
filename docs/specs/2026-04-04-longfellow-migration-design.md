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

### Predicate Circuits — `assert_attribute()` Modification

**Approach validated by ID-wallet-snark/longfellow-zk fork.** Instead of standalone predicate gadgets composed via MAC, we extend the existing `assert_attribute()` function in `mdoc_hash.h` to support comparison types beyond equality.

**How it works:** Add a `verification_type` field (2 bits, packed into the attribute length byte's top bits) to `RequestedAttribute`. The hash circuit already extracts attribute values during CBOR parsing and compares them — we change the comparison from equality-only to type-selected:

```cpp
// Inside assert_attribute():
auto is_leq = CMP.leq(n, val_got, val_want);  // val_got <= val_want
auto is_geq = CMP.leq(n, val_want, val_got);  // val_got >= val_want
auto is_eq  = lc_.land(is_leq, is_geq);        // val_got == val_want

// Select based on verification_type (0=EQ, 1=LEQ, 2=GEQ, 3=NEQ)
auto pass = mux(type, is_eq, is_leq, is_geq, lnot(is_eq));
lc_.assert1(pass);
```

Date strings (e.g., `"1998-09-04"`) are compared lexicographically via `Memcmp::leq` — no epoch conversion needed. This is the same primitive upstream already uses for `validFrom <= now`.

| Predicate | verification_type | How it works |
|---|---|---|
| eq | 0 | `val_got == val_want` (original behavior) |
| lte / "age >= N" | 1 | `birth_date <= cutoff_date` (lexicographic) |
| gte | 2 | `val_got >= val_want` (lexicographic) |
| neq | 3 | `val_got != val_want` |
| range | Two attributes | One LEQ + one GEQ on same field |
| set_member | Multiple EQ attributes | OR over multiple EQ checks on same field |

**Changes required:** ~3 lines in `mdoc_zk.h` (add `verification_type` to `RequestedAttribute`), ~20 lines in `mdoc_hash.h` (branch logic in `assert_attribute()`). No new circuits, no MAC composition changes, no new witness generation.

### Nullifier

Computed inside the hash circuit: `SHA-256(credential_id || contract_hash || salt)`.

- `credential_id` is private (extracted from mdoc CBOR during parsing)
- `contract_hash` and `salt` are public inputs
- `nullifier` is a public output
- No extra MAC composition needed — data is already in scope
- **Note:** Google's PR #134 (balfanz:ppid) adds HMAC-SHA256 pseudonyms internally. If this ships upstream, we should adopt their approach instead.

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

Forked to `alik-eth/longfellow-zk`. Upstream tracked via `upstream` remote.

### Predicate Integration (Minimal Diff)

Following the approach validated by ID-wallet-snark/longfellow-zk:

1. **`mdoc_zk.h`** — Add `uint8_t verification_type;` to `RequestedAttribute` struct (~3 lines)
2. **`mdoc_hash.h`** — Modify `assert_attribute()` to decode `verification_type` and branch on EQ/LEQ/GEQ/NEQ using `Memcmp::leq()` (~20 lines)
3. **`mdoc_zk.cc`** — Pass `verification_type` through in `fill_attributes()` (~2 lines)

No new circuits, no new files for predicates. The existing `run_mdoc_prover` / `run_mdoc_verifier` C API stays unchanged — predicates are encoded in the `RequestedAttribute.verification_type` field.

### Nullifier & Binding (New Circuits)

These require new SHA-256 computations inside the hash circuit:
- Nullifier: `SHA-256(credential_id || contract_hash || salt)` → new public output
- Binding: `SHA-256(binding_field)` → new public output
- Credential hash for escrow: `SHA-256(field_0 || ... || field_N)` → new public output

These use `FlatSHA256Circuit` (already available in the hash circuit) and require modifying `mdoc_hash.h` to add the computation + witness generation.

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
