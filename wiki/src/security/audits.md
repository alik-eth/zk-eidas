# Audits & Reviews

Longfellow has undergone three independent external security reviews. Reports are available in `vendor/longfellow-zk/docs/static/reviews/`.

## Trail of Bits (August 2025)

**Scope**: Full codebase security review of Longfellow.

**Key finding**: Under-constrained circuit bug — a witness variable was used for string length instead of a public variable, potentially allowing a prover to manipulate the comparison boundary.

**Resolution**: All issues fixed. The fix constrains the length variable to be publicly verifiable.

## ISRG Review (October 2025)

**Reviewer**: David Cook (Internet Security Research Group).

**Key finding**: Critical under-constraining flaw in the mdoc circuit — hash circuit witness index variables were missing bounds checks against MSO length. This could allow field substitution attacks: a malicious prover could swap one credential field for another while producing a valid proof.

**Resolution**: Fixed in Longfellow v0.8.4. Added bounds checks ensuring witness indices are within the declared MSO length.

## Ligero Security Analysis (December 2025)

**Reviewers**: Four academic experts in ZK proofs, interactive oracle proofs, and coding theory.

**Scope**: Formal security analysis of Longfellow's Ligero instantiation, establishing precise concrete security bounds.

**Key results**: Two main security theorems providing:
- Concrete soundness bounds for the Ligero commitment scheme as used in Longfellow
- Security guarantees for the composition of Sumcheck + Ligero

This is the strongest existing assurance for Longfellow's security — concrete bounds rather than asymptotic claims.

## What the Reviews Cover

| Review | Implementation Bugs | Protocol Soundness | Concrete Bounds |
|--------|--------------------|--------------------|-----------------|
| Trail of Bits | Yes (found 1) | No | No |
| ISRG | Yes (found 1) | No | No |
| Ligero Analysis | No | Yes | Yes |

## What's Missing

- **Mechanized verification**: None of these are machine-checked proofs. See [Formal Verification](formal-verification.md).
- **zk-eidas-specific review**: The reviews cover Longfellow itself, not the zk-eidas extensions (predicate gadgets, escrow, TSP attestation). The zk-eidas extensions are relatively thin (~100 lines of C++ in the hash circuit, ~400 lines of Rust escrow crypto) but have not been independently audited.
- **Cryptographic primitive review**: AES-256-GCM and ML-KEM-768 are NIST-standardized and widely reviewed, but their specific use in the identity escrow composition has not been audited.
