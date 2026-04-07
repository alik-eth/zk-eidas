# Formal Verification

## Current Status

As of April 2026, **no mechanized formal verification exists for Longfellow**. Google's IETF draft (draft-google-cfrg-libzk, Section 8) explicitly states: *"It is a goal to provide a mechanically verifiable proof for a high-level statement of the soundness."*

The system's security rests on:
- Paper proofs from eprint 2024/2010
- Three external security reviews (see [Audits](audits.md))
- The Ligero Security Analysis (Dec 2025) with two concrete security theorems

## Isabelle Sumcheck Formalization

The most relevant existing formalization is the **Isabelle/HOL proof of sumcheck soundness** (CSF 2024):

- **Authors**: Azucena Garvia Bosshard, Jonathan Bootle, Christoph Sprenger
- **Paper**: [arXiv:2402.06093](https://arxiv.org/abs/2402.06093)
- **Source**: [Archive of Formal Proofs](https://www.isa-afp.org/entries/Sumcheck_Protocol.html)
- **Properties proven**: Completeness (zero error) and soundness (error <= `n * deg(p) / |F|`)

The formalization is modular — designed for instantiation with different mathematical structures. It has **not** been instantiated for Longfellow's specific fields and polynomials.

Notable: Garvia Bosshard is now a Software Engineer at Google, suggesting internal alignment with Longfellow.

## Lean 4 Ecosystem

The ZK formal verification community has converged on Lean 4. Key projects:

| Project | What It Covers |
|---------|---------------|
| **ArkLib** (Verified-zkEVM) | Oracle reductions, sumcheck (in progress) |
| **VCVio** (U Minnesota) | Fiat-Shamir transform formalization |
| **ArkLibFri** (Nethermind) | FRI formal verification |
| **Clean** (zkSecurity) | Circuit DSL for verified ZK in Lean 4 |

## Gap Analysis

| Component | Formalized? | Where |
|-----------|------------|-------|
| Sumcheck soundness | Yes (abstract) | Isabelle/HOL (AFP) |
| Sumcheck for Longfellow fields | No | Needs instantiation |
| Ligero commitment | No | Paper proofs only |
| GKR reduction | No | Not formalized anywhere |
| SHA-256 circuit correctness | No | No tool for C++ circuits |
| Fiat-Shamir (Longfellow) | No | VCVio covers sigma protocols, not IOPs |

The fundamental gap: **no ZK formal verification tool supports C++ circuit definitions**. All existing tools (Picus, Ecne, Coda, CertiPlonk) target Circom/R1CS/gnark/Plonky3.

## Recommended Path

**Minimal meaningful formalization in Lean 4** (3-5 months):

1. Port Isabelle sumcheck axioms to Lean 4 (2 months)
2. Instantiate for multilinear polynomials over Longfellow's fields (1 month)
3. Formalize the GKR reduction for layered circuits (2-3 months)

This would produce the **first mechanized soundness proof for any Longfellow component** — publishable and useful for IETF standardization.

## Who Could Execute

- **Nethermind FV team** — Lean 4, did SP1 + CertiPlonk
- **zkSecurity** — Lean 4, ArkLib, Clean DSL
- **Christoph Sprenger** (ETH Zurich) — wrote the Isabelle sumcheck proof
- **Devon Tuma** (U Minnesota) — wrote VCVio (Fiat-Shamir in Lean)
