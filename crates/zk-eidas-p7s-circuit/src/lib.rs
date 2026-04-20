//! Longfellow circuit facade for eIDAS 1 p7s witnesses.
//!
//! Phase 2a: scaffolding + invariants 9, 4, 5, 6, 10, 2b, 1, 2a.
//! Phase 2b: adds invariants 3, 7, 8 (DER walker + stable_id-dependent).

pub mod prover;
pub mod verifier;
pub mod witness;

pub use prover::{prove, Proof};
pub use verifier::{verify, PublicInputs};
pub use witness::{Task1aWitness, Witness};

#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    #[error("FFI scaffolding not linked")]
    NotLinked,
    #[error("invalid witness: {0}")]
    InvalidWitness(String),
    #[error("prover failed with code {0}")]
    ProverFailed(u32),
    #[error("verifier failed with code {0}")]
    VerifierFailed(u32),
}

/// Sanity check: returns true iff the FFI is linked.
pub fn smoke() -> bool {
    longfellow_sys::p7s::smoke()
}
