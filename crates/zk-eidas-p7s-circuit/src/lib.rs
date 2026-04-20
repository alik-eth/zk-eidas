//! Longfellow circuit facade for eIDAS 1 p7s witnesses.
//!
//! Phase 2a: scaffolding + invariants 9, 4, 5, 6, 10, 2b, 1, 2a.
//! Phase 2b: adds invariants 3, 7, 8 (DER walker + stable_id-dependent).

pub mod prover;
pub mod verifier;
pub mod witness;

pub use prover::{prove, Proof};
pub use verifier::{verify, PublicInputs};
pub use witness::Witness;

#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    #[error("invalid witness: {0}")]
    InvalidWitness(String),
    #[error("context length {got} exceeds MAX_CONTEXT = {max}")]
    ContextTooLong { got: usize, max: usize },
    #[error("prover failed with code {0}")]
    ProverFailed(u32),
    #[error("verifier failed with code {0}")]
    VerifierFailed(u32),
    #[error("FFI returned null/empty proof")]
    MalformedProof,
}

impl From<longfellow_sys::p7s::P7sFfiError> for CircuitError {
    fn from(e: longfellow_sys::p7s::P7sFfiError) -> Self {
        use longfellow_sys::p7s::P7sFfiError;
        match e {
            P7sFfiError::ProveFailed(c) => CircuitError::ProverFailed(c),
            P7sFfiError::VerifyFailed(c) => CircuitError::VerifierFailed(c),
            P7sFfiError::MalformedProof => CircuitError::MalformedProof,
        }
    }
}
