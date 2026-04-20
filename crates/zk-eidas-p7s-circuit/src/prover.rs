//! Proof generation — Task 1b (invariant 9: SHA-256(context_bytes)).

use crate::{witness::Task1bWitness, CircuitError};

#[derive(Debug, Clone)]
pub struct Proof {
    pub bytes: Vec<u8>,
}

/// Phase 2a Task 1b prover.
///
/// Produces a Longfellow proof for the predicate
/// `context_hash == SHA-256(context_bytes)`. `context_bytes` must be at
/// most `longfellow_sys::p7s::CONTEXT_MAX_BYTES` long (v1 = 32 bytes).
pub fn prove(witness: &Task1bWitness) -> Result<Proof, CircuitError> {
    match longfellow_sys::p7s::prove(&witness.context_hash, &witness.context_bytes) {
        Ok(p) => Ok(Proof { bytes: p.0 }),
        Err(e) => Err(CircuitError::from(e)),
    }
}
