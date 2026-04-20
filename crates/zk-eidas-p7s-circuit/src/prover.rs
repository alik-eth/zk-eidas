//! Proof generation — Task 1a hello-world.

use crate::{witness::Task1aWitness, CircuitError};

#[derive(Debug, Clone)]
pub struct Proof {
    pub bytes: Vec<u8>,
}

/// Phase 2a Task 1a prover. Takes the trivial witness (just the
/// context_hash public input) and returns a Longfellow proof.
pub fn prove(witness: &Task1aWitness) -> Result<Proof, CircuitError> {
    match longfellow_sys::p7s::prove(&witness.context_hash) {
        Ok(p) => Ok(Proof { bytes: p.0 }),
        Err(code) => Err(CircuitError::ProverFailed(code)),
    }
}
