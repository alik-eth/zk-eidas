//! Proof verification — Task 1a hello-world.

use crate::{CircuitError, Proof};

/// Eventual public-input struct. Only `context_hash` is bound in Task 1a;
/// the remaining fields are placeholders that surface as subsequent
/// invariants land.
#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub context_hash: [u8; 32],
    pub pk: [u8; 65],
    pub nonce: [u8; 32],
    pub root_pk: [u8; 65],
    pub timestamp: u64,
}

/// Phase 2a Task 1a verifier. Returns `Ok(true)` iff the proof verifies
/// against `public.context_hash`.
pub fn verify(proof: &Proof, public: &PublicInputs) -> Result<bool, CircuitError> {
    match longfellow_sys::p7s::verify(&public.context_hash, &proof.bytes) {
        Ok(()) => Ok(true),
        Err(code) => Err(CircuitError::VerifierFailed(code)),
    }
}
