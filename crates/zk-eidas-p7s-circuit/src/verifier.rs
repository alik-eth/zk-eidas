//! Proof verification — Task 1b (invariant 9: context_hash SHA-256).

use crate::{CircuitError, Proof};

/// Eventual public-input struct. Only `context_hash` is bound by the
/// Task-1b circuit; the remaining fields are placeholders that surface
/// as subsequent invariants land.
#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub context_hash: [u8; 32],
    pub pk: [u8; 65],
    pub nonce: [u8; 32],
    pub root_pk: [u8; 65],
    pub timestamp: u64,
}

/// Phase 2a Task 1b verifier. Returns `Ok(true)` iff the proof verifies
/// against `public.context_hash`. A proof for the wrong public input
/// surfaces as `Ok(false)`; malformed proofs yield `Err(...)`.
pub fn verify(proof: &Proof, public: &PublicInputs) -> Result<bool, CircuitError> {
    use longfellow_sys::p7s::P7sFfiError;
    match longfellow_sys::p7s::verify(&public.context_hash, &proof.bytes) {
        Ok(()) => Ok(true),
        // A clean "proof does not verify for these inputs" is Ok(false),
        // letting callers distinguish wrong-public-input from broken-proof.
        Err(P7sFfiError::VerifyFailed(_)) => Ok(false),
        Err(e) => Err(CircuitError::from(e)),
    }
}
