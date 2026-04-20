//! Proof verification (scaffolding — populated in Step 1 / Task 1).

use crate::{CircuitError, Proof};

#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub context_hash: [u8; 32],
    pub pk: [u8; 65],
    pub nonce: [u8; 32],
    pub root_pk: [u8; 65],
    pub timestamp: u64,
    // declaration_hash, messageDigest checks are witness-internal.
}

pub fn verify(_proof: &Proof, _public: &PublicInputs) -> Result<bool, CircuitError> {
    // Scaffolding: no circuit constraints yet.
    Err(CircuitError::NotLinked)
}
