//! Proof generation (scaffolding — populated in Step 1 / Task 1).

use crate::{CircuitError, Witness};

#[derive(Debug, Clone)]
pub struct Proof {
    pub bytes: Vec<u8>,
}

pub fn prove(_witness: &Witness) -> Result<Proof, CircuitError> {
    // Scaffolding: no circuit constraints yet.
    Err(CircuitError::NotLinked)
}
