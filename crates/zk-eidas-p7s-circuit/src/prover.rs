//! Proof generation for the p7s circuit.
//!
//! The prover takes a `Witness` (which serializes to the v2 blob) and a
//! `PublicInputs` value; it produces a Longfellow proof that the
//! current invariants (9 and 4) hold.

use crate::{verifier::PublicInputs, witness::Witness, CircuitError};

#[derive(Debug, Clone)]
pub struct Proof {
    pub bytes: Vec<u8>,
}

/// Produce a proof binding `witness` to `public`.
pub fn prove(witness: &Witness, public: &PublicInputs) -> Result<Proof, CircuitError> {
    let wit_blob = witness.to_ffi_bytes()?;
    let pub_blob = public.to_ffi_bytes();
    match longfellow_sys::p7s::prove(&wit_blob, &pub_blob) {
        Ok(p) => Ok(Proof { bytes: p.0 }),
        Err(e) => Err(CircuitError::from(e)),
    }
}
