//! Proof generation for the p7s circuit.
//!
//! The prover takes a `Witness` (which serializes to the current v8
//! witness blob) and a `PublicInputs` value; it produces a dual-circuit
//! Longfellow proof (hash side over GF(2^128) + sig side over Fp256Base,
//! linked by a cross-field MAC gadget) that the Phase-2a invariants hold
//! on the witness:
//!
//!   * invariant 1  — signer cert's ECDSA verifies under the TestAnchorA synthetic root
//!   * invariant 4  — signed_content[pk_offset..] matches public.pk
//!   * invariant 5  — signed_content[nonce_offset..] matches public.nonce
//!   * invariant 6  — signed_content[ctx_offset..] matches context_bytes
//!   * invariant 9  — context_hash == SHA-256(context_bytes)
//!   * invariant 10 — signed_content[decl_offset..] == kDeclarationPhrase
//!   * invariant 2b — message_digest == SHA-256(signed_content)
//!
//! See `witness.rs` for the authoritative blob-schema history.

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
