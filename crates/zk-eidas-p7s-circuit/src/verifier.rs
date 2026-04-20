//! Proof verification + public-input blob builder.
//!
//! Public blob v2 layout (see schema history in `witness.rs`):
//!   u32 version = 2
//!   u8  context_hash[32]
//!   u8  pk[65]

use crate::{witness::PK_BYTES, witness::SCHEMA_VERSION, CircuitError, Proof};

/// Public inputs the circuit binds against. Task 20 adds `pk`; the
/// other fields here are placeholders populated as subsequent invariants
/// land (nonce, root_pk, timestamp).
#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub context_hash: [u8; 32],
    pub pk: [u8; PK_BYTES],
    pub nonce: [u8; 32],
    pub root_pk: [u8; PK_BYTES],
    pub timestamp: u64,
}

impl PublicInputs {
    /// Serialize the public-inputs blob (v2 layout).
    pub fn to_ffi_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32 + PK_BYTES);
        out.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
        out.extend_from_slice(&self.context_hash);
        out.extend_from_slice(&self.pk);
        out
    }
}

/// Verify a proof against the public inputs. Returns `Ok(true)` if the
/// proof verifies; `Ok(false)` on a clean rejection (e.g. wrong public
/// input); `Err(...)` on a malformed proof or transport failure.
pub fn verify(proof: &Proof, public: &PublicInputs) -> Result<bool, CircuitError> {
    use longfellow_sys::p7s::P7sFfiError;
    let pub_blob = public.to_ffi_bytes();
    match longfellow_sys::p7s::verify(&pub_blob, &proof.bytes) {
        Ok(()) => Ok(true),
        Err(P7sFfiError::VerifyFailed(_)) => Ok(false),
        Err(e) => Err(CircuitError::from(e)),
    }
}
