//! Proof verification + public-input blob builder.
//!
//! Public blob v6 layout (see schema history in `witness.rs`). The public
//! side is structurally identical to v3 — Tasks 22, 23, and 24 don't add
//! public inputs. The version byte still bumps so proofs minted under
//! distinct circuits aren't interchangeable.
//!   u32 version = 6
//!   u8  context_hash[32]
//!   u8  pk[65]
//!   u8  nonce[32]

use crate::{
    witness::{NONCE_BYTES, PK_BYTES, SCHEMA_VERSION},
    CircuitError, Proof,
};

/// Public inputs the circuit binds against. Task 20 added `pk`; Task 21
/// binds `nonce`. `root_pk`/`timestamp` remain placeholders populated by
/// subsequent invariants.
#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub context_hash: [u8; 32],
    pub pk: [u8; PK_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    pub root_pk: [u8; PK_BYTES],
    pub timestamp: u64,
}

impl PublicInputs {
    /// Serialize the public-inputs blob (v3 layout).
    pub fn to_ffi_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32 + PK_BYTES + NONCE_BYTES);
        out.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
        out.extend_from_slice(&self.context_hash);
        out.extend_from_slice(&self.pk);
        out.extend_from_slice(&self.nonce);
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
