//! P7s circuit FFI.
//!
//! Phase 2a Task 1a: trivially-satisfiable hello-world circuit over a
//! single 32-byte public input (`context_hash`). The real SHA-256
//! constraint lands in Task 1b.

use std::os::raw::c_ulong;

use crate::{p7s_free_proof, p7s_prove, p7s_verify, P7sErrorCode_P7S_SUCCESS};

/// Proof bytes owned by Rust (the C buffer is freed via `p7s_free_proof`
/// before returning).
#[derive(Debug, Clone)]
pub struct P7sProof(pub Vec<u8>);

/// Run the Task-1a prover for the given 32-byte public input.
pub fn prove(context_hash: &[u8; 32]) -> Result<P7sProof, u32> {
    let mut proof_out: *mut u8 = std::ptr::null_mut();
    let mut proof_len: c_ulong = 0;
    let code = unsafe {
        p7s_prove(
            context_hash.as_ptr(),
            &mut proof_out as *mut *mut u8,
            &mut proof_len as *mut c_ulong,
        )
    };
    if code != P7sErrorCode_P7S_SUCCESS {
        return Err(code);
    }
    if proof_out.is_null() || proof_len == 0 {
        return Err(u32::MAX);
    }
    let bytes = unsafe { std::slice::from_raw_parts(proof_out, proof_len as usize).to_vec() };
    unsafe { p7s_free_proof(proof_out) };
    Ok(P7sProof(bytes))
}

/// Run the Task-1a verifier. Returns `Ok(())` iff the proof is valid.
pub fn verify(context_hash: &[u8; 32], proof: &[u8]) -> Result<(), u32> {
    let code = unsafe {
        p7s_verify(
            context_hash.as_ptr(),
            proof.as_ptr(),
            proof.len() as c_ulong,
        )
    };
    if code == P7sErrorCode_P7S_SUCCESS {
        Ok(())
    } else {
        Err(code)
    }
}

/// Smoke hook preserved from Task 0 for continuity: returns true iff the
/// FFI links and a round-trip on an all-zero context succeeds.
pub fn smoke() -> bool {
    let ch = [0u8; 32];
    match prove(&ch) {
        Ok(p) => verify(&ch, &p.0).is_ok(),
        Err(_) => false,
    }
}
