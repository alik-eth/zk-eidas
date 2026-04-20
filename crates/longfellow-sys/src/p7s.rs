//! P7s circuit FFI.
//!
//! Phase 2a Task 1b: invariant 9 — `context_hash == SHA-256(context_bytes)`.
//! v1 bound: `context_bytes.len() <= 32` (CONTEXT_MAX_BYTES = 32).

use std::os::raw::c_ulong;

use crate::{p7s_free_proof, p7s_prove, p7s_verify, P7sErrorCode_P7S_SUCCESS};

/// v1 upper bound on context length (bytes). Enforced by the C++ circuit
/// (`kContextMaxBytes` in `p7s_hash.h`).
pub const CONTEXT_MAX_BYTES: usize = 32;

/// Proof bytes owned by Rust (the C buffer is freed via `p7s_free_proof`
/// before returning).
#[derive(Debug, Clone)]
pub struct P7sProof(pub Vec<u8>);

/// Errors returned by the Task-1b prove/verify wrappers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum P7sFfiError {
    #[error("context length {got} exceeds CONTEXT_MAX_BYTES = {max}")]
    ContextTooLong { got: usize, max: usize },
    #[error("FFI prove returned error code {0}")]
    ProveFailed(u32),
    #[error("FFI verify returned error code {0}")]
    VerifyFailed(u32),
    #[error("FFI returned null/empty proof")]
    MalformedProof,
}

/// Prove `SHA-256(context_bytes) == context_hash`.
pub fn prove(context_hash: &[u8; 32], context_bytes: &[u8]) -> Result<P7sProof, P7sFfiError> {
    if context_bytes.len() > CONTEXT_MAX_BYTES {
        return Err(P7sFfiError::ContextTooLong {
            got: context_bytes.len(),
            max: CONTEXT_MAX_BYTES,
        });
    }
    let mut proof_out: *mut u8 = std::ptr::null_mut();
    let mut proof_len: c_ulong = 0;
    let code = unsafe {
        p7s_prove(
            context_hash.as_ptr(),
            &mut proof_out as *mut *mut u8,
            &mut proof_len as *mut c_ulong,
            context_bytes.as_ptr(),
            context_bytes.len() as c_ulong,
        )
    };
    if code != P7sErrorCode_P7S_SUCCESS {
        return Err(P7sFfiError::ProveFailed(code));
    }
    if proof_out.is_null() || proof_len == 0 {
        return Err(P7sFfiError::MalformedProof);
    }
    let bytes = unsafe { std::slice::from_raw_parts(proof_out, proof_len as usize).to_vec() };
    unsafe { p7s_free_proof(proof_out) };
    Ok(P7sProof(bytes))
}

/// Verify a proof against `context_hash`. Returns `Ok(())` on accept.
pub fn verify(context_hash: &[u8; 32], proof: &[u8]) -> Result<(), P7sFfiError> {
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
        Err(P7sFfiError::VerifyFailed(code))
    }
}

/// Smoke hook: prove + verify a round-trip on an empty context. The real
/// regression tests live in `zk-eidas-p7s-circuit/tests/invariant_9.rs`.
pub fn smoke() -> bool {
    let ctx: &[u8] = b"";
    let ch: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(ctx).into()
    };
    match prove(&ch, ctx) {
        Ok(p) => verify(&ch, &p.0).is_ok(),
        Err(_) => false,
    }
}
