//! P7s circuit FFI — blob protocol (schema v7).
//!
//! Task 20 switched from typed C args to byte-blobs so additional witness
//! fields can land without per-task ABI churn. Task 25a splits the single
//! GF(2^128) circuit into a dual-circuit hash + sig setup linked via a
//! MAC gadget, but the blob schema itself stays identical to v6 — the
//! dual-proof structure is opaque to Rust (it's just more bytes inside
//! the `P7sProof` vector). The authoritative schema lives in
//! `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc` under the "schema
//! history" comment block; the Rust wrappers here only transport opaque
//! blobs and proof bytes.

use std::os::raw::c_ulong;

use crate::{p7s_free_proof, p7s_prove, p7s_verify, P7sErrorCode_P7S_SUCCESS};

/// Proof bytes owned by Rust (the C buffer is freed via `p7s_free_proof`
/// before returning).
#[derive(Debug, Clone)]
pub struct P7sProof(pub Vec<u8>);

/// Errors returned by the blob-protocol prove/verify wrappers. The
/// C++ side raises `P7S_INVALID_INPUT` for any schema-parse failure;
/// the specific cause (wrong version, bad offset, truncated blob) is
/// surfaced via the error code to help caller debugging.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum P7sFfiError {
    #[error("FFI prove returned error code {0}")]
    ProveFailed(u32),
    #[error("FFI verify returned error code {0}")]
    VerifyFailed(u32),
    #[error("FFI returned null/empty proof")]
    MalformedProof,
}

/// Prove the p7s circuit: produces an opaque proof bound to `public_blob`
/// using the private data in `witness_blob`. Callers serialize both
/// blobs per the v2 layout — `zk-eidas-p7s-circuit` provides the helpers.
pub fn prove(witness_blob: &[u8], public_blob: &[u8]) -> Result<P7sProof, P7sFfiError> {
    let mut proof_out: *mut u8 = std::ptr::null_mut();
    let mut proof_len: c_ulong = 0;
    let code = unsafe {
        p7s_prove(
            witness_blob.as_ptr(),
            witness_blob.len() as c_ulong,
            public_blob.as_ptr(),
            public_blob.len() as c_ulong,
            &mut proof_out as *mut *mut u8,
            &mut proof_len as *mut c_ulong,
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

/// Verify a proof against `public_blob`. Returns `Ok(())` on accept.
pub fn verify(public_blob: &[u8], proof: &[u8]) -> Result<(), P7sFfiError> {
    let code = unsafe {
        p7s_verify(
            public_blob.as_ptr(),
            public_blob.len() as c_ulong,
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
