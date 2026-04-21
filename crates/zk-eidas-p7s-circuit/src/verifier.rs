//! Proof verification + public-input blob builder.
//!
//! Public blob v11 layout (see schema history in `witness.rs`). Task
//! 34 (invariant 7) adds the first NEW public input since v3 — the
//! `nullifier[32]` output — and a placeholder `trust_anchor_index`
//! u32 that Task #36 will wire to real trust-anchor selection.
//!   u32 version = 11
//!   u8  context_hash[32]
//!   u8  pk[65]
//!   u8  nonce[32]
//!   u8  nullifier[32]        ← v11 (Task 34)
//!   u32 trust_anchor_index   ← v11 (Task 34) placeholder
//!
//! Notes:
//!   * The DIIA QTSP 2311 root pubkey used by invariant 1 is a
//!     compile-time constant in the C++ circuit — NOT part of the
//!     public blob. `PublicInputs.root_pk` is retained for type-system
//!     continuity but `to_ffi_bytes()` ignores it.
//!   * The user holder public key used by invariant 2a IS part of the
//!     public blob — it's `pk[65]`, the same bytes invariant 4
//!     constrains on the hash side. The C++ verifier host parses
//!     `pk[1..33]`/`pk[33..65]` (big-endian SEC1) into Fp256Base X/Y
//!     and feeds them as sig-circuit public-input EltWs. Callers must
//!     supply pk in SEC1 uncompressed form (leading 0x04 byte); both
//!     the host and the hash circuit reject non-uncompressed points.
//!   * `nullifier` equals `SHA-256(stable_id || context)` where
//!     `stable_id` is the 16-byte PrintableString value of the X.520
//!     serialNumber attribute in cert_tbs's Subject DN (DIIA RNOKPP
//!     format: `TINUA-` + 10 digits). Same formula Phase 1 computes
//!     host-side at `crates/zk-eidas-p7s/src/outputs.rs`.
//!   * `trust_anchor_index` is a v11 placeholder: the current circuit
//!     reads it from the public blob but does NOT use it. Task #36
//!     activates real trust-anchor selection.

use crate::{
    witness::{NONCE_BYTES, NULLIFIER_LEN, PK_BYTES, SCHEMA_VERSION},
    CircuitError, Proof,
};

/// Public inputs the circuit binds against. Task 20 added `pk`; Task 21
/// binds `nonce`; Task 34 adds `nullifier` (public output of invariant
/// 7) + `trust_anchor_index` (v11 placeholder, activated by #36).
/// `root_pk`/`timestamp` remain legacy placeholders retained for
/// type-system continuity — `to_ffi_bytes()` ignores them.
#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub context_hash: [u8; 32],
    pub pk: [u8; PK_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    /// SHA-256(stable_id || context) — public output of invariant 7.
    /// Callers supply the expected value; the circuit enforces
    /// equality with the SHA output it computes in-circuit. Use
    /// `compute_outputs()` from `zk_eidas_p7s` crate to derive.
    pub nullifier: [u8; NULLIFIER_LEN],
    /// v11 placeholder — Task #36 wires real trust-anchor table
    /// selection against this index. In #34 the circuit reads it but
    /// does not constrain anything on it; pass `0`.
    pub trust_anchor_index: u32,
    pub root_pk: [u8; PK_BYTES],
    pub timestamp: u64,
}

impl PublicInputs {
    /// Serialize the public-inputs blob (current v11 layout).
    pub fn to_ffi_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(4 + 32 + PK_BYTES + NONCE_BYTES + NULLIFIER_LEN + 4);
        out.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
        out.extend_from_slice(&self.context_hash);
        out.extend_from_slice(&self.pk);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.trust_anchor_index.to_le_bytes());
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
