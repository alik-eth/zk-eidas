//! Out-of-circuit holder binding (invariant 8).
//!
//! Binds a ZK proof to the holder's Ethereum wallet secp256k1 keypair by
//! signing a 32-byte canonical digest of the proof's public outputs. The
//! ZK proof stays P-256-only on the sig side — holder binding is a
//! blockchain-agnostic ECDSA/secp256k1 sidecar signature that any
//! secp256k1 verifier (EVM `ecrecover`, Bitcoin, etc.) can check without
//! touching the Longfellow verify path.
//!
//! Verification is a two-layer check:
//!   1. The ZK verifier accepts the proof against `PublicInputs`.
//!   2. The holder-binding verifier accepts the secp256k1 signature over
//!      `ProofOutputsHash` under the holder's wallet pubkey.
//! Both must pass for the combined claim "this holder produced this
//! proof" to hold.
//!
//! Canonical outputs hash (see Phase 2b design doc, Q3 = C):
//!   `ProofOutputsHash = SHA-256(context_hash || pk || nonce || nullifier)`
//! The trust-anchor index (witness-driven field finalized by Task 36)
//! is deliberately excluded from the hash — holder binding is about
//! what the proof CLAIMS (scope, holder key, freshness, nullifier
//! identity), not about which certificate root vouched for the
//! underlying cert chain.
//!
//! Task 35 ships the lib surface only: `ProofOutputsHash` + its
//! `from_components` constructor + `sign_holder_binding` /
//! `verify_holder_binding`. The `PublicInputs`-derived helper
//! (`ProofOutputsHash::from_public_inputs`) and the demo-layer
//! wiring (API `/p7s/holder-binding/verify` endpoint +
//! `personal_sign` UI flow) are deferred to Task 35b (#40), which
//! runs after Task 36 pins the final `PublicInputs` shape — that
//! way the helper lands once the trust-anchor-index landscape is
//! finalized, without churning the hash encoding between tasks.

use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};

/// Canonical 32-byte digest the holder signs over. Constructed by
/// callers from the proof's public outputs; the lib is agnostic to how
/// the bytes are derived (the `from_public_inputs` helper lands in
/// Task 35b / #40 once the `PublicInputs` shape is pinned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofOutputsHash(pub [u8; 32]);

impl ProofOutputsHash {
    /// Compute the canonical digest from the four field components.
    /// Encoding is tight concatenation with no length prefixes: the
    /// component widths are compile-time constants, and a verifier
    /// reconstructs the same digest byte-for-byte.
    pub fn from_components(
        context_hash: &[u8; 32],
        pk: &[u8; 65],
        nonce: &[u8; 32],
        nullifier: &[u8; 32],
    ) -> Self {
        let mut h = Sha256::new();
        h.update(context_hash);
        h.update(pk);
        h.update(nonce);
        h.update(nullifier);
        ProofOutputsHash(h.finalize().into())
    }
}

/// Holder signs the canonical outputs hash with their secp256k1
/// wallet private key. Returns a DER-less fixed-size (r, s) signature.
pub fn sign_holder_binding(sk: &SigningKey, outputs: &ProofOutputsHash) -> Signature {
    sk.sign(&outputs.0)
}

/// Error shape for verify failures. Kept as a dedicated enum (rather
/// than surfacing `k256::ecdsa::Error`) so downstream callers don't
/// need to depend on `k256` just to match on rejection reasons.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HolderBindingError {
    #[error("holder-binding signature verification failed")]
    Invalid,
}

/// Verifier-side check: confirms `sig` is a valid secp256k1 signature
/// over `outputs.0` under `pk`. Returns `Ok(())` on accept, `Err(...)`
/// on any rejection (wrong pubkey, tampered outputs, malformed sig).
pub fn verify_holder_binding(
    pk: &VerifyingKey,
    outputs: &ProofOutputsHash,
    sig: &Signature,
) -> Result<(), HolderBindingError> {
    pk.verify(&outputs.0, sig)
        .map_err(|_| HolderBindingError::Invalid)
}
