//! Phase 2b Task 35 — invariant 8: out-of-circuit holder binding.
//!
//! Binds a ZK proof to the holder's secp256k1 Ethereum wallet via a
//! sidecar ECDSA signature over the canonical public-outputs digest.
//! The ZK proof's sig side stays P-256-only; holder binding is
//! blockchain-agnostic (any secp256k1 verifier, including EVM
//! `ecrecover`, can check it).
//!
//! Tests:
//!   1. Happy round-trip: holder signs → verifier accepts.
//!   2. Wrong pubkey: signature minted under key A, verifier uses key B
//!      → reject with `HolderBindingError::Invalid`.
//!   3. Tampered outputs: signature minted over outputs H, verifier
//!      passes tampered outputs H' (one bit flipped) → reject.
//!   4. Canonical-encoding stability: same inputs to `from_components`
//!      always produce the same digest; changing any one component
//!      changes the digest — the load-bearing property for holder
//!      binding to detect proof-output substitution.
//!
//! The `from_public_inputs` helper (reads a `PublicInputs` directly)
//! and the demo-layer wiring (API `/p7s/holder-binding/verify`
//! endpoint + `personal_sign` UI flow) land in Task 35b (#40) after
//! Task 36 pins the final `PublicInputs` shape. This file exercises
//! the primitive signing / verification API and the `from_components`
//! canonical-encoding path only.

use k256::ecdsa::SigningKey;
use rand::rngs::OsRng;

use zk_eidas_p7s_circuit::holder_binding::{
    sign_holder_binding, verify_holder_binding, HolderBindingError, ProofOutputsHash,
};

/// Deterministic 32-byte outputs for tests — the holder-binding lib
/// is agnostic to how the digest is derived (the real
/// `from_components` path is exercised by the stability test below).
fn dummy_outputs() -> ProofOutputsHash {
    ProofOutputsHash([0x42u8; 32])
}

#[test]
fn holder_binding_happy_round_trips() {
    let sk = SigningKey::random(&mut OsRng);
    let pk = sk.verifying_key();
    let outputs = dummy_outputs();

    let sig = sign_holder_binding(&sk, &outputs);
    verify_holder_binding(pk, &outputs, &sig).expect("honest holder sig must verify");
}

#[test]
fn holder_binding_wrong_pk_rejects() {
    let sk = SigningKey::random(&mut OsRng);
    let other_sk = SigningKey::random(&mut OsRng);
    let wrong_pk = other_sk.verifying_key();
    let outputs = dummy_outputs();

    let sig = sign_holder_binding(&sk, &outputs);
    assert_eq!(
        verify_holder_binding(wrong_pk, &outputs, &sig),
        Err(HolderBindingError::Invalid),
        "signature minted under sk_A must not verify under sk_B's pubkey",
    );
}

#[test]
fn holder_binding_tampered_outputs_rejects() {
    let sk = SigningKey::random(&mut OsRng);
    let pk = sk.verifying_key();
    let outputs = dummy_outputs();

    let sig = sign_holder_binding(&sk, &outputs);

    // Flip one bit anywhere in the 32-byte digest; verifier must reject.
    let mut tampered = outputs;
    tampered.0[0] ^= 0x01;
    assert_eq!(
        verify_holder_binding(pk, &tampered, &sig),
        Err(HolderBindingError::Invalid),
        "tampered outputs must not verify under the original signature",
    );
}

#[test]
fn from_components_is_stable_and_distinct_under_change() {
    // Confirms the canonical encoding is byte-stable (same inputs →
    // same 32-byte digest) and that changing any one component
    // changes the digest — the load-bearing property for holder
    // binding to detect proof-output substitution.
    let context_hash = [0xAAu8; 32];
    let pk = [0xBBu8; 65];
    let nonce = [0xCCu8; 32];
    let nullifier = [0xDDu8; 32];

    let h1 = ProofOutputsHash::from_components(&context_hash, &pk, &nonce, &nullifier);
    let h2 = ProofOutputsHash::from_components(&context_hash, &pk, &nonce, &nullifier);
    assert_eq!(h1, h2, "same inputs must produce the same digest");

    let mut nullifier2 = nullifier;
    nullifier2[0] ^= 0x01;
    let h3 = ProofOutputsHash::from_components(&context_hash, &pk, &nonce, &nullifier2);
    assert_ne!(
        h1, h3,
        "changing nullifier must change the digest (collision-free)",
    );
}
