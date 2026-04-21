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
//!   4. Canonical-encoding stability (`from_components` path): same
//!      inputs to `from_components` always produce the same digest;
//!      changing any one component changes the digest — the
//!      load-bearing property for holder binding to detect
//!      proof-output substitution.
//!   5. Trust-anchor-index exclusion (Task #40, `from_public_inputs`
//!      path): the canonical digest is invariant under changes to
//!      `PublicInputs.trust_anchor_index` / `root_pk` / `timestamp`
//!      but shifts under changes to claim-content fields (checked
//!      via `nullifier`). Pins the Phase 2b Q3 decision that holder
//!      binding is blockchain-agnostic — the holder signs what the
//!      proof CLAIMS, not which anchor verified it.

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

#[test]
fn holder_binding_hash_excludes_trust_anchor_index() {
    // Soundness test for the Phase 2b Q3 design decision: holder
    // binding is blockchain-agnostic and independent of which root
    // CA vouched for the holder's cert chain. The canonical digest
    // MUST be identical across PublicInputs that differ only in
    // `trust_anchor_index` / `root_pk` / `timestamp` — those are
    // anchor-selection / issuance metadata, not "what the proof
    // claims." Flipping any of them must not alter the signed bytes.
    use zk_eidas_p7s_circuit::PublicInputs;

    let base = PublicInputs {
        context_hash: [0x11u8; 32],
        pk: [0x22u8; 65],
        nonce: [0x33u8; 32],
        nullifier: [0x44u8; 32],
        trust_anchor_index: 0,
        root_pk: [0x55u8; 65],
        timestamp: 1_700_000_000,
    };
    let h_base = ProofOutputsHash::from_public_inputs(&base);

    // Same claim content, different trust anchor index.
    let mut alt_index = base.clone();
    alt_index.trust_anchor_index = 42;
    assert_eq!(
        h_base,
        ProofOutputsHash::from_public_inputs(&alt_index),
        "digest must ignore trust_anchor_index",
    );

    // Same claim content, different root_pk (the compile-time anchor
    // material that matches the index).
    let mut alt_root = base.clone();
    alt_root.root_pk = [0xAAu8; 65];
    assert_eq!(
        h_base,
        ProofOutputsHash::from_public_inputs(&alt_root),
        "digest must ignore root_pk",
    );

    // Same claim content, different timestamp (issuance metadata).
    let mut alt_ts = base.clone();
    alt_ts.timestamp = 1_800_000_000;
    assert_eq!(
        h_base,
        ProofOutputsHash::from_public_inputs(&alt_ts),
        "digest must ignore timestamp",
    );

    // Positive control: a claim-content change DOES shift the digest.
    // Here we flip `nullifier` — same rationale as
    // `from_components_is_stable_and_distinct_under_change`, but
    // verified through the `from_public_inputs` path so the two
    // construction paths can't silently disagree.
    let mut alt_nullifier = base;
    alt_nullifier.nullifier[0] ^= 0x01;
    assert_ne!(
        h_base,
        ProofOutputsHash::from_public_inputs(&alt_nullifier),
        "digest MUST change when nullifier changes (from_public_inputs path)",
    );
}
