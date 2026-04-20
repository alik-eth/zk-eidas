//! Phase 2a Task 1b — invariant 9: `context_hash == SHA-256(context_bytes)`.
//!
//! Happy-path: honest witness + the real DIIA fixture's context bytes.
//! Negative 1 (wrong claimed hash): prover refuses to produce a bogus proof.
//! Negative 2 (tampered context): prover refuses when the preimage
//!   doesn't match the declared hash.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, CircuitError, PublicInputs, Task1bWitness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

fn diia_context_bytes() -> Vec<u8> {
    let context = b"0x";
    let w = build_witness(FIXTURE, context, DUMMY_ROOT_PK).expect("parse fixture");
    let off = &w.offsets;
    let ctx =
        &w.p7s_bytes[off.json_context_start..off.json_context_start + off.json_context_len];
    assert_eq!(ctx, context, "parser should surface the same context");
    ctx.to_vec()
}

fn public_for(context_hash: [u8; 32]) -> PublicInputs {
    PublicInputs {
        context_hash,
        pk: [0u8; 65],
        nonce: [0u8; 32],
        root_pk: [0u8; 65],
        timestamp: 0,
    }
}

#[test]
fn happy_path_diia_context_round_trips() {
    let ctx = diia_context_bytes();
    let witness = Task1bWitness::honest(ctx.clone());
    let proof = prove(&witness).expect("prove must succeed on honest witness");
    assert!(!proof.bytes.is_empty(), "proof must have non-zero length");

    let public = public_for(witness.context_hash);
    let ok = verify(&proof, &public).expect("verify must yield a decision");
    assert!(ok, "verifier must accept an honest proof");

    // Sanity: the public output matches the off-circuit SHA-256.
    let expected: [u8; 32] = Sha256::digest(&ctx).into();
    assert_eq!(witness.context_hash, expected);
}

/// Negative 1: the prover refuses a witness whose declared `context_hash`
/// does not match `SHA-256(context_bytes)`.
#[test]
fn wrong_claimed_hash_prover_refuses() {
    let ctx = diia_context_bytes();
    // A plausible-but-wrong hash (all-zero is very unlikely to equal
    // SHA-256 of any input).
    let witness = Task1bWitness {
        context_hash: [0u8; 32],
        context_bytes: ctx,
    };
    let err = prove(&witness).expect_err("prove must refuse mismatched witness");
    assert!(
        matches!(err, CircuitError::ProverFailed(_)),
        "expected ProverFailed, got {err:?}"
    );
}

/// Negative 2: the prover refuses when the preimage bytes have been
/// tampered relative to the declared hash. Same class of failure as
/// Negative 1 but framed from the preimage side.
#[test]
fn tampered_context_prover_refuses() {
    let ctx = diia_context_bytes();
    let honest_hash: [u8; 32] = Sha256::digest(&ctx).into();
    let mut tampered = ctx.clone();
    tampered[0] ^= 0x01; // flip one bit of the preimage
    let witness = Task1bWitness {
        context_hash: honest_hash,
        context_bytes: tampered,
    };
    let err = prove(&witness).expect_err("prove must refuse tampered preimage");
    assert!(
        matches!(err, CircuitError::ProverFailed(_)),
        "expected ProverFailed, got {err:?}"
    );
}
