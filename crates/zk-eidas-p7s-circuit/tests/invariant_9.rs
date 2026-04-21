//! Phase 2a Task 1b — invariant 9: `context_hash == SHA-256(context_bytes)`.
//!
//! Happy-path: honest witness + the DIIA fixture's context bytes.
//! Negative 1 (wrong claimed hash): prover refuses to produce a bogus proof.
//! Negative 2 (tampered context): prover refuses when the preimage
//!   doesn't match the declared hash.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, CircuitError, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

fn fixture_pk_and_nonce() -> ([u8; 65], [u8; 32]) {
    let w = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let off = &w.offsets;
    let mut pk = [0u8; 65];
    hex::decode_to_slice(
        &w.p7s_bytes[off.json_pk_start..off.json_pk_start + off.json_pk_len],
        &mut pk,
    )
    .unwrap();
    let mut nonce = [0u8; 32];
    hex::decode_to_slice(
        &w.p7s_bytes[off.json_nonce_start..off.json_nonce_start + off.json_nonce_len],
        &mut nonce,
    )
    .unwrap();
    (pk, nonce)
}

fn honest_public(context: &[u8]) -> PublicInputs {
    let (pk, nonce) = fixture_pk_and_nonce();
    let w = build_witness(FIXTURE, context, DUMMY_ROOT_PK).unwrap();
    let outputs = zk_eidas_p7s::compute_outputs(&w).unwrap();
    PublicInputs {
        context_hash: Sha256::digest(context).into(),
        pk,
        nonce,
        nullifier: outputs.nullifier,
        trust_anchor_index: 0,
        root_pk: [0u8; 65],
        timestamp: 0,
    }
}

#[test]
fn happy_path_context_round_trips() {
    let ctx: &[u8] = b"0x";
    let inner = build_witness(FIXTURE, ctx, DUMMY_ROOT_PK).expect("parse fixture");
    let w = Witness::new(inner);
    let public = honest_public(ctx);

    let proof = prove(&w, &public).expect("prove must succeed on honest witness");
    assert!(!proof.bytes.is_empty(), "proof must have non-zero length");

    let ok = verify(&proof, &public).expect("verify must yield a decision");
    assert!(ok, "verifier must accept an honest proof");
}

/// Negative 1: the prover refuses a witness whose declared `context_hash`
/// does not match `SHA-256(context_bytes)`.
#[test]
fn wrong_claimed_hash_prover_refuses() {
    let ctx: &[u8] = b"0x";
    let inner = build_witness(FIXTURE, ctx, DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut public = honest_public(ctx);
    public.context_hash = [0u8; 32]; // plausible-but-wrong

    let err = prove(&w, &public).expect_err("prove must refuse mismatched hash");
    assert!(
        matches!(err, CircuitError::ProverFailed(_)),
        "expected ProverFailed, got {err:?}"
    );
}

/// Negative 2: the prover refuses when the witness context differs from
/// the declared public `context_hash`. Same class of failure framed from
/// the preimage side.
#[test]
fn tampered_context_prover_refuses() {
    let ctx: &[u8] = b"0x";
    let public = honest_public(ctx);

    // Build the witness with a DIFFERENT context — its computed SHA-256
    // won't match `public.context_hash`.
    let mut tampered_ctx = ctx.to_vec();
    tampered_ctx[0] ^= 0x01;
    let inner = build_witness(FIXTURE, &tampered_ctx, DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);

    let err = prove(&w, &public).expect_err("prove must refuse tampered context");
    assert!(
        matches!(err, CircuitError::ProverFailed(_)),
        "expected ProverFailed, got {err:?}"
    );
}
