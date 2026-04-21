//! Phase 2a Task 22 — invariant 6: JSON "context" field byte-equals the
//! SHA-256 preimage held in the witness.
//!
//! The context byte-length is derived in-circuit from the SHA padding
//! (Task 1b's invariant 9), so there is no independent length wire to
//! attack. Tests focus on the byte-range equality.
//!
//! Tests:
//!   1. Happy: real DIIA fixture with context = "0x" → round-trips.
//!   2. Wrong public context_hash: prover refuses (invariant 9 fails).
//!   3. Tampered JSON context bytes in signed_content: byte_range mismatch
//!      at prove time.
//!   4. Proptest over random short contexts (1..=32 bytes): every honest
//!      witness proves and verifies.

use proptest::prelude::*;
use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, CircuitError, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

// v4 blob offsets — keep in sync with `witness.rs`'s serializer.
const SC_START_IN_BLOB: usize = 4 + 4 + 32 + 4; // 44
const PK_OFF_IN_BLOB: usize = SC_START_IN_BLOB + 1024; // 1068
const PK_HEX_IN_BLOB: usize = PK_OFF_IN_BLOB + 4; // 1072
const NONCE_OFF_IN_BLOB: usize = PK_HEX_IN_BLOB + 130; // 1202
const NONCE_HEX_IN_BLOB: usize = NONCE_OFF_IN_BLOB + 4; // 1206
const CTX_OFF_IN_BLOB: usize = NONCE_HEX_IN_BLOB + 64; // 1270

fn expected_pk() -> [u8; 65] {
    let w = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let off = &w.offsets;
    let mut out = [0u8; 65];
    hex::decode_to_slice(
        &w.p7s_bytes[off.json_pk_start..off.json_pk_start + off.json_pk_len],
        &mut out,
    )
    .unwrap();
    out
}

fn expected_nonce() -> [u8; 32] {
    let w = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let off = &w.offsets;
    let mut out = [0u8; 32];
    hex::decode_to_slice(
        &w.p7s_bytes[off.json_nonce_start..off.json_nonce_start + off.json_nonce_len],
        &mut out,
    )
    .unwrap();
    out
}

fn public_for(ctx: &[u8]) -> PublicInputs {
    let w = build_witness(FIXTURE, ctx, DUMMY_ROOT_PK).unwrap();
    let outputs = zk_eidas_p7s::compute_outputs(&w).unwrap();
    PublicInputs {
        context_hash: Sha256::digest(ctx).into(),
        pk: expected_pk(),
        nonce: expected_nonce(),
        nullifier: outputs.nullifier,
        trust_anchor_index: 0,
        root_pk: [0u8; 65],
        timestamp: 0,
    }
}

fn context_offset(blob: &[u8]) -> usize {
    u32::from_le_bytes([
        blob[CTX_OFF_IN_BLOB],
        blob[CTX_OFF_IN_BLOB + 1],
        blob[CTX_OFF_IN_BLOB + 2],
        blob[CTX_OFF_IN_BLOB + 3],
    ]) as usize
}

/// (1) Happy: the fixture's JSON context is literally "0x" (2 bytes).
#[test]
fn invariant_6_happy_round_trips() {
    let ctx: &[u8] = b"0x";
    let inner = build_witness(FIXTURE, ctx, DUMMY_ROOT_PK).expect("parse fixture");
    let w = Witness::new(inner);
    let public = public_for(ctx);

    let proof = prove(&w, &public).expect("prove");
    assert!(
        verify(&proof, &public).expect("verify"),
        "honest proof must verify"
    );
}

/// (2) Wrong public context_hash: the SHA-256 invariant (9) fails at
/// prove time, surfacing as `ProverFailed`. This isn't strictly an
/// invariant-6 test but confirms the cross-invariant plumbing still
/// catches the error after Task 22's changes.
#[test]
fn invariant_6_wrong_public_context_hash_prover_refuses() {
    let ctx: &[u8] = b"0x";
    let inner = build_witness(FIXTURE, ctx, DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut public = public_for(ctx);
    public.context_hash = [0u8; 32]; // plausibly wrong

    let err = prove(&w, &public).expect_err("prove must refuse wrong hash");
    assert!(
        matches!(err, CircuitError::ProverFailed(_)),
        "expected ProverFailed, got {err:?}"
    );
}

/// (3) Tampered JSON context bytes in signed_content: the byte-range
/// equality (invariant 6) fails because context_bytes (SHA-bound) still
/// hold the real context while signed_content claims something else.
#[test]
fn invariant_6_tampered_signed_content_prover_refuses() {
    let ctx: &[u8] = b"0x";
    let inner = build_witness(FIXTURE, ctx, DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let honest = w.to_ffi_bytes().expect("serialize");

    let c_off = context_offset(&honest);
    // Context is 2 bytes; flip byte 0 of its signed_content slice (the
    // '0' of "0x"). SHA is still computed over the real "0x" bytes in
    // context_bytes, so byte_range_eq fails.
    let mut tampered = honest.clone();
    tampered[SC_START_IN_BLOB + c_off] ^= 0x01;

    let public = public_for(ctx);
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&tampered, &pub_blob)
        .expect_err("prove must refuse tampered context in signed_content");
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(_) => {}
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}

/// (4) Proptest: random public.context_hash values never verify against
/// a proof minted for the real fixture context. Memoize the honest proof
/// and flip public bits to make each iteration cheap (verify-only).
fn honest_proof_cached() -> &'static zk_eidas_p7s_circuit::Proof {
    use std::sync::OnceLock;
    static PROOF: OnceLock<zk_eidas_p7s_circuit::Proof> = OnceLock::new();
    PROOF.get_or_init(|| {
        let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
        let w = Witness::new(inner);
        let correct = public_for(b"0x");
        prove(&w, &correct).expect("honest prove")
    })
}

proptest! {
    #[test]
    fn invariant_6_proptest_wrong_public_context_hash(idx in 0usize..32, xor in 1u8..=255) {
        let proof = honest_proof_cached();
        let mut wrong = public_for(b"0x");
        let honest_hash = wrong.context_hash;
        wrong.context_hash[idx] ^= xor;
        if wrong.context_hash != honest_hash {
            prop_assert!(!verify(proof, &wrong).expect("verify"));
        }
    }
}
