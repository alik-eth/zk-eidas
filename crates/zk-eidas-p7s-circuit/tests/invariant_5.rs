//! Phase 2a Task 21 — invariant 5: JSON "nonce" field hex-decodes to
//! `public.nonce`, and the hex chars are byte-equal to the slice of
//! `signed_content` at `json_nonce_offset`.
//!
//! Tests mirror `invariant_4.rs`:
//!   1. Happy: real DIIA fixture, expected nonce → round-trips.
//!   2. Wrong public nonce: verifier rejects.
//!   3. Tampered nonce bytes in signed_content: prover refuses (byte_range_eq).
//!   4. Invalid hex char at a nonce position: prover refuses (HexDecode lookup).
//!   5. Silent nonce_hex substitution: byte-packing vs public.nonce rejects.
//!   6. Proptest: random single-byte flips to public.nonce all reject.

use proptest::prelude::*;
use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

// v3 blob offsets — keep in sync with `witness.rs`'s serializer.
const SC_START_IN_BLOB: usize = 4 + 4 + 32 + 4; // 44
const PK_OFF_IN_BLOB: usize = SC_START_IN_BLOB + 1024; // 1068
const PK_HEX_IN_BLOB: usize = PK_OFF_IN_BLOB + 4; // 1072
const NONCE_OFF_IN_BLOB: usize = PK_HEX_IN_BLOB + 130; // 1202
const NONCE_HEX_IN_BLOB: usize = NONCE_OFF_IN_BLOB + 4; // 1206

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

fn public_for(nonce: [u8; 32], ctx: &[u8]) -> PublicInputs {
    let w = build_witness(FIXTURE, ctx, DUMMY_ROOT_PK).unwrap();
    let outputs = zk_eidas_p7s::compute_outputs(&w).unwrap();
    PublicInputs {
        context_hash: Sha256::digest(ctx).into(),
        pk: expected_pk(),
        nonce,
        nullifier: outputs.nullifier,
        trust_anchor_index: 0,
        root_pk: [0u8; 65],
        timestamp: 0,
    }
}

fn nonce_offset(blob: &[u8]) -> usize {
    u32::from_le_bytes([
        blob[NONCE_OFF_IN_BLOB],
        blob[NONCE_OFF_IN_BLOB + 1],
        blob[NONCE_OFF_IN_BLOB + 2],
        blob[NONCE_OFF_IN_BLOB + 3],
    ]) as usize
}

/// (1) Happy: honest witness + correct public.nonce → round-trips.
#[test]
fn invariant_5_happy_round_trips() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let public = public_for(expected_nonce(), b"0x");

    let proof = prove(&w, &public).expect("prove");
    assert!(
        verify(&proof, &public).expect("verify"),
        "honest proof must verify"
    );
}

/// (2) Wrong public nonce → verifier rejects.
#[test]
fn invariant_5_wrong_public_nonce_rejects() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let correct = public_for(expected_nonce(), b"0x");

    let proof = prove(&w, &correct).expect("prove");

    let mut wrong_nonce = expected_nonce();
    wrong_nonce[7] ^= 0x55;
    let wrong = public_for(wrong_nonce, b"0x");
    assert!(
        !verify(&proof, &wrong).expect("verify must decide"),
        "wrong nonce must not verify"
    );
}

/// (3) Tampered nonce bytes in signed_content: byte_range_eq fails.
#[test]
fn invariant_5_tampered_signed_content_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let honest = w.to_ffi_bytes().expect("serialize");

    let n_off = nonce_offset(&honest);
    let mut tampered = honest.clone();
    tampered[SC_START_IN_BLOB + n_off + 5] ^= 0x01;

    let public = public_for(expected_nonce(), b"0x");
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&tampered, &pub_blob)
        .expect_err("prove must refuse tampered signed_content");
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(_) => {}
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}

/// (4) Invalid hex char at a nonce position → HexDecode lookup rejects.
#[test]
fn invariant_5_invalid_hex_char_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let honest = w.to_ffi_bytes().expect("serialize");

    let n_off = nonce_offset(&honest);
    let mut tampered = honest.clone();
    // Flip matching positions in signed_content and nonce_hex so
    // byte_range_eq still holds but HexDecode rejects.
    tampered[SC_START_IN_BLOB + n_off + 10] = b'!';
    tampered[NONCE_HEX_IN_BLOB + 10] = b'!';

    let public = public_for(expected_nonce(), b"0x");
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&tampered, &pub_blob)
        .expect_err("prove must refuse non-hex char");
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(_) => {}
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}

/// (5) Silent nonce_hex substitution: both copies stay hex-valid, but
/// the decoded nonce differs from public.nonce — byte packing rejects.
#[test]
fn invariant_5_silent_nonce_hex_substitution_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let honest = w.to_ffi_bytes().expect("serialize");

    let n_off = nonce_offset(&honest);
    let mut tampered = honest.clone();
    let old = honest[NONCE_HEX_IN_BLOB + 10];
    let new = if old == b'2' { b'3' } else { b'2' };
    tampered[SC_START_IN_BLOB + n_off + 10] = new;
    tampered[NONCE_HEX_IN_BLOB + 10] = new;

    let public = public_for(expected_nonce(), b"0x");
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&tampered, &pub_blob)
        .expect_err("prove must refuse nonce_hex that decodes to the wrong nonce");
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(_) => {}
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}

/// (6) Proptest: random single-byte flips to public.nonce all reject.
fn honest_proof_cached() -> &'static zk_eidas_p7s_circuit::Proof {
    use std::sync::OnceLock;
    static PROOF: OnceLock<zk_eidas_p7s_circuit::Proof> = OnceLock::new();
    PROOF.get_or_init(|| {
        let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
        let w = Witness::new(inner);
        let correct = public_for(expected_nonce(), b"0x");
        prove(&w, &correct).expect("honest prove")
    })
}

proptest! {
    #[test]
    fn invariant_5_proptest_wrong_public_nonce(idx in 0usize..32, xor in 1u8..=255) {
        let proof = honest_proof_cached();
        let mut wrong_nonce = expected_nonce();
        wrong_nonce[idx] ^= xor;
        if wrong_nonce != expected_nonce() {
            let wrong = public_for(wrong_nonce, b"0x");
            prop_assert!(!verify(proof, &wrong).expect("verify"));
        }
    }
}
