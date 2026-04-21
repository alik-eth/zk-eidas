//! Declaration whitelist — the JSON "declaration" field equals the single
//! N=1 whitelist entry (`kDeclarationPhrase`, 510 ASCII bytes) compiled
//! into the circuit.
//!
//! Tests:
//!   1. Happy: fixture declaration matches the whitelist.
//!   2. Tamper a declaration byte in signed_content: prover refuses.
//!   3. Swap the declaration bytes with a non-whitelisted phrase (same
//!      length, different content): prover refuses.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

// v5 blob offsets — keep in sync with `witness.rs`'s serializer.
const SC_START_IN_BLOB: usize = 4 + 4 + 32 + 4; // 44
const PK_OFF_IN_BLOB: usize = SC_START_IN_BLOB + 1024; // 1068
const PK_HEX_IN_BLOB: usize = PK_OFF_IN_BLOB + 4; // 1072
const NONCE_OFF_IN_BLOB: usize = PK_HEX_IN_BLOB + 130; // 1202
const NONCE_HEX_IN_BLOB: usize = NONCE_OFF_IN_BLOB + 4; // 1206
const CTX_OFF_IN_BLOB: usize = NONCE_HEX_IN_BLOB + 64; // 1270
const DECL_OFF_IN_BLOB: usize = CTX_OFF_IN_BLOB + 4; // 1274

const DECLARATION_LEN: usize = 510;

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

fn decl_offset(blob: &[u8]) -> usize {
    u32::from_le_bytes([
        blob[DECL_OFF_IN_BLOB],
        blob[DECL_OFF_IN_BLOB + 1],
        blob[DECL_OFF_IN_BLOB + 2],
        blob[DECL_OFF_IN_BLOB + 3],
    ]) as usize
}

/// (1) Happy: the real fixture's declaration is the single v1 whitelist
/// entry — prove+verify round-trips.
#[test]
fn declaration_whitelist_happy_round_trips() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let public = public_for(b"0x");

    let proof = prove(&w, &public).expect("prove");
    assert!(
        verify(&proof, &public).expect("verify"),
        "honest proof must verify"
    );
}

/// (2) Tampered declaration byte in signed_content: byte_range_eq rejects.
#[test]
fn declaration_whitelist_tampered_byte_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let honest = w.to_ffi_bytes().expect("serialize");

    let d_off = decl_offset(&honest);
    // Flip a byte in the middle of the declaration (position 200).
    let mut tampered = honest.clone();
    tampered[SC_START_IN_BLOB + d_off + 200] ^= 0x01;

    let public = public_for(b"0x");
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&tampered, &pub_blob)
        .expect_err("prove must refuse tampered declaration byte");
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(_) => {}
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}

/// (3) Swap entire declaration with a non-whitelisted phrase of the same
/// length: byte_range_eq rejects. The replacement is an ASCII 'X' block
/// of the exact whitelist length.
#[test]
fn declaration_whitelist_non_whitelisted_phrase_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let honest = w.to_ffi_bytes().expect("serialize");

    let d_off = decl_offset(&honest);
    let mut tampered = honest.clone();
    for i in 0..DECLARATION_LEN {
        tampered[SC_START_IN_BLOB + d_off + i] = b'X';
    }

    let public = public_for(b"0x");
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&tampered, &pub_blob)
        .expect_err("prove must refuse non-whitelisted declaration");
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(_) => {}
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}
