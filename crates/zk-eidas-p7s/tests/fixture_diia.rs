//! Integration test against a real DIIA QKB binding document.
//!
//! The fixture is `fixtures/binding.qkb.p7s` — a Ukrainian DIIA-issued
//! qualified certificate signing over a QKB JSON that declares a
//! secp256k1 public key.

use hex_literal::hex;
use sha2::{Digest, Sha256};
use zk_eidas_p7s::{build_witness, compute_outputs};

/// Placeholder trust anchor for tests. Real DIIA root key is not yet
/// wired in; this test focuses on offset extraction and output derivation.
/// When `host_verify` is called, it will fail against this dummy anchor —
/// that's expected until we plug in the real DIIA root.
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

const FIXTURE: &[u8] = include_bytes!("../fixtures/binding.qkb.p7s");

/// The stable ID encoded in the fixture's signer cert subject.
const EXPECTED_STABLE_ID: &[u8] = b"TINUA-3627506575";

/// The secp256k1 pubkey declared in the fixture's JSON body.
const EXPECTED_PK: [u8; 65] = hex!(
    "04aa1cd4d92aef29df5644f29d79bae2f81ba3c2ae347075fbec1301b84db712b4"
    "a0683ffcdf9b4a5eebdaaf74f0719510044d40961854901f44ce31e88b27ff2b"
);

/// The nonce in the fixture's JSON.
const EXPECTED_NONCE: [u8; 32] = hex!(
    "78b634054062c77d6a027b291108f6c908e52b83c8f05a9c326cbbeb6feea750"
);

#[test]
fn offsets_extract_correct_stable_id() {
    let witness = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).expect("parse");
    let off = &witness.offsets;

    let got = &witness.p7s_bytes[off.subject_sn_start..off.subject_sn_start + off.subject_sn_len];
    assert_eq!(got, EXPECTED_STABLE_ID, "stable_id mismatch");
}

#[test]
fn offsets_extract_correct_pk_hex() {
    let witness = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).expect("parse");
    let off = &witness.offsets;

    let pk_hex = &witness.p7s_bytes[off.json_pk_start..off.json_pk_start + off.json_pk_len];
    // Should be 130 ASCII hex chars (65 bytes uncompressed SEC1 = 0x04 || X[32] || Y[32])
    assert_eq!(off.json_pk_len, 130);
    assert_eq!(pk_hex, hex::encode(EXPECTED_PK).as_bytes());
}

#[test]
fn public_outputs_match_expected() {
    let context = b"0x";
    let witness = build_witness(FIXTURE, context, DUMMY_ROOT_PK).expect("parse");
    let out = compute_outputs(&witness).expect("compute outputs");

    assert_eq!(out.pk, EXPECTED_PK, "pk extraction");
    assert_eq!(out.nonce, EXPECTED_NONCE, "nonce extraction");

    // Nullifier = SHA-256(stable_id || context)
    let expected_nullifier: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(EXPECTED_STABLE_ID);
        h.update(context);
        h.finalize().into()
    };
    assert_eq!(out.nullifier, expected_nullifier, "nullifier");

    // Binding hash = SHA-256(stable_id)
    let expected_binding: [u8; 32] = Sha256::digest(EXPECTED_STABLE_ID).into();
    assert_eq!(out.binding_hash, expected_binding, "binding_hash");
}

#[test]
fn context_mismatch_is_detected() {
    // Witness says "wrong" but the JSON has "0x" — compute_outputs must catch this
    let witness = build_witness(FIXTURE, b"wrong", DUMMY_ROOT_PK).expect("parse");
    let err = compute_outputs(&witness).expect_err("should fail");
    assert!(
        matches!(err, zk_eidas_p7s::P7sError::ContextMismatch { .. }),
        "expected ContextMismatch, got {err:?}"
    );
}
