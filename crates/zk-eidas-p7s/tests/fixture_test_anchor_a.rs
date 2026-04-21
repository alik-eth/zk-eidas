//! Integration tests against the TestAnchorA synthetic QKB binding fixture.
//!
//! The fixture at `fixtures/binding.qkb.p7s` is a synthetic TestAnchorA
//! CAdES envelope produced by `src/bin/gen_synthetic_fixtures.rs`
//! (Task #43a). Same offsets, same JSON shape, same RFC 3161 TSA
//! countersignature shell as the original — but the signer cert DN + SPKI
//! + cert sig + content sig + ESSCertIDv2 hash were regenerated with a
//! deterministic synthetic root and signer keypair so the fixture carries
//! no real personal QES signature.

use hex_literal::hex;
use sha2::{Digest, Sha256};
use zk_eidas_p7s::{build_witness, compute_outputs};

/// TestAnchorA synthetic root pubkey — the issuer of the signer cert
/// in the synthetic fixture. Generator seed:
/// `zk-eidas-test-anchor-A-root-v1`. Uncompressed SEC1 P-256 point:
/// `0x04 || X[32] || Y[32]`. The submodule's
/// `kDiiaRootPkX/Y_decimal` constants encode the same X, Y in
/// decimal form.
const TEST_ANCHOR_A_ROOT_PK: [u8; 65] = hex!(
    "04"
    "e62c46fd4aeeef700e933114a1b85af927a007019f157e89f3ec8a36d4dc08a3"
    "c327059b5cb8ef635db4fc15e3da7ef174332efd07b7ef3a35c4b69492a64c28"
);

const FIXTURE: &[u8] = include_bytes!("../fixtures/binding.qkb.p7s");

/// The stable ID encoded in the fixture's signer cert subject.
/// Post-#43a this is the synthetic `TINUA-1111111111` rather than any
/// real RNOKPP. Format preserved for bit-compatible byte surgery.
const EXPECTED_STABLE_ID: &[u8] = b"TINUA-1111111111";

/// The secp256k1 pubkey declared in the fixture's JSON body. This
/// field is NOT touched by #43a — the JSON payload is unchanged from
/// the pre-scrub fixture, so the pk value here is a real repo-public
/// secp256k1 key and not personally identifying.
const EXPECTED_PK: [u8; 65] = hex!(
    "04aa1cd4d92aef29df5644f29d79bae2f81ba3c2ae347075fbec1301b84db712b4"
    "a0683ffcdf9b4a5eebdaaf74f0719510044d40961854901f44ce31e88b27ff2b"
);

/// The nonce in the fixture's JSON. Also untouched by #43a.
const EXPECTED_NONCE: [u8; 32] = hex!(
    "78b634054062c77d6a027b291108f6c908e52b83c8f05a9c326cbbeb6feea750"
);

#[test]
fn offsets_extract_correct_stable_id() {
    let witness = build_witness(FIXTURE, b"0x", TEST_ANCHOR_A_ROOT_PK).expect("parse");
    let off = &witness.offsets;

    let got = &witness.p7s_bytes[off.subject_sn_start..off.subject_sn_start + off.subject_sn_len];
    assert_eq!(got, EXPECTED_STABLE_ID, "stable_id mismatch");
}

#[test]
fn offsets_extract_correct_pk_hex() {
    let witness = build_witness(FIXTURE, b"0x", TEST_ANCHOR_A_ROOT_PK).expect("parse");
    let off = &witness.offsets;

    let pk_hex = &witness.p7s_bytes[off.json_pk_start..off.json_pk_start + off.json_pk_len];
    // Should be 130 ASCII hex chars (65 bytes uncompressed SEC1 = 0x04 || X[32] || Y[32])
    assert_eq!(off.json_pk_len, 130);
    assert_eq!(pk_hex, hex::encode(EXPECTED_PK).as_bytes());
}

#[test]
fn public_outputs_match_expected() {
    let context = b"0x";
    let witness = build_witness(FIXTURE, context, TEST_ANCHOR_A_ROOT_PK).expect("parse");
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
    let witness = build_witness(FIXTURE, b"wrong", TEST_ANCHOR_A_ROOT_PK).expect("parse");
    let err = compute_outputs(&witness).expect_err("should fail");
    assert!(
        matches!(err, zk_eidas_p7s::P7sError::ContextMismatch { .. }),
        "expected ContextMismatch, got {err:?}"
    );
}

#[test]
fn host_verify_succeeds_with_test_anchor_a_root() {
    let witness = build_witness(FIXTURE, b"0x", TEST_ANCHOR_A_ROOT_PK).expect("parse");
    zk_eidas_p7s::host_verify(&witness)
        .expect("host_verify must succeed against TestAnchorA synthetic root");
}
