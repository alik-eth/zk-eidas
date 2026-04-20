//! Phase 2 prep: verifies that the parser extracts the `declaration` string
//! and the `timestamp` integer from the signed JSON.
//!
//! `declaration` feeds the Phase 2 DeclarationWhitelist invariant (10).
//! `timestamp` is exposed as a public output of the circuit for
//! frontend-policy anti-replay.

use zk_eidas_p7s::build_witness;

const FIXTURE_A: &[u8] = include_bytes!("../fixtures/binding.qkb.p7s");
const FIXTURE_B: &[u8] = include_bytes!("../fixtures/admin-binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

const EXPECTED_DECLARATION: &[u8] = b"I, the Holder of the qualified electronic signature applied to this statement, declare that I have generated the public key pk specified in this statement, that I retain sole control of the corresponding private key, and that I accept legal responsibility for all actions cryptographically attributable to that private key, subject to the conditions specified in this statement and in any referenced escrow configuration, until such time as I publish a revocation signed by this qualified electronic signature.";

#[test]
fn declaration_extracted_verbatim_from_fixture_a() {
    let w = build_witness(FIXTURE_A, b"0x", DUMMY_ROOT_PK).expect("parse");
    let off = &w.offsets;
    let got = &w.p7s_bytes[off.json_declaration_start..off.json_declaration_start + off.json_declaration_len];
    assert_eq!(off.json_declaration_len, EXPECTED_DECLARATION.len());
    assert_eq!(got, EXPECTED_DECLARATION);
}

#[test]
fn declaration_matches_across_fixtures() {
    let w_a = build_witness(FIXTURE_A, b"0x", DUMMY_ROOT_PK).expect("parse A");
    let w_b = build_witness(FIXTURE_B, b"0x", DUMMY_ROOT_PK).expect("parse B");
    let a = &w_a.p7s_bytes[w_a.offsets.json_declaration_start
        ..w_a.offsets.json_declaration_start + w_a.offsets.json_declaration_len];
    let b = &w_b.p7s_bytes[w_b.offsets.json_declaration_start
        ..w_b.offsets.json_declaration_start + w_b.offsets.json_declaration_len];
    assert_eq!(a, b, "both fixtures share the same declaration text");
}

#[test]
fn timestamp_extracted_as_ascii_digits_fixture_a() {
    let w = build_witness(FIXTURE_A, b"0x", DUMMY_ROOT_PK).expect("parse");
    let off = &w.offsets;
    let got = &w.p7s_bytes[off.json_timestamp_start..off.json_timestamp_start + off.json_timestamp_len];
    assert_eq!(got, b"1776621679");
}

#[test]
fn timestamp_extracted_as_ascii_digits_fixture_b() {
    let w = build_witness(FIXTURE_B, b"0x", DUMMY_ROOT_PK).expect("parse");
    let off = &w.offsets;
    let got = &w.p7s_bytes[off.json_timestamp_start..off.json_timestamp_start + off.json_timestamp_len];
    assert_eq!(got, b"1776390649");
}

#[test]
fn timestamp_differs_across_fixtures() {
    let w_a = build_witness(FIXTURE_A, b"0x", DUMMY_ROOT_PK).expect("parse A");
    let w_b = build_witness(FIXTURE_B, b"0x", DUMMY_ROOT_PK).expect("parse B");
    let a = &w_a.p7s_bytes[w_a.offsets.json_timestamp_start
        ..w_a.offsets.json_timestamp_start + w_a.offsets.json_timestamp_len];
    let b = &w_b.p7s_bytes[w_b.offsets.json_timestamp_start
        ..w_b.offsets.json_timestamp_start + w_b.offsets.json_timestamp_len];
    assert_ne!(a, b, "fixtures should have distinct timestamps");
}
