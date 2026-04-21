//! Integration tests against the TestAnchorB synthetic QKB binding
//! fixture (Task #44).
//!
//! Same surgery recipe as the TestAnchorA fixtures, but with the
//! `DN_SUBS_TESTANCHOR_B` reg-code / DN-org substitutions and the
//! `zk-eidas-p7s-testanchor-b-*-v1` key derivation seeds. These
//! fixtures exist to exercise the N=2 trust-anchor multiplexer in
//! the sig circuit against a non-zero `trust_anchor_index`.

use hex_literal::hex;
use zk_eidas_p7s::build_witness;

/// TestAnchorB synthetic root pubkey. Seed:
/// `zk-eidas-p7s-testanchor-b-root-v1`. Mirrors the submodule's
/// `kTestAnchorBRootPkX/Y_decimal` constants.
const TEST_ANCHOR_B_ROOT_PK: [u8; 65] = hex!(
    "04"
    "3a48db8f884948fb58ce44bc21a3deeb6e62ceb23c7a1384cf27d126c8ea0b9b"
    "baed0eeec7f234ced5e8b233cec71ed2346d1dbb3559acb2f5ccc1faa4778043"
);

const FIXTURE_B: &[u8] = include_bytes!("../fixtures/testanchor-b-binding.qkb.p7s");

/// Stable-ID encoded in the TestAnchorB fixture's signer cert subject.
/// Derived from the `DN_SUBS_TESTANCHOR_B` table.
const EXPECTED_STABLE_ID_B: &[u8] = b"TINUB-2222222222";

#[test]
fn parser_returns_trust_anchor_index_1_for_testanchor_b() {
    let witness = build_witness(FIXTURE_B, b"0x", TEST_ANCHOR_B_ROOT_PK).expect("parse");
    assert_eq!(
        witness.offsets.trust_anchor_index, 1,
        "TestAnchorB issuer DN must probe to index 1 (TQSB-00000000-02 marker)"
    );
}

#[test]
fn offsets_extract_testanchor_b_stable_id() {
    let witness = build_witness(FIXTURE_B, b"0x", TEST_ANCHOR_B_ROOT_PK).expect("parse");
    let off = &witness.offsets;
    let got = &witness.p7s_bytes[off.subject_sn_start..off.subject_sn_start + off.subject_sn_len];
    assert_eq!(got, EXPECTED_STABLE_ID_B);
}

#[test]
fn host_verify_succeeds_with_testanchor_b_root() {
    let witness = build_witness(FIXTURE_B, b"0x", TEST_ANCHOR_B_ROOT_PK).expect("parse");
    zk_eidas_p7s::host_verify(&witness)
        .expect("host_verify must succeed against TestAnchorB synthetic root");
}
