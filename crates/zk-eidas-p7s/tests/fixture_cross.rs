//! Cross-fixture equality test for the person-level nullifier property.
//!
//! Two independently-signed QKB documents for the same synthetic
//! holder stable-ID (`TINUA-1111111111`, produced by the TestAnchorA
//! fixture generator) must produce identical nullifier and
//! binding_hash outputs, because both derive from the same stable_id.
//! The pre-#43a fixtures exercised the same property against a real
//! DIIA Ukrainian tax ID; the synthetic fixtures preserve the
//! stable-ID format and share-across-fixtures property by
//! construction.

use zk_eidas_p7s::{build_witness, compute_outputs};

const FIXTURE_A: &[u8] = include_bytes!("../fixtures/binding.qkb.p7s");
const FIXTURE_B: &[u8] = include_bytes!("../fixtures/admin-binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

#[test]
fn same_stable_id_produces_same_nullifier_and_binding() {
    let context = b"0x";

    let w_a = build_witness(FIXTURE_A, context, DUMMY_ROOT_PK).expect("parse A");
    let w_b = build_witness(FIXTURE_B, context, DUMMY_ROOT_PK).expect("parse B");

    let out_a = compute_outputs(&w_a).expect("compute A");
    let out_b = compute_outputs(&w_b).expect("compute B");

    assert_eq!(
        out_a.nullifier, out_b.nullifier,
        "nullifier must be identical across two p7s files for the same stable_id"
    );
    assert_eq!(
        out_a.binding_hash, out_b.binding_hash,
        "binding_hash must be identical across two p7s files for the same stable_id"
    );
    // Sanity: the fixtures are genuinely distinct (not a silent duplicate)
    assert_ne!(out_a.nonce, out_b.nonce, "fixtures should have distinct nonces");
}
