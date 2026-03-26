//! Integration test: mdoc with COSE_Sign1 → signed proof → verification.
//!
//! Proves the full pipeline works end-to-end for mdoc/mDL credentials using
//! the same signed circuits as SD-JWT (ECDSA P-256 + SHA-256).

use zk_eidas::{Predicate, ZkCredential, ZkVerifier};
use zk_eidas_mdoc::MdocParser;
use zk_eidas_types::credential::ClaimValue;

const CIRCUITS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circuits/build");

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn mdoc_signed_gte_proof_end_to_end() {
    let (mdoc_bytes, pub_key_x, pub_key_y) = zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(
        vec![
            ("age", ClaimValue::Integer(25)),
            ("given_name", ClaimValue::String("Олександр".into())),
        ],
        "DIIA",
    );

    let credential =
        MdocParser::parse_with_issuer_key(&mdoc_bytes, pub_key_x, pub_key_y).expect("parse failed");

    assert!(credential.signature_data().is_ecdsa());

    let proof = ZkCredential::from_credential(credential, CIRCUITS_PATH)
        .predicate("age", Predicate::gte(18))
        .prove()
        .expect("prove failed");

    let valid = ZkVerifier::new(CIRCUITS_PATH)
        .verify(&proof)
        .expect("verify failed");
    assert!(valid, "mdoc signed GTE proof should verify");
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn mdoc_signed_eq_proof_end_to_end() {
    let (mdoc_bytes, pub_key_x, pub_key_y) = zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(
        vec![("nationality", ClaimValue::String("UA".into()))],
        "DIIA",
    );

    let credential =
        MdocParser::parse_with_issuer_key(&mdoc_bytes, pub_key_x, pub_key_y).expect("parse failed");

    let proof = ZkCredential::from_credential(credential, CIRCUITS_PATH)
        .predicate("nationality", Predicate::eq("UA"))
        .prove()
        .expect("prove failed");

    let valid = ZkVerifier::new(CIRCUITS_PATH)
        .verify(&proof)
        .expect("verify failed");
    assert!(valid, "mdoc signed EQ proof should verify");
}
