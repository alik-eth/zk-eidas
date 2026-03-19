//! End-to-end integration tests for signed ZK proofs.
//!
//! These tests require compiled signed Noir circuits (checked into repo)
//! and download Barretenberg's SRS on first run.

use zk_eidas::{Predicate, ZkCredential, ZkVerifier};

const CIRCUITS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circuits/build");

/// Helper: build an ECDSA-signed SD-JWT with the given claims.
fn build_signed_sdjwt(claims: serde_json::Value) -> String {
    let (sdjwt, _key) =
        zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(claims, "https://pid.example.eu");
    sdjwt
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn signed_gte_proof_end_to_end() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({ "age": 25 }));

    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .expect("parse failed")
        .predicate("age", Predicate::gte(18))
        .prove()
        .expect("prove failed");

    let valid = ZkVerifier::new(CIRCUITS_PATH)
        .verify(&proof)
        .expect("verify failed");
    assert!(valid, "signed GTE proof should verify");
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn signed_lte_proof_end_to_end() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({ "score": 42 }));

    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .expect("parse failed")
        .predicate("score", Predicate::lte(100))
        .prove()
        .expect("prove failed");

    let valid = ZkVerifier::new(CIRCUITS_PATH)
        .verify(&proof)
        .expect("verify failed");
    assert!(valid, "signed LTE proof should verify");
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn signed_eq_proof_end_to_end() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({ "country": "DE" }));

    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .expect("parse failed")
        .predicate("country", Predicate::eq("DE"))
        .prove()
        .expect("prove failed");

    let valid = ZkVerifier::new(CIRCUITS_PATH)
        .verify(&proof)
        .expect("verify failed");
    assert!(valid, "signed EQ proof should verify");
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn signed_neq_proof_end_to_end() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({ "country": "DE" }));

    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .expect("parse failed")
        .predicate("country", Predicate::neq("FR"))
        .prove()
        .expect("prove failed");

    let valid = ZkVerifier::new(CIRCUITS_PATH)
        .verify(&proof)
        .expect("verify failed");
    assert!(valid, "signed NEQ proof should verify");
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn signed_set_member_proof_end_to_end() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({ "country": "DE" }));

    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .expect("parse failed")
        .predicate("country", Predicate::set_member(vec!["DE", "FR", "IT"]))
        .prove()
        .expect("prove failed");

    let valid = ZkVerifier::new(CIRCUITS_PATH)
        .verify(&proof)
        .expect("verify failed");
    assert!(valid, "signed set_member proof should verify");
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn signed_range_proof_end_to_end() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({ "score": 75 }));

    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .expect("parse failed")
        .predicate("score", Predicate::gte(50))
        .prove()
        .expect("prove failed");

    let valid = ZkVerifier::new(CIRCUITS_PATH)
        .verify(&proof)
        .expect("verify failed");
    assert!(valid, "signed range (GTE) proof should verify");
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn signed_compound_and_proof() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({ "age": 25, "score": 80 }));

    let proofs = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .expect("parse failed")
        .predicate("age", Predicate::gte(18))
        .predicate("score", Predicate::lte(100))
        .prove_all()
        .expect("prove_all failed");

    assert_eq!(proofs.len(), 2, "should produce two proofs");

    let verifier = ZkVerifier::new(CIRCUITS_PATH);
    for (i, proof) in proofs.iter().enumerate() {
        let valid = verifier.verify(proof).expect("verify failed");
        assert!(valid, "compound proof {i} should verify");
    }
}
