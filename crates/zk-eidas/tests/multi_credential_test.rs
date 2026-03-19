//! Multi-credential holder binding integration test.
//!
//! Proves that two different credentials issued to the same holder can be
//! linked via a shared binding hash without revealing the linking claim.

use serial_test::serial;
use zk_eidas::{Predicate, ZkCredential, ZkVerifier};
use zk_eidas_types::predicate::PredicateOp;

const CIRCUITS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circuits/build");

/// Helper: build an ECDSA-signed SD-JWT with the given claims and issuer.
fn build_signed_sdjwt(claims: serde_json::Value, issuer: &str) -> String {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(claims, issuer);
    sdjwt
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn multi_credential_holder_binding() {
    // Issue two credentials to the same holder (same personal_identifier)
    let sdjwt_pid = build_signed_sdjwt(
        serde_json::json!({
            "birthdate": "2000-06-15",
            "nationality": "UA",
            "personal_identifier": "UA-123456789"
        }),
        "https://diia.gov.ua",
    );

    let sdjwt_uni = build_signed_sdjwt(
        serde_json::json!({
            "degree": "masters",
            "university": "KPI",
            "personal_identifier": "UA-123456789"
        }),
        "https://university.edu.ua",
    );

    // Prove age >= 18 from PID + binding on personal_identifier
    let (pid_proofs, pid_binding) = ZkCredential::from_sdjwt(&sdjwt_pid, CIRCUITS_PATH)
        .expect("parse PID failed")
        .predicate("birthdate", Predicate::gte(18))
        .prove_with_binding("personal_identifier")
        .expect("prove PID with binding failed");

    // Prove degree == "masters" from university credential + binding
    let (uni_proofs, uni_binding) = ZkCredential::from_sdjwt(&sdjwt_uni, CIRCUITS_PATH)
        .expect("parse UNI failed")
        .predicate("degree", Predicate::eq("masters"))
        .prove_with_binding("personal_identifier")
        .expect("prove UNI with binding failed");

    // Binding hashes should match (same personal_identifier)
    assert_eq!(
        pid_binding, uni_binding,
        "binding hashes should match for same holder"
    );

    // Should have binding proofs
    assert!(
        pid_proofs
            .iter()
            .any(|p| p.predicate_op() == PredicateOp::HolderBinding),
        "PID proofs should contain a HolderBinding proof"
    );
    assert!(
        uni_proofs
            .iter()
            .any(|p| p.predicate_op() == PredicateOp::HolderBinding),
        "UNI proofs should contain a HolderBinding proof"
    );

    // Verify all proofs
    let verifier = ZkVerifier::new(CIRCUITS_PATH);
    for proof in pid_proofs.iter().chain(uni_proofs.iter()) {
        assert!(
            verifier.verify(proof).unwrap(),
            "proof {:?} should verify",
            proof.predicate_op()
        );
    }

    // Verify cross-credential binding
    assert!(
        verifier
            .verify_holder_binding(&pid_proofs, &uni_proofs)
            .unwrap(),
        "cross-credential binding should match"
    );
}
