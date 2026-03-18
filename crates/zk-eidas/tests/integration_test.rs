mod synthetic;

use zk_eidas::{Predicate, ZkCredential, ZkVerifier};

#[test]
#[ignore = "requires compiled Circom circuit artifacts"]
fn test_age_verification_over_18() {
    let sdjwt = synthetic::pid_credential::adult_citizen();
    let proof = ZkCredential::from_sdjwt(&sdjwt, "../../circuits/predicates")
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove()
        .unwrap();
    let valid = ZkVerifier::new("../../circuits/predicates")
        .verify(&proof)
        .unwrap();
    assert!(valid, "Adult citizen should pass age >= 18 verification");
}

#[test]
#[ignore = "requires compiled Circom circuit artifacts"]
fn test_age_verification_minor_fails() {
    let sdjwt = synthetic::pid_credential::minor_citizen();
    let result = ZkCredential::from_sdjwt(&sdjwt, "../../circuits/predicates")
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove();
    assert!(result.is_err(), "Minor should fail age >= 18 verification");
}

#[test]
#[ignore = "requires compiled Circom circuit artifacts"]
fn test_french_citizen_age_verification() {
    let sdjwt = synthetic::pid_credential::french_citizen();
    let proof = ZkCredential::from_sdjwt(&sdjwt, "../../circuits/predicates")
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove()
        .unwrap();
    let valid = ZkVerifier::new("../../circuits/predicates")
        .verify(&proof)
        .unwrap();
    assert!(valid, "French citizen should pass age >= 18 verification");
}

#[test]
#[ignore = "requires compiled Circom circuit artifacts"]
fn test_dutch_citizen_nationality_set_member() {
    let sdjwt = synthetic::pid_credential::dutch_citizen();
    let proof = ZkCredential::from_sdjwt(&sdjwt, "../../circuits/predicates")
        .unwrap()
        .predicate(
            "issuing_country",
            Predicate::set_member(vec!["NL", "DE", "FR", "IT", "ES"]),
        )
        .prove()
        .unwrap();
    let valid = ZkVerifier::new("../../circuits/predicates")
        .verify(&proof)
        .unwrap();
    assert!(valid, "Dutch citizen should be in EU nationality set");
}
