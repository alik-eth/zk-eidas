use zk_eidas::{age_cutoff_epoch_days_from, Predicate, ZkCredential, ZkVerifier};

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn test_builder_prove_age_gte() {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "John",
            "family_name": "Doe",
            "birthdate": "2000-01-15",
        }),
        "https://issuer.example.com",
    );

    let proof = ZkCredential::from_sdjwt(&sdjwt, "../../circuits/build")
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove()
        .unwrap();

    assert!(!proof.proof_bytes().is_empty());
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn test_builder_prove_and_verify() {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "John",
            "birthdate": "2000-01-15",
        }),
        "https://issuer.example.com",
    );

    let proof = ZkCredential::from_sdjwt(&sdjwt, "../../circuits/build")
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove()
        .unwrap();

    let result = ZkVerifier::new("../../circuits/build")
        .verify(&proof)
        .unwrap();

    assert!(result);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn test_builder_prove_age_lte() {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "John",
            "birthdate": "2000-01-15",
        }),
        "https://issuer.example.com",
    );

    // age <= 65 on a date claim: should succeed (person born in 2000 is ~26, which is <= 65)
    let proof = ZkCredential::from_sdjwt(&sdjwt, "../../circuits/build")
        .unwrap()
        .predicate("birthdate", Predicate::lte(65))
        .prove()
        .unwrap();

    let result = ZkVerifier::new("../../circuits/build")
        .verify(&proof)
        .unwrap();

    assert!(result);
}

#[test]
fn test_age_cutoff_calculation() {
    let cutoff = age_cutoff_epoch_days_from(18, 2026, 3, 11);
    let expected = zk_eidas_utils::date_to_epoch_days(2008, 3, 11).max(0) as u64;
    assert_eq!(cutoff, expected);
}

#[test]
fn test_age_cutoff_21_years() {
    let cutoff = age_cutoff_epoch_days_from(21, 2026, 6, 15);
    let expected = zk_eidas_utils::date_to_epoch_days(2005, 6, 15).max(0) as u64;
    assert_eq!(cutoff, expected);
}
