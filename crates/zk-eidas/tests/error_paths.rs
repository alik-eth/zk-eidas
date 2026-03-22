use zk_eidas::{Predicate, ZkCredential, ZkError};

const CIRCUITS: &str = "../../circuits/build";

#[test]
fn prove_with_no_predicates_returns_error() {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({"age": 25}),
        "test-issuer",
    );

    let result = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS).unwrap().prove();

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ZkError::EmptyPredicates),
        "expected EmptyPredicates when no predicates are added"
    );
}

#[test]
fn prove_with_missing_claim_returns_error() {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({"age": 25}),
        "test-issuer",
    );

    let result = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("nonexistent_claim", Predicate::gte(18))
        .prove();

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ZkError::ClaimNotFound(ref name) if name == "nonexistent_claim"),
        "expected ClaimNotFound for a claim not in the credential"
    );
}

#[test]
fn prove_string_claim_with_gte_returns_error() {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({"name": "Alice", "age": 30}),
        "test-issuer",
    );

    let result = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("name", Predicate::gte(18))
        .prove();

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ZkError::IncompatibleClaimType),
        "expected IncompatibleClaimType when applying gte to a string claim"
    );
}

#[test]
fn prove_opaque_credential_returns_ecdsa_required() {
    let sdjwt = zk_eidas_parser::test_utils::build_synthetic_sdjwt(
        serde_json::json!({"age": 25}),
        "test-issuer",
    );

    let result = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("age", Predicate::gte(18))
        .prove();

    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), ZkError::EcdsaRequired),
        "expected EcdsaRequired for opaque (non-ECDSA) credential"
    );
}

#[test]
fn parse_invalid_sdjwt_returns_error() {
    let result = ZkCredential::from_sdjwt("this-is-not-a-valid-sdjwt", CIRCUITS);

    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        matches!(err, ZkError::Parse(_)),
        "expected Parse error for garbage SD-JWT input, got: {err}"
    );
}

#[test]
fn prove_all_with_no_predicates_returns_empty() {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({"age": 25}),
        "test-issuer",
    );

    let result = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .prove_all();

    assert!(result.is_ok(), "prove_all with no predicates should return Ok");
    assert!(result.unwrap().is_empty(), "expected empty vec for no predicates (binding-only mode)");
}
