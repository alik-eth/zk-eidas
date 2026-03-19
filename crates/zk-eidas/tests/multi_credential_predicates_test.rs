//! Integration tests for multi-credential demo predicates.
//!
//! Tests the specific predicate combinations used by each credential type
//! in the demo wizard: PID, Driver's License (mdoc), Diploma, Vehicle.

use serial_test::serial;
use zk_eidas::{Predicate, ZkCredential, ZkVerifier};
use zk_eidas_mdoc::MdocParser;
use zk_eidas_types::credential::ClaimValue;

const CIRCUITS_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circuits/build");

fn build_signed_sdjwt(claims: serde_json::Value) -> String {
    let (sdjwt, _key) =
        zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(claims, "https://issuer.example.eu");
    sdjwt
}

fn verify_proof(proof: &zk_eidas_types::proof::ZkProof) {
    let valid = ZkVerifier::new(CIRCUITS_PATH)
        .verify(proof)
        .expect("verify failed");
    assert!(valid, "proof should verify");
}

// === Driver's License (mdoc) ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn drivers_license_category_eq() {
    let (mdoc_bytes, pkx, pky) = zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(
        vec![
            ("category", ClaimValue::String("A, B, C1".into())),
            ("holder_name", ClaimValue::String("Kadri Tamm".into())),
        ],
        "https://ppa.ee",
    );
    let credential = MdocParser::parse_with_issuer_key(&mdoc_bytes, pkx, pky).unwrap();
    let proof = ZkCredential::from_credential(credential, CIRCUITS_PATH)
        .predicate("category", Predicate::eq("A, B, C1"))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn drivers_license_expiry_date_gte_epoch_days() {
    // expiry_date stored as epoch days integer (not ClaimValue::Date)
    let expiry_epoch_days = zk_eidas_utils::date_to_epoch_days(2034, 3, 22);
    let today_epoch_days = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        (now.as_secs() / 86400) as u64
    };

    let (mdoc_bytes, pkx, pky) = zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(
        vec![("expiry_date", ClaimValue::Integer(expiry_epoch_days as i64))],
        "https://ppa.ee",
    );
    let credential = MdocParser::parse_with_issuer_key(&mdoc_bytes, pkx, pky).unwrap();
    let proof = ZkCredential::from_credential(credential, CIRCUITS_PATH)
        .predicate("expiry_date", Predicate::gte(today_epoch_days as i64))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn drivers_license_issue_date_lte_epoch_days() {
    // issue_date as epoch days, proving it was issued at least 2 years ago
    let issue_epoch_days = zk_eidas_utils::date_to_epoch_days(2019, 3, 22);
    let two_years_ago = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let today_secs = now.as_secs();
        // Approximate 2 years ago
        (today_secs / 86400 - 730) as u64
    };

    let (mdoc_bytes, pkx, pky) = zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(
        vec![("issue_date", ClaimValue::Integer(issue_epoch_days as i64))],
        "https://ppa.ee",
    );
    let credential = MdocParser::parse_with_issuer_key(&mdoc_bytes, pkx, pky).unwrap();
    let proof = ZkCredential::from_credential(credential, CIRCUITS_PATH)
        .predicate("issue_date", Predicate::lte(two_years_ago as i64))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn drivers_license_restrictions_eq_none() {
    let (mdoc_bytes, pkx, pky) = zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(
        vec![("restrictions", ClaimValue::String("None".into()))],
        "https://ppa.ee",
    );
    let credential = MdocParser::parse_with_issuer_key(&mdoc_bytes, pkx, pky).unwrap();
    let proof = ZkCredential::from_credential(credential, CIRCUITS_PATH)
        .predicate("restrictions", Predicate::eq("None"))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

// === University Diploma (SD-JWT) ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn diploma_field_of_study_set_member() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({
        "field_of_study": "Computer Science",
        "student_name": "Camille Dubois",
    }));
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .unwrap()
        .predicate(
            "field_of_study",
            Predicate::set_member(vec![
                "Computer Science",
                "Mathematics",
                "Physics",
                "Chemistry",
                "Biology",
                "Engineering",
            ]),
        )
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn diploma_graduation_year_gte() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({
        "graduation_year": 2023,
        "student_name": "Camille Dubois",
    }));
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .unwrap()
        .predicate("graduation_year", Predicate::gte(2020))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn diploma_degree_set_member() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({
        "degree": "Master (M2)",
        "student_name": "Camille Dubois",
    }));
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .unwrap()
        .predicate(
            "degree",
            Predicate::set_member(vec!["Master (M1)", "Master (M2)", "PhD"]),
        )
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn diploma_university_eq() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({
        "university": "Sorbonne Universit\u{00e9}",
        "student_name": "Camille Dubois",
    }));
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .unwrap()
        .predicate("university", Predicate::eq("Sorbonne Universit\u{00e9}"))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

// === Vehicle Registration (SD-JWT) ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn vehicle_insurance_expiry_gte_epoch_days() {
    // insurance_expiry stored as epoch days for direct comparison
    let expiry_epoch_days = zk_eidas_utils::date_to_epoch_days(2027, 1, 15) as i64;
    let today_epoch_days = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        (now.as_secs() / 86400) as i64
    };

    let sdjwt = build_signed_sdjwt(serde_json::json!({
        "insurance_expiry": expiry_epoch_days,
        "owner_name": "Maximilian Schneider",
    }));
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .unwrap()
        .predicate("insurance_expiry", Predicate::gte(today_epoch_days))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn vehicle_make_model_set_member() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({
        "make_model": "Volkswagen Golf",
        "owner_name": "Maximilian Schneider",
    }));
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .unwrap()
        .predicate(
            "make_model",
            Predicate::set_member(vec![
                "Volkswagen Golf",
                "BMW 3 Series",
                "Toyota Corolla",
                "Renault Clio",
                "Fiat 500",
            ]),
        )
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn vehicle_vin_neq_revoked() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({
        "vin": "WVWZZZ1JZYW000001",
        "owner_name": "Maximilian Schneider",
    }));
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .unwrap()
        .predicate("vin", Predicate::neq("REVOKED"))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

// === Compound proof with non-PID credential ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn diploma_compound_and_stem_recent_grad() {
    let sdjwt = build_signed_sdjwt(serde_json::json!({
        "field_of_study": "Computer Science",
        "graduation_year": 2023,
        "student_name": "Camille Dubois",
    }));
    let compound = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS_PATH)
        .unwrap()
        .predicate(
            "field_of_study",
            Predicate::and(vec![Predicate::set_member(vec![
                "Computer Science",
                "Mathematics",
                "Physics",
                "Chemistry",
                "Biology",
                "Engineering",
            ])]),
        )
        .predicate(
            "graduation_year",
            Predicate::and(vec![Predicate::gte(2020)]),
        )
        .prove_compound()
        .unwrap();

    assert_eq!(compound.proofs().len(), 2);
}

// === mdoc compound proof ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn drivers_license_compound_category_and_valid() {
    let expiry_epoch_days = zk_eidas_utils::date_to_epoch_days(2034, 3, 22);
    let today_epoch_days = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        (now.as_secs() / 86400) as u64
    };

    let (mdoc_bytes, pkx, pky) = zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(
        vec![
            ("category", ClaimValue::String("A, B, C1".into())),
            ("expiry_date", ClaimValue::Integer(expiry_epoch_days as i64)),
        ],
        "https://ppa.ee",
    );
    let credential = MdocParser::parse_with_issuer_key(&mdoc_bytes, pkx, pky).unwrap();
    let compound = ZkCredential::from_credential(credential, CIRCUITS_PATH)
        .predicate("category", Predicate::and(vec![Predicate::eq("A, B, C1")]))
        .predicate(
            "expiry_date",
            Predicate::and(vec![Predicate::gte(today_epoch_days as i64)]),
        )
        .prove_compound()
        .unwrap();

    assert_eq!(compound.proofs().len(), 2);
}
