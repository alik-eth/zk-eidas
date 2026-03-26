//! EUDI ARF PID conformance tests (Layer 1 — synthetic vectors).
//!
//! Tests the full parse → prove → verify pipeline against SD-JWT VCs
//! matching the exact EUDI PID credential schema (ARF-specified field names).
//!
//! To add real EUDI test vectors (Layer 2):
//! 1. Place SD-JWT string in tests/vectors/<name>.jwt
//! 2. Place issuer public key as tests/vectors/<name>.pub.json
//! 3. Use parse_with_issuer_key() instead of parse()

mod synthetic;

use serial_test::serial;
use zk_eidas::{Predicate, ZkCredential, ZkVerifier};

const CIRCUITS: &str = "../../circuits/build";

fn verify_proof(proof: &zk_eidas_types::proof::ZkProof) {
    let valid = ZkVerifier::new(CIRCUITS)
        .verify(proof)
        .expect("verification call failed");
    assert!(valid, "proof should verify");
}

// === Age verification ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_age_gte_18() {
    let sdjwt = synthetic::eudi_pid::eudi_pid_de();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("birth_date", Predicate::gte(18))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_age_over_18_boolean() {
    let sdjwt = synthetic::eudi_pid::eudi_pid_de();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("age_over_18", Predicate::eq("true"))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_minor_fails_age_check() {
    // ark-circom panics via debug_assert on unsatisfied constraints rather
    // than returning Err, so we need to catch the panic in debug builds.
    let result = std::panic::catch_unwind(|| {
        let sdjwt = synthetic::eudi_pid::eudi_pid_minor();
        ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
            .unwrap()
            .predicate("birth_date", Predicate::gte(18))
            .prove()
    });
    assert!(
        result.is_err() || result.unwrap().is_err(),
        "minor should fail age >= 18 proof generation"
    );
}

// === Nationality / issuing country ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_nationality_set_member() {
    let sdjwt = synthetic::eudi_pid::eudi_pid_de();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate(
            "nationality",
            Predicate::set_member(vec![
                "AT", "BE", "BG", "HR", "CY", "CZ", "DE", "DK", "EE", "ES",
                "FI", "FR", "GR", "HU", "IE", "IT",
            ]),
        )
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_issuing_country_eq() {
    let sdjwt = synthetic::eudi_pid::eudi_pid_de();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("issuing_country", Predicate::eq("DE"))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_issuing_country_neq() {
    let sdjwt = synthetic::eudi_pid::eudi_pid_fr();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("issuing_country", Predicate::neq("RU"))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

// === Name / gender ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_name_eq() {
    let sdjwt = synthetic::eudi_pid::eudi_pid_de();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("family_name", Predicate::eq("Mueller"))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_gender_eq() {
    let sdjwt = synthetic::eudi_pid::eudi_pid_de();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("gender", Predicate::eq("M"))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

// === Residency ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_resident_country_set_member() {
    let sdjwt = synthetic::eudi_pid::eudi_pid_fr();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate(
            "resident_country",
            Predicate::set_member(vec![
                "AT", "BE", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU",
                "IS", "IT", "LV", "LI", "LT", "LU",
            ]),
        )
        .prove()
        .unwrap();
    verify_proof(&proof);
}

// === Document validity ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_document_not_expired() {
    let sdjwt = synthetic::eudi_pid::eudi_pid_de();
    let today_epoch_days = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        (now.as_secs() / 86400) as i64
    };
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("expiry_date", Predicate::gte(today_epoch_days))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

// === Cross-border ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_cross_border_fr_to_de() {
    // French citizen verified by a German service — age check
    let sdjwt = synthetic::eudi_pid::eudi_pid_fr();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("birth_date", Predicate::gte(18))
        .prove()
        .unwrap();
    verify_proof(&proof);
}

// === UA bridge ===

#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
#[serial]
async fn pid_ua_bridge() {
    // Ukrainian credential accepted in eIDAS context (EU27 + UA set)
    let sdjwt = synthetic::eudi_pid::eudi_pid_ua();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate(
            "nationality",
            Predicate::set_member(vec![
                "AT", "BE", "BG", "HR", "CY", "CZ", "DE", "DK", "EE", "ES",
                "FI", "FR", "GR", "HU", "IE", "UA",
            ]),
        )
        .prove()
        .unwrap();
    verify_proof(&proof);
}
