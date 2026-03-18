#![allow(dead_code)]
//! Synthetic EUDI ARF PID credentials for conformance testing.
//!
//! Field names match the EUDI Architecture Reference Framework PID schema
//! exactly (snake_case). Each credential is ECDSA P-256 signed.
//!
//! These are synthetic (self-signed) credentials. To test with real EUDI
//! vectors, place SD-JWT strings in `tests/vectors/` and use
//! `parse_with_issuer_key()` with the real issuer public key.

/// German PID — adult male, Berlin resident.
pub fn eudi_pid_de() -> String {
    let expiry_days = zk_eidas_utils::date_to_epoch_days(2035, 6, 15);
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "family_name": "Mueller",
            "given_name": "Hans",
            "birth_date": "1985-11-30",
            "age_over_18": true,
            "issuing_country": "DE",
            "issuing_authority": "Bundesdruckerei",
            "nationality": "DE",
            "resident_country": "DE",
            "resident_city": "Berlin",
            "gender": "M",
            "document_number": "DE-PID-2025-001",
            "expiry_date": expiry_days,
        }),
        "https://pid.bund.de",
    );
    sdjwt
}

/// French PID — adult female, Paris resident.
pub fn eudi_pid_fr() -> String {
    let expiry_days = zk_eidas_utils::date_to_epoch_days(2034, 4, 22);
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "family_name": "Dubois",
            "given_name": "Camille",
            "birth_date": "1993-04-22",
            "age_over_18": true,
            "issuing_country": "FR",
            "issuing_authority": "Agence Nationale des Titres Securises",
            "nationality": "FR",
            "resident_country": "FR",
            "resident_city": "Paris",
            "gender": "F",
            "document_number": "FR-PID-2024-042",
            "expiry_date": expiry_days,
        }),
        "https://pid.france.gouv.fr",
    );
    sdjwt
}

/// Ukrainian PID — adult male, Kyiv resident. Tests EU-UA bridge scenario.
pub fn eudi_pid_ua() -> String {
    let expiry_days = zk_eidas_utils::date_to_epoch_days(2035, 5, 14);
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "family_name": "Kovalenko",
            "given_name": "Oleksandr",
            "birth_date": "1998-05-14",
            "age_over_18": true,
            "issuing_country": "UA",
            "issuing_authority": "Ministry of Digital Transformation",
            "nationality": "UA",
            "resident_country": "UA",
            "resident_city": "Kyiv",
            "gender": "M",
            "document_number": "UA-PID-2025-100",
            "expiry_date": expiry_days,
        }),
        "https://pid.diia.gov.ua",
    );
    sdjwt
}

/// German minor PID — age 15, should fail age >= 18 checks.
pub fn eudi_pid_minor() -> String {
    let expiry_days = zk_eidas_utils::date_to_epoch_days(2031, 8, 3);
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "family_name": "Schmidt",
            "given_name": "Emma",
            "birth_date": "2011-08-03",
            "age_over_18": false,
            "issuing_country": "DE",
            "issuing_authority": "Bundesdruckerei",
            "nationality": "DE",
            "resident_country": "DE",
            "resident_city": "Munich",
            "gender": "F",
            "document_number": "DE-PID-2025-099",
            "expiry_date": expiry_days,
        }),
        "https://pid.bund.de",
    );
    sdjwt
}
