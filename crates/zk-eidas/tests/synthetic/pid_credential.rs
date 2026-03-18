#![allow(dead_code)]
/// Adult Ukrainian citizen (age 25) with standard EUDI PID claims.
pub fn adult_citizen() -> String {
    zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Oleksandr",
            "family_name": "Kovalenko",
            "birthdate": "2000-06-15",
            "nationalities": ["UA"],
            "issuing_authority": "Ministry of Digital Transformation",
            "issuing_country": "UA",
        }),
        "https://id.diia.gov.ua",
    ).0
}

/// Minor Ukrainian citizen (age 15).
pub fn minor_citizen() -> String {
    zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Maria",
            "family_name": "Shevchenko",
            "birthdate": "2011-03-22",
            "nationalities": ["UA"],
            "issuing_authority": "Ministry of Digital Transformation",
            "issuing_country": "UA",
        }),
        "https://id.diia.gov.ua",
    ).0
}

/// EU citizen with cross-border PID.
pub fn eu_citizen() -> String {
    zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Hans",
            "family_name": "Mueller",
            "birthdate": "1985-11-30",
            "nationalities": ["DE"],
            "issuing_authority": "Bundesdruckerei",
            "issuing_country": "DE",
        }),
        "https://id.bund.de",
    ).0
}

/// French citizen (age 30) — issued by French national ID provider.
pub fn french_citizen() -> String {
    zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Jean",
            "family_name": "Dupont",
            "birthdate": "1995-09-20",
            "nationalities": ["FR"],
            "issuing_authority": "Agence Nationale des Titres Sécurisés",
            "issuing_country": "FR",
        }),
        "https://id.france.gouv.fr",
    ).0
}

/// Dutch citizen (age 28) — issued by Dutch DigiD.
pub fn dutch_citizen() -> String {
    zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Pieter",
            "family_name": "de Vries",
            "birthdate": "1997-12-05",
            "nationalities": ["NL"],
            "issuing_authority": "Rijksdienst voor Identiteitsgegevens",
            "issuing_country": "NL",
        }),
        "https://id.digid.nl",
    ).0
}

/// Italian citizen (age 45) — issued by Italian SPID.
pub fn italian_citizen() -> String {
    zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Marco",
            "family_name": "Rossi",
            "birthdate": "1980-04-11",
            "nationalities": ["IT"],
            "issuing_authority": "Istituto Poligrafico e Zecca dello Stato",
            "issuing_country": "IT",
        }),
        "https://id.spid.gov.it",
    ).0
}

/// Spanish citizen (age 19, barely adult) — edge case for age checks.
pub fn spanish_citizen_barely_adult() -> String {
    zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Ana",
            "family_name": "García",
            "birthdate": "2007-01-15",
            "nationalities": ["ES"],
            "issuing_authority": "Dirección General de la Policía",
            "issuing_country": "ES",
        }),
        "https://id.policia.es",
    ).0
}

/// Adult French citizen with real ECDSA signature — for signed circuit tests.
pub fn french_citizen_signed() -> String {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Jean",
            "family_name": "Dupont",
            "birthdate": "1995-09-20",
            "nationalities": ["FR"],
            "issuing_authority": "Agence Nationale des Titres Sécurisés",
            "issuing_country": "FR",
        }),
        "https://id.france.gouv.fr",
    );
    sdjwt
}

/// Italian citizen with real ECDSA signature — for signed eq/neq tests.
pub fn italian_citizen_signed() -> String {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Marco",
            "family_name": "Rossi",
            "birthdate": "1980-04-11",
            "nationalities": ["IT"],
            "issuing_authority": "Istituto Poligrafico e Zecca dello Stato",
            "issuing_country": "IT",
        }),
        "https://id.spid.gov.it",
    );
    sdjwt
}

/// Adult German citizen with real ECDSA signature.
pub fn eu_citizen_signed() -> String {
    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Hans",
            "family_name": "Mueller",
            "birthdate": "1985-11-30",
            "nationalities": ["DE"],
            "issuing_authority": "Bundesdruckerei",
            "issuing_country": "DE",
        }),
        "https://id.bund.de",
    );
    sdjwt
}
