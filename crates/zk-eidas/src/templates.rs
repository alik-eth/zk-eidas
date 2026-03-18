//! Pre-built predicate templates for common eIDAS verification scenarios.

use crate::Predicate;

/// A predicate template: (claim_name, predicate, human_description).
pub type Template = (&'static str, Predicate, &'static str);

/// Prove the holder is at least 18 years old.
pub fn age_over_18() -> Template {
    (
        "birthdate",
        Predicate::gte(18),
        "Holder is at least 18 years old",
    )
}

/// Prove the holder is at least 21 years old.
pub fn age_over_21() -> Template {
    (
        "birthdate",
        Predicate::gte(21),
        "Holder is at least 21 years old",
    )
}

/// Prove the holder is at least 65 years old.
pub fn age_over_65() -> Template {
    (
        "birthdate",
        Predicate::gte(65),
        "Holder is at least 65 years old",
    )
}

/// Prove the holder is a national of an EU member state (group 1 of 2).
///
/// The set_member circuit supports at most 16 elements. The 27 EU countries
/// are split into two templates. Use both with `Predicate::Or` for full coverage.
pub fn eu_nationality() -> Template {
    (
        "nationality",
        Predicate::set_member(vec![
            "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE",
            "IT", "LV",
        ]),
        "Holder is a national of an EU member state",
    )
}

/// Prove the holder is a national of an EU member state (group 2 of 2).
pub fn eu_nationality_2() -> Template {
    (
        "nationality",
        Predicate::set_member(vec![
            "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
        ]),
        "Holder is a national of an EU member state (group 2)",
    )
}

/// Prove the credential has not been revoked.
pub fn credential_not_revoked() -> Template {
    (
        "credential_status",
        Predicate::neq("revoked"),
        "Credential has not been revoked",
    )
}

/// Prove the holder resides in a Schengen area country (group 1 of 2).
pub fn schengen_residency() -> Template {
    (
        "resident_country",
        Predicate::set_member(vec![
            "AT", "BE", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IS", "IT", "LV", "LI",
            "LT", "LU",
        ]),
        "Holder resides in a Schengen area country",
    )
}

/// Prove the holder resides in a Schengen area country (group 2 of 2).
pub fn schengen_residency_2() -> Template {
    (
        "resident_country",
        Predicate::set_member(vec![
            "MT", "NL", "NO", "PL", "PT", "SK", "SI", "ES", "SE", "CH",
        ]),
        "Holder resides in a Schengen area country (group 2)",
    )
}

/// Return all built-in predicate templates.
pub fn all() -> Vec<Template> {
    vec![
        age_over_18(),
        age_over_21(),
        age_over_65(),
        eu_nationality(),
        eu_nationality_2(),
        credential_not_revoked(),
        schengen_residency(),
        schengen_residency_2(),
    ]
}
