use zk_eidas::templates;

#[test]
fn age_over_18_returns_gte_predicate() {
    let (claim, pred, desc) = templates::age_over_18();
    assert_eq!(claim, "birthdate");
    assert_eq!(desc, "Holder is at least 18 years old");
    assert!(matches!(pred, zk_eidas::Predicate::Gte(18)));
}

#[test]
fn age_over_21_returns_gte_predicate() {
    let (claim, pred, _desc) = templates::age_over_21();
    assert_eq!(claim, "birthdate");
    assert!(matches!(pred, zk_eidas::Predicate::Gte(21)));
}

#[test]
fn eu_nationality_returns_set_member() {
    let (claim, pred, desc) = templates::eu_nationality();
    assert_eq!(claim, "nationality");
    assert_eq!(desc, "Holder is a national of an EU member state");
    match pred {
        zk_eidas::Predicate::SetMember(countries) => {
            assert!(countries.len() <= 16, "group 1 must be <= 16");
            assert!(countries.contains(&"DE".to_string()));
            assert!(countries.contains(&"FR".to_string()));
            assert!(!countries.contains(&"UA".to_string()));
        }
        _ => panic!("expected SetMember"),
    }
}

#[test]
fn credential_not_revoked_returns_neq() {
    let (claim, pred, _desc) = templates::credential_not_revoked();
    assert_eq!(claim, "credential_status");
    assert!(matches!(pred, zk_eidas::Predicate::Neq(_)));
}

#[test]
fn all_templates_returns_non_empty_list() {
    let all = templates::all();
    assert!(all.len() >= 4);
}

/// Circuit set_member has a max of 16 elements. Templates must not exceed this.
#[test]
fn set_member_templates_respect_circuit_max() {
    for (claim, pred, desc) in templates::all() {
        if let zk_eidas::Predicate::SetMember(values) = pred {
            assert!(
                values.len() <= 16,
                "template '{desc}' for claim '{claim}' has {} values, max is 16",
                values.len()
            );
        }
    }
}
