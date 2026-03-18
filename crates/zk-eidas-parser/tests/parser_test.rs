use serde_json::json;
use zk_eidas_parser::test_utils::build_synthetic_sdjwt;
use zk_eidas_parser::SdJwtParser;
use zk_eidas_types::credential::ClaimValue;

#[test]
fn test_parse_sdjwt_extracts_claims() {
    let claims = json!({
        "given_name": "John",
        "family_name": "Doe",
        "birthdate": "2000-01-15",
    });
    let sdjwt = build_synthetic_sdjwt(claims, "https://issuer.example.com");
    let parser = SdJwtParser::new();
    let credential = parser.parse(&sdjwt).expect("should parse successfully");

    assert_eq!(credential.issuer(), "https://issuer.example.com");
    assert!(credential.claims().contains_key("given_name"));
    assert!(credential.claims().contains_key("family_name"));
    assert!(credential.claims().contains_key("birthdate"));
}

#[test]
fn test_parse_sdjwt_converts_date_claim() {
    let claims = json!({
        "birthdate": "2000-01-15",
    });
    let sdjwt = build_synthetic_sdjwt(claims, "https://issuer.example.com");
    let parser = SdJwtParser::new();
    let credential = parser.parse(&sdjwt).expect("should parse successfully");

    let birthdate = credential
        .claims()
        .get("birthdate")
        .expect("birthdate claim");
    match birthdate {
        ClaimValue::Date { year, month, day } => {
            assert_eq!(*year, 2000);
            assert_eq!(*month, 1);
            assert_eq!(*day, 15);
        }
        other => panic!("expected Date, got {:?}", other),
    }
}

#[test]
fn test_parse_sdjwt_converts_string_claim() {
    let claims = json!({
        "given_name": "John",
    });
    let sdjwt = build_synthetic_sdjwt(claims, "https://issuer.example.com");
    let parser = SdJwtParser::new();
    let credential = parser.parse(&sdjwt).expect("should parse successfully");

    let name = credential
        .claims()
        .get("given_name")
        .expect("given_name claim");
    match name {
        ClaimValue::String(s) => assert_eq!(s, "John"),
        other => panic!("expected String, got {:?}", other),
    }
}

#[test]
fn test_parse_invalid_sdjwt_returns_error() {
    let parser = SdJwtParser::new();
    let result = parser.parse("not-a-valid-sdjwt");
    assert!(result.is_err());
}
