use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zk_eidas_types::credential::{Credential, SignatureData};

use crate::claims::json_to_claim_value;

/// Errors that can occur when parsing an SD-JWT credential.
#[derive(Debug, Error)]
pub enum ParseError {
    /// The SD-JWT string does not have the expected structure.
    #[error("invalid SD-JWT format")]
    InvalidFormat,
    /// A base64url segment could not be decoded.
    #[error("base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    /// A JSON payload or disclosure could not be parsed.
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    /// A required JWT claim (e.g. `iss`) is missing from the payload.
    #[error("missing required field: {0}")]
    MissingField(String),
}

/// Parser for SD-JWT Verifiable Credentials (SD-JWT VC).
pub struct SdJwtParser;

impl SdJwtParser {
    /// Create a new parser instance.
    pub fn new() -> Self {
        Self
    }

    /// Parse an SD-JWT with a known issuer ECDSA P-256 public key.
    ///
    /// Uses the provided key instead of `cnf.jwk` (which per spec is the
    /// holder's key-binding key, not the issuer's signing key).
    pub fn parse_with_issuer_key(
        &self,
        sdjwt: &str,
        pub_key_x: [u8; 32],
        pub_key_y: [u8; 32],
    ) -> Result<Credential, ParseError> {
        self.parse_internal(sdjwt, Some((pub_key_x, pub_key_y)))
    }

    /// Parse an SD-JWT string into a [`Credential`] with claims, signature data, and disclosures.
    ///
    /// Falls back to `cnf.jwk` for the public key if present (suitable for demos).
    pub fn parse(&self, sdjwt: &str) -> Result<Credential, ParseError> {
        self.parse_internal(sdjwt, None)
    }

    fn parse_internal(
        &self,
        sdjwt: &str,
        issuer_key: Option<([u8; 32], [u8; 32])>,
    ) -> Result<Credential, ParseError> {
        // Split on '~' — first part is the JWT, rest are disclosures
        let parts: Vec<&str> = sdjwt.split('~').collect();
        if parts.is_empty() {
            return Err(ParseError::InvalidFormat);
        }

        let jwt = parts[0];
        let disclosure_parts: Vec<&str> = parts[1..]
            .iter()
            .copied()
            .filter(|s| !s.is_empty())
            .collect();

        // Split JWT on '.' — must have 3 segments
        let jwt_segments: Vec<&str> = jwt.split('.').collect();
        if jwt_segments.len() != 3 {
            return Err(ParseError::InvalidFormat);
        }

        // Decode payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(jwt_segments[1])?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

        // Extract issuer
        let issuer = payload
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ParseError::MissingField("iss".to_string()))?
            .to_string();

        // Decode signature
        let signature = URL_SAFE_NO_PAD.decode(jwt_segments[2])?;

        // Compute message hash (SHA-256 of the JWS signing input)
        let signing_input = format!("{}.{}", jwt_segments[0], jwt_segments[1]);
        let message_hash: [u8; 32] = Sha256::digest(signing_input.as_bytes()).into();

        // Extract _sd hashes from payload
        let sd_claims_hashes: Vec<[u8; 32]> = payload
            .get("_sd")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        let b64 = v.as_str()?;
                        let bytes = URL_SAFE_NO_PAD.decode(b64).ok()?;
                        <[u8; 32]>::try_from(bytes.as_slice()).ok()
                    })
                    .collect()
            })
            .unwrap_or_default();

        let mut claims = BTreeMap::new();
        let mut disclosures = BTreeMap::new();

        // Process disclosures
        for disclosure in &disclosure_parts {
            let decoded = URL_SAFE_NO_PAD.decode(disclosure)?;
            let arr: serde_json::Value = serde_json::from_slice(&decoded)?;
            let arr = arr.as_array().ok_or(ParseError::InvalidFormat)?;
            if arr.len() != 3 {
                return Err(ParseError::InvalidFormat);
            }
            let name = arr[1].as_str().ok_or(ParseError::InvalidFormat)?;
            if let Some(cv) = json_to_claim_value(&arr[2]) {
                claims.insert(name.to_string(), cv);
            }
            // Save raw disclosure bytes for signed circuits
            disclosures.insert(name.to_string(), disclosure.as_bytes().to_vec());
        }

        // Extract non-disclosed claims from payload
        let skip_keys = ["_sd", "_sd_alg", "cnf", "iss", "iat", "exp", "vct"];
        if let Some(obj) = payload.as_object() {
            for (key, value) in obj {
                if skip_keys.contains(&key.as_str()) {
                    continue;
                }
                if !claims.contains_key(key) {
                    if let Some(cv) = json_to_claim_value(value) {
                        claims.insert(key.clone(), cv);
                    }
                }
            }
        }

        // Build SignatureData
        // Prefer explicitly provided issuer key; fall back to cnf.jwk for demos
        let signature_data = if let Some((ik_x, ik_y)) = issuer_key {
            if signature.len() != 64 {
                return Err(ParseError::InvalidFormat);
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&signature);
            SignatureData::Ecdsa {
                pub_key_x: ik_x,
                pub_key_y: ik_y,
                signature: sig,
                message_hash,
                sd_claims_hashes,
            }
        } else if let Some(jwk) = payload.get("cnf").and_then(|cnf| cnf.get("jwk")) {
            let x_bytes = jwk
                .get("x")
                .and_then(|v| v.as_str())
                .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok());
            let y_bytes = jwk
                .get("y")
                .and_then(|v| v.as_str())
                .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok());

            match (x_bytes, y_bytes) {
                (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => {
                    if signature.len() != 64 {
                        return Err(ParseError::InvalidFormat);
                    }
                    let mut pub_key_x = [0u8; 32];
                    let mut pub_key_y = [0u8; 32];
                    pub_key_x.copy_from_slice(&x);
                    pub_key_y.copy_from_slice(&y);

                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&signature);

                    SignatureData::Ecdsa {
                        pub_key_x,
                        pub_key_y,
                        signature: sig,
                        message_hash,
                        sd_claims_hashes,
                    }
                }
                _ => SignatureData::Opaque {
                    signature: signature.clone(),
                    public_key: vec![],
                },
            }
        } else {
            SignatureData::Opaque {
                signature: signature.clone(),
                public_key: vec![],
            }
        };

        Ok(Credential::new(claims, issuer, signature_data, disclosures))
    }
}

impl Default for SdJwtParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{build_ecdsa_signed_sdjwt, build_synthetic_sdjwt};
    use zk_eidas_types::credential::ClaimValue;

    #[test]
    fn parse_empty_string_returns_error() {
        let parser = SdJwtParser::new();
        assert!(parser.parse("").is_err());
    }

    #[test]
    fn parse_no_dots_returns_invalid_format() {
        let parser = SdJwtParser::new();
        let err = parser.parse("nodots").unwrap_err();
        assert!(matches!(err, ParseError::InvalidFormat));
    }

    #[test]
    fn parse_missing_issuer_returns_error() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"test"}"#.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(&[0u8; 64]);
        let jwt = format!("{header}.{payload}.{sig}");

        let parser = SdJwtParser::new();
        let err = parser.parse(&jwt).unwrap_err();
        assert!(matches!(err, ParseError::MissingField(_)));
    }

    #[test]
    fn parse_invalid_base64_returns_error() {
        let parser = SdJwtParser::new();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#.as_bytes());
        let jwt = format!("{header}.!!!invalid!!!.sig");
        assert!(parser.parse(&jwt).is_err());
    }

    #[test]
    fn parse_invalid_json_payload_returns_error() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(b"not json");
        let sig = URL_SAFE_NO_PAD.encode(&[0u8; 64]);
        let jwt = format!("{header}.{payload}.{sig}");

        let parser = SdJwtParser::new();
        let err = parser.parse(&jwt).unwrap_err();
        assert!(matches!(err, ParseError::JsonError(_)));
    }

    #[test]
    fn parse_invalid_disclosure_format_returns_error() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(r#"{"iss":"test"}"#.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(&[0u8; 64]);
        let bad_disclosure = URL_SAFE_NO_PAD.encode(r#"["salt","key"]"#.as_bytes());
        let jwt = format!("{header}.{payload}.{sig}~{bad_disclosure}");

        let parser = SdJwtParser::new();
        let err = parser.parse(&jwt).unwrap_err();
        assert!(matches!(err, ParseError::InvalidFormat));
    }

    #[test]
    fn parse_opaque_signature_when_no_cnf() {
        let claims = serde_json::json!({ "age": 30 });
        let sdjwt = build_synthetic_sdjwt(claims, "test-issuer");

        let parser = SdJwtParser::new();
        let cred = parser.parse(&sdjwt).unwrap();
        assert!(!cred.signature_data().is_ecdsa());
    }

    #[test]
    fn parse_date_claim_from_disclosure() {
        let claims = serde_json::json!({ "birthdate": "1990-05-15" });
        let sdjwt = build_synthetic_sdjwt(claims, "test");

        let parser = SdJwtParser::new();
        let cred = parser.parse(&sdjwt).unwrap();
        let birthdate = cred
            .claims()
            .get("birthdate")
            .expect("birthdate claim missing");
        assert_eq!(
            *birthdate,
            ClaimValue::Date {
                year: 1990,
                month: 5,
                day: 15,
            }
        );
    }

    #[test]
    fn parse_non_disclosed_payload_claims() {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#.as_bytes());
        let payload =
            URL_SAFE_NO_PAD.encode(r#"{"iss":"test","status":"active","level":5}"#.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(&[0u8; 64]);
        let jwt = format!("{header}.{payload}.{sig}");

        let parser = SdJwtParser::new();
        let cred = parser.parse(&jwt).unwrap();
        assert_eq!(
            *cred.claims().get("status").expect("status missing"),
            ClaimValue::String("active".to_string())
        );
        assert_eq!(
            *cred.claims().get("level").expect("level missing"),
            ClaimValue::Integer(5)
        );
    }

    #[test]
    fn parse_rejects_wrong_signature_length() {
        // Build a JWT where cnf.jwk exists (triggering ECDSA path) but signature is 32 bytes
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#.as_bytes());
        let payload_json = serde_json::json!({
            "iss": "test",
            "cnf": { "jwk": { "kty": "EC", "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode([1u8; 32]),
                "y": URL_SAFE_NO_PAD.encode([2u8; 32])
            }}
        });
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_string(&payload_json).unwrap().as_bytes(),
        );
        let sig = URL_SAFE_NO_PAD.encode(&[0u8; 32]); // Wrong length!
        let jwt = format!("{header}.{payload}.{sig}");

        let parser = SdJwtParser::new();
        let err = parser.parse(&jwt).unwrap_err();
        match err {
            ParseError::InvalidFormat => {}
            _ => panic!("expected InvalidFormat for wrong signature length, got: {err:?}"),
        }
    }

    #[test]
    fn parse_ecdsa_signed_sdjwt() {
        let claims = serde_json::json!({
            "age": 25,
            "name": "Alice",
        });
        let (sdjwt, _key) = build_ecdsa_signed_sdjwt(claims, "https://issuer.example.com");

        let parser = SdJwtParser::new();
        let cred = parser.parse(&sdjwt).unwrap();

        assert_eq!(cred.issuer(), "https://issuer.example.com");
        assert!(cred.signature_data().is_ecdsa());
        assert!(cred.disclosures().contains_key("age"));
        assert!(cred.disclosures().contains_key("name"));

        match cred.signature_data() {
            zk_eidas_types::credential::SignatureData::Ecdsa {
                pub_key_x,
                pub_key_y,
                signature,
                message_hash,
                sd_claims_hashes,
            } => {
                assert_ne!(*pub_key_x, [0u8; 32]);
                assert_ne!(*pub_key_y, [0u8; 32]);
                assert_ne!(*signature, [0u8; 64]);
                assert_ne!(*message_hash, [0u8; 32]);
                assert_eq!(sd_claims_hashes.len(), 2);
            }
            _ => panic!("expected Ecdsa"),
        }
    }

    #[test]
    fn parse_with_issuer_key_uses_provided_key() {
        let claims = serde_json::json!({ "age": 25 });
        let (sdjwt, key_bytes) = build_ecdsa_signed_sdjwt(claims, "issuer");

        // Extract the public key from the signing key
        use p256::ecdsa::SigningKey;
        let sk = SigningKey::from_bytes(key_bytes.as_slice().into()).unwrap();
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let mut issuer_x = [0u8; 32];
        let mut issuer_y = [0u8; 32];
        issuer_x.copy_from_slice(point.x().unwrap().as_slice());
        issuer_y.copy_from_slice(point.y().unwrap().as_slice());

        let parser = SdJwtParser::new();
        let cred = parser
            .parse_with_issuer_key(&sdjwt, issuer_x, issuer_y)
            .unwrap();

        assert!(cred.signature_data().is_ecdsa());
        match cred.signature_data() {
            SignatureData::Ecdsa { pub_key_x, pub_key_y, .. } => {
                assert_eq!(pub_key_x, &issuer_x, "should use provided issuer key, not cnf.jwk");
                assert_eq!(pub_key_y, &issuer_y);
            }
            _ => panic!("expected Ecdsa"),
        }
    }
}
