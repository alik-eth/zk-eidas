//! ISO 18013-5 mdoc (mobile document) parser for the zk-eidas pipeline.
//!
//! Converts CBOR-encoded mdoc credential bytes into
//! [`zk_eidas_types::credential::Credential`] values.

use std::collections::BTreeMap;
use thiserror::Error;
use zk_eidas_types::credential::{ClaimValue, Credential, SignatureData};

mod cose;
mod mso;

pub mod test_utils;

/// Errors that can occur when parsing mdoc CBOR data.
#[derive(Debug, Error)]
pub enum MdocError {
    /// The CBOR bytes could not be decoded.
    #[error("CBOR decode error: {0}")]
    CborDecode(String),
    /// The mdoc structure is missing expected fields or has wrong types.
    #[error("invalid mdoc structure: {0}")]
    InvalidStructure(String),
    /// The namespace is not supported by this parser.
    #[error("unsupported namespace: {0}")]
    UnsupportedNamespace(String),
}

/// Parser for ISO 18013-5 mdoc credentials encoded as CBOR.
pub struct MdocParser;

/// Intermediate parsed mdoc structure before building a Credential.
struct ParsedMdoc<'a> {
    issuer_signed_map: &'a [(ciborium::Value, ciborium::Value)],
    ns_map: &'a [(ciborium::Value, ciborium::Value)],
}

/// Navigate CBOR to the issuerSigned and nameSpaces maps.
fn navigate_mdoc(root: &ciborium::Value) -> Result<ParsedMdoc<'_>, MdocError> {
    let root_map = root
        .as_map()
        .ok_or_else(|| MdocError::InvalidStructure("root is not a map".into()))?;

    let documents = find_in_map(root_map, "documents")
        .ok_or_else(|| MdocError::InvalidStructure("missing documents".into()))?;

    let docs_array = documents
        .as_array()
        .ok_or_else(|| MdocError::InvalidStructure("documents is not an array".into()))?;

    let doc = docs_array
        .first()
        .ok_or_else(|| MdocError::InvalidStructure("documents array is empty".into()))?;

    let doc_map = doc
        .as_map()
        .ok_or_else(|| MdocError::InvalidStructure("document is not a map".into()))?;

    let issuer_signed = find_in_map(doc_map, "issuerSigned")
        .ok_or_else(|| MdocError::InvalidStructure("missing issuerSigned".into()))?;

    let issuer_signed_map = issuer_signed
        .as_map()
        .ok_or_else(|| MdocError::InvalidStructure("issuerSigned is not a map".into()))?;

    let name_spaces = find_in_map(issuer_signed_map, "nameSpaces")
        .ok_or_else(|| MdocError::InvalidStructure("missing nameSpaces".into()))?;

    let ns_map = name_spaces
        .as_map()
        .ok_or_else(|| MdocError::InvalidStructure("nameSpaces is not a map".into()))?;

    Ok(ParsedMdoc {
        issuer_signed_map,
        ns_map,
    })
}

/// Extract claims and disclosures from nameSpaces.
#[allow(clippy::type_complexity)]
fn extract_claims_and_disclosures(
    ns_map: &[(ciborium::Value, ciborium::Value)],
) -> Result<(BTreeMap<String, ClaimValue>, BTreeMap<String, Vec<u8>>), MdocError> {
    let mut claims = BTreeMap::new();
    let mut disclosures = BTreeMap::new();

    for (ns_key, ns_val) in ns_map {
        let _ns_name = ns_key
            .as_text()
            .ok_or_else(|| MdocError::InvalidStructure("namespace key is not text".into()))?;

        let items = ns_val
            .as_array()
            .ok_or_else(|| MdocError::InvalidStructure("namespace value is not an array".into()))?;

        for item in items {
            // Items may be Tag(24, bstr(cbor)) per ISO 18013-5 or plain maps.
            let unwrapped_item = unwrap_tag24(item);
            let item_map = unwrapped_item
                .as_map()
                .ok_or_else(|| MdocError::InvalidStructure("item is not a map".into()))?;

            let identifier = find_in_map(item_map, "elementIdentifier")
                .and_then(|v| v.as_text())
                .ok_or_else(|| MdocError::InvalidStructure("missing elementIdentifier".into()))?;

            let value = find_in_map(item_map, "elementValue")
                .ok_or_else(|| MdocError::InvalidStructure("missing elementValue".into()))?;

            let claim_value = cbor_to_claim_value(identifier, value)?;
            claims.insert(identifier.to_string(), claim_value);

            // Re-encode the unwrapped item to get its CBOR bytes for disclosure
            let mut item_cbor = Vec::new();
            ciborium::into_writer(&*unwrapped_item, &mut item_cbor)
                .map_err(|e| MdocError::CborDecode(e.to_string()))?;
            disclosures.insert(identifier.to_string(), item_cbor);
        }
    }

    Ok((claims, disclosures))
}

/// Determine the issuer string from claims.
fn determine_issuer(claims: &BTreeMap<String, ClaimValue>) -> String {
    claims
        .get("issuing_authority")
        .and_then(|v| match v {
            ClaimValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "unknown".to_string())
}

impl MdocParser {
    /// Parse ISO 18013-5 mdoc CBOR bytes into a Credential.
    ///
    /// Signature data is stored as `Opaque` since no issuer public key is
    /// provided. Use [`parse_with_issuer_key`](Self::parse_with_issuer_key) to
    /// get `SignatureData::Ecdsa` for in-circuit verification.
    pub fn parse(mdoc_bytes: &[u8]) -> Result<Credential, MdocError> {
        let root: ciborium::Value =
            ciborium::from_reader(mdoc_bytes).map_err(|e| MdocError::CborDecode(e.to_string()))?;

        let parsed = navigate_mdoc(&root)?;
        let (claims, disclosures) = extract_claims_and_disclosures(parsed.ns_map)?;

        // Extract issuerAuth as opaque bytes
        let signature_data = match find_in_map(parsed.issuer_signed_map, "issuerAuth") {
            Some(auth) => {
                let mut sig_bytes = Vec::new();
                ciborium::into_writer(auth, &mut sig_bytes)
                    .map_err(|e| MdocError::CborDecode(e.to_string()))?;
                SignatureData::Opaque {
                    signature: sig_bytes,
                    public_key: vec![],
                }
            }
            None => SignatureData::Opaque {
                signature: vec![],
                public_key: vec![],
            },
        };

        let issuer = determine_issuer(&claims);

        Ok(Credential::new(claims, issuer, signature_data, disclosures))
    }

    /// Parse mdoc CBOR bytes with a known issuer ECDSA P-256 public key.
    ///
    /// When the issuer's public key is known (e.g., from external certificate
    /// validation), this method produces `SignatureData::Ecdsa` so the existing
    /// signed circuits can verify the COSE signature in-circuit.
    pub fn parse_with_issuer_key(
        mdoc_bytes: &[u8],
        pub_key_x: [u8; 32],
        pub_key_y: [u8; 32],
    ) -> Result<Credential, MdocError> {
        let root: ciborium::Value =
            ciborium::from_reader(mdoc_bytes).map_err(|e| MdocError::CborDecode(e.to_string()))?;

        let parsed = navigate_mdoc(&root)?;
        let (claims, disclosures) = extract_claims_and_disclosures(parsed.ns_map)?;

        // Extract and parse COSE_Sign1 from issuerAuth.
        // issuerAuth can be either:
        //   - CBOR bytes (legacy: coset-serialized tagged COSE_Sign1)
        //   - CBOR Array (ISO 18013-5: inline [protected, unprotected, payload, signature])
        let auth_val = find_in_map(parsed.issuer_signed_map, "issuerAuth")
            .ok_or_else(|| MdocError::InvalidStructure("missing issuerAuth".into()))?;

        let cose_extracted = if let Some(auth_bytes) = auth_val.as_bytes() {
            // Legacy format: opaque COSE_Sign1 bytes
            cose::extract_cose_sign1(auth_bytes)?
        } else if let Some(auth_arr) = auth_val.as_array() {
            // ISO 18013-5 format: inline COSE_Sign1 array
            cose::extract_cose_sign1_from_array(auth_arr)?
        } else {
            return Err(MdocError::InvalidStructure(
                "issuerAuth is neither bytes nor array".into(),
            ));
        };

        // Parse MSO from COSE payload
        let mso = mso::parse_mso(&cose_extracted.payload)?;

        // Build sd_claims_hashes from ValueDigests (sorted by digestID)
        let sd_claims_hashes: Vec<[u8; 32]> = mso.value_digests.values().copied().collect();

        // Build signature — must be exactly 64 bytes (r || s)
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&cose_extracted.signature);

        let signature_data = SignatureData::Ecdsa {
            pub_key_x,
            pub_key_y,
            signature,
            message_hash: cose_extracted.message_hash,
            sd_claims_hashes,
        };

        let issuer = determine_issuer(&claims);

        Ok(Credential::new(claims, issuer, signature_data, disclosures))
    }
}

/// Unwrap a CBOR Tag(24, bstr(inner_cbor)) to the decoded inner value.
/// If the value is not Tag(24, bytes), returns it as-is.
fn unwrap_tag24(val: &ciborium::Value) -> std::borrow::Cow<'_, ciborium::Value> {
    if let ciborium::Value::Tag(24, inner) = val {
        if let Some(bytes) = inner.as_bytes() {
            if let Ok(decoded) = ciborium::from_reader::<ciborium::Value, _>(bytes.as_slice()) {
                return std::borrow::Cow::Owned(decoded);
            }
        }
    }
    std::borrow::Cow::Borrowed(val)
}

/// Find a value by text key in a CBOR map.
pub(crate) fn find_in_map<'a>(
    map: &'a [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'a ciborium::Value> {
    map.iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

/// Convert a ciborium Value to a ClaimValue based on the element identifier.
fn cbor_to_claim_value(identifier: &str, value: &ciborium::Value) -> Result<ClaimValue, MdocError> {
    // Handle CBOR Tag 1004 (fulldate) — ISO 18013-5 date encoding
    if let ciborium::Value::Tag(1004, inner) = value {
        if let Some(text) = inner.as_text() {
            return parse_date(text);
        }
    }

    // birth_date is always a date (strict)
    if identifier == "birth_date" {
        let text = value
            .as_text()
            .ok_or_else(|| MdocError::InvalidStructure("birth_date is not a string".into()))?;
        return parse_date(text);
    }

    // Other date-like fields: try date parse, fall back to string
    if identifier.ends_with("_date") || identifier.ends_with("_expiry") {
        if let Some(text) = value.as_text() {
            if let Ok(date) = parse_date(text) {
                return Ok(date);
            }
        }
    }

    if let Some(s) = value.as_text() {
        return Ok(ClaimValue::String(s.to_string()));
    }
    if let Some(i) = value.as_integer() {
        let n: i128 = i.into();
        let n_i64 = i64::try_from(n).map_err(|_| {
            MdocError::InvalidStructure(format!(
                "integer value {n} for element '{identifier}' overflows i64"
            ))
        })?;
        return Ok(ClaimValue::Integer(n_i64));
    }
    if let Some(b) = value.as_bool() {
        return Ok(ClaimValue::Boolean(b));
    }

    Err(MdocError::InvalidStructure(format!(
        "unsupported value type for element '{identifier}'"
    )))
}

/// Parse a "YYYY-MM-DD" string into ClaimValue::Date.
fn parse_date(s: &str) -> Result<ClaimValue, MdocError> {
    ClaimValue::from_date_str(s)
        .map_err(|e| MdocError::InvalidStructure(format!("invalid date '{s}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_mdoc() -> Vec<u8> {
        use ciborium::Value;

        let item1 = Value::Map(vec![
            (
                Value::Text("elementIdentifier".into()),
                Value::Text("given_name".into()),
            ),
            (
                Value::Text("elementValue".into()),
                Value::Text("Олександр".into()),
            ),
        ]);
        let item2 = Value::Map(vec![
            (
                Value::Text("elementIdentifier".into()),
                Value::Text("birth_date".into()),
            ),
            (
                Value::Text("elementValue".into()),
                Value::Text("1998-05-14".into()),
            ),
        ]);

        let doc = Value::Map(vec![(
            Value::Text("issuerSigned".into()),
            Value::Map(vec![(
                Value::Text("nameSpaces".into()),
                Value::Map(vec![(
                    Value::Text("org.iso.18013.5.1".into()),
                    Value::Array(vec![item1, item2]),
                )]),
            )]),
        )]);

        let root = Value::Map(vec![(
            Value::Text("documents".into()),
            Value::Array(vec![doc]),
        )]);

        let mut buf = Vec::new();
        ciborium::into_writer(&root, &mut buf).unwrap();
        buf
    }

    #[test]
    fn parse_synthetic_mdoc() {
        let bytes = build_test_mdoc();
        let cred = MdocParser::parse(&bytes).unwrap();
        assert_eq!(
            cred.claims().get("given_name"),
            Some(&ClaimValue::String("Олександр".into()))
        );
        assert_eq!(
            cred.claims().get("birth_date"),
            Some(&ClaimValue::Date {
                year: 1998,
                month: 5,
                day: 14
            })
        );
    }

    #[test]
    fn parse_empty_bytes_returns_error() {
        let err = MdocParser::parse(&[]).unwrap_err();
        assert!(matches!(err, MdocError::CborDecode(_)));
    }

    #[test]
    fn parse_invalid_cbor_returns_error() {
        let err = MdocParser::parse(&[0xFF, 0xFF, 0xFF]).unwrap_err();
        assert!(matches!(err, MdocError::CborDecode(_)));
    }

    #[test]
    fn parse_missing_documents_returns_error() {
        use ciborium::Value;
        let root = Value::Map(vec![(Value::Text("other".into()), Value::Array(vec![]))]);
        let mut buf = Vec::new();
        ciborium::into_writer(&root, &mut buf).unwrap();

        let err = MdocParser::parse(&buf).unwrap_err();
        assert!(matches!(err, MdocError::InvalidStructure(_)));
    }

    #[test]
    fn parse_empty_documents_array_returns_error() {
        use ciborium::Value;
        let root = Value::Map(vec![(
            Value::Text("documents".into()),
            Value::Array(vec![]),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&root, &mut buf).unwrap();

        let err = MdocParser::parse(&buf).unwrap_err();
        assert!(matches!(err, MdocError::InvalidStructure(_)));
    }

    /// Helper to build an mdoc with a single claim in a single namespace.
    fn build_single_claim_mdoc(identifier: &str, value: ciborium::Value) -> Vec<u8> {
        use ciborium::Value;
        let item = Value::Map(vec![
            (
                Value::Text("elementIdentifier".into()),
                Value::Text(identifier.into()),
            ),
            (Value::Text("elementValue".into()), value),
        ]);
        let doc = Value::Map(vec![(
            Value::Text("issuerSigned".into()),
            Value::Map(vec![(
                Value::Text("nameSpaces".into()),
                Value::Map(vec![(Value::Text("ns".into()), Value::Array(vec![item]))]),
            )]),
        )]);
        let root = Value::Map(vec![(
            Value::Text("documents".into()),
            Value::Array(vec![doc]),
        )]);
        let mut buf = Vec::new();
        ciborium::into_writer(&root, &mut buf).unwrap();
        buf
    }

    #[test]
    fn parse_integer_overflow_returns_error() {
        // u64::MAX > i64::MAX, so converting to i64 would silently wrap
        let overflow_val: u64 = (i64::MAX as u64) + 1;
        let bytes =
            build_single_claim_mdoc("big", ciborium::Value::Integer(overflow_val.into()));
        let result = MdocParser::parse(&bytes);
        assert!(result.is_err(), "integer > i64::MAX should return MdocError");
        assert!(matches!(result.unwrap_err(), MdocError::InvalidStructure(_)));
    }

    #[test]
    fn parse_integer_claim() {
        let bytes = build_single_claim_mdoc("age", ciborium::Value::Integer(25.into()));
        let cred = MdocParser::parse(&bytes).unwrap();
        assert_eq!(cred.claims().get("age"), Some(&ClaimValue::Integer(25)));
    }

    #[test]
    fn parse_boolean_claim() {
        let bytes = build_single_claim_mdoc("active", ciborium::Value::Bool(true));
        let cred = MdocParser::parse(&bytes).unwrap();
        assert_eq!(
            cred.claims().get("active"),
            Some(&ClaimValue::Boolean(true))
        );
    }

    #[test]
    fn parse_invalid_date_format() {
        let bytes =
            build_single_claim_mdoc("birth_date", ciborium::Value::Text("not-a-date".into()));
        let err = MdocParser::parse(&bytes).unwrap_err();
        assert!(matches!(err, MdocError::InvalidStructure(_)));
    }

    #[test]
    fn parse_issuer_from_issuing_authority_claim() {
        let bytes =
            build_single_claim_mdoc("issuing_authority", ciborium::Value::Text("DIIA".into()));
        let cred = MdocParser::parse(&bytes).unwrap();
        assert_eq!(cred.issuer(), "DIIA");
    }

    #[test]
    fn parse_missing_issuer_defaults_to_unknown() {
        let bytes = build_test_mdoc();
        let cred = MdocParser::parse(&bytes).unwrap();
        assert_eq!(cred.issuer(), "unknown");
    }

    #[test]
    fn parse_mdoc_with_cose_sign1_extracts_ecdsa() {
        let (mdoc_bytes, pub_key_x, pub_key_y) = crate::test_utils::build_ecdsa_signed_mdoc(
            vec![("given_name", ClaimValue::String("Test".into()))],
            "test-issuer",
        );

        let cred = MdocParser::parse_with_issuer_key(&mdoc_bytes, pub_key_x, pub_key_y).unwrap();

        assert!(cred.signature_data().is_ecdsa());
        assert!(!cred.disclosures().is_empty());
        assert_eq!(
            cred.claims().get("given_name"),
            Some(&ClaimValue::String("Test".into()))
        );
    }

    #[test]
    fn parse_without_key_still_works() {
        let bytes = build_test_mdoc();
        let cred = MdocParser::parse(&bytes).unwrap();
        assert!(!cred.signature_data().is_ecdsa());
    }

    #[test]
    fn parse_extracts_disclosures() {
        let (mdoc_bytes, pub_key_x, pub_key_y) = crate::test_utils::build_ecdsa_signed_mdoc(
            vec![
                ("age", ClaimValue::Integer(25)),
                ("given_name", ClaimValue::String("Alice".into())),
            ],
            "test-issuer",
        );

        let cred = MdocParser::parse_with_issuer_key(&mdoc_bytes, pub_key_x, pub_key_y).unwrap();

        assert_eq!(cred.disclosures().len(), 2);
        assert!(cred.disclosures().contains_key("age"));
        assert!(cred.disclosures().contains_key("given_name"));
    }

    /// Verify the byte-level CBOR structure matches Longfellow's C++ parser expectations.
    #[test]
    fn longfellow_compatible_structure() {
        use ciborium::Value;

        let (mdoc_bytes, _pkx, _pky) = crate::test_utils::build_ecdsa_signed_mdoc(
            vec![
                ("given_name", ClaimValue::String("Alice".into())),
                ("age_over_18", ClaimValue::Boolean(true)),
            ],
            "test-issuer",
        );

        let root: Value = ciborium::from_reader(mdoc_bytes.as_slice()).unwrap();

        // Navigate: root -> documents[0]
        let docs = root.as_map().unwrap().iter()
            .find(|(k, _)| k.as_text() == Some("documents")).unwrap().1
            .as_array().unwrap();
        let doc = docs[0].as_map().unwrap();

        // docType must be present
        let doc_type = doc.iter().find(|(k, _)| k.as_text() == Some("docType"))
            .unwrap().1.as_text().unwrap();
        assert_eq!(doc_type, "org.iso.18013.5.1.mDL");

        // issuerSigned -> issuerAuth must be a 4-element array
        let issuer_signed = doc.iter().find(|(k, _)| k.as_text() == Some("issuerSigned"))
            .unwrap().1.as_map().unwrap();
        let issuer_auth = issuer_signed.iter().find(|(k, _)| k.as_text() == Some("issuerAuth"))
            .unwrap().1.as_array().unwrap();
        assert_eq!(issuer_auth.len(), 4, "issuerAuth must be a 4-element COSE_Sign1 array");

        // issuerAuth[0] = protected header bytes
        assert!(issuer_auth[0].as_bytes().is_some());
        // issuerAuth[1] = unprotected header (empty map)
        assert!(issuer_auth[1].as_map().is_some());
        // issuerAuth[2] = payload bytes (Tag-24 wrapped MSO)
        let payload = issuer_auth[2].as_bytes().unwrap();
        assert_eq!(payload[0], 0xD8, "MSO must start with Tag major type");
        assert_eq!(payload[1], 0x18, "Tag number must be 24");
        assert_eq!(payload[2], 0x59, "MSO bstr must use 2-byte length (59)");
        // issuerAuth[3] = signature (64 bytes for ES256)
        assert_eq!(issuer_auth[3].as_bytes().unwrap().len(), 64);

        // nameSpaces items must be Tag(24, bstr)
        let ns = issuer_signed.iter().find(|(k, _)| k.as_text() == Some("nameSpaces"))
            .unwrap().1.as_map().unwrap();
        let items = ns.iter().find(|(k, _)| k.as_text() == Some("org.iso.18013.5.1"))
            .unwrap().1.as_array().unwrap();
        assert_eq!(items.len(), 2);
        for item in items {
            assert!(matches!(item, Value::Tag(24, _)), "each item must be Tag(24, ...)");
        }

        // deviceSigned -> deviceAuth -> deviceSignature must be a 4-element array
        let device_signed = doc.iter().find(|(k, _)| k.as_text() == Some("deviceSigned"))
            .unwrap().1.as_map().unwrap();
        let device_auth = device_signed.iter().find(|(k, _)| k.as_text() == Some("deviceAuth"))
            .unwrap().1.as_map().unwrap();
        let device_sig = device_auth.iter().find(|(k, _)| k.as_text() == Some("deviceSignature"))
            .unwrap().1.as_array().unwrap();
        assert_eq!(device_sig.len(), 4, "deviceSignature must be a 4-element COSE_Sign1 array");
        assert_eq!(device_sig[3].as_bytes().unwrap().len(), 64);

        // Verify MSO inner structure
        let mso_len = ((payload[3] as usize) << 8) | (payload[4] as usize);
        let mso_bytes = &payload[5..5 + mso_len];
        let mso: Value = ciborium::from_reader(mso_bytes).unwrap();
        let mso_map = mso.as_map().unwrap();

        // Check MSO has all required fields
        let field_names: Vec<&str> = mso_map.iter()
            .filter_map(|(k, _)| k.as_text()).collect();
        assert!(field_names.contains(&"version"));
        assert!(field_names.contains(&"digestAlgorithm"));
        assert!(field_names.contains(&"validityInfo"));
        assert!(field_names.contains(&"deviceKeyInfo"));
        assert!(field_names.contains(&"valueDigests"));

        // Check valueDigests has 2 entries
        let vd = mso_map.iter().find(|(k, _)| k.as_text() == Some("valueDigests"))
            .unwrap().1.as_map().unwrap();
        let org_digests = vd.iter().find(|(k, _)| k.as_text() == Some("org.iso.18013.5.1"))
            .unwrap().1.as_map().unwrap();
        assert_eq!(org_digests.len(), 2);
    }
}
