use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A typed claim value extracted from a credential.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClaimValue {
    /// Signed 64-bit integer.
    Integer(i64),
    /// UTF-8 string.
    String(String),
    /// Boolean flag.
    Boolean(bool),
    /// Calendar date (ISO 8601).
    Date {
        /// Year (e.g. 1998).
        year: u16,
        /// Month (1--12).
        month: u8,
        /// Day (1--31).
        day: u8,
    },
}

impl ClaimValue {
    /// Create a validated `Date` claim value.
    ///
    /// Returns an error if month is not in 1..=12 or day exceeds the maximum
    /// for the given month (28/29 for Feb depending on leap year, 30 or 31
    /// for other months).
    pub fn date(year: u16, month: u8, day: u8) -> Result<Self, &'static str> {
        if month < 1 || month > 12 {
            return Err("month must be between 1 and 12");
        }
        let max_day = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                let y = year as u32;
                if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 {
                    29
                } else {
                    28
                }
            }
            _ => unreachable!(),
        };
        if day < 1 || day > max_day {
            return Err("day is out of range for the given month");
        }
        Ok(ClaimValue::Date { year, month, day })
    }

    /// Convert claim value to a byte vector suitable for circuit witness.
    /// Integers/booleans/dates -> 8 bytes (u64 big-endian).
    /// Strings -> 32 bytes (SHA-256 hash).
    ///
    /// Returns an error for negative integers (unsigned field elements only).
    pub fn to_field_element(&self) -> Result<Vec<u8>, FieldElementError> {
        match self {
            ClaimValue::Integer(n) => {
                if *n < 0 {
                    return Err(FieldElementError::NegativeInteger(*n));
                }
                Ok((*n as u64).to_be_bytes().to_vec())
            }
            ClaimValue::Boolean(b) => Ok((*b as u64).to_be_bytes().to_vec()),
            ClaimValue::Date { year, month, day } => {
                let days =
                    zk_eidas_utils::date_to_epoch_days(*year as u32, *month as u32, *day as u32);
                // Circuits use unsigned values; clamp negative epoch days to 0
                let unsigned_days = days.max(0) as u64;
                Ok(unsigned_days.to_be_bytes().to_vec())
            }
            ClaimValue::String(s) => {
                use sha2::{Digest, Sha256};
                let hash = Sha256::digest(s.as_bytes());
                Ok(hash.to_vec())
            }
        }
    }
}

/// Error converting a claim value to a field element.
#[derive(Debug, thiserror::Error)]
pub enum FieldElementError {
    /// Negative integers cannot be represented as unsigned field elements.
    #[error("negative integer {0} cannot be converted to field element")]
    NegativeInteger(i64),
}

/// Signature data attached to a credential. Scheme-agnostic via enum variants.
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureData {
    /// ECDSA secp256r1 (ES256) — used by eIDAS SD-JWT VCs.
    Ecdsa {
        pub_key_x: [u8; 32],
        pub_key_y: [u8; 32],
        signature: [u8; 64],
        message_hash: [u8; 32],
        sd_claims_hashes: Vec<[u8; 32]>,
    },
    /// Opaque signature for unsupported or future schemes.
    Opaque {
        signature: Vec<u8>,
        public_key: Vec<u8>,
    },
}

impl SignatureData {
    /// Returns `true` if this is an ECDSA signature.
    pub fn is_ecdsa(&self) -> bool {
        matches!(self, SignatureData::Ecdsa { .. })
    }
}

/// A parsed credential with claims, issuer identity, signature data, and raw disclosures.
#[derive(Debug, Clone, PartialEq)]
pub struct Credential {
    claims: BTreeMap<String, ClaimValue>,
    issuer: String,
    signature_data: SignatureData,
    disclosures: BTreeMap<String, Vec<u8>>,
}

impl Credential {
    /// Create a new credential from its constituent parts.
    pub fn new(
        claims: BTreeMap<String, ClaimValue>,
        issuer: String,
        signature_data: SignatureData,
        disclosures: BTreeMap<String, Vec<u8>>,
    ) -> Self {
        Self {
            claims,
            issuer,
            signature_data,
            disclosures,
        }
    }
    /// Returns the map of claim names to typed values.
    pub fn claims(&self) -> &BTreeMap<String, ClaimValue> {
        &self.claims
    }
    /// Returns the issuer identifier string.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    /// Returns the signature data (ECDSA or opaque).
    pub fn signature_data(&self) -> &SignatureData {
        &self.signature_data
    }
    /// Returns the raw SD-JWT disclosure bytes, keyed by claim name.
    pub fn disclosures(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.disclosures
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn credential_with_ecdsa_signature_data() {
        let mut claims = BTreeMap::new();
        claims.insert("age".to_string(), ClaimValue::Integer(25));

        let sig_data = SignatureData::Ecdsa {
            pub_key_x: [1u8; 32],
            pub_key_y: [2u8; 32],
            signature: [3u8; 64],
            message_hash: [4u8; 32],
            sd_claims_hashes: vec![[5u8; 32]],
        };

        let mut disclosures = BTreeMap::new();
        disclosures.insert("age".to_string(), b"test_disclosure".to_vec());

        let cred = Credential::new(
            claims.clone(),
            "issuer".to_string(),
            sig_data.clone(),
            disclosures.clone(),
        );

        assert_eq!(cred.claims(), &claims);
        assert_eq!(cred.issuer(), "issuer");
        assert_eq!(cred.disclosures(), &disclosures);
        match cred.signature_data() {
            SignatureData::Ecdsa { pub_key_x, .. } => assert_eq!(*pub_key_x, [1u8; 32]),
            _ => panic!("expected Ecdsa"),
        }
    }

    #[test]
    fn credential_with_opaque_signature_data() {
        let sig_data = SignatureData::Opaque {
            signature: vec![0u8; 64],
            public_key: vec![0u8; 64],
        };
        let cred = Credential::new(
            BTreeMap::new(),
            "issuer".to_string(),
            sig_data,
            BTreeMap::new(),
        );
        assert!(matches!(
            cred.signature_data(),
            SignatureData::Opaque { .. }
        ));
    }

    #[test]
    fn signature_data_is_ecdsa() {
        let ecdsa = SignatureData::Ecdsa {
            pub_key_x: [0u8; 32],
            pub_key_y: [0u8; 32],
            signature: [0u8; 64],
            message_hash: [0u8; 32],
            sd_claims_hashes: vec![],
        };
        assert!(ecdsa.is_ecdsa());

        let opaque = SignatureData::Opaque {
            signature: vec![],
            public_key: vec![],
        };
        assert!(!opaque.is_ecdsa());
    }

    #[test]
    fn date_constructor_valid() {
        let d = ClaimValue::date(2000, 6, 15).unwrap();
        assert_eq!(d, ClaimValue::Date { year: 2000, month: 6, day: 15 });
    }

    #[test]
    fn date_constructor_invalid_month_13() {
        assert!(ClaimValue::date(2000, 13, 1).is_err());
    }

    #[test]
    fn date_constructor_invalid_day_32() {
        assert!(ClaimValue::date(2000, 1, 32).is_err());
    }

    #[test]
    fn date_constructor_zero_month() {
        assert!(ClaimValue::date(2000, 0, 1).is_err());
    }

    #[test]
    fn date_constructor_zero_day() {
        assert!(ClaimValue::date(2000, 1, 0).is_err());
    }

    #[test]
    fn date_constructor_feb_29_leap_year() {
        assert!(ClaimValue::date(2000, 2, 29).is_ok());
        assert!(ClaimValue::date(2024, 2, 29).is_ok());
    }

    #[test]
    fn date_constructor_feb_29_non_leap_year() {
        assert!(ClaimValue::date(2023, 2, 29).is_err());
        assert!(ClaimValue::date(1900, 2, 29).is_err());
    }

    #[test]
    fn date_constructor_feb_31_always_invalid() {
        assert!(ClaimValue::date(2000, 2, 31).is_err());
    }

    #[test]
    fn date_constructor_apr_31_invalid() {
        assert!(ClaimValue::date(2000, 4, 31).is_err());
        assert!(ClaimValue::date(2000, 4, 30).is_ok());
    }

    #[test]
    fn to_field_element_negative_integer_returns_error() {
        let cv = ClaimValue::Integer(-5);
        let result = cv.to_field_element();
        assert!(result.is_err(), "negative integer should return Err, not panic");
    }

    #[test]
    fn to_field_element_positive_integer_returns_ok() {
        let cv = ClaimValue::Integer(42);
        let result = cv.to_field_element();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42u64.to_be_bytes().to_vec());
    }

    #[test]
    fn to_field_element_zero_returns_ok() {
        let cv = ClaimValue::Integer(0);
        assert!(cv.to_field_element().is_ok());
    }
}
