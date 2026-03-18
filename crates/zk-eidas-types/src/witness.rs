use crate::credential::{Credential, SignatureData};
use crate::predicate::Predicate;

/// Circuit witness data derived from a credential and predicate.
#[derive(Debug, Clone, PartialEq)]
pub struct Witness {
    claim_field: Vec<u8>,
    threshold_field: Vec<u8>,
    signature_data: SignatureData,
}

impl Witness {
    /// Build a witness from a credential and predicate, extracting the claim field element.
    pub fn from_credential_and_predicate(
        credential: &Credential,
        predicate: &Predicate,
    ) -> Result<Self, WitnessError> {
        let claim_value = credential
            .claims()
            .get(predicate.claim_name())
            .ok_or_else(|| WitnessError::ClaimNotFound(predicate.claim_name().to_string()))?;
        Ok(Self {
            claim_field: claim_value
                .to_field_element()
                .map_err(|e| WitnessError::FieldElement(e.to_string()))?,
            threshold_field: predicate
                .threshold_field()
                .map_err(|e| WitnessError::FieldElement(e.to_string()))?,
            signature_data: credential.signature_data().clone(),
        })
    }
    /// Returns the claim value as a field element byte slice.
    pub fn claim_field(&self) -> &[u8] {
        &self.claim_field
    }
    /// Returns the threshold value as a field element byte slice.
    pub fn threshold_field(&self) -> &[u8] {
        &self.threshold_field
    }
    /// Returns the credential's signature data.
    pub fn signature_data(&self) -> &SignatureData {
        &self.signature_data
    }
}

/// Error type for witness construction failures.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    /// The requested claim was not present in the credential.
    #[error("claim not found in credential: {0}")]
    ClaimNotFound(String),
    /// A claim value could not be converted to a field element.
    #[error("field element conversion error: {0}")]
    FieldElement(String),
}
