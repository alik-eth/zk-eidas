//! OpenID4VP (Verifiable Presentation) types for eIDAS 2.0 wallet interop.

use serde::{Deserialize, Serialize};

use crate::Predicate;
use zk_eidas_types::proof::ZkProof;

/// A Presentation Definition describes what credentials and claims a verifier requires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationDefinition {
    pub id: String,
    pub input_descriptors: Vec<InputDescriptor>,
}

/// Describes one credential requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    pub id: String,
    pub constraints: Vec<FieldConstraint>,
}

/// A constraint on a single claim field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConstraint {
    /// JSONPath to the claim (e.g., `$.birthdate`).
    pub path: String,
    /// Predicate operation: "gte", "lte", "eq", "neq", "set_member".
    pub predicate_op: String,
    /// Threshold or expected value as a string.
    pub value: String,
}

/// A VP Token wrapping ZK proofs for presentation to a verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VPToken {
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMapEntry>,
    pub proofs: Vec<ProofEntry>,
}

/// Maps an input descriptor to a proof in the VP Token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorMapEntry {
    pub id: String,
    pub proof_index: usize,
}

/// A single proof entry in the VP Token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEntry {
    pub predicate_op: String,
    pub proof_json: String,
}

/// A Presentation Submission maps proofs back to the definition's descriptors.
/// Part of the OpenID4VP response from holder to verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<SubmissionDescriptor>,
}

/// Maps a descriptor from the definition to a proof location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionDescriptor {
    pub id: String,
    pub format: String,
    pub path: String,
}

impl PresentationSubmission {
    /// Build a submission from a definition and proofs.
    pub fn from_definition_and_proofs(
        definition: &PresentationDefinition,
        proofs: &[ZkProof],
    ) -> Result<Self, String> {
        if proofs.len() < definition.input_descriptors.len() {
            return Err(format!(
                "not enough proofs ({}) for descriptors ({})",
                proofs.len(),
                definition.input_descriptors.len()
            ));
        }

        let descriptor_map = definition
            .input_descriptors
            .iter()
            .enumerate()
            .map(|(i, desc)| SubmissionDescriptor {
                id: desc.id.clone(),
                format: "zk_proof".to_string(),
                path: format!("$.proofs[{}]", i),
            })
            .collect();

        Ok(Self {
            id: format!("sub-{}", definition.id),
            definition_id: definition.id.clone(),
            descriptor_map,
        })
    }
}

// --- PresentationDefinition -> Predicates ---

impl PresentationDefinition {
    /// Convert this Presentation Definition into (claim_name, Predicate) pairs.
    pub fn to_predicates(&self) -> Result<Vec<(String, Predicate)>, String> {
        let mut result = Vec::new();
        for descriptor in &self.input_descriptors {
            for constraint in &descriptor.constraints {
                let claim_name = constraint.path.trim_start_matches("$.").to_string();
                let predicate = match constraint.predicate_op.as_str() {
                    "gte" => {
                        let v: i64 = constraint
                            .value
                            .parse()
                            .map_err(|e| format!("invalid gte value: {e}"))?;
                        Predicate::gte(v)
                    }
                    "lte" => {
                        let v: i64 = constraint
                            .value
                            .parse()
                            .map_err(|e| format!("invalid lte value: {e}"))?;
                        Predicate::lte(v)
                    }
                    "eq" => Predicate::eq(&constraint.value),
                    "neq" => Predicate::neq(&constraint.value),
                    "set_member" => {
                        let values: Vec<&str> = constraint.value.split(',').collect();
                        Predicate::set_member(values)
                    }
                    other => return Err(format!("unsupported predicate_op: {other}")),
                };
                result.push((claim_name, predicate));
            }
        }
        Ok(result)
    }
}

// --- VP Token ---

impl VPToken {
    /// Create a VP Token from a Presentation Definition and generated proofs.
    pub fn from_proofs(
        definition: &PresentationDefinition,
        proofs: &[ZkProof],
    ) -> Result<Self, String> {
        if proofs.len() < definition.input_descriptors.len() {
            return Err(format!(
                "not enough proofs ({}) for descriptors ({})",
                proofs.len(),
                definition.input_descriptors.len()
            ));
        }

        let descriptor_map: Vec<DescriptorMapEntry> = definition
            .input_descriptors
            .iter()
            .enumerate()
            .map(|(i, desc)| DescriptorMapEntry {
                id: desc.id.clone(),
                proof_index: i,
            })
            .collect();

        let proof_entries: Result<Vec<ProofEntry>, String> = proofs
            .iter()
            .map(|p| {
                let json = serde_json::to_string(p)
                    .map_err(|e| format!("failed to serialize proof: {e}"))?;
                Ok(ProofEntry {
                    predicate_op: format!("{:?}", p.predicate_op()),
                    proof_json: json,
                })
            })
            .collect();
        let proof_entries = proof_entries?;

        Ok(VPToken {
            definition_id: definition.id.clone(),
            descriptor_map,
            proofs: proof_entries,
        })
    }

    /// Extract ZkProofs back from the VP Token.
    pub fn extract_proofs(&self) -> Result<Vec<ZkProof>, String> {
        self.proofs
            .iter()
            .map(|entry| {
                serde_json::from_str(&entry.proof_json)
                    .map_err(|e| format!("failed to parse proof: {e}"))
            })
            .collect()
    }
}
