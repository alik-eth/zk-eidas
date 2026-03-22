use crate::predicate::PredicateOp;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A zero-knowledge proof with its verification key and predicate metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZkProof {
    proof_bytes: Vec<u8>,
    public_inputs: Vec<Vec<u8>>,
    verification_key: Vec<u8>,
    predicate_op: PredicateOp,
    nullifier: Option<[u8; 32]>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    binding_hash: Option<[u8; 32]>,
    #[serde(default)]
    version: u8,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    ecdsa_commitment: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    claim_name: Option<String>,
}

impl ZkProof {
    /// Create a new proof from its raw components.
    pub fn new(
        proof_bytes: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
        verification_key: Vec<u8>,
        predicate_op: PredicateOp,
    ) -> Self {
        Self {
            proof_bytes,
            public_inputs,
            verification_key,
            predicate_op,
            nullifier: None,
            binding_hash: None,
            version: 2,
            ecdsa_commitment: None,
            claim_name: None,
        }
    }

    /// Attach a nullifier to this proof for double-spend prevention.
    pub fn with_nullifier(mut self, nullifier: [u8; 32]) -> Self {
        self.nullifier = Some(nullifier);
        self
    }

    /// Returns the nullifier, if one was attached.
    pub fn nullifier(&self) -> Option<&[u8; 32]> {
        self.nullifier.as_ref()
    }

    /// Attach a holder binding hash to this proof.
    pub fn with_binding_hash(mut self, hash: [u8; 32]) -> Self {
        self.binding_hash = Some(hash);
        self
    }

    /// Returns the holder binding hash, if one was attached.
    pub fn binding_hash(&self) -> Option<&[u8; 32]> {
        self.binding_hash.as_ref()
    }

    /// Attach an ECDSA commitment to this proof.
    pub fn with_ecdsa_commitment(mut self, value: Vec<u8>) -> Self {
        self.ecdsa_commitment = Some(value);
        self
    }

    /// Returns the ECDSA commitment, if one was attached.
    pub fn ecdsa_commitment(&self) -> Option<&[u8]> {
        self.ecdsa_commitment.as_deref()
    }

    /// Attach a claim name to this proof, linking it to its ECDSA proof.
    pub fn with_claim_name(mut self, name: String) -> Self {
        self.claim_name = Some(name);
        self
    }

    /// Returns the claim name, if one was attached.
    pub fn claim_name(&self) -> Option<&str> {
        self.claim_name.as_deref()
    }

    /// Returns the proof format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the raw proof bytes (Groth16 serialized proof).
    pub fn proof_bytes(&self) -> &[u8] {
        &self.proof_bytes
    }
    /// Returns the public inputs for verification.
    pub fn public_inputs(&self) -> &[Vec<u8>] {
        &self.public_inputs
    }
    /// Returns the verification key bytes.
    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }
    /// Returns which predicate operation this proof certifies.
    pub fn predicate_op(&self) -> PredicateOp {
        self.predicate_op
    }
}

/// Logical operator for compound proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogicalOp {
    /// All sub-proofs must be valid.
    And,
    /// At least one sub-proof must be valid.
    Or,
}

/// Court-resolvable nullifier for contract-bound proofs.
///
/// Contains the nullifier value, contract_hash, salt (all printed on paper),
/// and the Groth16 proof that the nullifier was correctly computed from
/// the issuer-signed credential_id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractNullifier {
    #[serde(default = "default_role")]
    pub role: String,
    pub nullifier: Vec<u8>,
    pub contract_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub proof: ZkProof,
}

fn default_role() -> String {
    "holder".to_string()
}

/// A compound proof wrapping multiple sub-proofs with a logical operator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompoundProof {
    proofs: Vec<ZkProof>,
    op: LogicalOp,
    #[serde(default)]
    ecdsa_proofs: HashMap<String, ZkProof>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    contract_nullifier: Option<ContractNullifier>,
}

impl CompoundProof {
    /// Create a compound proof from sub-proofs joined by a logical operator.
    pub fn new(proofs: Vec<ZkProof>, op: LogicalOp) -> Self {
        Self { proofs, op, ecdsa_proofs: HashMap::new(), contract_nullifier: None }
    }

    /// Create a compound proof with associated ECDSA proofs keyed by claim name.
    pub fn with_ecdsa_proofs(
        proofs: Vec<ZkProof>,
        op: LogicalOp,
        ecdsa_proofs: HashMap<String, ZkProof>,
    ) -> Self {
        Self { proofs, op, ecdsa_proofs, contract_nullifier: None }
    }

    /// Attach a contract nullifier to this compound proof.
    pub fn with_contract_nullifier(mut self, cn: ContractNullifier) -> Self {
        self.contract_nullifier = Some(cn);
        self
    }

    /// Returns the contract nullifier, if one was attached.
    pub fn contract_nullifier(&self) -> Option<&ContractNullifier> {
        self.contract_nullifier.as_ref()
    }

    /// Returns the sub-proofs.
    pub fn proofs(&self) -> &[ZkProof] {
        &self.proofs
    }

    /// Returns the logical operator (And / Or).
    pub fn op(&self) -> LogicalOp {
        self.op
    }

    /// Returns the ECDSA proofs keyed by claim name.
    pub fn ecdsa_proofs(&self) -> &HashMap<String, ZkProof> {
        &self.ecdsa_proofs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compound_proof_serde_with_ecdsa_proofs() {
        let ecdsa = ZkProof::new(vec![1, 2], vec![vec![b'1', b'2']], vec![], PredicateOp::Ecdsa);
        let pred = ZkProof::new(vec![3, 4], vec![vec![b'3']], vec![], PredicateOp::Gte)
            .with_claim_name("birth_date".into());
        let mut ecdsa_map = HashMap::new();
        ecdsa_map.insert("birth_date".into(), ecdsa);
        let compound = CompoundProof::with_ecdsa_proofs(vec![pred], LogicalOp::And, ecdsa_map);

        let json = serde_json::to_string(&compound).unwrap();
        let decoded: CompoundProof = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.ecdsa_proofs().len(), 1);
        assert!(decoded.ecdsa_proofs().contains_key("birth_date"));
        assert_eq!(decoded.proofs()[0].claim_name(), Some("birth_date"));
    }

    #[test]
    fn compound_proof_serde_backward_compat() {
        let old_json = r#"{"proofs":[],"op":"And"}"#;
        let decoded: CompoundProof = serde_json::from_str(old_json).unwrap();
        assert!(decoded.ecdsa_proofs().is_empty());
    }

    #[test]
    fn zkproof_serde_backward_compat_no_claim_name() {
        let json = r#"{"proof_bytes":[],"public_inputs":[],"verification_key":[],"predicate_op":"Gte","nullifier":null,"version":2}"#;
        let decoded: ZkProof = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.claim_name(), None);
    }

    #[test]
    fn contract_nullifier_serde_roundtrip() {
        let cn = ContractNullifier {
            role: "holder".to_string(),
            nullifier: vec![1, 2, 3],
            contract_hash: vec![4, 5, 6],
            salt: vec![7, 8, 9],
            proof: ZkProof::new(vec![10], vec![vec![11]], vec![], PredicateOp::Nullifier),
        };
        let json = serde_json::to_string(&cn).unwrap();
        let decoded: ContractNullifier = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.nullifier, vec![1, 2, 3]);
        assert_eq!(decoded.contract_hash, vec![4, 5, 6]);
        assert_eq!(decoded.salt, vec![7, 8, 9]);
    }

    #[test]
    fn compound_proof_with_contract_nullifier_serde() {
        let cn = ContractNullifier {
            role: "holder".to_string(),
            nullifier: vec![1],
            contract_hash: vec![2],
            salt: vec![3],
            proof: ZkProof::new(vec![], vec![], vec![], PredicateOp::Nullifier),
        };
        let compound = CompoundProof::with_ecdsa_proofs(vec![], LogicalOp::And, HashMap::new())
            .with_contract_nullifier(cn);
        let json = serde_json::to_string(&compound).unwrap();
        let decoded: CompoundProof = serde_json::from_str(&json).unwrap();
        assert!(decoded.contract_nullifier().is_some());
        assert_eq!(decoded.contract_nullifier().unwrap().nullifier, vec![1]);
    }

    #[test]
    fn compound_proof_without_contract_nullifier_backward_compat() {
        let json = r#"{"proofs":[],"op":"And"}"#;
        let decoded: CompoundProof = serde_json::from_str(json).unwrap();
        assert!(decoded.contract_nullifier().is_none());
    }

    #[test]
    fn contract_nullifier_with_role_serde_roundtrip() {
        let cn = ContractNullifier {
            role: "seller".to_string(),
            nullifier: vec![1, 2, 3],
            contract_hash: vec![4, 5, 6],
            salt: vec![7, 8, 9],
            proof: ZkProof::new(vec![10], vec![vec![11]], vec![], PredicateOp::Nullifier),
        };
        let json = serde_json::to_string(&cn).unwrap();
        let decoded: ContractNullifier = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.role, "seller");
        assert_eq!(decoded.nullifier, vec![1, 2, 3]);
    }
}
