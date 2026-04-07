use crate::credential::ClaimValue;
use serde::{Deserialize, Serialize};

/// Identifies which predicate circuit to use for proof generation and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PredicateOp {
    /// Stage 1: ECDSA signature verification
    Ecdsa,
    /// Stage 2 predicates (all implicitly signed via ECDSA commitment chain)
    Gte,
    Lte,
    Eq,
    Neq,
    Range,
    SetMember,
    /// Special circuits
    Nullifier,
    HolderBinding,
}

/// A fully-specified predicate binding a claim name, operation, and threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct Predicate {
    claim_name: String,
    op: PredicateOp,
    threshold: ClaimValue,
}

impl Predicate {
    /// Create a predicate for the given claim, operation, and threshold value.
    pub fn new(claim_name: &str, op: PredicateOp, threshold: ClaimValue) -> Self {
        Self {
            claim_name: claim_name.to_string(),
            op,
            threshold,
        }
    }
    /// Shorthand for a GTE predicate.
    pub fn gte(claim_name: &str, threshold: ClaimValue) -> Self {
        Self::new(claim_name, PredicateOp::Gte, threshold)
    }
    /// Shorthand for a LTE predicate.
    pub fn lte(claim_name: &str, threshold: ClaimValue) -> Self {
        Self::new(claim_name, PredicateOp::Lte, threshold)
    }
    /// Shorthand for an equality predicate.
    pub fn eq(claim_name: &str, value: ClaimValue) -> Self {
        Self::new(claim_name, PredicateOp::Eq, value)
    }
    /// Shorthand for a not-equal predicate.
    pub fn neq(claim_name: &str, value: ClaimValue) -> Self {
        Self::new(claim_name, PredicateOp::Neq, value)
    }
    /// Returns the claim name this predicate applies to.
    pub fn claim_name(&self) -> &str {
        &self.claim_name
    }
    /// Returns the predicate operation.
    pub fn op(&self) -> PredicateOp {
        self.op
    }
    /// Returns the threshold / expected value.
    pub fn threshold(&self) -> &ClaimValue {
        &self.threshold
    }
    /// Returns the threshold as a field element byte vector for circuit input.
    pub fn threshold_field(&self) -> Result<Vec<u8>, crate::credential::FieldElementError> {
        self.threshold.to_field_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate_ops_roundtrip_serde() {
        let ops = [
            PredicateOp::Ecdsa,
            PredicateOp::Gte,
            PredicateOp::Lte,
            PredicateOp::Eq,
            PredicateOp::Neq,
            PredicateOp::Range,
            PredicateOp::SetMember,
            PredicateOp::Nullifier,
            PredicateOp::HolderBinding,
        ];
        for op in &ops {
            let json = serde_json::to_string(op).unwrap();
            let back: PredicateOp = serde_json::from_str(&json).unwrap();
            assert_eq!(*op, back);
        }
    }
}
