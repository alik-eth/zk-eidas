use serde::{Deserialize, Serialize};

/// Poseidon commitment from the ECDSA verification circuit (Stage 1).
/// Links Stage 2 predicate proofs to a verified ECDSA signature.
/// commitment = Poseidon(claim_value, sd_array_hash, message_hash)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcdsaCommitment {
    value: Vec<u8>,
}

impl EcdsaCommitment {
    pub fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }
}
