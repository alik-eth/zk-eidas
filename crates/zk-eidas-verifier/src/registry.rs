use std::collections::HashMap;

use rust_rapidsnark::groth16_verify_wrapper;

use zk_eidas_prover::CircuitLoader;
use zk_eidas_types::predicate::PredicateOp;
use zk_eidas_types::proof::ZkProof;

use crate::VerifierError;

/// A pre-loaded registry of trusted verification keys, keyed by predicate op.
///
/// Unlike [`crate::Verifier`] which loads circuits from disk on every call,
/// `TrustedCircuitRegistry` loads all verification keys once and holds them in memory
/// as JSON strings (snarkjs format).
pub struct TrustedCircuitRegistry {
    keys: HashMap<PredicateOp, String>,
}

impl TrustedCircuitRegistry {
    /// Create an empty registry (no verification keys loaded).
    pub fn empty() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Returns all predicate ops that the registry attempts to load.
    pub fn supported_ops() -> Vec<PredicateOp> {
        vec![
            PredicateOp::Ecdsa,
            PredicateOp::Gte,
            PredicateOp::Lte,
            PredicateOp::Eq,
            PredicateOp::Neq,
            PredicateOp::Range,
            PredicateOp::SetMember,
            PredicateOp::Nullifier,
            PredicateOp::HolderBinding,
        ]
    }

    /// Load all known predicate verification keys from a directory of circuit artifacts.
    ///
    /// Reads each circuit's `vk.json` file to get the verification key.
    /// Circuits that fail to load are silently skipped.
    pub fn from_directory(path: &str) -> Result<Self, String> {
        let loader = CircuitLoader::new(path);
        let mut keys = HashMap::new();
        for op in Self::supported_ops() {
            if let Ok(artifacts) = loader.load(op) {
                if let Ok(vk_json) = std::fs::read_to_string(&artifacts.vk_json_path) {
                    keys.insert(op, vk_json);
                }
            }
        }
        Ok(Self { keys })
    }

    /// Check whether a verification key is loaded for a given predicate op.
    pub fn has(&self, op: PredicateOp) -> bool {
        self.keys.contains_key(&op)
    }

    /// Look up the verification key JSON for a given predicate op.
    pub fn get(&self, op: PredicateOp) -> Option<&str> {
        self.keys.get(&op).map(|s| s.as_str())
    }
}

/// A verifier that uses a [`TrustedCircuitRegistry`] for filesystem-free proof verification.
///
/// All verification keys are pre-loaded in memory, making verification fast and
/// independent of the filesystem after initial setup.
pub struct RegistryVerifier {
    registry: TrustedCircuitRegistry,
}

impl RegistryVerifier {
    /// Create a registry verifier backed by the given trusted circuit registry.
    pub fn new(registry: TrustedCircuitRegistry) -> Self {
        Self { registry }
    }

    /// Verify a proof using the pre-loaded verification key from the registry.
    pub fn verify(&self, proof: &ZkProof) -> Result<bool, VerifierError> {
        let op = match proof.predicate_op() {
            PredicateOp::Reveal => PredicateOp::Eq,
            other => other,
        };
        let vk_json = self.registry.get(op).ok_or_else(|| {
            VerifierError::CircuitLoadFailed(format!(
                "no trusted circuit for {:?}",
                proof.predicate_op()
            ))
        })?;

        // Extract the proof JSON string from proof bytes
        let proof_json = std::str::from_utf8(proof.proof_bytes())
            .map_err(|e| VerifierError::VerificationFailed(format!(
                "proof bytes are not valid UTF-8: {e}"
            )))?;

        // Reconstruct public signals as a JSON array of decimal strings
        let public_signals: Vec<String> = proof
            .public_inputs()
            .iter()
            .map(|bytes| {
                String::from_utf8(bytes.clone()).map_err(|e| {
                    VerifierError::VerificationFailed(format!(
                        "public input is not valid UTF-8: {e}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let inputs_json = serde_json::to_string(&public_signals)
            .map_err(|e| VerifierError::VerificationFailed(format!(
                "failed to serialize public inputs: {e}"
            )))?;

        // Verify with rapidsnark
        let valid = groth16_verify_wrapper(proof_json, &inputs_json, vk_json)
            .map_err(|e| VerifierError::VerificationFailed(format!(
                "rapidsnark verify failed: {e}"
            )))?;

        Ok(valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_returns_false_for_has() {
        let registry = TrustedCircuitRegistry::empty();
        assert!(!registry.has(PredicateOp::Gte));
        assert!(!registry.has(PredicateOp::Eq));
    }

    #[test]
    fn empty_registry_get_returns_none() {
        let registry = TrustedCircuitRegistry::empty();
        assert!(registry.get(PredicateOp::Gte).is_none());
        assert!(registry.get(PredicateOp::Ecdsa).is_none());
    }

    #[test]
    fn registry_verifier_missing_circuit_returns_error() {
        let registry = TrustedCircuitRegistry::empty();
        let verifier = RegistryVerifier::new(registry);
        let proof = ZkProof::new(vec![1, 2, 3], vec![], vec![10, 20], PredicateOp::Gte);
        let result = verifier.verify(&proof);
        assert!(result.is_err());
        match result.unwrap_err() {
            VerifierError::CircuitLoadFailed(_) => {}
            other => panic!("expected CircuitLoadFailed, got {:?}", other),
        }
    }

    #[test]
    fn from_directory_nonexistent_returns_empty() {
        let registry = TrustedCircuitRegistry::from_directory("/nonexistent/path/xyz").unwrap();
        assert!(!registry.has(PredicateOp::Gte));
    }

    #[test]
    fn supported_ops_lists_all_9() {
        let ops = TrustedCircuitRegistry::supported_ops();
        assert!(ops.contains(&PredicateOp::Ecdsa));
        assert!(ops.contains(&PredicateOp::Gte));
        assert!(ops.contains(&PredicateOp::Lte));
        assert!(ops.contains(&PredicateOp::Eq));
        assert!(ops.contains(&PredicateOp::Neq));
        assert!(ops.contains(&PredicateOp::Range));
        assert!(ops.contains(&PredicateOp::SetMember));
        assert!(ops.contains(&PredicateOp::Nullifier));
        assert!(ops.contains(&PredicateOp::HolderBinding));
        assert_eq!(ops.len(), 9, "ecdsa + 6 predicates + nullifier + holder_binding");
    }
}
