use std::path::Path;

use rust_rapidsnark::groth16_verify_wrapper;

use zk_eidas_prover::CircuitLoader;
use zk_eidas_types::predicate::PredicateOp;
use zk_eidas_types::proof::ZkProof;

/// On-demand proof verifier that loads circuits from disk for each verification.
///
/// The verification key is always derived from the trusted `vk.json` file on disk,
/// never from the proof's bundled VK, maintaining the trust model.
pub struct Verifier {
    loader: CircuitLoader,
}

impl Verifier {
    /// Create a verifier that loads circuits from `circuits_path`.
    ///
    /// The path should point to the `circuits/build/` directory containing
    /// subdirectories for each circuit (gte/, lte/, ecdsa_verify/, etc.).
    pub fn new(circuits_path: impl AsRef<Path>) -> Self {
        Self {
            loader: CircuitLoader::new(circuits_path),
        }
    }

    /// Create a verifier backed by the given circuit loader.
    pub fn from_loader(loader: CircuitLoader) -> Self {
        Self { loader }
    }

    /// Verify a proof by auto-routing based on the proof's predicate op.
    pub fn verify(&self, proof: &ZkProof) -> Result<bool, VerifierError> {
        self.verify_with_op(proof, proof.predicate_op())
    }

    /// Verify a proof using a VK derived from the given predicate op's circuit.
    ///
    /// The VK bundled in the proof is IGNORED — we always derive it ourselves from
    /// the trusted `vk.json` file on disk.
    pub fn verify_with_op(
        &self,
        proof: &ZkProof,
        op: PredicateOp,
    ) -> Result<bool, VerifierError> {
        // 1. Load circuit artifacts to find the vk.json path
        let artifacts = self
            .loader
            .load(op)
            .map_err(|e| VerifierError::CircuitLoadFailed(e.to_string()))?;

        // 2. Read the verification key JSON from the trusted vk.json file
        let vk_json = std::fs::read_to_string(&artifacts.vk_json_path)
            .map_err(|e| VerifierError::CircuitLoadFailed(format!(
                "failed to read vk.json: {e}"
            )))?;

        // 3. Extract the proof JSON string from proof bytes
        let proof_json = std::str::from_utf8(proof.proof_bytes())
            .map_err(|e| VerifierError::VerificationFailed(format!(
                "proof bytes are not valid UTF-8: {e}"
            )))?;

        // 4. Reconstruct public signals as a JSON array of decimal strings
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

        // 5. Verify with rapidsnark (serialized: ffiasm Engine is not thread-safe)
        let _guard = zk_eidas_prover::RAPIDSNARK_LOCK.lock().unwrap();
        let valid = groth16_verify_wrapper(proof_json, &inputs_json, &vk_json)
            .map_err(|e| VerifierError::VerificationFailed(format!(
                "rapidsnark verify failed: {e}"
            )))?;

        Ok(valid)
    }
}

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    /// The circuit artifacts (vk.json) could not be loaded from disk.
    #[error("circuit load failed: {0}")]
    CircuitLoadFailed(String),
    /// The Groth16 verification call failed or the proof/inputs could not be deserialized.
    #[error("verification failed: {0}")]
    VerificationFailed(String),
}
