use std::path::Path;
use std::process::Command;

use num_bigint::BigInt;
use rust_rapidsnark::groth16_prover_zkey_file_wrapper;

use crate::circuit::{CircuitArtifacts, CircuitError, CircuitLoader};
use crate::signed_input::SignedProofInput;
use zk_eidas_types::commitment::EcdsaCommitment;
use zk_eidas_types::predicate::PredicateOp;
use zk_eidas_types::proof::ZkProof;

/// Errors that can occur during proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    /// A circuit could not be loaded.
    #[error("circuit error: {0}")]
    Circuit(#[from] CircuitError),
    /// The Groth16 proving call failed.
    #[error("proving failed: {0}")]
    ProvingFailed(String),
    /// Failed to read the zkey file.
    #[error("zkey read failed: {0}")]
    ZkeyError(String),
    /// Failed to serialize proof or verification key.
    #[error("serialization failed: {0}")]
    SerializationError(String),
    /// Witness generation failed or produced unexpected output.
    #[error("witness generation failed: {0}")]
    WitnessGenFailed(String),
}

/// Generates zero-knowledge proofs for Circom circuits using rapidsnark (Groth16).
///
/// Two-stage architecture:
/// - **Stage 1**: `prove_ecdsa()` verifies an ECDSA signature and outputs a Poseidon commitment.
/// - **Stage 2**: `prove_gte()`, `prove_lte()`, etc. consume the commitment and prove predicates.
///
/// Witness generation uses native C++ binaries compiled from Circom `--c` output.
/// Proof generation uses rapidsnark for ~10x speedup over pure arkworks Groth16.
pub struct Prover {
    loader: CircuitLoader,
}

impl Prover {
    /// Create a prover that loads circuit artifacts from `circuits_path`.
    ///
    /// The path should point to the `circuits/build/` directory containing
    /// subdirectories for each circuit (gte/, lte/, ecdsa_verify/, etc.).
    pub fn new(circuits_path: impl AsRef<Path>) -> Self {
        Self {
            loader: CircuitLoader::new(circuits_path),
        }
    }

    /// Create a prover backed by the given circuit loader.
    pub fn from_loader(loader: CircuitLoader) -> Self {
        Self { loader }
    }

    // ---------------------------------------------------------------
    // Stage 1: ECDSA signature verification
    // ---------------------------------------------------------------

    /// Stage 1: Prove ECDSA P-256 signature verification.
    ///
    /// This is the heavy proof (called once per credential). It verifies that a
    /// valid ECDSA signature exists over the message hash, and outputs a Poseidon
    /// commitment = Poseidon(claim_value, sd_array_hash, message_hash_field).
    ///
    /// Returns `(proof, commitment)` where the commitment is used as input to
    /// Stage 2 predicate circuits.
    pub fn prove_ecdsa(
        &self,
        input: &SignedProofInput,
    ) -> Result<(ZkProof, EcdsaCommitment, Vec<u8>, Vec<u8>), ProverError> {
        let artifacts = self.loader.load(PredicateOp::Ecdsa)?;

        let input_value = build_ecdsa_input_value(input);
        let wtns_bytes = generate_cpp_witness(&artifacts.cpp_witness_bin, &input_value)?;
        let (proof, public_inputs, vk_bytes) = prove_with_wtns(&artifacts, wtns_bytes)?;

        // Public outputs order (Circom convention: outputs first, then public inputs):
        //   [0] = commitment
        //   [1] = sd_array_hash_out
        //   [2] = msg_hash_field_out
        //   [3..14] = pub_key_x[6], pub_key_y[6]
        let commitment_bytes = public_inputs.first().cloned().unwrap_or_default();
        let sd_array_hash = public_inputs.get(1).cloned().unwrap_or_default();
        let msg_hash_field = public_inputs.get(2).cloned().unwrap_or_default();

        let commitment = EcdsaCommitment::new(commitment_bytes.clone());

        let zk_proof = ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::Ecdsa)
            .with_ecdsa_commitment(commitment_bytes);

        Ok((zk_proof, commitment, sd_array_hash, msg_hash_field))
    }

    // ---------------------------------------------------------------
    // Stage 2: Predicate proofs
    // ---------------------------------------------------------------

    /// Stage 2: Prove that `claim_value >= threshold`.
    ///
    /// The commitment (from Stage 1) binds this proof to a verified ECDSA signature.
    pub fn prove_gte(
        &self,
        claim_value: u64,
        threshold: u64,
        commitment: &EcdsaCommitment,
        sd_array_hash: &[u8],
        message_hash: &[u8],
    ) -> Result<ZkProof, ProverError> {
        let artifacts = self.loader.load(PredicateOp::Gte)?;
        let mut input = build_commitment_json(claim_value, sd_array_hash, message_hash, commitment);
        input.insert("threshold".into(), serde_json::json!(threshold.to_string()));
        let wtns_bytes = generate_cpp_witness(&artifacts.cpp_witness_bin, &serde_json::Value::Object(input))?;
        let (proof, public_inputs, vk_bytes) = prove_with_wtns(&artifacts, wtns_bytes)?;
        Ok(ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::Gte))
    }

    /// Stage 2: Prove that `claim_value <= threshold`.
    pub fn prove_lte(
        &self,
        claim_value: u64,
        threshold: u64,
        commitment: &EcdsaCommitment,
        sd_array_hash: &[u8],
        message_hash: &[u8],
    ) -> Result<ZkProof, ProverError> {
        let artifacts = self.loader.load(PredicateOp::Lte)?;
        let mut input = build_commitment_json(claim_value, sd_array_hash, message_hash, commitment);
        input.insert("threshold".into(), serde_json::json!(threshold.to_string()));
        let wtns_bytes = generate_cpp_witness(&artifacts.cpp_witness_bin, &serde_json::Value::Object(input))?;
        let (proof, public_inputs, vk_bytes) = prove_with_wtns(&artifacts, wtns_bytes)?;
        Ok(ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::Lte))
    }

    /// Stage 2: Prove that `claim_value == expected`.
    pub fn prove_eq(
        &self,
        claim_value: u64,
        expected: u64,
        commitment: &EcdsaCommitment,
        sd_array_hash: &[u8],
        message_hash: &[u8],
    ) -> Result<ZkProof, ProverError> {
        let artifacts = self.loader.load(PredicateOp::Eq)?;
        let mut input = build_commitment_json(claim_value, sd_array_hash, message_hash, commitment);
        input.insert("expected".into(), serde_json::json!(expected.to_string()));
        let wtns_bytes = generate_cpp_witness(&artifacts.cpp_witness_bin, &serde_json::Value::Object(input))?;
        let (proof, public_inputs, vk_bytes) = prove_with_wtns(&artifacts, wtns_bytes)?;
        Ok(ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::Eq))
    }

    /// Stage 2: Prove that `claim_value != expected`.
    pub fn prove_neq(
        &self,
        claim_value: u64,
        expected: u64,
        commitment: &EcdsaCommitment,
        sd_array_hash: &[u8],
        message_hash: &[u8],
    ) -> Result<ZkProof, ProverError> {
        let artifacts = self.loader.load(PredicateOp::Neq)?;
        let mut input = build_commitment_json(claim_value, sd_array_hash, message_hash, commitment);
        input.insert("expected".into(), serde_json::json!(expected.to_string()));
        let wtns_bytes = generate_cpp_witness(&artifacts.cpp_witness_bin, &serde_json::Value::Object(input))?;
        let (proof, public_inputs, vk_bytes) = prove_with_wtns(&artifacts, wtns_bytes)?;
        Ok(ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::Neq))
    }

    /// Stage 2: Prove that `low <= claim_value <= high`.
    pub fn prove_range(
        &self,
        claim_value: u64,
        low: u64,
        high: u64,
        commitment: &EcdsaCommitment,
        sd_array_hash: &[u8],
        message_hash: &[u8],
    ) -> Result<ZkProof, ProverError> {
        let artifacts = self.loader.load(PredicateOp::Range)?;
        let mut input = build_commitment_json(claim_value, sd_array_hash, message_hash, commitment);
        input.insert("low".into(), serde_json::json!(low.to_string()));
        input.insert("high".into(), serde_json::json!(high.to_string()));
        let wtns_bytes = generate_cpp_witness(&artifacts.cpp_witness_bin, &serde_json::Value::Object(input))?;
        let (proof, public_inputs, vk_bytes) = prove_with_wtns(&artifacts, wtns_bytes)?;
        Ok(ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::Range))
    }

    /// Stage 2: Prove that `claim_value` is a member of `set[0..set_len]`.
    pub fn prove_set_member(
        &self,
        claim_value: u64,
        set: &[u64; 16],
        set_len: u64,
        commitment: &EcdsaCommitment,
        sd_array_hash: &[u8],
        message_hash: &[u8],
    ) -> Result<ZkProof, ProverError> {
        let artifacts = self.loader.load(PredicateOp::SetMember)?;
        let mut input = build_commitment_json(claim_value, sd_array_hash, message_hash, commitment);
        input.insert("set".into(), serde_json::json!(set.iter().map(|v| v.to_string()).collect::<Vec<_>>()));
        input.insert("set_len".into(), serde_json::json!(set_len.to_string()));
        let wtns_bytes = generate_cpp_witness(&artifacts.cpp_witness_bin, &serde_json::Value::Object(input))?;
        let (proof, public_inputs, vk_bytes) = prove_with_wtns(&artifacts, wtns_bytes)?;
        Ok(ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::SetMember))
    }

    /// Stage 2: Prove a court-resolvable nullifier.
    ///
    /// Computes `nullifier = Poseidon(credential_id, contract_hash, salt)` inside the circuit.
    /// The commitment chain ensures `credential_id` is the issuer-signed document_number.
    /// The nullifier is extracted from the circuit's public output.
    pub fn prove_nullifier(
        &self,
        credential_id: u64,
        contract_hash: u64,
        salt: u64,
        commitment: &EcdsaCommitment,
        sd_array_hash: &[u8],
        message_hash: &[u8],
    ) -> Result<ZkProof, ProverError> {
        let artifacts = self.loader.load(PredicateOp::Nullifier)?;

        let input = serde_json::json!({
            "credential_id": credential_id.to_string(),
            "sd_array_hash": bytes_to_decimal_string(sd_array_hash),
            "message_hash": bytes_to_decimal_string(message_hash),
            "commitment": bytes_to_decimal_string(commitment.value()),
            "contract_hash": contract_hash.to_string(),
            "salt": salt.to_string(),
        });

        let wtns_bytes = generate_cpp_witness(&artifacts.cpp_witness_bin, &input)?;
        let (proof, public_inputs, vk_bytes) = prove_with_wtns(&artifacts, wtns_bytes)?;

        // Public output [0] = nullifier (circuit output)
        let nullifier_str = public_inputs.first()
            .and_then(|b| String::from_utf8(b.clone()).ok())
            .ok_or_else(|| ProverError::WitnessGenFailed("nullifier output missing".into()))?;
        let nullifier_bigint = nullifier_str.parse::<num_bigint::BigUint>()
            .map_err(|e| ProverError::WitnessGenFailed(format!("nullifier parse: {e}")))?;
        let mut nullifier_bytes = [0u8; 32];
        let be = nullifier_bigint.to_bytes_be();
        let start = 32usize.saturating_sub(be.len());
        nullifier_bytes[start..].copy_from_slice(&be[..be.len().min(32)]);

        Ok(ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::Nullifier)
            .with_nullifier(nullifier_bytes))
    }

    /// Stage 2: Prove a holder binding hash.
    ///
    /// Proves that `binding_hash = Poseidon(claim_value)`, enabling cross-credential
    /// holder linking without revealing the claim value.
    pub fn prove_holder_binding(
        &self,
        claim_value: u64,
        commitment: &EcdsaCommitment,
        sd_array_hash: &[u8],
        message_hash: &[u8],
    ) -> Result<ZkProof, ProverError> {
        let artifacts = self.loader.load(PredicateOp::HolderBinding)?;

        let input = serde_json::json!({
            "claim_value": claim_value.to_string(),
            "sd_array_hash": bytes_to_decimal_string(sd_array_hash),
            "message_hash": bytes_to_decimal_string(message_hash),
            "commitment": bytes_to_decimal_string(commitment.value()),
        });

        let wtns_bytes = generate_cpp_witness(&artifacts.cpp_witness_bin, &input)?;
        let (proof, public_inputs, vk_bytes) = prove_with_wtns(&artifacts, wtns_bytes)?;

        // Public outputs order: [0] = binding_hash, [1] = commitment
        let binding_hash_bytes = public_inputs.first().cloned().unwrap_or_default();
        let binding_hash_str = String::from_utf8(binding_hash_bytes).unwrap_or_default();
        let binding_hash_bigint = binding_hash_str.parse::<num_bigint::BigUint>().unwrap_or_default();
        let mut hash_bytes = [0u8; 32];
        let be_bytes = binding_hash_bigint.to_bytes_be();
        let start = 32usize.saturating_sub(be_bytes.len());
        hash_bytes[start..].copy_from_slice(&be_bytes[..be_bytes.len().min(32)]);

        Ok(ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::HolderBinding)
            .with_binding_hash(hash_bytes))
    }
}

// ---------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------

/// Build the standard commitment-chain JSON inputs shared by all Stage 2 circuits.
///
/// Private: claim_value, sd_array_hash, message_hash
/// Public: commitment
fn build_commitment_json(
    claim_value: u64,
    sd_array_hash: &[u8],
    message_hash: &[u8],
    commitment: &EcdsaCommitment,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert("claim_value".into(), serde_json::json!(claim_value.to_string()));
    map.insert("sd_array_hash".into(), serde_json::json!(bytes_to_decimal_string(sd_array_hash)));
    map.insert("message_hash".into(), serde_json::json!(bytes_to_decimal_string(message_hash)));
    map.insert("commitment".into(), serde_json::json!(bytes_to_decimal_string(commitment.value())));
    map
}

/// Convert bytes to a decimal string for use as a circuit input.
/// If the bytes are a valid UTF-8 decimal string (from rapidsnark public signals),
/// parse as decimal. Otherwise treat as big-endian binary.
fn bytes_to_decimal_string(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        if s.parse::<num_bigint::BigInt>().is_ok() {
            return s.to_string();
        }
    }
    num_bigint::BigInt::from_signed_bytes_be(bytes).to_string()
}

/// Generate witness using native C++ binary.
///
/// The C++ witness generator is compiled from Circom's `--c` output.
/// Usage: ./<circuit> <input.json> <witness.wtns>
fn generate_cpp_witness(
    cpp_bin: &Path,
    input_json: &serde_json::Value,
) -> Result<Vec<u8>, ProverError> {
    let tmp_dir = tempfile::tempdir()
        .map_err(|e| ProverError::WitnessGenFailed(format!("failed to create temp dir: {e}")))?;
    let input_path = tmp_dir.path().join("input.json");
    let output_path = tmp_dir.path().join("witness.wtns");

    std::fs::write(&input_path, input_json.to_string())
        .map_err(|e| ProverError::WitnessGenFailed(format!("failed to write input.json: {e}")))?;

    let result = Command::new(cpp_bin)
        .arg(&input_path)
        .arg(&output_path)
        .output()
        .map_err(|e| ProverError::WitnessGenFailed(format!("failed to run C++ witness generator: {e}")))?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(ProverError::WitnessGenFailed(format!(
            "C++ witness generation failed (exit {}): {}",
            result.status.code().unwrap_or(-1),
            stderr.lines().last().unwrap_or("unknown error")
        )));
    }

    std::fs::read(&output_path)
        .map_err(|e| ProverError::WitnessGenFailed(format!("failed to read witness output: {e}")))
}

/// Run rapidsnark Groth16 prover on pre-computed witness bytes.
///
/// Returns (proof_json_bytes, public_inputs_bytes, vk_json_bytes).
fn prove_with_wtns(
    artifacts: &CircuitArtifacts,
    wtns_bytes: Vec<u8>,
) -> Result<(Vec<u8>, Vec<Vec<u8>>, Vec<u8>), ProverError> {
    let zkey_path = artifacts.zkey_path.to_string_lossy().to_string();
    let _guard = crate::RAPIDSNARK_LOCK.lock().unwrap();
    let proof_result = groth16_prover_zkey_file_wrapper(&zkey_path, wtns_bytes)
        .map_err(|e| ProverError::ProvingFailed(format!("rapidsnark prove failed: {e}")))?;

    let proof_json_bytes = proof_result.proof.into_bytes();

    let public_signals: Vec<String> = serde_json::from_str(&proof_result.public_signals)
        .map_err(|e| ProverError::SerializationError(format!(
            "failed to parse public signals: {e}"
        )))?;

    let pub_inputs_bytes: Vec<Vec<u8>> = public_signals
        .into_iter()
        .map(|s| s.into_bytes())
        .collect();

    let vk_json_bytes = std::fs::read(&artifacts.vk_json_path)
        .map_err(|e| ProverError::ZkeyError(format!(
            "failed to read vk.json: {e}"
        )))?;

    Ok((proof_json_bytes, pub_inputs_bytes, vk_json_bytes))
}

/// Build the input JSON value for the ECDSA circuit.
fn build_ecdsa_input_value(input: &SignedProofInput) -> serde_json::Value {
    let r_limbs = SignedProofInput::to_43bit_limbs(&input.signature_r);
    let s_limbs = SignedProofInput::to_43bit_limbs(&input.signature_s);
    let msg_limbs = SignedProofInput::to_43bit_limbs(&input.message_hash);
    let pkx_limbs = SignedProofInput::to_43bit_limbs(&input.pub_key_x);
    let pky_limbs = SignedProofInput::to_43bit_limbs(&input.pub_key_y);

    let to_strings = |limbs: &[BigInt; 6]| -> Vec<String> {
        limbs.iter().map(|l| l.to_string()).collect()
    };

    serde_json::json!({
        "signature_r": to_strings(&r_limbs),
        "signature_s": to_strings(&s_limbs),
        "message_hash": to_strings(&msg_limbs),
        "pub_key_x": to_strings(&pkx_limbs),
        "pub_key_y": to_strings(&pky_limbs),
        "claim_value": input.claim_value.to_string(),
        "disclosure_hash": input.disclosure_hash.to_string(),
        "sd_array": input.sd_array.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
    })
}

/// Build the input JSON for the ECDSA circuit (used by C++ witness gen and browser proving).
pub fn build_ecdsa_input_json(input: &SignedProofInput) -> String {
    build_ecdsa_input_value(input).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prover_new_and_missing_circuits() {
        let prover = Prover::new("/nonexistent");
        let commitment = EcdsaCommitment::new(vec![0u8; 32]);
        let result = prover.prove_gte(100, 18, &commitment, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn prover_lte_missing_circuits() {
        let prover = Prover::new("/nonexistent");
        let commitment = EcdsaCommitment::new(vec![0u8; 32]);
        let result = prover.prove_lte(100, 200, &commitment, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn prover_eq_missing_circuits() {
        let prover = Prover::new("/nonexistent");
        let commitment = EcdsaCommitment::new(vec![0u8; 32]);
        let result = prover.prove_eq(42, 42, &commitment, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn prover_neq_missing_circuits() {
        let prover = Prover::new("/nonexistent");
        let commitment = EcdsaCommitment::new(vec![0u8; 32]);
        let result = prover.prove_neq(42, 99, &commitment, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn prover_range_missing_circuits() {
        let prover = Prover::new("/nonexistent");
        let commitment = EcdsaCommitment::new(vec![0u8; 32]);
        let result = prover.prove_range(50, 10, 100, &commitment, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn prover_set_member_missing_circuits() {
        let prover = Prover::new("/nonexistent");
        let commitment = EcdsaCommitment::new(vec![0u8; 32]);
        let set = [0u64; 16];
        let result = prover.prove_set_member(1, &set, 1, &commitment, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn prover_nullifier_missing_circuits() {
        let prover = Prover::new("/nonexistent");
        let commitment = EcdsaCommitment::new(vec![0u8; 32]);
        let result = prover.prove_nullifier(42, 100, 200, &commitment, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn prover_holder_binding_missing_circuits() {
        let prover = Prover::new("/nonexistent");
        let commitment = EcdsaCommitment::new(vec![0u8; 32]);
        let result = prover.prove_holder_binding(42, &commitment, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn prover_ecdsa_missing_circuits() {
        let prover = Prover::new("/nonexistent");
        let input = SignedProofInput {
            signature_r: [0u8; 32],
            signature_s: [0u8; 32],
            message_hash: [0u8; 32],
            pub_key_x: [0u8; 32],
            pub_key_y: [0u8; 32],
            claim_value: 42,
            disclosure_hash: 0,
            sd_array: [0u64; 16],
        };
        let result = prover.prove_ecdsa(&input);
        assert!(result.is_err());
    }

    /// Integration test: prove + verify a GTE predicate.
    /// Requires compiled circuit artifacts and zkey at circuits/build/gte/.
    #[test]
    #[ignore = "requires compiled circuit artifacts and zkey (run `make circuits` first)"]
    fn prove_and_verify_gte() {
        let circuits_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("circuits/build");

        let prover = Prover::new(&circuits_path);
        let commitment = EcdsaCommitment::new(vec![0u8; 32]);
        let sd_array_hash = [0u8; 32];
        let message_hash = [0u8; 32];

        let result = prover.prove_gte(25, 18, &commitment, &sd_array_hash, &message_hash);
        assert!(result.is_ok(), "prove_gte failed: {:?}", result.err());

        let proof = result.unwrap();
        assert_eq!(proof.predicate_op(), PredicateOp::Gte);
        assert!(!proof.proof_bytes().is_empty());
        assert!(!proof.verification_key().is_empty());
    }
}
