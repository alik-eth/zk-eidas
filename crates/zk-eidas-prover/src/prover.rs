use std::path::Path;

use ark_bn254::Fr;
use ark_circom::{CircomBuilder, CircomConfig};
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
}

/// Generates zero-knowledge proofs for Circom circuits using rapidsnark (Groth16).
///
/// Two-stage architecture:
/// - **Stage 1**: `prove_ecdsa()` verifies an ECDSA signature and outputs a Poseidon commitment.
/// - **Stage 2**: `prove_gte()`, `prove_lte()`, etc. consume the commitment and prove predicates.
///
/// Witness generation uses ark-circom (WASM-based). Proof generation uses rapidsnark
/// for ~10x speedup over pure arkworks Groth16.
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

        let mut builder = create_builder(&artifacts)?;

        // Private inputs: signature_r[6], signature_s[6], message_hash[6]
        let r_limbs = SignedProofInput::to_43bit_limbs(&input.signature_r);
        let s_limbs = SignedProofInput::to_43bit_limbs(&input.signature_s);
        let msg_limbs = SignedProofInput::to_43bit_limbs(&input.message_hash);

        for limb in &r_limbs {
            builder.push_input("signature_r", limb.clone());
        }
        for limb in &s_limbs {
            builder.push_input("signature_s", limb.clone());
        }
        for limb in &msg_limbs {
            builder.push_input("message_hash", limb.clone());
        }

        // Private inputs: claim_value, disclosure_hash, sd_array[16]
        builder.push_input("claim_value", BigInt::from(input.claim_value));
        builder.push_input("disclosure_hash", BigInt::from(input.disclosure_hash));
        for val in &input.sd_array {
            builder.push_input("sd_array", BigInt::from(*val));
        }

        // Public inputs: pub_key_x[6], pub_key_y[6]
        let pkx_limbs = SignedProofInput::to_43bit_limbs(&input.pub_key_x);
        let pky_limbs = SignedProofInput::to_43bit_limbs(&input.pub_key_y);

        for limb in &pkx_limbs {
            builder.push_input("pub_key_x", limb.clone());
        }
        for limb in &pky_limbs {
            builder.push_input("pub_key_y", limb.clone());
        }

        // Generate proof
        let (proof, public_inputs, vk_bytes) = generate_proof(&artifacts, builder)?;

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
        let mut builder = create_builder(&artifacts)?;

        push_commitment_inputs(&mut builder, claim_value, sd_array_hash, message_hash, commitment);
        builder.push_input("threshold", BigInt::from(threshold));

        let (proof, public_inputs, vk_bytes) = generate_proof(&artifacts, builder)?;
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
        let mut builder = create_builder(&artifacts)?;

        push_commitment_inputs(&mut builder, claim_value, sd_array_hash, message_hash, commitment);
        builder.push_input("threshold", BigInt::from(threshold));

        let (proof, public_inputs, vk_bytes) = generate_proof(&artifacts, builder)?;
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
        let mut builder = create_builder(&artifacts)?;

        push_commitment_inputs(&mut builder, claim_value, sd_array_hash, message_hash, commitment);
        builder.push_input("expected", BigInt::from(expected));

        let (proof, public_inputs, vk_bytes) = generate_proof(&artifacts, builder)?;
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
        let mut builder = create_builder(&artifacts)?;

        push_commitment_inputs(&mut builder, claim_value, sd_array_hash, message_hash, commitment);
        builder.push_input("expected", BigInt::from(expected));

        let (proof, public_inputs, vk_bytes) = generate_proof(&artifacts, builder)?;
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
        let mut builder = create_builder(&artifacts)?;

        push_commitment_inputs(&mut builder, claim_value, sd_array_hash, message_hash, commitment);
        builder.push_input("low", BigInt::from(low));
        builder.push_input("high", BigInt::from(high));

        let (proof, public_inputs, vk_bytes) = generate_proof(&artifacts, builder)?;
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
        let mut builder = create_builder(&artifacts)?;

        push_commitment_inputs(&mut builder, claim_value, sd_array_hash, message_hash, commitment);
        for val in set {
            builder.push_input("set", BigInt::from(*val));
        }
        builder.push_input("set_len", BigInt::from(set_len));

        let (proof, public_inputs, vk_bytes) = generate_proof(&artifacts, builder)?;
        Ok(ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::SetMember))
    }

    /// Stage 2: Prove a nullifier for double-spend prevention.
    ///
    /// Proves knowledge of `credential_secret` such that
    /// `nullifier = Poseidon(credential_secret, scope)`.
    /// The commitment chain ensures this is bound to a valid ECDSA signature.
    pub fn prove_nullifier(
        &self,
        credential_secret: u64,
        scope: u64,
        nullifier: u64,
        claim_value: u64,
        commitment: &EcdsaCommitment,
        sd_array_hash: &[u8],
        message_hash: &[u8],
    ) -> Result<ZkProof, ProverError> {
        let artifacts = self.loader.load(PredicateOp::Nullifier)?;
        let mut builder = create_builder(&artifacts)?;

        // Private inputs
        builder.push_input("credential_secret", BigInt::from(credential_secret));
        builder.push_input("sd_array_hash", bytes_to_bigint(sd_array_hash));
        builder.push_input("message_hash", bytes_to_bigint(message_hash));
        builder.push_input("claim_value", BigInt::from(claim_value));

        // Public inputs
        builder.push_input("commitment", bytes_to_bigint(commitment.value()));
        builder.push_input("scope", BigInt::from(scope));
        builder.push_input("nullifier", BigInt::from(nullifier));

        let (proof, public_inputs, vk_bytes) = generate_proof(&artifacts, builder)?;

        // Serialize nullifier to 32 bytes for the ZkProof metadata
        let nullifier_bytes = u64_to_32bytes(nullifier);

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
        binding_hash: u64,
        commitment: &EcdsaCommitment,
        sd_array_hash: &[u8],
        message_hash: &[u8],
    ) -> Result<ZkProof, ProverError> {
        let artifacts = self.loader.load(PredicateOp::HolderBinding)?;
        let mut builder = create_builder(&artifacts)?;

        // Private inputs
        builder.push_input("claim_value", BigInt::from(claim_value));
        builder.push_input("sd_array_hash", bytes_to_bigint(sd_array_hash));
        builder.push_input("message_hash", bytes_to_bigint(message_hash));

        // Public inputs
        builder.push_input("commitment", bytes_to_bigint(commitment.value()));
        builder.push_input("binding_hash", BigInt::from(binding_hash));

        let (proof, public_inputs, vk_bytes) = generate_proof(&artifacts, builder)?;

        let hash_bytes = u64_to_32bytes(binding_hash);

        Ok(ZkProof::new(proof, public_inputs, vk_bytes, PredicateOp::HolderBinding)
            .with_binding_hash(hash_bytes))
    }
}

// ---------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------

/// Create a `CircomBuilder` from circuit artifacts (loads WASM + R1CS).
fn create_builder(artifacts: &CircuitArtifacts) -> Result<CircomBuilder<Fr>, ProverError> {
    let cfg = CircomConfig::<Fr>::new(
        &artifacts.wasm_path,
        &artifacts.r1cs_path,
    )
    .map_err(|e| ProverError::ProvingFailed(format!("failed to load circuit config: {e}")))?;

    Ok(CircomBuilder::new(cfg))
}

/// Push the standard commitment-chain private/public inputs shared by all Stage 2 circuits.
///
/// Private: claim_value, sd_array_hash, message_hash
/// Public: commitment
fn push_commitment_inputs(
    builder: &mut CircomBuilder<Fr>,
    claim_value: u64,
    sd_array_hash: &[u8],
    message_hash: &[u8],
    commitment: &EcdsaCommitment,
) {
    // Private inputs (order matches circom signal declaration order)
    builder.push_input("claim_value", BigInt::from(claim_value));
    builder.push_input("sd_array_hash", bytes_to_bigint(sd_array_hash));
    builder.push_input("message_hash", bytes_to_bigint(message_hash));

    // Public input
    builder.push_input("commitment", bytes_to_bigint(commitment.value()));
}

/// Convert bytes to a BigInt for use as a circuit input.
/// If the bytes are a valid UTF-8 decimal string (from rapidsnark public signals),
/// parse as decimal. Otherwise treat as big-endian binary.
fn bytes_to_bigint(bytes: &[u8]) -> BigInt {
    if let Ok(s) = std::str::from_utf8(bytes) {
        if let Ok(n) = s.parse::<BigInt>() {
            return n;
        }
    }
    BigInt::from_signed_bytes_be(bytes)
}

/// Convert a u64 to a 32-byte big-endian array (for ZkProof metadata).
fn u64_to_32bytes(val: u64) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[24..].copy_from_slice(&val.to_be_bytes());
    result
}

/// Convert witness field elements (from ark-circom) to .wtns binary format
/// compatible with rapidsnark.
///
/// The .wtns format is:
/// - 4 bytes magic: "wtns"
/// - 4 bytes version: 2 (little-endian u32)
/// - 4 bytes num_sections: 2 (little-endian u32)
/// - Section 1 (field info):
///   - 4 bytes section_id: 1 (little-endian u32)
///   - 8 bytes section_size (little-endian u64)
///   - 4 bytes field_size: 32 (little-endian u32)
///   - 32 bytes prime (bn254 prime, little-endian)
///   - 4 bytes num_witness (little-endian u32)
/// - Section 2 (witness values):
///   - 4 bytes section_id: 2 (little-endian u32)
///   - 8 bytes section_size (little-endian u64)
///   - witness values, each 32 bytes (little-endian)
fn witness_to_wtns(witness: &[Fr]) -> Vec<u8> {
    use ark_serialize::CanonicalSerialize;

    let field_size: u32 = 32;
    let num_witness = witness.len() as u32;

    // BN254 prime in little-endian bytes
    let prime: [u8; 32] = [
        0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43,
        0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
        0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
        0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
    ];

    let section1_size: u64 = (4 + 32 + 4) as u64; // field_size + prime + num_witness
    let section2_size: u64 = (num_witness as u64) * (field_size as u64);

    let total_size = 4 + 4 + 4 // magic + version + num_sections
        + 4 + 8 + section1_size as usize // section 1 header + data
        + 4 + 8 + section2_size as usize; // section 2 header + data

    let mut buf = Vec::with_capacity(total_size);

    // Header
    buf.extend_from_slice(b"wtns");
    buf.extend_from_slice(&2u32.to_le_bytes()); // version
    buf.extend_from_slice(&2u32.to_le_bytes()); // num_sections

    // Section 1: field info
    buf.extend_from_slice(&1u32.to_le_bytes()); // section_id
    buf.extend_from_slice(&section1_size.to_le_bytes()); // section_size
    buf.extend_from_slice(&field_size.to_le_bytes()); // field_size
    buf.extend_from_slice(&prime); // prime
    buf.extend_from_slice(&num_witness.to_le_bytes()); // num_witness

    // Section 2: witness values
    buf.extend_from_slice(&2u32.to_le_bytes()); // section_id
    buf.extend_from_slice(&section2_size.to_le_bytes()); // section_size

    for w in witness {
        let mut elem_bytes = Vec::with_capacity(32);
        w.serialize_compressed(&mut elem_bytes)
            .expect("field element serialization should not fail");
        // ark-serialize compressed for Fr is 32 bytes little-endian
        buf.extend_from_slice(&elem_bytes);
    }

    buf
}

/// Generate a Groth16 proof using rapidsnark with a pre-computed zkey.
///
/// Uses ark-circom for witness generation (WASM-based), then feeds the witness
/// to rapidsnark for fast proof generation.
///
/// Returns (proof_json_bytes, public_inputs_bytes, vk_json_bytes).
fn generate_proof(
    artifacts: &CircuitArtifacts,
    builder: CircomBuilder<Fr>,
) -> Result<(Vec<u8>, Vec<Vec<u8>>, Vec<u8>), ProverError> {
    // Build the circuit with witness using ark-circom (WASM witness generator)
    let circom = builder
        .build()
        .map_err(|e| ProverError::ProvingFailed(format!("witness generation failed: {e}")))?;

    // Extract the full witness (including public inputs)
    let witness = circom
        .witness
        .ok_or_else(|| ProverError::ProvingFailed("no witness generated".into()))?;

    // Convert witness to .wtns binary format
    let wtns_bytes = witness_to_wtns(&witness);

    // Use rapidsnark for fast proof generation
    let zkey_path = artifacts.zkey_path.to_string_lossy().to_string();
    let proof_result = groth16_prover_zkey_file_wrapper(&zkey_path, wtns_bytes)
        .map_err(|e| ProverError::ProvingFailed(format!("rapidsnark prove failed: {e}")))?;

    // proof_result.proof is a JSON string, proof_result.public_signals is a JSON string
    let proof_json_bytes = proof_result.proof.into_bytes();

    // Parse public signals from JSON array of decimal strings
    let public_signals: Vec<String> = serde_json::from_str(&proof_result.public_signals)
        .map_err(|e| ProverError::SerializationError(format!(
            "failed to parse public signals: {e}"
        )))?;

    // Store each public signal as its decimal string bytes
    let pub_inputs_bytes: Vec<Vec<u8>> = public_signals
        .into_iter()
        .map(|s| s.into_bytes())
        .collect();

    // Read VK JSON from the trusted vk.json file
    let vk_json_bytes = std::fs::read(&artifacts.vk_json_path)
        .map_err(|e| ProverError::ZkeyError(format!(
            "failed to read vk.json: {e}"
        )))?;

    Ok((proof_json_bytes, pub_inputs_bytes, vk_json_bytes))
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
        let result = prover.prove_nullifier(42, 1, 99, 10, &commitment, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn prover_holder_binding_missing_circuits() {
        let prover = Prover::new("/nonexistent");
        let commitment = EcdsaCommitment::new(vec![0u8; 32]);
        let result = prover.prove_holder_binding(42, 99, &commitment, &[0u8; 32], &[0u8; 32]);
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

    #[test]
    fn bytes_to_bigint_roundtrip() {
        let bytes = [0u8, 0, 0, 0, 0, 0, 0, 42];
        let bi = bytes_to_bigint(&bytes);
        assert_eq!(bi, BigInt::from(42));
    }

    #[test]
    fn u64_to_32bytes_correct() {
        let result = u64_to_32bytes(42);
        assert_eq!(result[31], 42);
        assert_eq!(result[..24], [0u8; 24]);
    }

    #[test]
    fn witness_to_wtns_header_correct() {
        // Create a minimal witness with one element (value 0)
        use ark_bn254::Fr;
        let witness = vec![Fr::from(0u64)];
        let wtns = witness_to_wtns(&witness);

        // Check magic
        assert_eq!(&wtns[0..4], b"wtns");
        // Check version = 2
        assert_eq!(u32::from_le_bytes(wtns[4..8].try_into().unwrap()), 2);
        // Check num_sections = 2
        assert_eq!(u32::from_le_bytes(wtns[8..12].try_into().unwrap()), 2);
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
