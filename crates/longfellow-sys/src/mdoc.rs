//! High-level mdoc prove/verify API wrapping Longfellow FFI.

use crate::safe::{VerifyType, make_attribute, gen_circuit};
use crate::*;
use std::ffi::CString;

/// Error type for mdoc proving/verification.
#[derive(Debug, thiserror::Error)]
pub enum MdocError {
    #[error("circuit generation failed: {0}")]
    CircuitGeneration(String),
    #[error("prover failed with code {0}")]
    ProverFailed(u32),
    #[error("verifier failed with code {0}")]
    VerifierFailed(u32),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// An attribute to disclose or prove a predicate on.
#[derive(Debug, Clone)]
pub struct AttributeRequest {
    pub namespace: String,
    pub identifier: String,
    pub cbor_value: Vec<u8>,
    pub verify_type: VerifyType,
}

/// Proof output from the Longfellow prover.
#[derive(Debug, Clone)]
pub struct MdocProof {
    pub proof_bytes: Vec<u8>,
    pub nullifier_hash: [u8; 32],
    pub binding_hash: [u8; 32],
    pub circuit_spec_index: usize,
}

/// Cached circuit bytes for a specific number of attributes.
pub struct MdocCircuit {
    bytes: Vec<u8>,
    spec_index: usize,
    num_attributes: usize,
}

impl MdocCircuit {
    /// Generate a circuit for the given number of attributes (1-4).
    pub fn generate(num_attributes: usize) -> Result<Self, MdocError> {
        if num_attributes == 0 || num_attributes > 4 {
            return Err(MdocError::InvalidInput(format!(
                "num_attributes must be 1-4, got {num_attributes}"
            )));
        }
        // kZkSpecs[0..3] are v7 specs for 1-4 attributes
        let spec_index = num_attributes - 1;
        let bytes = gen_circuit(spec_index)
            .map_err(MdocError::CircuitGeneration)?;
        Ok(Self {
            bytes,
            spec_index,
            num_attributes,
        })
    }

    pub fn num_attributes(&self) -> usize {
        self.num_attributes
    }

    /// Save the serialized circuit bytes to a file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, &self.bytes)
    }

    /// Load a previously saved circuit from a file.
    pub fn load(path: &std::path::Path, num_attributes: usize) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let spec_index = num_attributes - 1;
        Ok(Self { bytes, spec_index, num_attributes })
    }
}

/// Prove selective disclosure + predicates on an mdoc credential.
/// `contract_hash` is an 8-byte domain separator for the nullifier.
/// The returned proof includes `nullifier_hash = SHA-256(e || contract_hash)`.
pub fn prove(
    circuit: &MdocCircuit,
    mdoc_bytes: &[u8],
    issuer_pk_x: &str,
    issuer_pk_y: &str,
    session_transcript: &[u8],
    attributes: &[AttributeRequest],
    now: &str,
    contract_hash: &[u8; 8],
) -> Result<MdocProof, MdocError> {
    if attributes.len() != circuit.num_attributes {
        return Err(MdocError::InvalidInput(format!(
            "circuit expects {} attributes, got {}",
            circuit.num_attributes,
            attributes.len()
        )));
    }

    // Convert attributes to C structs
    let c_attrs: Vec<RequestedAttribute> = attributes
        .iter()
        .map(|a| make_attribute(&a.namespace, &a.identifier, &a.cbor_value, a.verify_type))
        .collect();

    let pkx = CString::new(issuer_pk_x)
        .map_err(|e| MdocError::InvalidInput(e.to_string()))?;
    let pky = CString::new(issuer_pk_y)
        .map_err(|e| MdocError::InvalidInput(e.to_string()))?;
    let now_c = CString::new(now)
        .map_err(|e| MdocError::InvalidInput(e.to_string()))?;

    unsafe {
        let spec = kZkSpecs.as_ptr().add(circuit.spec_index);
        let mut proof_ptr: *mut u8 = std::ptr::null_mut();
        let mut proof_len: std::os::raw::c_ulong = 0;
        let mut nullifier_hash = [0u8; 32];
        let mut binding_hash = [0u8; 32];

        let ret = run_mdoc_prover(
            circuit.bytes.as_ptr(),
            circuit.bytes.len() as std::os::raw::c_ulong,
            mdoc_bytes.as_ptr(),
            mdoc_bytes.len() as std::os::raw::c_ulong,
            pkx.as_ptr(),
            pky.as_ptr(),
            session_transcript.as_ptr(),
            session_transcript.len() as std::os::raw::c_ulong,
            c_attrs.as_ptr(),
            c_attrs.len() as std::os::raw::c_ulong,
            now_c.as_ptr(),
            contract_hash.as_ptr(),
            &mut proof_ptr,
            &mut proof_len,
            nullifier_hash.as_mut_ptr(),
            binding_hash.as_mut_ptr(),
            spec,
        );

        if ret != MdocProverErrorCode_MDOC_PROVER_SUCCESS {
            return Err(MdocError::ProverFailed(ret as u32));
        }

        let proof_bytes = std::slice::from_raw_parts(proof_ptr, proof_len as usize).to_vec();
        libc::free(proof_ptr as *mut libc::c_void);

        Ok(MdocProof {
            proof_bytes,
            nullifier_hash,
            binding_hash,
            circuit_spec_index: circuit.spec_index,
        })
    }
}

/// Verify an mdoc proof (including nullifier).
pub fn verify(
    circuit: &MdocCircuit,
    proof: &MdocProof,
    issuer_pk_x: &str,
    issuer_pk_y: &str,
    session_transcript: &[u8],
    attributes: &[AttributeRequest],
    now: &str,
    doc_type: &str,
    contract_hash: &[u8; 8],
) -> Result<(), MdocError> {
    let c_attrs: Vec<RequestedAttribute> = attributes
        .iter()
        .map(|a| make_attribute(&a.namespace, &a.identifier, &a.cbor_value, a.verify_type))
        .collect();

    let pkx = CString::new(issuer_pk_x)
        .map_err(|e| MdocError::InvalidInput(e.to_string()))?;
    let pky = CString::new(issuer_pk_y)
        .map_err(|e| MdocError::InvalidInput(e.to_string()))?;
    let now_c = CString::new(now)
        .map_err(|e| MdocError::InvalidInput(e.to_string()))?;
    let doc_type_c = CString::new(doc_type)
        .map_err(|e| MdocError::InvalidInput(e.to_string()))?;

    unsafe {
        let spec = kZkSpecs.as_ptr().add(circuit.spec_index);

        let ret = run_mdoc_verifier(
            circuit.bytes.as_ptr(),
            circuit.bytes.len() as std::os::raw::c_ulong,
            pkx.as_ptr(),
            pky.as_ptr(),
            session_transcript.as_ptr(),
            session_transcript.len() as std::os::raw::c_ulong,
            c_attrs.as_ptr(),
            c_attrs.len() as std::os::raw::c_ulong,
            now_c.as_ptr(),
            contract_hash.as_ptr(),
            proof.nullifier_hash.as_ptr(),
            proof.binding_hash.as_ptr(),
            proof.proof_bytes.as_ptr(),
            proof.proof_bytes.len() as std::os::raw::c_ulong,
            doc_type_c.as_ptr(),
            spec,
        );

        if ret != MdocVerifierErrorCode_MDOC_VERIFIER_SUCCESS {
            return Err(MdocError::VerifierFailed(ret as u32));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_generation_1_attr() {
        let circuit = MdocCircuit::generate(1).unwrap();
        assert_eq!(circuit.num_attributes(), 1);
        assert!(circuit.bytes.len() > 100_000);
    }

    #[test]
    fn circuit_generation_invalid() {
        assert!(MdocCircuit::generate(0).is_err());
        assert!(MdocCircuit::generate(5).is_err());
    }

    #[test]
    fn prove_with_null_mdoc_fails() {
        let circuit = MdocCircuit::generate(1).unwrap();
        let attrs = vec![AttributeRequest {
            namespace: "org.iso.18013.5.1".into(),
            identifier: "age_over_18".into(),
            cbor_value: vec![0xf5],
            verify_type: VerifyType::Eq,
        }];

        let result = prove(
            &circuit,
            &[], // empty mdoc
            "00",
            "00",
            &[],
            &attrs,
            "2026-01-01T00:00:00Z",
            &[0u8; 8],
        );

        assert!(result.is_err());
    }
}
