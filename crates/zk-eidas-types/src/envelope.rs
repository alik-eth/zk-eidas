use serde::{Deserialize, Serialize};

use crate::proof::{LogicalOp, ZkProof};

/// Compact envelope wrapping one or more proofs for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEnvelope {
    version: u8,
    proofs: Vec<EnvelopeProof>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    logical_op: Option<LogicalOp>,
}

/// A single proof entry within an envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeProof {
    /// Human-readable predicate description (e.g. "age >= 18").
    pub predicate: String,
    /// Raw proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Public inputs for verification.
    pub public_inputs: Vec<Vec<u8>>,
    /// Predicate operation name (e.g. "Gte", "Reveal").
    pub op: String,
    /// Claim name for revealed values (e.g. "document_number").
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revealed_claim: Option<String>,
    /// Plaintext value for revealed claims (e.g. "UA-1234567890").
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revealed_value: Option<String>,
}

impl ProofEnvelope {
    /// Create an envelope from ZkProofs with predicate descriptions.
    pub fn from_proofs(proofs: &[ZkProof], descriptions: &[String]) -> Self {
        let entries = proofs
            .iter()
            .zip(descriptions.iter())
            .map(|(proof, desc)| EnvelopeProof {
                predicate: desc.clone(),
                proof_bytes: proof.proof_bytes().to_vec(),
                public_inputs: proof.public_inputs().to_vec(),
                op: format!("{:?}", proof.predicate_op()),
                revealed_claim: None,
                revealed_value: None,
            })
            .collect();

        Self {
            version: 1,
            proofs: entries,
            logical_op: None,
        }
    }

    /// Create an envelope from ZkProofs with predicate descriptions and optional revealed values.
    pub fn from_proofs_with_reveals(
        proofs: &[ZkProof],
        descriptions: &[String],
        reveals: &[Option<(String, String)>],
    ) -> Self {
        let entries = proofs
            .iter()
            .zip(descriptions.iter())
            .enumerate()
            .map(|(i, (proof, desc))| {
                let reveal = reveals.get(i).and_then(|r| r.as_ref());
                EnvelopeProof {
                    predicate: desc.clone(),
                    proof_bytes: proof.proof_bytes().to_vec(),
                    public_inputs: proof.public_inputs().to_vec(),
                    op: format!("{:?}", proof.predicate_op()),
                    revealed_claim: reveal.map(|(c, _)| c.clone()),
                    revealed_value: reveal.map(|(_, v)| v.clone()),
                }
            })
            .collect();

        Self {
            version: 1,
            proofs: entries,
            logical_op: None,
        }
    }

    /// Serialize to compact CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| format!("CBOR encode failed: {e}"))?;
        Ok(buf)
    }

    /// Deserialize from CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(bytes).map_err(|e| format!("CBOR decode failed: {e}"))
    }

    /// Serialize to deflate-compressed CBOR bytes.
    pub fn to_compressed_bytes(&self) -> Result<Vec<u8>, String> {
        let cbor = self.to_bytes()?;
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&cbor)
            .map_err(|e| format!("Deflate write failed: {e}"))?;
        encoder
            .finish()
            .map_err(|e| format!("Deflate finish failed: {e}"))
    }

    /// Deserialize from deflate-compressed CBOR bytes.
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, String> {
        use flate2::read::DeflateDecoder;
        use std::io::Read;
        let mut decoder = DeflateDecoder::new(bytes);
        let mut cbor = Vec::new();
        decoder
            .read_to_end(&mut cbor)
            .map_err(|e| format!("Inflate failed: {e}"))?;
        Self::from_bytes(&cbor)
    }

    /// Returns the proof entries in this envelope.
    pub fn proofs(&self) -> &[EnvelopeProof] {
        &self.proofs
    }

    /// Returns the envelope format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the logical operator for compound proofs.
    pub fn logical_op(&self) -> Option<LogicalOp> {
        self.logical_op
    }

    /// Set the logical operator for compound proofs.
    pub fn set_logical_op(&mut self, op: Option<LogicalOp>) {
        self.logical_op = op;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::predicate::PredicateOp;

    #[test]
    fn roundtrip_cbor() {
        let proof = ZkProof::new(
            vec![1, 2, 3],
            vec![vec![4, 5]],
            vec![6, 7],
            PredicateOp::Gte,
        );
        let envelope = ProofEnvelope::from_proofs(&[proof], &["age >= 18".to_string()]);
        let bytes = envelope.to_bytes().unwrap();
        let decoded = ProofEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.version(), 1);
        assert_eq!(decoded.proofs().len(), 1);
        assert_eq!(decoded.proofs()[0].predicate, "age >= 18");
    }

    #[test]
    fn roundtrip_compressed_cbor() {
        let proof = ZkProof::new(
            vec![1; 1000],
            vec![vec![4, 5]],
            vec![6, 7],
            PredicateOp::Gte,
        );
        let envelope = ProofEnvelope::from_proofs(&[proof], &["age >= 18".to_string()]);
        let compressed = envelope.to_compressed_bytes().unwrap();
        let decompressed = ProofEnvelope::from_compressed_bytes(&compressed).unwrap();
        assert_eq!(decompressed.version(), 1);
        assert_eq!(decompressed.proofs().len(), 1);
        assert_eq!(decompressed.proofs()[0].predicate, "age >= 18");
        let raw = envelope.to_bytes().unwrap();
        assert!(compressed.len() < raw.len());
    }

    #[test]
    fn logical_op_preserved_in_cbor() {
        let proof = ZkProof::new(vec![1, 2, 3], vec![], vec![], PredicateOp::Gte);
        let mut envelope = ProofEnvelope::from_proofs(&[proof], &["test".to_string()]);
        envelope.set_logical_op(Some(LogicalOp::And));
        let bytes = envelope.to_bytes().unwrap();
        let decoded = ProofEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.logical_op(), Some(LogicalOp::And));
    }

    #[test]
    fn logical_op_none_for_single_proof() {
        let proof = ZkProof::new(vec![1], vec![], vec![], PredicateOp::Eq);
        let envelope = ProofEnvelope::from_proofs(&[proof], &["test".to_string()]);
        assert_eq!(envelope.logical_op(), None);
    }

    #[test]
    fn roundtrip_cbor_with_revealed_value() {
        let proof = ZkProof::new(
            vec![1, 2, 3],
            vec![vec![4, 5]],
            vec![6, 7],
            PredicateOp::Eq, // Will be PredicateOp::Reveal once Task 1 merges
        );
        let reveals = vec![Some(("document_number".to_string(), "UA-1234567890".to_string()))];
        let envelope = ProofEnvelope::from_proofs_with_reveals(
            &[proof],
            &["reveal document_number".to_string()],
            &reveals,
        );
        let bytes = envelope.to_bytes().unwrap();
        let decoded = ProofEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.proofs().len(), 1);
        assert_eq!(decoded.proofs()[0].revealed_claim.as_deref(), Some("document_number"));
        assert_eq!(decoded.proofs()[0].revealed_value.as_deref(), Some("UA-1234567890"));
    }

    #[test]
    fn from_proofs_has_no_revealed_values() {
        let proof = ZkProof::new(vec![1], vec![], vec![5], PredicateOp::Gte);
        let envelope = ProofEnvelope::from_proofs(&[proof], &["age >= 18".to_string()]);
        assert!(envelope.proofs()[0].revealed_claim.is_none());
        assert!(envelope.proofs()[0].revealed_value.is_none());
    }
}
