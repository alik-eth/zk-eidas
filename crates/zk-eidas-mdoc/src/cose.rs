use crate::MdocError;
use coset::{CborSerializable, CoseSign1};
use sha2::{Digest, Sha256};

/// Extracted fields from a COSE_Sign1 structure.
#[derive(Debug)]
pub(crate) struct CoseSign1Extracted {
    /// Raw ECDSA signature bytes (64 bytes: r || s).
    pub signature: Vec<u8>,
    /// SHA-256 of the Sig_structure — the message hash for ECDSA verification.
    pub message_hash: [u8; 32],
    /// Raw payload bytes (the MSO).
    pub payload: Vec<u8>,
}

/// Parse COSE_Sign1 CBOR bytes and extract signature data.
pub(crate) fn extract_cose_sign1(cose_bytes: &[u8]) -> Result<CoseSign1Extracted, MdocError> {
    let cose = CoseSign1::from_slice(cose_bytes)
        .map_err(|e| MdocError::CborDecode(format!("COSE_Sign1 decode: {e}")))?;

    let signature = cose.signature.clone();
    if signature.len() != 64 {
        return Err(MdocError::InvalidStructure(format!(
            "COSE signature must be 64 bytes (ES256), got {}",
            signature.len()
        )));
    }

    let payload = cose
        .payload
        .clone()
        .ok_or_else(|| MdocError::InvalidStructure("COSE_Sign1 missing payload".into()))?;

    // Reconstruct Sig_structure and hash it.
    // Sig_structure = ["Signature1", protected, external_aad, payload]
    let sig_structure = cose.tbs_data(b""); // external_aad = empty
    let message_hash: [u8; 32] = Sha256::digest(&sig_structure).into();

    Ok(CoseSign1Extracted {
        signature,
        message_hash,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cose_sign1_fields() {
        use coset::{iana, CoseSign1Builder, HeaderBuilder};

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();
        let payload = b"test-mso-payload".to_vec();
        let fake_sig = vec![0xAA; 64];

        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload.clone())
            .try_create_signature(b"", |_| {
                Ok::<_, Box<dyn std::error::Error>>(fake_sig.clone())
            })
            .unwrap()
            .build();

        let cose_bytes = cose.to_vec().unwrap();
        let extracted = extract_cose_sign1(&cose_bytes).unwrap();

        assert_eq!(extracted.signature, &fake_sig[..]);
        assert_eq!(extracted.payload, payload);
        assert_eq!(extracted.signature.len(), 64);
    }

    #[test]
    fn message_hash_matches_manual_sig_structure() {
        use coset::{iana, CoseSign1Builder, HeaderBuilder};

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();
        let payload = b"mso-bytes".to_vec();

        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .try_create_signature(b"", |_| Ok::<_, Box<dyn std::error::Error>>(vec![0u8; 64]))
            .unwrap()
            .build();

        let tbs = cose.tbs_data(b"");
        let cose_bytes = cose.to_vec().unwrap();
        let extracted = extract_cose_sign1(&cose_bytes).unwrap();
        let expected_hash: [u8; 32] = Sha256::digest(&tbs).into();
        assert_eq!(extracted.message_hash, expected_hash);
    }

    #[test]
    fn rejects_wrong_signature_length() {
        use coset::{iana, CoseSign1Builder, HeaderBuilder};

        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();

        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(b"test".to_vec())
            .try_create_signature(b"", |_| Ok::<_, Box<dyn std::error::Error>>(vec![0u8; 32])) // wrong length
            .unwrap()
            .build();

        let cose_bytes = cose.to_vec().unwrap();
        let err = extract_cose_sign1(&cose_bytes).unwrap_err();
        assert!(matches!(err, MdocError::InvalidStructure(_)));
    }
}
