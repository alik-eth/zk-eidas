use crate::MdocError;
use coset::{CborSerializable, CoseSign1};
use sha2::{Digest, Sha256};

fn cbor_encode(val: &ciborium::Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf).expect("CBOR encoding failed");
    buf
}

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

/// Extract fields from a COSE_Sign1 represented as an inline CBOR array
/// `[protected_bytes, unprotected_map, payload_bytes, signature_bytes]`.
///
/// This is the ISO 18013-5 format where issuerAuth is a CBOR array, not
/// opaque tagged bytes.
pub(crate) fn extract_cose_sign1_from_array(
    arr: &[ciborium::Value],
) -> Result<CoseSign1Extracted, MdocError> {
    if arr.len() != 4 {
        return Err(MdocError::InvalidStructure(format!(
            "COSE_Sign1 array must have 4 elements, got {}",
            arr.len()
        )));
    }

    let protected_bytes = arr[0]
        .as_bytes()
        .ok_or_else(|| MdocError::InvalidStructure("COSE_Sign1[0] (protected) is not bytes".into()))?;

    // arr[2] is the payload — it can be raw Tag-24 wrapped MSO bytes
    let payload_bytes = arr[2]
        .as_bytes()
        .ok_or_else(|| MdocError::InvalidStructure("COSE_Sign1[2] (payload) is not bytes".into()))?;

    // The payload is Tag-24 wrapped MSO: D8 18 59 <len2> <mso_cbor>
    // We need to unwrap it to get the raw MSO bytes.
    let mso_payload = unwrap_tag24_bytes(payload_bytes)?;

    let signature = arr[3]
        .as_bytes()
        .ok_or_else(|| MdocError::InvalidStructure("COSE_Sign1[3] (signature) is not bytes".into()))?
        .clone();

    if signature.len() != 64 {
        return Err(MdocError::InvalidStructure(format!(
            "COSE signature must be 64 bytes (ES256), got {}",
            signature.len()
        )));
    }

    // Reconstruct the Sig_structure for hash computation:
    // ["Signature1", protected_bytes, external_aad, payload]
    let sig_structure = ciborium::Value::Array(vec![
        ciborium::Value::Text("Signature1".into()),
        ciborium::Value::Bytes(protected_bytes.clone()),
        ciborium::Value::Bytes(vec![]),
        ciborium::Value::Bytes(payload_bytes.clone()),
    ]);
    let tbs = cbor_encode(&sig_structure);
    let message_hash: [u8; 32] = Sha256::digest(&tbs).into();

    Ok(CoseSign1Extracted {
        signature,
        message_hash,
        payload: mso_payload,
    })
}

/// Unwrap Tag-24 encoded bytes: skip the D8 18 (58 XX | 59 XX XX) prefix
/// to extract the inner CBOR bytes.
fn unwrap_tag24_bytes(data: &[u8]) -> Result<Vec<u8>, MdocError> {
    // The payload bytes may already be the raw tag-24 encoding:
    // D8 18 58 XX <data>  (1-byte length, total prefix = 4 bytes)
    // D8 18 59 XX XX <data>  (2-byte length, total prefix = 5 bytes)
    if data.len() >= 4 && data[0] == 0xD8 && data[1] == 0x18 {
        if data[2] == 0x58 {
            let len = data[3] as usize;
            if data.len() >= 4 + len {
                return Ok(data[4..4 + len].to_vec());
            }
        } else if data[2] == 0x59 && data.len() >= 5 {
            let len = ((data[3] as usize) << 8) | (data[4] as usize);
            if data.len() >= 5 + len {
                return Ok(data[5..5 + len].to_vec());
            }
        }
    }
    // Not tag-24 wrapped, return as-is (could be raw MSO bytes)
    Ok(data.to_vec())
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
