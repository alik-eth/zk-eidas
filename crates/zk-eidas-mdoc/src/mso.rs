use std::collections::BTreeMap;

use crate::MdocError;

/// Parsed MSO (Mobile Security Object).
#[derive(Debug)]
pub(crate) struct Mso {
    /// All ValueDigests across all namespaces, keyed by digestID.
    pub value_digests: BTreeMap<i64, [u8; 32]>,
}

/// Parse MSO CBOR bytes and extract ValueDigests.
pub(crate) fn parse_mso(mso_bytes: &[u8]) -> Result<Mso, MdocError> {
    let root: ciborium::Value =
        ciborium::from_reader(mso_bytes).map_err(|e| MdocError::CborDecode(e.to_string()))?;

    let root_map = root
        .as_map()
        .ok_or_else(|| MdocError::InvalidStructure("MSO is not a map".into()))?;

    let digest_alg = crate::find_in_map(root_map, "digestAlgorithm")
        .and_then(|v| v.as_text())
        .ok_or_else(|| MdocError::InvalidStructure("MSO missing digestAlgorithm".into()))?
        .to_string();

    if digest_alg != "SHA-256" {
        return Err(MdocError::InvalidStructure(format!(
            "unsupported digest algorithm: {digest_alg} (only SHA-256 supported)"
        )));
    }

    let vd_val = crate::find_in_map(root_map, "valueDigests")
        .ok_or_else(|| MdocError::InvalidStructure("MSO missing valueDigests".into()))?;

    let vd_map = vd_val
        .as_map()
        .ok_or_else(|| MdocError::InvalidStructure("valueDigests is not a map".into()))?;

    let mut value_digests = BTreeMap::new();

    for (_ns_key, ns_val) in vd_map {
        let ns_digests = ns_val
            .as_map()
            .ok_or_else(|| MdocError::InvalidStructure("namespace digests is not a map".into()))?;

        for (id_val, hash_val) in ns_digests {
            let digest_id: i64 = id_val
                .as_integer()
                .ok_or_else(|| MdocError::InvalidStructure("digestID is not an integer".into()))?
                .try_into()
                .map_err(|_| MdocError::InvalidStructure("digestID out of range".into()))?;

            let hash_bytes = hash_val
                .as_bytes()
                .ok_or_else(|| MdocError::InvalidStructure("digest value is not bytes".into()))?;

            if hash_bytes.len() != 32 {
                return Err(MdocError::InvalidStructure(format!(
                    "digest must be 32 bytes, got {}",
                    hash_bytes.len()
                )));
            }

            let mut hash: [u8; 32] = [0u8; 32];
            hash.copy_from_slice(hash_bytes);
            value_digests.insert(digest_id, hash);
        }
    }

    Ok(Mso {
        value_digests,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_value_digests_from_mso() {
        use ciborium::Value;

        let digest0 = vec![0xAA; 32];
        let digest1 = vec![0xBB; 32];

        let mso = Value::Map(vec![
            (Value::Text("version".into()), Value::Text("1.0".into())),
            (
                Value::Text("digestAlgorithm".into()),
                Value::Text("SHA-256".into()),
            ),
            (
                Value::Text("valueDigests".into()),
                Value::Map(vec![(
                    Value::Text("org.iso.18013.5.1".into()),
                    Value::Map(vec![
                        (Value::Integer(0.into()), Value::Bytes(digest0.clone())),
                        (Value::Integer(1.into()), Value::Bytes(digest1.clone())),
                    ]),
                )]),
            ),
        ]);

        let mut mso_bytes = Vec::new();
        ciborium::into_writer(&mso, &mut mso_bytes).unwrap();

        let parsed = parse_mso(&mso_bytes).unwrap();
        assert_eq!(parsed.value_digests.len(), 2);

        let d0: [u8; 32] = digest0.try_into().unwrap();
        let d1: [u8; 32] = digest1.try_into().unwrap();
        assert_eq!(parsed.value_digests.get(&0), Some(&d0));
        assert_eq!(parsed.value_digests.get(&1), Some(&d1));
    }

    #[test]
    fn rejects_unsupported_digest_algorithm() {
        use ciborium::Value;

        let mso = Value::Map(vec![
            (
                Value::Text("digestAlgorithm".into()),
                Value::Text("SHA-512".into()),
            ),
            (Value::Text("valueDigests".into()), Value::Map(vec![])),
        ]);

        let mut mso_bytes = Vec::new();
        ciborium::into_writer(&mso, &mut mso_bytes).unwrap();

        let err = parse_mso(&mso_bytes).unwrap_err();
        assert!(matches!(err, MdocError::InvalidStructure(_)));
    }
}
