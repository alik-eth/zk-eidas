//! WebAssembly bindings for zk-eidas proof inspection and envelope decoding.
//!
//! Provides browser-side utilities for parsing proofs, decoding CBOR envelopes,
//! and nullifier deduplication.

use wasm_bindgen::prelude::*;
use zk_eidas_types::proof::ZkProof;
use zk_eidas_types::credential::bytes_to_u64;
use zk_eidas_types::to_43bit_limbs;
use sha2::{Sha256, Digest};

/// Parse a ZK proof from JSON and return proof metadata as JSON.
///
/// Returns: { "predicateOp": string, "hasNullifier": bool, "nullifier": string|null,
///            "proofSize": number, "version": number, "hasEcdsaCommitment": bool }
///
/// Note: Full verification requires snarkjs / native FFI which doesn't compile
/// to wasm32. This function provides proof inspection/parsing in the browser.
#[wasm_bindgen]
pub fn parse_proof(proof_json: &str) -> Result<String, JsError> {
    let proof: ZkProof = serde_json::from_str(proof_json)
        .map_err(|e| JsError::new(&format!("invalid proof JSON: {e}")))?;

    let nullifier_hex = proof.nullifier().map(hex::encode);

    let is_escrow = proof.predicate_op() == zk_eidas_types::predicate::PredicateOp::IdentityEscrow;

    let result = serde_json::json!({
        "predicateOp": format!("{:?}", proof.predicate_op()),
        "hasNullifier": proof.nullifier().is_some(),
        "nullifier": nullifier_hex,
        "proofSize": proof.proof_bytes().len(),
        "version": proof.version(),
        "hasEcdsaCommitment": proof.ecdsa_commitment().is_some(),
        "isIdentityEscrow": is_escrow,
    });

    Ok(result.to_string())
}

/// Decode a ProofEnvelope from CBOR bytes and return its contents as JSON.
#[wasm_bindgen]
pub fn decode_envelope(cbor_bytes: &[u8]) -> Result<String, JsError> {
    let envelope = zk_eidas_types::envelope::ProofEnvelope::from_bytes(cbor_bytes)
        .map_err(|e| JsError::new(&e))?;

    let proofs: Vec<serde_json::Value> = envelope
        .proofs()
        .iter()
        .map(|p| {
            serde_json::json!({
                "predicate": p.predicate,
                "op": p.op,
                "proofSize": p.proof_bytes.len(),
            })
        })
        .collect();

    let result = serde_json::json!({
        "version": envelope.version(),
        "proofs": proofs,
    });

    Ok(result.to_string())
}

/// Check if a nullifier has been seen before (client-side dedup).
/// Takes a JSON array of known nullifiers and a new nullifier hex string.
/// Returns true if the nullifier is already in the list.
#[wasm_bindgen]
pub fn check_nullifier_duplicate(
    known_nullifiers_json: &str,
    nullifier_hex: &str,
) -> Result<bool, JsError> {
    let known: Vec<String> = serde_json::from_str(known_nullifiers_json)
        .map_err(|e| JsError::new(&format!("invalid nullifier list: {e}")))?;

    Ok(known.iter().any(|n| n == nullifier_hex))
}

/// Parse an mdoc token ("mdoc:<base64>:<hex_x>:<hex_y>") into a Credential.
fn parse_mdoc_credential(token: &str) -> Result<zk_eidas_types::credential::Credential, JsError> {
    use base64::Engine;
    let parts: Vec<&str> = token.splitn(4, ':').collect();
    if parts.len() != 4 || parts[0] != "mdoc" {
        return Err(JsError::new("expected mdoc:<base64>:<hex_x>:<hex_y>"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|e| JsError::new(&format!("mdoc base64 decode: {e}")))?;
    let pub_key_x: [u8; 32] = hex::decode(parts[2])
        .map_err(|e| JsError::new(&format!("mdoc hex x: {e}")))?
        .try_into()
        .map_err(|_| JsError::new("pub_key_x must be 32 bytes"))?;
    let pub_key_y: [u8; 32] = hex::decode(parts[3])
        .map_err(|e| JsError::new(&format!("mdoc hex y: {e}")))?
        .try_into()
        .map_err(|_| JsError::new("pub_key_y must be 32 bytes"))?;

    zk_eidas_mdoc::MdocParser::parse_with_issuer_key(&bytes, pub_key_x, pub_key_y)
        .map_err(|e| JsError::new(&format!("mdoc parse: {e}")))
}

/// Prepare ECDSA circuit inputs from a credential — fully client-side.
///
/// Accepts both SD-JWT and mdoc format credentials (auto-detected).
/// mdoc tokens use the format: "mdoc:<base64>:<hex_pubx>:<hex_puby>"
///
/// Returns JSON: { "ecdsa_inputs": {...}, "claim_value": "..." }
#[wasm_bindgen]
pub fn prepare_inputs(credential_token: &str, claim_name: &str) -> Result<String, JsError> {
    let credential = if credential_token.starts_with("mdoc:") {
        parse_mdoc_credential(credential_token)?
    } else {
        let parser = zk_eidas_parser::SdJwtParser::new();
        parser.parse(credential_token)
            .map_err(|e| JsError::new(&format!("SD-JWT parse error: {e}")))?
    };

    let sig_data = match credential.signature_data() {
        zk_eidas_types::credential::SignatureData::Ecdsa {
            pub_key_x, pub_key_y, signature, message_hash, sd_claims_hashes,
        } => (pub_key_x, pub_key_y, signature, message_hash, sd_claims_hashes),
        _ => return Err(JsError::new("credential has no ECDSA signature data")),
    };

    let (pub_key_x, pub_key_y, signature, message_hash, sd_claims_hashes) = sig_data;

    // Check claim exists
    let claim_value = credential.claims().get(claim_name)
        .ok_or_else(|| JsError::new(&format!("claim '{claim_name}' not found")))?;

    // Check disclosure exists
    let disclosure = credential.disclosures().get(claim_name)
        .ok_or_else(|| JsError::new(&format!("no disclosure for claim '{claim_name}'")))?;

    // Convert claim to u64
    let claim_u64 = claim_value.to_circuit_u64();

    // Compute disclosure hash
    let disclosure_hash_bytes: [u8; 32] = Sha256::digest(disclosure).into();
    let disclosure_hash = bytes_to_u64(&disclosure_hash_bytes);

    // Build sd_array
    let mut sd_array = [0u64; 16];
    for (i, hash) in sd_claims_hashes.iter().take(16).enumerate() {
        sd_array[i] = bytes_to_u64(hash);
    }

    // Split signature
    let mut sig_r = [0u8; 32];
    let mut sig_s = [0u8; 32];
    sig_r.copy_from_slice(&signature[..32]);
    sig_s.copy_from_slice(&signature[32..]);

    // Build circuit input JSON
    let r_limbs = to_43bit_limbs(&sig_r);
    let s_limbs = to_43bit_limbs(&sig_s);
    let msg_limbs = to_43bit_limbs(message_hash);
    let pkx_limbs = to_43bit_limbs(pub_key_x);
    let pky_limbs = to_43bit_limbs(pub_key_y);

    let to_strings = |limbs: &[num_bigint::BigInt; 6]| -> Vec<String> {
        limbs.iter().map(|l| l.to_string()).collect()
    };

    let ecdsa_inputs = serde_json::json!({
        "signature_r": to_strings(&r_limbs),
        "signature_s": to_strings(&s_limbs),
        "message_hash": to_strings(&msg_limbs),
        "pub_key_x": to_strings(&pkx_limbs),
        "pub_key_y": to_strings(&pky_limbs),
        "claim_value": claim_u64.to_string(),
        "disclosure_hash": disclosure_hash.to_string(),
        "sd_array": sd_array.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
    });

    let result = serde_json::json!({
        "ecdsa_inputs": ecdsa_inputs,
        "claim_value": claim_u64.to_string(),
    });

    Ok(result.to_string())
}


#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn wasm_parse_proof_valid() {
        let json = serde_json::json!({
            "proof_bytes": [1, 2, 3, 4],
            "public_inputs": [],
            "verification_key": [10, 20, 30],
            "predicate_op": "Gte",
            "nullifier": null,
            "version": 2
        });
        let result = parse_proof(&json.to_string()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["predicateOp"], "Gte");
        assert_eq!(parsed["hasNullifier"], false);
        assert_eq!(parsed["proofSize"], 4);
        assert_eq!(parsed["version"], 2);
        assert_eq!(parsed["hasEcdsaCommitment"], false);
    }

    #[wasm_bindgen_test]
    fn wasm_parse_proof_invalid_json_returns_error() {
        let result = parse_proof("not json");
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_parse_proof_with_nullifier() {
        let json = serde_json::json!({
            "proof_bytes": [1, 2],
            "public_inputs": [],
            "verification_key": [5],
            "predicate_op": "Nullifier",
            "nullifier": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,42]
        });
        let result = parse_proof(&json.to_string()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["hasNullifier"], true);
        assert!(parsed["nullifier"].as_str().unwrap().ends_with("2a"));
    }

    #[wasm_bindgen_test]
    fn wasm_check_nullifier_duplicate_found() {
        let known = r#"["0xabc123","0xdef456"]"#;
        assert!(check_nullifier_duplicate(known, "0xabc123").unwrap());
    }

    #[wasm_bindgen_test]
    fn wasm_check_nullifier_duplicate_not_found() {
        let known = r#"["0xabc123","0xdef456"]"#;
        assert!(!check_nullifier_duplicate(known, "0x999999").unwrap());
    }

    #[wasm_bindgen_test]
    fn wasm_check_nullifier_duplicate_empty() {
        assert!(!check_nullifier_duplicate("[]", "0xabc").unwrap());
    }

    #[wasm_bindgen_test]
    fn wasm_check_nullifier_invalid_returns_error() {
        assert!(check_nullifier_duplicate("not json", "x").is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_decode_envelope_invalid_returns_error() {
        assert!(decode_envelope(&[0xFF, 0xFF]).is_err());
    }

    #[wasm_bindgen_test]
    fn wasm_decode_envelope_valid() {
        use zk_eidas_types::envelope::ProofEnvelope;
        use zk_eidas_types::predicate::PredicateOp;

        let proof = ZkProof::new(vec![1, 2, 3], vec![], vec![6, 7], PredicateOp::Gte);
        let envelope = ProofEnvelope::from_proofs(&[proof], &["age >= 18".to_string()]);
        let cbor = envelope.to_bytes().unwrap();

        let result = decode_envelope(&cbor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["proofs"].as_array().unwrap().len(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proof_valid() {
        let json = serde_json::json!({
            "proof_bytes": [1, 2, 3, 4],
            "public_inputs": [],
            "verification_key": [10, 20, 30],
            "predicate_op": "Gte",
            "nullifier": null,
            "version": 2
        });
        let result = parse_proof(&json.to_string()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["predicateOp"], "Gte");
        assert_eq!(parsed["hasNullifier"], false);
        assert_eq!(parsed["proofSize"], 4);
        assert_eq!(parsed["version"], 2);
        assert_eq!(parsed["hasEcdsaCommitment"], false);
    }

    // On non-wasm targets, JsError::new() panics instead of returning Err,
    // so error-path tests use #[should_panic].
    #[test]
    #[should_panic(expected = "cannot call wasm-bindgen imported functions on non-wasm targets")]
    fn parse_proof_invalid_json() {
        let _ = parse_proof("not json");
    }

    #[test]
    fn parse_proof_with_nullifier() {
        let json = serde_json::json!({
            "proof_bytes": [1, 2],
            "public_inputs": [],
            "verification_key": [5],
            "predicate_op": "Nullifier",
            "nullifier": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        });
        let result = parse_proof(&json.to_string()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["hasNullifier"], true);
    }

    #[test]
    fn check_nullifier_duplicate_found() {
        let known = r#"["0xabc123","0xdef456"]"#;
        assert!(check_nullifier_duplicate(known, "0xabc123").unwrap());
    }

    #[test]
    fn check_nullifier_duplicate_not_found() {
        let known = r#"["0xabc123","0xdef456"]"#;
        assert!(!check_nullifier_duplicate(known, "0x999999").unwrap());
    }

    #[test]
    fn check_nullifier_duplicate_empty_list() {
        let known = r#"[]"#;
        assert!(!check_nullifier_duplicate(known, "0xabc123").unwrap());
    }

    #[test]
    #[should_panic(expected = "cannot call wasm-bindgen imported functions on non-wasm targets")]
    fn check_nullifier_duplicate_invalid_json() {
        let _ = check_nullifier_duplicate("not json", "0xabc");
    }

    #[test]
    #[should_panic(expected = "cannot call wasm-bindgen imported functions on non-wasm targets")]
    fn decode_envelope_invalid_cbor() {
        let _ = decode_envelope(&[0xFF, 0xFF]);
    }

    #[test]
    fn decode_envelope_valid() {
        use zk_eidas_types::envelope::ProofEnvelope;
        use zk_eidas_types::predicate::PredicateOp;

        let proof = ZkProof::new(vec![1, 2, 3], vec![], vec![6, 7], PredicateOp::Gte);
        let envelope = ProofEnvelope::from_proofs(&[proof], &["age >= 18".to_string()]);
        let cbor = envelope.to_bytes().unwrap();

        let result = decode_envelope(&cbor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["version"], 1);
        assert_eq!(parsed["proofs"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["proofs"][0]["op"], "Gte");
    }
}
