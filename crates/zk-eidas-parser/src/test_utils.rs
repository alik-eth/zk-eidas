use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Build a synthetic SD-JWT VC for testing purposes.
///
/// Takes a JSON object of claims and an issuer string, creates disclosures
/// for each claim, and returns a properly formatted SD-JWT string.
pub fn build_synthetic_sdjwt(claims: serde_json::Value, issuer: &str) -> String {
    let obj = claims.as_object().expect("claims must be a JSON object");

    let mut disclosures = Vec::new();
    let mut sd_hashes = Vec::new();

    for (key, value) in obj {
        // Create disclosure: [salt, key, value]
        let salt = format!("salt_{}", key);
        let disclosure_arr = serde_json::json!([salt, key, value]);
        let disclosure_json = serde_json::to_string(&disclosure_arr).unwrap();
        let encoded_disclosure = URL_SAFE_NO_PAD.encode(disclosure_json.as_bytes());

        // Compute SHA-256 hash of the encoded disclosure
        let hash = Sha256::digest(encoded_disclosure.as_bytes());
        let hash_b64 = URL_SAFE_NO_PAD.encode(hash);
        sd_hashes.push(serde_json::Value::String(hash_b64));

        disclosures.push(encoded_disclosure);
    }

    // Build JWT payload (no cnf.jwk — synthetic JWTs use Opaque signature)
    let payload = serde_json::json!({
        "iss": issuer,
        "iat": 1700000000,
        "exp": 1800000000,
        "vct": "urn:eudi:pid:1",
        "_sd_alg": "sha-256",
        "_sd": sd_hashes,
    });

    // Build header
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "dc+sd-jwt",
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());

    // Dummy 64-byte signature
    let dummy_sig = vec![0u8; 64];
    let sig_b64 = URL_SAFE_NO_PAD.encode(&dummy_sig);

    let jwt = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let mut result = jwt;
    for d in &disclosures {
        result.push('~');
        result.push_str(d);
    }
    result.push('~');

    result
}

/// Build an SD-JWT VC with a real ECDSA (ES256/P-256) signature for integration testing.
///
/// Returns `(sdjwt_string, signing_key_bytes)` so tests can verify the full chain.
pub fn build_ecdsa_signed_sdjwt(claims: serde_json::Value, issuer: &str) -> (String, Vec<u8>) {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::rngs::OsRng;

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x_bytes = point.x().unwrap().as_slice();
    let y_bytes = point.y().unwrap().as_slice();

    let obj = claims.as_object().expect("claims must be a JSON object");

    let mut disclosures = Vec::new();
    let mut sd_hashes = Vec::new();

    for (key, value) in obj {
        let salt = format!("salt_{}", key);
        let disclosure_arr = serde_json::json!([salt, key, value]);
        let disclosure_json = serde_json::to_string(&disclosure_arr).unwrap();
        let encoded_disclosure = URL_SAFE_NO_PAD.encode(disclosure_json.as_bytes());
        let hash = Sha256::digest(encoded_disclosure.as_bytes());
        let hash_b64 = URL_SAFE_NO_PAD.encode(hash);
        sd_hashes.push(serde_json::Value::String(hash_b64));
        disclosures.push(encoded_disclosure);
    }

    let payload = serde_json::json!({
        "iss": issuer,
        "iat": 1700000000,
        "exp": 1800000000,
        "vct": "urn:eudi:pid:1",
        "_sd_alg": "sha-256",
        "_sd": sd_hashes,
        "cnf": {
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(x_bytes),
                "y": URL_SAFE_NO_PAD.encode(y_bytes),
            }
        }
    });

    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "dc+sd-jwt",
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    // IMPORTANT: Normalize signature to low-S form (s <= n/2).
    //
    // The `ecdsa` crate's `sign_prehashed()` does NOT normalize S after signing,
    // so ~50% of signatures will have high-S values. However, the Noir ACVM
    // blackbox solver (`acvm_blackbox_solver::ecdsa::secp256r1::verify_signature`)
    // enforces BIP-0062 low-S normalization and returns `false` for high-S
    // signatures. This causes the circuit's `assert(valid_sig)` to fail with
    // "Failed assertion" during proof generation — an intermittent ~50% failure
    // rate that depends on the random signing key.
    let signature = signature.normalize_s().unwrap_or(signature);
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    let jwt = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    let mut result = jwt;
    for d in &disclosures {
        result.push('~');
        result.push_str(d);
    }
    result.push('~');

    (result, signing_key.to_bytes().to_vec())
}
