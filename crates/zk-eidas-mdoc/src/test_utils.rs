//! Test utilities for building synthetic ECDSA-signed mdoc credentials.

use ciborium::Value;
use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use sha2::{Digest, Sha256};
use zk_eidas_types::credential::ClaimValue;

/// Build a synthetic mdoc with a real ECDSA (ES256/P-256) COSE_Sign1 signature.
///
/// Returns `(mdoc_cbor_bytes, pub_key_x, pub_key_y)`.
pub fn build_ecdsa_signed_mdoc(
    claims: Vec<(&str, ClaimValue)>,
    _issuer: &str,
) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::rngs::OsRng;

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let pub_key_x: [u8; 32] = point.x().unwrap().as_slice().try_into().unwrap();
    let pub_key_y: [u8; 32] = point.y().unwrap().as_slice().try_into().unwrap();

    // Build IssuerSignedItems and compute ValueDigests
    let mut items = Vec::new();
    let mut value_digests = Vec::new();

    for (i, (name, val)) in claims.iter().enumerate() {
        let random_salt = vec![i as u8; 16]; // deterministic salt for testing
        let cbor_value = claim_to_cbor(val);

        let item = Value::Map(vec![
            (
                Value::Text("digestID".into()),
                Value::Integer((i as i64).into()),
            ),
            (Value::Text("random".into()), Value::Bytes(random_salt)),
            (
                Value::Text("elementIdentifier".into()),
                Value::Text(name.to_string()),
            ),
            (Value::Text("elementValue".into()), cbor_value),
        ]);

        // CBOR-encode the item for digest computation
        let mut item_cbor = Vec::new();
        ciborium::into_writer(&item, &mut item_cbor).unwrap();

        // SHA-256 of the CBOR-encoded IssuerSignedItem
        let digest: [u8; 32] = Sha256::digest(&item_cbor).into();
        value_digests.push((i as i64, digest));

        items.push(item);
    }

    // Build MSO
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
                Value::Map(
                    value_digests
                        .iter()
                        .map(|(id, hash)| {
                            (Value::Integer((*id).into()), Value::Bytes(hash.to_vec()))
                        })
                        .collect(),
                ),
            )]),
        ),
    ]);

    let mut mso_bytes = Vec::new();
    ciborium::into_writer(&mso, &mut mso_bytes).unwrap();

    // Build COSE_Sign1 envelope
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .build();

    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(mso_bytes)
        .try_create_signature(b"", |tbs_data| {
            // Sign the Sig_structure bytes with P-256
            let sig: Signature = signing_key.sign(tbs_data);
            // Low-S normalization (BIP-0062) — required for Noir ACVM compatibility.
            // ~50% of P-256 signatures have high-S and fail without this.
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok::<_, Box<dyn std::error::Error>>(sig.to_bytes().to_vec())
        })
        .unwrap()
        .build();

    let cose_bytes = cose.to_vec().unwrap();

    // Build the full mdoc structure
    let doc = Value::Map(vec![(
        Value::Text("issuerSigned".into()),
        Value::Map(vec![
            (
                Value::Text("nameSpaces".into()),
                Value::Map(vec![(
                    Value::Text("org.iso.18013.5.1".into()),
                    Value::Array(items),
                )]),
            ),
            (Value::Text("issuerAuth".into()), Value::Bytes(cose_bytes)),
        ]),
    )]);

    let root = Value::Map(vec![(
        Value::Text("documents".into()),
        Value::Array(vec![doc]),
    )]);

    let mut mdoc_bytes = Vec::new();
    ciborium::into_writer(&root, &mut mdoc_bytes).unwrap();

    (mdoc_bytes, pub_key_x, pub_key_y)
}

fn claim_to_cbor(val: &ClaimValue) -> Value {
    match val {
        ClaimValue::String(s) => Value::Text(s.clone()),
        ClaimValue::Integer(i) => Value::Integer((*i).into()),
        ClaimValue::Boolean(b) => Value::Bool(*b),
        ClaimValue::Date { year, month, day } => {
            Value::Text(format!("{year:04}-{month:02}-{day:02}"))
        }
    }
}
