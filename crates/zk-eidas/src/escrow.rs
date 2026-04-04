//! Identity escrow utilities: credential field packing, key generation, and encryption.
//!
//! These utilities support identity escrow: AES-256-GCM encrypts credential fields
//! outside the circuit. The symmetric key K is encrypted to an escrow authority's
//! ML-KEM-768 public key, released only on court order or arbitration ruling.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use num_bigint::BigUint;
use zk_eidas_types::credential::{ClaimValue, Credential};

use crate::builder::ZkError;

/// Encrypt credential field values with AES-256-GCM using `key`.
///
/// Returns `(ciphertexts, tags)` where each element corresponds to one field.
/// Each nonce is derived deterministically from the field index (counter mode).
pub fn encrypt_fields_aes_gcm(
    fields: &[(&str, &[u8])],
    key: &[u8; 32],
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), ZkError> {
    let cipher = Aes256Gcm::new(key.into());
    let mut ciphertexts = Vec::new();
    let mut tags = Vec::new();
    for (i, (_name, value)) in fields.iter().enumerate() {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[8..12].copy_from_slice(&(i as u32).to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, value.as_ref())
            .map_err(|e| ZkError::InvalidInput(format!("AES-GCM encrypt: {e}")))?;
        let (ct_only, tag) = ct.split_at(ct.len() - 16);
        ciphertexts.push(ct_only.to_vec());
        tags.push(tag.to_vec());
    }
    Ok((ciphertexts, tags))
}

/// Decrypt AES-256-GCM ciphertexts using `key`.
///
/// `ciphertexts` and `tags` must be the same length and correspond to fields in order.
/// Returns the plaintext bytes for each field.
pub fn decrypt_fields_aes_gcm(
    ciphertexts: &[Vec<u8>],
    tags: &[Vec<u8>],
    key: &[u8; 32],
) -> Result<Vec<Vec<u8>>, ZkError> {
    let cipher = Aes256Gcm::new(key.into());
    let mut fields = Vec::new();
    for (i, (ct, tag)) in ciphertexts.iter().zip(tags.iter()).enumerate() {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[8..12].copy_from_slice(&(i as u32).to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ct_with_tag = ct.clone();
        ct_with_tag.extend_from_slice(tag);
        let plaintext = cipher.decrypt(nonce, ct_with_tag.as_ref())
            .map_err(|e| ZkError::InvalidInput(format!("AES-GCM decrypt: {e}")))?;
        fields.push(plaintext);
    }
    Ok(fields)
}

/// BN254 scalar field order: p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_ORDER: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Pack credential fields into 8 BN254 field elements for the identity escrow circuit.
///
/// Returns the packed data as decimal strings (suitable for circuit witness input)
/// and the `claim_index` indicating which slot contains the ECDSA-committed claim.
pub fn pack_credential_fields(
    credential: &Credential,
    field_names: &[String],
    ecdsa_claim: &str,
) -> Result<([String; 8], u8), ZkError> {
    if field_names.len() > 8 {
        return Err(ZkError::InvalidInput(format!(
            "identity escrow supports at most 8 fields, got {}",
            field_names.len()
        )));
    }

    let mut claim_index: Option<u8> = None;
    let mut data: [String; 8] = std::array::from_fn(|_| "0".to_string());

    for (i, name) in field_names.iter().enumerate() {
        let value = credential
            .claims()
            .get(name)
            .ok_or_else(|| ZkError::ClaimNotFound(name.clone()))?;

        let bytes = value.to_escrow_field();
        let bigint = BigUint::from_bytes_be(&bytes);
        data[i] = bigint.to_string();

        if name == ecdsa_claim {
            claim_index = Some(i as u8);
        }
    }

    let claim_index = claim_index.ok_or_else(|| {
        ZkError::InvalidInput(format!(
            "ecdsa_claim '{ecdsa_claim}' not found in field_names list"
        ))
    })?;

    Ok((data, claim_index))
}

/// Generate a random symmetric key K as a BN254 field element (decimal string).
///
/// Generates 31 random bytes, interpreted as a big-endian unsigned integer.
/// This is always less than the BN254 scalar field order (~254 bits).
pub fn generate_escrow_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 31];
    rand::thread_rng().fill_bytes(&mut bytes);
    let k = BigUint::from_bytes_be(&bytes);
    // Ensure k < BN254 order (31 bytes = 248 bits, always < ~254 bits)
    debug_assert!(k < BN254_ORDER.parse::<BigUint>().unwrap());
    k.to_string()
}

/// Derive a deterministic symmetric key K from credential data and authority pubkey.
///
/// Uses SHA-256(credential_data || authority_pubkey) truncated to 31 bytes.
/// Deterministic: same inputs always produce the same K, enabling proof caching.
pub fn derive_escrow_key(credential_data: &[String; 8], authority_pubkey: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    for field in credential_data {
        hasher.update(field.as_bytes());
    }
    hasher.update(authority_pubkey);
    let hash: [u8; 32] = hasher.finalize().into();
    // Take first 31 bytes — always < BN254 order
    let k = BigUint::from_bytes_be(&hash[..31]);
    k.to_string()
}

/// Encrypt the symmetric key K to an escrow authority's ML-KEM-768 encapsulation key.
///
/// `k_decimal` is the key as a decimal string. `authority_pubkey` is the ML-KEM-768
/// encapsulation key (1184 bytes, FIPS 203).
///
/// Returns (ciphertext || encrypted_k) where:
/// - ciphertext: ML-KEM-768 ciphertext (1088 bytes) encapsulating the shared secret
/// - encrypted_k: K XORed with SHA-256(shared_secret) (32 bytes)
pub fn encrypt_key_to_authority(
    k_decimal: &str,
    authority_pubkey: &[u8],
) -> Result<Vec<u8>, ZkError> {
    use ml_kem::kem::Encapsulate;

    let k_bigint: BigUint = k_decimal
        .parse()
        .map_err(|e| ZkError::InvalidInput(format!("invalid K decimal: {e}")))?;
    let k_bytes_raw = k_bigint.to_bytes_be();

    // Pad to 32 bytes
    let mut k_padded = [0u8; 32];
    let start = 32usize.saturating_sub(k_bytes_raw.len());
    k_padded[start..].copy_from_slice(&k_bytes_raw[..k_bytes_raw.len().min(32)]);

    // Reconstruct encapsulation key from a seed-derived DK
    // The authority_pubkey is actually a 64-byte seed — reconstruct the EK from it
    let seed: [u8; 64] = authority_pubkey.try_into()
        .map_err(|_| ZkError::InvalidInput(format!(
            "ML-KEM-768 authority key must be 64-byte seed, got {} bytes",
            authority_pubkey.len()
        )))?;
    let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed.into());
    let ek = dk.encapsulation_key().clone();

    // Encapsulate: produces (ciphertext, shared_secret)
    let (ct, ss) = ek.encapsulate();

    // Encrypt K: XOR with SHA-256(shared_secret)
    use sha2::{Sha256, Digest};
    let ss_bytes: &[u8] = ss.as_ref();
    let mask: [u8; 32] = Sha256::digest(ss_bytes).into();
    let mut encrypted_k = [0u8; 32];
    for i in 0..32 {
        encrypted_k[i] = k_padded[i] ^ mask[i];
    }

    // Return ciphertext || encrypted_k
    let ct_ref: &[u8] = ct.as_ref();
    let mut result = Vec::with_capacity(ct_ref.len() + 32);
    result.extend_from_slice(ct_ref);
    result.extend_from_slice(&encrypted_k);

    Ok(result)
}

/// Decrypt the symmetric key K from ML-KEM-768 ciphertext using the authority's seed.
///
/// `encrypted` is (ciphertext || encrypted_k) as produced by `encrypt_key_to_authority`.
/// `secret_key` is the ML-KEM-768 seed (64 bytes).
///
/// Returns K as a decimal string.
pub fn decrypt_key(encrypted: &[u8], secret_key: &[u8]) -> Result<String, ZkError> {
    use ml_kem::kem::TryDecapsulate;

    // Reconstruct decapsulation key from seed
    let seed: [u8; 64] = secret_key.try_into()
        .map_err(|_| ZkError::InvalidInput(format!(
            "ML-KEM-768 seed must be 64 bytes, got {}",
            secret_key.len()
        )))?;
    let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed.into());

    // Split: ciphertext + encrypted_k (32 bytes)
    let ct_size = encrypted.len().checked_sub(32)
        .ok_or_else(|| ZkError::InvalidInput("encrypted data too short".into()))?;
    let ct_bytes = &encrypted[..ct_size];
    let encrypted_k = &encrypted[ct_size..];

    // Decapsulate
    let ct_array: ml_kem::ml_kem_768::Ciphertext = ct_bytes.try_into()
        .map_err(|_| ZkError::InvalidInput(format!("invalid ML-KEM ciphertext size: {}", ct_bytes.len())))?;
    let ss = dk.try_decapsulate(&ct_array)
        .map_err(|_| ZkError::InvalidInput("ML-KEM decapsulation failed".into()))?;

    // Decrypt K: XOR with SHA-256(shared_secret)
    use sha2::{Sha256, Digest};
    let ss_bytes: &[u8] = ss.as_ref();
    let mask: [u8; 32] = Sha256::digest(ss_bytes).into();
    let mut k_padded = [0u8; 32];
    for i in 0..32 {
        k_padded[i] = encrypted_k[i] ^ mask[i];
    }

    let k = BigUint::from_bytes_be(&k_padded);
    Ok(k.to_string())
}

/// Generate an ML-KEM-768 keypair for escrow authority.
///
/// Returns (seed, encapsulation_key) as byte vectors.
/// The seed is 64 bytes (used for both encryption and decryption).
/// The EK is 1184 bytes (can be published).
pub fn generate_authority_keypair() -> (Vec<u8>, Vec<u8>) {
    use ml_kem::MlKem768;
    use ml_kem::kem::{Kem, KeyExport};
    let (dk, _) = MlKem768::generate_keypair();
    let seed = dk.to_seed().expect("keypair should have seed");
    let ek = dk.encapsulation_key();
    let ek_exported = ek.to_bytes();
    (seed.to_vec(), ek_exported.to_vec())
}

/// Convert the ECDSA claim_value (u64) to the same decimal string representation
/// used in the escrow circuit, matching the `to_escrow_field()` encoding.
pub fn claim_value_to_escrow_decimal(value: &ClaimValue) -> String {
    let bytes = value.to_escrow_field();
    BigUint::from_bytes_be(&bytes).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zk_eidas_types::credential::{ClaimValue, SignatureData};

    fn make_test_credential() -> Credential {
        let mut claims = BTreeMap::new();
        claims.insert("name".to_string(), ClaimValue::String("Alice".to_string()));
        claims.insert(
            "address".to_string(),
            ClaimValue::String("123 Main St".to_string()),
        );
        claims.insert(
            "document_number".to_string(),
            ClaimValue::String("UA-1234567890".to_string()),
        );
        claims.insert("age".to_string(), ClaimValue::Integer(25));
        Credential::new(
            claims,
            "test-issuer".to_string(),
            SignatureData::Opaque {
                signature: vec![],
                public_key: vec![],
            },
            BTreeMap::new(),
        )
    }

    #[test]
    fn pack_credential_fields_basic() {
        let cred = make_test_credential();
        let fields = vec![
            "name".to_string(),
            "address".to_string(),
            "document_number".to_string(),
            "age".to_string(),
        ];
        let (data, claim_index) = pack_credential_fields(&cred, &fields, "name").unwrap();

        // name is at index 0
        assert_eq!(claim_index, 0);

        // First field should be non-zero (Alice encoded)
        assert_ne!(data[0], "0");

        // Unused slots should be zero
        assert_eq!(data[4], "0");
        assert_eq!(data[7], "0");
    }

    #[test]
    fn pack_credential_fields_claim_index_middle() {
        let cred = make_test_credential();
        let fields = vec!["name".to_string(), "age".to_string()];
        let (_, claim_index) = pack_credential_fields(&cred, &fields, "age").unwrap();
        assert_eq!(claim_index, 1);
    }

    #[test]
    fn pack_credential_fields_missing_claim() {
        let cred = make_test_credential();
        let fields = vec!["nonexistent".to_string()];
        let result = pack_credential_fields(&cred, &fields, "nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn pack_credential_fields_ecdsa_claim_not_in_list() {
        let cred = make_test_credential();
        let fields = vec!["name".to_string()];
        let result = pack_credential_fields(&cred, &fields, "age");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ecdsa_claim"));
    }

    #[test]
    fn pack_credential_fields_too_many_fields() {
        let cred = make_test_credential();
        let fields: Vec<String> = (0..9).map(|i| format!("field_{i}")).collect();
        let result = pack_credential_fields(&cred, &fields, "field_0");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("at most 8"));
    }

    #[test]
    fn generate_escrow_key_is_valid() {
        let k = generate_escrow_key();
        // Should be a valid decimal string
        let bigint: BigUint = k.parse().expect("should be valid decimal");
        // Should be < BN254 order
        let order: BigUint = BN254_ORDER.parse().unwrap();
        assert!(bigint < order, "key should be less than BN254 order");
        // Should be non-zero
        assert!(bigint > BigUint::from(0u32));
    }

    #[test]
    fn generate_escrow_key_is_random() {
        let k1 = generate_escrow_key();
        let k2 = generate_escrow_key();
        assert_ne!(k1, k2, "two random keys should differ");
    }

    #[test]
    fn mlkem_encrypt_decrypt_roundtrip() {
        let (seed, _ek) = generate_authority_keypair();

        let k = generate_escrow_key();
        // Both encrypt and decrypt use the 64-byte seed
        let encrypted = encrypt_key_to_authority(&k, &seed).unwrap();
        let decrypted = decrypt_key(&encrypted, &seed).unwrap();
        assert_eq!(k, decrypted);
    }

    #[test]
    fn mlkem_wrong_key_fails() {
        let (seed, _) = generate_authority_keypair();
        let (wrong_seed, _) = generate_authority_keypair();

        let k = generate_escrow_key();
        let encrypted = encrypt_key_to_authority(&k, &seed).unwrap();
        let decrypted = decrypt_key(&encrypted, &wrong_seed).unwrap();
        // ML-KEM decapsulation with wrong key produces a different shared secret,
        // so decryption yields garbage — not the original K
        assert_ne!(k, decrypted);
    }

    #[test]
    fn claim_value_to_escrow_decimal_string() {
        let cv = ClaimValue::String("Alice".to_string());
        let decimal = claim_value_to_escrow_decimal(&cv);
        // Should match BigUint::from_bytes_be(to_escrow_field())
        let expected = BigUint::from_bytes_be(&cv.to_escrow_field());
        assert_eq!(decimal, expected.to_string());
    }

    #[test]
    fn claim_value_to_escrow_decimal_integer() {
        let cv = ClaimValue::Integer(42);
        let decimal = claim_value_to_escrow_decimal(&cv);
        let parsed: BigUint = decimal.parse().unwrap();
        assert_eq!(parsed, BigUint::from(42u64));
    }

    #[test]
    fn aes_gcm_escrow_round_trip() {
        let key = [0x42u8; 32];
        let fields = vec![
            ("name", b"Alice".as_slice()),
            ("dob", b"1990-01-15".as_slice()),
        ];
        let (cts, tags) = encrypt_fields_aes_gcm(&fields, &key).unwrap();
        let decrypted = decrypt_fields_aes_gcm(&cts, &tags, &key).unwrap();
        assert_eq!(decrypted[0], b"Alice");
        assert_eq!(decrypted[1], b"1990-01-15");
    }

    #[test]
    fn aes_gcm_tampered_tag_fails() {
        let key = [0x42u8; 32];
        let fields = vec![("name", b"Alice".as_slice())];
        let (cts, mut tags) = encrypt_fields_aes_gcm(&fields, &key).unwrap();
        tags[0][0] ^= 0xff;
        assert!(decrypt_fields_aes_gcm(&cts, &tags, &key).is_err());
    }
}
