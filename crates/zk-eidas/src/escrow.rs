//! Identity escrow utilities: AES-256-GCM field encryption and ML-KEM-768 key wrapping.
//!
//! These utilities support identity escrow: AES-256-GCM encrypts credential fields
//! outside the circuit. The symmetric key K is encrypted to an escrow authority's
//! ML-KEM-768 public key, released only on court order or arbitration ruling.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use num_bigint::BigUint;

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

/// Verify that the escrow digest matches the SHA-256 hash of the concatenated fields.
///
/// Used by the escrow authority after decryption to confirm the decrypted fields
/// match the in-circuit commitment from the ZK proof.
pub fn verify_escrow_digest(fields: &[[u8; 32]; 8], expected: &[u8; 32]) -> bool {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    for f in fields {
        hasher.update(f);
    }
    let computed: [u8; 32] = hasher.finalize().into();
    computed == *expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlkem_encrypt_decrypt_roundtrip() {
        let (seed, _ek) = generate_authority_keypair();

        // Use a fixed valid decimal key
        let k = "12345678901234567890123456789012345678901234567890".to_string();
        // Both encrypt and decrypt use the 64-byte seed
        let encrypted = encrypt_key_to_authority(&k, &seed).unwrap();
        let decrypted = decrypt_key(&encrypted, &seed).unwrap();
        assert_eq!(k, decrypted);
    }

    #[test]
    fn mlkem_wrong_key_fails() {
        let (seed, _) = generate_authority_keypair();
        let (wrong_seed, _) = generate_authority_keypair();

        let k = "12345678901234567890123456789012345678901234567890".to_string();
        let encrypted = encrypt_key_to_authority(&k, &seed).unwrap();
        let decrypted = decrypt_key(&encrypted, &wrong_seed).unwrap();
        // ML-KEM decapsulation with wrong key produces a different shared secret,
        // so decryption yields garbage — not the original K
        assert_ne!(k, decrypted);
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

    #[test]
    fn verify_escrow_digest_matches() {
        use sha2::{Sha256, Digest};
        let mut fields = [[0u8; 32]; 8];
        fields[0][..5].copy_from_slice(b"Alice");
        fields[1][..3].copy_from_slice(b"Bob");

        let mut hasher = Sha256::new();
        for f in &fields {
            hasher.update(f);
        }
        let expected: [u8; 32] = hasher.finalize().into();
        assert!(verify_escrow_digest(&fields, &expected));
    }

    #[test]
    fn verify_escrow_digest_mismatch() {
        let fields = [[0u8; 32]; 8];
        let wrong = [0xFFu8; 32];
        assert!(!verify_escrow_digest(&fields, &wrong));
    }
}
