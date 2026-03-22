use num_bigint::BigInt;

/// Structured input for the Stage 1 ECDSA verification circuit.
///
/// The ECDSA circuit uses 43-bit limbs (k=6, n=43) for P-256 scalars.
/// This struct stores raw 32-byte values and provides conversion methods
/// to the limb encoding expected by the circuit.
pub struct SignedProofInput {
    /// ECDSA signature r component (32 bytes, big-endian)
    pub signature_r: [u8; 32],
    /// ECDSA signature s component (32 bytes, big-endian)
    pub signature_s: [u8; 32],
    /// SHA-256 hash of the signed message (32 bytes, big-endian)
    pub message_hash: [u8; 32],
    /// Issuer public key X coordinate (32 bytes, big-endian)
    pub pub_key_x: [u8; 32],
    /// Issuer public key Y coordinate (32 bytes, big-endian)
    pub pub_key_y: [u8; 32],
    /// The claim value being proven (as a field element)
    pub claim_value: u64,
    /// Poseidon hash of the disclosure data
    pub disclosure_hash: u64,
    /// The sd_array (16 field elements for selective disclosure)
    pub sd_array: [u64; 16],
}

impl SignedProofInput {
    /// Create a new signed proof input from its constituent parts.
    pub fn new(
        signature_r: [u8; 32],
        signature_s: [u8; 32],
        message_hash: [u8; 32],
        pub_key_x: [u8; 32],
        pub_key_y: [u8; 32],
        claim_value: u64,
        disclosure_hash: u64,
        sd_array: [u64; 16],
    ) -> Self {
        Self {
            signature_r,
            signature_s,
            message_hash,
            pub_key_x,
            pub_key_y,
            claim_value,
            disclosure_hash,
            sd_array,
        }
    }

    /// Convert a 32-byte big-endian scalar into 6 limbs of 43 bits each.
    ///
    /// The ECDSA circuit uses k=6, n=43 encoding: each P-256 scalar is split
    /// into 6 limbs where limb[i] contains bits [43*i .. 43*(i+1)).
    /// Limbs are little-endian (limb[0] is the least significant).
    ///
    /// Delegates to [`zk_eidas_types::to_43bit_limbs`].
    pub fn to_43bit_limbs(bytes: &[u8; 32]) -> [BigInt; 6] {
        zk_eidas_types::to_43bit_limbs(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_proof_input_from_parts() {
        let input = SignedProofInput {
            signature_r: [0xAA; 32],
            signature_s: [0xBB; 32],
            message_hash: [0xCC; 32],
            pub_key_x: [0xDD; 32],
            pub_key_y: [0xEE; 32],
            claim_value: 42,
            disclosure_hash: 123,
            sd_array: [0u64; 16],
        };
        assert_eq!(input.signature_r[0], 0xAA);
        assert_eq!(input.signature_s[0], 0xBB);
        assert_eq!(input.message_hash[0], 0xCC);
        assert_eq!(input.claim_value, 42);
    }

    #[test]
    fn limb_decomposition_small_value() {
        // Test with a small value that fits in one limb
        let mut bytes = [0u8; 32];
        bytes[31] = 42; // value = 42
        let limbs = SignedProofInput::to_43bit_limbs(&bytes);
        assert_eq!(limbs[0], BigInt::from(42));
        for limb in &limbs[1..] {
            assert_eq!(*limb, BigInt::from(0));
        }
    }

    #[test]
    fn limb_decomposition_roundtrip() {
        // Test that decomposition preserves the original value
        let bytes: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        ];
        let limbs = SignedProofInput::to_43bit_limbs(&bytes);

        // Reconstruct: value = sum(limb[i] * 2^(43*i))
        let mut reconstructed = BigInt::from(0);
        for (i, limb) in limbs.iter().enumerate() {
            reconstructed += limb << (43 * i);
        }
        let original = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes);
        assert_eq!(reconstructed, original);
    }

    #[test]
    fn limb_values_are_within_43_bits() {
        let bytes = [0xFF; 32];
        let limbs = SignedProofInput::to_43bit_limbs(&bytes);
        let max_limb = BigInt::from(1) << 43;
        for limb in &limbs {
            assert!(*limb < max_limb, "Limb {limb} exceeds 43-bit max");
            assert!(*limb >= BigInt::from(0), "Limb {limb} is negative");
        }
    }
}
