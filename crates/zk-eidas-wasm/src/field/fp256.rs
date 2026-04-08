//! P-256 base field (Fp256) with Montgomery arithmetic.
//!
//! Modulus: p = 2^256 - 2^224 + 2^192 + 2^96 - 1
//!        = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
//!
//! Elements are stored in Montgomery form: a_mont = a * R mod p, where R = 2^256.

use super::Field;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// P-256 modulus in little-endian u64 limbs.
const MODULUS: [u64; 4] = [
    0xFFFFFFFFFFFFFFFF, // p[0]
    0x00000000FFFFFFFF, // p[1]
    0x0000000000000000, // p[2]
    0xFFFFFFFF00000001, // p[3]
];

/// Montgomery constant: m' = -p^{-1} mod 2^64.
/// Since p[0] = 2^64 - 1, p ≡ -1 (mod 2^64), so p^{-1} ≡ -1, and m' = 1.
const M_PRIME: u64 = 1;

/// R^2 mod p, where R = 2^256. Used for converting to Montgomery form.
/// Computed as pow(2, 512, p).
const R_SQUARED: [u64; 4] = [
    0x0000000000000003,
    0xFFFFFFFBFFFFFFFF,
    0xFFFFFFFFFFFFFFFE,
    0x00000004FFFFFFFD,
];

/// p - 2, for Fermat inversion: a^{-1} = a^{p-2} mod p.
const P_MINUS_2: [u64; 4] = [
    0xFFFFFFFFFFFFFFFD,
    0x00000000FFFFFFFF,
    0x0000000000000000,
    0xFFFFFFFF00000001,
];

// ---------------------------------------------------------------------------
// Element type
// ---------------------------------------------------------------------------

/// A P-256 field element stored in Montgomery form as four u64 limbs (little-endian).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Fp256Elt(pub [u64; 4]);

/// Marker type for the P-256 base field.
#[derive(Clone)]
pub struct Fp256;

// ---------------------------------------------------------------------------
// Portable multi-precision helpers
// ---------------------------------------------------------------------------

/// Widening multiply: a * b -> (lo, hi).
#[inline(always)]
fn mul_u64(a: u64, b: u64) -> (u64, u64) {
    let r = (a as u128) * (b as u128);
    (r as u64, (r >> 64) as u64)
}

/// Add with carry: a + b + carry -> (result, new_carry).
#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let r = (a as u128) + (b as u128) + (carry as u128);
    (r as u64, (r >> 64) as u64)
}

/// Subtract with borrow: a - b - borrow -> (result, new_borrow).
/// new_borrow is 1 if underflow, 0 otherwise.
#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let r = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (r as u64, (r >> 127) as u64)
}

// ---------------------------------------------------------------------------
// Core Montgomery operations
// ---------------------------------------------------------------------------

/// Add two 4-limb values mod p.
fn fp256_add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    // Step 1: add limbs
    let (r0, c) = adc(a[0], b[0], 0);
    let (r1, c) = adc(a[1], b[1], c);
    let (r2, c) = adc(a[2], b[2], c);
    let (r3, c) = adc(a[3], b[3], c);

    // Step 2: conditionally subtract p if result >= p
    // Try subtracting p; if no borrow overall, use the subtracted result.
    let (s0, bw) = sbb(r0, MODULUS[0], 0);
    let (s1, bw) = sbb(r1, MODULUS[1], bw);
    let (s2, bw) = sbb(r2, MODULUS[2], bw);
    let (s3, bw) = sbb(r3, MODULUS[3], bw);
    // Account for the carry from addition
    let (_,  bw) = sbb(c, 0, bw);

    // If borrow (bw == 1), the subtraction underflowed => keep original
    // If no borrow (bw == 0), keep the subtracted result
    let mask = bw.wrapping_neg(); // 0xFFFF...FF if borrow, 0 if no borrow
    [
        s0 ^ (mask & (r0 ^ s0)),
        s1 ^ (mask & (r1 ^ s1)),
        s2 ^ (mask & (r2 ^ s2)),
        s3 ^ (mask & (r3 ^ s3)),
    ]
}

/// Subtract two 4-limb values mod p.
fn fp256_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, bw) = sbb(a[0], b[0], 0);
    let (r1, bw) = sbb(a[1], b[1], bw);
    let (r2, bw) = sbb(a[2], b[2], bw);
    let (r3, bw) = sbb(a[3], b[3], bw);

    // If underflow, add p back
    let mask = bw.wrapping_neg(); // all-ones if borrow
    let (r0, c) = adc(r0, MODULUS[0] & mask, 0);
    let (r1, c) = adc(r1, MODULUS[1] & mask, c);
    let (r2, c) = adc(r2, MODULUS[2] & mask, c);
    let (r3, _) = adc(r3, MODULUS[3] & mask, c);

    [r0, r1, r2, r3]
}

/// Schoolbook 4x4 -> 8 limb multiply.
/// Each row i writes carry to r[i+4], which is always fresh (only accessed
/// by the inner loop of the *next* row, never as a carry destination twice).
fn mul4x4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry: u64 = 0;
        for j in 0..4 {
            let (lo, hi) = mul_u64(a[i], b[j]);
            let (s, c1) = adc(r[i + j], lo, carry);
            r[i + j] = s;
            carry = hi + c1; // safe: hi <= 2^64-2, c1 <= 1
        }
        r[i + 4] = carry;
    }
    r
}

/// Montgomery multiplication: compute (a * b * R^{-1}) mod p.
///
/// Two-phase: schoolbook multiply then Montgomery reduction.
fn fp256_mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    // Phase 1: full 8-limb product
    let mut r = [0u64; 9]; // 8 product limbs + 1 overflow for reduction carries
    let prod = mul4x4(a, b);
    r[..8].copy_from_slice(&prod);

    // Phase 2: Montgomery reduction
    for i in 0..4 {
        let q = r[i].wrapping_mul(M_PRIME);

        let mut carry: u64 = 0;
        for j in 0..4 {
            let (lo, hi) = mul_u64(q, MODULUS[j]);
            let (s, c1) = adc(r[i + j], lo, carry);
            r[i + j] = s;
            carry = hi + c1; // safe: hi <= 2^64-2, c1 <= 1
        }
        // Propagate carry
        let mut k = i + 4;
        loop {
            if k > 8 || carry == 0 {
                break;
            }
            let (s, c) = adc(r[k], carry, 0);
            r[k] = s;
            carry = c;
            k += 1;
        }
    }

    // Result is in r[4..8], with possible overflow in r[8]
    let result = [r[4], r[5], r[6], r[7]];

    // Conditional subtraction if result (including overflow) >= p
    let (s0, bw) = sbb(result[0], MODULUS[0], 0);
    let (s1, bw) = sbb(result[1], MODULUS[1], bw);
    let (s2, bw) = sbb(result[2], MODULUS[2], bw);
    let (s3, bw) = sbb(result[3], MODULUS[3], bw);
    // Account for the overflow bit r[8]
    let (_, bw) = sbb(r[8], 0, bw);

    let mask = bw.wrapping_neg();
    [
        s0 ^ (mask & (result[0] ^ s0)),
        s1 ^ (mask & (result[1] ^ s1)),
        s2 ^ (mask & (result[2] ^ s2)),
        s3 ^ (mask & (result[3] ^ s3)),
    ]
}

/// Negate: if a == 0, return 0; otherwise return p - a.
fn fp256_neg(a: &[u64; 4]) -> [u64; 4] {
    let is_zero = (a[0] | a[1] | a[2] | a[3]) == 0;
    if is_zero {
        [0, 0, 0, 0]
    } else {
        let (r0, bw) = sbb(MODULUS[0], a[0], 0);
        let (r1, bw) = sbb(MODULUS[1], a[1], bw);
        let (r2, bw) = sbb(MODULUS[2], a[2], bw);
        let (r3, _)  = sbb(MODULUS[3], a[3], bw);
        [r0, r1, r2, r3]
    }
}

/// Fermat inversion: a^{p-2} mod p, via square-and-multiply.
fn fp256_invert(a: &[u64; 4]) -> [u64; 4] {
    // Montgomery one = R mod p
    let one = fp256_mont_mul(&[1, 0, 0, 0], &R_SQUARED);
    let mut result = one;

    // Scan p-2 from MSB to LSB
    for i in (0..256).rev() {
        result = fp256_mont_mul(&result, &result);
        let word = i / 64;
        let bit = i % 64;
        if (P_MINUS_2[word] >> bit) & 1 == 1 {
            result = fp256_mont_mul(&result, a);
        }
    }
    result
}

/// Convert from Montgomery form to normal form by multiplying by 1 (= R^{-1} in Montgomery).
fn from_montgomery(a: &[u64; 4]) -> [u64; 4] {
    fp256_mont_mul(a, &[1, 0, 0, 0])
}

/// Convert to Montgomery form by multiplying by R^2 mod p.
fn to_montgomery(a: &[u64; 4]) -> [u64; 4] {
    fp256_mont_mul(a, &R_SQUARED)
}

/// Check if a < p (in normal, non-Montgomery form).
fn is_less_than_modulus(a: &[u64; 4]) -> bool {
    // Compare from most significant limb
    for i in (0..4).rev() {
        if a[i] < MODULUS[i] {
            return true;
        }
        if a[i] > MODULUS[i] {
            return false;
        }
    }
    false // equal to modulus, not less
}

// ---------------------------------------------------------------------------
// Field trait implementation
// ---------------------------------------------------------------------------

impl Field for Fp256 {
    type Elt = Fp256Elt;

    const BYTES: usize = 32;
    const SUBFIELD_BYTES: usize = 32;
    const BITS: usize = 256;
    const FIELD_ID: u8 = 1;

    fn zero(&self) -> Fp256Elt {
        Fp256Elt([0, 0, 0, 0])
    }

    fn one(&self) -> Fp256Elt {
        // 1 in Montgomery form = R mod p = to_montgomery([1,0,0,0])
        Fp256Elt(to_montgomery(&[1, 0, 0, 0]))
    }

    fn add(&self, a: &Fp256Elt, b: &Fp256Elt) -> Fp256Elt {
        Fp256Elt(fp256_add(&a.0, &b.0))
    }

    fn sub(&self, a: &Fp256Elt, b: &Fp256Elt) -> Fp256Elt {
        Fp256Elt(fp256_sub(&a.0, &b.0))
    }

    fn mul(&self, a: &Fp256Elt, b: &Fp256Elt) -> Fp256Elt {
        Fp256Elt(fp256_mont_mul(&a.0, &b.0))
    }

    fn neg(&self, a: &Fp256Elt) -> Fp256Elt {
        Fp256Elt(fp256_neg(&a.0))
    }

    fn invert(&self, a: &Fp256Elt) -> Fp256Elt {
        Fp256Elt(fp256_invert(&a.0))
    }

    fn of_scalar(&self, s: u64) -> Fp256Elt {
        Fp256Elt(to_montgomery(&[s, 0, 0, 0]))
    }

    fn of_bytes(&self, bytes: &[u8]) -> Option<Fp256Elt> {
        if bytes.len() != Self::BYTES {
            return None;
        }
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        if !is_less_than_modulus(&limbs) {
            return None;
        }
        Some(Fp256Elt(to_montgomery(&limbs)))
    }

    fn to_bytes(&self, elt: &Fp256Elt) -> Vec<u8> {
        let normal = from_montgomery(&elt.0);
        let mut out = Vec::with_capacity(32);
        for limb in &normal {
            out.extend_from_slice(&limb.to_le_bytes());
        }
        out
    }

    fn of_subfield_bytes(&self, bytes: &[u8]) -> Option<Fp256Elt> {
        // For Fp256, subfield == full field (kSubFieldBytes == kBytes in C++)
        self.of_bytes(bytes)
    }

    fn is_subfield(&self, _elt: &Fp256Elt) -> bool {
        // For Fp256, every element is in the subfield (matching C++ in_subfield)
        true
    }

    fn sample(&self, rng: &mut dyn FnMut(usize) -> Vec<u8>) -> Fp256Elt {
        // Rejection sampling: read 32 bytes (little-endian), accept if < modulus.
        // Matches C++ FpGeneric::sample which uses N::of_bytes(buf, exact_bits_).
        // For P-256, exact_bits_ = 256, so total_l = 32 and no bit masking needed.
        loop {
            let bytes = rng(32);
            let mut limbs = [0u64; 4];
            for i in 0..4 {
                limbs[i] =
                    u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
            }
            if is_less_than_modulus(&limbs) {
                return Fp256Elt(to_montgomery(&limbs));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Decimal string parsing (for issuer public key coordinates)
// ---------------------------------------------------------------------------

impl Fp256 {
    /// Parse a decimal string to a field element.
    /// The value is reduced mod p and converted to Montgomery form.
    pub fn of_decimal_string(&self, s: &str) -> Option<Fp256Elt> {
        if s.is_empty() {
            return None;
        }
        // Parse decimal digits into limbs via repeated multiply-by-10 + add-digit,
        // operating on a 5-limb accumulator (320 bits, enough for intermediate products).
        let mut acc = [0u64; 5]; // big enough for 256-bit result + overflow during multiply

        for ch in s.bytes() {
            if !ch.is_ascii_digit() {
                return None;
            }
            let digit = (ch - b'0') as u64;

            // acc *= 10
            let mut carry = 0u64;
            for limb in acc.iter_mut() {
                let (lo, hi) = mul_u64(*limb, 10);
                let (s, c) = adc(lo, carry, 0);
                *limb = s;
                carry = hi + c;
            }
            if carry != 0 {
                return None; // overflow
            }

            // acc += digit
            let (s, c) = adc(acc[0], digit, 0);
            acc[0] = s;
            for i in 1..5 {
                let (s, c2) = adc(acc[i], 0, c);
                acc[i] = s;
                if c2 == 0 {
                    break;
                }
            }
        }

        // Values >= 2^256 are rejected (valid P-256 coordinates are < p < 2^256).
        if acc[4] != 0 {
            return None;
        }

        let limbs = [acc[0], acc[1], acc[2], acc[3]];
        if !is_less_than_modulus(&limbs) {
            // Value >= p. Handle the case where value == p (maps to zero),
            // or value is slightly above p (reduce by subtracting p once).
            if limbs == MODULUS {
                return Some(self.zero());
            }
            let sub = fp256_sub(&limbs, &MODULUS);
            if is_less_than_modulus(&sub) {
                return Some(Fp256Elt(to_montgomery(&sub)));
            }
            return None;
        }

        Some(Fp256Elt(to_montgomery(&limbs)))
    }

    /// Interpret 32 big-endian bytes as a 256-bit integer and convert to
    /// Montgomery form, reducing mod p.
    ///
    /// This mirrors C++ `nat_from_be<Nat>(hash)` followed by `f_.to_montgomery(nat)`.
    /// SHA-256 hashes can produce values >= p, so unlike `of_bytes` this does NOT
    /// reject values >= p — Montgomery multiplication handles the reduction.
    pub fn of_bytes_be(&self, bytes: &[u8; 32]) -> Fp256Elt {
        // Reverse from big-endian to little-endian byte order.
        let mut le = [0u8; 32];
        for i in 0..32 {
            le[i] = bytes[31 - i];
        }
        // Read into u64 limbs (little-endian).
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(le[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        // to_montgomery performs mont_mul(limbs, R^2) which inherently reduces mod p,
        // even if limbs >= p (as long as limbs < 2^256, which is guaranteed by 32 bytes).
        Fp256Elt(to_montgomery(&limbs))
    }

    /// Parse a hex string (with optional `0x` prefix) to a field element.
    /// The hex string is interpreted as big-endian bytes.
    pub fn of_hex_string(&self, s: &str) -> Option<Fp256Elt> {
        let hex_str = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        if hex_str.is_empty() || hex_str.len() > 64 {
            return None;
        }
        // Pad to 64 hex chars (32 bytes)
        let padded = format!("{:0>64}", hex_str);
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(self.of_bytes_be(&bytes))
    }

    /// Parse a string that may be decimal or hex (0x-prefixed) to a field element.
    pub fn of_string(&self, s: &str) -> Option<Fp256Elt> {
        if s.starts_with("0x") || s.starts_with("0X") {
            self.of_hex_string(s)
        } else {
            self.of_decimal_string(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_sanity() {
        let product = MODULUS[0].wrapping_mul(M_PRIME);
        assert_eq!(product, u64::MAX);
    }

    #[test]
    fn mont_mul_large_values() {
        // (p-2) in Montgomery form:
        // big_mont = 0xfffffffd00000003000000000000000000000002fffffffffffffffffffffffd
        let big = Fp256Elt([
            0xfffffffffffffffd,
            0x00000002ffffffff,
            0x0000000000000000,
            0xfffffffd00000003,
        ]);
        // big^2 in Montgomery form should be:
        // 0x00000003fffffffbfffffffffffffffffffffffc000000000000000000000004
        let expected_sq = Fp256Elt([
            0x0000000000000004,
            0xfffffffc00000000,
            0xffffffffffffffff,
            0x00000003fffffffb,
        ]);
        let sq = Fp256Elt(fp256_mont_mul(&big.0, &big.0));
        assert_eq!(sq, expected_sq, "large value squaring mismatch");
    }

    #[test]
    fn mont_mul_42_squared() {
        // 42_mont = [0x2a, 0xffffffd600000000, 0xffffffffffffffff, 0x00000029ffffffd5]
        // but that's big-endian display. In LE limbs:
        // 42 * R mod p = 0x00000029ffffffd5ffffffffffffffffffffffd600000000000000000000002a
        let a = Fp256Elt([
            0x000000000000002a,
            0xffffffd600000000,
            0xffffffffffffffff,
            0x00000029ffffffd5,
        ]);
        // 1764 * R mod p = 0x000006e3fffff91bfffffffffffffffffffff91c0000000000000000000006e4
        let expected = Fp256Elt([
            0x00000000000006e4,
            0xfffff91c00000000,
            0xffffffffffffffff,
            0x000006e3fffff91b,
        ]);
        let result = Fp256Elt(fp256_mont_mul(&a.0, &a.0));
        assert_eq!(result, expected, "42^2 Montgomery squaring mismatch");
    }
}
