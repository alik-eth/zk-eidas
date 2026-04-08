//! GF(2^128) binary field: GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)
//!
//! Elements are 128 bits stored as `[u64; 2]` (little-endian: `[lo, hi]`).
//! Arithmetic follows the generic (non-SIMD) implementation from
//! `vendor/longfellow-zk/lib/gf2k/sysdep.h`.

use super::Field;

/// A GF(2^128) element stored as two u64 limbs (little-endian).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Gf2Elt(pub [u64; 2]);

impl Gf2Elt {
    /// Access bit `i` of the polynomial representation.
    pub fn bit(&self, i: usize) -> bool {
        let word = i / 64;
        let bit = i % 64;
        (self.0[word] >> bit) & 1 == 1
    }
}

/// Marker type for the GF(2^128) field.
#[derive(Clone)]
pub struct Gf2_128;

// ---------------------------------------------------------------------------
// Carry-less multiplication primitives (ported from sysdep.h generic impl)
// ---------------------------------------------------------------------------

/// 64x64 → lower 64 bits of carry-less product, via Kronecker substitution.
/// Modeled after Highway / BearSSL.
fn clmul64_lo(x: u64, y: u64) -> u64 {
    let m0: u64 = 0x1111111111111111;
    let m1: u64 = 0x2222222222222222;
    let m2: u64 = 0x4444444444444444;
    let m3: u64 = 0x8888888888888888;

    let (x0, x1, x2, x3) = (x & m0, x & m1, x & m2, x & m3);
    let (y0, y1, y2, y3) = (y & m0, y & m1, y & m2, y & m3);

    let z0 = x0.wrapping_mul(y0)
        ^ x1.wrapping_mul(y3)
        ^ x2.wrapping_mul(y2)
        ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1)
        ^ x1.wrapping_mul(y0)
        ^ x2.wrapping_mul(y3)
        ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2)
        ^ x1.wrapping_mul(y1)
        ^ x2.wrapping_mul(y0)
        ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3)
        ^ x1.wrapping_mul(y2)
        ^ x2.wrapping_mul(y1)
        ^ x3.wrapping_mul(y0);

    (z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3)
}

fn bitrev64(mut n: u64) -> u64 {
    n = ((n >> 1) & 0x5555555555555555) | ((n & 0x5555555555555555) << 1);
    n = ((n >> 2) & 0x3333333333333333) | ((n & 0x3333333333333333) << 2);
    n = ((n >> 4) & 0x0f0f0f0f0f0f0f0f) | ((n & 0x0f0f0f0f0f0f0f0f) << 4);
    n = ((n >> 8) & 0x00ff00ff00ff00ff) | ((n & 0x00ff00ff00ff00ff) << 8);
    n = ((n >> 16) & 0x0000ffff0000ffff) | ((n & 0x0000ffff0000ffff) << 16);
    (n << 32) | (n >> 32)
}

/// 64x64 → upper 64 bits of carry-less product.
fn clmul64_hi(x: u64, y: u64) -> u64 {
    bitrev64(clmul64_lo(bitrev64(x), bitrev64(y))) >> 1
}

/// 64x64 → 128-bit carry-less product as (lo, hi).
fn clmul64(x: u64, y: u64) -> [u64; 2] {
    [clmul64_lo(x, y), clmul64_hi(x, y)]
}

// ---------------------------------------------------------------------------
// GF(2^128) reduction: return (t0 + x^64 * t1) mod irreducible
// Ported exactly from the C++ generic gf2_128_reduce.
// ---------------------------------------------------------------------------

/// `t0` and `t1` are each 128-bit values stored as `[u64; 2]`.
/// Computes `t0 + x^64 * t1` reduced mod x^128 + x^7 + x^2 + x + 1.
fn gf2_128_reduce(t0: &mut [u64; 2], t1: &[u64; 2]) {
    let a = t1[1]; // high limb of t1 = bits [192..255] of the full product
    t0[0] ^= a;
    t0[0] ^= a << 1;
    t0[1] ^= a >> 63;
    t0[0] ^= a << 2;
    t0[1] ^= a >> 62;
    t0[0] ^= a << 7;
    t0[1] ^= a >> 57;
    t0[1] ^= t1[0]; // low limb of t1 = bits [128..191] shifted into position
}

/// Full GF(2^128) multiplication using Karatsuba carry-less multiply + reduction.
fn gf2_128_mul(x: &[u64; 2], y: &[u64; 2]) -> [u64; 2] {
    // Karatsuba: split x = (x0, x1), y = (y0, y1)
    let t0 = clmul64(x[0], y[0]); // x0*y0
    let t2 = clmul64(x[1], y[1]); // x1*y1
    let t1_raw = clmul64(x[0] ^ x[1], y[0] ^ y[1]); // (x0+x1)*(y0+y1)

    // t1 = t1_raw + t0 + t2 = x0*y1 + x1*y0 (the "cross" term)
    let mut t1 = [
        t1_raw[0] ^ t0[0] ^ t2[0],
        t1_raw[1] ^ t0[1] ^ t2[1],
    ];

    // reduce: t1 = t1 + x^64 * t2
    gf2_128_reduce(&mut t1, &t2);

    // reduce: result = t0 + x^64 * t1
    let mut result = t0;
    gf2_128_reduce(&mut result, &t1);

    result
}

// ---------------------------------------------------------------------------
// Field trait implementation
// ---------------------------------------------------------------------------

impl Field for Gf2_128 {
    type Elt = Gf2Elt;

    const BYTES: usize = 16;
    const SUBFIELD_BYTES: usize = 1;
    const BITS: usize = 128;
    const FIELD_ID: u8 = 4;

    fn zero(&self) -> Gf2Elt {
        Gf2Elt([0, 0])
    }

    fn one(&self) -> Gf2Elt {
        Gf2Elt([1, 0])
    }

    fn add(&self, a: &Gf2Elt, b: &Gf2Elt) -> Gf2Elt {
        Gf2Elt([a.0[0] ^ b.0[0], a.0[1] ^ b.0[1]])
    }

    fn sub(&self, a: &Gf2Elt, b: &Gf2Elt) -> Gf2Elt {
        // In GF(2^k), subtraction == addition == XOR
        self.add(a, b)
    }

    fn mul(&self, a: &Gf2Elt, b: &Gf2Elt) -> Gf2Elt {
        Gf2Elt(gf2_128_mul(&a.0, &b.0))
    }

    fn neg(&self, a: &Gf2Elt) -> Gf2Elt {
        // In GF(2^k), negation is identity
        *a
    }

    fn invert(&self, a: &Gf2Elt) -> Gf2Elt {
        // Fermat's little theorem: a^{-1} = a^{2^128 - 2}
        // 2^128 - 2 in binary = 1111...1110 (127 ones then a zero)
        // = (((...((1*a)^2 * a)^2 * a)...)^2 * a)^2
        //   with 126 square-and-multiply steps, then a final square.
        let mut result = *a; // a^1
        for _ in 0..126 {
            result = self.mul(&result, &result); // square
            result = self.mul(&result, a); // multiply by a
        }
        result = self.mul(&result, &result); // final square (trailing zero bit)
        result
    }

    fn of_scalar(&self, s: u64) -> Gf2Elt {
        Gf2Elt([s, 0])
    }

    fn of_bytes(&self, bytes: &[u8]) -> Option<Gf2Elt> {
        if bytes.len() != Self::BYTES {
            return None;
        }
        let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        Some(Gf2Elt([lo, hi]))
    }

    fn to_bytes(&self, elt: &Gf2Elt) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&elt.0[0].to_le_bytes());
        out.extend_from_slice(&elt.0[1].to_le_bytes());
        out
    }

    fn of_subfield_bytes(&self, bytes: &[u8]) -> Option<Gf2Elt> {
        if bytes.len() != Self::SUBFIELD_BYTES {
            return None;
        }
        Some(Gf2Elt([bytes[0] as u64, 0]))
    }

    fn is_subfield(&self, elt: &Gf2Elt) -> bool {
        elt.0[1] == 0 && elt.0[0] < 256
    }

    fn sample(&self, rng: &mut dyn FnMut(usize) -> Vec<u8>) -> Gf2Elt {
        // Every 128-bit value is a valid GF(2^128) element.
        let bytes = rng(16);
        self.of_bytes(&bytes).unwrap()
    }
}
