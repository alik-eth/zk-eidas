use zk_eidas_wasm::algebra::dense::DenseFiller;
use zk_eidas_wasm::algebra::eq::{bind_variable, eq_eval};
use zk_eidas_wasm::algebra::poly::SumcheckPoly;
use zk_eidas_wasm::field::{fp256::Fp256, gf2_128::Gf2_128, Field};

#[test]
fn gf2_128_zero_is_additive_identity() {
    let f = Gf2_128;
    let a = f.of_scalar(42);
    assert_eq!(f.add(&a, &f.zero()), a);
}

#[test]
fn gf2_128_add_is_xor() {
    let f = Gf2_128;
    let a = f.of_scalar(0xFF);
    let b = f.of_scalar(0x0F);
    assert_eq!(f.add(&a, &b), f.of_scalar(0xF0));
}

#[test]
fn gf2_128_add_self_is_zero() {
    let f = Gf2_128;
    let a = f.of_scalar(0xDEADBEEF);
    assert_eq!(f.add(&a, &a), f.zero());
}

#[test]
fn gf2_128_mul_one() {
    let f = Gf2_128;
    let a = f.of_scalar(42);
    assert_eq!(f.mul(&a, &f.one()), a);
}

#[test]
fn gf2_128_mul_zero() {
    let f = Gf2_128;
    let a = f.of_scalar(42);
    assert_eq!(f.mul(&a, &f.zero()), f.zero());
}

#[test]
fn gf2_128_mul_commutative() {
    let f = Gf2_128;
    let a = f.of_scalar(0xDEADBEEF);
    let b = f.of_scalar(0xCAFEBABE);
    assert_eq!(f.mul(&a, &b), f.mul(&b, &a));
}

#[test]
fn gf2_128_mul_associative() {
    let f = Gf2_128;
    let a = f.of_scalar(0xDEAD);
    let b = f.of_scalar(0xBEEF);
    let c = f.of_scalar(0xCAFE);
    assert_eq!(f.mul(&f.mul(&a, &b), &c), f.mul(&a, &f.mul(&b, &c)));
}

#[test]
fn gf2_128_mul_distributive() {
    let f = Gf2_128;
    let a = f.of_scalar(0xDEAD);
    let b = f.of_scalar(0xBEEF);
    let c = f.of_scalar(0xCAFE);
    // a * (b + c) = a*b + a*c
    let lhs = f.mul(&a, &f.add(&b, &c));
    let rhs = f.add(&f.mul(&a, &b), &f.mul(&a, &c));
    assert_eq!(lhs, rhs);
}

#[test]
fn gf2_128_mul_self_inverse() {
    let f = Gf2_128;
    let a = f.of_scalar(0xDEADBEEF);
    let inv = f.invert(&a);
    assert_eq!(f.mul(&a, &inv), f.one());
}

#[test]
fn gf2_128_invert_one() {
    let f = Gf2_128;
    assert_eq!(f.invert(&f.one()), f.one());
}

#[test]
fn gf2_128_roundtrip_bytes() {
    let f = Gf2_128;
    let a = f.of_scalar(0x123456789ABCDEF0);
    let bytes = f.to_bytes(&a);
    assert_eq!(bytes.len(), 16);
    assert_eq!(f.of_bytes(&bytes), Some(a));
}

#[test]
fn gf2_128_subfield() {
    let f = Gf2_128;
    assert!(f.is_subfield(&f.of_scalar(255)));
    assert!(!f.is_subfield(&f.of_scalar(256)));
}

#[test]
fn gf2_128_neg_is_identity() {
    let f = Gf2_128;
    let a = f.of_scalar(0xDEADBEEF);
    assert_eq!(f.neg(&a), a);
}

#[test]
fn gf2_128_bit_access() {
    use zk_eidas_wasm::field::gf2_128::Gf2Elt;
    let elt = Gf2Elt([0b1010, 0]);
    assert!(!elt.bit(0));
    assert!(elt.bit(1));
    assert!(!elt.bit(2));
    assert!(elt.bit(3));
}

#[test]
fn gf2_128_mul_large_values() {
    // Test with values that span both u64 words
    let f = Gf2_128;
    use zk_eidas_wasm::field::gf2_128::Gf2Elt;
    let a = Gf2Elt([0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]);
    let b = Gf2Elt([0x02, 0]);
    let ab = f.mul(&a, &b);
    let ba = f.mul(&b, &a);
    assert_eq!(ab, ba);
    // a*b should not be zero
    assert_ne!(ab, f.zero());
}

#[test]
fn gf2_128_invert_large() {
    let f = Gf2_128;
    use zk_eidas_wasm::field::gf2_128::Gf2Elt;
    let a = Gf2Elt([0x123456789ABCDEF0, 0xFEDCBA9876543210]);
    let inv = f.invert(&a);
    assert_eq!(f.mul(&a, &inv), f.one());
}

#[test]
fn gf2_128_sub_equals_add() {
    let f = Gf2_128;
    let a = f.of_scalar(0xDEAD);
    let b = f.of_scalar(0xBEEF);
    assert_eq!(f.sub(&a, &b), f.add(&a, &b));
}

#[test]
fn gf2_128_of_subfield_bytes() {
    let f = Gf2_128;
    let elt = f.of_subfield_bytes(&[0x42]).unwrap();
    assert_eq!(elt, f.of_scalar(0x42));
}

// ---------------------------------------------------------------------------
// Fp256 tests
// ---------------------------------------------------------------------------

#[test]
fn fp256_zero_is_additive_identity() {
    let f = Fp256;
    let a = f.of_scalar(1000);
    assert_eq!(f.add(&a, &f.zero()), a);
}

#[test]
fn fp256_add_sub_roundtrip() {
    let f = Fp256;
    let a = f.of_scalar(1000);
    let b = f.of_scalar(2000);
    let sum = f.add(&a, &b);
    assert_eq!(f.sub(&sum, &b), a);
}

#[test]
fn fp256_mul_one() {
    let f = Fp256;
    let a = f.of_scalar(0xDEADBEEF);
    assert_eq!(f.mul(&a, &f.one()), a);
}

#[test]
fn fp256_mul_zero() {
    let f = Fp256;
    let a = f.of_scalar(42);
    assert_eq!(f.mul(&a, &f.zero()), f.zero());
}

#[test]
fn fp256_mul_commutative() {
    let f = Fp256;
    let a = f.of_scalar(0xDEADBEEF);
    let b = f.of_scalar(0xCAFEBABE);
    assert_eq!(f.mul(&a, &b), f.mul(&b, &a));
}

#[test]
fn fp256_mul_associative() {
    let f = Fp256;
    let a = f.of_scalar(123);
    let b = f.of_scalar(456);
    let c = f.of_scalar(789);
    assert_eq!(f.mul(&f.mul(&a, &b), &c), f.mul(&a, &f.mul(&b, &c)));
}

#[test]
fn fp256_mul_distributive() {
    let f = Fp256;
    let a = f.of_scalar(100);
    let b = f.of_scalar(200);
    let c = f.of_scalar(300);
    let lhs = f.mul(&a, &f.add(&b, &c));
    let rhs = f.add(&f.mul(&a, &b), &f.mul(&a, &c));
    assert_eq!(lhs, rhs);
}

#[test]
fn fp256_mul_inverse() {
    let f = Fp256;
    let a = f.of_scalar(42);
    let inv = f.invert(&a);
    assert_eq!(f.mul(&a, &inv), f.one());
}

#[test]
fn fp256_invert_one() {
    let f = Fp256;
    assert_eq!(f.invert(&f.one()), f.one());
}

#[test]
fn fp256_neg_add_zero() {
    let f = Fp256;
    let a = f.of_scalar(42);
    assert_eq!(f.add(&a, &f.neg(&a)), f.zero());
}

#[test]
fn fp256_modulus_wraps() {
    let f = Fp256;
    // (p - 1) + 1 should be 0
    let max = f.sub(&f.zero(), &f.one()); // p - 1 in Montgomery
    let wrapped = f.add(&max, &f.one());
    assert_eq!(wrapped, f.zero());
}

#[test]
fn fp256_roundtrip_bytes() {
    let f = Fp256;
    let a = f.of_scalar(0x123456789ABCDEF0);
    let bytes = f.to_bytes(&a);
    assert_eq!(bytes.len(), 32);
    assert_eq!(f.of_bytes(&bytes), Some(a));
}

#[test]
fn fp256_of_scalar_small() {
    let f = Fp256;
    // of_scalar(2) * of_scalar(3) should equal of_scalar(6)
    let two = f.of_scalar(2);
    let three = f.of_scalar(3);
    let six = f.of_scalar(6);
    assert_eq!(f.mul(&two, &three), six);
}

#[test]
fn fp256_large_inversion() {
    let f = Fp256;
    let a = f.of_scalar(0xFFFFFFFFFFFFFFFF);
    let inv = f.invert(&a);
    assert_eq!(f.mul(&a, &inv), f.one());
}

#[test]
fn fp256_of_decimal_string() {
    let f = Fp256;
    // "42" should parse to the same as of_scalar(42)
    let from_str = f.of_decimal_string("42").unwrap();
    let from_scalar = f.of_scalar(42);
    assert_eq!(from_str, from_scalar);
}

#[test]
fn fp256_of_decimal_string_zero() {
    let f = Fp256;
    let z = f.of_decimal_string("0").unwrap();
    assert_eq!(z, f.zero());
}

#[test]
fn fp256_of_decimal_string_large() {
    let f = Fp256;
    // A large but valid P-256 coordinate
    let val = f
        .of_decimal_string(
            "48439561293906451759052585252797914202762949526041747995844080717082404635286",
        )
        .unwrap();
    // Verify it round-trips through bytes
    let bytes = f.to_bytes(&val);
    assert_eq!(f.of_bytes(&bytes), Some(val));
}

#[test]
fn fp256_of_decimal_string_invalid() {
    let f = Fp256;
    assert!(f.of_decimal_string("").is_none());
    assert!(f.of_decimal_string("abc").is_none());
    assert!(f.of_decimal_string("12x34").is_none());
}

#[test]
fn fp256_subfield() {
    let f = Fp256;
    assert!(f.is_subfield(&f.of_scalar(255)));
    assert!(!f.is_subfield(&f.of_scalar(256)));
}

#[test]
fn fp256_of_subfield_bytes() {
    let f = Fp256;
    let elt = f.of_subfield_bytes(&[0x42]).unwrap();
    assert_eq!(elt, f.of_scalar(0x42));
}

// ---------------------------------------------------------------------------
// SumcheckPoly tests
// ---------------------------------------------------------------------------

#[test]
fn wpoly_eval_at_known_points() {
    let f = Fp256;
    // Poly through (0, 1), (1, 3), (2, 7)
    let poly = SumcheckPoly::new(vec![f.of_scalar(1), f.of_scalar(3), f.of_scalar(7)]);
    assert_eq!(poly.eval(&f.zero(), &f), f.of_scalar(1));
    assert_eq!(poly.eval(&f.one(), &f), f.of_scalar(3));
    assert_eq!(poly.eval(&f.of_scalar(2), &f), f.of_scalar(7));
}

#[test]
fn wpoly_eval_at_challenge() {
    let f = Fp256;
    // Linear poly through (0, 0), (1, 1), (2, 2) -> p(x) = x
    let poly = SumcheckPoly::new(vec![f.of_scalar(0), f.of_scalar(1), f.of_scalar(2)]);
    assert_eq!(poly.eval(&f.of_scalar(5), &f), f.of_scalar(5));
    assert_eq!(poly.eval(&f.of_scalar(100), &f), f.of_scalar(100));
}

#[test]
fn cpoly_4_points() {
    let f = Fp256;
    // Poly through (0, 1), (1, 1), (2, 1), (3, 1) -> constant 1
    let poly = SumcheckPoly::new(vec![f.one(), f.one(), f.one(), f.one()]);
    assert_eq!(poly.eval(&f.of_scalar(42), &f), f.one());
}

// ---------------------------------------------------------------------------
// EQ polynomial tests
// ---------------------------------------------------------------------------

#[test]
fn eq_eval_matching() {
    let f = Fp256;
    // On the boolean hypercube, EQ(x, x) = 1
    let r = vec![f.one(), f.zero()];
    assert_eq!(eq_eval(&r, &r, &f), f.one());
    let r2 = vec![f.zero(), f.zero()];
    assert_eq!(eq_eval(&r2, &r2, &f), f.one());
    let r3 = vec![f.one(), f.one()];
    assert_eq!(eq_eval(&r3, &r3, &f), f.one());
}

#[test]
fn eq_eval_boolean() {
    let f = Fp256;
    let x = vec![f.one(), f.zero()];
    let r = vec![f.one(), f.zero()];
    assert_eq!(eq_eval(&x, &r, &f), f.one());
    let r2 = vec![f.zero(), f.one()];
    assert_eq!(eq_eval(&x, &r2, &f), f.zero());
}

// ---------------------------------------------------------------------------
// Bind variable tests
// ---------------------------------------------------------------------------

#[test]
fn bind_variable_test() {
    let f = Fp256;
    // f(x0, x1) evaluated on {0,1}^2:
    // f(0,0)=1, f(1,0)=2, f(0,1)=3, f(1,1)=4
    let evals = vec![
        f.of_scalar(1),
        f.of_scalar(2),
        f.of_scalar(3),
        f.of_scalar(4),
    ];
    // Bind x0 = 0: should give [f(0,0), f(0,1)] = [1, 3]
    let bound = bind_variable(&evals, &f.zero(), &f);
    assert_eq!(bound, vec![f.of_scalar(1), f.of_scalar(3)]);
    // Bind x0 = 1: should give [f(1,0), f(1,1)] = [2, 4]
    let bound = bind_variable(&evals, &f.one(), &f);
    assert_eq!(bound, vec![f.of_scalar(2), f.of_scalar(4)]);
}

// ---------------------------------------------------------------------------
// DenseFiller tests
// ---------------------------------------------------------------------------

#[test]
fn dense_filler_push_scalar_bits() {
    let f = Fp256;
    let mut filler = DenseFiller::<Fp256>::new();
    filler.push_scalar_bits(0b1010, 4, &f);
    assert_eq!(filler.len(), 4);
    let dense = filler.into_dense(4);
    // LSB first: bit0=0, bit1=1, bit2=0, bit3=1
    assert_eq!(dense.data[0], f.zero());
    assert_eq!(dense.data[1], f.one());
    assert_eq!(dense.data[2], f.zero());
    assert_eq!(dense.data[3], f.one());
}
