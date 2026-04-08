use zk_eidas_wasm::field::{gf2_128::Gf2_128, Field};

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
