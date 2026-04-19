//! Tests that the parser locates signedAttrs and messageDigest correctly,
//! and that messageDigest actually equals SHA-256(signed_content).

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;

const FIXTURE: &[u8] = include_bytes!("../fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

#[test]
fn signedattrs_offset_is_present_and_implicit_tagged() {
    let w = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).expect("parse");
    let off = &w.offsets;

    // signedAttrs must be non-empty and start with [0] IMPLICIT tag 0xA0
    assert!(off.signed_attrs_len > 2, "signedAttrs too short");
    assert_eq!(
        w.p7s_bytes[off.signed_attrs_start],
        0xA0,
        "signedAttrs first byte must be [0] IMPLICIT tag"
    );
}

#[test]
fn message_digest_equals_sha256_of_signed_content() {
    let w = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).expect("parse");
    let off = &w.offsets;

    let md = &w.p7s_bytes[off.message_digest_start..off.message_digest_start + off.message_digest_len];
    let content = &w.p7s_bytes[off.signed_content_start..off.signed_content_start + off.signed_content_len];
    let expected: [u8; 32] = Sha256::digest(content).into();

    assert_eq!(off.message_digest_len, 32);
    assert_eq!(md, expected.as_slice(), "messageDigest must equal SHA-256(signed_content)");
}
