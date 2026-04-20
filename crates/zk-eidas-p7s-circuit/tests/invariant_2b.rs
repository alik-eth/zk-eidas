//! Phase 2a Task 24 — invariant 2b: `message_digest == SHA-256(signed_content)`.
//!
//! message_digest is a prover witness (32 bytes); the binding between
//! this digest and the signedAttrs byte range arrives in Task 26
//! (invariant 2a). This test file exercises only the SHA-256 identity.
//!
//! Tests:
//!   1. Happy: honest witness (message_digest computed from
//!      signed_content) round-trips.
//!   2. Tampered signed_content byte: SHA hash changes, prover refuses.
//!   3. Tampered message_digest: no longer matches SHA(signed_content),
//!      prover refuses.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

// v6 blob offsets — keep in sync with `witness.rs`'s serializer.
const SC_START_IN_BLOB: usize = 4 + 4 + 32 + 4; // 44
const PK_OFF_IN_BLOB: usize = SC_START_IN_BLOB + 1024; // 1068
const PK_HEX_IN_BLOB: usize = PK_OFF_IN_BLOB + 4; // 1072
const NONCE_OFF_IN_BLOB: usize = PK_HEX_IN_BLOB + 130; // 1202
const NONCE_HEX_IN_BLOB: usize = NONCE_OFF_IN_BLOB + 4; // 1206
const CTX_OFF_IN_BLOB: usize = NONCE_HEX_IN_BLOB + 64; // 1270
const DECL_OFF_IN_BLOB: usize = CTX_OFF_IN_BLOB + 4; // 1274
const MESSAGE_DIGEST_IN_BLOB: usize = DECL_OFF_IN_BLOB + 4; // 1278

fn expected_pk() -> [u8; 65] {
    let w = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let off = &w.offsets;
    let mut out = [0u8; 65];
    hex::decode_to_slice(
        &w.p7s_bytes[off.json_pk_start..off.json_pk_start + off.json_pk_len],
        &mut out,
    )
    .unwrap();
    out
}

fn expected_nonce() -> [u8; 32] {
    let w = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let off = &w.offsets;
    let mut out = [0u8; 32];
    hex::decode_to_slice(
        &w.p7s_bytes[off.json_nonce_start..off.json_nonce_start + off.json_nonce_len],
        &mut out,
    )
    .unwrap();
    out
}

fn honest_public() -> PublicInputs {
    PublicInputs {
        context_hash: Sha256::digest(b"0x").into(),
        pk: expected_pk(),
        nonce: expected_nonce(),
        root_pk: [0u8; 65],
        timestamp: 0,
    }
}

/// (1) Happy: honest witness (Rust serializer computes message_digest
/// from signed_content, circuit checks it matches SHA-256 of the
/// SHA-padded signed_content).
#[test]
fn invariant_2b_happy_round_trips() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let public = honest_public();
    let proof = prove(&w, &public).expect("prove");
    assert!(
        verify(&proof, &public).expect("verify"),
        "honest proof must verify"
    );
}

/// (2) Tampered signed_content: the SHA-256 computed from the (now
/// altered) signed_content no longer equals the claimed message_digest
/// in the witness, so the prover refuses. We tamper one byte in a
/// region that (a) isn't inside pk/nonce/context/declaration (so those
/// byte_range_eq checks still pass) and (b) changes the SHA. Byte at
/// `sc_start + 7` sits inside `"scheme":"secp256k1"` — safe from the
/// other invariants' windows.
#[test]
fn invariant_2b_tampered_signed_content_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let honest = w.to_ffi_bytes().expect("serialize");

    // Flip a bit in a byte that is NOT inside any JSON invariant window.
    // Byte at sc_start + 7 is inside `"scheme":"secp256k1"` (after all
    // other fields). Flipping invalidates SHA(sc) but keeps
    // pk/nonce/context/decl byte_range_eq intact.
    //
    // Actually to be safe, let's tamper the LAST byte of signed_content —
    // the closing '}' of the JSON. Not inside any JSON-field window.
    // First, figure out sc_len from the blob header.
    let sc_len = u32::from_le_bytes([
        honest[40], honest[41], honest[42], honest[43],
    ]) as usize;
    let last_sc_byte = SC_START_IN_BLOB + sc_len - 1;

    let mut tampered = honest.clone();
    tampered[last_sc_byte] ^= 0x01;

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&tampered, &pub_blob)
        .expect_err("prove must refuse when signed_content hash changes");
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(_) => {}
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}

/// (3) Tampered message_digest: no longer equals SHA-256(signed_content),
/// so the in-circuit SHA check fails.
#[test]
fn invariant_2b_tampered_message_digest_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let honest = w.to_ffi_bytes().expect("serialize");

    let mut tampered = honest.clone();
    // Flip a byte in the middle of message_digest[32].
    tampered[MESSAGE_DIGEST_IN_BLOB + 15] ^= 0xff;

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&tampered, &pub_blob)
        .expect_err("prove must refuse when message_digest doesn't match SHA");
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(_) => {}
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}
