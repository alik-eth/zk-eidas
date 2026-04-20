//! Phase 2a Task 29 (25b) — invariant 1: the signer cert's ECDSA
//! signature verifies over `cert_tbs` under the hardcoded DIIA QTSP
//! 2311 root pubkey, and the cross-circuit MAC binds the resulting
//! digest `e = SHA-256(cert_tbs)` across the hash / sig circuit split.
//!
//! The DIIA root is compile-time constant in the C++ sig circuit
//! (see `vendor/longfellow-zk/lib/circuits/p7s/sub/p7s_signature.h`),
//! so the honest path only passes when the fixture's cert_sig is a
//! genuine DIIA-minted signature.
//!
//! Tests:
//!   1. Happy: honest witness round-trips.
//!   2. Tampered cert_tbs byte — SHA digest changes → ECDSA verify
//!      fails → compute_witness returns false → P7S_INVALID_INPUT.
//!   3. Tampered r scalar — signature no longer verifies under the
//!      DIIA root → same failure mode.
//!   4. Tampered s scalar — same as (3).

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

// v8 blob offsets — keep in sync with `witness.rs`'s serializer.
// Layout (LE u32s = 4 bytes each):
//   0   version(4) + ctx_len(4) + ctx(32) + sc_len(4)           = 44
//   44  signed_content(1024)                                     = 1068
//   1068 json_pk_offset(4) + pk_hex(130)                          = 1202
//   1202 json_nonce_offset(4) + nonce_hex(64)                     = 1270
//   1270 json_context_offset(4)                                   = 1274
//   1274 json_declaration_offset(4)                               = 1278
//   1278 message_digest(32)                                       = 1310
//   1310 cert_tbs_len(4) + cert_tbs(2048)                         = 3362
//   3362 cert_sig_r(32) + cert_sig_s(32)                          = 3426
const SC_START_IN_BLOB: usize = 44;
const CERT_TBS_LEN_IN_BLOB: usize = 1310;
const CERT_TBS_DATA_IN_BLOB: usize = CERT_TBS_LEN_IN_BLOB + 4; // 1314
const CERT_SIG_R_IN_BLOB: usize = CERT_TBS_DATA_IN_BLOB + 2048; // 3362
const CERT_SIG_S_IN_BLOB: usize = CERT_SIG_R_IN_BLOB + 32; // 3394
const BLOB_TOTAL_LEN: usize = CERT_SIG_S_IN_BLOB + 32; // 3426

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

/// (1) Happy: honest DIIA fixture round-trips.
#[test]
fn invariant_1_happy_round_trips() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let public = honest_public();
    let proof = prove(&w, &public).expect("prove must succeed on honest DIIA witness");
    assert!(
        verify(&proof, &public).expect("verify yields a decision"),
        "honest DIIA proof must verify against the hardcoded root pubkey"
    );
}

/// (2) Tampered cert_tbs byte: the SHA-256 output changes, the cert
/// signature no longer verifies on the tampered `e`, and the prover
/// refuses at witness-generation time (P7S_INVALID_INPUT).
#[test]
fn invariant_1_tampered_cert_tbs_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");
    assert_eq!(
        honest.len(),
        BLOB_TOTAL_LEN,
        "v8 blob layout mismatch — update constants"
    );

    // Flip a byte inside cert_tbs (away from any byte-range window).
    // Byte 100 of cert_tbs is well inside the TBS body.
    honest[CERT_TBS_DATA_IN_BLOB + 100] ^= 0x01;

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse tampered cert_tbs");
    match err {
        // The tampered SHA → wrong e → (r,s) don't verify → C++
        // `VerifyWitness3::compute_witness` returns false, which the
        // host layer surfaces as P7S_INVALID_INPUT (code 2).
        longfellow_sys::p7s::P7sFfiError::ProveFailed(code) => {
            assert!(
                code == 2 || code == 3,
                "expected INVALID_INPUT(2) or PROVER_FAILURE(3), got {code}"
            );
        }
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}

/// (3) Tampered `r` scalar: the (r, s) pair is no longer a valid
/// signature of the honest `e` under the DIIA root — compute_witness
/// returns false, the C++ prover returns P7S_INVALID_INPUT.
#[test]
fn invariant_1_tampered_r_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    // Flip a byte in r (middle of the 32-byte scalar).
    honest[CERT_SIG_R_IN_BLOB + 15] ^= 0xff;

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse tampered r");
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(code) => {
            assert!(
                code == 2 || code == 3,
                "expected INVALID_INPUT(2) or PROVER_FAILURE(3), got {code}"
            );
        }
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}

/// (4) Tampered `s` scalar: symmetric to (3).
#[test]
fn invariant_1_tampered_s_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    // Flip a byte in s (middle of the 32-byte scalar).
    honest[CERT_SIG_S_IN_BLOB + 15] ^= 0xff;

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse tampered s");
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(code) => {
            assert!(
                code == 2 || code == 3,
                "expected INVALID_INPUT(2) or PROVER_FAILURE(3), got {code}"
            );
        }
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}
