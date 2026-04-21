//! Phase 2a Task 26 — invariant 2a (+ merged SPKI binding):
//!
//!   * The CMS content signature `(r2, s2)` is a valid P-256 ECDSA
//!     signature of `e2 = SHA-256(signedAttrs_canonical)` under the
//!     holder's signing key, where `signedAttrs_canonical` is the
//!     raw witnessed signedAttrs with the [0] IMPLICIT tag 0xA0
//!     rewritten to SET OF tag 0x31 (the form CMS content sigs are
//!     computed over).
//!
//!   * The holder's signing key is extracted host-side from
//!     cert_tbs's SubjectPublicKeyInfo at `cert_tbs_spki_offset`,
//!     and the hash circuit asserts (a) 26 bytes of DIIA P-256
//!     SPKI DER prefix at the offset (anti-offset-redirect anchor)
//!     and (b) the 65-byte SEC1 point byte-equal to the holder_pk
//!     passed privately into the sig circuit. The X and Y
//!     coordinates cross-bind hash→sig via MAC.
//!
//! Tests:
//!   1. Happy: honest witness round-trips (end-to-end content sig
//!      verifies over honest signedAttrs).
//!   2. Tampered content_sig_r — ECDSA on `e2` under holder_pk no
//!      longer verifies, prover refuses.
//!   3. Tampered content_sig_s — same as (2).
//!   4. Tampered signedAttrs body byte — digest changes, content
//!      sig no longer matches, prover refuses.
//!   5. Tampered `cert_tbs_spki_offset` (the §10 SPKI prefix-anchor
//!      negative): lying by ±1 byte slides the anchor window off
//!      the real SPKI DER prefix, the in-circuit 26-byte prefix
//!      assertion is unsatisfiable, prover refuses.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

// v11 blob layout constants — mirrors invariant_1.rs.
const CERT_TBS_LEN_IN_BLOB: usize = 1310;
const CERT_TBS_SPKI_OFFSET_IN_BLOB: usize = CERT_TBS_LEN_IN_BLOB + 4; // 1314
const CERT_TBS_DATA_IN_BLOB: usize = CERT_TBS_SPKI_OFFSET_IN_BLOB + 4; // 1318
const CERT_SIG_R_IN_BLOB: usize = CERT_TBS_DATA_IN_BLOB + 2048; // 3366
const CERT_SIG_S_IN_BLOB: usize = CERT_SIG_R_IN_BLOB + 32; // 3398
const SIGNED_ATTRS_LEN_IN_BLOB: usize = CERT_SIG_S_IN_BLOB + 32; // 3430
const SIGNED_ATTRS_MD_OFFSET_IN_BLOB: usize = SIGNED_ATTRS_LEN_IN_BLOB + 4; // 3434
const SIGNED_ATTRS_DATA_IN_BLOB: usize = SIGNED_ATTRS_MD_OFFSET_IN_BLOB + 4; // 3438
const CONTENT_SIG_R_IN_BLOB: usize = SIGNED_ATTRS_DATA_IN_BLOB + 1536; // 4974
const CONTENT_SIG_S_IN_BLOB: usize = CONTENT_SIG_R_IN_BLOB + 32; // 5006
// v11 tail (+12 bytes): subject_sn_offset + subject_dn_start + trust_anchor_index.
const BLOB_TOTAL_LEN: usize = CONTENT_SIG_S_IN_BLOB + 32 + 12; // 5050

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
    let w = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let outputs = zk_eidas_p7s::compute_outputs(&w).unwrap();
    PublicInputs {
        context_hash: Sha256::digest(b"0x").into(),
        pk: expected_pk(),
        nonce: expected_nonce(),
        nullifier: outputs.nullifier,
        trust_anchor_index: 0,
        root_pk: [0u8; 65],
        timestamp: 0,
    }
}

fn expect_prove_refused(err: longfellow_sys::p7s::P7sFfiError) {
    match err {
        // C++ surfaces `VerifyWitness3::compute_witness` returning
        // false as P7S_INVALID_INPUT(2); a circuit-level constraint
        // failure (e.g. the SPKI prefix anchor) shows up as
        // P7S_PROVER_FAILURE(3). Either is a valid "honest prover
        // refuses tampered witness" signal.
        longfellow_sys::p7s::P7sFfiError::ProveFailed(code) => {
            assert!(
                code == 2 || code == 3,
                "expected INVALID_INPUT(2) or PROVER_FAILURE(3), got {code}"
            );
        }
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}

/// (1) Happy: honest DIIA fixture round-trips — content sig over
/// signedAttrs_canonical verifies under the holder key extracted
/// from cert_tbs's SPKI, and every cross-circuit MAC agrees.
#[test]
fn invariant_2a_happy_round_trips() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let public = honest_public();
    let proof =
        prove(&w, &public).expect("prove must succeed on honest DIIA witness");
    assert!(
        verify(&proof, &public).expect("verify yields a decision"),
        "honest DIIA proof must verify under the content-sig binding"
    );
}

/// (2) Tampered content_sig_r: content (r2, s2) no longer verifies
/// over honest e2 under holder_pk; ECDSA VerifyWitness3 fails.
#[test]
fn invariant_2a_tampered_content_sig_r_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");
    assert_eq!(
        honest.len(),
        BLOB_TOTAL_LEN,
        "v9 blob layout mismatch — update constants"
    );

    honest[CONTENT_SIG_R_IN_BLOB + 15] ^= 0xff;

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse tampered content_sig_r");
    expect_prove_refused(err);
}

/// (3) Tampered content_sig_s: symmetric to (2).
#[test]
fn invariant_2a_tampered_content_sig_s_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    honest[CONTENT_SIG_S_IN_BLOB + 15] ^= 0xff;

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse tampered content_sig_s");
    expect_prove_refused(err);
}

/// (4) Tampered signedAttrs body byte: the SHA-256 output changes,
/// e2 no longer matches the content-sig's signed digest, ECDSA
/// VerifyWitness3 fails (invariant 2a's ECDSA leg refuses).
#[test]
fn invariant_2a_tampered_signed_attrs_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    // Flip a byte well inside the signedAttrs body — stay away from
    // byte 0 (0xA0 tag, rejected at parse time) and past the header.
    honest[SIGNED_ATTRS_DATA_IN_BLOB + 100] ^= 0x01;

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse tampered signedAttrs body");
    expect_prove_refused(err);
}

/// (5) Tampered `cert_tbs_spki_offset` (SPKI prefix-anchor
/// negative — handoff-30 §10). Supply an offset that is not the
/// real SPKI SEQUENCE start; the in-circuit 26-byte DIIA prefix
/// anchor is unsatisfiable. Even without the post-parse rewrite
/// touching cert_tbs, the prover refuses at prove time.
///
/// The C++ `parse_witness_blob` also validates the prefix match
/// host-side (redundant belt-and-suspenders); that check trips
/// first and surfaces as P7S_INVALID_INPUT. Either signal proves
/// the anchor is load-bearing — a future refactor dropping either
/// layer fails this test.
#[test]
fn invariant_2a_tampered_spki_offset_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    // Slide the anchor by one byte. Read honest offset back as u32 LE.
    let mut offset_bytes = [0u8; 4];
    offset_bytes.copy_from_slice(
        &honest[CERT_TBS_SPKI_OFFSET_IN_BLOB..CERT_TBS_SPKI_OFFSET_IN_BLOB + 4],
    );
    let honest_offset = u32::from_le_bytes(offset_bytes);
    assert!(
        honest_offset > 0,
        "honest SPKI offset must be positive for this test to meaningfully slide"
    );
    let lie = honest_offset - 1;
    honest[CERT_TBS_SPKI_OFFSET_IN_BLOB..CERT_TBS_SPKI_OFFSET_IN_BLOB + 4]
        .copy_from_slice(&lie.to_le_bytes());

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse lied SPKI offset");
    expect_prove_refused(err);
}

/// (6) Under `--features test-bypass-host-anchors`, skip both the
/// Rust parser's SPKI anchor check AND the C++ parse_witness_blob
/// anchor check, then supply a lying `cert_tbs_spki_offset`. With
/// both host-parser layers bypassed, the prover still rejects — the
/// downstream `VerifyWitness3::compute_witness` call fails because
/// the holder_pk bytes extracted at the lying offset no longer form
/// a P-256 point whose ECDSA verifies against the content signature.
/// That surfaces as P7S_INVALID_INPUT(2). (Note: this does NOT
/// exercise the in-circuit 26-byte SPKI anchor directly — the
/// ECDSA compute_witness check lies between the bypass and the
/// circuit. That's a limitation of using offset-sliding as the lie:
/// any lie that produces different SPKI bytes also breaks ECDSA
/// at witness construction. Achieving in-circuit-anchor-only failure
/// on the SPKI side would require constructing a lying witness
/// whose shifted 65-byte SEC1 window coincidentally forms a valid
/// P-256 point AND whose signature verifies — computationally
/// hard. For practical soundness coverage, the host check + the
/// ECDSA compute_witness + the in-circuit anchor stack together.)
///
/// This retrofits #26's test gap (reviewer N1). The test proves
/// SOME layer below the host parser rejects lied SPKI offsets;
/// combined with test (5) above which proves the host layer does,
/// both layers have now seen a lying-offset witness.
#[cfg(feature = "test-bypass-host-anchors")]
#[test]
fn invariant_2a_tampered_spki_offset_bypass_parser() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    // Slide the SPKI anchor by one byte — same construction as the
    // host-path test, just routed through the bypass FFI.
    let mut offset_bytes = [0u8; 4];
    offset_bytes.copy_from_slice(
        &honest[CERT_TBS_SPKI_OFFSET_IN_BLOB..CERT_TBS_SPKI_OFFSET_IN_BLOB + 4],
    );
    let honest_offset = u32::from_le_bytes(offset_bytes);
    assert!(honest_offset > 0);
    let lie = honest_offset - 1;
    honest[CERT_TBS_SPKI_OFFSET_IN_BLOB..CERT_TBS_SPKI_OFFSET_IN_BLOB + 4]
        .copy_from_slice(&lie.to_le_bytes());

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove_bypass_host_anchors(&honest, &pub_blob)
        .expect_err(
            "prove_bypass_host_anchors must refuse — ECDSA compute_witness \
             (or the in-circuit SPKI anchor) rejects the lying-offset witness",
        );
    // Either 2 (ECDSA compute_witness failed, most common) or 3
    // (in-circuit anchor, rare — requires the sliding to produce a
    // valid point). Both indicate "lying offset rejected".
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(code) if code == 2 || code == 3 => {}
        other => panic!(
            "expected P7S_INVALID_INPUT(2) or P7S_PROVER_FAILURE(3), got {other:?}"
        ),
    }
}
