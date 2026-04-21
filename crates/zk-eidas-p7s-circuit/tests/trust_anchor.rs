//! Phase 2b Task 36 — trust-anchor multi-QTSP refactor. Tests the
//! refactored selection path where the signer cert's issuer DN picks
//! a compile-time `kTrustAnchors[]` entry, and the in-circuit `vlt`
//! bound check ensures the witnessed `trust_anchor_index` refers to
//! an anchor that actually exists.
//!
//! Phase 2b ships with `kTrustAnchorCount = 1` (DIIA only). Task #37
//! will extend both the submodule's table and the host-side
//! `TRUST_ANCHOR_PROBES` list; the *shape* of the selection wiring
//! under test here doesn't change.
//!
//! Tests:
//!   1. Happy: honest DIIA fixture → prove + verify succeeds with
//!      `trust_anchor_index = 0` (the parser-picked value). Same
//!      round-trip as `fixture_diia.rs` but scoped to the
//!      trust-anchor surface.
//!   2. Out-of-range: host-tamper the witness-blob `trust_anchor_index`
//!      to `1` (no such entry in the N=1 table). Both the C++
//!      parse_witness_blob host-side bound check AND the in-circuit
//!      `vlt(index, kTrustAnchorCount)` assertion reject — the host
//!      check trips first and surfaces P7S_INVALID_INPUT.
//!   3. Compile-time sanity: documents the `static_assert(
//!      kTrustAnchorCount >= 1)` guard in `sub/p7s_signature.h`.
//!      Runtime no-op — if the submodule ever emptied the table, the
//!      C++ build (and therefore this whole crate's build) would
//!      fail long before this test runs. Kept as a present-tense
//!      reminder for future extenders.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::{build_witness, compute_outputs};
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

// v11 blob tail offsets — mirrors invariant_7.rs's `SUBJECT_SN_OFFSET_IN_BLOB`
// + 8 (sn_offset + dn_start_offset = two u32s). The trust_anchor_index
// is the final u32 in the witness blob.
const CONTENT_SIG_S_END: usize = 5038;
const TRUST_ANCHOR_IDX_IN_BLOB: usize = CONTENT_SIG_S_END + 8; // 5046
const BLOB_TOTAL_LEN: usize = TRUST_ANCHOR_IDX_IN_BLOB + 4; // 5050

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
    let outputs = compute_outputs(&w).unwrap();
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
        longfellow_sys::p7s::P7sFfiError::ProveFailed(code) => {
            assert!(
                code == 2 || code == 3,
                "expected INVALID_INPUT(2) or PROVER_FAILURE(3), got {code}"
            );
        }
        other => panic!("expected ProveFailed, got {other:?}"),
    }
}

/// (1) Honest round-trip at `trust_anchor_index = 0`. The parser's
/// issuer-DN probe picks 0 for the DIIA fixture, the in-circuit
/// `vlt(0, 1)` is satisfied, and the cert-sig ECDSA verifies under
/// `kTrustAnchors[0]`. This mirrors `fixture_diia::prove_verify_round_trip`
/// — duplicated here as a dedicated trust-anchor-surface test so the
/// full regression suite still passes post-refactor.
#[test]
fn trust_anchor_happy_diia_index_0_prover_accepts() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    // Parser-picked index. For DIIA fixtures this must be 0.
    assert_eq!(
        inner.offsets.trust_anchor_index, 0,
        "parser must pick index 0 for a DIIA-issued cert"
    );

    let w = Witness::new(inner);
    let public = honest_public();
    let proof =
        prove(&w, &public).expect("prove must succeed on honest DIIA witness");
    assert!(
        verify(&proof, &public).expect("verify yields a decision"),
        "honest DIIA proof must verify under kTrustAnchors[0]"
    );
}

/// (2) Out-of-range index: the host parser picks `0`, but we tamper
/// the witness blob AFTER serialization to claim `1`. The C++
/// `parse_witness_blob` check `trust_anchor_index < kTrustAnchorCount`
/// trips first → P7S_INVALID_INPUT. Without the host check (or with
/// `kTrustAnchorCount` later grown to 2+ but the prover overshooting
/// beyond the actual size) the in-circuit `vlt(index, N)` assertion
/// takes over — same observable "prover refuses", different code
/// point. Either is a valid "bound check is live" signal.
#[test]
fn trust_anchor_out_of_range_index_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut tampered = w.to_ffi_bytes().expect("serialize");
    assert_eq!(
        tampered.len(),
        BLOB_TOTAL_LEN,
        "v11 blob layout mismatch — update constants"
    );

    // Overwrite the trust_anchor_index u32 with a value beyond the
    // N=1 table. Any value >= kTrustAnchorCount is out-of-range;
    // 1 is the minimal violation.
    tampered[TRUST_ANCHOR_IDX_IN_BLOB..TRUST_ANCHOR_IDX_IN_BLOB + 4]
        .copy_from_slice(&1u32.to_le_bytes());

    // Public blob also carries trust_anchor_index (mirror of the
    // witness field); keep them in sync so the test targets the
    // range check rather than a mirror-mismatch rejection. The
    // C++ parse_public_blob applies the same bound check (`index
    // < kTrustAnchorCount`) so setting it to 1 here will also trip
    // P7S_INVALID_INPUT at verify time — but prove fails first
    // because the witness blob is parsed before the public blob
    // in the prove call path.
    let mut public = honest_public();
    public.trust_anchor_index = 1;
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&tampered, &pub_blob)
        .expect_err("prove must refuse out-of-range trust_anchor_index");
    expect_prove_refused(err);
}

/// (3) Compile-time sanity. `sub/p7s_signature.h` carries
/// `static_assert(kTrustAnchorCount >= 1, ...)`. If a future refactor
/// empties the table that static_assert would fire at C++ compile
/// time — long before the Rust test harness runs. This runtime stub
/// exists as a present-tense reminder for future extenders that the
/// invariant is enforced at the submodule layer.
#[test]
fn trust_anchor_table_minimum_size_compile_assert() {
    // Intentionally empty — the real enforcement is the submodule's
    // static_assert. See vendor/longfellow-zk/lib/circuits/p7s/sub/
    // p7s_signature.h near the `kTrustAnchorCount` definition.
}
