//! Trust-anchor multi-QTSP refactor (Task 36) + N=2 multiplexer
//! (Task #44). Tests the selection path where the signer cert's
//! issuer DN picks a compile-time `kTrustAnchors[]` entry, and the
//! in-circuit `vlt` bound check + sig-circuit one-hot mux ensure
//! the witnessed `trust_anchor_index` refers to an anchor that
//! actually exists.
//!
//! Phase 2b ships with `kTrustAnchorCount = 2` (TestAnchorA +
//! TestAnchorB, both synthetic). Task #37 will extend the table with
//! real-QTSP anchors; the shape of the selection wiring under test
//! here is already N>1 and doesn't change.
//!
//! Tests:
//!   1. Happy (A): honest TestAnchorA fixture → prove + verify OK.
//!   2. Out-of-range: host-tamper the witness-blob `trust_anchor_index`
//!      to `kTrustAnchorCount` (first invalid value — 2). Both the
//!      host-side `parse_witness_blob` check AND the in-circuit
//!      `vlt(index, kTrustAnchorCount)` assertion reject.
//!   3. Compile-time sanity: documents the `static_assert(
//!      kTrustAnchorCount >= 1)` guard in `sub/p7s_signature.h`.
//!   4. Bypass-gated range-check (feature `test-bypass-host-anchors`):
//!      host bound check skipped; the in-circuit `vlt` must still
//!      reject an index >= kTrustAnchorCount.
//!   5. Happy (B): honest TestAnchorB fixture + index 1 → prove +
//!      verify OK. Exercises the N=2 multiplexer on the non-zero branch.
//!   6. Wrong-index rejected: TestAnchorA fixture with
//!      `trust_anchor_index = 1` (lies about which anchor signed) →
//!      cert-sig ECDSA verify fails because kTrustAnchors[1] is
//!      TestAnchorB's root, not A's.
//!   7. Bypass-gated range-check at 5: `trust_anchor_index = 5` with
//!      host bypass → in-circuit `vlt` assertion rejects.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::{build_witness, compute_outputs};
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

// v11 blob tail offsets — mirrors nullifier.rs's `SUBJECT_SN_OFFSET_IN_BLOB`
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
/// `kTrustAnchors[0]`. This mirrors `fixture_test_anchor_a::prove_verify_round_trip_on_test_anchor_a_fixture`
/// — duplicated here as a dedicated trust-anchor-surface test so the
/// full regression suite still passes post-refactor.
#[test]
fn trust_anchor_happy_index_0_prover_accepts() {
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
/// the witness blob AFTER serialization to claim `kTrustAnchorCount`
/// (2 — the smallest out-of-range value for the N=2 table). Both the
/// C++ `parse_witness_blob` host-side bound check AND the in-circuit
/// `vlt(index, kTrustAnchorCount)` assertion reject — the host check
/// trips first and surfaces P7S_INVALID_INPUT.
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

    // Overwrite the trust_anchor_index u32 with the smallest value
    // beyond the N=2 table. kTrustAnchorCount = 2 (see
    // sub/p7s_signature.h), so 2 is the minimal violation.
    tampered[TRUST_ANCHOR_IDX_IN_BLOB..TRUST_ANCHOR_IDX_IN_BLOB + 4]
        .copy_from_slice(&2u32.to_le_bytes());

    // Public blob also carries trust_anchor_index (mirror of the
    // witness field); keep them in sync so the test targets the
    // range check rather than a mirror-mismatch rejection.
    let mut public = honest_public();
    public.trust_anchor_index = 2;
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

/// (4) **Bypass-gated companion to (2).** Under
/// `--features test-bypass-host-anchors`, the C++ `parse_witness_blob`
/// bounds check `trust_anchor_index < kTrustAnchorCount` is skipped,
/// so the out-of-range index reaches the circuit's
/// `lc.assert1(lc.vlt(trust_anchor_index, kTrustAnchorCount))`
/// — the SOLE remaining enforcement layer.
///
/// For the N=2 table, we pick `5` (well beyond the table) to make
/// failure unambiguous regardless of how future N growth shifts the
/// "first invalid" value. `vlt(5, 2)` = false → `assert1(0)` →
/// eval_circuit fails → P7S_PROVER_FAILURE(3). Closes reviewer-2
/// audit nit N3 from #36 / follow-up from #44.
///
/// Note: the public blob's `trust_anchor_index` field is also checked
/// by `parse_public_blob` before `parse_witness_blob` in the prove
/// call path. To avoid P7S_INVALID_INPUT from the public-blob check,
/// we set `public.trust_anchor_index = 0` (in-range), while supplying
/// the out-of-range `5` only in the WITNESS blob. The mismatch between
/// public `0` and witness `5` would ordinarily be caught host-side,
/// but the bypass FFI skips the witness-blob bounds check — so the
/// circuit sees witness index `5` and the `vlt` assertion fires
/// before any array access.
#[cfg(feature = "test-bypass-host-anchors")]
#[test]
fn prove_out_of_range_index_rejected() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut tampered = w.to_ffi_bytes().expect("serialize");
    assert_eq!(
        tampered.len(),
        BLOB_TOTAL_LEN,
        "v11 blob layout mismatch — update constants"
    );

    // Supply trust_anchor_index = 5 in the WITNESS blob only.
    // The N=2 table has indices 0 and 1; 5 is unambiguously out-of-range.
    tampered[TRUST_ANCHOR_IDX_IN_BLOB..TRUST_ANCHOR_IDX_IN_BLOB + 4]
        .copy_from_slice(&5u32.to_le_bytes());

    // Keep the PUBLIC blob at index 0 to avoid tripping parse_public_blob's
    // own bound check before the witness-blob bypass path is reached.
    let public = honest_public();
    assert_eq!(
        public.trust_anchor_index, 0,
        "honest_public() must carry index 0 for the TestAnchorA fixture"
    );
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove_bypass_host_anchors(&tampered, &pub_blob)
        .expect_err(
            "prove_bypass_host_anchors must refuse — in-circuit \
             vlt(trust_anchor_index=5, kTrustAnchorCount=2) = false \
             → assert1(0) → P7S_PROVER_FAILURE",
        );
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(3) => {}
        other => panic!(
            "expected P7S_PROVER_FAILURE(3) from in-circuit vlt assert, got {other:?}"
        ),
    }
}

// ── TestAnchorB tests (Task #44) ─────────────────────────────────────

const FIXTURE_B: &[u8] =
    include_bytes!("../../zk-eidas-p7s/fixtures/testanchor-b-binding.qkb.p7s");

fn expected_pk_b() -> [u8; 65] {
    let w = build_witness(FIXTURE_B, b"0x", DUMMY_ROOT_PK).unwrap();
    let off = &w.offsets;
    let mut out = [0u8; 65];
    hex::decode_to_slice(
        &w.p7s_bytes[off.json_pk_start..off.json_pk_start + off.json_pk_len],
        &mut out,
    )
    .unwrap();
    out
}

fn expected_nonce_b() -> [u8; 32] {
    let w = build_witness(FIXTURE_B, b"0x", DUMMY_ROOT_PK).unwrap();
    let off = &w.offsets;
    let mut out = [0u8; 32];
    hex::decode_to_slice(
        &w.p7s_bytes[off.json_nonce_start..off.json_nonce_start + off.json_nonce_len],
        &mut out,
    )
    .unwrap();
    out
}

fn honest_public_b() -> PublicInputs {
    let w = build_witness(FIXTURE_B, b"0x", DUMMY_ROOT_PK).unwrap();
    let outputs = compute_outputs(&w).unwrap();
    PublicInputs {
        context_hash: Sha256::digest(b"0x").into(),
        pk: expected_pk_b(),
        nonce: expected_nonce_b(),
        nullifier: outputs.nullifier,
        trust_anchor_index: 1,
        root_pk: [0u8; 65],
        timestamp: 0,
    }
}

/// (5) Happy TestAnchorB round-trip at `trust_anchor_index = 1`.
/// Exercises the non-zero branch of the N=2 sig-side mux: the circuit
/// picks `kTrustAnchors[1]` (TestAnchorB root) and verifies the cert
/// signature against it. Parser's issuer-DN probe independently picks
/// 1 for the TestAnchorB fixture.
#[test]
fn prove_testanchor_b_happy_path() {
    let inner = build_witness(FIXTURE_B, b"0x", DUMMY_ROOT_PK).unwrap();
    assert_eq!(
        inner.offsets.trust_anchor_index, 1,
        "parser must pick index 1 for a TestAnchorB-issued cert"
    );

    let w = Witness::new(inner);
    let public = honest_public_b();
    let proof =
        prove(&w, &public).expect("prove must succeed on honest TestAnchorB witness");
    assert!(
        verify(&proof, &public).expect("verify yields a decision"),
        "honest TestAnchorB proof must verify under kTrustAnchors[1]"
    );
}

/// (6) Wrong-index rejected: a TestAnchorA witness claims
/// `trust_anchor_index = 1` (TestAnchorB's slot). The sig-circuit mux
/// picks `kTrustAnchors[1]` (TestAnchorB's root), but the cert_sig
/// was signed by TestAnchorA's root — ECDSA verify fails at
/// prove time (compute_witness returns false →
/// P7S_INVALID_INPUT) or verify time depending on where the bad
/// witness surfaces. Either outcome is a valid "cross-anchor lying
/// is rejected" signal.
///
/// Parser naturally resolves TestAnchorA's fixture to index 0, so we
/// override the witness blob post-serialization.
#[test]
fn prove_testanchor_a_with_wrong_index_rejected() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut tampered = w.to_ffi_bytes().expect("serialize");
    assert_eq!(tampered.len(), BLOB_TOTAL_LEN);

    // Override witness trust_anchor_index = 1 (in-range for N=2, but
    // lies about which anchor signed the cert).
    tampered[TRUST_ANCHOR_IDX_IN_BLOB..TRUST_ANCHOR_IDX_IN_BLOB + 4]
        .copy_from_slice(&1u32.to_le_bytes());

    let mut public = honest_public();
    public.trust_anchor_index = 1;
    let pub_blob = public.to_ffi_bytes();

    let err = longfellow_sys::p7s::prove(&tampered, &pub_blob)
        .expect_err("prove must refuse — A's cert_sig doesn't verify under B's root");
    expect_prove_refused(err);
}
