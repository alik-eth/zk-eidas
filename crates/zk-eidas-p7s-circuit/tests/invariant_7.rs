//! Phase 2b Task 34 — invariant 7: `nullifier == SHA-256(stable_id[16] ||
//! context_raw)`, where `stable_id` is the 16-byte PrintableString
//! value of the X.520 serialNumber attribute in cert_tbs's Subject DN
//! (synthetic TestAnchorA stable-ID format; mirrors the real-DIIA
//! RNOKPP layout of `TINUA-` + 10 digits). The host computes the
//! same formula in `zk_eidas_p7s::compute_outputs` (Phase 1); the
//! circuit enforces it so a malicious prover can't lie.
//!
//! Tests (per plan §Step-14):
//!   1. Happy: honest TestAnchorA fixture → prove+verify; in-circuit
//!      nullifier equals the Phase 1 host-computed nullifier.
//!   2. Cross-holder same RNOKPP: both `binding.qkb.p7s` and
//!      `admin-binding.qkb.p7s` share the same holder RNOKPP — same
//!      nullifier.
//!   3. Tampered stable_id bytes in cert_tbs: SHA input changes,
//!      prover refuses.
//!   4. Tampered `subject_sn_offset` into issuer-DN serialNumber: the
//!      dual-match range check `sn_offset > subject_dn_start` fails,
//!      prover refuses. LOAD-BEARING soundness test — without the
//!      range check, the prover could bind `nullifier` to the issuer
//!      QTSP's reg code instead of the holder's RNOKPP.
//!   5. Wrong public context: the prover commits to the honest
//!      context-in-SHA, but the caller supplies a different public
//!      context_hash → different nullifier in `PublicInputs` → the
//!      in-circuit byte equality between computed SHA output and
//!      public `nullifier` fails.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::{build_witness, compute_outputs};
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE_BINDING: &[u8] =
    include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const FIXTURE_ADMIN: &[u8] =
    include_bytes!("../../zk-eidas-p7s/fixtures/admin-binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

// v11 blob tail layout (see invariant_1.rs for full layout). Only the
// tail offsets are needed here for tampering tests.
const CONTENT_SIG_S_END: usize = 5038;
const SUBJECT_SN_OFFSET_IN_BLOB: usize = CONTENT_SIG_S_END; // 5038
const SUBJECT_DN_START_IN_BLOB: usize = SUBJECT_SN_OFFSET_IN_BLOB + 4; // 5042
#[allow(dead_code)]
const TRUST_ANCHOR_IDX_IN_BLOB: usize = SUBJECT_DN_START_IN_BLOB + 4; // 5046

const CERT_TBS_DATA_IN_BLOB: usize = 1318;

fn expected_pk(fx: &[u8]) -> [u8; 65] {
    let w = build_witness(fx, b"0x", DUMMY_ROOT_PK).unwrap();
    let off = &w.offsets;
    let mut out = [0u8; 65];
    hex::decode_to_slice(
        &w.p7s_bytes[off.json_pk_start..off.json_pk_start + off.json_pk_len],
        &mut out,
    )
    .unwrap();
    out
}

fn expected_nonce(fx: &[u8]) -> [u8; 32] {
    let w = build_witness(fx, b"0x", DUMMY_ROOT_PK).unwrap();
    let off = &w.offsets;
    let mut out = [0u8; 32];
    hex::decode_to_slice(
        &w.p7s_bytes[off.json_nonce_start..off.json_nonce_start + off.json_nonce_len],
        &mut out,
    )
    .unwrap();
    out
}

fn honest_public(fx: &[u8]) -> PublicInputs {
    let w = build_witness(fx, b"0x", DUMMY_ROOT_PK).unwrap();
    let outputs = compute_outputs(&w).unwrap();
    PublicInputs {
        context_hash: Sha256::digest(b"0x").into(),
        pk: expected_pk(fx),
        nonce: expected_nonce(fx),
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

/// (1) Happy path. Also asserts the parser reports stable_id offset
/// 370 for the fixture — drifts here would change the anchor story,
/// so we want a hard fail rather than a silent regression.
#[test]
fn invariant_7_nullifier_matches_phase1_host_output() {
    let inner = build_witness(FIXTURE_BINDING, b"0x", DUMMY_ROOT_PK).unwrap();
    assert_eq!(
        inner.offsets.subject_sn_offset_in_tbs, 370,
        "TestAnchorA fixture's X.520 serialNumber offset within cert_tbs \
         must be 370 (see fixtures/kat-subject-serial.json); the synthetic \
         cert preserves this offset by being a length-preserving rewrite \
         of the original DIIA layout"
    );
    assert_eq!(
        inner.offsets.subject_dn_start_offset_in_tbs, 294,
        "TestAnchorA fixture's Subject DN start offset within cert_tbs \
         must be 294 (measured: issuer_end + validity = 294)"
    );
    let expected = compute_outputs(&inner).unwrap();
    let w = Witness::new(inner);
    let public = honest_public(FIXTURE_BINDING);
    assert_eq!(
        public.nullifier, expected.nullifier,
        "public.nullifier and compute_outputs must agree"
    );
    let proof = prove(&w, &public).expect("prove honest");
    assert!(
        verify(&proof, &public).expect("verify yields a decision"),
        "honest proof must verify"
    );
}

/// (2) Both TestAnchorA fixtures share the same synthetic holder and
/// therefore the same stable-ID. Under the same public context, the
/// two proofs MUST expose the SAME `nullifier` — this is the
/// cross-cert-renewal property invariant 7 guarantees (Phase 1
/// comment on `outputs.rs:17-41`).
#[test]
fn invariant_7_cross_holder_same_rnokpp_same_nullifier() {
    let w1 = build_witness(FIXTURE_BINDING, b"0x", DUMMY_ROOT_PK).unwrap();
    let w2 = build_witness(FIXTURE_ADMIN, b"0x", DUMMY_ROOT_PK).unwrap();
    let o1 = compute_outputs(&w1).unwrap();
    let o2 = compute_outputs(&w2).unwrap();
    assert_eq!(
        o1.nullifier, o2.nullifier,
        "same-RNOKPP fixtures must produce identical nullifiers under \
         the same context — if this asserts, the fixtures don't share a \
         holder (or the parser drifted)"
    );
    // Spot-check: both also produce matching stable_id bytes.
    let s1 = &w1.p7s_bytes
        [w1.offsets.subject_sn_start..w1.offsets.subject_sn_start + 16];
    let s2 = &w2.p7s_bytes
        [w2.offsets.subject_sn_start..w2.offsets.subject_sn_start + 16];
    assert_eq!(s1, s2, "same-holder fixtures must have the same stable_id");
    assert_eq!(
        std::str::from_utf8(s1).unwrap_or(""),
        "TINUA-1111111111",
        "fixture stable_id drifted from kat-subject-serial.json baseline"
    );
}

/// (3) Tampered stable_id bytes inside `cert_tbs`: the 16-byte
/// PrintableString value at `cert_tbs[subject_sn_offset + 9 .. + 25]`
/// changes, so:
///   - The honest `nullifier` in `PublicInputs` no longer equals
///     `SHA-256(tampered_stable_id || context)` the circuit computes,
///     breaking the public-output equality.
///   - Additionally, invariant 1's cert_tbs SHA-256 differs, so the
///     cert ECDSA fails — either trip is a valid rejection signal.
#[test]
fn invariant_7_tampered_stable_id_bytes_prover_refuses() {
    let inner = build_witness(FIXTURE_BINDING, b"0x", DUMMY_ROOT_PK).unwrap();
    let sn_offset = inner.offsets.subject_sn_offset_in_tbs;
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    // Flip a byte inside the 16-byte stable_id value (position 12
    // within the value, i.e. sn_offset + 9 + 12 within cert_tbs —
    // a digit in the middle of the RNOKPP number).
    let target = CERT_TBS_DATA_IN_BLOB + sn_offset + 9 + 12;
    honest[target] ^= 0x01;

    let public = honest_public(FIXTURE_BINDING);
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse tampered stable_id");
    expect_prove_refused(err);
}

/// (4) **LOAD-BEARING soundness test.** Witness an offset pointing at
/// the ISSUER DN's serialNumber attribute instead of the subject DN's.
/// The TestAnchorA issuer DN carries the QTSP's registration code
/// `TQSA-00000000-01` under the SAME 9-byte anchor as the subject's
/// — without the in-circuit range check `subject_sn_offset >
/// subject_dn_start_offset`, the prover could bind `nullifier` to
/// the issuer's stable ID, giving EVERY proof the same nullifier and
/// defeating the anti-replay guarantee.
///
/// Expected refusal path:
///   1. Host parser DID populate `subject_sn_offset_in_tbs = 370`
///      (subject) in the P7sOffsets; test overrides the BLOB byte to
///      184 (issuer serialNumber's ATV SEQUENCE).
///   2. C++ parse_witness_blob rejects host-side: it asserts
///      `subject_dn_start_offset < subject_sn_offset`. 294 < 184 is
///      false → P7S_INVALID_INPUT.
///   3. Even if the host check is bypassed (via
///      `test-bypass-host-anchors` feature), the in-circuit
///      `lc.assert1(vlt(subject_dn_start, subject_sn))` catches it:
///      vlt(294, 184) = false → assert1(0) → eval_circuit fails →
///      P7S_PROVER_FAILURE.
#[test]
fn invariant_7_tampered_stable_id_offset_into_issuer_dn_prover_refuses() {
    let inner = build_witness(FIXTURE_BINDING, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    // Issuer DN serialNumber ATV sits at cert_tbs offset 184 (measured
    // at task kickoff). Overwrite the witnessed offset with 184.
    const ISSUER_SN_OFFSET_IN_TBS: u32 = 184;
    honest[SUBJECT_SN_OFFSET_IN_BLOB..SUBJECT_SN_OFFSET_IN_BLOB + 4]
        .copy_from_slice(&ISSUER_SN_OFFSET_IN_TBS.to_le_bytes());

    let public = honest_public(FIXTURE_BINDING);
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse issuer-DN-pointing sn_offset");
    expect_prove_refused(err);
}

/// (4b) **Bypass-gated companion to (4).** Under
/// `--features test-bypass-host-anchors`, the C++ `parse_witness_blob`
/// range check `subject_dn_start < subject_sn_offset` (line ≈1645) is
/// skipped, so the lied offset reaches the circuit's
/// `lc.assert1(lc.vlt(subject_dn_start_offset, subject_sn_offset))`
/// assertion — the SOLE remaining enforcement layer.
///
/// `vlt(294, 184)` = false → `assert1(0)` → eval_circuit fails →
/// P7S_PROVER_FAILURE(3). This test proves the in-circuit assertion is
/// load-bearing and would survive a hypothetical removal of the host-
/// side range check (closing reviewer-2 audit nit N1 from #34).
///
/// Notes on the nullifier: the tampered `subject_sn_offset` is fed to
/// the in-circuit SHA preimage; the honest `public.nullifier` won't
/// match — but the vlt assertion fires BEFORE the SHA computation
/// (it's asserted in `build_hash_circuit` before the routing step),
/// so the circuit refuses at the range check, not at nullifier
/// equality. P7S_PROVER_FAILURE is therefore the only expected code.
#[cfg(feature = "test-bypass-host-anchors")]
#[test]
fn invariant_7_tampered_stable_id_offset_into_issuer_dn_bypass_parser() {
    let inner = build_witness(FIXTURE_BINDING, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut tampered = w.to_ffi_bytes().expect("serialize");

    // Issuer DN serialNumber sits at cert_tbs offset 184 — before the
    // subject DN starts at 294. This makes `vlt(294, 184)` = false in
    // the circuit. Same value as in the host-path test (4) above.
    const ISSUER_SN_OFFSET_IN_TBS: u32 = 184;
    tampered[SUBJECT_SN_OFFSET_IN_BLOB..SUBJECT_SN_OFFSET_IN_BLOB + 4]
        .copy_from_slice(&ISSUER_SN_OFFSET_IN_TBS.to_le_bytes());

    let public = honest_public(FIXTURE_BINDING);
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove_bypass_host_anchors(&tampered, &pub_blob)
        .expect_err(
            "prove_bypass_host_anchors must refuse — in-circuit \
             vlt(subject_dn_start=294, subject_sn=184) = false \
             → assert1(0) → P7S_PROVER_FAILURE",
        );
    // With both host-parser range checks bypassed, only the circuit's
    // `lc.assert1(lc.vlt(subject_dn_start_offset, subject_sn_offset))`
    // is left. It fires as P7S_PROVER_FAILURE(3).
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(3) => {}
        other => panic!(
            "expected P7S_PROVER_FAILURE(3) from in-circuit vlt assert, got {other:?}"
        ),
    }
}

/// (5) Wrong public context. The prover witnesses the honest context
/// bytes (satisfying invariant 9's SHA), but the caller mints a
/// `PublicInputs` whose `nullifier` is computed against a DIFFERENT
/// context. The in-circuit SHA output (over the honest stable_id +
/// honest context) can't equal the lied public `nullifier`, so prove
/// fails. In practice the CIRCUIT would fail first at the invariant-9
/// `context_hash` mismatch before reaching the nullifier equality,
/// but either trip is a valid rejection signal.
#[test]
fn invariant_7_wrong_context_different_nullifier() {
    let inner = build_witness(FIXTURE_BINDING, b"0x", DUMMY_ROOT_PK).unwrap();
    // Grab stable_id bytes BEFORE moving `inner` into Witness.
    let sn_start = inner.offsets.subject_sn_start;
    let stable_id: [u8; 16] = inner.p7s_bytes[sn_start..sn_start + 16]
        .try_into()
        .expect("16-byte stable_id");
    let w = Witness::new(inner);
    // Build a SECOND witness with a DIFFERENT context to get its
    // (different) nullifier. The fixture's JSON.context is literally
    // "0x", so a different byte string would fail the JSON-context
    // byte-equality. Instead: keep the witness context "0x" but fake
    // the public nullifier by recomputing it against context "0y".
    let mut honest_public_wrong_ctx = honest_public(FIXTURE_BINDING);
    // nullifier = SHA-256(stable_id || "0y") — DIFFERENT from the
    // real SHA-256(stable_id || "0x") the circuit will compute.
    let mut h = Sha256::new();
    h.update(&stable_id);
    h.update(b"0y");
    honest_public_wrong_ctx.nullifier = h.finalize().into();

    let pub_blob = honest_public_wrong_ctx.to_ffi_bytes();
    let honest_blob = w.to_ffi_bytes().expect("serialize");
    let err = longfellow_sys::p7s::prove(&honest_blob, &pub_blob)
        .expect_err("prove must refuse lied nullifier public input");
    expect_prove_refused(err);
}
