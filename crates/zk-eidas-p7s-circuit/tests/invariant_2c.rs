//! Phase 2a Task 31 — invariant 2c: blob.message_digest byte-equals
//! the 32-byte OCTET STRING embedded in signed_attrs at the CMS
//! messageDigest attribute.
//!
//! Motivation — closes the soundness gap where an attacker with honest
//! (cert, signed_attrs, sigs) substitutes a fake signed_content whose
//! SHA-256 they put into message_digest. Pre-#31 all ten invariants
//! pass. Post-#31: the new byte-equality fails because
//! `SHA-256(fake) != SHA-256(real) = signed_attrs[md_offset+17..+49]`.
//!
//! Tests:
//!   1. Happy: honest witness round-trips (equality holds).
//!   2. M1 motivating attack: swap signed_content + recompute
//!      message_digest → invariant 2c fails (while 1 + 2a + 2b would
//!      all pass independently). This is the load-bearing soundness
//!      test — if it didn't trip, the gap isn't closed.
//!   3. M2 tampered embedded messageDigest byte in signed_attrs[77..].
//!      Content-sig ECDSA also trips (signed_attrs hash changes) —
//!      documented as double-failure, the byte-eq is the cheaper trip.
//!   4. M3 tampered `signed_attrs_md_offset` — 17-byte anchor fails.
//!   5. M4 TSA-inner offset (documented as theoretical): witnessing
//!      offset 930 (the nested contentTimestamp messageDigest) PASSES
//!      on honest signed_content because the TSA timestamps the same
//!      content → both 32-byte blobs equal. Documents the SHA-256
//!      preimage-resistance argument from handoff-31 §6.2.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

// v10 blob layout constants — mirror invariant_1.rs / invariant_2a.rs.
// signed_attrs_md_offset sits immediately after signed_attrs_len.
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
const BLOB_TOTAL_LEN: usize = CONTENT_SIG_S_IN_BLOB + 32; // 5038

// signed_content lives at absolute blob offset 44 (version + ctx_len +
// ctx[32] + sc_len = 44). Length is 1024.
const SIGNED_CONTENT_DATA_IN_BLOB: usize = 44;
const SIGNED_CONTENT_LEN_IN_BLOB: usize = 40;  // sc_len u32
// message_digest lives at 1278 (see invariant_1.rs layout comment).
const MESSAGE_DIGEST_IN_BLOB: usize = 1278;

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

fn expect_prove_refused(err: longfellow_sys::p7s::P7sFfiError) {
    match err {
        // C++ surfaces `VerifyWitness3::compute_witness` returning
        // false as P7S_INVALID_INPUT(2); a circuit-level constraint
        // failure (e.g. the messageDigest byte-equality) shows up
        // as P7S_PROVER_FAILURE(3). Either is a valid "honest prover
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

/// (1) Happy: honest DIIA fixture round-trips — the embedded 32-byte
/// OCTET STRING inside signed_attrs[md_offset+17..+49] byte-equals
/// blob.message_digest (= SHA-256(signed_content)), so invariant 2c's
/// in-circuit equality holds. Both DIIA fixtures report
/// `signed_attrs_md_offset = 60` (verified pre-flight — see
/// handoff-31 §3.1 and §7.1).
#[test]
fn invariant_2c_happy_round_trips() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    // Smoke: parser-level offset matches the researcher's measurement.
    assert_eq!(
        inner.offsets.signed_attrs_md_offset, 60,
        "DIIA fixture's messageDigest offset within signed_attrs must be 60 \
         (see handoff-31 §3.1); if this asserts, the researcher's fixture \
         measurement drifted and the circuit's 17-byte anchor story needs \
         re-validation"
    );
    let w = Witness::new(inner);
    let public = honest_public();
    let proof =
        prove(&w, &public).expect("prove must succeed on honest DIIA witness");
    assert!(
        verify(&proof, &public).expect("verify yields a decision"),
        "honest DIIA proof must verify under the messageDigest binding"
    );
}

/// (2) M1 — the motivating attack. An attacker-controlled
/// `signed_content` replaces the honest one, and `message_digest` is
/// recomputed to match so invariants 2b + 1 + 2a all still pass
/// independently. Without invariant 2c this would succeed. With 2c,
/// the in-circuit byte equality `signed_attrs[md_offset+17..+49] ==
/// message_digest` fails because `signed_attrs` is intact (so
/// window[17..49] = SHA-256(real_content)) but message_digest =
/// SHA-256(fake_content).
///
/// Construction: bit-flip a byte inside the signed_content (but
/// OUTSIDE any witnessed locator's target window — keep pk, nonce,
/// context, declaration offsets all still pointing to valid bytes).
/// Recompute message_digest = SHA-256(flipped). The content-sig's
/// honest signedAttrs still hashes to the TRUE e2 that the ECDSA
/// actually signed, so invariant 2a passes; invariant 2b still
/// passes because we recomputed SHA(sc). The only thing broken is
/// the embedded-vs-blob messageDigest equality — exactly the gap
/// #31 closes.
#[test]
fn invariant_2c_motivating_attack_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");
    assert_eq!(
        honest.len(),
        BLOB_TOTAL_LEN,
        "v10 blob layout mismatch — update constants"
    );

    // Read signed_content length to pick a safe byte inside real content.
    let mut sc_len_bytes = [0u8; 4];
    sc_len_bytes.copy_from_slice(
        &honest[SIGNED_CONTENT_LEN_IN_BLOB..SIGNED_CONTENT_LEN_IN_BLOB + 4],
    );
    let sc_len = u32::from_le_bytes(sc_len_bytes) as usize;
    assert!(sc_len > 0, "honest signed_content must be nonempty");
    // Flip the LAST byte of signed_content — deep inside the tail,
    // guaranteed to be outside any JSON locator window (pk / nonce /
    // context / declaration offsets all point earlier), so those
    // invariants continue to be satisfiable post-tamper.
    let target_rel = sc_len - 1;
    honest[SIGNED_CONTENT_DATA_IN_BLOB + target_rel] ^= 0x01;

    // Recompute SHA-256(tampered signed_content) and overwrite
    // message_digest so invariant 2b still passes. This is the whole
    // point of the attack — the attacker preimages their fake content
    // into message_digest.
    let new_sc = &honest[SIGNED_CONTENT_DATA_IN_BLOB..SIGNED_CONTENT_DATA_IN_BLOB + sc_len];
    let new_md: [u8; 32] = Sha256::digest(new_sc).into();
    honest[MESSAGE_DIGEST_IN_BLOB..MESSAGE_DIGEST_IN_BLOB + 32]
        .copy_from_slice(&new_md);

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();
    // Pre-#31 this would have succeeded (all per-leg invariants
    // independently satisfied). Post-#31, the in-circuit byte equality
    // between message_digest and signed_attrs[md+17..md+49] fails —
    // the attacker would need SHA-256 preimage to defeat it.
    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove MUST refuse signed_content-substitution attack");
    expect_prove_refused(err);
}

/// (3) M2 — bit-flip inside the embedded messageDigest OCTET STRING
/// bytes themselves (signed_attrs[md_offset + 17..md_offset + 49]).
/// Triggers two failures: (a) invariant 2c's byte-eq against
/// message_digest (the earlier, cheaper trip), and (b) invariant 2a's
/// SHA-256(signed_attrs) → new e2 → content-sig ECDSA no longer
/// verifies under holder_pk. Documented as double-failure per
/// handoff-31 §7.2 M2.
#[test]
fn invariant_2c_tampered_embedded_digest_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    // Read the witnessed md offset, then flip a bit in window[17..49].
    let mut off_bytes = [0u8; 4];
    off_bytes.copy_from_slice(
        &honest[SIGNED_ATTRS_MD_OFFSET_IN_BLOB..SIGNED_ATTRS_MD_OFFSET_IN_BLOB + 4],
    );
    let md_offset = u32::from_le_bytes(off_bytes) as usize;
    // Tamper byte inside the 32-byte digest value (idx 20 is arbitrary).
    honest[SIGNED_ATTRS_DATA_IN_BLOB + md_offset + 17 + 20] ^= 0x01;

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse tampered embedded messageDigest");
    expect_prove_refused(err);
}

/// (4) M3 — lie about `signed_attrs_md_offset`. Slide by ±1 so the
/// 17-byte CMS messageDigest DER prefix anchor can't match (one-byte
/// lie produces window[0..17] = `?? 30 2f ...` or `2f 06 09 ...`
/// instead of `30 2f ...`). The in-circuit anchor is unsatisfiable;
/// prover refuses at prove time.
///
/// The C++ `parse_witness_blob` also validates the prefix match
/// host-side in production (belt-and-suspenders); that check trips
/// first and surfaces as P7S_INVALID_INPUT. Either signal proves
/// the anchor is load-bearing. The companion test
/// `invariant_2c_tampered_md_offset_bypass_parser` in the
/// `test-bypass-host-anchors` feature gate exercises the in-circuit
/// anchor alone by skipping the host check.
#[test]
fn invariant_2c_tampered_md_offset_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    let mut off_bytes = [0u8; 4];
    off_bytes.copy_from_slice(
        &honest[SIGNED_ATTRS_MD_OFFSET_IN_BLOB..SIGNED_ATTRS_MD_OFFSET_IN_BLOB + 4],
    );
    let honest_offset = u32::from_le_bytes(off_bytes);
    assert!(
        honest_offset > 0,
        "honest messageDigest offset must be positive for this test"
    );
    let lie = honest_offset - 1;
    honest[SIGNED_ATTRS_MD_OFFSET_IN_BLOB..SIGNED_ATTRS_MD_OFFSET_IN_BLOB + 4]
        .copy_from_slice(&lie.to_le_bytes());

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err("prove must refuse lied messageDigest offset");
    expect_prove_refused(err);
}

/// (5) M4 — witnessing the TSA-inner messageDigest offset (~930
/// within signed_attrs, inside the nested contentTimestamp
/// attribute's TSTInfo). The 17-byte DER anchor MATCHES there (the
/// dual-match property called out in handoff-31 §6.1). But on DIIA
/// fixtures the 32-byte blob at the inner offset is
/// `SHA-256(TSTInfo)` — the TSA hashes the TSTInfo structure that
/// describes the outer p7s, NOT `signed_content` directly — so it
/// differs from `blob.message_digest = SHA-256(signed_content)`.
/// Witnessing the inner offset therefore FAILS the byte-equality
/// constraint. This is STRICTLY STRONGER than the handoff-31 §6.2
/// argument: not only is a preimage attack infeasible, the inner
/// blob isn't even equal to the outer on the happy path.
///
/// The prefix-anchor is still a ≥2-match site (proven above via the
/// anchor occurrence scan), so the soundness story hinges on SHA-256
/// preimage resistance when a prover CONSTRUCTS bytes that coincide.
/// This test documents the observed fixture property that makes the
/// dual-match concern even weaker in practice: witnessing the inner
/// offset fails outright on honest DIIA timestamps.
#[test]
fn invariant_2c_tsa_inner_offset_prover_refuses() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    const ANCHOR: [u8; 17] = [
        0x30, 0x2f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x09, 0x04, 0x31, 0x22, 0x04, 0x20,
    ];
    let sa = &honest[SIGNED_ATTRS_DATA_IN_BLOB..SIGNED_ATTRS_DATA_IN_BLOB + 1536];
    let mut occurrences = Vec::new();
    for i in 0..sa.len().saturating_sub(17) {
        if sa[i..i + 17] == ANCHOR {
            occurrences.push(i);
        }
    }
    assert!(
        occurrences.len() >= 2,
        "expected >= 2 CMS-messageDigest anchors in DIIA fixture \
         (outer + nested TSA); got: {:?}",
        occurrences
    );
    let tsa_inner_offset = occurrences[1] as u32;

    // Confirm the inner 32-byte blob differs from the outer — if it
    // DID equal, this test would need to flip to expect-pass (and
    // soundness would lean harder on SHA-256 preimage resistance).
    let outer = &sa[occurrences[0] + 17..occurrences[0] + 49];
    let inner_bytes = &sa[occurrences[1] + 17..occurrences[1] + 49];
    assert_ne!(
        outer, inner_bytes,
        "DIIA fixture's TSA-inner messageDigest unexpectedly equals the \
         outer one — soundness argument in the test docstring needs \
         revisiting (see handoff-31 §6.2)"
    );

    // Swap the witnessed offset from outer (60) to TSA-inner (~930).
    honest[SIGNED_ATTRS_MD_OFFSET_IN_BLOB..SIGNED_ATTRS_MD_OFFSET_IN_BLOB + 4]
        .copy_from_slice(&tsa_inner_offset.to_le_bytes());

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove(&honest, &pub_blob)
        .expect_err(
            "TSA-inner offset prove must fail — inner 32-byte blob ≠ \
             blob.message_digest",
        );
    expect_prove_refused(err);
}

/// (6) Under `--features test-bypass-host-anchors`, skip the
/// Rust parser's 17-byte anchor check AND the C++ parse_witness_blob
/// check, then supply a lying `signed_attrs_md_offset`. The in-circuit
/// 17-byte CMS messageDigest DER anchor is the SOLE remaining
/// enforcement layer. Proves the anchor is load-bearing — a refactor
/// that accidentally drops the in-circuit assertion fails this test.
#[cfg(feature = "test-bypass-host-anchors")]
#[test]
fn invariant_2c_tampered_md_offset_bypass_parser() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let w = Witness::new(inner);
    let mut honest = w.to_ffi_bytes().expect("serialize");

    // Slide by one byte — mirrors the host-path test (4) above,
    // just routed through the bypass FFI.
    let mut off_bytes = [0u8; 4];
    off_bytes.copy_from_slice(
        &honest[SIGNED_ATTRS_MD_OFFSET_IN_BLOB..SIGNED_ATTRS_MD_OFFSET_IN_BLOB + 4],
    );
    let honest_offset = u32::from_le_bytes(off_bytes);
    assert!(honest_offset > 0);
    let lie = honest_offset - 1;
    honest[SIGNED_ATTRS_MD_OFFSET_IN_BLOB..SIGNED_ATTRS_MD_OFFSET_IN_BLOB + 4]
        .copy_from_slice(&lie.to_le_bytes());

    let public = honest_public();
    let pub_blob = public.to_ffi_bytes();
    let err = longfellow_sys::p7s::prove_bypass_host_anchors(&honest, &pub_blob)
        .expect_err(
            "prove_bypass_host_anchors must refuse — in-circuit 17-byte \
             messageDigest anchor is the sole remaining enforcement layer",
        );
    match err {
        longfellow_sys::p7s::P7sFfiError::ProveFailed(3) => {}
        other => panic!(
            "expected P7S_PROVER_FAILURE(3) from in-circuit anchor, got {other:?}"
        ),
    }
}
