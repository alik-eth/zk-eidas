//! End-to-end smoke: build witness blob → prove → verify against the
//! TestAnchorA synthetic fixture. Covered by `invariant_4.rs` / `invariant_5.rs` too, but
//! this file is the minimal "is the FFI linked" regression.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

fn decode_hex_field(p7s: &[u8], start: usize, len: usize) -> Vec<u8> {
    let hex_body = &p7s[start..start + len];
    let mut out = vec![0u8; len / 2];
    hex::decode_to_slice(hex_body, &mut out).expect("parseable hex");
    out
}

#[test]
fn prove_verify_round_trip_on_test_anchor_a_fixture() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).expect("parse fixture");
    let off = inner.offsets;
    let mut pk = [0u8; 65];
    pk.copy_from_slice(&decode_hex_field(&inner.p7s_bytes, off.json_pk_start, off.json_pk_len));
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&decode_hex_field(
        &inner.p7s_bytes,
        off.json_nonce_start,
        off.json_nonce_len,
    ));
    let outputs = zk_eidas_p7s::compute_outputs(&inner).expect("compute outputs");
    let w = Witness::new(inner);

    let context_hash: [u8; 32] = Sha256::digest(b"0x").into();
    let public = PublicInputs {
        context_hash,
        pk,
        nonce,
        nullifier: outputs.nullifier,
        trust_anchor_index: 0,
        root_pk: [0u8; 65],
        timestamp: 0,
    };

    let proof = prove(&w, &public).expect("prove must succeed on honest witness");
    assert!(!proof.bytes.is_empty(), "proof must have non-zero length");

    let ok = verify(&proof, &public).expect("verify must yield a decision");
    assert!(ok, "verifier must accept an honest proof");
}
