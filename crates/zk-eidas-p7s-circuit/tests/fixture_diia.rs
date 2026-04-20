//! End-to-end smoke: build witness blob → prove → verify against the
//! DIIA fixture. Covered by `invariant_4.rs` too, but this file is the
//! minimal "is the FFI linked" regression.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Witness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

fn expected_pk_from_fixture() -> [u8; 65] {
    let w = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).unwrap();
    let off = &w.offsets;
    let pk_hex = &w.p7s_bytes[off.json_pk_start..off.json_pk_start + off.json_pk_len];
    let mut out = [0u8; 65];
    hex::decode_to_slice(pk_hex, &mut out).expect("parseable pk_hex");
    out
}

#[test]
fn prove_verify_round_trip_on_diia_fixture() {
    let inner = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).expect("parse fixture");
    let w = Witness::new(inner);
    let pk = expected_pk_from_fixture();
    let context_hash: [u8; 32] = Sha256::digest(b"0x").into();
    let public = PublicInputs {
        context_hash,
        pk,
        nonce: [0u8; 32],
        root_pk: [0u8; 65],
        timestamp: 0,
    };

    let proof = prove(&w, &public).expect("prove must succeed on honest witness");
    assert!(!proof.bytes.is_empty(), "proof must have non-zero length");

    let ok = verify(&proof, &public).expect("verify must yield a decision");
    assert!(ok, "verifier must accept an honest proof");
}
