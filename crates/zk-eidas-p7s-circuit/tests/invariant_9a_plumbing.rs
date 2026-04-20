//! Phase 2a Task 1a — plumbing smoke on the real DIIA fixture.
//!
//! Computes `context_hash = SHA-256(context_bytes)` off-circuit and
//! round-trips it through the trivially-satisfiable Longfellow circuit.
//! The constraint is `context_hash == context_hash`; Task 1b will add
//! the real SHA-256 check.

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, PublicInputs, Task1aWitness};

const FIXTURE: &[u8] = include_bytes!("../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

fn compute_context_hash() -> [u8; 32] {
    let context = b"0x";
    let w = build_witness(FIXTURE, context, DUMMY_ROOT_PK).expect("parse fixture");
    let off = &w.offsets;
    let ctx_bytes =
        &w.p7s_bytes[off.json_context_start..off.json_context_start + off.json_context_len];
    assert_eq!(ctx_bytes, context, "parser should surface the same context bytes");
    Sha256::digest(ctx_bytes).into()
}

#[test]
fn plumbing_roundtrip_real_fixture() {
    let context_hash = compute_context_hash();
    let witness = Task1aWitness { context_hash };
    let proof = prove(&witness).expect("prove must succeed for Task 1a");
    assert!(!proof.bytes.is_empty(), "proof must have non-zero length");

    let public = PublicInputs {
        context_hash,
        pk: [0u8; 65],
        nonce: [0u8; 32],
        root_pk: [0u8; 65],
        timestamp: 0,
    };
    let ok = verify(&proof, &public).expect("verify must return a decision");
    assert!(ok, "verifier must accept a freshly-minted proof");
}
