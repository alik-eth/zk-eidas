//! End-to-end test: build witness → (eventual) prove → (eventual) verify.
//! Scaffolding only in M0 — tests prove/verify once invariants land.

use zk_eidas_p7s_circuit::smoke;

#[test]
fn ffi_is_linked() {
    assert!(smoke(), "p7s FFI scaffolding must be linked");
}
