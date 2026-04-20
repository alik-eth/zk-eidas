//! P7s circuit FFI (Phase 2a — scaffolding stubs).
//!
//! Populated incrementally as invariants land in the C++ circuit.

use crate::{p7s_prove_stub, p7s_verify_stub};

/// Returns true iff the scaffolding FFI is linked.
pub fn smoke() -> bool {
    unsafe { p7s_prove_stub() == 0 && p7s_verify_stub() == 0 }
}
