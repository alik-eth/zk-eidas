//! Longfellow-shaped witness.
//!
//! Phase 2a Task 1a: the only input carried to the circuit is the
//! 32-byte `context_hash`. The richer witness (p7s bytes, offsets, ...)
//! threads in as subsequent invariants land.

use zk_eidas_p7s::P7sWitness;

#[derive(Debug, Clone)]
pub struct Witness {
    inner: P7sWitness,
}

impl Witness {
    pub fn new(inner: P7sWitness) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &P7sWitness {
        &self.inner
    }

    /// Convenience for Task 1a: build a witness whose only circuit-facing
    /// field is the 32-byte context_hash computed off-circuit.
    pub fn context_hash_only(context_hash: [u8; 32]) -> Task1aWitness {
        Task1aWitness { context_hash }
    }
}

/// Minimal witness shape for Task 1a.
///
/// Keeping this separate from `Witness` lets the richer `Witness` struct
/// grow into future tasks without flipping its API every step.
#[derive(Debug, Clone, Copy)]
pub struct Task1aWitness {
    pub context_hash: [u8; 32],
}
