//! Longfellow-shaped witness.
//!
//! Phase 2a Task 1b: the circuit now binds `context_hash` to the preimage
//! `context_bytes` via SHA-256. The richer `Witness` holds the full p7s
//! parse for later invariants; `Task1bWitness` carries only the inputs
//! the current circuit needs.

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
}

/// Minimal witness shape for Task 1b.
///
/// The prover provides both the claimed 32-byte `context_hash` and the
/// preimage `context_bytes`; the circuit asserts their SHA-256 relation.
#[derive(Debug, Clone)]
pub struct Task1bWitness {
    pub context_hash: [u8; 32],
    pub context_bytes: Vec<u8>,
}

impl Task1bWitness {
    /// Build a witness, computing `context_hash = SHA-256(context_bytes)`
    /// off-circuit. Convenient for tests and honest callers.
    pub fn honest(context_bytes: impl Into<Vec<u8>>) -> Self {
        use sha2::Digest;
        let context_bytes = context_bytes.into();
        let context_hash = sha2::Sha256::digest(&context_bytes).into();
        Self {
            context_hash,
            context_bytes,
        }
    }
}
