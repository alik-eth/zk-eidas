//! Zero-knowledge proof generation using Circom circuits and the Groth16 backend.
//!
//! This crate handles circuit loading, witness construction, and Groth16 proof
//! generation for all predicate types using ark-circom and arkworks.
//!
//! ## Two-stage architecture
//!
//! - **Stage 1 (ECDSA)**: Verifies ECDSA P-256 signature over a credential,
//!   outputs a Poseidon commitment binding claim_value, sd_array_hash, and message_hash.
//! - **Stage 2 (Predicates)**: Lightweight circuits that consume the commitment
//!   and prove claim predicates (gte, lte, eq, neq, range, set_member, nullifier, holder_binding).

use std::sync::Mutex;

pub mod circuit;
pub mod prover;
mod signed_input;

pub use circuit::{CircuitArtifacts, CircuitError, CircuitLoader};
pub use prover::{build_ecdsa_input_json, Prover, ProverError};
pub use signed_input::SignedProofInput;

/// rapidsnark's C FFI shares a mutable static `AltBn128::Engine::engine`
/// singleton (from ffiasm) across all prove/verify calls. Concurrent access
/// causes data races. This mutex serializes all rapidsnark FFI calls.
pub static RAPIDSNARK_LOCK: Mutex<()> = Mutex::new(());
