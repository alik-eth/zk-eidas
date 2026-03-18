//! Zero-knowledge proof verification for the zk-eidas pipeline.
//!
//! Provides both on-demand ([`Verifier`]) and pre-loaded ([`RegistryVerifier`])
//! Groth16 proof verification against trusted circuit artifacts (`vk.json` files)
//! using rapidsnark for fast native verification.
//!
//! Also provides plain bitfield-based revocation status checking via the
//! [`revocation`] module (no longer ZK-based).

mod registry;
pub mod revocation;
mod verifier;

pub use registry::{RegistryVerifier, TrustedCircuitRegistry};
pub use verifier::{Verifier, VerifierError};
