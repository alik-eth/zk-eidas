//! Core types for the zk-eidas pipeline: credentials, proofs, predicates,
//! witnesses, and transport envelopes.

pub mod commitment;
pub mod credential;
pub mod envelope;
pub mod predicate;
pub mod proof;
pub mod witness;

pub use commitment::EcdsaCommitment;
pub use proof::{CompoundProof, LogicalOp};
