//! # zk-eidas
//!
//! Zero-Knowledge Selective Disclosure for eIDAS 2.0 Credentials.
//!
//! This is the main facade crate. It re-exports the escrow utilities,
//! predicate types, and proof types for use with Longfellow-based proving.

mod builder;
pub mod escrow;
pub mod openid4vp;
pub mod templates;
pub use builder::{age_cutoff_epoch_days_from, Predicate, ZkError};
pub use zk_eidas_types::envelope::ProofEnvelope;
pub use zk_eidas_types::proof::{CompoundProof, LogicalOp};
