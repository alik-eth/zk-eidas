//! # zk-eidas
//!
//! Zero-Knowledge Selective Disclosure for eIDAS 2.0 Credentials.
//!
//! This is the main facade crate that integrators use. It re-exports the
//! builder, verifier, predicate templates, and proof types needed to generate
//! and verify zero-knowledge proofs over SD-JWT and mdoc credentials.
//!
//! ```rust,no_run
//! use zk_eidas::{ZkCredential, ZkVerifier, Predicate};
//!
//! # let sdjwt = "";
//! let proof = ZkCredential::from_sdjwt(sdjwt, "circuits/predicates")
//!     .unwrap()
//!     .predicate("birthdate", Predicate::gte(18))
//!     .prove()
//!     .unwrap();
//!
//! let valid = ZkVerifier::new("circuits/predicates")
//!     .verify(&proof)
//!     .unwrap();
//! ```

mod builder;
pub mod escrow;
pub mod openid4vp;
pub mod templates;
pub use builder::{age_cutoff_epoch_days_from, Predicate, ZkCredential, ZkError, ZkVerifier};
pub use zk_eidas_types::envelope::ProofEnvelope;
pub use zk_eidas_types::proof::{CompoundProof, LogicalOp};
