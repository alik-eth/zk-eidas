//! SD-JWT and credential parsing for the zk-eidas pipeline.
//!
//! Converts raw SD-JWT strings into [`zk_eidas_types::credential::Credential`]
//! values that the prover can consume.

mod claims;
mod sdjwt;
pub mod test_utils;

pub use sdjwt::{ParseError, SdJwtParser};
