//! PKCS#7/CMS credential parser and witness builder for zk-eidas.
//!
//! Parses a QTSP-signed PKCS#7 document (e.g. a DIIA QKB binding document),
//! locates the byte ranges the ZK circuit must re-check, and derives the
//! public outputs (nullifier, binding hash, embedded secp256k1 pubkey).
//!
//! The circuit later re-parses the same p7s bytes using these offsets as
//! a guide. Rust parses with semantic awareness; the circuit parses
//! structurally using the same offsets.

mod locator;
mod outputs;
mod parser;
mod verify;
mod witness;

pub use outputs::compute_outputs;
pub use verify::host_verify;
pub use witness::{build_witness, P7sOffsets, P7sPublicOutputs, P7sWitness};

#[derive(Debug, thiserror::Error)]
pub enum P7sError {
    #[error("DER decode: {0}")]
    Der(String),
    #[error("CMS structure: {0}")]
    Cms(String),
    #[error("no signer certificate in SignedData")]
    NoCerts,
    #[error("serialNumber attribute not found in subject DN")]
    NoSerialNumber,
    #[error("SubjectPublicKeyInfo not a P-256 uncompressed point")]
    NotP256,
    #[error("byte offset could not be located: {0}")]
    OffsetNotFound(&'static str),
    #[error("JSON field not found: {0}")]
    JsonFieldMissing(&'static str),
    #[error("ECDSA verification failed: {0}")]
    BadSignature(&'static str),
    #[error("context mismatch: witness says {witness:?}, input says {input:?}")]
    ContextMismatch {
        witness: Vec<u8>,
        input: Vec<u8>,
    },
}

impl From<der::Error> for P7sError {
    fn from(e: der::Error) -> Self {
        P7sError::Der(e.to_string())
    }
}
