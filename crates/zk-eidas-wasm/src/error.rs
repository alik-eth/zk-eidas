use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("circuit deserialization failed")]
    CircuitParse,
    #[error("proof deserialization failed: {0}")]
    ProofParse(String),
    #[error("invalid public input: {0}")]
    InvalidInput(String),
    #[error("decompression failed")]
    Decompress,
    #[error("verification failed")]
    VerificationFailed,
    #[error("unsupported field ID: {0}")]
    UnsupportedField(u8),
}
