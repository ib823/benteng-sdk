//! Benteng error types

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BentengError {
    #[error("Policy mismatch")]
    PolicyMismatch,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("AEAD failure")]
    AeadFailure,

    #[error("Entropy unavailable")]
    EntropyUnavailable,
    #[error("KMS error: {0}")]
    KmsError(String),

    #[error("Internal error")]
    InternalError,
}

pub type Result<T> = std::result::Result<T, BentengError>;
