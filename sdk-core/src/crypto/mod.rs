//! Cryptographic operations for Benteng

pub mod aad;
pub mod aead;
pub mod kdf;
pub mod kem;
pub mod sig;
pub mod kms;

use crate::error::{BentengError, Result};
use rand::RngCore;

/// Fill buffer with cryptographically secure random bytes
pub fn secure_random(buf: &mut [u8]) -> Result<()> {
    let mut rng = rand::thread_rng();
    rng.try_fill_bytes(buf)
        .map_err(|_| BentengError::EntropyUnavailable)
}

/// Generate a random nonce for AEAD
pub fn generate_nonce() -> Result<[u8; 12]> {
    let mut nonce = [0u8; 12];
    secure_random(&mut nonce)?;
    Ok(nonce)
}
