//! Digital signature operations

use crate::error::{BentengError, Result};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

/// Dilithium3 key generation
pub fn dilithium3_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let (pk, sk) = dilithium3::keypair();
    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

/// Dilithium3 sign
pub fn dilithium3_sign(secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let sk =
        dilithium3::SecretKey::from_bytes(secret_key).map_err(|_| BentengError::InternalError)?;

    let sig = dilithium3::detached_sign(message, &sk);

    Ok(sig.as_bytes().to_vec())
}

/// Dilithium3 verify
pub fn dilithium3_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    let pk = dilithium3::PublicKey::from_bytes(public_key)
        .map_err(|_| BentengError::InvalidSignature)?;

    let sig = dilithium3::DetachedSignature::from_bytes(signature)
        .map_err(|_| BentengError::InvalidSignature)?;

    Ok(dilithium3::verify_detached_signature(&sig, message, &pk).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium3_roundtrip() {
        let (pk, sk) = dilithium3_keypair().unwrap();
        let msg = b"Test message";
        let sig = dilithium3_sign(&sk, msg).unwrap();
        let valid = dilithium3_verify(&pk, msg, &sig).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_dilithium3_invalid_sig() {
        let (pk, _) = dilithium3_keypair().unwrap();
        let msg = b"Test message";
        let bad_sig = vec![0u8; 3293]; // Dilithium3 signature size
        let valid = dilithium3_verify(&pk, msg, &bad_sig).unwrap();

        assert!(!valid);
    }
}
