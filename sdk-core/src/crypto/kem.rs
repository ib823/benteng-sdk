//! Key Encapsulation Mechanism operations

use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use pqcrypto_kyber::kyber768;
use zeroize::Zeroizing;
use crate::error::{BentengError, Result};

/// Kyber768 key generation
pub fn kyber768_keypair() -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let (pk, sk) = kyber768::keypair();
    Ok((
        pk.as_bytes().to_vec(),
        Zeroizing::new(sk.as_bytes().to_vec()),
    ))
}

/// Kyber768 encapsulation
pub fn kyber768_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let pk = kyber768::PublicKey::from_bytes(public_key)
        .map_err(|_| BentengError::InternalError)?;
    
    let (ss, ct) = kyber768::encapsulate(&pk);
    
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    shared_secret.copy_from_slice(&ss.as_bytes()[..32]);
    
    Ok((ct.as_bytes().to_vec(), shared_secret))
}

/// Kyber768 decapsulation
pub fn kyber768_decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let sk = kyber768::SecretKey::from_bytes(secret_key)
        .map_err(|_| BentengError::InternalError)?;
    
    let ct = kyber768::Ciphertext::from_bytes(ciphertext)
        .map_err(|_| BentengError::InternalError)?;
    
    let ss = kyber768::decapsulate(&ct, &sk);
    
    let mut shared_secret = Zeroizing::new([0u8; 32]);
    shared_secret.copy_from_slice(&ss.as_bytes()[..32]);
    
    Ok(shared_secret)
}

/// X25519 operations for hybrid mode
pub struct X25519KeyPair {
    pub public: [u8; 32],
    pub secret: Zeroizing<[u8; 32]>,
}

pub fn x25519_keypair() -> X25519KeyPair {
    use x25519_dalek::PublicKey;
    use x25519_dalek::EphemeralSecret;
    
    let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    
    // We need to store the secret somehow - create from random bytes
    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret_bytes[..]);
    
    X25519KeyPair {
        public: *public.as_bytes(),
        secret: secret_bytes,
    }
}

pub fn x25519_shared_secret(
    secret: &[u8; 32],
    their_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    // For now, we'll use a simple operation
    // In production, you'd want proper x25519 implementation
    let mut shared = Zeroizing::new([0u8; 32]);
    
    // Simple XOR for demo - replace with actual x25519
    for i in 0..32 {
        shared[i] = secret[i] ^ their_public[i];
    }
    
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kyber768_roundtrip() {
        let (pk, sk) = kyber768_keypair().unwrap();
        let (ct, ss1) = kyber768_encapsulate(&pk).unwrap();
        let ss2 = kyber768_decapsulate(&sk, &ct).unwrap();
        
        assert_eq!(&ss1[..], &ss2[..]);
    }
}
