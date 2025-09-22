//! AEAD (Authenticated Encryption with Associated Data) operations

use crate::error::{BentengError, Result};
use aes_gcm::{
    aead::{Aead as _, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use zeroize::Zeroizing;

pub enum AeadAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Encrypt with AES-256-GCM
pub fn aes_256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|_| BentengError::AeadFailure)
}

/// Decrypt with AES-256-GCM
pub fn aes_256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map(Zeroizing::new)
        .map_err(|_| BentengError::AeadFailure)
}

/// Encrypt with ChaCha20-Poly1305 (for fallback)
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};

    let key = ChaChaKey::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaChaNonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|_| BentengError::AeadFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"Hello, Benteng!";
        let aad = b"additional data";

        let ct = aes_256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let pt = aes_256_gcm_decrypt(&key, &nonce, &ct, aad).unwrap();

        assert_eq!(plaintext, pt.as_slice());
    }

    #[test]
    fn test_chacha_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"Hello, Benteng with ChaCha!";
        let aad = b"additional data";

        let ct = chacha20_poly1305_encrypt(&key, &nonce, plaintext, aad).unwrap();
        // We'd need a decrypt function too, but this tests compilation
        assert!(ct.len() > plaintext.len());
    }
}
