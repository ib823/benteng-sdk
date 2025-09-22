//! High-level envelope operations

use crate::{
    crypto::{self, aad::Aad, aead, kdf, kem, sig},
    envelope::Envelope,
    error::{BentengError, Result},
};
use zeroize::Zeroizing;

/// Envelope operations
pub struct EnvelopeOps;

impl EnvelopeOps {
    /// Encrypt and sign a payload
    pub fn encrypt_and_sign(
        payload: &[u8],
        tenant_id: &[u8],
        policy_id: &[u8],
        path: &str,
        server_kem_pk: &[u8],
        client_sig_sk: &[u8],
        hybrid: bool,
    ) -> Result<Envelope> {
        let mut envelope = Envelope::new(
            tenant_id.to_vec(),
            policy_id.to_vec(),
            path.to_string(),
        );
        
        // Set hybrid flag
        envelope.algs.hybrid = hybrid;
        
        // Generate nonce
        let nonce = crypto::generate_nonce()?;
        envelope.nonce = nonce.to_vec();
        
        // Set timestamp
        let ts_epoch_ms = chrono::Utc::now().timestamp_millis() as u64;
        envelope.ts_epoch_ms = ts_epoch_ms;
        
        // Build AAD
        let aad = Aad::build(
            envelope.ver,
            tenant_id,
            policy_id,
            path,
            ts_epoch_ms,
            &envelope.aad_ext.required_algs,
            hybrid,
            envelope.aad_ext.device_attest_hash.clone(),
        );
        let aad_bytes = aad.to_cbor()?;
        
        // Generate DEK
        let (kem_ct, shared_secret) = kem::kyber768_encapsulate(server_kem_pk)?;
        envelope.kem_ct = kem_ct;
        
        // Derive DEK from shared secret
        let dek = kdf::hkdf_sha256_derive(
            &shared_secret[..],
            Some(tenant_id),
            policy_id,
            32,
        )?;
        
        // Encrypt payload
        let mut dek_array = [0u8; 32];
        dek_array.copy_from_slice(&dek);
        let ciphertext = aead::aes_256_gcm_encrypt(
            &dek_array,
            &nonce,
            payload,
            &aad_bytes,
        )?;
        envelope.ct = ciphertext;
        
        // Sign the envelope
        let sig_msg = Self::build_signature_message(&envelope, &aad_bytes)?;
        let signature = sig::dilithium3_sign(client_sig_sk, &sig_msg)?;
        envelope.sig = signature;
        
        Ok(envelope)
    }
    
    /// Verify envelope signature and policy
    pub fn verify(
        envelope: &Envelope,
        client_sig_pk: &[u8],
    ) -> Result<()> {
        // Rebuild AAD - make sure to use the same hybrid flag
        let aad = Aad::build(
            envelope.ver,
            &envelope.tenant_id,
            &envelope.policy_id,
            &envelope.path,
            envelope.ts_epoch_ms,
            &envelope.aad_ext.required_algs,
            envelope.algs.hybrid,  // Use the actual hybrid flag from envelope
            envelope.aad_ext.device_attest_hash.clone(),
        );
        let aad_bytes = aad.to_cbor()?;
        
        // Build signature message
        let sig_msg = Self::build_signature_message(envelope, &aad_bytes)?;
        
        // Verify signature
        if !sig::dilithium3_verify(client_sig_pk, &sig_msg, &envelope.sig)? {
            return Err(BentengError::InvalidSignature);
        }
        
        Ok(())
    }
    
    /// Decrypt envelope
    pub fn decrypt(
        envelope: &Envelope,
        server_kem_sk: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        // Rebuild AAD
        let aad = Aad::build(
            envelope.ver,
            &envelope.tenant_id,
            &envelope.policy_id,
            &envelope.path,
            envelope.ts_epoch_ms,
            &envelope.aad_ext.required_algs,
            envelope.algs.hybrid,
            envelope.aad_ext.device_attest_hash.clone(),
        );
        let aad_bytes = aad.to_cbor()?;
        
        // Decapsulate to get shared secret
        let shared_secret = kem::kyber768_decapsulate(server_kem_sk, &envelope.kem_ct)?;
        
        // Derive DEK
        let dek = kdf::hkdf_sha256_derive(
            &shared_secret[..],
            Some(&envelope.tenant_id),
            &envelope.policy_id,
            32,
        )?;
        
        // Decrypt
        let mut dek_array = [0u8; 32];
        dek_array.copy_from_slice(&dek);
        let nonce = <[u8; 12]>::try_from(&envelope.nonce[..])
            .map_err(|_| BentengError::InternalError)?;
        
        aead::aes_256_gcm_decrypt(
            &dek_array,
            &nonce,
            &envelope.ct,
            &aad_bytes,
        )
    }
    
    /// Build signature message
    fn build_signature_message(envelope: &Envelope, aad_bytes: &[u8]) -> Result<Vec<u8>> {
        use sha2::Digest;
        
        let mut msg = Vec::new();
        
        // Include envelope header (without signature)
        let mut env_copy = envelope.clone();
        env_copy.sig = vec![];
        let header = env_copy.to_cbor()?;
        msg.extend_from_slice(&header);
        
        // Include nonce
        msg.extend_from_slice(&envelope.nonce);
        
        // Include ciphertext
        msg.extend_from_slice(&envelope.ct);
        
        // Include AAD hash
        let mut hasher = sha2::Sha256::new();
        hasher.update(aad_bytes);
        msg.extend_from_slice(&hasher.finalize());
        
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_verify_decrypt() {
        // Generate keys
        let (server_kem_pk, server_kem_sk) = kem::kyber768_keypair().unwrap();
        let (client_sig_pk, client_sig_sk) = sig::dilithium3_keypair().unwrap();
        
        let payload = b"Secret message";
        let tenant_id = b"tenant123";
        let policy_id = b"policy456";
        let path = "/test";
        
        // Encrypt and sign
        let envelope = EnvelopeOps::encrypt_and_sign(
            payload,
            tenant_id,
            policy_id,
            path,
            &server_kem_pk,
            &client_sig_sk,
            false,  // Not hybrid
        ).unwrap();
        
        // Debug: Check envelope values
        assert_eq!(envelope.tenant_id, tenant_id);
        assert_eq!(envelope.policy_id, policy_id);
        assert_eq!(envelope.path, path);
        assert!(!envelope.algs.hybrid);
        
        // Verify with the correct client public key
        match EnvelopeOps::verify(&envelope, &client_sig_pk) {
            Ok(_) => {},
            Err(e) => panic!("Verification failed: {:?}", e),
        }
        
        // Decrypt
        let decrypted = EnvelopeOps::decrypt(&envelope, &server_kem_sk).unwrap();
        assert_eq!(payload, decrypted.as_slice());
    }
}
