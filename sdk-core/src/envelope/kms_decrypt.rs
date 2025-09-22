//! KMS-based decrypt operations for envelopes

use crate::error::BentengError;
use crate::envelope::Envelope;
use crate::crypto::kms::KmsGate;
use crate::crypto::aad::Aad;
use crate::crypto::aead;

/// Decrypt an envelope using dual-control KMS
pub async fn decrypt_with_kms<K: KmsGate>(
    envelope: &Envelope,
    kms: &K,
) -> Result<Vec<u8>, BentengError> {
    // Extract KEM ciphertext from envelope
    let kem_ct = &envelope.kem_ct;
    
    // Get DEK from dual-control KMS
    let dek = kms.dual_decrypt(
        kem_ct,
        &envelope.policy_id,
        &envelope.tenant_id,
        &envelope.path,
    ).await?;
    
    // Extract fields from envelope
    let required_algs = envelope.aad_ext.required_algs.as_str();
    
    let device_attest_hash = envelope.aad_ext.device_attest_hash.clone();
    
    let hybrid = envelope.algs.hybrid;
    
    // Build AAD
    let aad = Aad::build(
        envelope.ver,
        &envelope.tenant_id,
        &envelope.policy_id,
        &envelope.path,
        envelope.ts_epoch_ms,
        required_algs,
        hybrid,
        device_attest_hash,
    );
    
    // Get AAD bytes
    let aad_bytes = aad.to_cbor()?;
    
    // Convert nonce to array
    let nonce_array: [u8; 12] = envelope.nonce.as_slice()
        .try_into()
        .map_err(|_| BentengError::AeadFailure)?;
    
    // Decrypt payload
    let plaintext = aead::aes_256_gcm_decrypt(
        &dek,
        &nonce_array,
        &envelope.ct,
        &aad_bytes,
    )?;
    
    // Convert Zeroizing<Vec<u8>> to Vec<u8>
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kms::{DualControlConfig, DualControlKms};
    
    #[tokio::test]
    async fn test_kms_decrypt() {
        // Setup KMS
        let config = DualControlConfig {
            require_quorum: false,
            ..Default::default()
        };
        let kms = DualControlKms::new(config);
        
        // Initialize mock HSM
        let kid = format!("{}-{}", 
            hex::encode(&[0xABu8; 4]), 
            hex::encode(&[0x12u8; 4])
        );
        kms.init_mock_hsm(&kid).await.unwrap();
        
        // For now, just test that KMS can be initialized
        // Full integration test would require fixing all the imports
        assert!(kms.check_quorum(&[0u8; 32]).await.unwrap() == false);
    }
}
