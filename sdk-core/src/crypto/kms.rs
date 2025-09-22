//! Dual-control KMS gate for threshold cryptography
//! K1 from HSM-A (Kyber decapsulation + HKDF1)
//! K2 from HSM-B (Quorum approval + HKDF2)
//! Final DEK = HKDF(K1 || K2)

use crate::error::BentengError;
use crate::crypto::kdf::hkdf_sha256_derive;
use crate::crypto::kem::{kyber768_keypair, kyber768_decapsulate};


use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::{SystemTime, Duration};

/// Result type for KMS operations
type Result<T> = std::result::Result<T, BentengError>;

/// Dual-control KMS configuration
#[derive(Clone, Debug)]
pub struct DualControlConfig {
    pub hsm_a_endpoint: String,
    pub hsm_b_endpoint: String,
    pub require_quorum: bool,
    pub quorum_threshold: usize,
    pub timeout_ms: u64,
    pub max_cache_entries: usize,
    pub cache_ttl_secs: u64,
}

impl Default for DualControlConfig {
    fn default() -> Self {
        Self {
            hsm_a_endpoint: "mock://hsm-a".to_string(),
            hsm_b_endpoint: "mock://hsm-b".to_string(),
            require_quorum: true,
            quorum_threshold: 2,
            timeout_ms: 5000,
            max_cache_entries: 100,
            cache_ttl_secs: 300,
        }
    }
}

/// Cached key material with expiry
#[derive(ZeroizeOnDrop)]
struct CachedKey {
    #[zeroize(skip)]
    expires_at: SystemTime,
    key_material: Vec<u8>,
}

/// Mock HSM key storage
struct HsmKeyPair {
    public_key: Vec<u8>,
    secret_key: Zeroizing<Vec<u8>>,
}

/// KMS gate trait for dual-control operations
pub trait KmsGate: Send + Sync {
    /// Perform dual-control decryption to derive DEK
    fn dual_decrypt(
        &self,
        kem_ciphertext: &[u8],
        policy_id: &[u8],
        tenant_id: &[u8],
        path: &str,
    ) -> impl std::future::Future<Output = Result<[u8; 32]>> + Send;
    
    /// Get quorum approval status
    fn check_quorum(&self, request_id: &[u8]) -> impl std::future::Future<Output = Result<bool>> + Send;
}

/// Production dual-control KMS implementation
pub struct DualControlKms {
    config: DualControlConfig,
    cache: Arc<RwLock<HashMap<Vec<u8>, CachedKey>>>,
    hsm_a_keys: Arc<RwLock<HashMap<String, HsmKeyPair>>>, // Mock HSM-A storage
    quorum_approvals: Arc<RwLock<HashMap<Vec<u8>, Vec<String>>>>, // Mock quorum tracking
}

impl DualControlKms {
    pub fn new(config: DualControlConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            hsm_a_keys: Arc::new(RwLock::new(HashMap::new())),
            quorum_approvals: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Initialize with a mock HSM key for testing
    pub async fn init_mock_hsm(&self, kid: &str) -> Result<()> {
        let (public_key, secret_key) = kyber768_keypair()?;
        let mut keys = self.hsm_a_keys.write().await;
        keys.insert(kid.to_string(), HsmKeyPair {
            public_key,
            secret_key,
        });
        Ok(())
    }
    
    /// Get public key for a KID
    pub async fn get_public_key(&self, kid: &str) -> Result<Vec<u8>> {
        let keys = self.hsm_a_keys.read().await;
        let pair = keys.get(kid)
            .ok_or_else(|| BentengError::KmsError("Key not found".into()))?;
        Ok(pair.public_key.clone())
    }
    
    /// Get K1 from HSM-A via Kyber decapsulation
    async fn get_k1(&self, kem_ciphertext: &[u8], kid: &str) -> Result<[u8; 32]> {
        // In production, this would call actual HSM API
        // For now, use mock HSM storage
        let keys = self.hsm_a_keys.read().await;
        let pair = keys.get(kid)
            .ok_or_else(|| BentengError::KmsError("KEM key not found in HSM-A".into()))?;
        
        // Decapsulate to get shared secret
        let shared_secret = kyber768_decapsulate(&pair.secret_key, kem_ciphertext)?;
        
        // Apply HKDF1 with HSM-A specific domain separation
        let k1_vec = hkdf_sha256_derive(
            &*shared_secret,
            Some(b"benteng/hsm-a/k1/v1"),
            b"",
            32
        )?;
        
        let mut k1 = [0u8; 32];
        k1.copy_from_slice(&k1_vec);
        
        Ok(k1)
    }
    
    /// Get K2 from HSM-B via quorum approval
    async fn get_k2(&self, request_id: &[u8], policy_id: &[u8]) -> Result<[u8; 32]> {
        // Check quorum approval
        if self.config.require_quorum {
            let approvals = self.quorum_approvals.read().await;
            let approval_list = approvals.get(request_id);
            
            if approval_list.map_or(0, |list| list.len()) < self.config.quorum_threshold {
                return Err(BentengError::KmsError("Insufficient quorum approvals".into()));
            }
        }
        
        // In production, this would call HSM-B API with quorum proof
        // For now, derive K2 from request_id and policy_id
        let mut context = Vec::new();
        context.extend_from_slice(request_id);
        context.extend_from_slice(policy_id);
        
        let k2_vec = hkdf_sha256_derive(
            &context,
            Some(b"benteng/hsm-b/k2/v1"),
            b"",
            32
        )?;
        
        let mut k2 = [0u8; 32];
        k2.copy_from_slice(&k2_vec);
        
        Ok(k2)
    }
    
    /// Add quorum approval (for testing)
    pub async fn add_approval(&self, request_id: &[u8], approver: &str) -> Result<()> {
        let mut approvals = self.quorum_approvals.write().await;
        approvals.entry(request_id.to_vec())
            .or_insert_with(Vec::new)
            .push(approver.to_string());
        Ok(())
    }
}

impl KmsGate for DualControlKms {
    async fn dual_decrypt(
        &self,
        kem_ciphertext: &[u8],
        policy_id: &[u8],
        tenant_id: &[u8],
        path: &str,
    ) -> Result<[u8; 32]> {
        // Generate cache key
        let mut cache_key = Vec::new();
        cache_key.extend_from_slice(kem_ciphertext);
        cache_key.extend_from_slice(policy_id);
        cache_key.extend_from_slice(tenant_id);
        cache_key.extend_from_slice(path.as_bytes());
        
        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(&cache_key) {
                if cached.expires_at > SystemTime::now() {
                    let mut dek = [0u8; 32];
                    dek.copy_from_slice(&cached.key_material);
                    return Ok(dek);
                }
            }
        }
        
        // Generate request ID for quorum tracking
        let request_id_vec = hkdf_sha256_derive(
            &cache_key,
            Some(b"benteng/request-id/v1"),
            b"",
            32
        )?;
        
        let mut request_id = [0u8; 32];
        request_id.copy_from_slice(&request_id_vec);
        
        // Get K1 from HSM-A (Kyber decapsulation + HKDF1)
        let kid = format!("{}-{}", 
            hex::encode(&tenant_id[..4]), 
            hex::encode(&policy_id[..4])
        );
        let k1 = self.get_k1(kem_ciphertext, &kid).await?;
        
        // Get K2 from HSM-B (quorum approval + HKDF2)
        let k2 = self.get_k2(&request_id, policy_id).await?;
        
        // Combine K1 and K2 using HKDF to derive final DEK
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&k1);
        combined.extend_from_slice(&k2);
        
        let dek_vec = hkdf_sha256_derive(
            &combined,
            Some(b"benteng/dek/v1"),
            &[tenant_id, policy_id, path.as_bytes()].concat(),
            32
        )?;
        
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&dek_vec);
        
        // Zeroize intermediate keys
        let mut k1 = k1;
        let mut k2 = k2;
        k1.zeroize();
        k2.zeroize();
        combined.zeroize();
        
        // Cache the result
        {
            let mut cache = self.cache.write().await;
            let cached = CachedKey {
                expires_at: SystemTime::now() + Duration::from_secs(self.config.cache_ttl_secs),
                key_material: dek.to_vec(),
            };
            
            // Evict old entries if cache is full
            if cache.len() >= self.config.max_cache_entries {
                // Remove expired entries
                cache.retain(|_, v| v.expires_at > SystemTime::now());
                
                // If still full, remove oldest
                if cache.len() >= self.config.max_cache_entries {
                    if let Some(oldest_key) = cache.keys().next().cloned() {
                        cache.remove(&oldest_key);
                    }
                }
            }
            
            cache.insert(cache_key, cached);
        }
        
        Ok(dek)
    }
    
    async fn check_quorum(&self, request_id: &[u8]) -> Result<bool> {
        let approvals = self.quorum_approvals.read().await;
        let count = approvals.get(request_id).map_or(0, |list| list.len());
        Ok(count >= self.config.quorum_threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_dual_control_basic() {
        let config = DualControlConfig {
            require_quorum: false, // Disable for basic test
            ..Default::default()
        };
        
        let kms = DualControlKms::new(config);
        
        // Initialize mock HSM key
        let kid = format!("{}-{}", hex::encode(&[1u8; 4]), hex::encode(&[2u8; 4]));
        kms.init_mock_hsm(&kid).await.unwrap();
        
        // Generate test KEM ciphertext
        let public_key = kms.get_public_key(&kid).await.unwrap();
        let (ciphertext, _) = crate::crypto::kem::kyber768_encapsulate(&public_key).unwrap();
        
        // Test dual decrypt
        let dek = kms.dual_decrypt(
            &ciphertext,
            &[2u8; 8],
            &[1u8; 16],
            "/test/path"
        ).await.unwrap();
        
        assert_eq!(dek.len(), 32);
    }
    
    #[tokio::test]
    async fn test_dual_control_with_quorum() {
        let config = DualControlConfig {
            require_quorum: true,
            quorum_threshold: 2,
            ..Default::default()
        };
        
        let kms = DualControlKms::new(config);
        
        // Initialize mock HSM key
        let kid = format!("{}-{}", hex::encode(&[1u8; 4]), hex::encode(&[2u8; 4]));
        kms.init_mock_hsm(&kid).await.unwrap();
        
        // Generate test data
        let public_key = kms.get_public_key(&kid).await.unwrap();
        let (ciphertext, _) = crate::crypto::kem::kyber768_encapsulate(&public_key).unwrap();
        
        // Generate request ID
        let mut request_data = Vec::new();
        request_data.extend_from_slice(&ciphertext);
        request_data.extend_from_slice(&[2u8; 8]);
        request_data.extend_from_slice(&[1u8; 16]);
        request_data.extend_from_slice(b"/test/path");
        
        let request_id_vec = hkdf_sha256_derive(
            &request_data,
            Some(b"benteng/request-id/v1"),
            b"",
            32
        ).unwrap();
        
        let mut request_id = [0u8; 32];
        request_id.copy_from_slice(&request_id_vec);
        
        // Should fail without quorum
        let result = kms.dual_decrypt(
            &ciphertext,
            &[2u8; 8],
            &[1u8; 16],
            "/test/path"
        ).await;
        assert!(result.is_err());
        
        // Add approvals
        kms.add_approval(&request_id, "approver1").await.unwrap();
        kms.add_approval(&request_id, "approver2").await.unwrap();
        
        // Should succeed with quorum
        let dek = kms.dual_decrypt(
            &ciphertext,
            &[2u8; 8],
            &[1u8; 16],
            "/test/path"
        ).await.unwrap();
        
        assert_eq!(dek.len(), 32);
        
        // Check quorum status
        assert!(kms.check_quorum(&request_id).await.unwrap());
    }
}
