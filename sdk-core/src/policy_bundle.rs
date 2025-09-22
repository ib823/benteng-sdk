use crate::policy::Policy;
use crate::crypto::sig;
use serde::{Serialize, Deserialize};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicyBundle {
    pub policies: Vec<Policy>,
    pub version: u64,
    pub created_at: u64,
    pub not_after: u64,
    pub signer_kid: String,
    pub signature: Vec<u8>,
}

impl SignedPolicyBundle {
    pub fn create(
        policies: Vec<Policy>,
        version: u64,
        ttl_secs: u64,
        signer_kid: String,
        signing_key: &[u8],
    ) -> Result<Self, crate::error::BentengError> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let bundle = Self {
            policies,
            version,
            created_at: now,
            not_after: now + ttl_secs,
            signer_kid,
            signature: vec![], // Will be filled after signing
        };
        
        // Serialize for signing (without signature field)
        let msg = Self::serialize_for_signing(&bundle)?;
        
        // Sign with Dilithium3
        let signature = sig::dilithium3_sign(signing_key, &msg)?;
        
        Ok(Self { signature, ..bundle })
    }
    
    pub fn verify(&self, public_key: &[u8]) -> Result<bool, crate::error::BentengError> {
        let msg = Self::serialize_for_signing(self)?;
        sig::dilithium3_verify(public_key, &msg, &self.signature)
    }
    
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now >= self.created_at && now < self.not_after
    }
    
    fn serialize_for_signing(bundle: &Self) -> Result<Vec<u8>, crate::error::BentengError> {
        let mut to_sign = bundle.clone();
        to_sign.signature = vec![]; // Clear signature for deterministic serialization
        
        serde_json::to_vec(&to_sign)
            .map_err(|_| crate::error::BentengError::InternalError)
    }
}

pub struct PolicyDistributor {
    current_bundle: Option<SignedPolicyBundle>,
    next_bundle: Option<SignedPolicyBundle>,
}

impl PolicyDistributor {
    pub fn new() -> Self {
        Self {
            current_bundle: None,
            next_bundle: None,
        }
    }
    
    pub fn update_bundle(&mut self, bundle: SignedPolicyBundle) {
        if bundle.version > self.current_version() {
            self.next_bundle = Some(bundle);
        }
    }
    
    pub fn activate_next(&mut self) {
        if let Some(next) = self.next_bundle.take() {
            self.current_bundle = Some(next);
        }
    }
    
    pub fn get_policy(&self, tenant_id: &str, policy_id: &str) -> Option<&Policy> {
        self.current_bundle.as_ref()?.policies.iter()
            .find(|p| p.tenant_id == tenant_id && p.policy_id == policy_id)
    }
    
    fn current_version(&self) -> u64 {
        self.current_bundle.as_ref().map(|b| b.version).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_policy_bundle_signing() {
        let (pk, sk) = sig::dilithium3_keypair().unwrap();
        
        let policies = vec![
            Policy {
                tenant_id: "tenant1".to_string(),
                policy_id: "policy1".to_string(),
                path: "/test".to_string(),
                required_algs: "kyber+dilithium".to_string(),
                max_age_ms: 30000,
                max_body_bytes: 65536,
                require_device_attest: false,
                hybrid_allowed: true,
                replay_ttl_ms: 30000,
                version: 1,
            }
        ];
        
        let bundle = SignedPolicyBundle::create(
            policies,
            1,
            3600, // 1 hour TTL
            "btk/policy-signer/v1".to_string(),
            &sk,
        ).unwrap();
        
        assert!(bundle.verify(&pk).unwrap());
        assert!(bundle.is_valid());
    }
}
