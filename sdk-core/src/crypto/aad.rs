//! Additional Authenticated Data (AAD) construction

use crate::error::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// AAD structure for binding context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aad {
    pub ver: u8,
    pub tenant_id: Vec<u8>,
    pub policy_id: Vec<u8>,
    pub path: String,
    pub ts_epoch_ms: u64,
    pub required_algs: String,
    pub hybrid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_attest_hash: Option<Vec<u8>>,
}

impl Aad {
    /// Build AAD from envelope components
    pub fn build(
        ver: u8,
        tenant_id: &[u8],
        policy_id: &[u8],
        path: &str,
        ts_epoch_ms: u64,
        required_algs: &str,
        hybrid: bool,
        device_attest_hash: Option<Vec<u8>>,
    ) -> Self {
        Self {
            ver,
            tenant_id: tenant_id.to_vec(),
            policy_id: policy_id.to_vec(),
            path: path.to_string(),
            ts_epoch_ms,
            required_algs: required_algs.to_string(),
            hybrid,
            device_attest_hash,
        }
    }

    /// Serialize AAD to canonical CBOR
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        cbor4ii::serde::to_vec(vec![], self).map_err(|_| crate::error::BentengError::InternalError)
    }

    /// Compute hash of AAD for signature
    pub fn hash(&self) -> Result<[u8; 32]> {
        let cbor = self.to_cbor()?;
        let mut hasher = Sha256::new();
        hasher.update(&cbor);
        Ok(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aad_deterministic() {
        let aad1 = Aad::build(
            1,
            b"tenant",
            b"policy",
            "/path",
            1234567890,
            "kyber+dilithium",
            true,
            None,
        );

        let aad2 = Aad::build(
            1,
            b"tenant",
            b"policy",
            "/path",
            1234567890,
            "kyber+dilithium",
            true,
            None,
        );

        assert_eq!(aad1.to_cbor().unwrap(), aad2.to_cbor().unwrap());
        assert_eq!(aad1.hash().unwrap(), aad2.hash().unwrap());
    }
}
