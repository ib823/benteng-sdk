//! Cryptographic envelope implementation

pub mod operations;

use serde::{Deserialize, Serialize};
use crate::error::{BentengError, Result};

pub const ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AlgorithmSet {
    pub kem: String,
    pub sig: String,
    pub aead: String,
    pub hybrid: bool,
}

impl Default for AlgorithmSet {
    fn default() -> Self {
        Self {
            kem: "ML-KEM-768".into(),
            sig: "ML-DSA-65".into(),
            aead: "AES-256-GCM".into(),
            hybrid: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AadExtensions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_attest_hash: Option<Vec<u8>>,
    pub required_algs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "1")]
    pub ver: u8,
    #[serde(rename = "2")]
    pub algs: AlgorithmSet,
    #[serde(rename = "3")]
    pub tenant_id: Vec<u8>,
    #[serde(rename = "4")]
    pub policy_id: Vec<u8>,
    #[serde(rename = "5")]
    pub path: String,
    #[serde(rename = "6")]
    pub ts_epoch_ms: u64,
    #[serde(rename = "7")]
    pub nonce: Vec<u8>,
    #[serde(rename = "8")]
    pub aad_ext: AadExtensions,
    #[serde(rename = "9", skip_serializing_if = "Option::is_none")]
    pub kem_pub_ephem: Option<Vec<u8>>,
    #[serde(rename = "10")]
    pub kem_ct: Vec<u8>,
    #[serde(rename = "11")]
    pub sig: Vec<u8>,
    #[serde(rename = "12")]
    pub ct: Vec<u8>,
}

impl Envelope {
    pub fn new(tenant_id: Vec<u8>, policy_id: Vec<u8>, path: String) -> Self {
        Self {
            ver: ENVELOPE_VERSION,
            algs: AlgorithmSet::default(),
            tenant_id,
            policy_id,
            path,
            ts_epoch_ms: chrono::Utc::now().timestamp_millis() as u64,
            nonce: vec![0; 12],
            aad_ext: AadExtensions {
                device_attest_hash: None,
                required_algs: "kyber+dilithium".into(),
            },
            kem_pub_ephem: None,
            kem_ct: vec![],
            sig: vec![],
            ct: vec![],
        }
    }
    
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        cbor4ii::serde::to_vec(vec![], self)
            .map_err(|_| BentengError::InternalError)
    }
    
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        cbor4ii::serde::from_slice(data)
            .map_err(|_| BentengError::InternalError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_envelope_roundtrip() {
        let env = Envelope::new(
            b"tenant123".to_vec(),
            b"policy456".to_vec(),
            "/payments/transfer".into(),
        );
        
        let cbor = env.to_cbor().unwrap();
        let env2 = Envelope::from_cbor(&cbor).unwrap();
        
        assert_eq!(env.tenant_id, env2.tenant_id);
        assert_eq!(env.policy_id, env2.policy_id);
        assert_eq!(env.path, env2.path);
    }
}
pub mod kms_decrypt;
