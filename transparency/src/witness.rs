use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use reqwest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessSignature {
    pub witness_id: String,
    pub tree_size: usize,
    pub root_hash: [u8; 32],
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

pub struct WitnessCoordinator {
    witnesses: Vec<WitnessEndpoint>,
    quorum_threshold: usize,
}

#[derive(Clone)]
struct WitnessEndpoint {
    id: String,
    url: String,
    public_key: Vec<u8>,
}

impl WitnessCoordinator {
    pub fn new(witnesses: Vec<(String, String, Vec<u8>)>, quorum: usize) -> Self {
        let witnesses = witnesses
            .into_iter()
            .map(|(id, url, pk)| WitnessEndpoint {
                id,
                url,
                public_key: pk,
            })
            .collect();
        
        Self {
            witnesses,
            quorum_threshold: quorum,
        }
    }
    
    pub async fn request_cosignatures(
        &self,
        tree_size: usize,
        root_hash: [u8; 32],
    ) -> Result<Vec<WitnessSignature>, String> {
        let mut signatures = Vec::new();
        
        for witness in &self.witnesses {
            match self.request_single_signature(witness, tree_size, root_hash).await {
                Ok(sig) => signatures.push(sig),
                Err(e) => {
                    tracing::warn!("Witness {} failed: {}", witness.id, e);
                }
            }
        }
        
        if signatures.len() >= self.quorum_threshold {
            Ok(signatures)
        } else {
            Err(format!(
                "Insufficient witness signatures: {} < {}",
                signatures.len(),
                self.quorum_threshold
            ))
        }
    }
    
    async fn request_single_signature(
        &self,
        witness: &WitnessEndpoint,
        tree_size: usize,
        root_hash: [u8; 32],
    ) -> Result<WitnessSignature, String> {
        let client = reqwest::Client::new();
        
        #[derive(Serialize)]
        struct SignRequest {
            tree_size: usize,
            root_hash: String,
        }
        
        let response = client
            .post(&format!("{}/sign", witness.url))
            .json(&SignRequest {
                tree_size,
                root_hash: hex::encode(root_hash),
            })
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        
        if !response.status().is_success() {
            return Err(format!("Witness returned {}", response.status()));
        }
        
        let signature: WitnessSignature = response
            .json()
            .await
            .map_err(|e| e.to_string())?;
        
        // Verify signature using witness public key
        if !self.verify_witness_signature(&signature, &witness.public_key) {
            return Err("Invalid witness signature".to_string());
        }
        
        Ok(signature)
    }
    
    fn verify_witness_signature(
        &self,
        sig: &WitnessSignature,
        public_key: &[u8],
    ) -> bool {
        // Use Dilithium3 to verify
        use crate::crypto::sig;
        
        let mut msg = Vec::new();
        msg.extend_from_slice(&sig.tree_size.to_le_bytes());
        msg.extend_from_slice(&sig.root_hash);
        msg.extend_from_slice(&sig.timestamp.to_le_bytes());
        
        sig::dilithium3_verify(public_key, &msg, &sig.signature)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_witness_quorum() {
        // Test witness coordination logic
        let witnesses = vec![
            ("witness1".into(), "http://w1.example".into(), vec![]),
            ("witness2".into(), "http://w2.example".into(), vec![]),
            ("witness3".into(), "http://w3.example".into(), vec![]),
        ];
        
        let coordinator = WitnessCoordinator::new(witnesses, 2);
        assert_eq!(coordinator.quorum_threshold, 2);
    }
}
