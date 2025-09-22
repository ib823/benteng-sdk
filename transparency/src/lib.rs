//! Benteng Transparency Log

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub v: u8,
    pub ten: Vec<u8>,      // tenant_id
    pub typ: String,        // "verify" or "decrypt"
    pub ts: u64,            // timestamp ms
    pub hdr_h: [u8; 32],    // header hash
    pub sig_h: [u8; 32],    // signature hash
    pub kid: String,
    pub pol: Vec<u8>,       // policy_id
    pub rc: u16,            // result code (0 = success)
}

/// Merkle tree node
#[derive(Debug, Clone)]
pub struct MerkleNode {
    pub hash: [u8; 32],
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
}

/// Transparency log
pub struct TransparencyLog {
    entries: Vec<LogEntry>,
    tree: Option<MerkleNode>,
    checkpoints: Vec<Checkpoint>,
}

/// Signed checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub tree_size: usize,
    pub root_hash: [u8; 32],
    pub ts: u64,
    pub ver: u8,
    pub signature: Vec<u8>,
}

impl TransparencyLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            tree: None,
            checkpoints: Vec::new(),
        }
    }
    
    /// Append entry to log
    pub fn append(&mut self, entry: LogEntry) -> Result<usize, String> {
        let entry_id = self.entries.len();
        self.entries.push(entry);
        self.rebuild_tree();
        Ok(entry_id)
    }
    
    /// Get entry by ID
    pub fn get_entry(&self, id: usize) -> Option<&LogEntry> {
        self.entries.get(id)
    }
    
    /// Get latest checkpoint
    pub fn get_latest_checkpoint(&self) -> Option<&Checkpoint> {
        self.checkpoints.last()
    }
    
    /// Create new checkpoint
    pub fn create_checkpoint(&mut self) -> Result<Checkpoint, String> {
        let root_hash = self.get_root_hash()
            .ok_or_else(|| "No entries in log".to_string())?;
        
        let checkpoint = Checkpoint {
            tree_size: self.entries.len(),
            root_hash,
            ts: chrono::Utc::now().timestamp_millis() as u64,
            ver: 1,
            signature: vec![], // TODO: Sign with checkpoint signer
        };
        
        self.checkpoints.push(checkpoint.clone());
        Ok(checkpoint)
    }
    
    /// Rebuild Merkle tree
    fn rebuild_tree(&mut self) {
        if self.entries.is_empty() {
            self.tree = None;
            return;
        }
        
        // Create leaf nodes
        let mut nodes: Vec<MerkleNode> = self.entries
            .iter()
            .map(|entry| {
                let leaf_data = serde_json::to_vec(entry).unwrap();
                let mut hasher = Sha256::new();
                hasher.update(&[0x00]); // Leaf prefix
                hasher.update(&leaf_data);
                MerkleNode {
                    hash: hasher.finalize().into(),
                    left: None,
                    right: None,
                }
            })
            .collect();
        
        // Build tree bottom-up
        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in nodes.chunks(2) {
                let node = if chunk.len() == 2 {
                    let mut hasher = Sha256::new();
                    hasher.update(&[0x01]); // Node prefix
                    hasher.update(&chunk[0].hash);
                    hasher.update(&chunk[1].hash);
                    
                    MerkleNode {
                        hash: hasher.finalize().into(),
                        left: Some(Box::new(chunk[0].clone())),
                        right: Some(Box::new(chunk[1].clone())),
                    }
                } else {
                    chunk[0].clone()
                };
                next_level.push(node);
            }
            
            nodes = next_level;
        }
        
        self.tree = nodes.into_iter().next();
    }
    
    /// Get root hash
    pub fn get_root_hash(&self) -> Option<[u8; 32]> {
        self.tree.as_ref().map(|node| node.hash)
    }
    
    /// Get inclusion proof for entry
    pub fn get_inclusion_proof(&self, _entry_id: usize) -> Option<Vec<[u8; 32]>> {
        // TODO: Implement inclusion proof
        None
    }
}

impl Default for TransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transparency_log() {
        let mut log = TransparencyLog::new();
        
        let entry = LogEntry {
            v: 1,
            ten: b"tenant".to_vec(),
            typ: "verify".to_string(),
            ts: 1234567890,
            hdr_h: [0; 32],
            sig_h: [1; 32],
            kid: "btk/test/key/v1".to_string(),
            pol: b"policy".to_vec(),
            rc: 0,
        };
        
        let id = log.append(entry.clone()).unwrap();
        assert_eq!(id, 0);
        
        let retrieved = log.get_entry(0).unwrap();
        assert_eq!(retrieved.typ, "verify");
        
        let checkpoint = log.create_checkpoint().unwrap();
        assert_eq!(checkpoint.tree_size, 1);
    }
}
