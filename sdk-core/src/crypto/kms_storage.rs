use sled::{Db, IVec};
use std::path::Path;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedApproval {
    pub request_id: Vec<u8>,
    pub approver: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

pub struct QuorumStorage {
    db: Db,
}

impl QuorumStorage {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }
    
    pub fn add_approval(&self, approval: PersistedApproval) -> Result<(), sled::Error> {
        let key = format!("approval:{}:{}", 
            hex::encode(&approval.request_id),
            approval.approver
        );
        
        let value = serde_json::to_vec(&approval).unwrap();
        self.db.insert(key.as_bytes(), value)?;
        
        // Update approval count
        self.increment_approval_count(&approval.request_id)?;
        
        Ok(())
    }
    
    pub fn get_approvals(&self, request_id: &[u8]) -> Result<Vec<PersistedApproval>, sled::Error> {
        let prefix = format!("approval:{}:", hex::encode(request_id));
        
        let mut approvals = Vec::new();
        for item in self.db.scan_prefix(prefix.as_bytes()) {
            let (_, value) = item?;
            if let Ok(approval) = serde_json::from_slice(&value) {
                approvals.push(approval);
            }
        }
        
        Ok(approvals)
    }
    
    pub fn get_approval_count(&self, request_id: &[u8]) -> Result<usize, sled::Error> {
        let key = format!("count:{}", hex::encode(request_id));
        
        match self.db.get(key.as_bytes())? {
            Some(value) => {
                let count = u64::from_le_bytes(
                    value.as_ref().try_into().unwrap_or([0; 8])
                );
                Ok(count as usize)
            }
            None => Ok(0)
        }
    }
    
    fn increment_approval_count(&self, request_id: &[u8]) -> Result<(), sled::Error> {
        let key = format!("count:{}", hex::encode(request_id));
        
        self.db.update_and_fetch(key.as_bytes(), |old| {
            let count = match old {
                Some(bytes) => {
                    u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])) + 1
                }
                None => 1
            };
            Some(IVec::from(&count.to_le_bytes()))
        })?;
        
        Ok(())
    }
    
    pub fn cleanup_old_approvals(&self, max_age_secs: u64) -> Result<usize, sled::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let cutoff = now - max_age_secs;
        let mut removed = 0;
        
        for item in self.db.scan_prefix(b"approval:") {
            let (key, value) = item?;
            
            if let Ok(approval) = serde_json::from_slice::<PersistedApproval>(&value) {
                if approval.timestamp < cutoff {
                    self.db.remove(key)?;
                    removed += 1;
                }
            }
        }
        
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_quorum_persistence() {
        let dir = tempdir().unwrap();
        let storage = QuorumStorage::new(dir.path()).unwrap();
        
        let approval = PersistedApproval {
            request_id: vec![1, 2, 3, 4],
            approver: "approver1".to_string(),
            timestamp: 1234567890,
            signature: vec![5, 6, 7, 8],
        };
        
        storage.add_approval(approval.clone()).unwrap();
        
        let approvals = storage.get_approvals(&[1, 2, 3, 4]).unwrap();
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].approver, "approver1");
        
        let count = storage.get_approval_count(&[1, 2, 3, 4]).unwrap();
        assert_eq!(count, 1);
    }
}
