use chrono::{DateTime, Utc, Duration};
use sha2::{Sha256, Digest};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time;

pub struct SaltRotator {
    current_salt: Arc<RwLock<Salt>>,
    rotation_interval: Duration,
}

#[derive(Clone)]
struct Salt {
    value: [u8; 32],
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl SaltRotator {
    pub fn new(rotation_hours: i64) -> Self {
        let rotation_interval = Duration::hours(rotation_hours);
        let initial_salt = Salt::generate(rotation_interval);
        
        Self {
            current_salt: Arc::new(RwLock::new(initial_salt)),
            rotation_interval,
        }
    }
    
    pub async fn start_rotation(self: Arc<Self>) {
        let mut interval = time::interval(
            std::time::Duration::from_secs(3600) // Check hourly
        );
        
        loop {
            interval.tick().await;
            
            let should_rotate = {
                let salt = self.current_salt.read().await;
                Utc::now() >= salt.expires_at
            };
            
            if should_rotate {
                let new_salt = Salt::generate(self.rotation_interval);
                *self.current_salt.write().await = new_salt;
                tracing::info!("Salt rotated successfully");
            }
        }
    }
    
    pub async fn hash_ip(&self, ip: &str) -> String {
        let salt = self.current_salt.read().await;
        
        // Extract /24 prefix
        let prefix = ip.split('.')
            .take(3)
            .collect::<Vec<_>>()
            .join(".");
        
        // Hash with salt
        let mut hasher = Sha256::new();
        hasher.update(&salt.value);
        hasher.update(prefix.as_bytes());
        
        hex::encode(hasher.finalize())
    }
}

impl Salt {
    fn generate(ttl: Duration) -> Self {
        let mut value = [0u8; 32];
        getrandom::getrandom(&mut value).expect("Failed to generate salt");
        
        let created_at = Utc::now();
        let expires_at = created_at + ttl;
        
        Self {
            value,
            created_at,
            expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_ip_hashing() {
        let rotator = Arc::new(SaltRotator::new(24));
        
        let hash1 = rotator.hash_ip("192.168.1.100").await;
        let hash2 = rotator.hash_ip("192.168.1.200").await;
        
        // Same /24 should produce same hash
        assert_eq!(hash1, hash2);
        
        let hash3 = rotator.hash_ip("192.168.2.100").await;
        // Different /24 should produce different hash
        assert_ne!(hash1, hash3);
    }
}
