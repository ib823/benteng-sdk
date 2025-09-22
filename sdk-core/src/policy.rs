//! Policy management and validation

use crate::error::{BentengError, Result};
use serde::{Deserialize, Serialize};

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub tenant_id: String,
    pub policy_id: String,
    pub path: String,
    pub required_algs: String,
    pub max_age_ms: u64,
    pub max_body_bytes: usize,
    pub require_device_attest: bool,
    pub hybrid_allowed: bool,
    pub replay_ttl_ms: u64,
    pub version: u32,
}

impl Policy {
    /// Validate envelope against policy
    pub fn validate_envelope(
        &self,
        tenant_id: &[u8],
        policy_id: &[u8],
        path: &str,
        ts_epoch_ms: u64,
        required_algs: &str,
    ) -> Result<()> {
        // Check tenant match
        if tenant_id != self.tenant_id.as_bytes() {
            return Err(BentengError::PolicyMismatch);
        }

        // Check policy match
        if policy_id != self.policy_id.as_bytes() {
            return Err(BentengError::PolicyMismatch);
        }

        // Check path match
        if path != self.path {
            return Err(BentengError::PolicyMismatch);
        }

        // Check algorithms
        if required_algs != self.required_algs {
            return Err(BentengError::PolicyMismatch);
        }

        // Check age
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        if now_ms > ts_epoch_ms && (now_ms - ts_epoch_ms) > self.max_age_ms {
            return Err(BentengError::PolicyMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_validation() {
        let policy = Policy {
            tenant_id: "tenant123".to_string(),
            policy_id: "policy456".to_string(),
            path: "/payments/transfer".to_string(),
            required_algs: "kyber+dilithium".to_string(),
            max_age_ms: 30000,
            max_body_bytes: 65536,
            require_device_attest: false,
            hybrid_allowed: true,
            replay_ttl_ms: 30000,
            version: 1,
        };

        let now = chrono::Utc::now().timestamp_millis() as u64;

        // Should succeed
        assert!(policy
            .validate_envelope(
                b"tenant123",
                b"policy456",
                "/payments/transfer",
                now,
                "kyber+dilithium",
            )
            .is_ok());

        // Should fail - wrong tenant
        assert!(policy
            .validate_envelope(
                b"wrong",
                b"policy456",
                "/payments/transfer",
                now,
                "kyber+dilithium",
            )
            .is_err());
    }
}
