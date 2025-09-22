use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use benteng_sdk_core::{
    envelope::{Envelope, kms_decrypt::decrypt_with_kms},
    crypto::kms::{DualControlKms, DualControlConfig},
    policy::Policy,
};
use benteng_transparency::{TransparencyLog, LogEntry};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tower_http::trace::TraceLayer;
use tracing_subscriber;
use sha2::{Sha256, Digest};

#[derive(Clone)]
struct AppState {
    kms: Arc<DualControlKms>,
    transparency_log: Arc<RwLock<TransparencyLog>>,
    policy_cache: Arc<RwLock<HashMap<String, Policy>>>,
    replay_cache: Arc<RwLock<HashMap<Vec<u8>, SystemTime>>>,
    rate_limits: Arc<RwLock<HashMap<String, RateLimitBucket>>>,
}

#[derive(Clone)]
struct RateLimitBucket {
    tokens: f64,
    last_update: SystemTime,
    max_tokens: f64,
    refill_rate: f64,
}

impl RateLimitBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            last_update: SystemTime::now(),
            max_tokens,
            refill_rate,
        }
    }
    
    fn try_consume(&mut self, tokens: f64) -> bool {
        let now = SystemTime::now();
        let elapsed = now.duration_since(self.last_update)
            .unwrap_or(Duration::ZERO)
            .as_secs_f64();
        
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_update = now;
        
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    timestamp: u64,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    decision: String,
    claims: HashMap<String, String>,
    kid: String,
    receipt: ReceiptInfo,
}

#[derive(Debug, Serialize)]
struct DecryptResponse {
    decision: String,
    kid: String,
    receipt: ReceiptInfo,
}

#[derive(Debug, Serialize)]
struct ReceiptInfo {
    tlog_hash: String,
    checkpoint: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    decision: String,
    reason: String,
}

async fn health() -> impl IntoResponse {
    let response = HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    Json(response)
}

async fn verify(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let envelope: Envelope = match ciborium::from_reader(&body[..]) {
        Ok(env) => env,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    decision: "REJECTED".to_string(),
                    reason: "Invalid envelope format".to_string(),
                })
            ).into_response();
        }
    };
    
    let rate_key = format!("verify-{}-{}", 
        hex::encode(&envelope.tenant_id[..4.min(envelope.tenant_id.len())]),
        hex::encode(&envelope.policy_id[..4.min(envelope.policy_id.len())])
    );
    
    {
        let mut rate_limits = state.rate_limits.write().await;
        let bucket = rate_limits.entry(rate_key)
            .or_insert_with(|| RateLimitBucket::new(100.0, 10.0));
        
        if !bucket.try_consume(1.0) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    decision: "REJECTED".to_string(),
                    reason: "Rate limit exceeded".to_string(),
                })
            ).into_response();
        }
    }
    
    let sig_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&envelope.sig);
        let hash = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash);
        arr
    };
    
    {
        let mut replay_cache = state.replay_cache.write().await;
        let now = SystemTime::now();
        
        replay_cache.retain(|_, time| {
            now.duration_since(*time).unwrap_or(Duration::ZERO) < Duration::from_secs(300)
        });
        
        if replay_cache.contains_key(&sig_hash.to_vec()) {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    decision: "REJECTED".to_string(),
                    reason: "Replay detected".to_string(),
                })
            ).into_response();
        }
        
        replay_cache.insert(sig_hash.to_vec(), now);
    }
    
    let policy_key = format!("{}-{}-{}",
        hex::encode(&envelope.tenant_id[..4.min(envelope.tenant_id.len())]),
        hex::encode(&envelope.policy_id[..4.min(envelope.policy_id.len())]),
        &envelope.path
    );
    
    let policy = {
        let cache = state.policy_cache.read().await;
        cache.get(&policy_key).cloned().unwrap_or_else(|| {
            Policy {
                tenant_id: hex::encode(&envelope.tenant_id),
                policy_id: hex::encode(&envelope.policy_id),
                path: envelope.path.clone(),
                required_algs: envelope.aad_ext.required_algs.clone(),
                max_age_ms: 30000,
                max_body_bytes: 65536,
                require_device_attest: false,
                hybrid_allowed: true,
                replay_ttl_ms: 30000,
                version: 1,
            }
        })
    };
    
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    
    if now_ms > envelope.ts_epoch_ms + policy.max_age_ms {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                decision: "REJECTED".to_string(),
                reason: "Envelope too old".to_string(),
            })
        ).into_response();
    }
    
    let receipt_hash = {
        let mut log = state.transparency_log.write().await;
        let mut hasher = Sha256::new();
        hasher.update(b"verify");
        hasher.update(&envelope.tenant_id);
        hasher.update(&envelope.policy_id);
        hasher.update(&sig_hash);
        let hash = hasher.finalize();
        let mut hdr_h = [0u8; 32];
        hdr_h.copy_from_slice(&hash);
        
        let entry = LogEntry {
            v: 1,
            ten: envelope.tenant_id.clone(),
            typ: "verify".to_string(),
            ts: now_ms,
            hdr_h,
            sig_h: sig_hash,
            kid: format!("btk/ten-{}/server-sig/ML-DSA-65/v1", 
                hex::encode(&envelope.tenant_id[..4.min(envelope.tenant_id.len())])),
            pol: envelope.policy_id.clone(),
            rc: 0,
        };
        log.append(entry).unwrap();
        hex::encode(hash)
    };
    
    let mut claims = HashMap::new();
    claims.insert("alg".to_string(), envelope.aad_ext.required_algs.clone());
    claims.insert("age_ms".to_string(), (now_ms - envelope.ts_epoch_ms).to_string());
    claims.insert("path".to_string(), envelope.path.clone());
    
    let response = VerifyResponse {
        decision: "OK".to_string(),
        claims,
        kid: format!("btk/ten-{}/server-sig/ML-DSA-65/v1", 
            hex::encode(&envelope.tenant_id[..4.min(envelope.tenant_id.len())])),
        receipt: ReceiptInfo {
            tlog_hash: receipt_hash,
            checkpoint: "checkpoint-123".to_string(),
        },
    };
    
    (StatusCode::OK, Json(response)).into_response()
}

async fn decrypt(
    State(state): State<AppState>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let envelope: Envelope = match ciborium::from_reader(&body[..]) {
        Ok(env) => env,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    decision: "REJECTED".to_string(),
                    reason: "Invalid envelope format".to_string(),
                })
            ).into_response();
        }
    };
    
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    
    if now_ms > envelope.ts_epoch_ms + 30000 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                decision: "REJECTED".to_string(),
                reason: "Envelope too old".to_string(),
            })
        ).into_response();
    }
    
    match decrypt_with_kms(&envelope, state.kms.as_ref()).await {
        Ok(_plaintext) => {
            let receipt_hash = {
                let mut log = state.transparency_log.write().await;
                let mut hasher = Sha256::new();
                hasher.update(b"decrypt");
                hasher.update(&envelope.tenant_id);
                hasher.update(&envelope.policy_id);
                hasher.update(&envelope.nonce);
                let hash = hasher.finalize();
                let mut hdr_h = [0u8; 32];
                hdr_h.copy_from_slice(&hash);
                
                let mut sig_hasher = Sha256::new();
                sig_hasher.update(&envelope.sig);
                let sig_hash_result = sig_hasher.finalize();
                let mut sig_h = [0u8; 32];
                sig_h.copy_from_slice(&sig_hash_result);
                
                let entry = LogEntry {
                    v: 1,
                    ten: envelope.tenant_id.clone(),
                    typ: "decrypt".to_string(),
                    ts: now_ms,
                    hdr_h,
                    sig_h,
                    kid: format!("btk/ten-{}/server-kem/ML-KEM-768/v1",
                        hex::encode(&envelope.tenant_id[..4.min(envelope.tenant_id.len())])),
                    pol: envelope.policy_id.clone(),
                    rc: 0,
                };
                log.append(entry).unwrap();
                hex::encode(hash)
            };
            
            let response = DecryptResponse {
                decision: "OK".to_string(),
                kid: format!("btk/ten-{}/server-kem/ML-KEM-768/v1",
                    hex::encode(&envelope.tenant_id[..4.min(envelope.tenant_id.len())])),
                receipt: ReceiptInfo {
                    tlog_hash: receipt_hash,
                    checkpoint: "checkpoint-124".to_string(),
                },
            };
            
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Decrypt failed: {:?}", e);
            
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    decision: "REJECTED".to_string(),
                    reason: "Decrypt failed".to_string(),
                })
            ).into_response()
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    
    let kms_config = DualControlConfig {
        require_quorum: false,
        ..Default::default()
    };
    let kms = Arc::new(DualControlKms::new(kms_config));
    
    let kid = format!("{}-{}", hex::encode(&[0xABu8; 4]), hex::encode(&[0x12u8; 4]));
    kms.init_mock_hsm(&kid).await.unwrap();
    
    let state = AppState {
        kms,
        transparency_log: Arc::new(RwLock::new(TransparencyLog::new())),
        policy_cache: Arc::new(RwLock::new(HashMap::new())),
        replay_cache: Arc::new(RwLock::new(HashMap::new())),
        rate_limits: Arc::new(RwLock::new(HashMap::new())),
    };
    
    let app = Router::new()
        .route("/health", get(health))
        .route("/pqc/verify", post(verify))
        .route("/pqc/decrypt", post(decrypt))
        .layer(TraceLayer::new_for_http())
        .with_state(state);
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    
    println!("🚀 Benteng Edge API listening on http://0.0.0.0:3000");
    println!("📌 Endpoints:");
    println!("   GET  /health");
    println!("   POST /pqc/verify");
    println!("   POST /pqc/decrypt");
    
    axum::serve(listener, app)
        .await
        .unwrap();
}

mod salt_rotation;
use salt_rotation::SaltRotator;

// In main(), add:
// let salt_rotator = Arc::new(SaltRotator::new(24)); // 24 hour rotation
// tokio::spawn(salt_rotator.clone().start_rotation());
