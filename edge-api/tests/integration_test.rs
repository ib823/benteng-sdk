use benteng_sdk_core::{
    envelope::EnvelopeOps,
    crypto::{kem::KemPair, sig::SigningKey},
};
use reqwest;
use serde_json::Value;

#[tokio::test]
async fn test_verify_endpoint() {
    // Generate keys
    let kem_pair = KemPair::generate().unwrap();
    let signing_key = SigningKey::generate().unwrap();
    
    // Create envelope
    let payload = b"Integration test payload";
    let envelope = EnvelopeOps::encrypt_and_sign(
        payload,
        &[0xABu8; 16], // tenant_id
        &[0x12u8; 8],  // policy_id
        "/test/integration",
        "kyber+dilithium",
        true, // hybrid
        Some(&[0xFFu8; 32]), // device_attest_hash
        &kem_pair.public_key(),
        &signing_key,
    ).unwrap();
    
    // Serialize to CBOR
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&envelope, &mut cbor_data).unwrap();
    
    // Call verify endpoint
    let client = reqwest::Client::new();
    let response = client.post("http://localhost:3000/pqc/verify")
        .body(cbor_data.clone())
        .header("Content-Type", "application/cbor")
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    
    let json: Value = response.json().await.unwrap();
    assert_eq!(json["decision"], "OK");
    assert!(json["receipt"]["tlog_hash"].is_string());
}

#[tokio::test]
async fn test_decrypt_endpoint() {
    // Similar test for decrypt
    // Would need mock KMS setup
}
