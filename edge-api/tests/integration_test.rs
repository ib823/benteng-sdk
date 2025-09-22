use benteng_sdk_core::{
    envelope::operations::EnvelopeOps,
    crypto::{kem, sig},
};
use reqwest;
use serde_json::Value;

#[tokio::test]
async fn test_verify_endpoint() {
    // Generate keys
    let (kem_pk, _kem_sk) = kem::kyber768_keypair().unwrap();
    let (_sig_pk, sig_sk) = sig::dilithium3_keypair().unwrap();
    
    // Create envelope
    let payload = b"Integration test payload";
    let envelope = EnvelopeOps::encrypt_and_sign(
        payload,
        &[0xABu8; 16], // tenant_id
        &[0x12u8; 8],  // policy_id
        "/test/integration",
        &kem_pk,
        &sig_sk,
        false, // not hybrid
    ).unwrap();
    
    // Serialize to CBOR
    let mut cbor_data = Vec::new();
    ciborium::into_writer(&envelope, &mut cbor_data).unwrap();
    
    // Start server in background
    tokio::spawn(async {
        benteng_edge_api::run_server().await
    });
    
    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
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
}
