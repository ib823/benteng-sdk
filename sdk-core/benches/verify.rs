use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use benteng_sdk_core::{
    envelope::{Envelope, operations::EnvelopeOps},
    crypto::{kem, sig},
};

fn create_test_envelope() -> (Envelope, Vec<u8>, Vec<u8>) {
    let (server_kem_pk, server_kem_sk_zeroizing) = kem::kyber768_keypair().unwrap();
    let server_kem_sk = server_kem_sk_zeroizing.to_vec();
    let (client_sig_pk, client_sig_sk) = sig::dilithium3_keypair().unwrap();
    
    let payload = b"Benchmark payload data for testing performance";
    let tenant_id = b"tenant-bench";
    let policy_id = b"policy-bench";
    let path = "/bench/test";
    
    let envelope = EnvelopeOps::encrypt_and_sign(
        payload,
        tenant_id,
        policy_id,
        path,
        &server_kem_pk,
        &client_sig_sk,
        false,
    ).unwrap();
    
    (envelope, client_sig_pk, server_kem_sk)
}

fn bench_verify(c: &mut Criterion) {
    let (envelope, client_sig_pk, _) = create_test_envelope();
    
    c.bench_function("verify_envelope_p50", |b| {
        b.iter(|| {
            EnvelopeOps::verify(
                black_box(&envelope),
                black_box(&client_sig_pk),
            )
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let (envelope, _, server_kem_sk) = create_test_envelope();
    
    c.bench_function("decrypt_envelope_p50", |b| {
        b.iter(|| {
            EnvelopeOps::decrypt(
                black_box(&envelope),
                black_box(&server_kem_sk),
            )
        })
    });
}

fn bench_envelope_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("envelope_sizes");
    
    for size in [64, 256, 1024, 4096, 16384].iter() {
        let payload = vec![0x42u8; *size];
        let (server_kem_pk, _) = kem::kyber768_keypair().unwrap();
        let (_, client_sig_sk) = sig::dilithium3_keypair().unwrap();
        
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, _| {
                b.iter(|| {
                    EnvelopeOps::encrypt_and_sign(
                        &payload,
                        b"tenant",
                        b"policy",
                        "/test",
                        &server_kem_pk,
                        &client_sig_sk,
                        false,
                    )
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_verify, bench_decrypt, bench_envelope_sizes);
criterion_main!(benches);
