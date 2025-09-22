#!/usr/bin/env bash
set -euo pipefail

source ~/.benteng_env

echo "===== Benteng Setup Verification v2 ====="

# Test Rust compilation
echo -n "Testing Rust compilation... "
echo 'fn main() { println!("OK"); }' > /tmp/test.rs
if rustc /tmp/test.rs -o /tmp/test && /tmp/test | grep -q OK; then
    echo "✓ ($(rustc --version | cut -d' ' -f2))"
else
    echo "✗"
fi

# Test WASM compilation
echo -n "Testing WASM target... "
if rustc --target wasm32-unknown-unknown /tmp/test.rs -o /tmp/test.wasm 2>/dev/null; then
    echo "✓"
else
    echo "✗"
fi

# Test SoftHSM2
echo -n "Testing SoftHSM2... "
if softhsm2-util --show-slots 2>/dev/null | grep -q "BENTENG_DEV"; then
    echo "✓"
else
    echo "✗"
fi

# Test PQClean Kyber
echo -n "Testing PQClean Kyber768... "
if [ -f "/tmp/PQClean/crypto_kem/kyber768/clean/libkyber768_clean.a" ]; then
    echo "✓"
else
    echo "✗"
fi

# Test PQClean Dilithium
echo -n "Testing PQClean Dilithium3... "
if [ -f "/tmp/PQClean/crypto_sign/dilithium3/clean/libdilithium3_clean.a" ]; then
    echo "✓"
else
    echo "✗"
fi

# Test cargo tools
echo -n "Testing cargo-nextest... "
if cargo nextest --version &>/dev/null; then
    echo "✓"
else
    echo "✗"
fi

echo -n "Testing wasm-pack... "
if wasm-pack --version &>/dev/null; then
    echo "✓"
else
    echo "✗"
fi

# Test project structure
echo -n "Testing project structure... "
if [ -d "$BENTENG_ROOT/sdk-core" ] && [ -d "$BENTENG_ROOT/edge-api" ]; then
    echo "✓"
else
    echo "✗"
fi

echo "===== Verification Complete ====="
echo ""
echo "Environment variables:"
echo "  BENTENG_ROOT: $BENTENG_ROOT"
echo "  PQCLEAN_PATH: $PQCLEAN_PATH"
echo "  SOFTHSM2_CONF: $SOFTHSM2_CONF"
