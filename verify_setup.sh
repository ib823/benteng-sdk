#!/usr/bin/env bash
set -euo pipefail

source ~/.benteng_env || true

echo "===== Benteng Setup Verification ====="

# Test Rust compilation
echo -n "Testing Rust compilation... "
echo 'fn main() { println!("OK"); }' > /tmp/test.rs
if rustc /tmp/test.rs -o /tmp/test && /tmp/test | grep -q OK; then
    echo "✓"
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
if softhsm2-util --show-slots | grep -q "BENTENG_DEV"; then
    echo "✓"
else
    echo "✗"
fi

# Test PQClean
echo -n "Testing PQClean availability... "
if [ -f "/tmp/PQClean/crypto_kem/kyber768/clean/libkyber768_clean.a" ]; then
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

echo "===== Verification Complete ====="
