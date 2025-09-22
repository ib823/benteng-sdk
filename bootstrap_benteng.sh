#!/usr/bin/env bash
set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}==================================="
echo "Benteng Development Environment Setup"
echo "===================================${NC}"

# Function to print status
status() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Update system packages
status "Updating system packages..."
sudo apt-get update -qq

# Install essential build tools
status "Installing build essentials..."
sudo apt-get install -y -qq \
    build-essential \
    cmake \
    clang \
    llvm \
    pkg-config \
    libssl-dev \
    libgmp-dev \
    libpcre3-dev \
    zlib1g-dev \
    m4 \
    curl \
    wget \
    jq \
    protobuf-compiler

# Install Rust if not present
if ! command -v rustc &> /dev/null; then
    status "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
else
    status "Rust already installed: $(rustc --version)"
fi

# Update Rust and install required components
status "Configuring Rust toolchain..."
rustup update stable
rustup update nightly
rustup component add rustfmt clippy
rustup component add rust-src --toolchain nightly

# Install WASM targets
status "Installing WebAssembly targets..."
rustup target add wasm32-unknown-unknown
rustup target add wasm32-wasi

# Install Rust development tools
status "Installing Rust development tools..."
cargo install cargo-nextest --locked || true
cargo install cargo-audit --locked || true
cargo install cargo-deny --locked || true
cargo install cargo-tarpaulin --locked || true
cargo install cargo-fuzz --locked || true
cargo install wasm-pack --locked || true
cargo install cargo-expand --locked || true
cargo install just --locked || true

# Install Node.js 20 LTS if needed
if ! command -v node &> /dev/null || [ "$(node -v | cut -d'.' -f1 | sed 's/v//')" -lt 18 ]; then
    status "Installing Node.js 20 LTS..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
else
    status "Node.js already installed: $(node -v)"
fi

# Install SoftHSM2 for development
status "Installing SoftHSM2..."
sudo apt-get install -y softhsm2

# Initialize SoftHSM2 token for development
status "Initializing SoftHSM2 development token..."
mkdir -p ~/.config/softhsm2
cat > ~/.config/softhsm2/softhsm2.conf << 'SOFTHSM'
directories.tokendir = /tmp/softhsm2/
objectstore.backend = file
log.level = INFO
SOFTHSM

mkdir -p /tmp/softhsm2
softhsm2-util --init-token --slot 0 --label "BENTENG_DEV" --pin 0000 --so-pin 0000 || true

# Install Python packages for tooling
status "Installing Python packages..."
pip3 install --user cbor2 pyyaml

# Create project structure
status "Creating Benteng project structure..."
mkdir -p benteng/{sdk-core,sdk-ios,sdk-android,sdk-web,edge-api,cli,transparency,admin-console,formal,devops,policies,docs}
mkdir -p benteng/.github/workflows
mkdir -p benteng/.devcontainer

# Install PQClean (for PQC algorithms)
status "Building PQClean for PQC support..."
if [ ! -d "/tmp/PQClean" ]; then
    git clone https://github.com/PQClean/PQClean.git /tmp/PQClean
    cd /tmp/PQClean
    make clean
    make -j$(nproc)
    cd -
fi

# Create environment file
cat > ~/.benteng_env << 'ENVFILE'
# Benteng Development Environment
export BENTENG_DEV=1
export RUST_BACKTRACE=1
export SOFTHSM2_CONF=$HOME/.config/softhsm2/softhsm2.conf
export PATH=$HOME/.cargo/bin:$PATH

# Development KMS endpoints (mock)
export KMS_ENDPOINT_A="softhsm://slot=0"
export KMS_ENDPOINT_B="softhsm://slot=0"
export KMS_PIN="0000"

# PQClean location
export PQCLEAN_PATH="/tmp/PQClean"

# Development settings
export BENTENG_LOG_LEVEL="debug"
export BENTENG_ENV="dev"
ENVFILE

# Source the environment
source ~/.benteng_env

# Add to bashrc for persistence
if ! grep -q "benteng_env" ~/.bashrc; then
    echo "[ -f ~/.benteng_env ] && source ~/.benteng_env" >> ~/.bashrc
fi

success "Bootstrap complete!"
echo ""
echo -e "${BLUE}Environment Summary:${NC}"
echo "  Rust: $(rustc --version | cut -d' ' -f2)"
echo "  Cargo: $(cargo --version | cut -d' ' -f2)"
echo "  Node: $(node -v)"
echo "  WASM targets: installed"
echo "  SoftHSM2: initialized (PIN: 0000)"
echo "  PQClean: built at /tmp/PQClean"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. cd benteng"
echo "2. Run: source ~/.benteng_env"
echo "3. Ready for development!"
