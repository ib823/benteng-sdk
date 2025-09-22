#!/usr/bin/env bash
set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "==================================="
echo "Benteng Environment Assessment v0.1"
echo "==================================="

# Function to check command availability
check_cmd() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1: $(command -v $1)"
        if [ "$2" = "version" ]; then
            $1 --version 2>/dev/null | head -1 || echo "Version check failed"
        fi
        return 0
    else
        echo -e "${RED}✗${NC} $1: NOT FOUND"
        return 1
    fi
}

# Function to check Rust components
check_rust_component() {
    if rustup component list --installed | grep -q "$1"; then
        echo -e "${GREEN}✓${NC} Rust component: $1"
        return 0
    else
        echo -e "${RED}✗${NC} Rust component $1: NOT INSTALLED"
        return 1
    fi
}

# System Information
echo -e "\n${YELLOW}System Information:${NC}"
echo "OS: $(uname -s) $(uname -r)"
echo "Architecture: $(uname -m)"
echo "CPU cores: $(nproc)"
echo "Memory: $(free -h | awk '/^Mem:/ {print $2}')"
echo "Disk: $(df -h / | awk 'NR==2 {print $4 " available"}')"

# Core Development Tools
echo -e "\n${YELLOW}Core Development Tools:${NC}"
check_cmd "git" "version"
check_cmd "make" "version"
check_cmd "cmake" "version"
check_cmd "gcc" "version"
check_cmd "clang" "version"
check_cmd "pkg-config" "version"

# Rust Toolchain
echo -e "\n${YELLOW}Rust Toolchain:${NC}"
if check_cmd "rustc" "version"; then
    check_cmd "cargo" "version"
    check_rust_component "rustfmt"
    check_rust_component "clippy"
    echo "Installed targets:"
    rustup target list --installed | sed 's/^/  /'
fi

# Rust Tools
echo -e "\n${YELLOW}Rust Development Tools:${NC}"
check_cmd "cargo-nextest" ""
check_cmd "cargo-audit" ""
check_cmd "cargo-deny" ""
check_cmd "cargo-tarpaulin" ""
check_cmd "cargo-fuzz" ""
check_cmd "wasm-pack" ""

# WebAssembly
echo -e "\n${YELLOW}WebAssembly Support:${NC}"
check_cmd "wasm-pack" "version"
rustup target list --installed | grep -q "wasm32-unknown-unknown" && \
    echo -e "${GREEN}✓${NC} wasm32-unknown-unknown target" || \
    echo -e "${RED}✗${NC} wasm32-unknown-unknown target"
rustup target list --installed | grep -q "wasm32-wasi" && \
    echo -e "${GREEN}✓${NC} wasm32-wasi target" || \
    echo -e "${RED}✗${NC} wasm32-wasi target"

# Node.js/npm (for web SDK and admin console)
echo -e "\n${YELLOW}Node.js/npm:${NC}"
check_cmd "node" "version"
check_cmd "npm" "version"

# Python (for tooling)
echo -e "\n${YELLOW}Python:${NC}"
check_cmd "python3" "version"
check_cmd "pip3" "version"

# Security/Crypto Tools
echo -e "\n${YELLOW}Security/Crypto Tools:${NC}"
check_cmd "openssl" "version"
check_cmd "softhsm2-util" "version"

# Formal Verification Tools
echo -e "\n${YELLOW}Formal Verification:${NC}"
check_cmd "z3" "version"
check_cmd "fstar.exe" "" || check_cmd "fstar" ""
check_cmd "krml" ""

# Container/K8s Tools
echo -e "\n${YELLOW}Container/K8s Tools:${NC}"
check_cmd "docker" "version"
check_cmd "kubectl" "version"
check_cmd "helm" "version"

# eBPF/Observability Tools
echo -e "\n${YELLOW}eBPF/Observability:${NC}"
check_cmd "bpftool" "version"
check_cmd "tetragon" "version"

# Check critical libraries
echo -e "\n${YELLOW}Critical Libraries:${NC}"
ldconfig -p 2>/dev/null | grep -q libssl && \
    echo -e "${GREEN}✓${NC} OpenSSL library" || \
    echo -e "${RED}✗${NC} OpenSSL library"
ldconfig -p 2>/dev/null | grep -q libgmp && \
    echo -e "${GREEN}✓${NC} GMP library" || \
    echo -e "${RED}✗${NC} GMP library"

# Check GitHub Actions environment variables
echo -e "\n${YELLOW}GitHub Environment:${NC}"
[ -n "${GITHUB_WORKSPACE:-}" ] && echo "GitHub Workspace: $GITHUB_WORKSPACE" || echo "Not in GitHub Actions"
[ -n "${CODESPACES:-}" ] && echo -e "${GREEN}✓${NC} Running in Codespace" || echo "Not in Codespace"

# Summary
echo -e "\n${YELLOW}==================================${NC}"
echo "Assessment complete. Check RED items above for missing prerequisites."
echo -e "${YELLOW}==================================${NC}"
