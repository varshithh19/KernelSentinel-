#!/usr/bin/env bash
set -e

echo "=== KernelSentinel Ubuntu Setup ==="

sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
                    linux-headers-$(uname -r) pkg-config python3-pip python3-venv git

if ! command -v rustc &> /dev/null; then
    echo "Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

echo "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r medical-agent/requirements.txt

echo "Building C user-space collector..."
cd ebpf/c-collector
make
cd ../..

echo "Setup complete. Run ./scripts/start.sh to launch KernelSentinel."
