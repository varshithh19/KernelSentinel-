# KernelSentinel: VMware Ubuntu Setup Guide

Target Platform: VMware Workstation / Player running Ubuntu 22.04 / 24.04 LTS (4 GB RAM, 2 vCPUs).

---

## 1. System Prerequisites

Install the required kernel headers, eBPF libraries, Rust toolchain, and build tools:

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
                    linux-headers-$(uname -r) pkg-config python3-pip python3-venv git
```

Install Rust and Cargo:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
```

---

## 2. Clone and Configure

```bash
git clone https://github.com/your-username/KernelSentinel.git
cd KernelSentinel

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r medical-agent/requirements.txt

# Configure environment variables
cp .env.example .env
```

---

## 3. Build Components

### Build Rust eBPF Monitor:
```bash
cd ebpf/rust-monitor
cargo build --release
cd ../..
```

### Build C User-Space Collector:
```bash
cd ebpf/c-collector
make
cd ../..
```

---

## 4. Run KernelSentinel

Start the complete stack (requires `sudo` for eBPF attachment):
```bash
sudo ./scripts/start.sh
```

Or run components individually:
1. **Medical Agent & Dashboard:**
   ```bash
   python -m uvicorn dashboard.app.server:dashboard_app --host 0.0.0.0 --port 8000
   ```
2. **C Event Collector (privileged):**
   ```bash
   sudo ./ebpf/c-collector/kernelsentinel_collector --port 9090
   ```

Access the real-time Security Operations Dashboard at:  
👉 **http://localhost:8000**
