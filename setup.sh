#!/bin/bash
# =============================================================
# KernelSentinel — One-Command Environment Setup
# Run as: sudo ./setup.sh
# EC2: Amazon Linux 2023, kernel 6.1+
# =============================================================

set -e  # Exit on any error

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   KernelSentinel — Environment Setup    ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Step 1: System update ──────────────────────────────────────
echo "[1/8] Updating system..."
dnf update -y -q

# ── Step 2: Kernel headers ─────────────────────────────────────
echo "[2/8] Installing kernel headers..."
dnf install -y -q kernel-devel kernel-headers

# ── Step 3: Clang + LLVM (for eBPF compilation) ───────────────
echo "[3/8] Installing clang and llvm..."
dnf install -y -q clang llvm

# ── Step 4: BCC tools (Python eBPF library) ───────────────────
echo "[4/8] Installing BCC tools..."
dnf install -y -q bcc bcc-tools python3-bcc

# ── Step 5: Python packages ────────────────────────────────────
echo "[5/8] Installing Python packages..."
dnf install -y -q python3-pip python3-devel
pip3 install -q \
    google-generativeai \
    boto3 \
    matplotlib \
    numpy \
    psutil \
    requests \
    python-dotenv


# ── Step 6: libbpf + bpftool ──────────────────────────────────
echo "[6/8] Installing libbpf..."
dnf install -y -q libbpf libbpf-devel bpftool 2>/dev/null || true

# ── Step 7: Mount BPF filesystem ──────────────────────────────
echo "[7/8] Mounting BPF filesystem..."
if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpf /sys/fs/bpf
fi

# ── Step 8: Create log directories ────────────────────────────
echo "[8/8] Creating directories..."
mkdir -p logs baseline_data

# ── Verify installation ────────────────────────────────────────
echo ""
echo "── Verification ──────────────────────────────────"
echo -n "  Kernel:  "; uname -r
echo -n "  Python:  "; python3 --version
echo -n "  Clang:   "; clang --version | head -1
echo -n "  BCC:     "; python3 -c "import bcc; print('OK')" 2>/dev/null || echo "FAILED"
echo -n "  Gemini:  "; python3 -c "import google.generativeai; print('OK')" 2>/dev/null || echo "FAILED"
echo -n "  boto3:   "; python3 -c "import boto3; print('OK')" 2>/dev/null || echo "FAILED"
echo -n "  BPF FS:  "; ls /sys/fs/bpf > /dev/null && echo "OK" || echo "FAILED"
echo ""

echo "╔══════════════════════════════════════════╗"
echo "║   Setup complete!                        ║"
echo "║                                          ║"
echo "║   Next: Set your Gemini API key:         ║"
echo "║   export GEMINI_API_KEY='your-key-here'  ║"
echo "║                                          ║"
echo "║   Then: sudo python3 ebpf/tracer.py      ║"
echo "╚══════════════════════════════════════════╝"
