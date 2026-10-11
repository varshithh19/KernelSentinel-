# KernelSentinel: Windows Host Demonstration Guide

This guide describes how to run and demonstrate KernelSentinel on a Windows host and explains process metrics behavior across virtualization boundaries.

---

## 1. Running Locally on Windows

KernelSentinel is designed to run its application layer, database, prompt security, behavioral detection engine, attack laboratory, and live dashboard directly on Windows:

```powershell
# In PowerShell:
cd C:\Users\varshith2\.gemini\antigravity\scratch\KernelSentinel

# Install Python dependencies
pip install -r medical-agent/requirements.txt

# Start the dashboard and medical agent
python -m uvicorn dashboard.app.server:dashboard_app --host 127.0.0.1 --port 8000 --reload
```

Open **http://127.0.0.1:8000** in your browser.

---

## 2. Windows Task Manager vs. Process Metrics Inside VM

### The Virtualization Boundary Explained:
1. **Windows Task Manager:**
   - When running Ubuntu inside VMware Workstation or VMware Player, Windows Task Manager displays the overall resource footprint of `vmware-vmx.exe`.
   - Windows Task Manager allocates a contiguous block of host RAM (e.g., 4 GB) to VMware.
   - **Important Engineering Fact:** Windows Task Manager cannot peer inside the guest Linux kernel to view an individual Linux process PID or its specific RSS memory.

2. **Accurate Process Measurement (KernelSentinel Dashboard):**
   - KernelSentinel uses `psutil` inside the guest OS or local process environment to inspect the specific AI Agent process:
     - `proc.memory_info().rss`: Exact Resident Set Size (RSS) memory in Bytes and MB.
     - `proc.cpu_percent()`: Live CPU utilization of the specific agent process.
     - `proc.create_time()`: Exact process creation timestamp to protect against PID reuse.

3. **Demonstrating on Windows:**
   - In the KernelSentinel dashboard, observe the "Live RSS Memory" tile showing exact MB and Bytes (e.g., ~42.3 MB).
   - Open Windows Task Manager -> Processes -> look for `Python` with matching PID.
   - You will see the matching memory usage in Windows Task Manager for the local process, proving real process telemetry!
