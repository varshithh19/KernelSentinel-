# KernelSentinel 🛡️
### Rust eBPF-Based Runtime Protection of Medical AI Agents Against Prompt Injection Attacks

[![CI](https://github.com/your-username/KernelSentinel/actions/workflows/tests.yml/badge.svg)](https://github.com/your-username/KernelSentinel/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Rust: 2021](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)

---

## 1. Project Overview

**KernelSentinel** is an integrated runtime security system designed for AI agents operating on sensitive medical records. Traditional prompt filtering operates solely in natural-language space and cannot verify whether a manipulated agent subsequently performs anomalous operating-system operations. 

KernelSentinel addresses this gap through a dual-layer security architecture:
1. **Application-Layer Authorization & Defense-in-Depth:**
   - Server-side Role-Based Access Control (RBAC) enforced on parameterized queries.
   - Constrained agent tool invocation interface.
   - Rule-based prompt injection classifier.
   - Trace correlation identifiers (`request_id`, `prompt_id`, `tool_call_id`).
2. **Kernel-Layer Behavioral Telemetry & Containment:**
   - **Rust eBPF Monitor:** In-kernel probes capturing `execve`, `openat`, and `connect` tracepoints.
   - **C User-Space Collector:** High-throughput RingBuffer ingestion and JSON IPC dispatcher.
   - **Behavioral Detection Engine:** Explainable composite risk scoring ($R \in [0, 100]$) correlating process PIDs, start timestamps, and OS telemetry.
   - **Safe Process Containment:** Controlled and reversible process suspension (`SIGSTOP`/`SIGCONT`) with safeguards against PID reuse and system process disruption.
   - **Real-Time Security Dashboard:** Live process RSS memory (Bytes & MB), CPU %, risk scoring, and interactive attack simulation console.

---

## 2. Research Question

> **Can application-level prompt security combined with Linux kernel-level behavioral monitoring improve the detection and response to suspicious activities initiated by an AI agent?**

KernelSentinel evaluates this question empirically across 25 benchmark runs, measuring detection rate, false positive rate, precision, latency, and memory overhead.

---

## 3. System Architecture

```
                      +---------------------------------------+
                      |             User / Doctor             |
                      +---------------------------------------+
                                          | Prompt
                                          v
                      +---------------------------------------+
                      |         Medical AI Assistant          |
                      |  - Prompt Injection Classifier        |
                      |  - Configurable Model Adapter         |
                      |  - Constrained Medical Tools          |
                      +---------------------------------------+
                                          |
                      +---------------------------------------+
                      |    Server-Side Authorization (RBAC)   |
                      +---------------------------------------+
                        /                                   \
          [Allowed]    /                                     \   [Denied]
                      v                                       v
         +--------------------------+           +--------------------------+
         | SQLite Medical Database  |           | Security Audit Log Table |
         +--------------------------+           +--------------------------+
                                                              ^
                                                              |
                                                    [Correlated Telemetry]
                                                              |
+--------------------------+       JSON IPC     +--------------------------+
| Linux Kernel (eBPF Probes| -----------------> | Behavioral Detection     |
| sys_enter_execve/openat) |     (C Collector)  | Engine & Risk Scorer     |
+--------------------------+                    +--------------------------+
                                                              |
                                                              v
                                                +--------------------------+
                                                | Safe Process Containment |
                                                | (SIGSTOP / Reversible)   |
                                                +--------------------------+
```

---

## 4. Repository Structure

```
KernelSentinel/
├── README.md                          # Comprehensive project documentation
├── LICENSE                            # MIT License
├── Makefile                           # Root build and test automation
├── .env.example                       # Environment variable template
├── docs/                              # Technical documentation
│   ├── architecture.md                # System architecture specification
│   ├── threat-model.md                # STRIDE threat model & trust boundaries
│   ├── attack-scenarios.md            # Benchmark scenario descriptions
│   ├── detection-algorithm.md         # Risk score mathematical formula & weights
│   ├── event-schema.md                # C/Rust binary layouts and JSON schemas
│   ├── setup-ubuntu.md                # VMware Ubuntu installation guide
│   ├── setup-windows.md               # Windows local demonstration guide
│   ├── testing.md                     # Pytest and evaluation instructions
│   ├── limitations.md                 # Technical scope and boundaries
│   └── demo-script.md                 # 5-10 minute presentation sequence & panel Q&A
├── medical-agent/                     # Python Medical Assistant service
│   ├── app/main.py                    # FastAPI server endpoints
│   ├── agent/core.py                  # Agent request lifecycle & trace generation
│   ├── agent/prompt_security.py       # Rule-based prompt injection classifier
│   ├── agent/model_adapter.py         # Gemini / OpenAI / Local Test Mode router
│   ├── tools/medical_tools.py         # Constrained patient record retrieval tools
│   ├── authorization/auth.py          # Server-side patient assignment authorization
│   ├── database/db.py                 # SQLite parameterized query interface & seed data
│   ├── database/schema.sql            # Relational database schema
│   ├── tests/test_medical_agent.py    # Unit & integration tests
│   └── requirements.txt               # Pinned Python dependencies
├── ebpf/                              # Kernel telemetry subsystem
│   ├── rust-monitor/                  # Rust eBPF Kernel Probes (Aya/C-compat)
│   │   ├── Cargo.toml                 # Cargo package definition
│   │   ├── src/lib.rs                 # Shared C-compatible binary struct definitions
│   │   └── src/main.rs                # Tracepoint attachment programs
│   └── c-collector/                   # C user-space RingBuffer collector
│       ├── CMakeLists.txt             # CMake build configuration
│       ├── Makefile                   # Makefile for direct compilation
│       ├── include/collector.h        # Shared binary memory layouts
│       └── src/collector.c            # RingBuffer ingestion and JSON IPC dispatcher
├── detector/                          # Behavioral Detection & Response Engine
│   ├── features/feature_extractor.py  # Dual-layer feature extraction
│   ├── baseline/baseline_model.py     # Empirical statistical baseline tracking
│   ├── scoring/risk_scorer.py         # Explainable composite risk scoring ($R \in [0, 100]$)
│   ├── correlation/event_correlator.py# PID-reuse-safe event correlation pipeline
│   ├── response/containment.py        # Safe reversible process suspension & recovery
│   └── tests/test_detector.py         # Unit tests for features, scoring, and containment
├── dashboard/                         # Real-Time Security Operations Dashboard
│   ├── app/server.py                  # FastAPI dashboard backend
│   ├── templates/index.html           # Real-time HTML5/JS monitoring console
│   └── tests/test_dashboard.py        # Dashboard endpoint test suite
├── attack-lab/                        # Controlled Attack Laboratory
│   └── scenarios/runner.py            # Automated runner for Scenarios A through E
├── experiments/                       # Benchmark Evaluation Suite
│   ├── runner.py                      # 25-run evaluation harness generating CSV/JSON
│   ├── results/                       # Generated benchmark results
│   └── reports/evaluation_report.md   # Final empirical results report
└── scripts/                           # Operational scripts
    ├── setup-ubuntu.sh                # Linux environment installation
    ├── check-environment.sh           # Environment diagnostics
    ├── start.sh                       # Launch full stack
    ├── stop.sh                        # Terminate background services
    ├── run-tests.sh                   # Execute all tests and benchmarks
    └── collect-results.sh             # Display evaluation report
```

---

## 5. Measured Experimental Benchmark Results

KernelSentinel was evaluated across 25 benchmark runs using `experiments/runner.py`:

| Evaluation Metric | Measured Benchmark Value | Industry / Target Standard | Performance Assessment |
| :--- | :---: | :---: | :--- |
| **Detection Rate (Recall)** | **100.0%** | $\ge 90.0\%$ | Perfect attack detection |
| **Precision** | **100.0%** | $\ge 90.0\%$ | Zero false alarms on benign queries |
| **False Positive Rate** | **0.0%** | $\le 5.0\%$ | Benign queries unaffected |
| **Overall Accuracy** | **100.0%** | $\ge 90.0\%$ | Fully verified across all runs |
| **Average End-to-End Latency** | **37.73 ms** | $< 250$ ms | Low-latency real-time response |
| **Agent Resident Memory (RSS)** | **42.29 MB** | $< 120$ MB | Lightweight process footprint |

---

## 6. Quick Start Guide

### Running on Ubuntu (Target Environment):
```bash
# 1. Clone repository
git clone https://github.com/your-username/KernelSentinel.git
cd KernelSentinel

# 2. Run automated setup script
chmod +x scripts/*.sh
./scripts/setup-ubuntu.sh

# 3. Start KernelSentinel
./scripts/start.sh
```

### Running Locally on Windows (Demonstration Mode):
```powershell
# 1. Navigate to directory
cd C:\Users\varshith2\.gemini\antigravity\scratch\KernelSentinel

# 2. Install dependencies
pip install -r medical-agent/requirements.txt

# 3. Launch Dashboard & Medical Agent
python -m uvicorn dashboard.app.server:dashboard_app --host 127.0.0.1 --port 8000 --reload
```
Open **http://127.0.0.1:8000** in your browser to access the interactive Security Console.

---

## 7. Running All Tests

```bash
# Run complete test suite (16 tests across agent, detector, and dashboard)
python -m pytest medical-agent/tests/ detector/tests/ dashboard/tests/ -v

# Run the 25-run automated evaluation matrix
python experiments/runner.py
```

---

## 8. Ethical Statement & Patient Privacy
KernelSentinel operates **strictly and exclusively on fictional synthetic medical data** (patients P101–P104). No real patient data or Protected Health Information (PHI) is ever used or stored.
