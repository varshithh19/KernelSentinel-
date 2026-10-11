# KernelSentinel Architecture Specification

## 1. High-Level Architecture Overview

KernelSentinel integrates dual-layer security protection for AI agents operating on sensitive medical records:
1. **Application-Layer Authorization & Defense-in-Depth:**
   - Server-side Role-Based Access Control (RBAC) enforced on parameterized queries.
   - Constrained agent tool invocation interface.
   - Rule-based prompt injection classifier.
   - Trace identifiers: `request_id`, `prompt_id`, `tool_call_id`.
2. **Kernel-Layer Behavioral Telemetry & Containment:**
   - Rust eBPF monitor capturing kernel tracepoints (`sys_enter_execve`, `sys_enter_openat`, `sys_enter_connect`).
   - C User-space event collector interfacing via RingBuffers and dispatching structured JSON over IPC.
   - Request-aware Behavioral Detection Engine correlating process PID, timestamps, and kernel anomalies.
   - Safe, reversible process containment (SIGSTOP/SIGCONT with PID reuse safety).

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

## 2. Component Directory Layout

- `medical-agent/`: Python FastAPI service implementing synthetic patient records, RBAC, model adapter, and prompt classification.
- `ebpf/rust-monitor/`: Rust eBPF program capturing `execve`, `openat`, and `connect` events with zero kernel memory exposure.
- `ebpf/c-collector/`: C99 user-space ring buffer collector and IPC forwarder.
- `detector/`: Feature extractor, empirical baseline tracker, explainable risk scorer, and PID-reuse-safe event correlator.
- `dashboard/`: Real-time monitoring console displaying live agent process RSS, CPU, and security incidents.
- `attack-lab/`: Controlled test harness executing benchmark attack scenarios A through E.
- `experiments/`: Benchmark runner producing reproducible CSV/JSON matrices and evaluation reports.
