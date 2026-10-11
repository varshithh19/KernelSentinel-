# KernelSentinel: B.Tech Project Review & Panel Demonstration Script

A 5-to-10 minute presentation sequence designed for academic and technical defense panels.

---

## 1. Demonstration Sequence

### Step 1: Architecture Overview (1 minute)
- **Action:** Open Dashboard at `http://localhost:8000`. Show high-level system tiles.
- **Talking Points:**
  - "KernelSentinel provides dual-layer runtime protection for AI agents in clinical settings."
  - "Combines server-side RBAC authorization with Linux kernel-level eBPF telemetry to protect patient privacy against direct and indirect prompt injection."

### Step 2: Normal Authorized Medical Query (Scenario A - 1 minute)
- **Action:** Click **"Scenario A (Normal Query)"**.
- **Observation:**
  - Dr. Smith queries Patient P101.
  - Server confirms authorization; history record retrieved.
  - Risk score: $0.0/100$ (NORMAL). Zero false alarms.

### Step 3: Direct Prompt Injection Attack (Scenario B - 1 minute)
- **Action:** Click **"Scenario B (Direct Injection)"**.
- **Observation:**
  - Attacker asks agent to ignore previous instructions and reveal unauthorized Patient P102.
  - Prompt classifier flags instruction override clause.
  - Server-side authorization denies the tool call.
  - Data disclosure blocked! Risk score jumps to $44.0/100$ (SUSPICIOUS).

### Step 4: MINJA Indirect Prompt Injection (Scenario C - 1.5 minutes)
- **Action:** Click **"Scenario C (MINJA Indirect)"**.
- **Observation:**
  - Dr. Smith retrieves an external clinic transfer note for P103 containing an embedded malicious instruction override targeting P102.
  - Audit log captures `INDIRECT_PROMPT_INJECTION_LOADED`.
  - When the agent attempts the follow-up tool call, server authorization stops it cold.
  - Risk score: $40.0/100$ (SUSPICIOUS).

### Step 5: Kernel Telemetry & Correlation (Scenario D - 1.5 minutes)
- **Action:** Click **"Scenario D (Process Anomaly)"**.
- **Observation:**
  - Workload triggers kernel-level file open (`/etc/shadow`) and process execution (`bash`).
  - Correlator matches kernel events to the Agent PID using start-time timestamps.
  - Composite risk score rises to $35.0/100$.

### Step 6: Live RAM & Process Monitoring (1 minute)
- **Action:** Point to the Live Metrics tiles.
- **Observation:**
  - Shows real Agent PID, live RSS memory (~42.3 MB), and CPU %.
  - Contrast host VMware memory allocation vs. granular guest process RSS.

### Step 7: Safe Containment & Recovery (1 minute)
- **Action:** Click **"Suspend Agent Process"** / **"Resume Agent Process"**.
- **Observation:**
  - Shows protection rules (safeguarding PID 1 and server PID).
  - Demonstrates reversible SIGSTOP/SIGCONT process pause.

### Step 8: Empirical Benchmark Evaluation (1 minute)
- **Action:** Show `experiments/reports/evaluation_report.md`.
- **Observation:**
  - 100% Detection Rate, 0% False Positive Rate across 25 benchmark runs.
  - Low average latency (~37.7 ms).

---

## 2. Key Defense Questions & Answers for the Panel

**Q1: Why is prompt filtering alone insufficient?**  
*A:* Natural language filtering can be bypassed by jailbreaks, character encoding, or indirect injection hidden in retrieved documents. Authorization must be enforced server-side on tool dispatch, backed by kernel monitoring.

**Q2: What is KernelSentinel's core novel contribution?**  
*A:* A request-aware correlation engine that explicitly links prompt IDs, agent request IDs, and agent PIDs with kernel-level syscall events and safe reversible containment, evaluated with empirical metrics.

**Q3: Does eBPF slow down the agent?**  
*A:* No. eBPF executes within in-kernel tracepoints with nanosecond-scale overhead. Our benchmark demonstrates an average end-to-end latency of only ~37.7 ms.
