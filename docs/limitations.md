# KernelSentinel Limitations & Scope Boundaries

Honest documentation of technical boundaries and engineering constraints:

---

## 1. Operating System & Kernel Boundaries
- **eBPF Platform Dependency:** Live eBPF kernel probes require a Linux kernel ($\ge 5.8$) with BTF support (`CONFIG_DEBUG_INFO_BTF=y`) and root privileges or `CAP_BPF` / `CAP_PERFMON`.
- **Non-Linux Demonstration Mode:** On Windows or platforms lacking eBPF support, KernelSentinel operates in test/demonstration mode with live process metrics and synthetic event injection, clearly indicated on the dashboard banner.
- **Syscall Semantics:** Syscall telemetry confirms execution of an OS action (`execve`, `openat`, `connect`), but does not prove intent on its own. Malicious intent is determined exclusively through correlation with application-layer requests.

---

## 2. Language Model & Prompt Filtering Boundaries
- **Prompt Injection Defense-in-Depth:** Rule-based prompt classifiers cannot guarantee 100% detection against novel, highly obfuscated, or adversarial token distributions.
- **Core Security Invariant:** KernelSentinel treats prompt classification as an informative telemetry signal rather than an access-control barrier. Access authorization is strictly enforced server-side before database query dispatch.
- **Model API vs Local Execution:** Remote API inference measures local agent process memory, not the cloud inference server memory.

---

## 3. Threat Model Boundaries
- **Synthetic Data Exclusively:** The system operates strictly on fictional synthetic records (P101-P104). Real Protected Health Information (PHI) is never used.
- **Host Compromise:** If an attacker achieves kernel root execution outside the monitored process scope, user-space detection engines may be bypassed.
