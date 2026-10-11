# KernelSentinel Behavioral Detection Algorithm

## 1. Mathematical Formulation

KernelSentinel designs a transparent, explainable behavioral risk-scoring algorithm combining application-level security states with kernel-level execution indicators.

The Composite Behavioral Risk Score $R \in [0, 100]$ is computed as:

$$R = 100 \times \frac{\sum_{i=1}^{N} w_i \cdot f_i}{\sum_{i=1}^{N} w_i}$$

Where:
- $f_i \in [0.0, 1.0]$ is the normalized feature value.
- $w_i > 0$ is the empirical feature weight.

---

## 2. Feature Definitions & Weight Justifications

| Feature ($f_i$) | Weight ($w_i$) | Normalization Logic | Security Justification |
| :--- | :---: | :--- | :--- |
| **`auth_denial`** | **25.0** | $1.0$ if tool invocation denied by RBAC, else $0.0$. | Direct indicator of unauthorized data access attempt. |
| **`prompt_suspicion`** | **20.0** | Normalized classifier confidence in $[0.0, 1.0]$. | Measures presence of adversarial prompt phrasing. |
| **`unexpected_file`** | **20.0** | $1.0$ if sensitive path touched; $0.3$ if non-DB file. | Detects unauthorized filesystem traversal attempts. |
| **`unexpected_exec`** | **15.0** | $1.0$ if shell/interpreter spawned; $0.5$ if other child. | Medical agent should never spawn external shells. |
| **`indirect_injection`**| **15.0** | $1.0$ if retrieved note contained untrusted override. | Tracks exposure to adversarial external content. |
| **`unexpected_net`** | **5.0** | $1.0$ if outbound socket connection initiated. | Medical queries should not establish external sockets. |
| **Total Weight Sum** | **100.0** | Clamped to $[0.0, 100.0]$. | Normalized percentage scale. |

---

## 3. Thresholds & Response Matrix

| Risk Score Range | Severity Category | Automated Response Action |
| :---: | :---: | :--- |
| **$0.0 \le R < 30.0$** | **NORMAL** | Allow execution; record telemetry baseline. |
| **$30.0 \le R < 60.0$**| **SUSPICIOUS** | Log audit alert; monitor process; deny tool call if unauthorized. |
| **$60.0 \le R < 80.0$**| **HIGH_RISK** | Deny access; raise high-severity security alert. |
| **$80.0 \le R \le 100.0$**| **CRITICAL** | Automated process containment (safe reversible suspension). |

---

## 4. Request-to-Kernel Correlation Pipeline

Syscalls do not inherently contain prompt IDs. KernelSentinel correlates them using an observable tuple:

$$\mathcal{C} = \langle \text{Prompt ID}, \text{Request ID}, \text{Agent PID}, \text{Process Start Time}, \text{Timestamp Window} \rangle$$

1. **Agent PID & Start Time Verification:** Prevents PID-reuse ambiguity.
2. **Temporal Window Binding:** Kernel events occurring within $\Delta t = 2000 \text{ ms}$ of the agent request start are evaluated.
3. **Provenance Separation:** Syscalls provide proof of an OS operation, not inherent malice. Malicious intent is determined by correlating the syscall with an unauthorized application request.
