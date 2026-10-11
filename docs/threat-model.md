# KernelSentinel Threat Model

## 1. System Scope & Boundaries
KernelSentinel secures an AI-assisted hospital clinical environment where doctors query synthetic patient records.
The AI agent operates under least-privilege principles with strictly constrained tool execution.

## 2. Threat Actors & Personas
1. **Malicious Clinical User / Attacker Identity (`test1`):**
   - Submits direct prompt injections attempting to jailbreak agent instructions and exfiltrate records of patients they are not authorized to access.
2. **Untrusted External Content Provider:**
   - Embeds adversarial indirect prompt injection payloads inside medical notes, transfer letters, or lab PDFs (e.g. MINJA attack methodology).
3. **Compromised Tool / Subprocess:**
   - Attempts unexpected filesystem traversal or command execution from within the host environment.

## 3. Threat Classification (STRIDE)

| Threat Category | Attack Vector | Security Mechanism |
| :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates authorized doctor identity | Session tokens and server-side user lookup. |
| **Tampering** | Indirect prompt injection in synthetic notes altering agent instructions | Untrusted content tagging and server-side RBAC enforcement. |
| **Repudiation** | Denying an unauthorized exfiltration attempt | Immutable audit logging linking `request_id`, `prompt_id`, and `pid`. |
| **Information Disclosure** | LLM persuaded to output patient P102 records to Doctor D1 | Server-side authorization check before executing SQL queries. |
| **Denial of Service** | Process resource exhaustion / CPU spinning | Bounded timeouts and behavioral resource monitoring. |
| **Elevation of Privilege**| Agent prompted to execute OS shell commands | Absence of arbitrary shell execution tools; eBPF `execve` detection. |

## 4. Trust Assumptions & Boundaries
- The LLM output is inherently untrusted. Natural language cannot grant permissions.
- The host kernel and eBPF runtime are trusted.
- Synthetic patient records only are used. No protected health information (PHI) is processed.
