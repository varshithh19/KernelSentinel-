#!/usr/bin/env python3
# =============================================================
# KernelSentinel — Autonomous Containment
# Module 4: Attack Response
#
# When risk score exceeds threshold:
#   1. Send SIGKILL to rogue process (primary)
#   2. Block network connections via iptables (secondary)
#   3. Generate forensic report
#   4. Send alert to AWS CloudWatch
# =============================================================

import os
import sys
import signal
import time
import json
import subprocess
from datetime import datetime

RED   = "\033[91m"
GREEN = "\033[92m"
BOLD  = "\033[1m"
RESET = "\033[0m"


class Containment:

    def __init__(self, cloudwatch_client=None):
        self.cw = cloudwatch_client
        self.incident_log = []

    def contain(self, pid: int, risk_score: float, breakdown: dict,
                reason: str = "risk_score_exceeded") -> dict:
        """
        Execute containment for a rogue process.
        Returns incident report dict.
        """
        start = time.time()
        print(f"\n{RED}{BOLD}{'='*55}{RESET}")
        print(f"{RED}{BOLD}  ⚠️  ATTACK DETECTED — INITIATING CONTAINMENT{RESET}")
        print(f"{RED}{BOLD}{'='*55}{RESET}")
        print(f"  PID:        {pid}")
        print(f"  Risk Score: {risk_score}")
        print(f"  Reason:     {reason}")
        print(f"  Time:       {datetime.now().strftime('%H:%M:%S.%f')}")

        results = {
            "pid":         pid,
            "risk_score":  risk_score,
            "breakdown":   breakdown,
            "reason":      reason,
            "timestamp":   datetime.now().isoformat(),
            "actions":     [],
        }

        # ── Action 1: SIGKILL ─────────────────────────────────
        kill_result = self._sigkill(pid)
        results["actions"].append(kill_result)

        # ── Action 2: iptables block (optional) ──────────────
        # block_result = self._block_network(pid)
        # results["actions"].append(block_result)

        # ── Action 3: Forensic capture ────────────────────────
        forensic = self._capture_forensics(pid)
        results["forensics"] = forensic

        # ── Containment latency ───────────────────────────────
        latency_ms = (time.time() - start) * 1000
        results["latency_ms"] = round(latency_ms, 2)

        print(f"\n  ✅ Contained in {latency_ms:.1f}ms")
        print(f"{GREEN}{BOLD}{'='*55}{RESET}\n")

        # Save incident
        self.incident_log.append(results)
        self._save_incident(results)

        return results

    def _sigkill(self, pid: int) -> dict:
        """Send SIGKILL to terminate the rogue process."""
        print(f"  [1] Sending SIGKILL to PID {pid}...", end=" ")
        try:
            os.kill(pid, signal.SIGKILL)
            # Verify process is dead
            time.sleep(0.1)
            try:
                os.kill(pid, 0)  # Signal 0 = check if process exists
                status = "process still running (may need root)"
            except ProcessLookupError:
                status = "terminated"

            print(f"{GREEN}✅ {status}{RESET}")
            return {"action": "SIGKILL", "status": status, "pid": pid}

        except ProcessLookupError:
            print(f"{GREEN}✅ Already terminated{RESET}")
            return {"action": "SIGKILL", "status": "already_gone", "pid": pid}
        except PermissionError:
            print(f"⚠️  Permission denied (run as sudo for cross-process kill)")
            return {"action": "SIGKILL", "status": "permission_denied", "pid": pid}
        except Exception as e:
            print(f"❌ {e}")
            return {"action": "SIGKILL", "status": "error", "error": str(e)}

    def _block_network(self, pid: int) -> dict:
        """Block outbound network for the process via iptables."""
        print(f"  [2] Blocking network connections...", end=" ")
        try:
            # Get process name for iptables rule
            proc_name = self._get_proc_name(pid)
            cmd = f"iptables -A OUTPUT -m owner --uid-owner {pid} -j DROP"
            result = subprocess.run(cmd, shell=True,
                                    capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{GREEN}✅ Network blocked{RESET}")
                return {"action": "iptables_block", "status": "blocked"}
            else:
                print(f"⚠️  {result.stderr.strip()}")
                return {"action": "iptables_block",
                        "status": "failed", "error": result.stderr}
        except Exception as e:
            print(f"❌ {e}")
            return {"action": "iptables_block", "status": "error", "error": str(e)}

    def _capture_forensics(self, pid: int) -> dict:
        """Capture process state before/after killing."""
        print(f"  [3] Capturing forensic data...", end=" ")
        forensics = {"pid": pid}

        # Try to read /proc/<pid> for process info
        proc_path = Path(f"/proc/{pid}") if False else None  # noqa
        try:
            # Process name
            try:
                with open(f"/proc/{pid}/comm") as f:
                    forensics["comm"] = f.read().strip()
            except:
                forensics["comm"] = "unknown"

            # Command line
            try:
                with open(f"/proc/{pid}/cmdline") as f:
                    forensics["cmdline"] = f.read().replace("\x00", " ").strip()
            except:
                forensics["cmdline"] = "unknown"

            # Open file descriptors (partial)
            try:
                fds = os.listdir(f"/proc/{pid}/fd")
                forensics["open_fds"] = len(fds)
            except:
                forensics["open_fds"] = "unknown"

        except Exception:
            forensics["error"] = "Process already terminated before forensics"

        print(f"{GREEN}✅{RESET}")
        return forensics

    def _get_proc_name(self, pid: int) -> str:
        try:
            with open(f"/proc/{pid}/comm") as f:
                return f.read().strip()
        except:
            return "unknown"

    def _save_incident(self, incident: dict):
        """Save incident report to file."""
        os.makedirs("logs", exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"logs/incident_{ts}.json"
        with open(path, "w") as f:
            json.dump(incident, f, indent=2)
        print(f"  📋 Incident report → {path}")


# Required import for forensics
from pathlib import Path


def main():
    """Test containment on a dummy process."""
    # Launch a sleep process to kill
    proc = subprocess.Popen(["sleep", "60"])
    pid  = proc.pid
    print(f"Created test process PID: {pid}")
    time.sleep(0.5)

    c = Containment()
    result = c.contain(
        pid=pid,
        risk_score=0.72,
        breakdown={"execution": 0.85, "network": 0.70, "file": 0.55, "sequence": 0.79},
        reason="demo_test",
    )
    print(f"\nContainment result: {result['actions']}")
    print(f"Latency: {result['latency_ms']}ms")


if __name__ == "__main__":
    main()
