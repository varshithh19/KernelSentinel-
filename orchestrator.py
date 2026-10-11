#!/usr/bin/env python3
# =============================================================
# KernelSentinel — Main Orchestrator
# THE BRAIN: ties all 5 modules together
#
# Flow:
#   1. Start eBPF tracer (background thread)
#   2. Run AI agent (normal or attack)
#   3. Every 10 seconds: score the syscall window
#   4. If risk > threshold: trigger containment
#   5. Send metrics to CloudWatch
#   6. Print live dashboard to terminal
#
# Run:
#   sudo python3 orchestrator.py --mode normal
#   sudo python3 orchestrator.py --mode attack --scenario minja_file_read
#   sudo python3 orchestrator.py --demo   (no agent needed)
# =============================================================

import os
import sys
import json
import time
import signal
import argparse
import threading
import subprocess
from datetime import datetime
from collections import defaultdict
from pathlib import Path

# ── Internal modules ──────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from algorithm.scorer     import (build_baseline_from_dicts, score,
                                  find_optimal_threshold, load_counts,
                                  ALL_SYSCALLS, run_demo)
from containment.containment import Containment
from aws.cloudwatch          import CloudWatchReporter

# ── Colors ────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
CLEAR  = "\033[2J\033[H"   # Clear terminal screen

BASELINE_FILE = "baseline_data/baseline.json"
DEFAULT_THRESHOLD = 0.35
SCORE_INTERVAL    = 10      # Score every N seconds
WINDOW_SECONDS    = 30      # Syscall window size for scoring


class Orchestrator:

    def __init__(self, baseline_file: str, threshold: float,
                 enable_cloudwatch: bool = True,
                 enable_containment: bool = True):

        # Load baseline
        if not Path(baseline_file).exists():
            print(f"⚠️  Baseline not found at {baseline_file}")
            print(f"   Run: sudo ./scripts/run_normal_baseline.sh first")
            print(f"   Or:  python3 algorithm/scorer.py --demo (uses synthetic data)")
            self.baseline = None
        else:
            with open(baseline_file) as f:
                self.baseline = json.load(f)
            print(f"✅ Baseline loaded: {self.baseline['_meta']['num_runs']} runs")

        self.threshold           = threshold
        self.containment         = Containment() if enable_containment else None
        self.cw                  = CloudWatchReporter() if enable_cloudwatch else None
        self.running             = False
        self.current_window      = defaultdict(int)
        self.window_lock         = threading.Lock()
        self.scores_history      = []
        self.agent_pid           = None
        self.tracer_thread       = None
        self.score_thread        = None
        self.contained_pids      = set()

    # ── eBPF Tracer (runs in background thread) ───────────────
    def start_tracer(self, pid: int = None):
        """
        Start the eBPF tracer in a background thread.
        Events come in via the ring buffer callback.
        """
        if os.geteuid() != 0:
            print("⚠️  Not running as root — eBPF disabled")
            print("   Re-run with: sudo python3 orchestrator.py ...")
            return False

        try:
            from bcc import BPF
        except ImportError:
            print("⚠️  BCC not available — using simulated tracer")
            self._start_simulated_tracer()
            return True

        BPF_CODE = r"""
#include <uapi/linux/ptrace.h>
#define SC_EXECVE 1
#define SC_OPENAT 2
#define SC_CONNECT 3
#define SC_READ 4
#define SC_WRITE 5
#define SC_FORK 6
#define SC_SOCKET 7
struct ev_t { u32 pid; u8 sc; char comm[16]; };
BPF_RINGBUF_OUTPUT(evts, 128);
BPF_HASH(wpids, u32, u8, 64);
BPF_ARRAY(wall, u8, 1);
static inline int chk(u32 p) {
    int z=0; u8 *a=wall.lookup(&z);
    if(a&&*a==1) return 1;
    u8 *v=wpids.lookup(&p); return v!=NULL;
}
static inline void em(u8 s) {
    u64 pt=bpf_get_current_pid_tgid(); u32 p=pt>>32;
    if(!chk(p)) return;
    struct ev_t *e=evts.ringbuf_reserve(sizeof(*e));
    if(!e) return;
    e->pid=p; e->sc=s;
    bpf_get_current_comm(&e->comm,16);
    evts.ringbuf_submit(e,0);
}
int te(struct pt_regs *c){em(1);return 0;}
int to(struct pt_regs *c){em(2);return 0;}
int tc(struct pt_regs *c){em(3);return 0;}
int tr(struct pt_regs *c){em(4);return 0;}
int tw(struct pt_regs *c){em(5);return 0;}
int tf(struct pt_regs *c){em(6);return 0;}
int ts(struct pt_regs *c){em(7);return 0;}
"""
        import ctypes

        SCMAP = {1:"execve",2:"openat",3:"connect",
                 4:"read",5:"write",6:"fork",7:"socket"}

        class Ev(ctypes.Structure):
            _fields_ = [("pid",ctypes.c_uint32),("sc",ctypes.c_uint8),
                        ("comm",ctypes.c_char*16)]

        b = BPF(text=BPF_CODE)
        hooks = [("execve","te"),("openat","to"),("connect","tc"),
                 ("read","tr"),("write","tw"),("fork","tf"),("socket","ts")]
        for sc, fn in hooks:
            try:
                b.attach_kprobe(event=b.get_syscall_fnname(sc), fn_name=fn)
            except:
                pass

        if pid:
            b["wpids"][ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
        else:
            b["wall"][ctypes.c_int(0)] = ctypes.c_uint8(1)

        def cb(ctx, data, size):
            ev   = ctypes.cast(data, ctypes.POINTER(Ev)).contents
            name = SCMAP.get(ev.sc, "?")
            with self.window_lock:
                self.current_window[name] += 1

        b["evts"].open_ring_buffer(cb)
        self._bpf = b

        def poll_loop():
            while self.running:
                b.ring_buffer_poll(timeout=100)

        self.tracer_thread = threading.Thread(target=poll_loop, daemon=True)
        self.tracer_thread.start()
        print(f"✅ eBPF tracer running (PID filter: {pid or 'ALL'})")
        return True

    def _start_simulated_tracer(self):
        """
        Fallback: generates synthetic syscall events.
        Used when BCC is not available or not running as root.
        Simulates normal behaviour; attack mode injects anomalies.
        """
        import random

        def sim_loop():
            while self.running:
                # Simulate normal syscall pattern
                with self.window_lock:
                    self.current_window["read"]    += random.randint(5, 15)
                    self.current_window["write"]   += random.randint(2, 8)
                    self.current_window["openat"]  += random.randint(1, 4)
                    self.current_window["connect"] += random.randint(0, 2)
                    self.current_window["socket"]  += random.randint(0, 1)
                    if random.random() < 0.1:
                        self.current_window["execve"] += 1
                time.sleep(1)

        self.tracer_thread = threading.Thread(target=sim_loop, daemon=True)
        self.tracer_thread.start()
        print("✅ Simulated tracer running (no eBPF / root needed)")

    # ── Scoring Loop (runs in background thread) ──────────────
    def start_scoring_loop(self):
        """Every SCORE_INTERVAL seconds: snapshot window, score it, decide."""

        def score_loop():
            while self.running:
                time.sleep(SCORE_INTERVAL)
                if not self.baseline:
                    continue

                # Snapshot and reset window
                with self.window_lock:
                    snapshot = dict(self.current_window)
                    self.current_window.clear()

                if not any(snapshot.values()):
                    continue

                # Run algorithm
                result = score(snapshot, self.baseline, self.threshold)
                risk   = result["risk_score"]
                ts     = datetime.now().strftime("%H:%M:%S")

                self.scores_history.append({
                    "ts": ts, "risk": risk,
                    "is_attack": result.get("is_attack", False),
                    "breakdown": result["breakdown"],
                })

                # Print live status
                self._print_live_status(ts, risk, result)

                # Send to CloudWatch
                if self.cw:
                    self.cw.send_risk_score(
                        risk_score=risk,
                        pid=self.agent_pid or 0,
                        is_attack=result.get("is_attack", False),
                        breakdown=result["breakdown"],
                    )

                # Trigger containment if attack detected
                if result.get("is_attack") and self.agent_pid:
                    if self.agent_pid not in self.contained_pids:
                        self.contained_pids.add(self.agent_pid)
                        if self.containment:
                            c_result = self.containment.contain(
                                pid=self.agent_pid,
                                risk_score=risk,
                                breakdown=result["breakdown"],
                                reason="risk_score_exceeded_threshold",
                            )
                            if self.cw:
                                self.cw.send_alert(
                                    pid=self.agent_pid,
                                    risk_score=risk,
                                    breakdown=result["breakdown"],
                                    containment_result=c_result,
                                )

        self.score_thread = threading.Thread(target=score_loop, daemon=True)
        self.score_thread.start()

    def _print_live_status(self, ts: str, risk: float, result: dict):
        """Print a live risk score status line."""
        bd = result["breakdown"]
        is_att = result.get("is_attack", False)

        if is_att:
            col    = RED
            status = f"{RED}{BOLD}⚠️  ATTACK DETECTED{RESET}"
        elif risk > self.threshold * 0.7:
            col    = YELLOW
            status = f"{YELLOW}⚡ SUSPICIOUS{RESET}"
        else:
            col    = GREEN
            status = f"{GREEN}✅ Normal{RESET}"

        bar_len = int(risk * 40)
        bar     = col + "█" * bar_len + RESET + "░" * (40 - bar_len)

        print(f"\n[{ts}] Risk: {col}{risk:.4f}{RESET} {status}")
        print(f"  [{bar}] {risk:.4f}")
        print(f"  Exec={bd['execution']:.3f}  Net={bd['network']:.3f}  "
              f"File={bd['file']:.3f}  Seq={bd['sequence']:.3f}  "
              f"Threshold={self.threshold}")

    def run(self, agent_pid: int = None, duration: int = 120):
        """Main run loop."""
        self.agent_pid = agent_pid
        self.running   = True

        print(f"\n{BOLD}{'='*55}{RESET}")
        print(f"{BOLD}  KernelSentinel Orchestrator — LIVE{RESET}")
        print(f"{BOLD}{'='*55}{RESET}")
        print(f"  Threshold:     {self.threshold}")
        print(f"  Score interval: every {SCORE_INTERVAL}s")
        print(f"  Agent PID:     {agent_pid or 'monitoring all'}")
        print(f"  Duration:      {duration}s")
        print(f"{'='*55}\n")

        # Start tracer and scoring
        self.start_tracer(pid=agent_pid)
        self.start_scoring_loop()

        # Run for duration
        try:
            end = time.time() + duration
            while self.running and time.time() < end:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{BOLD}Stopping...{RESET}")
        finally:
            self.running = False
            self._print_final_summary()

    def _print_final_summary(self):
        """Print end-of-run summary with all scores."""
        print(f"\n{BOLD}{'='*55}{RESET}")
        print(f"{BOLD}  Run Summary{RESET}")
        print(f"{BOLD}{'='*55}{RESET}")

        normal  = [s for s in self.scores_history if not s["is_attack"]]
        attacks = [s for s in self.scores_history if s["is_attack"]]

        print(f"  Total windows scored: {len(self.scores_history)}")
        print(f"  Normal windows:       {len(normal)}")
        print(f"  Attack detections:    {len(attacks)}")

        if self.scores_history:
            all_risks = [s["risk"] for s in self.scores_history]
            print(f"  Score range:          "
                  f"{min(all_risks):.4f} – {max(all_risks):.4f}")

        if attacks:
            print(f"\n  {RED}⚠️  ATTACKS DETECTED:{RESET}")
            for a in attacks:
                print(f"    [{a['ts']}] risk={a['risk']:.4f}")

        # Save session log
        os.makedirs("logs", exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"logs/session_{ts}.json"
        with open(path, "w") as f:
            json.dump(self.scores_history, f, indent=2)
        print(f"\n  💾 Session log → {path}")


# ── CLI ────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="KernelSentinel Orchestrator")
    parser.add_argument("--mode",      choices=["normal","attack","monitor","demo"],
                        default="monitor")
    parser.add_argument("--scenario",  default="minja_file_read",
                        help="Attack scenario (for --mode attack)")
    parser.add_argument("--pid",       type=int, help="Agent PID to monitor")
    parser.add_argument("--baseline",  default=BASELINE_FILE)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--duration",  type=int,   default=120)
    parser.add_argument("--no-cw",     action="store_true",
                        help="Disable CloudWatch")
    parser.add_argument("--demo",      action="store_true",
                        help="Run algorithm demo (no agent/eBPF needed)")
    args = parser.parse_args()

    # Demo mode — no agent or eBPF needed
    if args.demo or args.mode == "demo":
        run_demo()
        return

    orc = Orchestrator(
        baseline_file=args.baseline,
        threshold=args.threshold,
        enable_cloudwatch=not args.no_cw,
        enable_containment=True,
    )

    if args.mode == "normal":
        # Launch normal agent in background, monitor it
        print("Launching normal agent...")
        proc = subprocess.Popen(
            [sys.executable, "agent/normal_agent.py", "--runs", "5"],
            env={**os.environ, "GEMINI_API_KEY": os.environ.get("GEMINI_API_KEY","")},
        )
        time.sleep(2)
        orc.run(agent_pid=proc.pid, duration=args.duration)
        proc.wait()

    elif args.mode == "attack":
        print(f"Launching attack agent (scenario: {args.scenario})...")
        proc = subprocess.Popen(
            [sys.executable, "agent/attack_agent.py",
             "--scenario", args.scenario],
            env={**os.environ, "GEMINI_API_KEY": os.environ.get("GEMINI_API_KEY","")},
        )
        time.sleep(2)
        orc.run(agent_pid=proc.pid, duration=args.duration)

    elif args.mode == "monitor":
        # Just monitor a given PID
        orc.run(agent_pid=args.pid, duration=args.duration)


if __name__ == "__main__":
    main()
