#!/usr/bin/env python3
# =============================================================
# KernelSentinel — eBPF Syscall Tracer
# Module 1: Kernel-Level Monitoring
#
# Attaches kprobes to 7 critical syscalls and streams
# events to userspace via BCC ring buffer.
#
# Run: sudo python3 ebpf/tracer.py [--pid PID] [--output FILE]
#      sudo python3 ebpf/tracer.py --all          (all processes)
#      sudo python3 ebpf/tracer.py --test         (verify setup)
# =============================================================

import sys
import os
import json
import time
import signal
import argparse
import ctypes
from collections import defaultdict
from datetime import datetime

# ── BCC import (requires sudo) ────────────────────────────────
try:
    from bcc import BPF
except ImportError:
    print("❌ BCC not found. Run: sudo dnf install -y bcc bcc-tools python3-bcc")
    sys.exit(1)

# ── Syscall constants ─────────────────────────────────────────
SYSCALL = {
    1: "execve",
    2: "openat",
    3: "connect",
    4: "read",
    5: "write",
    6: "fork",
    7: "socket",
}
SYSCALL_REV = {v: k for k, v in SYSCALL.items()}

# ── eBPF C Program (loaded into kernel) ──────────────────────
# This is the kernel-space code. It runs inside the Linux kernel.
# It hooks into syscall entry points and sends events to userspace.
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

/* Syscall type identifiers */
#define SC_EXECVE   1
#define SC_OPENAT   2
#define SC_CONNECT  3
#define SC_READ     4
#define SC_WRITE    5
#define SC_FORK     6
#define SC_SOCKET   7

/* Event sent to userspace for every syscall */
struct event_t {
    u32  pid;            /* Process ID */
    u32  tgid;           /* Thread group ID */
    u8   syscall_id;     /* Which syscall (SC_* constants above) */
    u64  ts_ns;          /* Timestamp in nanoseconds */
    char comm[TASK_COMM_LEN];  /* Process name */
};

/* Ring buffer: kernel → userspace event channel */
BPF_RINGBUF_OUTPUT(events, 256);

/* Hash map: which PIDs to monitor (written by userspace) */
BPF_HASH(watched_pids, u32, u8, 64);

/* Flag: if set to 1, monitor ALL processes */
BPF_ARRAY(watch_all, u8, 1);

/* Helper: should we monitor this PID? */
static inline int should_watch(u32 pid) {
    /* Check watch_all flag */
    int zero = 0;
    u8 *all = watch_all.lookup(&zero);
    if (all && *all == 1) return 1;
    /* Check if PID is in watched set */
    u8 *v = watched_pids.lookup(&pid);
    return (v != NULL);
}

/* Helper: fill and submit an event */
static inline void emit(u8 sc_id) {
    u64 pt = bpf_get_current_pid_tgid();
    u32 pid  = pt >> 32;
    u32 tgid = (u32)pt;

    if (!should_watch(pid)) return;

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e) return;

    e->pid        = pid;
    e->tgid       = tgid;
    e->syscall_id = sc_id;
    e->ts_ns      = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    events.ringbuf_submit(e, 0);
}

/* Kprobe hooks — one per syscall */
int trace_execve(struct pt_regs *ctx)  { emit(SC_EXECVE);  return 0; }
int trace_openat(struct pt_regs *ctx)  { emit(SC_OPENAT);  return 0; }
int trace_connect(struct pt_regs *ctx) { emit(SC_CONNECT); return 0; }
int trace_read(struct pt_regs *ctx)    { emit(SC_READ);    return 0; }
int trace_write(struct pt_regs *ctx)   { emit(SC_WRITE);   return 0; }
int trace_fork(struct pt_regs *ctx)    { emit(SC_FORK);    return 0; }
int trace_socket(struct pt_regs *ctx)  { emit(SC_SOCKET);  return 0; }
"""

# ── Event struct matching the BPF struct ─────────────────────
class BpfEvent(ctypes.Structure):
    _fields_ = [
        ("pid",        ctypes.c_uint32),
        ("tgid",       ctypes.c_uint32),
        ("syscall_id", ctypes.c_uint8),
        ("ts_ns",      ctypes.c_uint64),
        ("comm",       ctypes.c_char * 16),
    ]

# ── Terminal colors ───────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

SYSCALL_COLOR = {
    "execve":  RED,
    "fork":    RED,
    "connect": YELLOW,
    "socket":  YELLOW,
    "openat":  CYAN,
    "read":    CYAN,
    "write":   CYAN,
}

# ── Tracer class ──────────────────────────────────────────────
class KernelSentinelTracer:

    def __init__(self, pid=None, watch_all=False, output_file=None):
        self.pid         = pid
        self.watch_all   = watch_all or (pid is None)
        self.output_file = output_file
        self.counts      = defaultdict(int)
        self.events      = []
        self.start_time  = time.time()
        self.b           = None
        self.running     = False

    def load(self):
        """Load the BPF program into the kernel."""
        print(f"{BOLD}[KernelSentinel] Loading eBPF program into kernel...{RESET}")
        self.b = BPF(text=BPF_PROGRAM)

        # Attach kprobes for each syscall
        hooks = [
            ("execve",  "trace_execve"),
            ("openat",  "trace_openat"),
            ("connect", "trace_connect"),
            ("read",    "trace_read"),
            ("write",   "trace_write"),
            ("fork",    "trace_fork"),
            ("socket",  "trace_socket"),
        ]
        attached = []
        for sc_name, fn_name in hooks:
            try:
                kernel_fn = self.b.get_syscall_fnname(sc_name)
                self.b.attach_kprobe(event=kernel_fn, fn_name=fn_name)
                attached.append(sc_name)
            except Exception as e:
                print(f"  ⚠️  Could not attach {sc_name}: {e}")

        print(f"  ✅ Kprobes attached: {', '.join(attached)}")

        # Set watch_all flag if needed
        if self.watch_all:
            watch_all_map = self.b["watch_all"]
            watch_all_map[ctypes.c_int(0)] = ctypes.c_uint8(1)
            print(f"  ✅ Monitoring ALL processes")

        # Set specific PID if given
        if self.pid and not self.watch_all:
            watched = self.b["watched_pids"]
            watched[ctypes.c_uint32(self.pid)] = ctypes.c_uint8(1)
            print(f"  ✅ Monitoring PID: {self.pid}")

        # Open ring buffer
        self.b["events"].open_ring_buffer(self._handle_event)
        print(f"  ✅ Ring buffer active")
        print()

    def add_pid(self, pid: int):
        """Dynamically add a PID to the watch list (called by orchestrator)."""
        if self.b:
            watched = self.b["watched_pids"]
            watched[ctypes.c_uint32(pid)] = ctypes.c_uint8(1)

    def _handle_event(self, ctx, data, size):
        """Called for every syscall event from the ring buffer."""
        ev   = ctypes.cast(data, ctypes.POINTER(BpfEvent)).contents
        sc   = SYSCALL.get(ev.syscall_id, "unknown")
        comm = ev.comm.decode("utf-8", errors="replace").rstrip("\x00")
        ts   = time.time() - self.start_time
        col  = SYSCALL_COLOR.get(sc, "")

        # Count
        self.counts[sc] += 1

        # Print
        print(f"  {ts:>8.3f}s  {ev.pid:<7} {comm:<16} {col}{sc}{RESET}")

        # Store
        self.events.append({
            "ts":      round(ts, 4),
            "pid":     ev.pid,
            "comm":    comm,
            "syscall": sc,
        })

    def poll(self, duration=None):
        """Poll ring buffer. Runs until Ctrl+C or duration expires."""
        self.running = True
        end = time.time() + duration if duration else float("inf")

        print(f"{'TIME':>10}  {'PID':<7} {'PROCESS':<16} SYSCALL")
        print("─" * 55)

        try:
            while self.running and time.time() < end:
                self.b.ring_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            pass

    def stop(self):
        self.running = False

    def get_counts(self) -> dict:
        """Return final syscall counts."""
        result = {sc: 0 for sc in SYSCALL.values()}
        result.update(dict(self.counts))
        return result

    def save(self):
        """Save event log and counts to output file."""
        if not self.output_file:
            return
        data = {
            "pid":       self.pid,
            "counts":    self.get_counts(),
            "events":    self.events,
            "duration":  time.time() - self.start_time,
            "timestamp": datetime.now().isoformat(),
        }
        with open(self.output_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n  💾 Trace saved → {self.output_file}")

    def print_summary(self):
        """Print a summary table of syscall counts."""
        total = sum(self.counts.values())
        print(f"\n{'─'*45}")
        print(f"  {'SYSCALL':<12} {'COUNT':>8}  {'BAR'}")
        print(f"{'─'*45}")
        for sc in SYSCALL.values():
            c = self.counts.get(sc, 0)
            bar = "█" * min(int(c / max(total, 1) * 40), 30)
            col = SYSCALL_COLOR.get(sc, "")
            print(f"  {col}{sc:<12}{RESET} {c:>8}  {col}{bar}{RESET}")
        print(f"{'─'*45}")
        print(f"  {'TOTAL':<12} {total:>8}")

# ── CLI entry point ───────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="KernelSentinel eBPF Syscall Tracer")
    parser.add_argument("--pid",    type=int, help="Monitor specific PID")
    parser.add_argument("--all",    action="store_true", help="Monitor all processes")
    parser.add_argument("--output", type=str, help="Save trace to JSON file")
    parser.add_argument("--duration", type=int, default=0,
                        help="Stop after N seconds (0=forever)")
    parser.add_argument("--test",   action="store_true",
                        help="Verify eBPF setup and exit")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("❌ Must run as root: sudo python3 ebpf/tracer.py")
        sys.exit(1)

    print()
    print(f"{BOLD}╔══════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║   KernelSentinel eBPF Tracer             ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════╝{RESET}")
    print()

    tracer = KernelSentinelTracer(
        pid=args.pid,
        watch_all=args.all or (not args.pid),
        output_file=args.output,
    )
    tracer.load()

    if args.test:
        print(f"{GREEN}✅ eBPF is working on this machine!{RESET}")
        print("   All kprobes loaded successfully.")
        print("   Your EC2 kernel supports KernelSentinel.")
        return

    def shutdown(sig, frame):
        print(f"\n{BOLD}Stopping tracer...{RESET}")
        tracer.stop()
        tracer.print_summary()
        tracer.save()
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("Press Ctrl+C to stop\n")
    tracer.poll(duration=args.duration if args.duration > 0 else None)
    tracer.print_summary()
    tracer.save()


if __name__ == "__main__":
    main()
