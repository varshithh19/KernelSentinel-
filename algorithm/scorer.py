#!/usr/bin/env python3
# =============================================================
# KernelSentinel — Behavioural Risk Scoring Algorithm
# YOUR ORIGINAL CONTRIBUTION — Steps 1 to 6
#
# Step 1: Load syscall data from eBPF tracer
# Step 2: Build normal behaviour baseline
# Step 3: Calculate deviation per syscall
# Step 4: Normalize deviations
# Step 5: Compute Behavioural Risk Score
# Step 6: Determine optimal threshold (F1 maximisation)
#
# Run:
#   python3 algorithm/scorer.py --demo          (test with synthetic data)
#   python3 algorithm/scorer.py --build-baseline --input logs/normal_*.json
#   python3 algorithm/scorer.py --score --input logs/run.json
#   python3 algorithm/scorer.py --evaluate      (full eval + graph)
# =============================================================

import json
import math
import os
import sys
import argparse
import time
from typing import Dict, List, Tuple
from collections import defaultdict
from pathlib import Path

# ── Syscalls we track ─────────────────────────────────────────
ALL_SYSCALLS = ["execve", "openat", "connect", "read", "write", "fork", "socket"]

# ── Feature groups for Risk Score calculation ─────────────────
# This grouping is YOUR design decision — justify it at review
FEATURES = {
    "execution": ["execve", "fork"],           # Process spawning
    "network":   ["connect", "socket"],        # Network activity
    "file":      ["openat", "read", "write"],  # File operations
    # "sequence" is computed dynamically (co-occurrence detection)
}

# ── Colors for terminal output ────────────────────────────────
RED   = "\033[91m"
GREEN = "\033[92m"
YELLOW= "\033[93m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
RESET = "\033[0m"

BASELINE_FILE = "baseline_data/baseline.json"


# =============================================================
# STEP 1 — Load syscall data from tracer output
# =============================================================
def load_counts(source) -> Dict[str, int]:
    """
    Load syscall counts from:
    - A JSON file path (string)
    - A dict (already loaded)
    - A list of files (averages them)
    
    Returns: {"execve": 2, "connect": 8, "read": 120, ...}
    """
    if isinstance(source, dict):
        counts = source.get("counts", source)
    elif isinstance(source, str):
        with open(source) as f:
            data = json.load(f)
        # Handle both formats: {counts: {...}} or event log
        if "counts" in data:
            counts = data["counts"]
        elif "events" in data:
            counts = defaultdict(int)
            for ev in data["events"]:
                counts[ev["syscall"]] += 1
            counts = dict(counts)
        else:
            counts = data
    else:
        counts = {}

    # Ensure all syscalls present
    result = {sc: 0 for sc in ALL_SYSCALLS}
    result.update({k: v for k, v in counts.items() if k in ALL_SYSCALLS})
    return result


# =============================================================
# STEP 2 — Build Normal Behaviour Profile (Baseline)
# =============================================================
def build_baseline(run_files: List[str]) -> Dict:
    """
    Run agent N times with legitimate prompts.
    Record syscall counts for each run.
    Compute mean and standard deviation per syscall.
    Store as the Normal Behaviour Profile.
    
    This is what "normal" looks like — everything is measured
    against this baseline.
    """
    all_runs = [load_counts(f) for f in run_files]
    n = len(all_runs)

    baseline = {"_meta": {"num_runs": n, "syscalls": ALL_SYSCALLS}}
    for sc in ALL_SYSCALLS:
        values = [r.get(sc, 0) for r in all_runs]
        mean   = sum(values) / n if n > 0 else 0
        var    = sum((v - mean) ** 2 for v in values) / n if n > 0 else 0
        stddev = math.sqrt(var)
        baseline[sc] = {
            "mean":   round(mean, 3),
            "stddev": round(stddev, 3),
            "min":    min(values) if values else 0,
            "max":    max(values) if values else 0,
        }
    return baseline


# =============================================================
# STEP 3 — Calculate Deviation
# =============================================================
def calculate_deviation(counts: Dict[str, int],
                        baseline: Dict) -> Dict[str, float]:
    """
    Formula: Deviation(syscall) = |Current_Count - Baseline_Mean|
    
    This measures how far the current run is from normal
    for each individual syscall.
    """
    return {
        sc: abs(counts.get(sc, 0) - baseline[sc]["mean"])
        for sc in ALL_SYSCALLS
    }


# =============================================================
# STEP 4 — Normalize the Deviation
# =============================================================
def normalize(deviations: Dict[str, float],
              baseline: Dict) -> Dict[str, float]:
    """
    Formula: Normalized(syscall) = Deviation / (Baseline_Mean + 1)
    
    Why +1? Prevents division by zero.
    Why divide by baseline? A deviation of 10 from a baseline of 1000
    is tiny. A deviation of 10 from a baseline of 1 is huge.
    This makes all syscalls comparable on the same scale (0 to ~1+).
    """
    return {
        sc: deviations[sc] / (baseline[sc]["mean"] + 1)
        for sc in ALL_SYSCALLS
    }


# =============================================================
# STEP 5 — Compute Behavioural Risk Score
# =============================================================
def compute_risk_score(normalized: Dict[str, float]) -> Tuple[float, Dict]:
    """
    Groups syscalls into features.
    Averages scores within each feature.
    Adds co-occurrence boost for sequence anomaly.
    Final: Risk = (Execution + Network + File + Sequence) / 4
    
    Returns: (risk_score, breakdown_dict)
    """
    # Feature scores
    exec_score = sum(normalized[sc] for sc in FEATURES["execution"]) \
                 / len(FEATURES["execution"])

    net_score  = sum(normalized[sc] for sc in FEATURES["network"]) \
                 / len(FEATURES["network"])

    file_score = sum(normalized[sc] for sc in FEATURES["file"]) \
                 / len(FEATURES["file"])

    # Sequence anomaly score:
    # If execve AND connect are BOTH elevated simultaneously,
    # that's the classic "spawn shell + phone home" attack pattern.
    # We boost the score when this co-occurrence happens.
    seq_base = (normalized["execve"] + normalized["connect"] +
                normalized["fork"]) / 3.0

    # Co-occurrence boost: both execve and connect elevated simultaneously
    co_occur_boost = 1.0
    if normalized["execve"] > 0.3 and normalized["connect"] > 0.3:
        co_occur_boost = 1.5  # 50% boost for concurrent exec+network

    seq_score = min(seq_base * co_occur_boost, 1.5)  # Cap at 1.5

    # Final Risk Score — equal weight to all 4 features
    # (Weights can be tuned experimentally — initial proposal)
    risk = (exec_score + net_score + file_score + seq_score) / 4.0

    breakdown = {
        "execution": round(exec_score, 4),
        "network":   round(net_score, 4),
        "file":      round(file_score, 4),
        "sequence":  round(seq_score, 4),
        "risk_score": round(risk, 4),
    }
    return round(risk, 4), breakdown


# =============================================================
# STEP 6 — Determine Optimal Threshold
# =============================================================
def find_optimal_threshold(normal_scores: List[float],
                           attack_scores: List[float]) -> Dict:
    """
    Test candidate thresholds from 0.05 to 0.95.
    For each threshold, compute precision, recall, F1.
    Pick the one with highest F1.
    
    F1 = 2 * precision * recall / (precision + recall)
    Maximising F1 balances detection rate vs false positives.
    """
    best = {"threshold": 0.35, "f1": 0, "precision": 0,
            "recall": 0, "fp_rate": 0, "detection_rate": 0,
            "tp": 0, "fp": 0, "tn": 0, "fn": 0}

    for t in [round(x * 0.05, 2) for x in range(1, 20)]:
        tp = sum(1 for s in attack_scores if s > t)
        fn = sum(1 for s in attack_scores if s <= t)
        tn = sum(1 for s in normal_scores if s <= t)
        fp = sum(1 for s in normal_scores if s > t)

        prec   = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1     = (2 * prec * recall / (prec + recall)
                  if (prec + recall) > 0 else 0)

        if f1 > best["f1"]:
            best = {
                "threshold":      t,
                "f1":             round(f1, 4),
                "precision":      round(prec, 4),
                "recall":         round(recall, 4),
                "detection_rate": round(recall * 100, 1),
                "fp_rate":        round(fp / max(len(normal_scores), 1) * 100, 1),
                "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            }
    return best


# =============================================================
# Full Pipeline: Score a single run
# =============================================================
def score(source, baseline: Dict, threshold: float = None) -> Dict:
    """Run the complete 6-step pipeline on one data source."""
    counts     = load_counts(source)
    deviations = calculate_deviation(counts, baseline)
    norm       = normalize(deviations, baseline)
    risk, breakdown = compute_risk_score(norm)

    result = {
        "counts":     counts,
        "deviations": {k: round(v, 4) for k, v in deviations.items()},
        "normalized": {k: round(v, 4) for k, v in norm.items()},
        "breakdown":  breakdown,
        "risk_score": risk,
    }
    if threshold is not None:
        result["threshold"]  = threshold
        result["is_attack"]  = risk > threshold
        result["decision"]   = "ATTACK" if risk > threshold else "NORMAL"
    return result


# =============================================================
# DEMO: Run with synthetic data (no real agent needed)
# =============================================================
def run_demo():
    """
    Generates synthetic syscall data to demonstrate the algorithm.
    Use this to get real numbers for your slides before EC2 is ready.
    """
    import random
    random.seed(42)

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  KernelSentinel Algorithm — DEMO MODE{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print("  (Synthetic data — replace with real eBPF logs on EC2)\n")

    # Simulate 20 normal runs
    normal_runs = []
    for _ in range(20):
        normal_runs.append({
            "execve":  random.randint(0, 2),
            "openat":  random.randint(15, 35),
            "connect": random.randint(5, 12),
            "read":    random.randint(100, 150),
            "write":   random.randint(25, 55),
            "fork":    random.randint(0, 1),
            "socket":  random.randint(4, 10),
        })

    # Simulate 5 attack runs (elevated execve, fork, connect)
    attack_runs = []
    for _ in range(5):
        attack_runs.append({
            "execve":  random.randint(8, 18),   # Spawning shells
            "openat":  random.randint(30, 60),  # Reading many files
            "connect": random.randint(20, 45),  # Phoning home
            "read":    random.randint(120, 200),
            "write":   random.randint(30, 80),
            "fork":    random.randint(5, 12),   # Process spawning
            "socket":  random.randint(15, 30),  # New sockets
        })

    # Step 2: Build baseline from normal runs
    print(f"{BOLD}STEP 2: Building Normal Behaviour Profile{RESET}")
    baseline = build_baseline_from_dicts(normal_runs)
    print_baseline(baseline)

    # Score all runs
    print(f"\n{BOLD}STEPS 3–5: Scoring All Runs{RESET}")
    normal_scores = []
    attack_scores = []

    print(f"\n  Normal runs:")
    for i, run in enumerate(normal_runs):
        r = score(run, baseline)
        normal_scores.append(r["risk_score"])
        indicator = "✅" if r["risk_score"] < 0.35 else "⚠️ "
        print(f"    Run {i+1:>2}: risk={r['risk_score']:.4f} {indicator}")

    print(f"\n  Attack runs:")
    for i, run in enumerate(attack_runs):
        r = score(run, baseline)
        attack_scores.append(r["risk_score"])
        indicator = "🔴" if r["risk_score"] > 0.35 else "❓"
        print(f"    Attack {i+1}: risk={r['risk_score']:.4f} {indicator}")

    # Step 6: Find threshold
    print(f"\n{BOLD}STEP 6: Finding Optimal Threshold{RESET}")
    result = find_optimal_threshold(normal_scores, attack_scores)

    # Print final results
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  RESULTS — Show These to Your Professor{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Normal score range:   "
          f"{GREEN}{min(normal_scores):.4f} – {max(normal_scores):.4f}{RESET}")
    print(f"  Attack score range:   "
          f"{RED}{min(attack_scores):.4f} – {max(attack_scores):.4f}{RESET}")
    print(f"  Optimal threshold:    {BOLD}{result['threshold']}{RESET}")
    print(f"  Detection rate:       {GREEN}{result['detection_rate']}%{RESET}")
    print(f"  False positive rate:  {GREEN}{result['fp_rate']}%{RESET}")
    print(f"  F1 Score:             {GREEN}{result['f1']}{RESET}")
    print(f"  Containment trigger:  Risk Score > {result['threshold']} → SIGKILL")
    print()

    # Generate graph
    try:
        plot_scores(normal_scores, attack_scores, result["threshold"])
    except Exception as e:
        print(f"  (Graph generation skipped: {e})")

    return {
        "normal_scores": normal_scores,
        "attack_scores": attack_scores,
        "threshold": result,
    }


def build_baseline_from_dicts(runs: List[Dict]) -> Dict:
    """Build baseline directly from list of count dicts."""
    n = len(runs)
    baseline = {"_meta": {"num_runs": n}}
    for sc in ALL_SYSCALLS:
        values = [r.get(sc, 0) for r in runs]
        mean   = sum(values) / n
        var    = sum((v - mean)**2 for v in values) / n
        baseline[sc] = {
            "mean":   round(mean, 3),
            "stddev": round(math.sqrt(var), 3),
            "min":    min(values),
            "max":    max(values),
        }
    return baseline


def print_baseline(baseline: Dict):
    print(f"\n  {'Syscall':<10} {'Mean':>8} {'StdDev':>10} {'Min':>6} {'Max':>6}")
    print(f"  {'─'*44}")
    for sc in ALL_SYSCALLS:
        b = baseline[sc]
        print(f"  {sc:<10} {b['mean']:>8.1f} {b['stddev']:>10.2f} "
              f"{b['min']:>6} {b['max']:>6}")


def plot_scores(normal_scores, attack_scores, threshold):
    """Generate and save risk score comparison graph."""
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend (works on EC2)
    import matplotlib.pyplot as plt
    import numpy as np

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle("KernelSentinel — Behavioural Risk Score Analysis",
                 fontsize=14, fontweight="bold")

    # Plot 1: Individual scores
    x_norm = list(range(1, len(normal_scores) + 1))
    x_att  = list(range(1, len(attack_scores) + 1))

    ax1.scatter(x_norm, normal_scores, color="green", s=80,
                label=f"Normal (n={len(normal_scores)})", zorder=5)
    ax1.scatter(x_att, attack_scores, color="red", s=100, marker="^",
                label=f"Attack (n={len(attack_scores)})", zorder=5)
    ax1.axhline(y=threshold, color="orange", linestyle="--", linewidth=2,
                label=f"Threshold = {threshold}")
    ax1.fill_between([0, max(len(normal_scores), len(attack_scores)) + 1],
                     threshold, 1.5, alpha=0.1, color="red",
                     label="Attack Zone")
    ax1.fill_between([0, max(len(normal_scores), len(attack_scores)) + 1],
                     0, threshold, alpha=0.1, color="green",
                     label="Normal Zone")
    ax1.set_xlabel("Run Number")
    ax1.set_ylabel("Risk Score")
    ax1.set_title("Risk Scores: Normal vs Attack")
    ax1.legend(loc="upper left")
    ax1.set_ylim(-0.05, 1.1)
    ax1.grid(True, alpha=0.3)

    # Plot 2: Distribution histogram
    bins = np.linspace(0, 1.2, 25)
    ax2.hist(normal_scores, bins=bins, alpha=0.7, color="green",
             label=f"Normal (mean={sum(normal_scores)/len(normal_scores):.3f})")
    ax2.hist(attack_scores, bins=bins, alpha=0.7, color="red",
             label=f"Attack (mean={sum(attack_scores)/len(attack_scores):.3f})")
    ax2.axvline(x=threshold, color="orange", linestyle="--", linewidth=2,
                label=f"Threshold = {threshold}")
    ax2.set_xlabel("Risk Score")
    ax2.set_ylabel("Count")
    ax2.set_title("Score Distribution")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    out = "logs/risk_score_graph.png"
    os.makedirs("logs", exist_ok=True)
    plt.savefig(out, dpi=150, bbox_inches="tight")
    print(f"\n  📊 Graph saved → {out}")
    print(f"     Copy to your local machine:")
    print(f"     scp -i key.pem ec2-user@IP:~/kernelsentinel/{out} .")


# =============================================================
# Main CLI
# =============================================================
def main():
    parser = argparse.ArgumentParser(description="KernelSentinel Risk Scorer")
    parser.add_argument("--demo",           action="store_true")
    parser.add_argument("--build-baseline", action="store_true")
    parser.add_argument("--score",          action="store_true")
    parser.add_argument("--evaluate",       action="store_true")
    parser.add_argument("--input",  nargs="+")
    parser.add_argument("--normal", nargs="+")
    parser.add_argument("--attack", nargs="+")
    parser.add_argument("--baseline", default=BASELINE_FILE)
    parser.add_argument("--threshold", type=float)
    parser.add_argument("--plot", action="store_true")
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    if args.build_baseline:
        if not args.input:
            print("❌ --input <files>"); sys.exit(1)
        baseline = build_baseline(args.input)
        os.makedirs(os.path.dirname(args.baseline), exist_ok=True)
        with open(args.baseline, "w") as f:
            json.dump(baseline, f, indent=2)
        print_baseline(baseline)
        print(f"\n✅ Baseline saved → {args.baseline}")
        return

    if args.score:
        if not args.input: print("❌ --input required"); sys.exit(1)
        with open(args.baseline) as f:
            baseline = json.load(f)
        for inp in args.input:
            r = score(inp, baseline, args.threshold)
            col = RED if r.get("is_attack") else GREEN
            print(f"\n{inp}: risk={col}{r['risk_score']}{RESET} "
                  f"→ {r.get('decision','?')}")
            print(f"  Breakdown: {r['breakdown']}")
        return

    if args.evaluate:
        if not (args.normal and args.attack):
            print("❌ --normal and --attack required"); sys.exit(1)
        with open(args.baseline) as f:
            baseline = json.load(f)
        normal_scores = [score(f, baseline)["risk_score"] for f in args.normal]
        attack_scores = [score(f, baseline)["risk_score"] for f in args.attack]
        thresh = find_optimal_threshold(normal_scores, attack_scores)
        print(f"\nNormal: {normal_scores}")
        print(f"Attack: {attack_scores}")
        print(f"Optimal threshold: {thresh}")
        if args.plot:
            plot_scores(normal_scores, attack_scores, thresh["threshold"])
        return

    # Default
    run_demo()


if __name__ == "__main__":
    main()
