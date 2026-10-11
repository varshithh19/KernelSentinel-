import time
import psutil
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from detector.features.feature_extractor import extract_features
from detector.scoring.risk_scorer import compute_risk_score, RiskAssessment

class CorrelatedTrace(BaseModel):
    correlation_id: str
    request_id: str
    prompt_id: str
    agent_pid: int
    target_worker_pid: Optional[int] = None
    target_pid: int
    process_create_time: float
    timestamp: float
    time_window_ms: float
    is_pid_reuse_safe: bool
    telemetry_source: str = "simulated"  # "live_kernel" or "simulated"
    correlated_kernel_events: List[Dict[str, Any]]
    risk_assessment: RiskAssessment
    recommended_action: str

def get_process_create_time(pid: int) -> float:
    try:
        proc = psutil.Process(pid)
        return proc.create_time()
    except Exception:
        return 0.0

def correlate_and_evaluate(
    agent_request: Dict[str, Any],
    security_events: List[Dict[str, Any]],
    raw_kernel_events: List[Dict[str, Any]],
    time_window_ms: float = 2000.0,
    target_worker_pid: Optional[int] = None
) -> CorrelatedTrace:
    """
    Correlates application-layer prompts and requests with kernel-layer syscall events.
    Verifies process identity to prevent PID reuse ambiguity and isolates live from simulated events.
    Does not assume web-server PID is identical to separate worker processes.
    """
    req_id = agent_request.get("request_id", "unknown_req")
    prompt_id = agent_request.get("prompt_id", "unknown_prm")

    # Use explicit target worker PID if provided, otherwise default to agent request PID
    effective_pid = target_worker_pid if target_worker_pid is not None else agent_request.get("pid", 0)
    req_time = agent_request.get("timestamp", time.time())
    process_start = get_process_create_time(effective_pid)

    # 1. Filter kernel events matching PID, freshness, and temporal window
    matched_kernel_events = []
    has_live_ebpf = False

    for kev in raw_kernel_events:
        kev_pid = kev.get("pid", 0)
        # Event must match the effective target PID
        if kev_pid != effective_pid:
            continue

        ev_ts = kev.get("ts")
        # Stale-event / PID-reuse safeguard:
        # If process creation time is known, reject events timestamped before process start
        if ev_ts is not None and process_start > 0 and ev_ts < (process_start - 0.5):
            continue

        # Temporal window check (if timestamps exist and are positive)
        if ev_ts is not None and req_time > 0:
            if abs(ev_ts - req_time) * 1000.0 > time_window_ms:
                continue

        if kev.get("provenance") == "kernel_ebpf":
            has_live_ebpf = True

        matched_kernel_events.append(kev)

    # 2. Extract features
    features = extract_features(agent_request, security_events, matched_kernel_events)

    # 3. Score risk
    risk = compute_risk_score(features)

    # 4. Determine response
    if risk.category == "CRITICAL":
        action = "CONTAIN_PROCESS_SUSPEND"
    elif risk.category == "HIGH_RISK":
        action = "DENY_ACCESS_AND_ALERT"
    elif risk.category == "SUSPICIOUS":
        action = "LOG_AND_MONITOR"
    else:
        action = "ALLOW"

    telemetry_source = "live_kernel" if has_live_ebpf else "simulated"

    agent_pid_val = agent_request.get("pid", effective_pid)

    return CorrelatedTrace(
        correlation_id=f"corr_{req_id}_{int(time.time()*1000)}",
        request_id=req_id,
        prompt_id=prompt_id,
        agent_pid=agent_pid_val,
        target_worker_pid=target_worker_pid,
        target_pid=effective_pid,
        process_create_time=process_start,
        timestamp=req_time,
        time_window_ms=time_window_ms,
        is_pid_reuse_safe=(process_start > 0),
        telemetry_source=telemetry_source,
        correlated_kernel_events=matched_kernel_events,
        risk_assessment=risk,
        recommended_action=action
    )
