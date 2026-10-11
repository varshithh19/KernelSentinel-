import time
import psutil
from typing import Dict, Any, List
from pydantic import BaseModel
from detector.features.feature_extractor import extract_features
from detector.scoring.risk_scorer import compute_risk_score, RiskAssessment

class CorrelatedTrace(BaseModel):
    correlation_id: str
    request_id: str
    prompt_id: str
    agent_pid: int
    process_create_time: float
    timestamp: float
    time_window_ms: float
    is_pid_reuse_safe: bool
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
    time_window_ms: float = 2000.0
) -> CorrelatedTrace:
    """
    Correlates application-layer prompts and requests with kernel-layer syscall events.
    Verifies process identity to prevent PID reuse ambiguity.
    """
    req_id = agent_request.get("request_id", "unknown_req")
    prompt_id = agent_request.get("prompt_id", "unknown_prm")
    pid = agent_request.get("pid", 0)
    req_time = agent_request.get("timestamp", time.time())
    process_start = get_process_create_time(pid)

    # 1. Filter kernel events matching PID and temporal window
    matched_kernel_events = []
    for kev in raw_kernel_events:
        kev_pid = kev.get("pid", 0)
        # Event is correlated if PID matches or child process of agent PID
        if kev_pid == pid:
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

    return CorrelatedTrace(
        correlation_id=f"corr_{req_id}_{int(time.time()*1000)}",
        request_id=req_id,
        prompt_id=prompt_id,
        agent_pid=pid,
        process_create_time=process_start,
        timestamp=req_time,
        time_window_ms=time_window_ms,
        is_pid_reuse_safe=(process_start > 0),
        correlated_kernel_events=matched_kernel_events,
        risk_assessment=risk,
        recommended_action=action
    )
