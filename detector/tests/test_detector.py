import os
import sys
import subprocess
import time
import pytest

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from detector.features.feature_extractor import extract_features
from detector.baseline.baseline_model import BaselineModel
from detector.scoring.risk_scorer import compute_risk_score
from detector.correlation.event_correlator import correlate_and_evaluate
from detector.response.containment import suspend_process, resume_process, is_protected_process

def test_feature_extraction_benign():
    agent_request = {"request_id": "req_1", "classification": {"confidence": 0.0}}
    security_events = []
    kernel_events = []

    features = extract_features(agent_request, security_events, kernel_events)
    assert features.auth_denial == 0.0
    assert features.prompt_suspicion == 0.0
    assert features.unexpected_exec == 0.0
    assert features.unexpected_file == 0.0

def test_feature_extraction_attack():
    agent_request = {"request_id": "req_2", "classification": {"confidence": 0.95}}
    security_events = [{"event_type": "UNAUTHORIZED_TOOL_ATTEMPT"}]
    kernel_events = [
        {"type": "exec", "comm": "bash", "filename": "/bin/bash", "pid": 1234},
        {"type": "open", "filename": "/etc/shadow", "flags": 0, "pid": 1234}
    ]

    features = extract_features(agent_request, security_events, kernel_events)
    assert features.auth_denial == 1.0
    assert features.prompt_suspicion == 0.95
    assert features.unexpected_exec > 0.0
    assert features.unexpected_file > 0.0

def test_risk_scoring_normal_vs_critical():
    benign_req = {"request_id": "req_b", "classification": {"confidence": 0.0}}
    benign_features = extract_features(benign_req, [], [])
    benign_risk = compute_risk_score(benign_features)
    assert benign_risk.category == "NORMAL"
    assert benign_risk.score < 30.0

    attack_req = {"request_id": "req_a", "classification": {"confidence": 0.95}}
    attack_events = [{"event_type": "UNAUTHORIZED_TOOL_ATTEMPT"}]
    attack_kernel = [
        {"type": "exec", "comm": "cmd.exe", "filename": "cmd.exe", "pid": 9999},
        {"type": "open", "filename": "id_rsa", "flags": 0, "pid": 9999}
    ]
    attack_features = extract_features(attack_req, attack_events, attack_kernel)
    attack_risk = compute_risk_score(attack_features)
    assert attack_risk.category in ["HIGH_RISK", "CRITICAL"]
    assert attack_risk.score >= 60.0

def test_baseline_deviation():
    model = BaselineModel()
    benign_features = extract_features({"classification": {"confidence": 0.0}}, [], [])
    for _ in range(5):
        model.train_on_sample(benign_features)

    assert model.sample_count == 5
    summary = model.get_baseline_summary()
    assert summary["auth_denial"]["mean"] == 0.0

    # Deviation of attack sample should be positive
    attack_features = extract_features(
        {"classification": {"confidence": 0.9}},
        [{"event_type": "UNAUTHORIZED_TOOL_ATTEMPT"}],
        []
    )
    dev = model.get_deviation(attack_features)
    assert dev > 0.5

def test_event_correlation():
    my_pid = os.getpid()
    agent_request = {
        "request_id": "req_corr_1",
        "prompt_id": "prm_corr_1",
        "pid": my_pid,
        "classification": {"confidence": 0.1}
    }
    raw_kernel = [
        {"type": "open", "filename": "test.txt", "pid": my_pid, "flags": 0},
        {"type": "exec", "comm": "other_proc", "pid": 99999, "filename": "other"}
    ]

    correlated = correlate_and_evaluate(agent_request, [], raw_kernel)
    assert correlated.request_id == "req_corr_1"
    assert correlated.agent_pid == my_pid
    # Only events matching my_pid should be correlated
    assert len(correlated.correlated_kernel_events) == 1
    assert correlated.correlated_kernel_events[0]["pid"] == my_pid

def test_containment_safeguards():
    # 1. Safeguard against protecting PID 1 or self PID
    prot_self, _ = is_protected_process(os.getpid())
    assert prot_self is True

    prot_low, _ = is_protected_process(1)
    assert prot_low is True

    result_self = suspend_process(os.getpid())
    assert result_self.success is False
    assert "Containment Aborted" in result_self.details

    # 2. Test containment on a harmless, disposable child process
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    try:
        suspend_res = suspend_process(child.pid)
        assert suspend_res.success is True
        assert suspend_res.target_pid == child.pid

        resume_res = resume_process(child.pid)
        assert resume_res.success is True
        assert resume_res.target_pid == child.pid
    finally:
        child.terminate()
        child.wait()
