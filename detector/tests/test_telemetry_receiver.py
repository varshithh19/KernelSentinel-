import os
import sys
import time
import json
import socket
import pytest

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from detector.transport.receiver import TelemetryReceiver, KernelTelemetryEvent
from detector.correlation.event_correlator import correlate_and_evaluate

def test_receiver_bind_and_lifecycle():
    """Verify TelemetryReceiver binds strictly to localhost (127.0.0.1) and starts/stops cleanly."""
    receiver = TelemetryReceiver(host="127.0.0.1", port=0)  # OS-allocated ephemeral port
    assert receiver.host == "127.0.0.1"

    receiver.start()
    assigned_port = receiver.port
    assert assigned_port > 0

    stats = receiver.get_stats()
    assert stats["running"] is True
    assert stats["host"] == "127.0.0.1"
    assert stats["port"] == assigned_port
    assert stats["events_received"] == 0

    receiver.stop()
    assert receiver.running is False
    stats_after = receiver.get_stats()
    assert stats_after["running"] is False

def test_receiver_rejects_external_binding():
    """Verify TelemetryReceiver refuses to bind to non-localhost addresses."""
    with pytest.raises(ValueError, match="strictly localhost-only"):
        TelemetryReceiver(host="0.0.0.0", port=9999)

    with pytest.raises(ValueError, match="strictly localhost-only"):
        TelemetryReceiver(host="192.168.1.100", port=9999)

def test_event_framing_and_schema_validation():
    """Verify line-delimited JSON frames are accepted, parsed into KernelTelemetryEvent, and stored."""
    receiver = TelemetryReceiver(host="127.0.0.1", port=0)
    receiver.start()
    port = receiver.port

    # Send valid line-delimited JSON
    payload1 = {
        "ts": time.time(),
        "pid": 4321,
        "comm": "python",
        "syscall": "openat",
        "ret": 3,
        "details": "filename=/path/to/data.db",
        "provenance": "kernel_ebpf"
    }
    payload2 = {
        "ts": time.time(),
        "pid": 4321,
        "comm": "cat",
        "syscall": "execve",
        "ret": 0,
        "details": "filename=/usr/bin/cat comm=cat",
        "provenance": "kernel_ebpf"
    }

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    client.sendall((json.dumps(payload1) + "\n" + json.dumps(payload2) + "\n").encode("utf-8"))
    client.close()

    # Allow brief window for socket read
    time.sleep(0.15)
    receiver.stop()

    events = receiver.get_events()
    assert len(events) == 2
    assert events[0]["pid"] == 4321
    assert events[0]["syscall"] == "openat"
    assert events[0]["type"] == "open"
    assert events[0]["filename"] == "/path/to/data.db"
    assert events[0]["provenance"] == "kernel_ebpf"

    assert events[1]["syscall"] == "execve"
    assert events[1]["type"] == "exec"
    assert events[1]["comm"] == "cat"
    assert events[1]["provenance"] == "kernel_ebpf"

    stats = receiver.get_stats()
    assert stats["events_received"] == 2
    assert stats["events_valid"] == 2
    assert stats["events_malformed"] == 0
    assert stats["events_oversized"] == 0

def test_malformed_and_oversized_message_rejection():
    """Verify malformed JSON, missing fields, and oversized lines (> 64 KB) are safely dropped."""
    receiver = TelemetryReceiver(host="127.0.0.1", port=0)
    receiver.start()
    port = receiver.port

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))

    # 1. Malformed JSON
    client.sendall(b"{bad json syntax\n")

    # 2. Schema validation failure (missing mandatory fields like pid, syscall)
    client.sendall(b'{"random_key": "val"}\n')

    # 3. Oversized line (> 65536 bytes) without newline delimiter
    oversized = b"A" * 70000 + b"\n"
    client.sendall(oversized)

    # 4. Valid line afterwards to verify receiver recovered gracefully
    valid_payload = {
        "ts": time.time(),
        "pid": 8888,
        "comm": "agent",
        "syscall": "connect",
        "ret": 0,
        "details": "remote=127.0.0.1:8000",
        "provenance": "kernel_ebpf"
    }
    client.sendall((json.dumps(valid_payload) + "\n").encode("utf-8"))
    client.close()

    time.sleep(0.2)
    receiver.stop()

    events = receiver.get_events()
    # Only the valid event should be present
    assert len(events) == 1
    assert events[0]["pid"] == 8888
    assert events[0]["syscall"] == "connect"

    stats = receiver.get_stats()
    assert stats["events_valid"] == 1
    assert stats["events_malformed"] >= 2
    assert stats["events_oversized"] >= 1

def test_transport_disconnection_and_reconnection():
    """Verify receiver remains alive and accepts subsequent connections after a client disconnects."""
    receiver = TelemetryReceiver(host="127.0.0.1", port=0)
    receiver.start()
    port = receiver.port

    # First client connects and immediately closes
    c1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c1.connect(("127.0.0.1", port))
    c1.close()

    time.sleep(0.05)

    # Second client connects and sends an event
    c2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c2.connect(("127.0.0.1", port))
    evt = {
        "ts": time.time(),
        "pid": 1111,
        "comm": "worker",
        "syscall": "fork",
        "ret": 2222,
        "details": "child_pid=2222",
        "provenance": "kernel_ebpf"
    }
    c2.sendall((json.dumps(evt) + "\n").encode("utf-8"))
    c2.close()

    time.sleep(0.15)
    receiver.stop()

    events = receiver.get_events()
    assert len(events) == 1
    assert events[0]["pid"] == 1111
    assert events[0]["ret"] == 2222

def test_provenance_separation_in_correlator():
    """Verify CorrelatedTrace reports telemetry_source as 'live_kernel' vs 'simulated'."""
    my_pid = os.getpid()
    agent_request = {
        "request_id": "req_prov_1",
        "prompt_id": "prm_prov_1",
        "pid": my_pid,
        "classification": {"confidence": 0.0}
    }

    # Case 1: Simulated events
    simulated_events = [
        {"type": "open", "filename": "db.sqlite3", "pid": my_pid, "flags": 0, "provenance": "simulated"}
    ]
    corr_sim = correlate_and_evaluate(agent_request, [], simulated_events)
    assert corr_sim.telemetry_source == "simulated"

    # Case 2: Live kernel events from eBPF
    live_events = [
        {"type": "open", "filename": "db.sqlite3", "pid": my_pid, "flags": 0, "provenance": "kernel_ebpf"}
    ]
    corr_live = correlate_and_evaluate(agent_request, [], live_events)
    assert corr_live.telemetry_source == "live_kernel"

def test_pid_reuse_stale_event_filtering():
    """Verify events timestamped before process creation time are rejected as stale/reused PID events."""
    import psutil
    proc = psutil.Process()
    my_pid = proc.pid
    p_create_time = proc.create_time()

    agent_request = {
        "request_id": "req_stale_1",
        "prompt_id": "prm_stale_1",
        "pid": my_pid,
        "timestamp": p_create_time + 1.0,
        "classification": {"confidence": 0.0}
    }

    # Stale event: ts happened well before this process was created
    stale_ts = p_create_time - 100.0
    fresh_ts = p_create_time + 1.0

    events = [
        {"type": "open", "filename": "old_file.txt", "pid": my_pid, "ts": stale_ts, "provenance": "kernel_ebpf"},
        {"type": "open", "filename": "current_file.txt", "pid": my_pid, "ts": fresh_ts, "provenance": "kernel_ebpf"}
    ]

    corr = correlate_and_evaluate(agent_request, [], events)
    # Only fresh event should be retained
    assert len(corr.correlated_kernel_events) == 1
    assert corr.correlated_kernel_events[0]["filename"] == "current_file.txt"

def test_target_worker_pid_distinct_from_server_pid():
    """Verify events can be correlated to a separate target worker process instead of the web server PID."""
    server_pid = 50000
    worker_pid = os.getpid()  # Use valid living PID for create_time check

    agent_request = {
        "request_id": "req_worker_1",
        "prompt_id": "prm_worker_1",
        "pid": server_pid,
        "classification": {"confidence": 0.0}
    }

    events = [
        {"type": "open", "filename": "server_access.log", "pid": server_pid, "provenance": "kernel_ebpf"},
        {"type": "open", "filename": "patient_data.csv", "pid": worker_pid, "provenance": "kernel_ebpf"}
    ]

    # Explicitly target the worker PID
    corr = correlate_and_evaluate(agent_request, [], events, target_worker_pid=worker_pid)
    assert corr.agent_pid == server_pid
    assert corr.target_worker_pid == worker_pid
    # Only worker_pid events correlated
    assert len(corr.correlated_kernel_events) == 1
    assert corr.correlated_kernel_events[0]["pid"] == worker_pid
    assert corr.correlated_kernel_events[0]["filename"] == "patient_data.csv"

def test_receiver_events_flow_into_detection_scoring():
    """
    Prove that events accepted and buffered by TelemetryReceiver are not merely stored,
    but directly flow into feature extraction and alter the resulting risk score and recommendation.
    """
    receiver = TelemetryReceiver(host="127.0.0.1", port=0)
    receiver.start()
    port = receiver.port

    my_pid = os.getpid()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))

    # Send suspicious kernel events (sensitive file read + unauthorized shell execution)
    ev1 = {
        "ts": time.time(),
        "pid": my_pid,
        "comm": "cat",
        "syscall": "openat",
        "details": "filename=/etc/shadow",
        "provenance": "kernel_ebpf"
    }
    ev2 = {
        "ts": time.time(),
        "pid": my_pid,
        "comm": "bash",
        "syscall": "execve",
        "details": "filename=/bin/bash comm=bash",
        "provenance": "kernel_ebpf"
    }
    client.sendall((json.dumps(ev1) + "\n" + json.dumps(ev2) + "\n").encode("utf-8"))
    client.close()

    time.sleep(0.15)
    receiver.stop()

    agent_request = {
        "request_id": "req_pipeline_test",
        "prompt_id": "prm_pipeline_test",
        "pid": my_pid,
        "timestamp": time.time(),
        "classification": {"confidence": 0.85}
    }
    security_events = [{"event_type": "UNAUTHORIZED_TOOL_ATTEMPT"}]

    # Ingest and correlate via TelemetryReceiver method
    trace = receiver.correlate_agent_request(
        agent_request=agent_request,
        security_events=security_events,
        time_window_ms=5000.0
    )

    # Verify events reached the pipeline and materially impacted risk assessment
    assert trace.telemetry_source == "live_kernel"
    assert len(trace.correlated_kernel_events) == 2
    assert trace.risk_assessment.score >= 50.0
    assert trace.risk_assessment.category in ("HIGH_RISK", "CRITICAL")
    assert trace.recommended_action in ("DENY_ACCESS_AND_ALERT", "CONTAIN_PROCESS_SUSPEND")
