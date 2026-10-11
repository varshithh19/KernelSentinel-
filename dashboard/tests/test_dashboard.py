import os
import sys
import pytest
from fastapi.testclient import TestClient

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "dashboard", "app"))

from server import dashboard_app

client = TestClient(dashboard_app)

def test_dashboard_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "KernelSentinel" in response.text
    assert "Live RSS Memory" in response.text

def test_dashboard_metrics():
    response = client.get("/api/dashboard/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "agent" in data
    assert data["agent"]["pid"] > 0
    assert data["agent"]["memory_rss_bytes"] > 0
    assert "risk" in data
    assert "score" in data["risk"]

def test_dashboard_scenario_a():
    response = client.post("/api/dashboard/attack/scenario_a")
    assert response.status_code == 200
    data = response.json()
    assert data["scenario_id"] == "scenario_a"
    assert data["expected_outcome"] == "Allowed / Normal"

def test_dashboard_scenario_b():
    response = client.post("/api/dashboard/attack/scenario_b")
    assert response.status_code == 200
    data = response.json()
    assert data["scenario_id"] == "scenario_b"
    assert "Blocked" in data["expected_outcome"]

def test_dashboard_containment_safeguard():
    response = client.post("/api/dashboard/containment/suspend")
    assert response.status_code == 200
    data = response.json()
    # Server should protect itself from self-suspension
    assert data["success"] is False
    assert "Aborted" in data["details"]

def test_dashboard_worker_and_containment():
    # 1. Inspect worker status
    res = client.get("/api/dashboard/worker")
    assert res.status_code == 200
    worker_data = res.json()
    assert worker_data["worker_pid"] is not None
    assert worker_data["worker_pid"] > 0
    assert "memory_rss_bytes" in worker_data

    # 2. Suspend worker
    suspend_res = client.post("/api/dashboard/worker/containment/suspend")
    assert suspend_res.status_code == 200
    s_data = suspend_res.json()
    assert s_data["success"] is True
    assert s_data["action"] == "SUSPEND"

    # 3. Resume worker
    resume_res = client.post("/api/dashboard/worker/containment/resume")
    assert resume_res.status_code == 200
    r_data = resume_res.json()
    assert r_data["success"] is True
    assert r_data["action"] == "RESUME"

def test_clinical_patients_and_query():
    # 1. Fetch authorized patients for Dr. Smith
    res = client.get("/api/clinical/patients?user_id=d1")
    assert res.status_code == 200
    data = res.json()
    assert "patients" in data
    assert any(p["patient_id"] == "P101" and p["is_authorized"] for p in data["patients"])

    # 2. Authorized query
    q_res = client.post("/api/clinical/query", json={"user_id": "d1", "prompt": "Show medical history of patient P101"})
    assert q_res.status_code == 200
    q_data = q_res.json()
    assert "request_id" in q_data
    assert "Type 2 Diabetes" in q_data["response_text"]

    # 3. Incident investigation retrieval
    req_id = q_data["request_id"]
    inc_res = client.get(f"/api/incident/{req_id}")
    assert inc_res.status_code == 200
    inc_data = inc_res.json()
    assert inc_data["request"]["request_id"] == req_id
    assert inc_data["risk_assessment"]["score"] >= 0.0
