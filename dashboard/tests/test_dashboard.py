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
