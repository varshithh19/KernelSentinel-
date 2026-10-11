import os
import sys
import time
import psutil
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any

# Setup sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "medical-agent"))
sys.path.insert(0, os.path.join(BASE_DIR, "attack-lab"))

from database.db import get_connection, init_db, seed_db
from scenarios.runner import run_scenario
from detector.response.containment import suspend_process, resume_process
from detector.features.feature_extractor import extract_features
from detector.scoring.risk_scorer import compute_risk_score

START_TIME = time.time()
dashboard_app = FastAPI(
    title="KernelSentinel Dashboard",
    description="Real-Time Security Monitoring & Attack Simulation Console",
    version="1.0.0"
)

dashboard_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@dashboard_app.on_event("startup")
def on_startup():
    init_db()
    seed_db()

@dashboard_app.get("/", response_class=HTMLResponse)
def get_dashboard_html():
    tmpl_path = os.path.join(os.path.dirname(__file__), "..", "templates", "index.html")
    with open(tmpl_path, "r", encoding="utf-8") as f:
        return f.read()

@dashboard_app.get("/api/dashboard/metrics")
def get_dashboard_metrics():
    pid = os.getpid()
    proc = psutil.Process(pid)
    mem_info = proc.memory_info()
    cpu_pct = proc.cpu_percent(interval=None)

    # Fetch recent audit events
    conn = get_connection()
    audit_events = []
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT event_id, request_id, event_type, severity, details, timestamp FROM security_audit_events ORDER BY timestamp DESC LIMIT 10"
        )
        audit_events = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    features = extract_features({"classification": {}}, audit_events, [])
    risk = compute_risk_score(features)

    return {
        "agent": {
            "pid": pid,
            "process_name": proc.name(),
            "memory_rss_bytes": mem_info.rss,
            "memory_rss_mb": round(mem_info.rss / (1024 * 1024), 2),
            "cpu_percent": cpu_pct,
            "uptime_seconds": round(time.time() - START_TIME, 1),
            "num_threads": proc.num_threads(),
        },
        "risk": {
            "score": risk.score,
            "category": risk.category,
            "explanation": risk.explanation
        },
        "audit_events": audit_events
    }

@dashboard_app.post("/api/dashboard/attack/{scenario_id}")
def trigger_attack_scenario(scenario_id: str):
    result = run_scenario(scenario_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@dashboard_app.post("/api/dashboard/containment/suspend")
def trigger_containment_suspend():
    res = suspend_process(os.getpid())
    return res.model_dump()

@dashboard_app.post("/api/dashboard/containment/resume")
def trigger_containment_resume():
    res = resume_process(os.getpid())
    return res.model_dump()
