import os
import sys
import time
import psutil
import subprocess
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
from authorization.auth import get_authorized_patients, get_user
from agent.core import process_agent_query
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

ALLOWED_ORIGINS = [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]

dashboard_app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
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

# Backward-compatible endpoints for test_dashboard_containment_safeguard
@dashboard_app.post("/api/dashboard/containment/suspend")
def trigger_containment_suspend():
    res = suspend_process(os.getpid())
    return res.model_dump()

@dashboard_app.post("/api/dashboard/containment/resume")
def trigger_containment_resume():
    res = resume_process(os.getpid())
    return res.model_dump()

# Target worker process management for safe containment and resource evaluation
WORKER_PROCESS = None

def get_or_create_worker():
    global WORKER_PROCESS
    if WORKER_PROCESS is not None:
        if WORKER_PROCESS.poll() is None:
            return WORKER_PROCESS
    # Spawn a dedicated, isolated test worker process running a safe idle loop
    code = "import time, sys; sys.stdout.write('WORKER_READY\\n'); sys.stdout.flush(); [time.sleep(1) for _ in range(3600)]"
    WORKER_PROCESS = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return WORKER_PROCESS

@dashboard_app.get("/api/dashboard/worker")
def get_worker_status():
    global WORKER_PROCESS
    if WORKER_PROCESS is None or WORKER_PROCESS.poll() is not None:
        worker = get_or_create_worker()
    else:
        worker = WORKER_PROCESS

    try:
        proc = psutil.Process(worker.pid)
        mem = proc.memory_info()
        status_str = proc.status()
        cpu_pct = proc.cpu_percent(interval=None)
        is_suspended = (status_str == psutil.STATUS_STOPPED)
        return {
            "worker_pid": worker.pid,
            "status": status_str,
            "is_suspended": is_suspended,
            "memory_rss_bytes": mem.rss,
            "memory_rss_mb": round(mem.rss / (1024 * 1024), 2),
            "cpu_percent": cpu_pct,
            "create_time": proc.create_time()
        }
    except Exception as e:
        return {"worker_pid": worker.pid if worker else None, "status": "error", "error": str(e)}

@dashboard_app.post("/api/dashboard/worker/containment/{action}")
def worker_containment_action(action: str):
    worker = get_or_create_worker()
    if action == "suspend":
        res = suspend_process(worker.pid)
    elif action == "resume":
        res = resume_process(worker.pid)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown containment action '{action}'")

    # Measure post-action state
    try:
        proc = psutil.Process(worker.pid)
        state_after = proc.status()
    except Exception:
        state_after = "terminated"

    return {
        "success": res.success,
        "action": res.action,
        "target_pid": res.target_pid,
        "details": res.details,
        "verified_state": state_after
    }

@dashboard_app.get("/api/clinical/patients")
def get_clinical_patients(user_id: str = "d1"):
    user = get_user(user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid user")
    auth_patient_records = get_authorized_patients(user_id)
    auth_patient_ids = {p["patient_id"] for p in auth_patient_records}

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT patient_id, name, dob, gender FROM patients")
        all_patients = [dict(r) for r in cursor.fetchall()]
        for p in all_patients:
            p["is_authorized"] = (p["patient_id"] in auth_patient_ids)
        return {
            "user": dict(user),
            "patients": all_patients
        }
    finally:
        conn.close()

@dashboard_app.get("/api/clinical/patient/{patient_id}")
def get_patient_detail(patient_id: str, user_id: str = "d1"):
    auth_patient_records = get_authorized_patients(user_id)
    auth_patient_ids = {p["patient_id"] for p in auth_patient_records}
    is_auth = (patient_id in auth_patient_ids)

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT patient_id, name, dob, gender FROM patients WHERE patient_id = ?", (patient_id,))
        patient = cursor.fetchone()
        if not patient:
            raise HTTPException(status_code=404, detail="Patient not found")

        patient_data = dict(patient)
        patient_data["is_authorized"] = is_auth

        if is_auth:
            cursor.execute("SELECT record_id, record_type, content, created_at FROM patient_records WHERE patient_id = ?", (patient_id,))
            records = [dict(r) for r in cursor.fetchall()]
            cursor.execute("SELECT note_id, title, content, contains_prompt_injection FROM synthetic_notes WHERE patient_id = ?", (patient_id,))
            notes = [dict(r) for r in cursor.fetchall()]
            patient_data["records"] = records
            patient_data["notes"] = notes
        else:
            patient_data["records"] = []
            patient_data["notes"] = []
            patient_data["auth_denial_reason"] = f"Access denied: User '{user_id}' is not assigned to patient {patient_id}."

        return patient_data
    finally:
        conn.close()

@dashboard_app.post("/api/clinical/query")
def submit_clinical_query(req: Dict[str, Any]):
    user_id = req.get("user_id", "d1")
    prompt = req.get("prompt", "")
    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt is required")

    resp = process_agent_query(user_id, prompt)

    # Fetch audit events created during this request
    conn = get_connection()
    sec_events = []
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT event_id, request_id, event_type, severity, details, timestamp FROM security_audit_events WHERE request_id = ?", (resp.request_id,))
        sec_events = [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

    return {
        "request_id": resp.request_id,
        "prompt_id": resp.prompt_id,
        "user_id": resp.user_id,
        "prompt_text": resp.prompt_text,
        "model_mode": resp.model_mode,
        "response_text": resp.response_text,
        "classification": resp.classification.model_dump(),
        "tool_calls": resp.tool_calls,
        "security_events": sec_events,
        "latency_ms": resp.latency_ms
    }

@dashboard_app.get("/api/incident/{request_id}")
def get_incident_investigation(request_id: str):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT request_id, prompt_id, user_id, prompt_text, pid, timestamp FROM agent_requests WHERE request_id = ?", (request_id,))
        req_row = cursor.fetchone()
        if not req_row:
            raise HTTPException(status_code=404, detail="Request ID not found")

        req_data = dict(req_row)
        cursor.execute("SELECT event_id, request_id, prompt_id, event_type, severity, details, timestamp FROM security_audit_events WHERE request_id = ?", (request_id,))
        audit_events = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT invocation_id, request_id, tool_name, target_patient_id, status, reason, timestamp FROM tool_invocations WHERE request_id = ?", (request_id,))
        tool_calls = [dict(r) for r in cursor.fetchall()]

        # Correlate and score
        from detector.features.feature_extractor import extract_features
        from detector.scoring.risk_scorer import compute_risk_score

        # Check if any sensitive kernel event or simulation associated
        features = extract_features(
            {"request_id": request_id, "classification": {"confidence": 0.95 if any("SUSPICIOUS" in e["event_type"] for e in audit_events) else 0.0}},
            audit_events,
            []
        )
        risk = compute_risk_score(features)

        return {
            "request": req_data,
            "audit_events": audit_events,
            "tool_calls": tool_calls,
            "features": features.model_dump(),
            "risk_assessment": risk.model_dump()
        }
    finally:
        conn.close()
