import os
import sys
import time
import psutil
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import init_db, seed_db, get_connection
from authorization.auth import get_authorized_patients, get_user
from agent.core import process_agent_query, AgentResponse

START_TIME = time.time()

app = FastAPI(
    title="KernelSentinel Medical AI Agent API",
    description="Runtime protection of medical AI agents against prompt injection attacks.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()
    seed_db()

class QueryRequest(BaseModel):
    user_id: str
    prompt: str

@app.post("/api/query", response_model=AgentResponse)
def handle_query(req: QueryRequest):
    user = get_user(req.user_id)
    if not user:
        raise HTTPException(status_code=400, detail=f"User ID '{req.user_id}' is invalid.")
    return process_agent_query(req.user_id, req.prompt)

@app.get("/api/patients")
def list_patients(user_id: str = Query(...)):
    user = get_user(user_id)
    if not user:
        raise HTTPException(status_code=400, detail=f"User ID '{user_id}' is invalid.")
    patients = get_authorized_patients(user_id)
    return {"user_id": user_id, "role": user["role"], "authorized_patients": patients}

@app.get("/api/users")
def list_users():
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, username, role, full_name FROM users")
        return {"users": [dict(row) for row in cursor.fetchall()]}
    finally:
        conn.close()

@app.get("/api/audit-logs")
def get_audit_logs(limit: int = 50):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT event_id, request_id, prompt_id, event_type, severity, details, timestamp FROM security_audit_events ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        return {"events": [dict(row) for row in cursor.fetchall()]}
    finally:
        conn.close()

@app.get("/api/health")
def get_process_health():
    pid = os.getpid()
    proc = psutil.Process(pid)
    mem_info = proc.memory_info()
    cpu_percent = proc.cpu_percent(interval=0.1)
    uptime_sec = round(time.time() - START_TIME, 2)

    return {
        "status": "healthy",
        "service": "medical-agent",
        "pid": pid,
        "process_name": proc.name(),
        "memory_rss_bytes": mem_info.rss,
        "memory_rss_mb": round(mem_info.rss / (1024 * 1024), 2),
        "cpu_percent": cpu_percent,
        "uptime_seconds": uptime_sec,
        "num_threads": proc.num_threads()
    }
