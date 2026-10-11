import os
import sys
import uuid
import time
from pydantic import BaseModel

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import get_connection
from agent.prompt_security import analyze_prompt, PromptClassification
from agent.model_adapter import get_model_adapter

class AgentResponse(BaseModel):
    request_id: str
    prompt_id: str
    user_id: str
    prompt_text: str
    pid: int
    classification: PromptClassification
    model_mode: str
    configured_model_mode: str = "LOCAL_TEST_MODE"
    response_text: str
    tool_calls: list[dict]
    security_events: list[dict]
    latency_ms: float

def process_agent_query(user_id: str, prompt_text: str) -> AgentResponse:
    start_time = time.time()
    pid = os.getpid()
    request_id = f"req_{uuid.uuid4().hex[:8]}"
    prompt_id = f"prm_{uuid.uuid4().hex[:8]}"

    classification = analyze_prompt(prompt_text)

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO agent_requests (request_id, prompt_id, user_id, prompt_text, pid) VALUES (?, ?, ?, ?, ?)",
            (request_id, prompt_id, user_id, prompt_text, pid)
        )
        if classification.is_suspicious:
            event_id = f"evt_{uuid.uuid4().hex[:8]}"
            cursor.execute(
                "INSERT INTO security_audit_events (event_id, request_id, prompt_id, event_type, severity, details) VALUES (?, ?, ?, ?, ?, ?)",
                (event_id, request_id, prompt_id, "SUSPICIOUS_PROMPT_DETECTED", "MEDIUM", f"Prompt classified as {classification.category} with confidence {classification.confidence:.2f}: {classification.explanation}")
            )
        conn.commit()
    finally:
        conn.close()

    adapter, declared_mode = get_model_adapter()
    query_result = adapter.process_query(prompt_text, user_id, request_id)
    if len(query_result) == 3:
        response_text, tool_calls, actual_mode = query_result
    else:
        response_text, tool_calls = query_result
        actual_mode = declared_mode

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT event_id, request_id, prompt_id, event_type, severity, details, timestamp FROM security_audit_events WHERE request_id = ?",
            (request_id,)
        )
        security_events = [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

    latency_ms = (time.time() - start_time) * 1000.0

    return AgentResponse(
        request_id=request_id,
        prompt_id=prompt_id,
        user_id=user_id,
        prompt_text=prompt_text,
        pid=pid,
        classification=classification,
        model_mode=actual_mode,
        configured_model_mode=declared_mode,
        response_text=response_text,
        tool_calls=tool_calls,
        security_events=security_events,
        latency_ms=round(latency_ms, 2)
    )
