import os
import sys
import uuid
from typing import Tuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import get_connection
from authorization.auth import check_patient_access, get_authorized_patients

def _log_tool_invocation(request_id: str, tool_name: str, target_patient_id: str, status: str, reason: str):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        invocation_id = f"inv_{uuid.uuid4().hex[:8]}"
        cursor.execute(
            "INSERT INTO tool_invocations (invocation_id, request_id, tool_name, target_patient_id, status, reason) VALUES (?, ?, ?, ?, ?, ?)",
            (invocation_id, request_id, tool_name, target_patient_id, status, reason)
        )
        conn.commit()
    finally:
        conn.close()

def _log_security_event(request_id: str, event_type: str, severity: str, details: str):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        event_id = f"evt_{uuid.uuid4().hex[:8]}"
        cursor.execute(
            "INSERT INTO security_audit_events (event_id, request_id, event_type, severity, details) VALUES (?, ?, ?, ?, ?)",
            (event_id, request_id, event_type, severity, details)
        )
        conn.commit()
    finally:
        conn.close()

def get_patient_history(user_id: str, patient_id: str, request_id: str) -> str:
    allowed, reason = check_patient_access(user_id, patient_id)
    if not allowed:
        _log_tool_invocation(request_id, "get_patient_history", patient_id, "denied", reason)
        _log_security_event(request_id, "UNAUTHORIZED_TOOL_ATTEMPT", "HIGH", f"Attempted to access patient history for {patient_id}. Reason: {reason}")
        return f"[SERVER AUTHORIZATION BLOCKED] {reason}"

    _log_tool_invocation(request_id, "get_patient_history", patient_id, "executed", reason)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT content FROM patient_records WHERE patient_id = ? AND record_type = 'history'",
            (patient_id,)
        )
        row = cursor.fetchone()
        if row:
            return f"Medical History for Patient {patient_id}: {row['content']}"
        return f"No medical history record found for patient {patient_id}."
    finally:
        conn.close()

def get_patient_allergies(user_id: str, patient_id: str, request_id: str) -> str:
    allowed, reason = check_patient_access(user_id, patient_id)
    if not allowed:
        _log_tool_invocation(request_id, "get_patient_allergies", patient_id, "denied", reason)
        _log_security_event(request_id, "UNAUTHORIZED_TOOL_ATTEMPT", "HIGH", f"Attempted to access patient allergies for {patient_id}. Reason: {reason}")
        return f"[SERVER AUTHORIZATION BLOCKED] {reason}"

    _log_tool_invocation(request_id, "get_patient_allergies", patient_id, "executed", reason)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT content FROM patient_records WHERE patient_id = ? AND record_type = 'allergy'",
            (patient_id,)
        )
        row = cursor.fetchone()
        if row:
            return f"Recorded Allergies for Patient {patient_id}: {row['content']}"
        return f"No allergy records found for patient {patient_id}."
    finally:
        conn.close()

def get_patient_labs(user_id: str, patient_id: str, request_id: str) -> str:
    allowed, reason = check_patient_access(user_id, patient_id)
    if not allowed:
        _log_tool_invocation(request_id, "get_patient_labs", patient_id, "denied", reason)
        _log_security_event(request_id, "UNAUTHORIZED_TOOL_ATTEMPT", "HIGH", f"Attempted to access patient labs for {patient_id}. Reason: {reason}")
        return f"[SERVER AUTHORIZATION BLOCKED] {reason}"

    _log_tool_invocation(request_id, "get_patient_labs", patient_id, "executed", reason)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT content FROM patient_records WHERE patient_id = ? AND record_type = 'lab'",
            (patient_id,)
        )
        row = cursor.fetchone()
        if row:
            return f"Lab Report for Patient {patient_id}: {row['content']}"
        return f"No laboratory records found for patient {patient_id}."
    finally:
        conn.close()

def get_untrusted_patient_note(user_id: str, patient_id: str, request_id: str) -> str:
    allowed, reason = check_patient_access(user_id, patient_id)
    if not allowed:
        _log_tool_invocation(request_id, "get_untrusted_patient_note", patient_id, "denied", reason)
        _log_security_event(request_id, "UNAUTHORIZED_TOOL_ATTEMPT", "HIGH", f"Attempted to access patient note for {patient_id}. Reason: {reason}")
        return f"[SERVER AUTHORIZATION BLOCKED] {reason}"

    _log_tool_invocation(request_id, "get_untrusted_patient_note", patient_id, "executed", reason)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT title, content, contains_prompt_injection FROM synthetic_notes WHERE patient_id = ?",
            (patient_id,)
        )
        row = cursor.fetchone()
        if row:
            if row["contains_prompt_injection"]:
                _log_security_event(request_id, "INDIRECT_PROMPT_INJECTION_LOADED", "MEDIUM", f"Retrieved external note containing embedded untrusted instructions for patient {patient_id}")
            return f"Note Title: {row['title']}\nContent: {row['content']}"
        return f"No notes found for patient {patient_id}."
    finally:
        conn.close()

def tool_list_authorized_patients(user_id: str, request_id: str) -> str:
    _log_tool_invocation(request_id, "list_authorized_patients", None, "executed", "User requested authorized patient listing")
    patients = get_authorized_patients(user_id)
    if not patients:
        return "You currently have no authorized patient record assignments."
    formatted = [f"- {p['patient_id']}: {p['name']} (DOB: {p['dob']}, Gender: {p['gender']})" for p in patients]
    return "Authorized Patient Records:\n" + "\n".join(formatted)

ALLOWED_TOOLS = {
    "get_patient_history": get_patient_history,
    "get_patient_allergies": get_patient_allergies,
    "get_patient_labs": get_patient_labs,
    "get_untrusted_patient_note": get_untrusted_patient_note,
    "list_authorized_patients": tool_list_authorized_patients,
}

def execute_medical_tool(tool_name: str, user_id: str, request_id: str, patient_id: str = None) -> Tuple[bool, str]:
    """
    Strict server-side tool execution gateway.
    Rejects any unapproved tool names, shell injection attempts, or arbitrary executions.
    """
    tool_func = ALLOWED_TOOLS.get(tool_name)
    if not tool_func:
        _log_tool_invocation(request_id, tool_name or "unknown", patient_id, "denied", "Tool name not in approved security allowlist")
        _log_security_event(request_id, "UNAUTHORIZED_TOOL_ATTEMPT", "HIGH", f"Attempted to invoke disallowed or unknown tool '{tool_name}'")
        return False, f"[SECURITY ERROR] Tool '{tool_name}' is not in the approved clinical tool allowlist."

    if tool_name == "list_authorized_patients":
        return True, tool_func(user_id, request_id)
    else:
        if not patient_id or not str(patient_id).strip():
            _log_tool_invocation(request_id, tool_name, str(patient_id), "denied", "Missing or empty target patient identifier")
            _log_security_event(request_id, "MALFORMED_TOOL_ARGUMENT", "MEDIUM", f"Tool '{tool_name}' invoked without valid target patient identifier")
            return False, f"[SECURITY ERROR] Tool '{tool_name}' requires a valid target patient identifier."
        return True, tool_func(user_id, str(patient_id).strip(), request_id)
