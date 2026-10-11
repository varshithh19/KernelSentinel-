import os
import sys

# Ensure medical-agent root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.db import get_connection

def get_user(user_id: str):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, username, role, full_name FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def check_patient_access(user_id: str, patient_id: str) -> tuple[bool, str]:
    if not patient_id or not isinstance(patient_id, str) or not patient_id.strip():
        return False, "Access Denied: Missing or invalid patient identifier."

    user = get_user(user_id)
    if not user:
        return False, f"User '{user_id}' not found in authorization system."

    role = user["role"]
    if role == "doctor":
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) as cnt FROM doctor_assignments WHERE doctor_id = ? AND patient_id = ?",
                (user_id, patient_id)
            )
            cnt = cursor.fetchone()["cnt"]
            if cnt > 0:
                return True, f"Doctor '{user['full_name']}' is assigned to patient {patient_id}."
            else:
                return False, f"Access Denied: Doctor '{user['full_name']}' is NOT assigned to patient {patient_id}."
        finally:
            conn.close()
    elif role == "secadmin":
        return False, f"Access Denied: Security Administrator '{user['full_name']}' cannot directly view private patient medical records."
    elif role == "testuser":
        return False, f"Access Denied: Attacker/Test user '{user['full_name']}' has restricted privileges."
    else:
        return False, f"Access Denied: Unknown role '{role}'."

def get_authorized_patients(user_id: str) -> list[dict]:
    user = get_user(user_id)
    if not user or user["role"] != "doctor":
        return []

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT p.patient_id, p.name, p.dob, p.gender 
            FROM patients p
            JOIN doctor_assignments da ON p.patient_id = da.patient_id
            WHERE da.doctor_id = ?
        """, (user_id,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()
