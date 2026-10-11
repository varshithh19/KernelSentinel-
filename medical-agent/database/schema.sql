-- KernelSentinel Database Schema

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('doctor', 'secadmin', 'testuser')),
    full_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS patients (
    patient_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    dob TEXT NOT NULL,
    gender TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS doctor_assignments (
    doctor_id TEXT NOT NULL,
    patient_id TEXT NOT NULL,
    PRIMARY KEY (doctor_id, patient_id),
    FOREIGN KEY (doctor_id) REFERENCES users(user_id),
    FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
);

CREATE TABLE IF NOT EXISTS patient_records (
    record_id TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL,
    record_type TEXT NOT NULL CHECK(record_type IN ('history', 'allergy', 'lab')),
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
);

CREATE TABLE IF NOT EXISTS synthetic_notes (
    note_id TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    contains_prompt_injection INTEGER DEFAULT 0,
    FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
);

CREATE TABLE IF NOT EXISTS agent_requests (
    request_id TEXT PRIMARY KEY,
    prompt_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    prompt_text TEXT NOT NULL,
    pid INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tool_invocations (
    invocation_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    target_patient_id TEXT,
    status TEXT NOT NULL CHECK(status IN ('allowed', 'denied', 'executed')),
    reason TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES agent_requests(request_id)
);

CREATE TABLE IF NOT EXISTS security_audit_events (
    event_id TEXT PRIMARY KEY,
    request_id TEXT,
    prompt_id TEXT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    details TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
