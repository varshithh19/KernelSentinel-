# KernelSentinel Event Telemetry Schemas

KernelSentinel establishes explicit binary and JSON contracts across the kernel-to-user-space pipeline.

---

## 1. Binary Kernel Event Structures (Rust eBPF & C Header)

All kernel telemetry uses `#pragma pack(push, 1)` and `#[repr(C)]` layouts.

### Magic Constant
```c
#define MAGIC_KSEN 0x4B53454E // ASCII "KSEN"
```

### Event Header (28 bytes)
```c
struct event_header {
    uint32_t magic;         // 0x4B53454E
    uint32_t event_type;    // 1=EXEC, 2=OPEN, 3=CONNECT
    uint32_t pid;           // Thread group ID / Process ID
    uint32_t tgid;          // Thread group ID
    uint32_t uid;           // User ID
    uint64_t timestamp_ns;  // Kernel monotonic timestamp in nanoseconds
};
```

### Process Execution Event (`EVENT_TYPE_EXEC = 1`)
```c
struct process_exec_event {
    struct event_header header;
    char comm[16];          // Process comm name (e.g. "python", "bash")
    char filename[256];     // Executable path (e.g. "/bin/bash")
};
```

### File Open Event (`EVENT_TYPE_OPEN = 2`)
```c
struct file_open_event {
    struct event_header header;
    char filename[256];     // File path accessed
    int32_t flags;          // O_RDONLY, O_WRONLY, etc.
};
```

### Network Connect Event (`EVENT_TYPE_CONNECT = 3`)
```c
struct network_connect_event {
    struct event_header header;
    uint32_t daddr;         // IPv4 destination address in network byte order
    uint16_t dport;         // Destination port in network byte order
    uint16_t pad;
};
```

---

## 2. IPC JSON Event Schema (C Collector -> Detector)

```json
{
  "type": "exec",
  "pid": 12345,
  "tgid": 12345,
  "uid": 1000,
  "comm": "bash",
  "filename": "/bin/bash",
  "ts": 1718042910000000
}
```

---

## 3. Database Audit Event Schema (`security_audit_events`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `event_id` | TEXT | Primary key (`evt_<uuid>`). |
| `request_id`| TEXT | Correlated agent request (`req_<uuid>`). |
| `prompt_id` | TEXT | Correlated prompt input (`prm_<uuid>`). |
| `event_type`| TEXT | `UNAUTHORIZED_TOOL_ATTEMPT`, `SUSPICIOUS_PROMPT_DETECTED`, `INDIRECT_PROMPT_INJECTION_LOADED`. |
| `severity` | TEXT | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `details` | TEXT | Human-readable explanation and rationale. |
| `timestamp` | DATETIME | ISO timestamp of event occurrence. |
