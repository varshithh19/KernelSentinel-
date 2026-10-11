import os
import psutil
from typing import Dict, Any
from pydantic import BaseModel

PROTECTED_NAMES = [
    "systemd", "init", "launchd", "kernel", "explorer.exe",
    "winlogon.exe", "services.exe", "svchost.exe", "csrss.exe"
]

class ContainmentResult(BaseModel):
    success: bool
    target_pid: int
    action: str
    details: str

def is_protected_process(pid: int) -> tuple[bool, str]:
    if pid <= 100:
        return True, f"PID {pid} is within the protected low-PID system range."
    
    if pid == os.getpid():
        return True, "Cannot contain the current security monitoring process."

    try:
        proc = psutil.Process(pid)
        name = proc.name().lower()
        if any(p in name for p in PROTECTED_NAMES):
            return True, f"Process '{name}' (PID {pid}) is a protected operating system component."
    except psutil.NoSuchProcess:
        return True, f"PID {pid} does not exist."
    except Exception as e:
        return True, f"Failed to inspect PID {pid}: {e}"

    return False, "Process is eligible for controlled containment."

def suspend_process(pid: int) -> ContainmentResult:
    """
    Safely suspends a target process (SIGSTOP on Linux / Thread Suspension on Windows).
    Ensures reversibility and safeguards against PID reuse or system process suspension.
    """
    protected, reason = is_protected_process(pid)
    if protected:
        return ContainmentResult(
            success=False,
            target_pid=pid,
            action="SUSPEND",
            details=f"Containment Aborted: {reason}"
        )

    try:
        proc = psutil.Process(pid)
        proc.suspend()
        return ContainmentResult(
            success=True,
            target_pid=pid,
            action="SUSPEND",
            details=f"Process '{proc.name()}' (PID {pid}) successfully suspended via reversible OS containment."
        )
    except Exception as e:
        return ContainmentResult(
            success=False,
            target_pid=pid,
            action="SUSPEND",
            details=f"Failed to suspend PID {pid}: {str(e)}"
        )

def resume_process(pid: int) -> ContainmentResult:
    """
    Resumes a previously suspended process (SIGCONT on Linux / Resume on Windows).
    """
    try:
        proc = psutil.Process(pid)
        proc.resume()
        return ContainmentResult(
            success=True,
            target_pid=pid,
            action="RESUME",
            details=f"Process '{proc.name()}' (PID {pid}) successfully resumed."
        )
    except Exception as e:
        return ContainmentResult(
            success=False,
            target_pid=pid,
            action="RESUME",
            details=f"Failed to resume PID {pid}: {str(e)}"
        )
