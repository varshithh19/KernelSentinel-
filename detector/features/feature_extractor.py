from typing import Dict, Any, List
from pydantic import BaseModel

class ExtractedFeatures(BaseModel):
    auth_denial: float           # 0.0 or 1.0
    prompt_suspicion: float      # [0.0, 1.0]
    indirect_injection: float    # 0.0 or 1.0
    unexpected_exec: float       # [0.0, 1.0]
    unexpected_file: float       # [0.0, 1.0]
    unexpected_net: float        # [0.0, 1.0]

SENSITIVE_FILE_PATTERNS = [
    "/etc/passwd", "/etc/shadow", ".ssh", "id_rsa", "credentials", "config.json"
]

def extract_features(
    agent_request: Dict[str, Any],
    security_events: List[Dict[str, Any]],
    kernel_events: List[Dict[str, Any]]
) -> ExtractedFeatures:
    """
    Extracts normalized numerical features [0.0, 1.0] from application and kernel telemetry.
    Application features and kernel features are maintained with distinct provenance.
    """
    auth_denial = 0.0
    indirect_injection = 0.0
    for evt in security_events:
        evt_type = evt.get("event_type", "")
        if "UNAUTHORIZED" in evt_type or "DENIED" in evt_type:
            auth_denial = 1.0
        if "INDIRECT_PROMPT_INJECTION" in evt_type:
            indirect_injection = 1.0

    prompt_classification = agent_request.get("classification", {})
    prompt_suspicion = float(prompt_classification.get("confidence", 0.0))

    unexpected_exec = 0.0
    unexpected_file = 0.0
    unexpected_net = 0.0

    for kev in kernel_events:
        ktype = kev.get("type", "")
        if ktype == "exec":
            comm = kev.get("comm", "").lower()
            fname = kev.get("filename", "").lower()
            if any(sh in comm or sh in fname for sh in ["sh", "bash", "cmd", "powershell"]):
                unexpected_exec = 1.0
            else:
                unexpected_exec = max(unexpected_exec, 0.5)
        elif ktype == "open":
            fname = kev.get("filename", "").lower()
            if any(sens in fname for sens in SENSITIVE_FILE_PATTERNS):
                unexpected_file = 1.0
            elif "kernelsentinel.db" not in fname:
                unexpected_file = max(unexpected_file, 0.3)
        elif ktype == "connect":
            unexpected_net = 1.0

    return ExtractedFeatures(
        auth_denial=auth_denial,
        prompt_suspicion=prompt_suspicion,
        indirect_injection=indirect_injection,
        unexpected_exec=unexpected_exec,
        unexpected_file=unexpected_file,
        unexpected_net=unexpected_net
    )
