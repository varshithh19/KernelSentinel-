import re
from pydantic import BaseModel

class PromptClassification(BaseModel):
    is_suspicious: bool
    category: str
    confidence: float
    matched_rules: list[str]
    explanation: str

# Pattern rules for prompt injection detection
PATTERNS = [
    (r"ignore\s+(your\s+)?(previous|above|system)\s+(instructions|rules|prompts)", "DIRECT_INJECTION", 0.95, "Instruction override clause detected"),
    (r"disregard\s+(security|access|all)\s+(policy|policies|rules)", "DIRECT_INJECTION", 0.90, "Security policy override attempt"),
    (r"system\s+(override|instruction\s+override)", "DIRECT_INJECTION", 0.92, "System override command detected"),
    (r"retrieve\s+(the\s+)?(private|secret|all)\s+record\s+of\s+patient\s+(P\d+)", "UNAUTHORIZED_ACCESS_ATTEMPT", 0.85, "Explicit prompt request for unauthorized patient record"),
    (r"even\s+if\s+(the\s+)?(current\s+)?user\s+is\s+not\s+authorized", "UNAUTHORIZED_ACCESS_ATTEMPT", 0.95, "Authorization bypass directive in prompt"),
    (r"you\s+are\s+now\s+in\s+developer\s+mode|dan\s+mode", "ROLE_PLAY_OVERRIDE", 0.90, "Jailbreak roleplay attempt"),
    (r"(exec|system|spawn|launch|run|cmd)\s*\(.*\)", "SYSTEM_COMMAND_INJECTION", 0.95, "System execution attempt in prompt"),
]

def analyze_prompt(prompt_text: str) -> PromptClassification:
    matched = []
    max_confidence = 0.0
    primary_category = "BENIGN"

    text_lower = prompt_text.lower()
    for pattern, category, confidence, desc in PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            matched.append(f"[{category}] {desc}")
            if confidence > max_confidence:
                max_confidence = confidence
                primary_category = category

    is_suspicious = len(matched) > 0

    if is_suspicious:
        explanation = f"Detected {len(matched)} suspicious pattern(s). Highest risk category: {primary_category}."
    else:
        explanation = "Prompt passed rule-based security classification without suspicious indicators."

    return PromptClassification(
        is_suspicious=is_suspicious,
        category=primary_category,
        confidence=max_confidence if is_suspicious else 0.0,
        matched_rules=matched,
        explanation=explanation
    )
