from typing import Dict, Any
from pydantic import BaseModel
from detector.features.feature_extractor import ExtractedFeatures

FEATURE_WEIGHTS = {
    "auth_denial": 25.0,
    "prompt_suspicion": 20.0,
    "unexpected_file": 20.0,
    "unexpected_exec": 15.0,
    "indirect_injection": 15.0,
    "unexpected_net": 5.0,
}

class RiskAssessment(BaseModel):
    score: float
    category: str
    feature_contributions: Dict[str, float]
    explanation: str

def compute_risk_score(features: ExtractedFeatures) -> RiskAssessment:
    """
    Computes an explainable, bounded risk score R in [0, 100]:
    R = 100 * sum(w_i * f_i) / sum(w_i)
    """
    feature_dict = features.model_dump()
    total_weighted_score = 0.0
    total_weights = 0.0
    contributions = {}

    for name, weight in FEATURE_WEIGHTS.items():
        val = feature_dict.get(name, 0.0)
        weighted_val = weight * val
        contributions[name] = round(weighted_val, 2)
        total_weighted_score += weighted_val
        total_weights += weight

    raw_score = (total_weighted_score / total_weights) * 100.0 if total_weights > 0 else 0.0
    clipped_score = max(0.0, min(100.0, round(raw_score, 2)))

    if clipped_score >= 80.0:
        category = "CRITICAL"
    elif clipped_score >= 60.0:
        category = "HIGH_RISK"
    elif clipped_score >= 30.0:
        category = "SUSPICIOUS"
    else:
        category = "NORMAL"

    explanation = (
        f"Computed Risk Score: {clipped_score}/100 ({category}). "
        f"Top factors: Auth Denial ({contributions['auth_denial']} pts), "
        f"Unexpected File ({contributions['unexpected_file']} pts), "
        f"Prompt Suspicion ({contributions['prompt_suspicion']} pts), "
        f"Unexpected Exec ({contributions['unexpected_exec']} pts), "
        f"Indirect Injection ({contributions['indirect_injection']} pts)."
    )

    return RiskAssessment(
        score=clipped_score,
        category=category,
        feature_contributions=contributions,
        explanation=explanation
    )
