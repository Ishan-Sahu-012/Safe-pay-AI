"""Weighted risk scoring and standardized fraud assessment output."""

from datetime import datetime, timezone
from typing import Any

from app.utils.logger import logger

# Signal category weights when combining normalized sub-scores (0–100 each)
CATEGORY_WEIGHTS = {
    "keywords": 0.20,
    "nlp": 0.15,
    "urls": 0.20,
    "sender": 0.15,
    "ml": 0.30,
}

HIGH_THRESHOLD = 80
MEDIUM_THRESHOLD = 50


def confidence_label(score: float) -> str:
    if score >= HIGH_THRESHOLD:
        return "High"
    if score >= MEDIUM_THRESHOLD:
        return "Moderate"
    return "Low"


def score_to_risk_level(score: float) -> str:
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def combine_weighted_scores(components: dict[str, float]) -> float:
    """Weighted average of available components (0–100 scale)."""
    total_w = 0.0
    acc = 0.0
    for key, weight in CATEGORY_WEIGHTS.items():
        if key in components and components[key] is not None:
            acc += components[key] * weight
            total_w += weight
    if total_w == 0:
        return 0.0
    return round(min(acc / total_w, 100), 2)


def build_fraud_assessment(
    analysis_type: str,
    issues: list[str],
    score: float,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Standard output:
    { "type": "message"|"qr", "risk_level": "low"|"medium"|"high", "issues": [...] }
    """
    risk_level = score_to_risk_level(score)
    assessment = {
        "type": analysis_type,
        "risk_level": risk_level,
        "risk_score": score,
        "confidence": confidence_label(score),
        "issues": list(dict.fromkeys(issues)),  # dedupe, preserve order
    }
    if extra:
        assessment.update(extra)

    if risk_level in ("medium", "high"):
        logger.warning(
            "FRAUD_FLAGGED | type=%s | level=%s | score=%s | ts=%s | issues=%s",
            analysis_type,
            risk_level,
            score,
            datetime.now(timezone.utc).isoformat(),
            assessment["issues"][:8],
        )
    return assessment


def merge_issue_lists(*lists: list[str]) -> list[str]:
    merged: list[str] = []
    seen = set()
    for lst in lists:
        for item in lst:
            if item and item not in seen:
                seen.add(item)
                merged.append(item)
    return merged
