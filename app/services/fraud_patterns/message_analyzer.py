"""Message / SMS / email fraud analysis orchestrator."""

from typing import Any

from app.ml.inference.text_predictor import predict_text_scam
from app.services.fraud_patterns.keywords import score_keywords
from app.services.fraud_patterns.nlp_signals import detect_nlp_signals
from app.services.fraud_patterns.scoring import (
    build_fraud_assessment,
    combine_weighted_scores,
    merge_issue_lists,
)
from app.services.fraud_patterns.sender_intel import analyze_sender_mismatch
from app.services.fraud_patterns.url_intel import analyze_urls_in_text


def _build_summary(status: str, score: float, reasons: list[str]) -> str:
    if status == "SCAM":
        return (
            "This message shows strong scam indicators and should be treated as fraudulent. "
            + (reasons[0] if reasons else "Review the message carefully.")
        )
    if status == "SUSPICIOUS":
        return (
            "This message appears suspicious and warrants extra caution. "
            + (reasons[0] if reasons else "Verify the sender and do not click unexpected links.")
        )
    return "No strong fraudulent signals were detected, but always verify unexpected requests before responding."


def _build_recommendation(status: str) -> str:
    if status == "SCAM":
        return "Do not respond, do not click links, and verify the sender through official channels."
    if status == "SUSPICIOUS":
        return "Verify the sender independently and avoid sharing any sensitive information."
    return "Proceed with normal caution and ignore any requests for passwords, OTPs or account updates."


def analyze_message(
    text: str,
    sender: str | None = None,
    sender_email: str | None = None,
    use_ml: bool = True,
    expand_urls: bool = True,
) -> dict[str, Any]:
    """
    Full message fraud analysis with weighted scoring.

    Returns fraud_assessment JSON plus legacy-compatible fields.
    """
    if not text or len(text.strip()) < 3:
        assessment = build_fraud_assessment("message", ["Message too short to analyze"], 0)
        return {"fraud_assessment": assessment, "risk_score": 0, "risk_level": "LOW", "reasons": assessment["issues"]}

    kw_score, matched_kw, kw_issues = score_keywords(text)
    nlp = detect_nlp_signals(text)
    url = analyze_urls_in_text(text, expand_shorteners=expand_urls)
    sender_intel = analyze_sender_mismatch(text, sender=sender, sender_email=sender_email)

    ml_score = 0.0
    ml_issues: list[str] = []
    if use_ml:
        try:
            ml_result = predict_text_scam(text)
            ml_score = float(ml_result.get("risk_score", 0) or 0)
            ml_issues = list(ml_result.get("explanation") or [])
        except Exception:
            ml_issues = ["ML model unavailable; rule-only scoring applied"]

    components_dict = {
        "keywords": kw_score,
        "nlp": nlp["score"],
        "urls": url["score"],
    }
    if sender or sender_email:
        components_dict["sender"] = sender_intel["score"]
    if use_ml:
        components_dict["ml"] = ml_score

    combined_score = combine_weighted_scores(components_dict)

    # If the ML model is strongly convinced of fraud, let that signal take priority.
    if use_ml and ml_score and ml_score > combined_score:
        combined_score = ml_score

    # Explicit sender/domain mismatch is a strong phishing marker.
    if sender_intel["issues"]:
        combined_score = min(100, round(combined_score + 15, 2))

    all_issues = merge_issue_lists(
        kw_issues,
        nlp["issues"],
        url["issues"],
        sender_intel["issues"],
        ml_issues,
    )

    assessment = build_fraud_assessment(
        "message",
        all_issues,
        combined_score,
        extra={
            "matched_keywords": matched_kw,
            "urls_found": url.get("urls", []),
            "components": {
                "keywords": kw_score,
                "nlp": nlp["score"],
                "urls": url["score"],
                "sender": sender_intel["score"],
                "ml": ml_score,
            },
        },
    )

    status_map = {"low": "SAFE", "medium": "SUSPICIOUS", "high": "SCAM"}
    status = status_map[assessment["risk_level"]]
    summary = _build_summary(status, combined_score, all_issues)
    recommendation = _build_recommendation(status)

    return {
        "fraud_assessment": assessment,
        "risk_score": combined_score,
        "risk_level": assessment["risk_level"].upper(),
        "status": status,
        "confidence": assessment["confidence"],
        "summary": summary,
        "recommendation": recommendation,
        "reasons": assessment["issues"],
        "matched_keywords": matched_kw,
        "url_analysis": url,
        "nlp_signals": nlp.get("signals", []),
        "components": assessment.get("components", {}),
    }
