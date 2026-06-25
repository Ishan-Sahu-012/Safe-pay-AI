"""NLP-style pattern detectors for scam messages (regex + heuristics)."""

import re
from typing import Any

# Each entry: (compiled_pattern, issue_label, weight)
URGENCY_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(urgent|asap|immediately|act now|within \d+ hours?)\b", re.I), "Urgency pressure tactic", 12),
    (re.compile(r"!{2,}"), "Excessive urgency punctuation", 8),
    (re.compile(r"\b(last chance|final notice|expires today)\b", re.I), "Deadline pressure", 10),
]

FEAR_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(blocked|suspended|frozen|terminated|compromised|hacked|deactivate|suspension)\b", re.I), "Fear / account threat language", 14),
    (re.compile(r"\b(legal action|arrest|penalty|fine)\b", re.I), "Legal threat intimidation", 12),
    (re.compile(r"\b(unauthorized|suspicious activity|unusual activity|confidential|identity check)\b", re.I), "False security alert", 10),
]

FINANCIAL_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(send money|wire transfer|bitcoin|crypto|gift card|upi pin|jackpot|lottery|prize|winner|bonus|reward|cash|refund|claim|offer|discount|free|guaranteed)\b", re.I), "Financial extraction or lure", 16),
    (re.compile(r"\b(pay\s*(now|immediately)|transfer\s+₹|rs\.?\s*\d+)\b", re.I), "Payment demand", 12),
]

AUTHORITY_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(verify|confirmation|confirm|authenticate|secure|account|login|password|otp|pin|confidential|update details|identity check)\b", re.I), "Authority or verification pressure", 14),
    (re.compile(r"\b(update your|account update|security alert)\b", re.I), "Account/security update request", 12),
]

LINK_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(click here|click link|access link|scan qr|scan qrcode|download|attachment|open file|reset|unlock|continue)\b", re.I), "Suspicious link or attachment prompt", 15),
    (re.compile(r"\b(visit|go to)\s+(the\s+)?(link|website|page)\b", re.I), "Suspicious redirect language", 12),
]

GREETING_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(dear user|dear customer|valued customer|sir/madam|friend|subscriber)\b", re.I), "Generic scam greeting", 10),
]

PRESSURE_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(within 24 hours|next 6 hours|immediately|act now|or else|failure to act|must comply|final warning|last chance|limited time)\b", re.I), "Urgency pressure tactic", 14),
]

IMPERSONATION_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(sbi|hdfc|icici|axis|paytm|phonepe|google pay|gpay|rbi|income tax)\b", re.I), "Institution name referenced", 6),
    (re.compile(r"\b(bank support|customer care|helpdesk|it department)\b", re.I), "Support impersonation", 12),
    (re.compile(r"\b(ceo|manager|hr department)\b", re.I), "Authority impersonation", 10),
]


def _run_patterns(text: str, patterns: list[tuple[re.Pattern, str, int]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for pattern, label, weight in patterns:
        if pattern.search(text):
            hits.append({"signal": label, "weight": weight, "category": "nlp"})
    return hits


def detect_nlp_signals(text: str) -> dict[str, Any]:
    """Detect urgency, fear, financial requests, and impersonation cues."""
    signals: list[dict[str, Any]] = []
    signals.extend(_run_patterns(text, URGENCY_PATTERNS))
    signals.extend(_run_patterns(text, FEAR_PATTERNS))
    signals.extend(_run_patterns(text, FINANCIAL_PATTERNS))
    signals.extend(_run_patterns(text, AUTHORITY_PATTERNS))
    signals.extend(_run_patterns(text, LINK_PATTERNS))
    signals.extend(_run_patterns(text, GREETING_PATTERNS))
    signals.extend(_run_patterns(text, PRESSURE_PATTERNS))
    signals.extend(_run_patterns(text, IMPERSONATION_PATTERNS))

    # ALL CAPS shouting (legit alerts rarely use >40% caps in long messages)
    if len(text) > 20:
        caps = sum(1 for c in text if c.isupper())
        if caps / len(text) >= 0.4:
            signals.append({"signal": "Aggressive capitalization", "weight": 10, "category": "nlp"})

    issues = [s["signal"] for s in signals]
    score = min(sum(s["weight"] for s in signals), 100)
    return {"score": score, "signals": signals, "issues": issues}
