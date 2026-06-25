"""Weighted phishing / scam keyword registry — extend PHISHING_KEYWORD_WEIGHTS to add patterns."""

# Higher weight = stronger phishing signal
PHISHING_KEYWORD_WEIGHTS: dict[str, int] = {
    # Urgency and pressure
    "urgent": 16,
    "immediately": 15,
    "act now": 15,
    "limited time": 14,
    "last chance": 14,
    "final warning": 14,
    "within 24 hours": 14,
    "next 6 hours": 14,
    "or else": 14,
    "failure to act": 14,
    "must comply": 14,
    "suspension": 15,
    "deactivate": 15,
    "blocked": 18,
    "suspended": 15,
    "expired": 12,
    "penalty": 13,

    # Authority, verification and account pressure
    "verify": 15,
    "verification": 12,
    "confirm": 12,
    "authenticate": 14,
    "secure": 13,
    "account": 8,
    "login": 10,
    "password": 20,
    "otp": 20,
    "pin": 18,
    "confidential": 14,
    "update details": 14,
    "identity check": 15,

    # Financial lure
    "prize": 16,
    "lottery": 16,
    "winner": 18,
    "jackpot": 16,
    "bonus": 14,
    "reward": 14,
    "free": 10,
    "cash": 14,
    "refund": 12,
    "claim": 13,
    "offer": 12,
    "discount": 12,
    "guaranteed": 15,
    "cashback": 12,
    "transfer": 11,
    "pay now": 14,

    # Suspicious links and attachments
    "click here": 16,
    "click link": 16,
    "access link": 15,
    "scan qr": 15,
    "scan qrcode": 15,
    "download": 11,
    "attachment": 12,
    "open file": 12,
    "reset": 11,
    "unlock": 12,
    "continue": 8,
    "link": 8,

    # Greetings and generic social engineering
    "dear user": 10,
    "valued customer": 10,
    "sir/madam": 10,
    "friend": 8,
    "subscriber": 8,
    "dear customer": 10,

    # General scam signals
    "security": 10,
    "alert": 9,
    "limited": 10,
    "account update": 12,
    "bank": 9,
    "refund": 12,
    "claim": 13,
    "free": 10,
    "offer": 12,
    "update your": 12,
    "irs": 15,
    "tax": 8,
}


def score_keywords(text: str) -> tuple[int, list[str], list[str]]:
    """Return (score, matched_keywords, issues)."""
    lower = text.lower()
    matched: list[str] = []
    issues: list[str] = []
    score = 0
    for keyword, weight in PHISHING_KEYWORD_WEIGHTS.items():
        if keyword in lower:
            matched.append(keyword)
            score += weight
            issues.append(f"Phishing keyword detected: '{keyword}' (+{weight})")
    return min(score, 100), matched, issues
