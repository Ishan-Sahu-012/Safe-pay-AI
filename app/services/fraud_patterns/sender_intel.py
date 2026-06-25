"""Sender display name vs. channel/domain mismatch detection."""

import re

FREE_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in",
    "hotmail.com", "outlook.com", "live.com", "proton.me", "protonmail.com",
    "icloud.com", "mail.com", "yandex.com", "rediffmail.com",
}

BANK_BRANDS = re.compile(
    r"\b(sbi|hdfc|icici|axis|kotak|paytm|phonepe|google pay|bank|visa|mastercard|rbi)\b",
    re.I,
)


def analyze_sender_mismatch(
    message: str,
    sender: str | None = None,
    sender_email: str | None = None,
) -> dict:
    """
    Flag when message impersonates a bank but sender is a free email or generic short code.
    """
    issues: list[str] = []
    score = 0
    claims_bank = bool(BANK_BRANDS.search(message))
    if not claims_bank:
        return {"score": 0, "issues": issues}

    sender_label = (sender or "").strip()
    email = (sender_email or "").strip().lower()

    if email and "@" in email:
        domain = email.split("@")[-1]
        if domain in FREE_EMAIL_DOMAINS:
            score += 25
            issues.append(
                f"Sender mismatch: message references a bank but email uses free provider '{domain}'"
            )
        display_bank = BANK_BRANDS.search(sender_label or email.split("@")[0])
        if display_bank and domain in FREE_EMAIL_DOMAINS:
            score += 10
            issues.append("Display name suggests bank while domain is a personal email provider")

    # SMS: sender like AD-XXXX vs body claiming to be "Bank Support"
    if sender_label and re.search(r"bank|support|secure|verify", message, re.I):
        if re.match(r"^[A-Z]{2}-[A-Z0-9]+$", sender_label, re.I) or len(sender_label) <= 8:
            if BANK_BRANDS.search(message) and not BANK_BRANDS.search(sender_label):
                score += 12
                issues.append(
                    f"Sender mismatch: institutional language in body but short code sender '{sender_label}'"
                )

    if sender_label and re.search(r"bank support|customer care", sender_label, re.I):
        if email and email.split("@")[-1] in FREE_EMAIL_DOMAINS:
            score += 20
            issues.append(
                f"Sender label '{sender_label}' inconsistent with free email domain"
            )

    return {"score": min(score, 100), "issues": issues}
