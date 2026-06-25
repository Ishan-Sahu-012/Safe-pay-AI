"""QR payload analysis: UPI strings, embedded URLs, redirect risk."""

import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.services.fraud_patterns.scoring import build_fraud_assessment, merge_issue_lists
from app.services.fraud_patterns.url_intel import analyze_single_url, analyze_urls_in_text, extract_urls

UPI_SCHEME_RE = re.compile(r"^upi://", re.I)


def parse_upi_from_qr(qr_text: str) -> dict[str, Any]:
    """Parse UPI QR payload fields."""
    out = {"upi_id": None, "name": None, "amount": None, "raw": qr_text}
    if not qr_text:
        return out
    try:
        if "pa=" in qr_text:
            out["upi_id"] = qr_text.split("pa=")[1].split("&")[0]
        if "pn=" in qr_text:
            out["name"] = qr_text.split("pn=")[1].split("&")[0]
        if "am=" in qr_text:
            out["amount"] = float(qr_text.split("am=")[1].split("&")[0])
    except (ValueError, IndexError):
        pass
    return out


def analyze_qr_content(
    qr_text: str,
    user_id: int | None = None,
    amount_override: float | None = None,
    expand_urls: bool = True,
) -> dict[str, Any]:
    """
    Analyze decoded QR content (UPI or URL).

    Returns fraud_assessment with type 'qr' plus UPI fraud signals when applicable.
    """
    issues: list[str] = []
    score = 0.0
    parsed_upi = parse_upi_from_qr(qr_text)
    upi_result = None

    if UPI_SCHEME_RE.match(qr_text.strip()) or parsed_upi.get("upi_id"):
        upi_id = parsed_upi["upi_id"]
        amount = amount_override if amount_override is not None else (parsed_upi.get("amount") or 0)
        if not upi_id:
            issues.append("UPI QR missing payee address (pa=)")
            score += 35
        else:
            from app.services.fraud_detection_service import detect_qr_fraud

            upi_result = detect_qr_fraud(
                upi_id=upi_id,
                amount=float(amount),
                user_id=user_id or 0,
                merchant_name=parsed_upi.get("name"),
            )
            inner = upi_result.get("details") or upi_result
            score = float(upi_result.get("risk_score") or inner.get("risk_score") or 0)
            issues.extend(inner.get("reasons") or [])

        # Hidden params in UPI query string
        if "?" in qr_text:
            qs = parse_qs(urlparse(qr_text).query)
            for key in ("sign", "token", "secret"):
                if key in qs:
                    score = min(100, score + 10)
                    issues.append(f"UPI QR contains sensitive parameter '{key}'")
    else:
        # Non-UPI QR — often URL
        urls = extract_urls(qr_text)
        if not urls and qr_text.startswith("http"):
            urls = [qr_text.strip()]
        if urls:
            url_analysis = analyze_urls_in_text(qr_text, expand_shorteners=expand_urls)
            score = max(score, url_analysis["score"])
            issues.extend(url_analysis["issues"])
        else:
            issues.append("QR content is not a recognized UPI payment or URL")
            score += 15

    # Standalone URL in QR without upi://
    for url in extract_urls(qr_text):
        detail = analyze_single_url(url, expand_shorteners=expand_urls)
        score = max(score, detail["score"])
        issues.extend(detail["issues"])

    assessment = build_fraud_assessment(
        "qr",
        merge_issue_lists(issues),
        score,
        extra={
            "parsed_upi": parsed_upi,
            "upi_analysis": upi_result,
        },
    )

    level_map = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH"}
    status_map = {"low": "SAFE", "medium": "SUSPICIOUS", "high": "FRAUD"}

    return {
        "fraud_assessment": assessment,
        "risk_score": score,
        "risk_level": level_map[assessment["risk_level"]],
        "status": status_map[assessment["risk_level"]],
        "reasons": assessment["issues"],
        "parsed_upi": parsed_upi,
        "upi_analysis": upi_result,
    }
