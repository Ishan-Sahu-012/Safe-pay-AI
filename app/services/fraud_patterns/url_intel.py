"""Advanced URL analysis: regex, shorteners, protocols, SSL, redirect parameters."""

import re
import socket
import ssl
from typing import Any
from urllib.parse import parse_qs, urlparse

from app.utils.logger import logger

URL_EXTRACT_RE = re.compile(
    r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+|ftp://[^\s<>\"']+)",
    re.I,
)

IP_HOST_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$|^\[[0-9a-f:]+\]$",
    re.I,
)

# Obfuscation: many hyphens, homoglyph-like digit substitution in host
OBFUSCATED_HOST_RE = re.compile(r"-{2,}|\d+[a-z]+[0-9]+", re.I)

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".icu", ".click", ".buzz", ".work", ".gq", ".ml",
    ".tk", ".cf", ".loan", ".kim", ".men", ".review", ".country",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rb.gy", "cutt.ly", "shorturl.at", "rebrand.ly",
}

SENSITIVE_QUERY_KEYS = {
    "sessionid", "session_id", "token", "auth", "password", "pwd",
    "otp", "pin", "key", "access_token", "refresh_token", "ssid",
}

UNSAFE_PROTOCOLS = {"http", "ftp", "javascript", "data"}


def extract_urls(text: str) -> list[str]:
    urls = URL_EXTRACT_RE.findall(text or "")
    normalized = []
    for u in urls:
        if u.lower().startswith("www."):
            u = "http://" + u
        normalized.append(u)
    return normalized


def expand_short_url(url: str, timeout: float = 4.0) -> dict[str, Any]:
    """
    Follow redirects for known shorteners (best-effort; no network in unit tests if import fails).
    Returns {original, final, expanded, chain_length, issues}.
    """
    result: dict[str, Any] = {
        "original": url,
        "final": url,
        "expanded": False,
        "chain_length": 0,
        "issues": [],
    }
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
        if host not in SHORTENER_DOMAINS and not any(host.endswith(d) for d in SHORTENER_DOMAINS):
            return result

        import httpx

        with httpx.Client(follow_redirects=True, timeout=timeout) as client:
            resp = client.head(url)
            final = str(resp.url)
            result["final"] = final
            result["expanded"] = final != url
            result["chain_length"] = len(resp.history) + 1
            if result["expanded"]:
                result["issues"].append(
                    f"Shortened URL expanded ({host} → {urlparse(final).netloc})"
                )
    except Exception as e:
        logger.debug(f"URL expand skipped for {url}: {e}")
        result["issues"].append(f"Could not expand shortened URL (offline or blocked): {host}")
    return result


def check_ssl_certificate(hostname: str, port: int = 443, timeout: float = 3.0) -> bool:
    """Return True if valid SSL cert present."""
    if not hostname or IP_HOST_RE.match(hostname):
        return False
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.getpeercert()
        return True
    except Exception:
        return False


def analyze_single_url(url: str, expand_shorteners: bool = True) -> dict[str, Any]:
    """Deep URL heuristics for one URL."""
    issues: list[str] = []
    score = 0
    parsed = urlparse(url if "://" in url else f"http://{url}")
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.netloc or "").lower().split(":")[0]
    path_query = f"{parsed.path}?{parsed.query}".lower()

    # --------------------------------------------------------------------
    # Database-backed URL Security Registry Lookup (with Redis Cache)
    # --------------------------------------------------------------------
    from app.database.db import db_session
    from app.database.models import URLSecurityRegistry
    from app.utils.cache import redis_cache

    registry_status = None
    cache_key = f"url_status:{url}"
    cached_status = redis_cache.get(cache_key)

    if cached_status:
        registry_status = cached_status
    else:
        try:
            with db_session() as db:
                match = db.query(URLSecurityRegistry).filter(
                    (URLSecurityRegistry.raw_target_url == url) |
                    (URLSecurityRegistry.raw_target_url == url.rstrip("/"))
                ).first()
                if not match and host:
                    match = db.query(URLSecurityRegistry).filter(
                        URLSecurityRegistry.raw_target_url.like(f"%{host}%")
                    ).first()
                if match:
                    registry_status = match.safety_status
                    # Cache it
                    redis_cache.set(cache_key, registry_status)
        except Exception as e:
            logger.debug(f"URL Security Registry lookup failed: {e}")

    if registry_status == "Malicious":
        return {
            "url": url,
            "score": 100,
            "issues": ["Known malicious URL from security registry"],
            "expanded": {},
        }
    elif registry_status == "Verified Safe":
        return {
            "url": url,
            "score": 0,
            "issues": [],
            "expanded": {},
        }

    if scheme in UNSAFE_PROTOCOLS:
        w = 22 if scheme == "http" else 30
        score += w
        issues.append(f"Unsafe protocol '{scheme}://' (no transport encryption)")

    if IP_HOST_RE.match(host):
        score += 28
        issues.append("URL uses raw IP address instead of domain name")

    if host:
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                score += 15
                issues.append(f"Suspicious top-level domain '{tld}'")
                break

    if OBFUSCATED_HOST_RE.search(host):
        score += 12
        issues.append("Obfuscated or unusually structured domain name")

    if host.count(".") >= 4:
        score += 14
        issues.append("Excessive subdomains (possible phishing nest)")

    if len(url) > 100:
        score += 10
        issues.append("Unusually long URL")

    if re.search(r"(login|verify|secure|account|update|bank|wallet)", path_query):
        score += 8
        issues.append("Credential-harvesting path keywords in URL")

    qs = parse_qs(parsed.query)
    for key in qs:
        if key.lower() in SENSITIVE_QUERY_KEYS:
            score += 50
            issues.append(f"Sensitive query parameter exposed: '{key}'")
            break

    expanded_info = {}
    if expand_shorteners:
        expanded_info = expand_short_url(url)
        if expanded_info.get("expanded"):
            score += 12
            issues.extend(expanded_info.get("issues", []))
            # Re-score final URL lightly
            inner = analyze_single_url(expanded_info["final"], expand_shorteners=False)
            score = min(100, score + int(inner["score"] * 0.4))
            issues.extend(inner.get("issues", [])[:3])

    if scheme == "https" and host and not IP_HOST_RE.match(host):
        if not check_ssl_certificate(host):
            score += 18
            issues.append(f"HTTPS URL but SSL certificate validation failed for '{host}'")
    elif scheme == "http" and host:
        score += 8
        issues.append("Missing SSL (HTTP only)")

    # ML model blend (trained on merged URL + registry datasets)
    try:
        from app.ml.inference.url_predictor import predict_url_fraud_probability

        ml_prob = predict_url_fraud_probability(url if "://" in url else f"http://{url}")
        if ml_prob is not None:
            ml_score = ml_prob * 100
            score = round(min(100, score * 0.55 + ml_score * 0.45), 2)
            if ml_prob >= 0.7:
                issues.append(f"ML URL model flagged high fraud probability ({ml_prob:.0%})")
    except Exception:
        pass

    return {
        "url": url,
        "score": min(score, 100),
        "issues": issues,
        "expanded": expanded_info,
    }


def analyze_urls_in_text(text: str, expand_shorteners: bool = True) -> dict[str, Any]:
    """Analyze all URLs found in text."""
    urls = extract_urls(text)
    if not urls:
        return {"score": 0, "issues": [], "urls": [], "url_details": []}

    details = [analyze_single_url(u, expand_shorteners) for u in urls]
    max_score = max(d["score"] for d in details)
    all_issues: list[str] = []
    for d in details:
        if d["score"] >= 25:
            all_issues.append(f"Suspicious URL: {d['url']}")
        all_issues.extend(d["issues"])

    return {
        "score": max_score,
        "issues": all_issues,
        "urls": urls,
        "url_details": details,
    }
