"""Smoke-test all SafePay API endpoints."""
import json
import sys
import uuid

import httpx

BASE = "http://127.0.0.1:8000"
PHONE = f"9{uuid.uuid4().int % 1_000_000_000:09d}"
EMAIL = f"test_{uuid.uuid4().hex[:8]}@example.com"
PASSWORD = "TestPass123!"


def main():
    client = httpx.Client(base_url=BASE, timeout=60.0)
    results = []
    token = None

    def record(name, resp, ok_extra=None):
        ok = 200 <= resp.status_code < 300
        if ok_extra:
            ok = ok and ok_extra(resp)
        results.append(
            {
                "endpoint": name,
                "status": resp.status_code,
                "ok": ok,
                "body": resp.text[:300],
            }
        )
        return resp

    # Public endpoints
    record("GET /", client.get("/"))
    record("GET /ping", client.get("/ping"))
    record("GET /system/info", client.get("/system/info"))
    record("GET /health/", client.get("/health/"))
    record("GET /health/database", client.get("/health/database"))
    record("GET /health/ml", client.get("/health/ml"))
    record("GET /health/system", client.get("/health/system"))
    record("GET /health/full-report", client.get("/health/full-report"))
    record("GET /health/ready", client.get("/health/ready"))
    record("GET /health/live", client.get("/health/live"))
    record("GET /fraud/health", client.get("/fraud/health"))
    record("GET /qr/health", client.get("/qr/health"))
    record("GET /sms/health", client.get("/sms/health"))

    # Register
    r = record(
        "POST /auth/register",
        client.post(
            "/auth/register",
            json={
                "name": "Test User",
                "email": EMAIL,
                "phone": PHONE,
                "password": PASSWORD,
            },
        ),
        lambda x: "access_token" in x.json(),
    )
    if r.status_code == 200:
        token = r.json().get("access_token")

    # Login
    r = record(
        "POST /auth/login",
        client.post(
            "/auth/login",
            json={"phone": PHONE, "password": PASSWORD},
        ),
        lambda x: "access_token" in x.json(),
    )
    if r.status_code == 200:
        token = r.json().get("access_token") or token

    headers = {"Authorization": f"Bearer {token}"} if token else {}

    record("GET /auth/health", client.get("/auth/health", headers=headers))
    record("GET /auth/profile", client.get("/auth/profile", headers=headers))
    record("POST /auth/refresh-token", client.post("/auth/refresh-token", headers=headers))
    record("POST /auth/logout", client.post("/auth/logout", headers=headers))

    record(
        "POST /fraud/scan-qr",
        client.post(
            "/fraud/scan-qr",
            headers=headers,
            json={
                "upi_id": "rahul123@oksbi",
                "amount": 500.0,
                "merchant_name": "Test Shop",
            },
        ),
    )
    record(
        "POST /fraud/scan-text",
        client.post(
            "/fraud/scan-text",
            headers=headers,
            json={"text": "URGENT verify your KYC immediately click link"},
        ),
    )
    record(
        "POST /fraud/bulk-scan",
        client.post(
            "/fraud/bulk-scan",
            headers=headers,
            json=[
                {"upi_id": "rahul123@oksbi", "amount": 100.0},
                {"upi_id": "pay99@fastpay", "amount": 5000.0},
            ],
        ),
    )
    record("GET /fraud/history", client.get("/fraud/history", headers=headers))
    record(
        "POST /fraud/report-upi",
        client.post(
            "/fraud/report-upi",
            headers=headers,
            params={"upi_id": "scam@fastpay", "reason": "test report"},
        ),
    )

    record(
        "POST /sms/scan",
        client.post(
            "/sms/scan",
            headers=headers,
            json={
                "message": "Your SBI account blocked verify OTP at http://evil.com",
                "sender": "AD-SBI",
            },
        ),
    )
    record(
        "POST /sms/bulk-scan",
        client.post(
            "/sms/bulk-scan",
            headers=headers,
            json={"messages": ["verify otp", "hello friend"]},
        ),
    )
    record("GET /sms/history", client.get("/sms/history", headers=headers))
    record(
        "POST /sms/report",
        client.post(
            "/sms/report",
            headers=headers,
            params={
                "sender": "SPAM",
                "message": "scam",
                "reason": "phishing",
            },
        ),
    )

    record("GET /qr/history", client.get("/qr/history", headers=headers))

    failed = [r for r in results if not r["ok"]]
    print(json.dumps({"total": len(results), "failed": len(failed), "results": results}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
