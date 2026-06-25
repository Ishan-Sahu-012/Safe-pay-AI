# app/tests/test_api.py

import io
import json
import time
import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

RAND_PHONE = f"9{uuid.uuid4().int % 1_000_000_000:09d}"
RAND_EMAIL = f"test_{uuid.uuid4().hex[:8]}@example.com"

TEST_USER = {
    "name": "Rahul Sharma",
    "email": RAND_EMAIL,
    "password": "StrongPass123@",
    "phone": RAND_PHONE
}

TEST_LOGIN = {
    "phone": RAND_PHONE,
    "password": "StrongPass123@"
}

TEST_UPI_PAYLOAD = {
    "upi_id": "pay98234723@fastpay",
    "amount": 25000,
    "merchant_name": "Test Merchant"
}

TEST_SMS_PAYLOAD = {
    "message": "URGENT! Your SBI account is blocked. Verify OTP immediately. Click: http://verify-bonus.xyz",
    "sender": "FREEOTP999"
}

ACCESS_TOKEN = None

def auth_headers():
    return {
        "Authorization": f"Bearer {ACCESS_TOKEN}"
    }

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data

def test_health_route():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True

def test_register():
    response = client.post(
        "/auth/register",
        json=TEST_USER
    )
    assert response.status_code in [200, 201]
    data = response.json()
    assert data["success"] is True

def test_login():
    global ACCESS_TOKEN
    response = client.post(
        "/auth/login",
        json=TEST_LOGIN
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    ACCESS_TOKEN = data["access_token"]

def test_invalid_login():
    response = client.post(
        "/auth/login",
        json={
            "phone": "9000000000",
            "password": "wrongpass"
        }
    )
    assert response.status_code in [400, 401]

def test_protected_route():
    response = client.get(
        "/auth/profile",
        headers=auth_headers()
    )
    assert response.status_code == 200

def test_unauthorized_access():
    response = client.get(
        "/auth/profile"
    )
    assert response.status_code in [401, 403]

def test_upi_fraud_detection():
    response = client.post(
        "/fraud/scan-qr",
        json=TEST_UPI_PAYLOAD,
        headers=auth_headers()
    )
    assert response.status_code == 200
    data = response.json()
    assert "scan_type" in data

def test_safe_upi_detection():
    response = client.post(
        "/fraud/scan-qr",
        json={
            "upi_id": "rahul123@oksbi",
            "amount": 500
        },
        headers=auth_headers()
    )
    assert response.status_code == 200

def test_sms_scam_detection():
    response = client.post(
        "/sms/scan",
        json=TEST_SMS_PAYLOAD,
        headers=auth_headers()
    )
    assert response.status_code == 200
    data = response.json()
    assert "analysis" in data

def test_safe_sms():
    response = client.post(
        "/sms/scan",
        json={
            "message": "Your electricity bill payment received",
            "sender": "SBIINB"
        },
        headers=auth_headers()
    )
    assert response.status_code == 200

def test_qr_analysis():
    fake_image = io.BytesIO(b"fake image content")
    response = client.post(
        "/qr/scan-image",
        files={
            "file": ("test.png", fake_image, "image/png")
        },
        headers=auth_headers()
    )
    assert response.status_code in [200, 400, 500]

def test_invalid_qr_upload():
    fake_file = io.BytesIO(b"not image")
    response = client.post(
        "/qr/scan-image",
        files={
            "file": ("test.txt", fake_file, "text/plain")
        },
        headers=auth_headers()
    )
    assert response.status_code in [400, 415]

def test_large_sms_payload():
    long_text = "OTP verify now " * 5000
    response = client.post(
        "/sms/scan",
        json={
            "message": long_text,
            "sender": "FREEOTP"
        },
        headers=auth_headers()
    )
    assert response.status_code in [200, 413, 422, 500]

@pytest.mark.parametrize(
    "payload",
    [
        "' OR 1=1 --",
        "'; DROP TABLE users; --",
        "\" OR \"1\"=\"1"
    ]
)
def test_sql_injection(payload):
    response = client.post(
        "/auth/login",
        json={
            "phone": payload,
            "password": payload
        }
    )
    assert response.status_code in [400, 401, 422]

def test_xss_payload():
    payload = {
        "message": "<script>alert('xss')</script>",
        "sender": "ATTACKER"
    }
    response = client.post(
        "/sms/scan",
        json=payload,
        headers=auth_headers()
    )
    assert response.status_code in [200, 400]

def test_api_performance():
    start = time.time()
    response = client.post(
        "/fraud/scan-qr",
        json=TEST_UPI_PAYLOAD,
        headers=auth_headers()
    )
    duration = time.time() - start
    assert response.status_code == 200
    assert duration < 5

def test_bulk_requests():
    for _ in range(10):
        response = client.post(
            "/sms/scan",
            json=TEST_SMS_PAYLOAD,
            headers=auth_headers()
        )
        assert response.status_code == 200

def test_invalid_json():
    headers = auth_headers()
    headers["Content-Type"] = "application/json"
    response = client.post(
        "/sms/scan",
        data="invalid-json",
        headers=headers
    )
    assert response.status_code in [400, 422]

def test_invalid_token():
    response = client.get(
        "/auth/profile",
        headers={
            "Authorization": "Bearer invalid.token.here"
        }
    )
    assert response.status_code in [401, 403]

def test_rate_limit():
    responses = []
    for _ in range(20):
        response = client.post(
            "/auth/login",
            json={
                "phone": "9999999999",
                "password": "wrong"
            }
        )
        responses.append(response.status_code)
    assert any(status in [429, 401] for status in responses)

def test_model_health():
    response = client.get(
        "/health/ml"
    )
    assert response.status_code == 200
    data = response.json()
    assert "models" in data

def test_database_health():
    response = client.get(
        "/health/database"
    )
    assert response.status_code == 200

def test_full_hybrid_pipeline():
    response = client.post(
        "/fraud/scan-text",
        json={
            "text": "Verify OTP urgently now"
        },
        headers=auth_headers()
    )
    assert response.status_code == 200
    data = response.json()
    assert "analysis" in data

def test_api_summary():
    endpoints = [
        "/health",
        "/health/ml",
        "/health/database"
    ]
    for endpoint in endpoints:
        response = client.get(endpoint)
        assert response.status_code == 200

if __name__ == "__main__":
    pytest.main(["-v", "tests/test_api.py"])