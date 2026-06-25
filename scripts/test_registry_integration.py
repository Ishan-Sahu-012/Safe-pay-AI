import os
import sys

# Ensure backend root is in python path
sys.path.append(os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from app.database.db import db_session, engine, Base
from app.database.models import UPIMerchantRegistry, URLSecurityRegistry, CommunicationInterceptLog, Message
from app.services.fraud_detection_service import detect_qr_fraud, detect_text_fraud
from app.services.fraud_patterns.url_intel import analyze_single_url

def init_and_seed_db():
    print("Initializing tables and seeding database...")
    Base.metadata.create_all(bind=engine)
    with db_session() as db:
        from app.database.seeding import seed_database_registry
        seed_database_registry(db)

def run_tests():
    print("=" * 60)
    print("RUNNING REGISTRY INTEGRATION TESTS")
    print("=" * 60)

    # Initialize tables and seed first
    init_and_seed_db()

    # 1. Verify Database Seeding
    print("\n[TEST 1] Verifying database seeding status...")
    with db_session() as db:
        merchant_count = db.query(UPIMerchantRegistry).count()
        url_count = db.query(URLSecurityRegistry).count()
        log_count = db.query(CommunicationInterceptLog).count()
        msg_count = db.query(Message).count()

        print(f"UPIMerchantRegistry entries  : {merchant_count}")
        print(f"URLSecurityRegistry entries  : {url_count}")
        print(f"CommunicationInterceptLogs   : {log_count}")
        print(f"Messages (spam dataset)      : {msg_count}")

        assert merchant_count >= 500, f"Expected 500+ merchants, got {merchant_count}"
        assert url_count >= 500, f"Expected 500+ URLs, got {url_count}"
        assert log_count >= 500, f"Expected 500+ logs, got {log_count}"
        assert msg_count >= 500, f"Expected 500+ messages, got {msg_count}"
        print("PASS: Seeding verification successful!")

    # 2. Verify QR Scan lookup for known merchant
    print("\n[TEST 2] Verifying QR scan lookup for known verified merchant...")
    # pay-upstox44138@apl is known, verified=1, reports=0, avg_val=152.15
    result = detect_qr_fraud(
        upi_id="pay-upstox44138@apl",
        amount=150.0,
        user_id=1,
        merchant_name="Upstox Retail Outlet"
    )
    print("Scan result:", result)
    assert result["success"] is True
    assert result["risk_level"] == "LOW"
    print("PASS: Verified merchant lookup success!")

    # 3. Verify QR Scan lookup for known fraud merchant
    print("\n[TEST 3] Verifying QR scan lookup for known fraudulent merchant...")
    # paytmmoney-verification-rcocw337@oksbi is known, verified=0, reports=4, avg_val=17589.09
    result_fraud = detect_qr_fraud(
        upi_id="paytmmoney-verification-rcocw337@oksbi",
        amount=18000.0,
        user_id=1,
        merchant_name="Paytmmoney Helpdesk Support"
    )
    print("Fraud Scan result:", result_fraud)
    assert result_fraud["success"] is True
    # Should have higher risk score due to report count and amount ratio
    assert result_fraud["risk_score"] > 30
    print("PASS: Fraud merchant lookup success!")

    # 4. Verify Automatic Registration of Unknown Merchant
    print("\n[TEST 4] Verifying automatic registration of unknown merchant...")
    test_upi = "new-unregistered-merchant@oksbi"
    with db_session() as db:
        # Verify not in DB first
        m = db.query(UPIMerchantRegistry).filter(UPIMerchantRegistry.upi_id == test_upi).first()
        if m:
            db.delete(m)
            db.commit()

    result_new = detect_qr_fraud(
        upi_id=test_upi,
        amount=500.0,
        user_id=1,
        merchant_name="New Test Merchant"
    )
    print("New Scan result:", result_new)
    assert result_new["success"] is True

    # Check it was written to database
    with db_session() as db:
        m = db.query(UPIMerchantRegistry).filter(UPIMerchantRegistry.upi_id == test_upi).first()
        assert m is not None, "New merchant was not saved to registry!"
        assert m.merchant_name == "New Test Merchant"
        assert m.merchant_avg_transaction_val == 500.0
        print("PASS: Unknown merchant registered successfully!")

    # 5. Verify URL Security Lookup (Malicious vs Verified Safe)
    print("\n[TEST 5] Verifying URL security registry lookup...")
    # https://upstox-rewards-activation.net is Malicious
    malicious_res = analyze_single_url("https://upstox-rewards-activation.net")
    print("Malicious URL result:", malicious_res)
    assert malicious_res["score"] == 100
    assert "Known malicious URL" in malicious_res["issues"][0]

    # https://www.bhim.com/main/dashboard is Verified Safe
    safe_res = analyze_single_url("https://www.bhim.com/main/dashboard")
    print("Safe URL result:", safe_res)
    assert safe_res["score"] == 0
    assert len(safe_res["issues"]) == 0
    print("PASS: URL security lookup success!")

    print("\n" + "=" * 60)
    print("ALL REGISTRY INTEGRATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
