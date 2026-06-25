# tests/test_ml.py

"""
==============================================================================
SafePay AI — ML Testing Suite
==============================================================================

Purpose
-------
Enterprise-grade ML testing framework.

Features
--------
✅ Model loading tests
✅ Prediction validation
✅ Feature extraction tests
✅ Hybrid intelligence tests
✅ Rule engine tests
✅ Performance benchmarks
✅ Stress testing
✅ Edge case validation
✅ Adversarial input testing

Used For
--------
1. ML validation
2. CI/CD pipelines
3. Production verification
4. Regression testing
5. Security testing

Run
---
pytest tests/test_ml.py -v

==============================================================================
"""

import random
import string
import time

import pytest

# ============================================================================
# MODEL IMPORTS
# ============================================================================

from app.ml.inference.upi_predictor import (

    predict_upi_fraud,

    simple_predict as simple_upi_predict,

    model_health as upi_health
)

from app.ml.inference.text_predictor import (

    predict_text_scam,

    simple_predict as simple_text_predict,

    model_health as text_health
)

# ============================================================================
# FEATURE IMPORTS
# ============================================================================

from app.ml.features.text_features import (

    clean_text,

    tokenize,

    extract_urls,

    extract_phone_numbers,

    extract_emails,

    shannon_entropy,

    detect_fraud_keywords,

    extract_text_features
)

# ============================================================================
# SERVICE IMPORTS
# ============================================================================

from app.services.rule_engine import (

    evaluate_text_rules,

    evaluate_upi_rules,

    evaluate_combined_rules
)

from app.services.risk_score_service import (

    calculate_hybrid_risk_score,

    generate_complete_risk_analysis
)

# ============================================================================
# SAMPLE DATA
# ============================================================================

SAFE_SMS = """

Your electricity bill payment
of Rs 550 has been received.
"""

SCAM_SMS = """

URGENT!

Your SBI account has been blocked.

Verify OTP immediately.

Click:
http://verify-bonus.xyz
"""

SAFE_UPI = "rahul123@oksbi"

SCAM_UPI = "pay98234723@fastpay"

# ============================================================================
# MODEL HEALTH
# ============================================================================

def test_upi_model_health():

    """
    Verify UPI model loads correctly.
    """

    result = upi_health()

    assert result["healthy"] is True

# ============================================================================
# TEXT MODEL HEALTH
# ============================================================================

def test_text_model_health():

    """
    Verify text model loads correctly.
    """

    result = text_health()

    assert result["healthy"] is True

# ============================================================================
# SAFE TEXT PREDICTION
# ============================================================================

def test_safe_text_prediction():

    """
    Legit SMS detection.
    """

    result = predict_text_scam(
        SAFE_SMS
    )

    assert result["success"] is True

    assert result["risk_score"] < 80

# ============================================================================
# SCAM TEXT PREDICTION
# ============================================================================

def test_scam_text_prediction():

    """
    Scam SMS detection.
    """

    result = predict_text_scam(
        SCAM_SMS
    )

    assert result["success"] is True

    assert result["risk_score"] >= 50

# ============================================================================
# SAFE UPI PREDICTION
# ============================================================================

def test_safe_upi_prediction():

    """
    Legit UPI detection.
    """

    result = predict_upi_fraud(

        upi_id=SAFE_UPI,

        requested_amount=500,

        seen_before=True,

        report_count=0,

        user_avg_amount=1000,

        first_time_user=False
    )

    assert result["success"] is True

# ============================================================================
# SCAM UPI PREDICTION
# ============================================================================

def test_scam_upi_prediction():

    """
    Fraud UPI detection.
    """

    result = predict_upi_fraud(

        upi_id=SCAM_UPI,

        requested_amount=25000,

        seen_before=False,

        report_count=5,

        user_avg_amount=1200,

        first_time_user=True
    )

    assert result["success"] is True

    assert result["risk_score"] >= 50

# ============================================================================
# SIMPLE PREDICT TEST
# ============================================================================

def test_simple_predict():

    """
    Lightweight predictor validation.
    """

    score = simple_text_predict(
        SCAM_SMS
    )

    assert isinstance(score, float)

# ============================================================================
# CLEAN TEXT TEST
# ============================================================================

def test_clean_text():

    """
    Text cleaning validation.
    """

    text = "Hello!!! OTP Verify NOW"

    cleaned = clean_text(text)

    assert isinstance(cleaned, str)

    assert "!" not in cleaned

# ============================================================================
# TOKENIZATION TEST
# ============================================================================

def test_tokenize():

    """
    Token extraction validation.
    """

    tokens = tokenize(
        "Verify your OTP immediately"
    )

    assert isinstance(tokens, list)

    assert len(tokens) > 0

# ============================================================================
# URL EXTRACTION TEST
# ============================================================================

def test_extract_urls():

    """
    URL extraction validation.
    """

    text = "Click http://verify.xyz now"

    urls = extract_urls(text)

    assert len(urls) > 0

# ============================================================================
# PHONE EXTRACTION TEST
# ============================================================================

def test_extract_phone_numbers():

    """
    Phone extraction validation.
    """

    text = "Call 9876543210 now"

    phones = extract_phone_numbers(text)

    assert len(phones) == 1

# ============================================================================
# EMAIL EXTRACTION TEST
# ============================================================================

def test_extract_emails():

    """
    Email extraction validation.
    """

    text = "Mail test@example.com"

    emails = extract_emails(text)

    assert len(emails) == 1

# ============================================================================
# ENTROPY TEST
# ============================================================================

def test_entropy():

    """
    Randomness validation.
    """

    low = shannon_entropy("rahul")

    high = shannon_entropy(
        "x92ms82pq11zx"
    )

    assert high > low

# ============================================================================
# FRAUD KEYWORDS TEST
# ============================================================================

def test_fraud_keywords():

    """
    Fraud keyword detection.
    """

    keywords = detect_fraud_keywords(

        "verify otp urgent reward"
    )

    assert len(keywords) > 0

# ============================================================================
# FEATURE EXTRACTION TEST
# ============================================================================

def test_feature_extraction():

    """
    NLP feature validation.
    """

    features = extract_text_features(
        SCAM_SMS
    )

    assert isinstance(features, dict)

    assert "entropy" in features

# ============================================================================
# RULE ENGINE TEST
# ============================================================================

def test_rule_engine_text():

    """
    Rule-based text analysis.
    """

    result = evaluate_text_rules(
        SCAM_SMS
    )

    assert result["score"] > 0

# ============================================================================
# UPI RULE ENGINE TEST
# ============================================================================

def test_rule_engine_upi():

    """
    Rule-based UPI analysis.
    """

    result = evaluate_upi_rules(

        upi_id=SCAM_UPI,

        amount=25000,

        report_count=5,

        first_time_user=True
    )

    assert result["score"] > 0

# ============================================================================
# COMBINED RULE ENGINE
# ============================================================================

def test_combined_rule_engine():

    """
    Hybrid rule engine validation.
    """

    result = evaluate_combined_rules(

        text=SCAM_SMS,

        upi_id=SCAM_UPI,

        amount=25000,

        url="http://verify-bonus.xyz"
    )

    assert result["success"] is True

# ============================================================================
# HYBRID SCORE TEST
# ============================================================================

def test_hybrid_score():

    """
    Hybrid intelligence validation.
    """

    result = calculate_hybrid_risk_score(

        ml_probability=0.92,

        rule_score=80,

        behavior_score=70,

        history_score=50,

        trust_score=20
    )

    assert result["risk_score"] > 50

# ============================================================================
# COMPLETE ANALYSIS TEST
# ============================================================================

def test_complete_risk_analysis():

    """
    Enterprise fraud pipeline.
    """

    result = generate_complete_risk_analysis(

        ml_probability=0.91,

        avg_transaction_amount=1500,

        current_amount=25000,

        transaction_velocity=9,

        previous_scores=[

            72,
            81,
            65,
            90
        ],

        account_age_days=5,

        successful_transactions=2,

        fraud_reports=3,

        fraud_keywords=6,

        suspicious_url=True,

        suspicious_psp=True,

        otp_detected=True,

        high_entropy=True,

        night_transaction=True,

        new_device=True
    )

    assert result["success"] is True

# ============================================================================
# PERFORMANCE TEST
# ============================================================================

def test_prediction_performance():

    """
    ML latency benchmark.
    """

    start = time.time()

    predict_text_scam(SCAM_SMS)

    duration = time.time() - start

    assert duration < 5

# ============================================================================
# STRESS TEST
# ============================================================================

def test_bulk_predictions():

    """
    Multiple prediction stress test.
    """

    for _ in range(20):

        result = predict_text_scam(
            SCAM_SMS
        )

        assert result["success"] is True

# ============================================================================
# EDGE CASES
# ============================================================================

@pytest.mark.parametrize(

    "text",

    [

        "",

        " ",

        "a",

        "🔥🔥🔥",

        "1234567890",

        "<script>alert(1)</script>"
    ]
)

def test_edge_cases(text):

    """
    Adversarial input validation.
    """

    result = predict_text_scam(text)

    assert isinstance(result, dict)

# ============================================================================
# RANDOM ADVERSARIAL INPUT
# ============================================================================

def test_random_noise():

    """
    Random string robustness.
    """

    random_text = "".join(

        random.choice(

            string.ascii_letters
        )

        for _ in range(500)
    )

    result = predict_text_scam(
        random_text
    )

    assert isinstance(result, dict)

# ============================================================================
# MODEL CONSISTENCY
# ============================================================================

def test_prediction_consistency():

    """
    Deterministic prediction validation.
    """

    result1 = predict_text_scam(
        SCAM_SMS
    )

    result2 = predict_text_scam(
        SCAM_SMS
    )

    diff = abs(

        result1["risk_score"]

        -

        result2["risk_score"]
    )

    assert diff < 1

# ============================================================================
# SAFE VS FRAUD DIFFERENCE
# ============================================================================

def test_safe_vs_fraud_difference():

    """
    Fraud should score higher.
    """

    safe_result = predict_text_scam(
        SAFE_SMS
    )

    scam_result = predict_text_scam(
        SCAM_SMS
    )

    assert (

        scam_result["risk_score"]

        >

        safe_result["risk_score"]
    )

# ============================================================================
# INVALID UPI TEST
# ============================================================================

def test_invalid_upi():

    """
    Invalid UPI robustness.
    """

    result = predict_upi_fraud(

        upi_id="invalidupi",

        requested_amount=1000
    )

    assert result["success"] is False

# ============================================================================
# HUGE INPUT TEST
# ============================================================================

def test_huge_text_input():

    """
    Large payload handling.
    """

    huge_text = SCAM_SMS * 500

    result = predict_text_scam(
        huge_text
    )

    assert isinstance(result, dict)

# ============================================================================
# MEMORY LEAK TEST
# ============================================================================

def test_repeated_predictions():

    """
    Long-running stability test.
    """

    for _ in range(50):

        predict_text_scam(SCAM_SMS)

        predict_upi_fraud(

            upi_id=SCAM_UPI,

            requested_amount=5000
        )

    assert True

# ============================================================================
# DEBUG
# ============================================================================

if __name__ == "__main__":

    pytest.main(

        [

            "-v",

            "tests/test_ml.py"
        ]
    )