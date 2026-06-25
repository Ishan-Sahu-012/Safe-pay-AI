# app/ml/inference/text_predictor.py

"""
==============================================================================
SafePay AI — Text Scam Predictor
==============================================================================

Purpose
-------
Runtime inference engine for scam text detection.

Used By
-------
1. sms_routes.py
2. fraud_detection_service.py
3. email_routes.py
4. whatsapp_scanner.py
5. OCR scam analysis

Flow
----
Raw Text
   ↓
Feature Extraction
   ↓
ML Model Prediction
   ↓
Hybrid Risk Analysis
   ↓
Fraud Intelligence Response

==============================================================================
"""

import os
import time
from datetime import datetime
from pathlib import Path

from app.ml.training.model2_text_classifier import (
    TextScamClassifier
)

from app.ml.features.text_features import (

    clean_text,

    extract_text_features,

    detect_fraud_keywords,

    extract_urls,

    extract_phone_numbers,

    extract_emails
)

from app.utils.logger import logger

# ============================================================================
# MODEL PATH
# ============================================================================

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "model2_text.pkl"

# ============================================================================
# LOAD MODEL
# ============================================================================

classifier = None

# ============================================================================
# LOAD TEXT MODEL
# ============================================================================

def load_text_model():

    global classifier

    try:

        if not os.path.exists(MODEL_PATH):

            raise FileNotFoundError(
                f"Model not found: {MODEL_PATH}"
            )

        logger.info(
            """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 LOADING TEXT SCAM MODEL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        classifier = TextScamClassifier.load(
            MODEL_PATH
        )

        logger.info(
            """
✅ TEXT MODEL LOADED SUCCESSFULLY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

    except Exception as e:

        logger.error(
            f"""
❌ TEXT MODEL LOADING FAILED

🧠 Error:
{str(e)}
"""
        )

        raise

# ============================================================================
# LAZY LOAD
# ============================================================================

def _ensure_model():
    global classifier
    if classifier is None:
        load_text_model()


try:
    load_text_model()
except Exception as load_error:
    logger.warning(f"Text model deferred load: {load_error}")

# ============================================================================
# RISK LEVEL
# ============================================================================

def calculate_risk_level(score: float):

    """
    Convert score into risk category.
    """

    if score >= 80:

        return "HIGH", "SCAM"

    elif score >= 50:

        return "MEDIUM", "SUSPICIOUS"

    return "LOW", "SAFE"

# ============================================================================
# AI EXPLANATION ENGINE
# ============================================================================

def generate_ai_explanation(
    features: dict,
    ml_probability: float
):

    reasons = []

    # ------------------------------------------------------------------------
    # Fraud Keywords
    # ------------------------------------------------------------------------

    if features["fraud_keyword_count"] >= 3:

        reasons.append(
            "Multiple scam-related keywords detected"
        )

    # ------------------------------------------------------------------------
    # URL Risk
    # ------------------------------------------------------------------------

    if features["url_risk_score"] >= 40:

        reasons.append(
            "Suspicious phishing-style URL found"
        )

    # ------------------------------------------------------------------------
    # Urgency Tactics
    # ------------------------------------------------------------------------

    if features["has_urgent"]:

        reasons.append(
            "Urgency pressure tactics detected"
        )

    # ------------------------------------------------------------------------
    # OTP Scam
    # ------------------------------------------------------------------------

    if features["has_otp"]:

        reasons.append(
            "OTP request detected"
        )

    # ------------------------------------------------------------------------
    # KYC Scam
    # ------------------------------------------------------------------------

    if features["has_kyc"]:

        reasons.append(
            "KYC verification scam pattern detected"
        )

    # ------------------------------------------------------------------------
    # High ML Probability
    # ------------------------------------------------------------------------

    if ml_probability >= 0.85:

        reasons.append(
            "AI model strongly classifies message as scam"
        )

    if not reasons:

        reasons.append(
            "No strong scam indicators detected"
        )

    return reasons

# ============================================================================
# MAIN PREDICTION FUNCTION
# ============================================================================

def predict_text_scam(text: str):

    """
    Main runtime prediction function.

    Returns:
    --------
    {
        risk_score,
        risk_level,
        status,
        ml_probability,
        features,
        explanation
    }
    """

    start_time = time.time()

    try:

        _ensure_model()

        # --------------------------------------------------------------------
        # Validation
        # --------------------------------------------------------------------

        if not isinstance(text, str):

            raise ValueError(
                "Text must be string"
            )

        if len(text.strip()) < 3:

            raise ValueError(
                "Text too short"
            )

        # --------------------------------------------------------------------
        # Clean Text
        # --------------------------------------------------------------------

        cleaned_text = clean_text(text)

        # --------------------------------------------------------------------
        # Extract Features
        # --------------------------------------------------------------------

        features = extract_text_features(text)

        # --------------------------------------------------------------------
        # ML Prediction
        # --------------------------------------------------------------------

        ml_probability = classifier.predict(
            cleaned_text
        )

        ml_score = ml_probability * 100

        # --------------------------------------------------------------------
        # Rule-Based Intelligence
        # --------------------------------------------------------------------

        keyword_bonus = min(

            features["fraud_keyword_count"] * 5,

            20
        )

        url_bonus = min(

            features["url_risk_score"] * 0.3,

            20
        )

        urgency_bonus = 10 if features["has_urgent"] else 0

        otp_bonus = 10 if features["has_otp"] else 0

        kyc_bonus = 10 if features["has_kyc"] else 0

        # --------------------------------------------------------------------
        # Hybrid Final Risk
        # --------------------------------------------------------------------

        final_risk_score = round(

            (
                ml_score * 0.65
            )
            +
            keyword_bonus
            +
            url_bonus
            +
            urgency_bonus
            +
            otp_bonus
            +
            kyc_bonus,

            2
        )

        final_risk_score = min(
            final_risk_score,
            100
        )

        # --------------------------------------------------------------------
        # Risk Classification
        # --------------------------------------------------------------------

        risk_level, status = calculate_risk_level(
            final_risk_score
        )

        # --------------------------------------------------------------------
        # AI Explanation
        # --------------------------------------------------------------------

        explanation = generate_ai_explanation(

            features,

            ml_probability
        )

        # --------------------------------------------------------------------
        # Metadata
        # --------------------------------------------------------------------

        urls = extract_urls(text)

        phones = extract_phone_numbers(text)

        emails = extract_emails(text)

        execution_time = round(

            (time.time() - start_time) * 1000,

            2
        )

        # --------------------------------------------------------------------
        # Logging
        # --------------------------------------------------------------------

        logger.info(
            f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📩 TEXT SCAM ANALYSIS COMPLETE

⚠️ Risk Score     : {final_risk_score}
🚨 Risk Level     : {risk_level}
🤖 ML Probability : {ml_probability}
⏱️ Execution Time : {execution_time} ms

🔍 Features:
{features}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        # --------------------------------------------------------------------
        # Response
        # --------------------------------------------------------------------

        return {

            "success": True,

            "timestamp": datetime.utcnow(),

            "risk_score": final_risk_score,

            "risk_level": risk_level,

            "status": status,

            "ml_probability": round(
                ml_probability,
                4
            ),

            "features": features,

            "detected_urls": urls,

            "detected_phones": phones,

            "detected_emails": emails,

            "explanation": explanation,

            "execution_time_ms": execution_time
        }

    except Exception as e:

        logger.error(
            f"""
❌ TEXT PREDICTION FAILED

🧠 Error:
{str(e)}
"""
        )

        return {

            "success": False,

            "error": str(e),

            "risk_score": 0,

            "risk_level": "UNKNOWN",

            "status": "ERROR"
        }

# ============================================================================
# SIMPLE PREDICTOR
# ============================================================================

def simple_predict(text: str):

    """
    Lightweight probability-only predictor.

    Used where only probability needed.
    """

    try:

        probability = classifier.predict(text)

        return round(
            probability,
            4
        )

    except Exception as e:

        logger.error(
            f"❌ Simple Predict Error: {str(e)}"
        )

        return 0.0

# ============================================================================
# HEALTH CHECK
# ============================================================================

def model_health():

    """
    Verify model status.
    """

    try:

        if classifier is None:

            return {

                "healthy": False,

                "reason": "Model not loaded"
            }

        sample = "Your KYC is blocked verify immediately"

        score = classifier.predict(sample)

        return {

            "healthy": True,

            "sample_prediction": score
        }

    except Exception as e:

        return {

            "healthy": False,

            "error": str(e)
        }

# ============================================================================
# DEBUG TEST
# ============================================================================

if __name__ == "__main__":

    sample = """

    URGENT!

    Your SBI account has been suspended.

    Verify KYC immediately at:

    http://secure-bank-verification.xyz

    Call now: 9876543210
    """

    result = predict_text_scam(sample)

    print("\n🚨 TEXT ANALYSIS RESULT:\n")

    for key, value in result.items():

        print(f"{key}: {value}")