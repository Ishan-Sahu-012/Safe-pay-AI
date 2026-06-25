# app/ml/inference/upi_predictor.py

"""
==============================================================================
SafePay AI — UPI Fraud Predictor
==============================================================================

Purpose
-------
Runtime inference engine for QR / UPI fraud detection.

Used By
-------
1. qr_routes.py
2. fraud_routes.py
3. payment_gateway_scanner.py
4. realtime_camera_scanner.py

Pipeline
--------
QR Code
   ↓
Extract UPI ID
   ↓
Feature Extraction
   ↓
Random Forest Prediction
   ↓
Hybrid Risk Intelligence
   ↓
Final Fraud Analysis

==============================================================================
"""

import os
import time
from datetime import datetime
from pathlib import Path

from app.ml.training.model1_upi_fraud_classifier import (

    UPIFraudClassifier,

    extract_features_from_upi,

    shannon_entropy
)

from app.utils.logger import logger

# ============================================================================
# MODEL PATH
# ============================================================================

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "model1_upi.pkl"

# ============================================================================
# GLOBAL MODEL
# ============================================================================

classifier = None

# ============================================================================
# SAFE PSPs
# ============================================================================

SAFE_PSP = {

    "oksbi",
    "okhdfcbank",
    "okicici",
    "ybl",
    "paytm",
    "ibl",
    "axl",
    "upi",
    "sbi",
    "hdfc",
    "icici"
}

# ============================================================================
# SUSPICIOUS PSPs
# ============================================================================

SUSPICIOUS_PSP = {

    "xpay",
    "qpay",
    "fastpay",
    "quickpay",
    "upipay",
    "mupay",
    "newupi"
}

# ============================================================================
# LOAD MODEL
# ============================================================================

def load_upi_model():

    global classifier

    try:

        if not os.path.exists(MODEL_PATH):

            raise FileNotFoundError(
                f"Model not found: {MODEL_PATH}"
            )

        logger.info(
            """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 LOADING UPI FRAUD MODEL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        classifier = UPIFraudClassifier.load(
            MODEL_PATH
        )

        logger.info(
            """
✅ UPI MODEL LOADED SUCCESSFULLY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

    except Exception as e:

        logger.error(
            f"""
❌ UPI MODEL LOAD FAILED

🧠 Error:
{str(e)}
"""
        )

        raise

# ============================================================================
# LAZY LOAD (avoid import-time crash if model file missing)
# ============================================================================

def _ensure_model():
    global classifier
    if classifier is None:
        load_upi_model()


try:
    load_upi_model()
except Exception as load_error:
    logger.warning(f"UPI model deferred load: {load_error}")

# ============================================================================
# VALIDATE UPI
# ============================================================================

def validate_upi(upi_id: str):

    """
    Basic UPI validation.
    """

    if "@" not in upi_id:

        return False

    parts = upi_id.split("@")

    if len(parts) != 2:

        return False

    if len(parts[0]) < 2:

        return False

    return True

# ============================================================================
# PSP ANALYSIS
# ============================================================================

def analyze_psp(upi_id: str):

    try:

        psp = upi_id.split("@")[1].lower()

        if psp in SAFE_PSP:

            return {

                "psp": psp,

                "risk": "LOW"
            }

        if psp in SUSPICIOUS_PSP:

            return {

                "psp": psp,

                "risk": "HIGH"
            }

        return {

            "psp": psp,

            "risk": "UNKNOWN"
        }

    except:

        return {

            "psp": "unknown",

            "risk": "UNKNOWN"
        }

# ============================================================================
# RULE ENGINE
# ============================================================================

def calculate_rule_risk(
    upi_id: str,
    features: dict
):

    """
    Rule-based fraud intelligence.
    """

    score = 0

    reasons = []

    # ------------------------------------------------------------------------
    # High Entropy
    # ------------------------------------------------------------------------

    if features["entropy"] > 0.85:

        score += 20

        reasons.append(
            "Random-looking UPI ID detected"
        )

    # ------------------------------------------------------------------------
    # Too Many Digits
    # ------------------------------------------------------------------------

    if features["num_digits"] >= 6:

        score += 15

        reasons.append(
            "Too many numeric characters"
        )

    # ------------------------------------------------------------------------
    # High Report Count
    # ------------------------------------------------------------------------

    if features["report_count"] >= 3:

        score += 25

        reasons.append(
            "Multiple fraud reports found"
        )

    # ------------------------------------------------------------------------
    # Suspicious Amount
    # ------------------------------------------------------------------------

    if features["amount_ratio"] >= 5:

        score += 20

        reasons.append(
            "Transaction amount unusually high"
        )

    # ------------------------------------------------------------------------
    # First-Time User
    # ------------------------------------------------------------------------

    if features["first_time_user"]:

        score += 10

        reasons.append(
            "First-time transaction with this UPI"
        )

    # ------------------------------------------------------------------------
    # Suspicious PSP
    # ------------------------------------------------------------------------

    psp_analysis = analyze_psp(upi_id)

    if psp_analysis["risk"] == "HIGH":

        score += 25

        reasons.append(
            "Suspicious payment service provider"
        )

    return min(score, 100), reasons

# ============================================================================
# RISK CLASSIFICATION
# ============================================================================

def classify_risk(score: float):

    if score >= 80:

        return "HIGH", "FRAUD"

    elif score >= 50:

        return "MEDIUM", "SUSPICIOUS"

    return "LOW", "SAFE"

# ============================================================================
# MAIN PREDICTOR
# ============================================================================

def predict_upi_fraud(

    upi_id: str,

    requested_amount: float,

    seen_before: bool = False,

    report_count: int = 0,

    user_avg_amount: float = 1000,

    first_time_user: bool = True
):

    """
    Main runtime prediction function.
    """

    start_time = time.time()

    try:

        _ensure_model()

        # --------------------------------------------------------------------
        # Validation
        # --------------------------------------------------------------------

        if not validate_upi(upi_id):

            raise ValueError(
                "Invalid UPI ID format"
            )

        # --------------------------------------------------------------------
        # Feature Extraction
        # --------------------------------------------------------------------

        features = extract_features_from_upi(

            upi_id=upi_id,

            seen_before=seen_before,

            report_count=report_count,

            requested_amount=requested_amount,

            user_avg_amount=user_avg_amount,

            first_time_user=first_time_user
        )

        # --------------------------------------------------------------------
        # ML Prediction
        # --------------------------------------------------------------------

        ml_probability = classifier.predict(
            features
        )

        ml_score = ml_probability * 100

        # --------------------------------------------------------------------
        # Rule Engine
        # --------------------------------------------------------------------

        rule_score, reasons = calculate_rule_risk(

            upi_id,

            features
        )

        # --------------------------------------------------------------------
        # Hybrid Risk
        # --------------------------------------------------------------------

        final_risk_score = round(

            (
                rule_score * 0.6
            )
            +
            (
                ml_score * 0.4
            ),

            2
        )

        final_risk_score = min(
            final_risk_score,
            100
        )

        # --------------------------------------------------------------------
        # Risk Classification
        # --------------------------------------------------------------------

        risk_level, status = classify_risk(
            final_risk_score
        )

        # --------------------------------------------------------------------
        # PSP Analysis
        # --------------------------------------------------------------------

        psp_analysis = analyze_psp(
            upi_id
        )

        # --------------------------------------------------------------------
        # Timing
        # --------------------------------------------------------------------

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
🏦 UPI FRAUD ANALYSIS COMPLETE

🏦 UPI ID        : {upi_id}
💰 Amount        : ₹{requested_amount}

⚠️ Final Score   : {final_risk_score}
🚨 Risk Level    : {risk_level}

🤖 ML Probability: {ml_probability}
🧠 Rule Score    : {rule_score}

⏱️ Time          : {execution_time} ms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        # --------------------------------------------------------------------
        # Response
        # --------------------------------------------------------------------

        return {

            "success": True,

            "timestamp": datetime.utcnow(),

            "upi_id": upi_id,

            "amount": requested_amount,

            "risk_score": final_risk_score,

            "risk_level": risk_level,

            "status": status,

            "ml_probability": round(
                ml_probability,
                4
            ),

            "rule_score": rule_score,

            "features": features,

            "psp_analysis": psp_analysis,

            "reasons": reasons,

            "execution_time_ms": execution_time
        }

    except Exception as e:

        logger.error(
            f"""
❌ UPI PREDICTION FAILED

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
# SIMPLE PREDICT
# ============================================================================

def simple_predict(
    upi_id: str,
    amount: float
):

    """
    Lightweight predictor.
    """

    try:

        features = extract_features_from_upi(

            upi_id=upi_id,

            seen_before=False,

            report_count=0,

            requested_amount=amount,

            user_avg_amount=1000,

            first_time_user=True
        )

        probability = classifier.predict(
            features
        )

        return round(
            probability,
            4
        )

    except Exception as e:

        logger.error(
            f"❌ Simple UPI Predict Error: {str(e)}"
        )

        return 0.0

# ============================================================================
# MODEL HEALTH
# ============================================================================

def model_health():

    try:

        sample = predict_upi_fraud(

            upi_id="rahul123@oksbi",

            requested_amount=500
        )

        return {

            "healthy": True,

            "sample_score":
                sample["risk_score"]
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

    result = predict_upi_fraud(

        upi_id="pay98234723@fastpay",

        requested_amount=25000,

        seen_before=False,

        report_count=5,

        user_avg_amount=1200,

        first_time_user=True
    )

    print("\n🚨 ANALYSIS RESULT:\n")

    for key, value in result.items():

        print(f"{key}: {value}")