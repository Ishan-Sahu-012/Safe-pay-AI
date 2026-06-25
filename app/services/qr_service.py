# app/services/qr_service.py

"""
==============================================================================
SafePay AI — QR Intelligence Service
==============================================================================

Purpose
-------
Enterprise-grade QR fraud analysis engine.

Features
--------
✅ QR decoding
✅ UPI extraction
✅ Merchant analysis
✅ Fraud detection
✅ QR validation
✅ Realtime scanning
✅ Hybrid AI intelligence
✅ Security alerts

Used By
-------
1. qr_routes.py
2. camera_scanner.py
3. realtime_detection.py
4. websocket_alerts.py

Architecture
-------------
QR Image
   ↓
QR Decoder
   ↓
UPI Parser
   ↓
Fraud Detection Service
   ↓
Hybrid Intelligence
   ↓
Risk Analysis

==============================================================================
"""

import base64
import io
import re
import time
from datetime import datetime

import cv2
import numpy as np

from PIL import Image
from pyzbar.pyzbar import decode

from app.services.fraud_detection_service import (
    detect_qr_fraud
)

from app.utils.logger import logger

# ============================================================================
# QR SERVICE CONFIG
# ============================================================================

MAX_IMAGE_SIZE_MB = 10

SUPPORTED_IMAGE_TYPES = [

    "PNG",

    "JPEG",

    "JPG"
]

# ============================================================================
# SUSPICIOUS WORDS
# ============================================================================

SUSPICIOUS_WORDS = [

    "reward",

    "cashback",

    "bonus",

    "offer",

    "winner",

    "free",

    "claim",

    "urgent",

    "verify"
]

# ============================================================================
# QR EXTRACTION
# ============================================================================

def decode_qr_image(image_np):

    """
    Decode QR from image with multiple fallback pre-processing and library strategies.
    Tries both pyzbar and OpenCV QRCodeDetector.
    """

    # Strategy 1: Direct pyzbar decode on raw image
    try:

        decoded_objects = decode(image_np)

        if decoded_objects and decoded_objects[0].data:

            return decoded_objects[0].data.decode("utf-8")

    except Exception:

        pass

    # Strategy 2: OpenCV QRCodeDetector on raw image
    try:

        detector = cv2.QRCodeDetector()

        val, points, _ = detector.detectAndDecode(image_np)

        if val:

            return val

    except Exception:

        pass

    # Convert to grayscale for further processing
    gray = None

    try:

        if len(image_np.shape) == 3:

            if image_np.shape[2] == 3:

                gray = cv2.cvtColor(image_np, cv2.COLOR_RGB2GRAY)

            elif image_np.shape[2] == 4:

                gray = cv2.cvtColor(image_np, cv2.COLOR_RGBA2GRAY)

        else:

            gray = image_np

    except Exception:

        pass

    if gray is not None:

        # Strategy 3: pyzbar on grayscale
        try:

            decoded_objects = decode(gray)

            if decoded_objects and decoded_objects[0].data:

                return decoded_objects[0].data.decode("utf-8")

        except Exception:

            pass

        # Strategy 4: OpenCV detector on grayscale
        try:

            detector = cv2.QRCodeDetector()

            val, points, _ = detector.detectAndDecode(gray)

            if val:

                return val

        except Exception:

            pass

        # Strategy 5: Thresholding/Binarization (Otsu's thresholding)
        try:

            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)

            decoded_objects = decode(thresh)

            if decoded_objects and decoded_objects[0].data:

                return decoded_objects[0].data.decode("utf-8")

        except Exception:

            pass

        try:

            detector = cv2.QRCodeDetector()

            val, points, _ = detector.detectAndDecode(thresh)

            if val:

                return val

        except Exception:

            pass

        # Strategy 6: Adaptive Thresholding (useful for uneven lighting)
        try:

            adaptive_thresh = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
            )

            decoded_objects = decode(adaptive_thresh)

            if decoded_objects and decoded_objects[0].data:

                return decoded_objects[0].data.decode("utf-8")

        except Exception:

            pass

        try:

            detector = cv2.QRCodeDetector()

            val, points, _ = detector.detectAndDecode(adaptive_thresh)

            if val:

                return val

        except Exception:

            pass

        # Strategy 7: Resize/Scale up (helps with small QR codes)
        try:

            height, width = gray.shape[:2]

            # Upscale 2x
            resized = cv2.resize(gray, (width * 2, height * 2), interpolation=cv2.INTER_CUBIC)

            decoded_objects = decode(resized)

            if decoded_objects and decoded_objects[0].data:

                return decoded_objects[0].data.decode("utf-8")

        except Exception:

            pass

        try:

            detector = cv2.QRCodeDetector()

            val, points, _ = detector.detectAndDecode(resized)

            if val:

                return val

        except Exception:

            pass

    return None

# ============================================================================
# UPI PARSER
# ============================================================================

def parse_upi_qr(raw_qr: str):

    """
    Extract UPI details from QR string.

    Example:
    upi://pay?pa=rahul@oksbi&pn=Rahul&am=500
    """

    try:

        result = {

            "upi_id": None,

            "merchant_name": None,

            "amount": 0,

            "transaction_note": None
        }

        # --------------------------------------------------------------------
        # UPI ID
        # --------------------------------------------------------------------

        if "pa=" in raw_qr:

            result["upi_id"] = (

                raw_qr.split("pa=")[1]

                .split("&")[0]
            )

        # --------------------------------------------------------------------
        # Merchant Name
        # --------------------------------------------------------------------

        if "pn=" in raw_qr:

            result["merchant_name"] = (

                raw_qr.split("pn=")[1]

                .split("&")[0]
            )

        # --------------------------------------------------------------------
        # Amount
        # --------------------------------------------------------------------

        if "am=" in raw_qr:

            amount = (

                raw_qr.split("am=")[1]

                .split("&")[0]
            )

            try:

                result["amount"] = float(
                    amount
                )

            except:

                result["amount"] = 0

        # --------------------------------------------------------------------
        # Transaction Note
        # --------------------------------------------------------------------

        if "tn=" in raw_qr:

            result["transaction_note"] = (

                raw_qr.split("tn=")[1]

                .split("&")[0]
            )

        return result

    except Exception as e:

        logger.error(
            f"❌ UPI Parse Failed: {str(e)}"
        )

        return None

# ============================================================================
# QR VALIDATOR
# ============================================================================

def validate_qr_data(parsed_data: dict):

    """
    Validate extracted QR data.
    """

    if not parsed_data:

        return False, "Invalid QR data"

    upi_id = parsed_data.get(
        "upi_id"
    )

    if not upi_id:

        return False, "UPI ID missing"

    # ------------------------------------------------------------------------
    # Basic UPI Validation
    # --------------------------------------------------------------------

    if "@" not in upi_id:

        return False, "Invalid UPI format"

    return True, "Valid QR"

# ============================================================================
# MERCHANT INTELLIGENCE
# ============================================================================

def analyze_merchant_risk(

    merchant_name: str | None
):

    """
    Merchant fraud intelligence.
    """

    try:

        if not merchant_name:

            return {

                "risk_score": 0,

                "reasons": []
            }

        lower = merchant_name.lower()

        risk = 0

        reasons = []

        # --------------------------------------------------------------------
        # Suspicious Keywords
        # --------------------------------------------------------------------

        for word in SUSPICIOUS_WORDS:

            if word in lower:

                risk += 15

                reasons.append(
                    f"Suspicious keyword: {word}"
                )

        # --------------------------------------------------------------------
        # Too Many Digits
        # --------------------------------------------------------------------

        digits = sum(

            c.isdigit()

            for c in merchant_name
        )

        if digits >= 5:

            risk += 15

            reasons.append(
                "Too many digits in merchant name"
            )

        # --------------------------------------------------------------------
        # Randomness Detection
        # --------------------------------------------------------------------

        special_chars = len(

            re.findall(

                r"[^a-zA-Z0-9 ]",

                merchant_name
            )
        )

        if special_chars >= 3:

            risk += 20

            reasons.append(
                "Random-looking merchant name"
            )

        return {

            "risk_score": min(risk, 100),

            "reasons": reasons
        }

    except Exception as e:

        logger.error(
            f"❌ Merchant Analysis Failed: {str(e)}"
        )

        return {

            "risk_score": 0,

            "reasons": []
        }

# ============================================================================
# PROCESS QR IMAGE
# ============================================================================

def process_qr_image(

    image_bytes: bytes,

    user_id: int | None = None
):

    """
    Full QR fraud analysis pipeline.
    """

    start = time.time()

    try:

        logger.info(
            """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📸 QR PROCESSING STARTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        # --------------------------------------------------------------------
        # Open Image
        # --------------------------------------------------------------------

        pil_image = Image.open(

            io.BytesIO(image_bytes)

        ).convert("RGB")

        image_np = np.array(
            pil_image
        )

        # --------------------------------------------------------------------
        # Decode QR
        # --------------------------------------------------------------------

        raw_qr = decode_qr_image(
            image_np
        )

        if not raw_qr:

            return {

                "success": False,

                "message": "No QR code detected"
            }

        # --------------------------------------------------------------------
        # Parse QR
        # --------------------------------------------------------------------
        parsed = parse_upi_qr(raw_qr)
        upi_id = parsed.get("upi_id")
        amount = parsed.get("amount") or 0.0
        merchant_name = parsed.get("merchant_name")

        valid, reason = validate_qr_data(parsed)

        if valid and upi_id:
            # --------------------------------------------------------------------
            # Merchant Intelligence
            # --------------------------------------------------------------------
            merchant_analysis = analyze_merchant_risk(merchant_name)

            # --------------------------------------------------------------------
            # Fraud Detection
            # --------------------------------------------------------------------
            fraud_result = detect_qr_fraud(
                upi_id=upi_id,
                amount=amount,
                user_id=user_id or 0,
                merchant_name=merchant_name
            )

            # --------------------------------------------------------------------
            # Combine Merchant Risk
            # --------------------------------------------------------------------
            combined_score = min(
                fraud_result["risk_score"] + merchant_analysis["risk_score"],
                100
            )
            fraud_result["risk_score"] = combined_score
        else:
            # Non-UPI QR code fallback (URL or generic text)
            from app.services.fraud_patterns.qr_analyzer import analyze_qr_content
            fraud_result = analyze_qr_content(
                qr_text=raw_qr,
                user_id=user_id,
                amount_override=amount
            )
            merchant_analysis = {
                "risk_score": 0,
                "reasons": []
            }
            combined_score = fraud_result["risk_score"]
            merchant_name = merchant_name or "N/A"
            parsed["upi_id"] = None
            parsed["merchant_name"] = merchant_name

        # --------------------------------------------------------------------
        # Final Risk Classification
        # --------------------------------------------------------------------
        if combined_score >= 80:
            fraud_result["risk_level"] = "HIGH"
            fraud_result["status"] = "FRAUD"
        elif combined_score >= 50:
            fraud_result["risk_level"] = "MEDIUM"
            fraud_result["status"] = "SUSPICIOUS"
        else:
            fraud_result["risk_level"] = "LOW"
            fraud_result["status"] = "SAFE"

        # --------------------------------------------------------------------
        # Timing
        # --------------------------------------------------------------------
        execution_time = round(
            (time.time() - start) * 1000,
            2
        )

        logger.info(
            f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ QR ANALYSIS COMPLETE

🏦 UPI:
{parsed.get('upi_id')}

⚠️ Risk Score:
{combined_score}

🚨 Risk Level:
{fraud_result['risk_level']}

⏱️ Time:
{execution_time} ms
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        )

        # --------------------------------------------------------------------
        # Final Response
        # --------------------------------------------------------------------
        return {
            "success": True,
            "timestamp": datetime.utcnow(),
            "qr_data": parsed,
            "merchant_analysis": merchant_analysis,
            "fraud_analysis": fraud_result,
            "execution_time_ms": execution_time
        }

    except Exception as e:

        logger.error(
            f"""
❌ QR SERVICE FAILED

🧠 Error:
{str(e)}
"""
        )

        return {

            "success": False,

            "error": str(e)
        }

# ============================================================================
# BASE64 FRAME PROCESSOR
# ============================================================================

def process_base64_frame(
    image_base64: str,
    user_id: int | None = None
):
    """
    Process realtime camera frame.
    """
    try:
        if "," in image_base64:
            image_base64 = image_base64.split(",")[1]

        image_bytes = base64.b64decode(
            image_base64
        )

        return process_qr_image(
            image_bytes=image_bytes,
            user_id=user_id
        )

    except Exception as e:
        logger.error(
            f"""
❌ BASE64 FRAME PROCESS FAILED

🧠 Error:
{str(e)}
"""
        )
        return {
            "success": False,
            "error": str(e)
        }

# ============================================================================
# SECURITY ALERT GENERATOR
# ============================================================================

def generate_qr_security_alert(

    result: dict
):

    """
    Generate realtime QR alerts.
    """

    try:

        if not result.get("success"):

            return {

                "alert": False
            }

        score = result["fraud_analysis"][
            "risk_score"
        ]

        if score >= 90:

            severity = "CRITICAL"

        elif score >= 75:

            severity = "HIGH"

        elif score >= 50:

            severity = "MEDIUM"

        else:

            severity = "LOW"

        return {

            "alert": score >= 50,

            "severity": severity,

            "message":
                f"Potential QR fraud detected ({score})",

            "timestamp":
                datetime.utcnow()
        }

    except Exception as e:

        logger.error(
            f"""
❌ ALERT GENERATION FAILED

🧠 Error:
{str(e)}
"""
        )

        return {

            "alert": False
        }

# ============================================================================
# HEALTH CHECK
# ============================================================================

def qr_service_health():

    """
    QR service diagnostics.
    """

    try:

        return {

            "healthy": True,

            "opencv_loaded": True,

            "pyzbar_loaded": True,

            "timestamp":
                datetime.utcnow()
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

    print(
        """
🚀 QR SERVICE READY
"""
    )