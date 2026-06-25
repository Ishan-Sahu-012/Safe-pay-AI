# app/api/routes/qr_routes.py

import base64
import io
import uuid
from datetime import datetime

import cv2
import numpy as np

from fastapi import (
    APIRouter,
    UploadFile,
    File,
    HTTPException,
    Depends
)

from pydantic import BaseModel

from PIL import Image
from pyzbar.pyzbar import decode

from app.database.db import get_db
from app.database.models import QRScanHistory
from app.dependencies import get_current_user
from app.services.fraud_detection_service import detect_qr_fraud
from app.services.fraud_patterns.qr_analyzer import analyze_qr_content
from app.utils.logger import logger

# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    prefix="/qr",
    tags=["QR Detection"]
)

# ============================================================================
# Helper Function
# ============================================================================

def _try_decode(image, strategy_name):
    """Try pyzbar + OpenCV QRCodeDetector on an image. Returns decoded string or None."""
    # pyzbar
    try:
        decoded_objects = decode(image)
        if decoded_objects and decoded_objects[0].data:
            logger.info(f"✅ QR decoded via {strategy_name} (pyzbar)")
            return decoded_objects[0].data.decode("utf-8")
    except Exception:
        pass
    # OpenCV QRCodeDetector
    try:
        detector = cv2.QRCodeDetector()
        val, points, _ = detector.detectAndDecode(image)
        if val:
            logger.info(f"✅ QR decoded via {strategy_name} (OpenCV)")
            return val
    except Exception:
        pass
    return None


def extract_qr_data(image_np):
    """
    Extract QR content from image with 12 fallback pre-processing strategies.
    Tries both pyzbar and OpenCV QRCodeDetector at each stage.
    Strategies cover clean images, photos, screenshots, inverted QRs, and blurry captures.
    """
    logger.info(f"🔍 QR extraction starting — image shape: {image_np.shape}, dtype: {image_np.dtype}")

    # Strategy 1: Direct decode on raw image
    result = _try_decode(image_np, "S1-raw")
    if result:
        return result

    # Convert to grayscale for further processing
    gray = None
    try:
        if len(image_np.shape) == 3:
            if image_np.shape[2] == 4:
                gray = cv2.cvtColor(image_np, cv2.COLOR_RGBA2GRAY)
            else:
                gray = cv2.cvtColor(image_np, cv2.COLOR_RGB2GRAY)
        else:
            gray = image_np
    except Exception:
        pass

    if gray is None:
        logger.warning("⚠️ QR extraction: could not convert to grayscale")
        return None

    # Strategy 2: Grayscale
    result = _try_decode(gray, "S2-grayscale")
    if result:
        return result

    # Strategy 3: Otsu's thresholding
    try:
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
        result = _try_decode(thresh, "S3-otsu")
        if result:
            return result
    except Exception:
        pass

    # Strategy 4: Adaptive thresholding (handles uneven lighting)
    try:
        adaptive = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
        )
        result = _try_decode(adaptive, "S4-adaptive-thresh")
        if result:
            return result
    except Exception:
        pass

    # Strategy 5: CLAHE contrast enhancement (handles low-contrast photos)
    try:
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        result = _try_decode(enhanced, "S5-CLAHE")
        if result:
            return result
    except Exception:
        pass

    # Strategy 6: CLAHE + Otsu (combined)
    try:
        clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        _, clahe_thresh = cv2.threshold(enhanced, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
        result = _try_decode(clahe_thresh, "S6-CLAHE+otsu")
        if result:
            return result
    except Exception:
        pass

    # Strategy 7: Sharpening (handles blurry photos)
    try:
        sharpen_kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
        sharpened = cv2.filter2D(gray, -1, sharpen_kernel)
        result = _try_decode(sharpened, "S7-sharpened")
        if result:
            return result
    except Exception:
        pass

    # Strategy 8: Gaussian denoising (handles noisy camera photos)
    try:
        denoised = cv2.GaussianBlur(gray, (3, 3), 0)
        _, denoised_thresh = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
        result = _try_decode(denoised_thresh, "S8-denoised+otsu")
        if result:
            return result
    except Exception:
        pass

    # Strategy 9: Inverted image (handles white-on-black QR codes)
    try:
        inverted = cv2.bitwise_not(gray)
        result = _try_decode(inverted, "S9-inverted")
        if result:
            return result
        _, inv_thresh = cv2.threshold(inverted, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
        result = _try_decode(inv_thresh, "S9-inverted+otsu")
        if result:
            return result
    except Exception:
        pass

    # Strategy 10: Upscale 2x (helps with small QR codes)
    try:
        h, w = gray.shape[:2]
        resized_up = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
        result = _try_decode(resized_up, "S10-upscale-2x")
        if result:
            return result
    except Exception:
        pass

    # Strategy 11: Upscale 3x (very small QR codes)
    try:
        h, w = gray.shape[:2]
        resized_3x = cv2.resize(gray, (w * 3, h * 3), interpolation=cv2.INTER_CUBIC)
        result = _try_decode(resized_3x, "S11-upscale-3x")
        if result:
            return result
    except Exception:
        pass

    # Strategy 12: Downscale large images (>2000px — pyzbar can choke on very large images)
    try:
        h, w = gray.shape[:2]
        if max(h, w) > 2000:
            scale = 1500.0 / max(h, w)
            resized_down = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
            result = _try_decode(resized_down, "S12-downscale")
            if result:
                return result
            _, down_thresh = cv2.threshold(resized_down, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
            result = _try_decode(down_thresh, "S12-downscale+otsu")
            if result:
                return result
    except Exception:
        pass

    logger.warning("❌ QR extraction failed — all 12 strategies exhausted")
    return None


# ============================================================================
# Parse UPI QR
# ============================================================================

def parse_upi_qr(qr_text: str):

    """
    Extract UPI details from raw QR string.

    Example:
    upi://pay?pa=rahul@oksbi&pn=Rahul&am=500
    """

    result = {

        "upi_id": None,

        "name": None,

        "amount": None
    }

    try:

        if "pa=" in qr_text:

            upi_id = qr_text.split("pa=")[1].split("&")[0]

            result["upi_id"] = upi_id

        if "pn=" in qr_text:

            name = qr_text.split("pn=")[1].split("&")[0]

            result["name"] = name

        if "am=" in qr_text:

            amount = qr_text.split("am=")[1].split("&")[0]

            result["amount"] = float(amount)

    except Exception:

        pass

    return result


# ============================================================================
# QR IMAGE SCAN API
# ============================================================================

@router.post("/scan-image")

async def scan_qr_image(

    file: UploadFile = File(...),

    db=Depends(get_db),

    current_user: dict = Depends(get_current_user)
):

    try:

        # --------------------------------------------------------------------
        # Logged-in User
        # --------------------------------------------------------------------

        if not current_user or "user_id" not in current_user:

            raise HTTPException(

                status_code=401,

                detail="User not authenticated"
            )

        user_id = current_user["user_id"]

        # --------------------------------------------------------------------
        # Validate File
        # --------------------------------------------------------------------

        allowed_types = [

            "image/png",

            "image/jpeg",

            "image/jpg"
        ]

        if file.content_type not in allowed_types:

            raise HTTPException(

                status_code=400,

                detail="Only PNG/JPG images allowed"
            )

        # --------------------------------------------------------------------
        # Read Image
        # --------------------------------------------------------------------

        image_bytes = await file.read()

        pil_image = Image.open(

            io.BytesIO(image_bytes)

        ).convert("RGB")

        image_np = np.array(pil_image)

        # --------------------------------------------------------------------
        # QR Extraction
        # --------------------------------------------------------------------

        qr_data = extract_qr_data(image_np)

        if not qr_data:

            raise HTTPException(

                status_code=404,

                detail="No QR code detected"
            )

        logger.info(
            f"""
📸 QR DETECTED

👤 User ID : {user_id}
📦 Raw QR  : {qr_data}
"""
        )

        # --------------------------------------------------------------------
        # Parse QR
        # --------------------------------------------------------------------

        parsed = parse_upi_qr(qr_data)

        upi_id = parsed["upi_id"]

        amount = parsed["amount"] or 0

        merchant_name = parsed["name"]

        # --------------------------------------------------------------------
        # Fraud Detection
        # --------------------------------------------------------------------

        if upi_id:
            analysis = detect_qr_fraud(

                upi_id=upi_id,

                amount=amount,

                user_id=user_id,

                merchant_name=merchant_name
            )
        else:
            # URL / non-UPI QR payload analysis path
            analysis = analyze_qr_content(
                qr_text=qr_data,
                user_id=user_id,
                amount_override=amount
            )
            if not merchant_name:
                merchant_name = "N/A"

        # --------------------------------------------------------------------
        # Save History
        # --------------------------------------------------------------------

        history = QRScanHistory(

            user_id=user_id,

            upi_id=upi_id,

            merchant_name=merchant_name,

            amount=amount,

            raw_qr=qr_data,

            risk_score=analysis.get("risk_score", 0),

            risk_level=analysis.get("risk_level", "LOW"),

            status=analysis.get("status", "SAFE"),

            created_at=datetime.utcnow()
        )

        db.add(history)

        db.commit()

        # --------------------------------------------------------------------
        # Final Logging
        # --------------------------------------------------------------------

        logger.info(
            f"""
✅ QR ANALYSIS COMPLETE

🏦 UPI ID      : {upi_id or 'N/A'}
💰 Amount      : ₹{amount}
⚠️ Risk Score  : {analysis['risk_score']}
🚨 Risk Level  : {analysis['risk_level']}
"""
        )

        # Broadcast threat if risk score >= 45
        if analysis.get("risk_score", 0) >= 45:
            import asyncio
            from app.services.ws_manager import ws_manager
            asyncio.create_task(ws_manager.broadcast({
                "type": "NEW_THREAT",
                "data": {
                    "threat_type": "UPI" if upi_id else "QR_CONTENT",
                    "value": upi_id or qr_data,
                    "risk_score": analysis.get("risk_score", 0),
                    "risk_level": analysis.get("risk_level", "LOW"),
                    "merchant_name": merchant_name or "Unknown",
                    "timestamp": datetime.utcnow().isoformat()
                }
            }))

        # --------------------------------------------------------------------
        # Response
        # --------------------------------------------------------------------

        return {

            "success": True,

            "message": "QR scanned successfully",

            "qr_data": {

                "upi_id": upi_id,

                "merchant_name": merchant_name,

                "amount": amount,

                "raw_qr": qr_data
            },

            "analysis": analysis
        }

    except HTTPException as e:

        raise e

    except Exception as e:

        logger.error(
            f"❌ QR Scan Error: {str(e)}"
        )

        raise HTTPException(

            status_code=500,

            detail="QR scanning failed"
        )


# ============================================================================
# LIVE CAMERA FRAME SCAN
# ============================================================================

class LiveFrameRequest(BaseModel):
    image_base64: str

@router.post("/scan-frame")
async def scan_live_frame(
    data: LiveFrameRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Mobile app sends camera frame in base64.
    """
    try:
        if not current_user or "user_id" not in current_user:
            raise HTTPException(
                status_code=401,
                detail="User not authenticated"
            )

        image_base64 = data.image_base64
        if "," in image_base64:
            image_base64 = image_base64.split(",")[1]

        # --------------------------------------------------------------------
        # Decode Base64
        # --------------------------------------------------------------------
        try:
            image_data = base64.b64decode(image_base64)
            image = Image.open(
                io.BytesIO(image_data)
            ).convert("RGB")
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid base64 image data: {str(e)}"
            )

        image_np = np.array(image)

        # --------------------------------------------------------------------
        # QR Detection
        # --------------------------------------------------------------------
        qr_data = extract_qr_data(image_np)
        if not qr_data:
            return {
                "success": False,
                "qr_detected": False,
                "message": "No QR detected"
            }

        parsed = parse_upi_qr(qr_data)
        upi_id = parsed["upi_id"]
        amount = parsed["amount"] or 0.0
        merchant_name = parsed["name"]

        # Run risk/fraud analysis on the detected QR data
        if upi_id:
            analysis = detect_qr_fraud(
                upi_id=upi_id,
                amount=amount,
                user_id=current_user["user_id"],
                merchant_name=merchant_name
            )
        else:
            analysis = analyze_qr_content(
                qr_text=qr_data,
                user_id=current_user["user_id"],
                amount_override=amount
            )
            if not merchant_name:
                merchant_name = "N/A"

        # --------------------------------------------------------------------
        # Response
        # --------------------------------------------------------------------
        return {
            "success": True,
            "qr_detected": True,
            "qr_data": {
                "upi_id": upi_id,
                "merchant_name": merchant_name,
                "amount": amount,
                "raw_qr": qr_data
            },
            "analysis": analysis
        }

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(
            f"❌ Live Frame Scan Error: {str(e)}"
        )
        raise HTTPException(
            status_code=500,
            detail="Live frame scan failed"
        )


# ============================================================================
# QR HISTORY
# ============================================================================

@router.get("/history")

async def qr_history(

    db=Depends(get_db),

    current_user: dict = Depends(get_current_user)
):

    try:

        if not current_user or "user_id" not in current_user:

            raise HTTPException(

                status_code=401,

                detail="User not authenticated"
            )

        history = db.query(QRScanHistory).filter(

            QRScanHistory.user_id == current_user["user_id"]

        ).order_by(

            QRScanHistory.created_at.desc()

        ).all()

        result = []

        for item in history:

            result.append({

                "id": item.id,

                "upi_id": item.upi_id,

                "merchant_name": item.merchant_name,

                "amount": item.amount,

                "risk_score": item.risk_score,

                "risk_level": item.risk_level,

                "status": item.status,

                "created_at": item.created_at
            })

        return {

            "success": True,

            "total_scans": len(result),

            "history": result
        }

    except Exception as e:

        logger.error(
            f"❌ QR History Error: {str(e)}"
        )

        raise HTTPException(

            status_code=500,

            detail="Could not fetch QR history"
        )


# ============================================================================
# QR HEALTH CHECK
# ============================================================================

@router.get("/health")

async def qr_service_health():

    return {

        "success": True,

        "service": "QR Detection Service",

        "status": "Running"
    }


# ============================================================================
# ANALYZE DECODED QR PAYLOAD (Phase 1 fast endpoint)
# No image upload — accepts pre-decoded QR string from client-side jsQR.
# Latency: ~50ms vs ~300ms for /scan-image.
# ============================================================================

class QRPayloadRequest(BaseModel):
    payload: str

@router.post("/analyze-payload")
async def analyze_qr_payload(
    data: QRPayloadRequest,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Fast QR fraud analysis from a decoded QR string.
    Called by the browser extension after client-side jsQR decoding.
    Skips image upload and pyzbar — just parses the UPI payload and runs ML.
    """
    try:
        if not current_user or "user_id" not in current_user:
            raise HTTPException(status_code=401, detail="User not authenticated")

        user_id  = current_user["user_id"]
        qr_data  = data.payload.strip()

        if not qr_data:
            raise HTTPException(status_code=400, detail="Empty QR payload")

        logger.info(f"⚡ QR Payload Analysis | User: {user_id} | Payload: {qr_data[:80]}")

        # Parse UPI fields from decoded string
        parsed      = parse_upi_qr(qr_data)
        upi_id      = parsed["upi_id"]
        amount      = parsed["amount"] or 0.0
        merchant    = parsed["name"]

        if upi_id:
            analysis = detect_qr_fraud(
                upi_id=upi_id,
                amount=amount,
                user_id=user_id,
                merchant_name=merchant
            )
        else:
            # Non-UPI QR payload (URL, text, etc.)
            from app.services.fraud_patterns.qr_analyzer import analyze_qr_content
            analysis    = analyze_qr_content(qr_text=qr_data, user_id=user_id, amount_override=amount)
            merchant    = merchant or "N/A"

        # Persist to QR history
        history = QRScanHistory(
            user_id      = user_id,
            upi_id       = upi_id,
            merchant_name= merchant,
            amount       = amount,
            raw_qr       = qr_data,
            risk_score   = analysis.get("risk_score", 0),
            risk_level   = analysis.get("risk_level", "LOW"),
            status       = analysis.get("status", "SAFE"),
            created_at   = datetime.utcnow()
        )
        db.add(history)
        db.commit()

        # Broadcast threat if risk score >= 45
        if analysis.get("risk_score", 0) >= 45:
            import asyncio
            from app.services.ws_manager import ws_manager
            asyncio.create_task(ws_manager.broadcast({
                "type": "NEW_THREAT",
                "data": {
                    "threat_type": "UPI" if upi_id else "QR_CONTENT",
                    "value": upi_id or qr_data,
                    "risk_score": analysis.get("risk_score", 0),
                    "risk_level": analysis.get("risk_level", "LOW"),
                    "merchant_name": merchant or "Unknown",
                    "timestamp": datetime.utcnow().isoformat()
                }
            }))

        return {
            "success":  True,
            "source":   "payload",
            "qr_data":  {
                "upi_id":        upi_id,
                "merchant_name": merchant,
                "amount":        amount,
                "raw_qr":        qr_data
            },
            "analysis": analysis
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ QR Payload Analysis Error: {str(e)}")
        raise HTTPException(status_code=500, detail="QR payload analysis failed")