# app/api/routes/fraud_routes.py

from datetime import datetime

from fastapi import (
    APIRouter,
    HTTPException,
    Depends
)

from pydantic import BaseModel

from app.services.fraud_detection_service import (
    detect_qr_fraud,
    detect_text_fraud,
)

from app.database.db import get_db

from app.database.models import ScanHistory, SMSScanHistory, QRScanHistory

from app.dependencies import get_current_user

from app.utils.logger import logger

# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    prefix="/fraud",
    tags=["Fraud Detection"]
)

# ============================================================================
# Request Models
# ============================================================================

class QRScanRequest(BaseModel):
    upi_id: str
    amount: float
    merchant_name: str | None = None
    ocr_text: str | None = None


class TextScanRequest(BaseModel):
    text: str
    sender: str | None = None
    ocr_text: str | None = None


# ============================================================================
# QR FRAUD DETECTION API
# ============================================================================

@router.post("/scan-qr")

async def scan_qr_code(
    data: QRScanRequest,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    try:

        # --------------------------------------------------------------------
        # Current Logged-in User
        # --------------------------------------------------------------------

        if not current_user or "user_id" not in current_user:

            raise HTTPException(
                status_code=401,
                detail="User not authenticated"
            )

        user_id = current_user["user_id"]

        logger.info(
            f"🔍 QR Scan Started | User: {user_id}"
        )

        # --------------------------------------------------------------------
        # Fraud Detection
        # --------------------------------------------------------------------

        result = detect_qr_fraud(
            upi_id=data.upi_id,
            amount=data.amount,
            user_id=user_id,
            merchant_name=data.merchant_name,
            ocr_text=data.ocr_text
        )

        # --------------------------------------------------------------------
        # Save Scan History
        # --------------------------------------------------------------------

        history = ScanHistory(

            user_id=user_id,

            scan_type="QR",

            input_value=data.upi_id,

            risk_score=result["risk_score"],

            risk_level=result["risk_level"],

            status=result["status"],

            created_at=datetime.utcnow()
        )

        db.add(history)

        db.commit()

        # --------------------------------------------------------------------
        # Logging
        # --------------------------------------------------------------------

        logger.info(
            f"""
✅ QR Fraud Scan Completed

👤 User ID     : {user_id}
🏦 UPI ID      : {data.upi_id}
💰 Amount      : ₹{data.amount}
⚠️ Risk Score  : {result['risk_score']}
🚨 Risk Level  : {result['risk_level']}
"""
        )

        # Broadcast threat if risk score >= 45
        if result.get("risk_score", 0) >= 45:
            import asyncio
            from app.services.ws_manager import ws_manager
            asyncio.create_task(ws_manager.broadcast({
                "type": "NEW_THREAT",
                "data": {
                    "threat_type": "UPI",
                    "value": data.upi_id,
                    "risk_score": result.get("risk_score", 0),
                    "risk_level": result.get("risk_level", "LOW"),
                    "merchant_name": data.merchant_name or "Unknown",
                    "timestamp": datetime.utcnow().isoformat()
                }
            }))

        # --------------------------------------------------------------------
        # Response
        # --------------------------------------------------------------------

        return {

            "success": True,

            "scan_type": "QR",

            "data": {

                "upi_id": data.upi_id,

                "amount": data.amount,

                "merchant_name": data.merchant_name
            },

            "analysis": result
        }

    except Exception as e:

        logger.error(
            f"❌ QR Fraud Scan Error: {str(e)}"
        )

        raise HTTPException(
            status_code=500,
            detail="QR fraud scan failed"
        )


# ============================================================================
# TEXT / SMS FRAUD DETECTION API
# ============================================================================

@router.post("/scan-text")

async def scan_text_message(
    data: TextScanRequest,
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    try:

        # --------------------------------------------------------------------
        # Current User
        # --------------------------------------------------------------------

        if not current_user or "user_id" not in current_user:

            raise HTTPException(
                status_code=401,
                detail="User not authenticated"
            )

        user_id = current_user["user_id"]

        logger.info(
            f"📩 Text Scan Started | User: {user_id}"
        )

        # --------------------------------------------------------------------
        # Text Fraud Detection
        # --------------------------------------------------------------------

        result = detect_text_fraud(
            text=data.text,
            sender=data.sender,
            ocr_text=data.ocr_text
        )

        # --------------------------------------------------------------------
        # Save History
        # --------------------------------------------------------------------

        history = ScanHistory(

            user_id=user_id,

            scan_type="TEXT",

            input_value=data.text[:100],

            risk_score=result["risk_score"],

            risk_level=result["risk_level"],

            status=result["status"],

            created_at=datetime.utcnow()
        )

        db.add(history)

        db.commit()

        # --------------------------------------------------------------------
        # Logging
        # --------------------------------------------------------------------

        logger.info(
            f"""
✅ Text Fraud Scan Completed

👤 User ID     : {user_id}
⚠️ Risk Score  : {result['risk_score']}
🚨 Risk Level  : {result['risk_level']}
"""
        )

        # Broadcast threat if risk score >= 45
        if result.get("risk_score", 0) >= 45:
            import asyncio
            from app.services.ws_manager import ws_manager
            asyncio.create_task(ws_manager.broadcast({
                "type": "NEW_THREAT",
                "data": {
                    "threat_type": "TEXT",
                    "value": data.text[:120] + ("..." if len(data.text) > 120 else ""),
                    "risk_score": result.get("risk_score", 0),
                    "risk_level": result.get("risk_level", "LOW"),
                    "timestamp": datetime.utcnow().isoformat()
                }
            }))

        # --------------------------------------------------------------------
        # Response
        # --------------------------------------------------------------------

        return {

            "success": True,

            "scan_type": "TEXT",

            "analysis": result
        }

    except Exception as e:

        logger.error(
            f"❌ Text Fraud Scan Error: {str(e)}"
        )

        raise HTTPException(
            status_code=500,
            detail="Text fraud scan failed"
        )


# ============================================================================
# BULK SCAN API
# ============================================================================

@router.post("/bulk-scan")

async def bulk_scan(
    requests: list[QRScanRequest],
    current_user: dict = Depends(get_current_user)
):

    try:

        if not current_user or "user_id" not in current_user:

            raise HTTPException(
                status_code=401,
                detail="User not authenticated"
            )

        results = []

        for item in requests:

            result = detect_qr_fraud(
                upi_id=item.upi_id,
                amount=item.amount,
                user_id=current_user["user_id"],
                merchant_name=item.merchant_name,
                ocr_text=item.ocr_text
            )

            results.append({

                "upi_id": item.upi_id,

                "amount": item.amount,

                "analysis": result
            })

            # Broadcast threat if risk score >= 45
            if result.get("risk_score", 0) >= 45:
                import asyncio
                from app.services.ws_manager import ws_manager
                asyncio.create_task(ws_manager.broadcast({
                    "type": "NEW_THREAT",
                    "data": {
                        "threat_type": "UPI",
                        "value": item.upi_id,
                        "risk_score": result.get("risk_score", 0),
                        "risk_level": result.get("risk_level", "LOW"),
                        "merchant_name": item.merchant_name or "Unknown",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                }))

        return {

            "success": True,

            "total_scans": len(results),

            "results": results
        }

    except Exception as e:

        logger.error(
            f"❌ Bulk Scan Error: {str(e)}"
        )

        raise HTTPException(
            status_code=500,
            detail="Bulk scan failed"
        )


# ============================================================================
# SCAN HISTORY API
# ============================================================================

@router.get("/history")

async def get_scan_history(
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user)
):

    try:

        if not current_user or "user_id" not in current_user:

            raise HTTPException(
                status_code=401,
                detail="User not authenticated"
            )

        history = db.query(ScanHistory).filter(

            ScanHistory.user_id == current_user["user_id"]

        ).order_by(

            ScanHistory.created_at.desc()

        ).all()

        response = []

        for item in history:

            response.append({

                "id": item.id,

                "scan_type": item.scan_type,

                "input_value": item.input_value,

                "risk_score": item.risk_score,

                "risk_level": item.risk_level,

                "status": item.status,

                "created_at": item.created_at
            })

        return {

            "success": True,

            "total_records": len(response),

            "history": response
        }

    except Exception as e:

        logger.error(
            f"❌ History Fetch Error: {str(e)}"
        )

        raise HTTPException(
            status_code=500,
            detail="Could not fetch history"
        )


# ============================================================================
# FRAUD REPORT API
# ============================================================================

@router.post("/report-upi")

async def report_fraud_upi(

    upi_id: str,

    reason: str,

    db=Depends(get_db),

    current_user: dict = Depends(get_current_user)
):

    try:

        if not current_user or "user_id" not in current_user:

            raise HTTPException(
                status_code=401,
                detail="User not authenticated"
            )

        logger.warning(
            f"""
🚨 FRAUD REPORT SUBMITTED

👤 User ID : {current_user['user_id']}
🏦 UPI ID  : {upi_id}
📝 Reason  : {reason}
"""
        )

        from app.database.models import UPIMerchantRegistry
        import random

        merchant = db.query(UPIMerchantRegistry).filter(UPIMerchantRegistry.upi_id == upi_id).first()
        if merchant:
            merchant.historical_report_count += 1
        else:
            new_mch_id = f"MCH_{random.randint(100000, 999999)}"
            merchant = UPIMerchantRegistry(
                merchant_id=new_mch_id,
                upi_id=upi_id,
                merchant_name="Reported Unknown Merchant",
                is_verified_merchant=0,
                historical_report_count=1,
                merchant_avg_transaction_val=0.0
            )
            db.add(merchant)
        db.commit()

        return {

            "success": True,

            "message": "Fraud report submitted successfully"
        }

    except Exception as e:

        logger.error(
            f"❌ Fraud Report Error: {str(e)}"
        )

        raise HTTPException(
            status_code=500,
            detail="Could not submit report"
        )


# ============================================================================
# SYSTEM HEALTH CHECK
# ============================================================================

@router.get("/health")

async def fraud_service_health():

    return {

        "success": True,

        "service": "Fraud Detection Service",

        "status": "Running"
    }


# ============================================================================
# FRAUD STATS API
# ============================================================================

@router.get("/stats")
async def get_fraud_stats(
    db=Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    try:
        if not current_user or "user_id" not in current_user:
            raise HTTPException(
                status_code=401,
                detail="User not authenticated"
            )
        user_id = current_user["user_id"]

        # Fetch all histories for user
        history_scans = db.query(ScanHistory).filter(ScanHistory.user_id == user_id).all()
        history_sms = db.query(SMSScanHistory).filter(SMSScanHistory.user_id == user_id).all()
        history_qr = db.query(QRScanHistory).filter(QRScanHistory.user_id == user_id).all()

        total_scans = len(history_scans) + len(history_sms) + len(history_qr)

        # Threats blocked (score >= 45)
        threats_blocked = 0
        safe_count = 0
        suspicious_count = 0
        fraud_count = 0

        # Combine recent list
        recent_items = []

        for item in history_scans:
            score = item.risk_score or 0
            if score >= 45:
                threats_blocked += 1
            
            # Category counting
            status = (item.status or "").upper()
            if score >= 75 or status in ("FRAUD", "SCAM"):
                fraud_count += 1
            elif score >= 45 or status == "SUSPICIOUS":
                suspicious_count += 1
            else:
                safe_count += 1

            recent_items.append({
                "id": item.id,
                "scan_type": item.scan_type or "TEXT",
                "input_value": item.input_value,
                "risk_score": score,
                "risk_level": item.risk_level or "LOW",
                "status": item.status or "SAFE",
                "created_at": item.created_at
            })

        for item in history_sms:
            score = item.risk_score or 0
            if score >= 45:
                threats_blocked += 1

            status = (item.status or "").upper()
            if score >= 75 or status in ("FRAUD", "SCAM"):
                fraud_count += 1
            elif score >= 45 or status == "SUSPICIOUS":
                suspicious_count += 1
            else:
                safe_count += 1

            recent_items.append({
                "id": item.id,
                "scan_type": "SMS",
                "input_value": item.message,
                "risk_score": score,
                "risk_level": item.risk_level or "LOW",
                "status": item.status or "SAFE",
                "created_at": item.created_at
            })

        for item in history_qr:
            score = item.risk_score or 0
            if score >= 45:
                threats_blocked += 1

            status = (item.status or "").upper()
            if score >= 75 or status in ("FRAUD", "SCAM"):
                fraud_count += 1
            elif score >= 45 or status == "SUSPICIOUS":
                suspicious_count += 1
            else:
                safe_count += 1

            recent_items.append({
                "id": item.id,
                "scan_type": "QR",
                "input_value": item.upi_id or item.raw_qr or "QR Code",
                "risk_score": score,
                "risk_level": item.risk_level or "LOW",
                "status": item.status or "SAFE",
                "created_at": item.created_at
            })

        # Sort combined recent items by created_at desc
        recent_items.sort(key=lambda x: x["created_at"] or datetime.min, reverse=True)
        recent = recent_items[:5]

        # Format datetime objects for output
        for r in recent:
            if isinstance(r["created_at"], datetime):
                r["created_at"] = r["created_at"].isoformat()

        return {
            "success": True,
            "total_scans": total_scans,
            "threats_blocked": threats_blocked,
            "safe_count": safe_count,
            "suspicious_count": suspicious_count,
            "fraud_count": fraud_count,
            "recent": recent
        }
    except Exception as e:
        logger.error(f"❌ Stats Fetch Error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Could not fetch stats"
        )