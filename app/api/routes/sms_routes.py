# app/api/routes/sms_routes.py

from datetime import datetime
import re

from fastapi import (
    APIRouter,
    HTTPException,
    Depends
)

from pydantic import BaseModel

from app.database.db import get_db
from app.database.models import SMSScanHistory
from app.dependencies import get_current_user

from app.services.fraud_detection_service import (
    detect_text_fraud
)

from app.utils.logger import logger

# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    prefix="/sms",
    tags=["SMS Scam Detection"]
)

# ============================================================================
# Request Models
# ============================================================================

class SMSScanRequest(BaseModel):
    message: str
    sender: str | None = None
    ocr_text: str | None = None


class BulkSMSRequest(BaseModel):

    messages: list[str]


# Removed keyword constants and calculate_keyword_risk functions
# since they are now handled by the central multi-layer engine

@router.post("/scan")

async def scan_sms(

    data: SMSScanRequest,

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

        logger.info(
            f"📩 SMS Scan Started | User: {user_id}"
        )

        # --------------------------------------------------------------------
        # Basic Validation
        # --------------------------------------------------------------------

        if len(data.message.strip()) < 5:

            raise HTTPException(

                status_code=400,

                detail="Message too short"
            )

        # --------------------------------------------------------------------
        # Extract Metadata (Now handled by the engine)
        # --------------------------------------------------------------------

        # --------------------------------------------------------------------
        # ML Detection
        # --------------------------------------------------------------------

        ml_result = detect_text_fraud(
            text=data.message,
            sender=data.sender,
            ocr_text=data.ocr_text
        )

        final_risk = ml_result.get("risk_score", 0)
        risk_level = ml_result.get("risk_level", "SAFE")
        status = ml_result.get("status", "SAFE")
        confidence = "High" if final_risk >= 80 else "Moderate" if final_risk >= 50 else "Low"
        
        reasons = ml_result.get("reasons", [])

        summary = (
            f"This message has a {confidence.lower()} confidence fraud rating "
            f"({final_risk}%). "
            f"{reasons[0] if reasons else 'Review the message for suspicious requests.'}"
        )

        recommendation = (
            "Do not click links or share OTPs. Verify the sender independently "
            "through official channels."
        )

        analysis = {
            "risk_score": final_risk,
            "risk_level": risk_level,
            "status": status,
            "confidence": confidence,
            "summary": summary,
            "recommendation": recommendation,
            "reasons": reasons
        }

        # --------------------------------------------------------------------
        # Save History
        # --------------------------------------------------------------------

        history = SMSScanHistory(

            user_id=user_id,

            sender=data.sender,

            message=data.message[:500],

            risk_score=final_risk,

            risk_level=risk_level,

            status=status,

            created_at=datetime.utcnow()
        )

        db.add(history)

        # --------------------------------------------------------------------
        # Save to communication_intercept_logs
        # --------------------------------------------------------------------
        import random
        from app.database.models import CommunicationInterceptLog

        intercept_id = f"MSG_{random.randint(100000, 999999)}"
        scam_cat = "None"
        if ml_result.get("details") and ml_result["details"].get("scam_category"):
            scam_cat = ml_result["details"]["scam_category"]
        elif status == "SCAM":
            scam_cat = "Phishing Scam"

        intercept_log = CommunicationInterceptLog(
            message_id=intercept_id,
            sender_address=data.sender or "Unknown",
            message_body=data.message,
            timestamp_received=datetime.utcnow(),
            reported_scam_category=scam_cat
        )
        db.add(intercept_log)

        db.commit()

        # --------------------------------------------------------------------
        # Logging
        # --------------------------------------------------------------------

        logger.info(
            f"""
📩 SMS ANALYSIS COMPLETE

👤 User ID         : {user_id}
📱 Sender          : {data.sender}
⚠️ Risk Score      : {final_risk}
🚨 Risk Level      : {risk_level}
🧠 Reasons         : {reasons}
"""
        )

        # Broadcast threat if risk score >= 45
        if final_risk >= 45:
            import asyncio
            from app.services.ws_manager import ws_manager
            asyncio.create_task(ws_manager.broadcast({
                "type": "NEW_THREAT",
                "data": {
                    "threat_type": "TEXT",
                    "value": data.message[:120] + ("..." if len(data.message) > 120 else ""),
                    "risk_score": final_risk,
                    "risk_level": risk_level,
                    "timestamp": datetime.utcnow().isoformat()
                }
            }))

        # --------------------------------------------------------------------
        # Response
        # --------------------------------------------------------------------

        return {

            "success": True,

            "analysis": analysis
        }

    except HTTPException as e:

        raise e

    except Exception as e:

        logger.error(
            f"❌ SMS Scan Error: {str(e)}"
        )

        raise HTTPException(

            status_code=500,

            detail="SMS scan failed"
        )

# ============================================================================
# BULK SMS SCAN
# ============================================================================

@router.post("/bulk-scan")

async def bulk_sms_scan(

    data: BulkSMSRequest,

    current_user: dict = Depends(get_current_user)
):

    try:

        if not current_user or "user_id" not in current_user:

            raise HTTPException(

                status_code=401,

                detail="User not authenticated"
            )

        results = []

        for msg in data.messages:

            ml_result = detect_text_fraud(msg)

            final_risk = ml_result.get("risk_score", 0)

            results.append({

                "message": msg[:80],

                "risk_score": final_risk,

                "reasons": ml_result.get("reasons", [])
            })

            # Broadcast threat if risk score >= 45
            if final_risk >= 45:
                import asyncio
                from app.services.ws_manager import ws_manager
                asyncio.create_task(ws_manager.broadcast({
                    "type": "NEW_THREAT",
                    "data": {
                        "threat_type": "TEXT",
                        "value": msg[:120] + ("..." if len(msg) > 120 else ""),
                        "risk_score": final_risk,
                        "risk_level": "HIGH" if final_risk >= 80 else "MEDIUM",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                }))

        return {

            "success": True,

            "total_messages": len(results),

            "results": results
        }

    except Exception as e:

        logger.error(
            f"❌ Bulk SMS Scan Error: {str(e)}"
        )

        raise HTTPException(

            status_code=500,

            detail="Bulk SMS scan failed"
        )

# ============================================================================
# SMS HISTORY
# ============================================================================

@router.get("/history")

async def sms_history(

    db=Depends(get_db),

    current_user: dict = Depends(get_current_user)
):

    try:

        if not current_user or "user_id" not in current_user:

            raise HTTPException(

                status_code=401,

                detail="User not authenticated"
            )

        history = db.query(SMSScanHistory).filter(

            SMSScanHistory.user_id == current_user["user_id"]

        ).order_by(

            SMSScanHistory.created_at.desc()

        ).all()

        results = []

        for item in history:

            results.append({

                "id": item.id,

                "sender": item.sender,

                "message": item.message,

                "risk_score": item.risk_score,

                "risk_level": item.risk_level,

                "status": item.status,

                "created_at": item.created_at
            })

        return {

            "success": True,

            "total_records": len(results),

            "history": results
        }

    except Exception as e:

        logger.error(
            f"❌ SMS History Error: {str(e)}"
        )

        raise HTTPException(

            status_code=500,

            detail="Could not fetch SMS history"
        )

# ============================================================================
# REPORT SCAM SMS
# ============================================================================

@router.post("/report")

async def report_scam_sms(

    sender: str,

    message: str,

    reason: str,

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
🚨 SCAM SMS REPORTED

👤 User ID : {current_user['user_id']}
📱 Sender  : {sender}
📝 Reason  : {reason}

💬 Message:
{message}
"""
        )

        # Future:
        # Save into scam_reports table
        # Share with central fraud DB
        # Notify admins

        return {

            "success": True,

            "message": "Scam SMS reported successfully"
        }

    except Exception as e:

        logger.error(
            f"❌ SMS Report Error: {str(e)}"
        )

        raise HTTPException(

            status_code=500,

            detail="Could not report scam SMS"
        )

# ============================================================================
# SMS HEALTH CHECK
# ============================================================================

@router.get("/health")

async def sms_health():

    return {

        "success": True,

        "service": "SMS Scam Detection",

        "status": "Running"
    }