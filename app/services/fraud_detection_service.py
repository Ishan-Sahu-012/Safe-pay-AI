import time
from datetime import datetime
from app.services.engine.pipeline import execute_fraud_pipeline
from app.utils.logger import logger

def format_response(service: str, result: dict, execution_time: float):
    """
    Standardized fraud response using Explainable AI format.
    """
    return {
        "success": True,
        "service": service,
        "timestamp": datetime.utcnow(),
        "execution_time_ms": execution_time,
        "risk_score": result.get("risk_score"),
        "risk_level": result.get("level"),
        "status": "FRAUD" if result.get("risk_score", 0) >= 80 else "SUSPICIOUS" if result.get("risk_score", 0) >= 50 else "SAFE",
        "reasons": result.get("reasons", [])
    }

def detect_upi_fraud(upi_id: str, amount: float, seen_before: bool = False, report_count: int = 0, user_avg_amount: float = 1000, first_time_user: bool = True, merchant_name: str = None):
    # Backward compatibility for any internal calls
    return execute_fraud_pipeline(upi_id=upi_id, amount=amount, merchant_name=merchant_name)

def detect_qr_fraud(upi_id: str, amount: float, user_id: int, merchant_name: str | None = None, ocr_text: str = None):
    start = time.time()
    try:
        logger.info(f"📸 QR FRAUD ANALYSIS STARTED | User: {user_id} | UPI: {upi_id}")
        
        # We can still add merchant caching here if we want, but requirements 
        # specifically asked to replace the detection logic with the new pipeline.
        result = execute_fraud_pipeline(
            upi_id=upi_id,
            amount=amount,
            merchant_name=merchant_name,
            ocr_text=ocr_text
        )
        
        execution_time = round((time.time() - start) * 1000, 2)
        return format_response("QR Fraud Detection", result, execution_time)
        
    except Exception as e:
        logger.error(f"❌ QR FRAUD DETECTION FAILED: {str(e)}")
        return {"success": False, "error": str(e), "risk_score": 0, "risk_level": "UNKNOWN", "status": "ERROR"}

def detect_text_fraud(text: str, sender: str | None = None, sender_email: str | None = None, ocr_text: str = None):
    start = time.time()
    try:
        logger.info("📩 TEXT FRAUD ANALYSIS STARTED")
        
        result = execute_fraud_pipeline(
            text=text,
            sender=sender or sender_email,
            ocr_text=ocr_text
        )
        
        execution_time = round((time.time() - start) * 1000, 2)
        return format_response("Text Scam Detection", result, execution_time)
        
    except Exception as e:
        logger.error(f"❌ TEXT FRAUD DETECTION FAILED: {str(e)}")
        return {"success": False, "error": str(e), "risk_score": 0, "risk_level": "UNKNOWN", "status": "ERROR"}

def hybrid_fraud_analysis(upi_id: str | None = None, amount: float | None = None, text: str | None = None, ocr_text: str = None):
    start = time.time()
    try:
        result = execute_fraud_pipeline(
            upi_id=upi_id,
            amount=amount,
            text=text,
            ocr_text=ocr_text
        )
        execution_time = round((time.time() - start) * 1000, 2)
        return format_response("Hybrid Fraud Intelligence", result, execution_time)
        
    except Exception as e:
        logger.error(f"❌ HYBRID ANALYSIS FAILED: {str(e)}")
        return {"success": False, "error": str(e)}

def service_health():
    return {
        "healthy": True,
        "timestamp": datetime.utcnow()
    }