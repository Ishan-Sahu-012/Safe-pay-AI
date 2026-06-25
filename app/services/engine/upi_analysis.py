import re
import math

class UPIAnalyzer:
    """
    Analyzes UPI handles for entropy, random patterns, and validity.
    """
    
    TRUSTED_PSPS = ["oksbi", "okaxis", "okhdfcbank", "okicici", "paytm", "ibl", "axl", "upi", "sbi", "icici", "hdfc", "ybl"]
    
    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0
        probabilities = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log(p, 2) for p in probabilities)

    @classmethod
    def analyze(cls, upi_id: str, merchant_name: str = None) -> dict:
        score = 0
        reasons = []
        
        if "@" not in upi_id:
            return {"score": 50, "reasons": ["Invalid UPI Format"]}
            
        handle, psp = upi_id.split("@", 1)
        handle = handle.lower()
        psp = psp.lower()
        
        # Check PSP
        if psp not in cls.TRUSTED_PSPS:
            score += 25
            reasons.append(f"Unknown/Suspicious PSP (@{psp})")
            
        # Check Entropy (Random characters like x9f8kq2z)
        entropy = cls._shannon_entropy(handle)
        
        # Calculate alphanumeric randomness
        digits = sum(c.isdigit() for c in handle)
        chars = sum(c.isalpha() for c in handle)
        
        # If it's a mix of a lot of random chars and numbers, entropy is high
        if entropy > 3.0 and len(handle) >= 6:
            if digits > 0 and chars > 0:
                score += 20
                reasons.append("Random Alphanumeric Handle (High Entropy)")
                
        # Length check
        if len(handle) > 20:
            score += 15
            reasons.append("Unusually long UPI handle")
            
        # Check against merchant name consistency if provided
        if merchant_name and merchant_name.lower() != "unknown merchant":
            merchant_lower = merchant_name.lower()
            # If the handle represents a known business name but the merchant name doesn't match
            # This is a basic check.
            suspicious_keywords = ["customer", "support", "refund", "kyc", "help", "care"]
            if any(k in handle for k in suspicious_keywords) and not any(k in merchant_lower for k in suspicious_keywords):
                score += 25
                reasons.append("Handle implies support/refund but merchant name doesn't match")
                
        return {
            "score": score,
            "reasons": reasons
        }
