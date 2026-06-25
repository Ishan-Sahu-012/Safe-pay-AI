class ExplainableDecisionEngine:
    """
    Takes the final score, determines the risk level,
    and formats the output strictly as requested,
    without raw probabilities.
    """
    
    @classmethod
    def get_decision(cls, risk_score: int, reasons: list) -> dict:
        if risk_score >= 90:
            level = "CRITICAL"
        elif risk_score >= 75:
            level = "HIGH"
        elif risk_score >= 50:
            level = "MEDIUM"
        elif risk_score >= 25:
            level = "LOW"
        else:
            level = "SAFE"
            
        return {
            "risk_score": risk_score,
            "level": level,
            "reasons": reasons
        }
