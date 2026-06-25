class RiskScoringEngine:
    """
    Centralized weighting engine.
    Aggregates points and normalizes to 0-100.
    Handles false positive reduction.
    """
    
    @classmethod
    def calculate_score(cls, signal_results: list, ml_probability: float = 0.0) -> dict:
        total_score = 0
        all_reasons = []
        
        # Add up scores from all signals
        for result in signal_results:
            total_score += result.get("score", 0)
            all_reasons.extend(result.get("reasons", []))
            
        # Add ML probability contribution (weighted at 20 points max if we want to mix it)
        # But per requirements, ML is a layer. We can add its score.
        if ml_probability > 0:
            ml_score = int(ml_probability * 100)
            if ml_score > 75:
                total_score += 25
                all_reasons.append("High Risk Machine Learning Prediction")
            elif ml_score > 50:
                total_score += 10
                all_reasons.append("Suspicious Machine Learning Prediction")
                
        # Normalize to 0-100
        final_score = min(max(int(total_score), 0), 100)
        
        # Deduplicate reasons while preserving order
        seen = set()
        unique_reasons = []
        for r in all_reasons:
            if r not in seen:
                unique_reasons.append(r)
                seen.add(r)
                
        # False Positive Reduction: Context Validation
        # If no reasons were found and ML score is low, ensure it's 0
        if not unique_reasons and final_score < 25:
            final_score = 0
            
        # If the only reason is "Urgency/Fear Language" and it's a known bank
        # we might want to reduce it, but for now we rely on the points scaling.
        
        return {
            "risk_score": final_score,
            "reasons": unique_reasons
        }
