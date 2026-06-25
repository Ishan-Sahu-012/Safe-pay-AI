import re

class SocialEngineeringAnalyzer:
    """
    Detects investment scams, urgency, fear, and reward manipulation.
    """
    
    INVESTMENT_SCAM_PATTERNS = [
        r'guaranteed return', r'double (your )?money', r'crypto profit',
        r'daily income', r'telegram investment', r'100% profit',
        r'high returns', r'multiply your money', r'investment plan'
    ]
    
    URGENCY_FEAR_PATTERNS = [
        r'account (will be )?blocked', r'kyc suspension', r'immediate action',
        r'urgent(ly)?', r'action required', r'suspend your account',
        r'within \d+ hours', r'last warning'
    ]
    
    REWARD_PATTERNS = [
        r'you have won', r'cashback of', r'claim your (prize|reward)',
        r'lottery winner', r'free bonus', r'exclusive offer'
    ]

    @classmethod
    def analyze(cls, text: str) -> dict:
        score = 0
        reasons = []
        
        text_lower = text.lower()
        
        # Investment Scams
        for pattern in cls.INVESTMENT_SCAM_PATTERNS:
            if re.search(pattern, text_lower):
                score += 50
                reasons.append("Investment Scam Pattern")
                break # only apply once
                
        # Urgency / Fear
        for pattern in cls.URGENCY_FEAR_PATTERNS:
            if re.search(pattern, text_lower):
                score += 15
                reasons.append("Urgency/Fear Language")
                break
                
        # Reward Manipulation
        for pattern in cls.REWARD_PATTERNS:
            if re.search(pattern, text_lower):
                score += 20
                reasons.append("Reward Manipulation")
                break
                
        return {
            "score": score,
            "reasons": reasons
        }
