import re

class SenderVerifier:
    """
    Checks for mismatches between the claimed sender in the text and the actual sender.
    """
    
    BANK_NAMES = [
        "hdfc", "sbi", "icici", "axis", "kotak", "pnb", "bob", "yes bank", "paytm", "phonepe"
    ]
    
    @classmethod
    def analyze(cls, text: str, sender: str = None) -> dict:
        if not sender:
            return {"score": 0, "reasons": []}
            
        score = 0
        reasons = []
        
        text_lower = text.lower()
        sender_lower = sender.lower()
        
        # Did they claim to be a bank?
        claimed_banks = [bank for bank in cls.BANK_NAMES if bank in text_lower]
        
        if claimed_banks:
            # Does the sender actually contain the bank name?
            # E.g. Claims HDFC but sender is "VX-UPDATE" or a standard phone number
            is_matched = False
            for bank in claimed_banks:
                if bank in sender_lower:
                    is_matched = True
                    break
                    
            if not is_matched:
                score += 30
                reasons.append(f"Sender Mismatch (Claims to be {claimed_banks[0].upper()})")
                
        # If the sender is just a 10 digit phone number but claims to be an institution
        if re.match(r'^\+?\d{10,12}$', sender) and claimed_banks:
            score += 20
            reasons.append("Official institution using a standard phone number")
            
        return {
            "score": score,
            "reasons": reasons
        }
