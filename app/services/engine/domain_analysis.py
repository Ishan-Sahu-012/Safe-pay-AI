import re
from urllib.parse import urlparse

class DomainAnalyzer:
    """
    Analyzes domains for typosquatting, suspicious TLDs, and fake bank domains.
    """
    
    TRUSTED_DOMAINS = [
        "hdfcbank.com", "onlinesbi.sbi", "sbi.co.in", 
        "icicibank.com", "axisbank.com", "kotak.com",
        "paytm.com", "phonepe.com", "amazon.in", "flipkart.com"
    ]
    
    SUSPICIOUS_TLDS = [".xyz", ".top", ".cc", ".icu", ".pw", ".online", ".site", ".tk", ".ml"]
    
    @staticmethod
    def _levenshtein(s1, s2):
        if len(s1) < len(s2):
            return DomainAnalyzer._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    @classmethod
    def analyze(cls, url: str) -> dict:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
            
        score = 0
        reasons = []
        
        # Exact match whitelist
        if domain in cls.TRUSTED_DOMAINS:
            return {"score": 0, "reasons": []}
            
        # TLD Check
        if any(domain.endswith(tld) for tld in cls.SUSPICIOUS_TLDS):
            score += 30
            reasons.append("Suspicious TLD")
            
        # IP Address instead of domain
        if re.match(r'^[\d\.]+$', domain):
            score += 35
            reasons.append("IP Address used as Domain")
            
        # Typosquatting / Fake Bank
        # Check against trusted domains for similarity
        for trusted in cls.TRUSTED_DOMAINS:
            trusted_base = trusted.split('.')[0]
            domain_base = domain.split('.')[0]
            
            # Substring match (e.g. hdfcbank-verification.com)
            if trusted_base in domain_base and domain != trusted:
                score += 40
                reasons.append(f"Fake Bank Domain ({trusted_base})")
                break
                
            # Typosquatting (distance 1 or 2)
            if len(domain_base) > 4:
                dist = cls._levenshtein(domain_base, trusted_base)
                if 0 < dist <= 2:
                    score += 40
                    reasons.append(f"Typosquatting Domain ({trusted_base})")
                    break
                    
        # Suspicious keywords in domain
        suspicious_keywords = ["secure", "update", "verify", "kyc", "login", "reward"]
        for kw in suspicious_keywords:
            if kw in domain:
                score += 15
                reasons.append("Suspicious keyword in domain")
                break
                
        # Shortened URL
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"]
        if domain in shorteners:
            score += 35
            reasons.append("Shortened URL")

        return {
            "score": score,
            "reasons": reasons
        }
