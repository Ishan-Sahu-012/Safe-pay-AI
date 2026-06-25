import re

class FeatureExtractor:
    """
    Extracts features (URLs, Emails, Phones, UPI IDs) from raw text or OCR.
    """
    
    URL_PATTERN = re.compile(r'https?://[^\s]+')
    EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
    PHONE_PATTERN = re.compile(r'\+?\d[\d -]{8,12}\d')
    UPI_PATTERN = re.compile(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}')

    @classmethod
    def extract_features(cls, text: str) -> dict:
        if not text:
            return {
                "urls": [],
                "emails": [],
                "phones": [],
                "upi_ids": []
            }
        
        return {
            "urls": cls.URL_PATTERN.findall(text),
            "emails": cls.EMAIL_PATTERN.findall(text),
            "phones": [p.strip() for p in cls.PHONE_PATTERN.findall(text) if len(re.sub(r'\D', '', p)) >= 10],
            "upi_ids": cls.UPI_PATTERN.findall(text)
        }
