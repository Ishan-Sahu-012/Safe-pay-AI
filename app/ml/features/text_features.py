# app/ml/features/text_features.py

"""
==============================================================================
SafePay AI — Advanced Text Feature Engine
==============================================================================

Purpose
-------
Converts raw scam text into ML-ready structured intelligence.

Used By
-------
1. SMS Scam Detection
2. Email Fraud Detection
3. WhatsApp Scam Detection
4. OCR Text Analysis
5. AI Threat Intelligence
6. Fraud Detection Services

Pipeline
--------
Raw Text
    ↓
Cleaning
    ↓
Tokenization
    ↓
Fraud Signal Detection
    ↓
Feature Extraction
    ↓
ML Prediction

==============================================================================
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse

from app.utils.logger import logger

# ============================================================================
# FRAUD SIGNAL WORDS
# ============================================================================

FRAUD_SIGNAL_WORDS = {

    "urgent",
    "immediately",
    "blocked",
    "suspended",
    "expired",
    "verify",
    "click",
    "link",
    "update",
    "kyc",
    "otp",
    "pin",
    "prize",
    "winner",
    "free",
    "offer",
    "limited",
    "guaranteed",
    "risk",
    "invest",
    "return",
    "withdraw",
    "transfer",
    "pay",
    "account",
    "bank",
    "refund",
    "cashback",
    "reward",
    "bonus",
    "selected",
    "approved",
    "cancel",
    "confirm",
    "security",
    "alert",
    "warning"
}

# ============================================================================
# STOPWORDS
# ============================================================================

_BASE_STOPWORDS = {

    "i", "me", "my", "we", "our",
    "you", "your", "he", "she",
    "it", "they", "them", "what",
    "which", "who", "this", "that",
    "these", "those", "am", "is",
    "are", "was", "were", "be",
    "been", "have", "has", "had",
    "do", "does", "did", "a",
    "an", "the", "and", "but",
    "if", "or", "because", "as",
    "until", "while", "of", "at",
    "by", "for", "with", "about",
    "against", "between", "into",
    "through", "before", "after",
    "above", "below", "to", "from",
    "up", "down", "in", "out",
    "on", "off", "over", "under"
}

# Keep fraud keywords even if they look common
STOPWORDS = _BASE_STOPWORDS - FRAUD_SIGNAL_WORDS

# ============================================================================
# CLEAN TEXT
# ============================================================================

def clean_text(text: str) -> str:

    """
    Clean raw text before ML inference.

    Steps:
    -------
    1. Lowercase
    2. Remove URLs
    3. Remove HTML
    4. Remove punctuation
    5. Remove extra spaces
    6. Remove stopwords
    """

    try:

        if not isinstance(text, str):

            return ""

        # --------------------------------------------------------------------
        # Lowercase
        # --------------------------------------------------------------------

        text = text.lower()

        # --------------------------------------------------------------------
        # Remove URLs
        # --------------------------------------------------------------------

        text = re.sub(

            r"http\S+|www\.\S+",

            " ",

            text
        )

        # --------------------------------------------------------------------
        # Remove HTML
        # --------------------------------------------------------------------

        text = re.sub(

            r"<[^>]+>",

            " ",

            text
        )

        # --------------------------------------------------------------------
        # Remove Special Characters
        # --------------------------------------------------------------------

        text = re.sub(

            r"[^a-z0-9\s]",

            " ",

            text
        )

        # --------------------------------------------------------------------
        # Remove Extra Spaces
        # --------------------------------------------------------------------

        text = re.sub(

            r"\s+",

            " ",

            text
        ).strip()

        # --------------------------------------------------------------------
        # Remove Stopwords
        # --------------------------------------------------------------------

        tokens = [

            word for word in text.split()

            if word not in STOPWORDS
        ]

        cleaned = " ".join(tokens)

        return cleaned

    except Exception as e:

        logger.error(
            f"❌ clean_text failed: {str(e)}"
        )

        return ""

# ============================================================================
# TOKENIZER
# ============================================================================

def tokenize(text: str):

    cleaned = clean_text(text)

    return cleaned.split()

# ============================================================================
# URL EXTRACTION
# ============================================================================

def extract_urls(text: str):

    pattern = r"(https?://\S+|www\.\S+)"

    return re.findall(pattern, text)

# ============================================================================
# PHONE EXTRACTION
# ============================================================================

def extract_phone_numbers(text: str):

    pattern = r"\b\d{10}\b"

    return re.findall(pattern, text)

# ============================================================================
# EMAIL EXTRACTION
# ============================================================================

def extract_emails(text: str):

    pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"

    return re.findall(pattern, text)

# ============================================================================
# ENTROPY
# ============================================================================

def shannon_entropy(text: str):

    """
    High entropy:
    random-looking scam strings.

    Example:
    xk29skx92pq
    """

    if not text:

        return 0.0

    freq = Counter(text)

    total = len(text)

    entropy = -sum(

        (count / total)
        *
        math.log2(count / total)

        for count in freq.values()
    )

    return round(entropy, 4)

# ============================================================================
# CAPITAL LETTER RATIO
# ============================================================================

def capital_ratio(text: str):

    if not text:

        return 0

    uppercase = sum(

        1 for c in text

        if c.isupper()
    )

    return round(

        uppercase / len(text),

        4
    )

# ============================================================================
# DIGIT RATIO
# ============================================================================

def digit_ratio(text: str):

    if not text:

        return 0

    digits = sum(

        1 for c in text

        if c.isdigit()
    )

    return round(

        digits / len(text),

        4
    )

# ============================================================================
# FRAUD KEYWORD DETECTION
# ============================================================================

def detect_fraud_keywords(text: str):

    tokens = tokenize(text)

    matched = [

        token for token in tokens

        if token in FRAUD_SIGNAL_WORDS
    ]

    return list(set(matched))

# ============================================================================
# URL RISK ANALYSIS
# ============================================================================

def analyze_url_risk(url: str):

    try:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        risk = 0

        # Long URL
        if len(url) > 75:

            risk += 20

        # Too many dots
        if domain.count(".") > 3:

            risk += 20

        # Numbers in domain
        if any(c.isdigit() for c in domain):

            risk += 15

        # Suspicious words
        suspicious = [

            "verify",
            "secure",
            "bonus",
            "winner",
            "reward",
            "claim",
            "gift"
        ]

        for word in suspicious:

            if word in domain:

                risk += 10

        return min(risk, 100)

    except:

        return 0

# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def extract_text_features(text: str):

    """
    Convert raw text into ML-ready features.
    """

    cleaned = clean_text(text)

    tokens = tokenize(text)

    urls = extract_urls(text)

    phones = extract_phone_numbers(text)

    emails = extract_emails(text)

    fraud_keywords = detect_fraud_keywords(text)

    features = {

        # Basic
        "text_length":
            len(text),

        "word_count":
            len(tokens),

        "unique_words":
            len(set(tokens)),

        # NLP
        "entropy":
            shannon_entropy(cleaned),

        "capital_ratio":
            capital_ratio(text),

        "digit_ratio":
            digit_ratio(text),

        # Fraud Intelligence
        "fraud_keyword_count":
            len(fraud_keywords),

        "has_urgent":
            int("urgent" in cleaned),

        "has_otp":
            int("otp" in cleaned),

        "has_kyc":
            int("kyc" in cleaned),

        # URLs
        "url_count":
            len(urls),

        "url_risk_score":
            max(
                [
                    analyze_url_risk(url)

                    for url in urls
                ] or [0]
            ),

        # Metadata
        "phone_count":
            len(phones),

        "email_count":
            len(emails),

        # Extra
        "avg_word_length":
            round(

                sum(len(word) for word in tokens)
                /
                max(len(tokens), 1),

                2
            )
    }

    return features

# ============================================================================
# FEATURE VECTOR ORDER
# ============================================================================

FEATURE_COLUMNS = [

    "text_length",

    "word_count",

    "unique_words",

    "entropy",

    "capital_ratio",

    "digit_ratio",

    "fraud_keyword_count",

    "has_urgent",

    "has_otp",

    "has_kyc",

    "url_count",

    "url_risk_score",

    "phone_count",

    "email_count",

    "avg_word_length"
]

# ============================================================================
# FEATURE VECTOR
# ============================================================================

def feature_vector(text: str):

    """
    Convert features dict
    into ML-ready vector.
    """

    features = extract_text_features(text)

    return [

        features[col]

        for col in FEATURE_COLUMNS
    ]

# ============================================================================
# DEBUG TEST
# ============================================================================

if __name__ == "__main__":

    sample = """

    URGENT!

    Your SBI account has been blocked.

    Verify KYC immediately:

    http://secure-banking-verify.xyz

    Call now: 9876543210
    """

    print("\n🧠 CLEANED TEXT:\n")

    print(clean_text(sample))

    print("\n📊 FEATURES:\n")

    features = extract_text_features(sample)

    for key, value in features.items():

        print(f"{key}: {value}")