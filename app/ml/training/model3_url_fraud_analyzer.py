# app/ml/training/model3_url_fraud_analyzer.py

"""
==============================================================================
SafePay AI — URL Fraud Analyzer
==============================================================================

Purpose
-------
AI-powered malicious URL detection system.

Features
--------
✅ URL phishing detection
✅ Domain intelligence
✅ Brand spoof detection
✅ TLD risk analysis
✅ Feature engineering
✅ Random Forest classifier
✅ Explainable predictions
✅ Model persistence
✅ Backend integration ready

==============================================================================
"""

import os
import pickle
import random
import warnings
from difflib import SequenceMatcher
from urllib.parse import urlparse

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (

    classification_report,

    confusion_matrix,

    roc_auc_score
)

from sklearn.model_selection import (

    StratifiedKFold,

    cross_val_score,

    train_test_split
)

from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

# ============================================================================
# CONSTANTS
# ============================================================================

RANDOM_STATE = 42

FEATURE_COLS = [

    "domain_length",

    "digit_count",

    "hyphen_count",

    "known_brand_similarity",

    "tld_risk_score"
]

LABEL_COL = "label"

# ============================================================================
# KNOWN BRANDS
# ============================================================================

KNOWN_BRANDS = [

    "paytm",

    "phonepe",

    "googlepay",

    "bhim",

    "amazon",

    "flipkart",

    "zerodha",

    "groww",

    "upstox",

    "icici",

    "hdfc",

    "sbi",

    "axisbank"
]

# ============================================================================
# TLD RISK
# ============================================================================

TLD_RISK = {

    "com": 0.1,

    "in": 0.1,

    "org": 0.15,

    "net": 0.2,

    "xyz": 0.85,

    "tk": 0.90,

    "cf": 0.85,

    "gq": 0.85,

    "top": 0.80,

    "click": 0.70,

    "link": 0.75,

    "shop": 0.60,

    "live": 0.65
}

DEFAULT_TLD_RISK = 0.50

# ============================================================================
# URL PARSER
# ============================================================================

def parse_url(url: str):

    """
    Parse domain + tld.
    """

    url = url.strip()

    if not url.startswith(

        ("http://", "https://")
    ):

        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    domain = domain.replace("www.", "")

    parts = domain.split(".")

    if len(parts) >= 2:

        domain_no_tld = ".".join(parts[:-1])

        tld = parts[-1]

    else:

        domain_no_tld = domain

        tld = ""

    return domain, domain_no_tld, tld

# ============================================================================
# BRAND SIMILARITY
# ============================================================================

def calculate_brand_similarity(

    domain_no_tld: str
):

    """
    Detect spoofed domains.
    """

    if not domain_no_tld:

        return 0.0

    scores = [

        SequenceMatcher(

            None,

            domain_no_tld,

            brand

        ).ratio()

        for brand in KNOWN_BRANDS
    ]

    return round(max(scores), 4)

# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def extract_features_from_url(

    url: str
):

    """
    Convert URL into ML features.
    """

    domain, domain_no_tld, tld = parse_url(url)

    return {

        "domain_length":

            len(domain_no_tld),

        "digit_count":

            sum(c.isdigit() for c in url),

        "hyphen_count":

            domain.count("-"),

        "known_brand_similarity":

            calculate_brand_similarity(
                domain_no_tld
            ),

        "tld_risk_score":

            TLD_RISK.get(

                tld.lower(),

                DEFAULT_TLD_RISK
            )
    }

# ============================================================================
# SYNTHETIC DATASET
# ============================================================================

def generate_synthetic_url_dataset(

    n_samples=6000
):

    """
    Generate training dataset.
    """

    random.seed(RANDOM_STATE)

    np.random.seed(RANDOM_STATE)

    records = []

    fraud_count = int(n_samples * 0.4)

    safe_count = n_samples - fraud_count

    safe_tlds = [

        "com",

        "in",

        "org"
    ]

    risky_tlds = [

        "xyz",

        "tk",

        "cf",

        "top"
    ]

    # ------------------------------------------------------------------------
    # SAFE URLs
    # ------------------------------------------------------------------------

    for _ in range(safe_count):

        records.append({

            "domain_length":
                random.randint(5, 15),

            "digit_count":
                random.randint(0, 2),

            "hyphen_count":
                random.randint(0, 1),

            "known_brand_similarity":
                round(random.uniform(0, 0.4), 4),

            "tld_risk_score":
                TLD_RISK.get(
                    random.choice(safe_tlds)
                ),

            LABEL_COL: 0
        })

    # ------------------------------------------------------------------------
    # FRAUD URLS
    # ------------------------------------------------------------------------

    for _ in range(fraud_count):

        records.append({

            "domain_length":
                random.randint(15, 40),

            "digit_count":
                random.randint(3, 12),

            "hyphen_count":
                random.randint(1, 5),

            "known_brand_similarity":
                round(random.uniform(0.5, 0.95), 4),

            "tld_risk_score":
                TLD_RISK.get(
                    random.choice(risky_tlds)
                ),

            LABEL_COL: 1
        })

    df = pd.DataFrame(records)

    df = df.sample(

        frac=1,

        random_state=RANDOM_STATE
    )

    return df.reset_index(drop=True)

# ============================================================================
# URL FRAUD ANALYZER
# ============================================================================

class URLFraudAnalyzer:

    """
    Enterprise URL fraud classifier.
    """

    def __init__(self):

        self.model = RandomForestClassifier(

            n_estimators=300,

            min_samples_split=5,

            min_samples_leaf=2,

            class_weight="balanced",

            random_state=RANDOM_STATE,

            n_jobs=-1
        )

        self.scaler = StandardScaler()

        self._trained = False

    # ------------------------------------------------------------------------

    def fit(self, df: pd.DataFrame):

        """
        Train model.
        """

        X = df[FEATURE_COLS].values

        y = df[LABEL_COL].values

        X_train, X_test, y_train, y_test = train_test_split(

            X,

            y,

            test_size=0.2,

            stratify=y,

            random_state=RANDOM_STATE
        )

        X_train = self.scaler.fit_transform(
            X_train
        )

        X_test = self.scaler.transform(
            X_test
        )

        # --------------------------------------------------------------------
        # CROSS VALIDATION
        # --------------------------------------------------------------------

        cv = StratifiedKFold(

            n_splits=5,

            shuffle=True,

            random_state=RANDOM_STATE
        )

        scores = cross_val_score(

            self.model,

            X_train,

            y_train,

            cv=cv,

            scoring="roc_auc"
        )

        print(

            f"""
📈 Model 3 ROC-AUC:
{scores.mean():.4f}
"""
        )

        # --------------------------------------------------------------------
        # TRAIN
        # --------------------------------------------------------------------

        self.model.fit(

            X_train,

            y_train
        )

        self._trained = True

        # --------------------------------------------------------------------
        # EVALUATION
        # --------------------------------------------------------------------

        preds = self.model.predict(X_test)

        probs = self.model.predict_proba(
            X_test
        )[:, 1]

        print(

            classification_report(

                y_test,

                preds
            )
        )

        print(

            f"""
🎯 ROC-AUC:
{roc_auc_score(y_test, probs):.4f}
"""
        )

        print(

            """
📊 Confusion Matrix
"""
        )

        print(

            confusion_matrix(
                y_test,
                preds
            )
        )

    # ------------------------------------------------------------------------

    def predict(self, input_data):

        """
        Predict fraud probability.
        """

        if not self._trained:

            raise RuntimeError(
                "Model not trained"
            )

        if isinstance(input_data, str):

            features = extract_features_from_url(
                input_data
            )

        else:

            features = input_data

        row = np.array([

            [

                features[col]

                for col in FEATURE_COLS
            ]
        ])

        row = self.scaler.transform(row)

        prob = self.model.predict_proba(
            row
        )[0][1]

        return round(float(prob), 4)

    # ------------------------------------------------------------------------

    def explain(self, url: str):

        """
        Explain prediction.
        """

        features = extract_features_from_url(
            url
        )

        score = self.predict(features)

        if score >= 0.80:

            level = "CRITICAL"

        elif score >= 0.60:

            level = "HIGH"

        elif score >= 0.40:

            level = "MEDIUM"

        else:

            level = "LOW"

        return {

            "url": url,

            "url_risk_score": score,

            "risk_level": level,

            "features": features
        }

    # ------------------------------------------------------------------------

    def save(self, path: str):

        """
        Save model.
        """

        with open(path, "wb") as f:

            pickle.dump({

                "model": self.model,

                "scaler": self.scaler

            }, f)

        print(
            f"✅ Saved model -> {path}"
        )

    # ------------------------------------------------------------------------

    @classmethod
    def load(cls, path: str):

        """
        Load trained model.
        """

        with open(path, "rb") as f:

            data = pickle.load(f)

        obj = cls()

        obj.model = data["model"]

        obj.scaler = data["scaler"]

        obj._trained = True

        print(
            f"✅ Loaded model <- {path}"
        )

        return obj

# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":

    print(
        """
🚀 Training URL Fraud Analyzer
"""
    )

    df = generate_synthetic_url_dataset()

    analyzer = URLFraudAnalyzer()

    analyzer.fit(df)

    os.makedirs(

        "app/ml/models",

        exist_ok=True
    )

    analyzer.save(

        "app/ml/models/model3_url_compatible.pkl"
    )

    # ------------------------------------------------------------------------
    # TEST
    # ------------------------------------------------------------------------

    urls = [

        "https://google.com",

        "https://paytm-secure-verification.xyz",

        "https://amaz0n-login-security.tk",

        "https://phonepe.com"
    ]

    for url in urls:

        result = analyzer.explain(url)

        print("\n", result)