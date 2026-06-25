# app/ml/training/model1_upi_fraud_classifier.py

"""
==============================================================================
SafePay AI — Advanced UPI Fraud Classifier
==============================================================================

Algorithm
---------
Random Forest + Hybrid Fraud Intelligence

Purpose
-------
Detect fraudulent UPI IDs and suspicious QR payment requests.

Used By
-------
1. qr_routes.py
2. fraud_routes.py
3. upi_predictor.py
4. realtime_camera_scanner.py

Pipeline
--------
UPI ID
   ↓
Feature Extraction
   ↓
Random Forest
   ↓
Fraud Probability
   ↓
Hybrid Risk Intelligence

==============================================================================

Reference Training Architecture:
:contentReference[oaicite:0]{index=0}

==============================================================================
"""

import math
import os
import pickle
import random
import warnings

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (

    classification_report,

    confusion_matrix,

    roc_auc_score
)

from sklearn.model_selection import (

    train_test_split,

    cross_val_score,

    StratifiedKFold
)

from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

# ============================================================================
# CONSTANTS
# ============================================================================

FEATURE_COLS = [

    "upi_length",

    "entropy",

    "num_digits",

    "seen_before",

    "report_count",

    "amount_ratio",

    "first_time_user"
]

LABEL_COL = "label"

RANDOM_STATE = 42

# ============================================================================
# SAFE PSPs
# ============================================================================

SAFE_PSP = [

    "ybl",

    "okaxis",

    "upi",

    "oksbi",

    "okhdfcbank",

    "okicici",

    "paytm",

    "ibl",

    "axl",

    "sbi",

    "hdfc",

    "icici"
]

# ============================================================================
# SUSPICIOUS PSPs
# ============================================================================

SCAM_PSP = [

    "xpay",

    "qpay",

    "zpay",

    "fastpay",

    "quickpay",

    "newupi",

    "mupay"
]

# ============================================================================
# SHANNON ENTROPY
# ============================================================================

def shannon_entropy(text: str):

    """
    Random-looking IDs
    generally have higher entropy.

    Example:
    xk92ms82pq
    """

    if not text:

        return 0.0

    frequency = {}

    for char in text:

        frequency[char] = frequency.get(char, 0) + 1

    total = len(text)

    entropy = -sum(

        (count / total)
        *
        math.log2(count / total)

        for count in frequency.values()
    )

    max_entropy = math.log2(total) if total > 1 else 1

    return round(

        entropy / max_entropy,

        4
    )

# ============================================================================
# FEATURE EXTRACTION
# ============================================================================

def extract_features_from_upi(

    upi_id: str,

    seen_before: bool,

    report_count: int,

    requested_amount: float,

    user_avg_amount: float,

    first_time_user: bool
):

    """
    Convert raw UPI data into ML features.
    """

    clean = upi_id.strip().lower()

    local_part = clean.split("@")[0]

    amount_ratio = (

        requested_amount / user_avg_amount

        if user_avg_amount > 0

        else 0
    )

    return {

        "upi_length":
            len(clean),

        "entropy":
            shannon_entropy(local_part),

        "num_digits":
            sum(c.isdigit() for c in clean),

        "seen_before":
            int(seen_before),

        "report_count":
            int(report_count),

        "amount_ratio":
            round(amount_ratio, 4),

        "first_time_user":
            int(first_time_user)
    }

# ============================================================================
# RANDOM DATA HELPERS
# ============================================================================

def _random_string(length: int):

    chars = "abcdefghijklmnopqrstuvwxyz0123456789"

    return "".join(

        random.choice(chars)

        for _ in range(length)
    )

# ============================================================================
# LEGIT UPI
# ============================================================================

def _legit_upi():

    names = [

        "rahul",

        "priya",

        "amit",

        "pooja",

        "vijay",

        "deepika",

        "nikhil",

        "sunita"
    ]

    name = random.choice(names)

    suffix = random.choice([

        "",

        str(random.randint(1, 999))
    ])

    return f"{name}{suffix}@{random.choice(SAFE_PSP)}"

# ============================================================================
# FRAUD UPI
# ============================================================================

def _fraud_upi():

    styles = [

        lambda:
            _random_string(
                random.randint(10, 18)
            )
            +
            "@"
            +
            random.choice(SCAM_PSP),

        lambda:
            "pay"
            +
            str(random.randint(
                10000000,
                99999999
            ))
            +
            "@"
            +
            random.choice(SCAM_PSP)
    ]

    return random.choice(styles)()

# ============================================================================
# SYNTHETIC DATASET
# ============================================================================

def generate_synthetic_dataset(

    n_samples: int = 8000,

    fraud_ratio: float = 0.30
):

    """
    Generate synthetic fraud dataset.
    """

    random.seed(RANDOM_STATE)

    np.random.seed(RANDOM_STATE)

    n_fraud = int(

        n_samples * fraud_ratio
    )

    n_legit = n_samples - n_fraud

    records = []

    # ------------------------------------------------------------------------
    # Legit Samples
    # ------------------------------------------------------------------------

    for _ in range(n_legit):

        upi = _legit_upi()

        local = upi.split("@")[0]

        records.append({

            "upi_length":
                len(upi),

            "entropy":
                shannon_entropy(local),

            "num_digits":
                sum(c.isdigit() for c in upi),

            "seen_before":
                int(random.random() < 0.75),

            "report_count":
                int(np.random.poisson(0.1)),

            "amount_ratio":
                round(
                    float(
                        np.random.lognormal(
                            0.0,
                            0.4
                        )
                    ),
                    3
                ),

            "first_time_user":
                int(random.random() < 0.25),

            LABEL_COL:
                0
        })

    # ------------------------------------------------------------------------
    # Fraud Samples
    # ------------------------------------------------------------------------

    for _ in range(n_fraud):

        upi = _fraud_upi()

        local = upi.split("@")[0]

        records.append({

            "upi_length":
                len(upi),

            "entropy":
                shannon_entropy(local),

            "num_digits":
                sum(c.isdigit() for c in upi),

            "seen_before":
                int(random.random() < 0.15),

            "report_count":
                int(np.random.poisson(2.5)),

            "amount_ratio":
                round(
                    float(
                        np.random.lognormal(
                            1.4,
                            0.7
                        )
                    ),
                    3
                ),

            "first_time_user":
                int(random.random() < 0.85),

            LABEL_COL:
                1
        })

    df = (

        pd.DataFrame(records)

        .sample(
            frac=1,
            random_state=RANDOM_STATE
        )

        .reset_index(drop=True)
    )

    print(

        f"""
📊 Dataset Generated

Rows    : {len(df)}
Legit   : {(df[LABEL_COL] == 0).sum()}
Fraud   : {(df[LABEL_COL] == 1).sum()}
"""
    )

    return df

# ============================================================================
# CLASSIFIER
# ============================================================================

class UPIFraudClassifier:

    """
    Production-grade UPI Fraud Detection Engine.
    """

    def __init__(self):

        self.scaler = StandardScaler()

        self.model = RandomForestClassifier(

            n_estimators=300,

            min_samples_split=5,

            min_samples_leaf=2,

            max_features="sqrt",

            class_weight="balanced",

            random_state=RANDOM_STATE,

            n_jobs=-1
        )

        self._trained = False

    # =========================================================================
    # TRAIN
    # =========================================================================

    def fit(self, df: pd.DataFrame):

        X = df[FEATURE_COLS].values

        y = df[LABEL_COL].values

        # --------------------------------------------------------------------
        # Train/Test Split
        # --------------------------------------------------------------------

        X_train, X_test, y_train, y_test = train_test_split(

            X,

            y,

            test_size=0.2,

            stratify=y,

            random_state=RANDOM_STATE
        )

        # --------------------------------------------------------------------
        # Scaling
        # --------------------------------------------------------------------

        X_train_scaled = self.scaler.fit_transform(
            X_train
        )

        X_test_scaled = self.scaler.transform(
            X_test
        )

        # --------------------------------------------------------------------
        # Cross Validation
        # --------------------------------------------------------------------

        cv = StratifiedKFold(

            n_splits=5,

            shuffle=True,

            random_state=RANDOM_STATE
        )

        scores = cross_val_score(

            self.model,

            X_train_scaled,

            y_train,

            cv=cv,

            scoring="roc_auc",

            n_jobs=-1
        )

        print(

            f"""
📈 Cross Validation ROC-AUC

Mean : {scores.mean():.4f}
STD  : {scores.std():.4f}
"""
        )

        # --------------------------------------------------------------------
        # Train Model
        # --------------------------------------------------------------------

        self.model.fit(

            X_train_scaled,

            y_train
        )

        self._trained = True

        print(
            "\n✅ Model training completed"
        )

        # --------------------------------------------------------------------
        # Evaluation
        # --------------------------------------------------------------------

        self._evaluate(

            X_test_scaled,

            y_test
        )

    # =========================================================================
    # PREDICT
    # =========================================================================

    def predict(self, features: dict):

        """
        Returns probability between 0 and 1.
        """

        if not self._trained:

            raise RuntimeError(
                "Model not trained"
            )

        row = np.array([

            [
                features[f]

                for f in FEATURE_COLS
            ]
        ])

        row_scaled = self.scaler.transform(
            row
        )

        probability = self.model.predict_proba(
            row_scaled
        )[0][1]

        return round(
            float(probability),
            4
        )

    # =========================================================================
    # EVALUATE
    # =========================================================================

    def _evaluate(self, X, y):

        predictions = self.model.predict(X)

        probabilities = self.model.predict_proba(X)[:, 1]

        print("\n📊 Classification Report\n")

        print(

            classification_report(

                y,

                predictions,

                target_names=[
                    "Legit",
                    "Fraud"
                ]
            )
        )

        print(

            f"""
ROC-AUC:
{roc_auc_score(y, probabilities):.4f}
"""
        )

        print(

            "\nConfusion Matrix:\n",

            confusion_matrix(
                y,
                predictions
            )
        )

    # =========================================================================
    # SAVE MODEL
    # =========================================================================

    def save(self, path: str):

        with open(path, "wb") as file:

            pickle.dump(

                {

                    "model":
                        self.model,

                    "scaler":
                        self.scaler
                },

                file
            )

        print(
            f"\n💾 Model saved: {path}"
        )

    # =========================================================================
    # LOAD MODEL
    # =========================================================================

    @classmethod

    def load(cls, path: str):

        with open(path, "rb") as file:

            data = pickle.load(file)

        obj = cls()

        obj.model = data["model"]

        obj.scaler = data["scaler"]

        obj._trained = True

        print(
            f"\nModel loaded: {path}"
        )

        return obj

# ============================================================================
# TRAINING ENTRY
# ============================================================================

if __name__ == "__main__":

    # ------------------------------------------------------------------------
    # Generate Dataset
    # ------------------------------------------------------------------------

    dataset = generate_synthetic_dataset()

    # ------------------------------------------------------------------------
    # Train Classifier
    # ------------------------------------------------------------------------

    classifier = UPIFraudClassifier()

    classifier.fit(dataset)

    # ------------------------------------------------------------------------
    # Save Model
    # ------------------------------------------------------------------------

    os.makedirs(

        "app/ml/models",

        exist_ok=True
    )

    classifier.save(

        "app/ml/models/model1_upi.pkl"
    )

    # ------------------------------------------------------------------------
    # Test Prediction
    # ------------------------------------------------------------------------

    features = extract_features_from_upi(

        upi_id="pay98234723@fastpay",

        seen_before=False,

        report_count=5,

        requested_amount=25000,

        user_avg_amount=1200,

        first_time_user=True
    )

    probability = classifier.predict(
        features
    )

    print(

        f"""
🚨 TEST FRAUD PROBABILITY

Probability:
{probability}
"""
    )