# app/ml/training/model2_text_classifier.py
from sklearn.pipeline import Pipeline
"""
==============================================================================
SafePay AI — Advanced Text Scam Classifier
==============================================================================

Algorithm
---------
TF-IDF + Logistic Regression

Purpose
-------
Detect scam messages, phishing text,
fraud emails, fake investment offers,
and malicious trading platform content.

Used By
-------
1. sms_routes.py
2. fraud_routes.py
3. text_predictor.py
4. email_scanner.py
5. trading_platform_scanner.py

Pipeline
--------
Raw Text
    ↓
Cleaning
    ↓
TF-IDF Vectorization
    ↓
Logistic Regression
    ↓
Scam Probability

==============================================================================

Reference Architecture:
:contentReference[oaicite:0]{index=0}

==============================================================================
"""

import os
import pickle
import random
import re
import warnings

import numpy as np
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (

    classification_report,

    confusion_matrix,

    roc_auc_score
)

from sklearn.model_selection import (

    train_test_split,

    StratifiedKFold,

    cross_val_score
)


warnings.filterwarnings("ignore")

# ============================================================================
# CONSTANTS
# ============================================================================

LABEL_COL = "label"

RANDOM_STATE = 42

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

    "winner",

    "free",

    "offer",

    "limited",

    "invest",

    "return",

    "withdraw",

    "transfer",

    "pay",

    "bank",

    "refund",

    "reward",

    "bonus",

    "approved",

    "confirm",

    "deactivate",

    "reactivate"
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

STOPWORDS = _BASE_STOPWORDS - FRAUD_SIGNAL_WORDS

# ============================================================================
# CLEAN TEXT
# ============================================================================

def clean_text(text: str):

    """
    Clean raw text before vectorization.
    """

    if not isinstance(text, str):

        return ""

    # ------------------------------------------------------------------------
    # Lowercase
    # ------------------------------------------------------------------------

    text = text.lower()

    # ------------------------------------------------------------------------
    # Remove URLs
    # ------------------------------------------------------------------------

    text = re.sub(

        r"http\S+|www\.\S+",

        " ",

        text
    )

    # ------------------------------------------------------------------------
    # Remove HTML
    # ------------------------------------------------------------------------

    text = re.sub(

        r"<[^>]+>",

        " ",

        text
    )

    # ------------------------------------------------------------------------
    # Remove Special Characters
    # ------------------------------------------------------------------------

    text = re.sub(

        r"[^a-z0-9\s]",

        " ",

        text
    )

    # ------------------------------------------------------------------------
    # Remove Extra Spaces
    # ------------------------------------------------------------------------

    text = re.sub(

        r"\s+",

        " ",

        text
    ).strip()

    # ------------------------------------------------------------------------
    # Remove Stopwords
    # ------------------------------------------------------------------------

    tokens = [

        word for word in text.split()

        if word not in STOPWORDS
    ]

    return " ".join(tokens)

# ============================================================================
# SYNTHETIC DATASET
# ============================================================================

def generate_synthetic_text_dataset(

    n_samples: int = 4000
):

    """
    Synthetic dataset fallback.
    """

    random.seed(RANDOM_STATE)

    scam_templates = [

        "your kyc is expired click here immediately",

        "your account will be blocked verify otp now",

        "congratulations you won rs 50000 claim reward now",

        "your bank account suspended update details immediately",

        "free cashback approved click to withdraw now",

        "investment offer guaranteed returns limited slots",

        "your upi account blocked reactivate immediately",

        "otp required for bank verification urgent",

        "your account compromised confirm pin immediately",

        "loan approved send fee now"
    ]

    legit_templates = [

        "your payment of rs 500 was successful",

        "your electricity bill payment received",

        "your amazon order shipped successfully",

        "meeting scheduled tomorrow at 10 am",

        "your account statement is ready",

        "your recharge completed successfully",

        "your movie tickets booked successfully",

        "your bank transaction completed",

        "lunch meeting tomorrow afternoon",

        "your package will arrive today"
    ]

    records = []

    n_scam = int(n_samples * 0.40)

    n_legit = n_samples - n_scam

    # ------------------------------------------------------------------------
    # Scam Samples
    # ------------------------------------------------------------------------

    for _ in range(n_scam):

        text = random.choice(scam_templates)

        records.append({

            "text": text,

            LABEL_COL: 1
        })

    # ------------------------------------------------------------------------
    # Legit Samples
    # ------------------------------------------------------------------------

    for _ in range(n_legit):

        text = random.choice(legit_templates)

        records.append({

            "text": text,

            LABEL_COL: 0
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
📊 Synthetic Dataset Generated

Rows   : {len(df)}
Scam   : {(df[LABEL_COL] == 1).sum()}
Legit  : {(df[LABEL_COL] == 0).sum()}
"""
    )

    return df

# ============================================================================
# TEXT CLASSIFIER
# ============================================================================

class TextScamClassifier:

    """
    Production-grade scam text classifier.
    """

    def __init__(self):

        self._trained = False

        # --------------------------------------------------------------------
        # Pipeline
        # --------------------------------------------------------------------

        self.pipeline = Pipeline([

            (

                "tfidf",

                TfidfVectorizer(

                    max_features=10000,

                    ngram_range=(1, 2),

                    sublinear_tf=True,

                    strip_accents="unicode",

                    analyzer="word",

                    stop_words=list(STOPWORDS)
                )
            ),

            (

                "lr",

                LogisticRegression(

                    C=1.0,

                    max_iter=1000,

                    class_weight="balanced",

                    random_state=RANDOM_STATE,

                    solver="lbfgs"
                )
            )
        ])

    # =========================================================================
    # TRAIN
    # =========================================================================

    def fit(self, df: pd.DataFrame):

        """
        Train classifier.
        """

        X = np.array([

            clean_text(text)

            for text in df["text"].values
        ])

        y = df[LABEL_COL].values

        # Scale vocabulary to dataset size for better accuracy on merged corpora
        n_samples = len(df)
        max_features = min(50000, max(10000, n_samples // 2))
        self.pipeline.set_params(tfidf__max_features=max_features)

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
        # Cross Validation
        # --------------------------------------------------------------------

        cv = StratifiedKFold(

            n_splits=5,

            shuffle=True,

            random_state=RANDOM_STATE
        )

        scores = cross_val_score(

            self.pipeline,

            X_train,

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
        # Train
        # --------------------------------------------------------------------

        self.pipeline.fit(

            X_train,

            y_train
        )

        self._trained = True

        print(
            "\n✅ Text classifier trained"
        )

        # --------------------------------------------------------------------
        # Evaluation
        # --------------------------------------------------------------------

        self._evaluate(

            X_test,

            y_test
        )

    # =========================================================================
    # PREDICT
    # =========================================================================

    def predict(self, text: str):

        """
        Predict scam probability.
        """

        if not self._trained:

            raise RuntimeError(
                "Model not trained"
            )

        cleaned = clean_text(text)

        probability = self.pipeline.predict_proba(

            [cleaned]

        )[0][1]

        return round(

            float(probability),

            4
        )

    # =========================================================================
    # EVALUATION
    # =========================================================================

    def _evaluate(self, X, y):

        predictions = self.pipeline.predict(X)

        probabilities = self.pipeline.predict_proba(X)[:, 1]

        print("\n📊 Classification Report\n")

        print(

            classification_report(

                y,

                predictions,

                target_names=[
                    "Legit",
                    "Scam"
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
    # SAVE
    # =========================================================================

    def save(self, path: str):

        with open(path, "wb") as file:

            pickle.dump(

                {

                    "pipeline":
                        self.pipeline
                },

                file
            )

        print(
            f"\n💾 Model saved: {path}"
        )

    # =========================================================================
    # LOAD
    # =========================================================================

    @classmethod

    def load(cls, path: str):

        with open(path, "rb") as file:

            data = pickle.load(file)

        obj = cls()

        obj.pipeline = data["pipeline"]

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

    dataset = generate_synthetic_text_dataset()

    # ------------------------------------------------------------------------
    # Train Model
    # ------------------------------------------------------------------------

    classifier = TextScamClassifier()

    classifier.fit(dataset)

    # ------------------------------------------------------------------------
    # Save Model
    # ------------------------------------------------------------------------

    os.makedirs(

        "app/ml/models",

        exist_ok=True
    )

    classifier.save(

        "app/ml/models/model2_text.pkl"
    )

    # ------------------------------------------------------------------------
    # Test Prediction
    # ------------------------------------------------------------------------

    sample = """

    URGENT!

    Your SBI account has been blocked.

    Verify KYC immediately.

    Click here now.
    """

    probability = classifier.predict(
        sample
    )

    print(

        f"""
🚨 TEST SCAM PROBABILITY

Probability:
{probability}
"""
    )