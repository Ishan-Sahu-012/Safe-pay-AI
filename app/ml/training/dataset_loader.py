"""
Unified dataset loader — merges all SafePay CSV sources for ML training.

Sources
-------
Text (model2):
  - app/ml/data/text_scam_dataset.csv
  - app/database/datasets/cleaned_spam_v2.csv
  - app/database/datasets/db_communication_intercept_logs.csv

UPI (model1):
  - app/ml/data/upi_fraud_dataset.csv
  - app/database/datasets/db_upi_merchant_registry.csv

URL (model3):
  - app/ml/data/url_fraud_dataset.csv
  - app/database/datasets/db_url_security_registry.csv
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pandas as pd

from app.ml.training.model1_upi_fraud_classifier import (
    FEATURE_COLS as UPI_FEATURE_COLS,
    extract_features_from_upi,
    generate_synthetic_dataset,
)
from app.ml.training.model2_text_classifier import (
    generate_synthetic_text_dataset,
)
from app.ml.training.model3_url_fraud_analyzer import (
    FEATURE_COLS as URL_FEATURE_COLS,
    extract_features_from_url,
    generate_synthetic_url_dataset,
)
from app.utils.logger import logger

BASE_DIR = Path(__file__).resolve().parents[2]  # app/
ML_DATA = BASE_DIR / "ml" / "data"
DB_DATA = BASE_DIR / "database" / "datasets"

LABEL_COL = "label"


def _read_csv(path: Path) -> pd.DataFrame | None:
    if not path.exists():
        logger.warning(f"Dataset not found, skipping: {path}")
        return None
    try:
        return pd.read_csv(path, encoding="utf-8", on_bad_lines="skip")
    except Exception:
        return pd.read_csv(path, encoding="latin-1", on_bad_lines="skip")


def _text_hash(text: str) -> str:
    normalized = re.sub(r"\s+", " ", str(text).strip().lower())
    return hashlib.md5(normalized.encode("utf-8", errors="ignore")).hexdigest()


def _dedupe_text_df(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    df = df.copy()
    df["_hash"] = df["text"].astype(str).map(_text_hash)
    df = df.drop_duplicates(subset=["_hash"], keep="first").drop(columns=["_hash"])
    return df.reset_index(drop=True)


def load_combined_text_dataset(
    include_synthetic: bool = True,
    synthetic_samples: int = 2000,
) -> pd.DataFrame:
    """Merge all text/SMS datasets into (text, label)."""
    frames: list[pd.DataFrame] = []

    # Primary ML export
    primary = _read_csv(ML_DATA / "text_scam_dataset.csv")
    if primary is not None and {"text", "label"}.issubset(primary.columns):
        frames.append(primary[["text", "label"]].astype({"label": int}))

    # SMS spam corpus
    spam = _read_csv(DB_DATA / "cleaned_spam_v2.csv")
    if spam is not None and {"message", "label"}.issubset(spam.columns):
        mapped = spam.rename(columns={"message": "text"})
        mapped["label"] = mapped["label"].astype(str).str.lower().map(
            {"spam": 1, "ham": 0}
        ).fillna(0).astype(int)
        frames.append(mapped[["text", "label"]])

    # Intercept logs (phishing vs legitimate)
    logs = _read_csv(DB_DATA / "db_communication_intercept_logs.csv")
    if logs is not None and "message_body" in logs.columns:
        mapped = logs.rename(columns={"message_body": "text"})
        cat = mapped.get("reported_scam_category", pd.Series([None] * len(mapped)))
        mapped["label"] = cat.apply(
            lambda c: 1 if isinstance(c, str) and c.strip().lower() not in ("", "none") else 0
        ).astype(int)
        frames.append(mapped[["text", "label"]])

    if not frames:
        logger.warning("No text CSVs found — using synthetic text dataset")
        return generate_synthetic_text_dataset(n_samples=synthetic_samples)

    combined = pd.concat(frames, ignore_index=True)
    combined["text"] = combined["text"].astype(str).str.strip()
    combined = combined[combined["text"].str.len() >= 3]
    combined[LABEL_COL] = combined[LABEL_COL].astype(int).clip(0, 1)
    combined = _dedupe_text_df(combined)

    if include_synthetic and len(combined) < 3000:
        synth = generate_synthetic_text_dataset(n_samples=synthetic_samples)
        combined = pd.concat([combined, synth[["text", "label"]]], ignore_index=True)
        combined = _dedupe_text_df(combined)

    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    logger.info(
        "Text training set: rows=%s scam=%s legit=%s",
        len(combined),
        int((combined[LABEL_COL] == 1).sum()),
        int((combined[LABEL_COL] == 0).sum()),
    )
    return combined


def _merchant_row_to_features(row: pd.Series) -> dict:
    upi_id = str(row.get("upi_id", "")).strip().lower()
    if "@" not in upi_id:
        return {}
    verified = int(row.get("is_verified_merchant", 0))
    reports = int(row.get("historical_report_count", 0))
    avg_val = float(row.get("merchant_avg_transaction_val", 1000) or 1000)

    label = 0 if verified == 1 and reports < 3 else 1
    feats = extract_features_from_upi(
        upi_id=upi_id,
        seen_before=bool(verified),
        report_count=reports,
        requested_amount=min(avg_val, 50000),
        user_avg_amount=1000.0,
        first_time_user=not bool(verified),
    )
    feats[LABEL_COL] = label
    return feats


def load_combined_upi_dataset(
    include_synthetic: bool = True,
    synthetic_samples: int = 4000,
) -> pd.DataFrame:
    """Merge UPI feature CSV + merchant registry-derived features."""
    frames: list[pd.DataFrame] = []

    primary = _read_csv(ML_DATA / "upi_fraud_dataset.csv")
    if primary is not None and set(UPI_FEATURE_COLS + [LABEL_COL]).issubset(primary.columns):
        frames.append(primary[UPI_FEATURE_COLS + [LABEL_COL]])

    registry = _read_csv(DB_DATA / "db_upi_merchant_registry.csv")
    if registry is not None and "upi_id" in registry.columns:
        rows = [_merchant_row_to_features(r) for _, r in registry.iterrows()]
        rows = [r for r in rows if r]
        if rows:
            frames.append(pd.DataFrame(rows)[UPI_FEATURE_COLS + [LABEL_COL]])

    if not frames:
        logger.warning("No UPI CSVs found — using synthetic UPI dataset")
        return generate_synthetic_dataset(n_samples=synthetic_samples)

    combined = pd.concat(frames, ignore_index=True)
    combined[LABEL_COL] = combined[LABEL_COL].astype(int).clip(0, 1)
    combined = combined.drop_duplicates().reset_index(drop=True)

    if include_synthetic:
        synth = generate_synthetic_dataset(n_samples=min(synthetic_samples, 3000))
        combined = pd.concat([combined, synth[UPI_FEATURE_COLS + [LABEL_COL]]], ignore_index=True)
        combined = combined.drop_duplicates().reset_index(drop=True)

    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    logger.info(
        "UPI training set: rows=%s fraud=%s legit=%s",
        len(combined),
        int((combined[LABEL_COL] == 1).sum()),
        int((combined[LABEL_COL] == 0).sum()),
    )
    return combined


def _url_registry_row(row: pd.Series) -> dict | None:
    url = str(row.get("raw_target_url", "")).strip()
    if not url:
        return None
    status = str(row.get("safety_status", "")).lower()
    label = 0 if "verified" in status or "safe" in status else 1
    feats = extract_features_from_url(url)
    feats[LABEL_COL] = label
    return feats


def load_combined_url_dataset(
    include_synthetic: bool = True,
    synthetic_samples: int = 3000,
) -> pd.DataFrame:
    """Merge URL feature CSV + security registry URLs."""
    frames: list[pd.DataFrame] = []

    primary = _read_csv(ML_DATA / "url_fraud_dataset.csv")
    if primary is not None and set(URL_FEATURE_COLS + [LABEL_COL]).issubset(primary.columns):
        frames.append(primary[URL_FEATURE_COLS + [LABEL_COL]])

    registry = _read_csv(DB_DATA / "db_url_security_registry.csv")
    if registry is not None and "raw_target_url" in registry.columns:
        rows = [_url_registry_row(r) for _, r in registry.iterrows()]
        rows = [r for r in rows if r]
        if rows:
            frames.append(pd.DataFrame(rows)[URL_FEATURE_COLS + [LABEL_COL]])

    if not frames:
        logger.warning("No URL CSVs found — using synthetic URL dataset")
        return generate_synthetic_url_dataset(n_samples=synthetic_samples)

    combined = pd.concat(frames, ignore_index=True)
    combined[LABEL_COL] = combined[LABEL_COL].astype(int).clip(0, 1)
    combined = combined.drop_duplicates().reset_index(drop=True)

    if include_synthetic:
        synth = generate_synthetic_url_dataset(n_samples=min(synthetic_samples, 2000))
        combined = pd.concat([combined, synth[URL_FEATURE_COLS + [LABEL_COL]]], ignore_index=True)
        combined = combined.drop_duplicates().reset_index(drop=True)

    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    logger.info(
        "URL training set: rows=%s malicious=%s safe=%s",
        len(combined),
        int((combined[LABEL_COL] == 1).sum()),
        int((combined[LABEL_COL] == 0).sum()),
    )
    return combined
