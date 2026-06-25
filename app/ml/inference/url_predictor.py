"""Runtime URL fraud model (model3) inference."""

from pathlib import Path

from app.utils.logger import logger

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "model3.pkl"

_analyzer = None


def load_url_model():
    global _analyzer
    from app.ml.training.model3_url_fraud_analyzer import URLFraudAnalyzer

    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"URL model not found: {MODEL_PATH}")
    _analyzer = URLFraudAnalyzer.load(str(MODEL_PATH))
    logger.info("URL fraud model (model3) loaded")


def _ensure_model():
    global _analyzer
    if _analyzer is None:
        load_url_model()


try:
    if MODEL_PATH.exists():
        load_url_model()
except Exception as exc:
    logger.warning(f"URL model deferred load: {exc}")


def predict_url_fraud_probability(url: str) -> float | None:
    """Return fraud probability 0–1, or None if model unavailable."""
    try:
        _ensure_model()
        return _analyzer.predict(url)
    except Exception as e:
        logger.debug(f"URL ML predict skipped: {e}")
        return None
