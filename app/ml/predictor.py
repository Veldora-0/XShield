from functools import lru_cache
from pathlib import Path

import joblib


PROJECT_ROOT = Path(__file__).resolve().parents[2]
VECTORIZER_PATH = PROJECT_ROOT / "models" / "xss_tfidf_vectorizer.joblib"
MODEL_PATH = PROJECT_ROOT / "models" / "xss_logistic_regression.joblib"


@lru_cache(maxsize=1)
def _load_artifacts():
    """Load saved ML artifacts once per process; prediction never retrains."""
    if not VECTORIZER_PATH.exists() or not MODEL_PATH.exists():
        raise FileNotFoundError(
            "Trained ML artifacts are missing. Run "
            "'python scripts\\train_ml_model.py' first."
        )

    try:
        return joblib.load(VECTORIZER_PATH), joblib.load(MODEL_PATH)
    except (OSError, ValueError, EOFError, ImportError) as error:
        raise RuntimeError(
            "Trusted ML artifacts could not be loaded. Verify the saved "
            "model and vectorizer files."
        ) from error


def predict_text(text: str) -> dict:
    """Predict whether one text value belongs to the benign or XSS class."""
    vectorizer, model = _load_artifacts()
    features = vectorizer.transform([str(text)])
    label = int(model.predict(features)[0])
    probability = float(model.predict_proba(features)[0][1])

    return {
        "label": label,
        "prediction": "xss" if label == 1 else "benign",
        "probability": probability,
    }
