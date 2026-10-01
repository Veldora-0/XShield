import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FINAL_TRAIN_PATH = PROJECT_ROOT / "data" / "processed" / "xss_train_final.csv"
LEGACY_TRAIN_PATH = PROJECT_ROOT / "data" / "processed" / "xss_train.csv"
TRAIN_PATH = FINAL_TRAIN_PATH if FINAL_TRAIN_PATH.exists() else LEGACY_TRAIN_PATH
TEST_PATH = PROJECT_ROOT / "data" / "processed" / "xss_test.csv"
MODELS_DIR = PROJECT_ROOT / "models"
VECTORIZER_PATH = MODELS_DIR / "xss_tfidf_vectorizer.joblib"
MODEL_PATH = MODELS_DIR / "xss_logistic_regression.joblib"
REPORT_PATH = MODELS_DIR / "ml_training_report.json"

RANDOM_SEED = 42


def find_column(frame: pd.DataFrame, expected_name: str) -> str:
    """Find a required column without depending on capitalization or spacing."""
    normalized = {
        " ".join(str(column).casefold().split()): str(column)
        for column in frame.columns
    }
    column = normalized.get(expected_name)
    if column is None:
        raise ValueError(
            f"Could not find the '{expected_name}' column. "
            f"Available columns: {list(frame.columns)}"
        )
    return column


def load_split(path: Path) -> tuple[pd.Series, pd.Series]:
    frame = pd.read_csv(path, encoding="utf-8")
    text_column = find_column(frame, "text")
    label_column = find_column(frame, "label")

    if frame[text_column].isna().any() or frame[label_column].isna().any():
        raise ValueError(f"Missing text or label values found in {path}.")

    labels = frame[label_column].astype(int)
    if not set(labels.unique()).issubset({0, 1}):
        raise ValueError(f"Unexpected labels found in {path}: {sorted(labels.unique())}")

    return frame[text_column].astype(str), labels


def train_model() -> dict:
    train_text, train_labels = load_split(TRAIN_PATH)
    test_text, test_labels = load_split(TEST_PATH)

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=2,
        sublinear_tf=True,
    )
    train_features = vectorizer.fit_transform(train_text)
    test_features = vectorizer.transform(test_text)

    model = LogisticRegression(
        class_weight="balanced",
        max_iter=1000,
        random_state=RANDOM_SEED,
        solver="liblinear",
    )
    model.fit(train_features, train_labels)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    joblib.dump(model, MODEL_PATH)

    report = {
        "training_samples": int(len(train_text)),
        "test_samples": int(len(test_text)),
        "tfidf_features": int(train_features.shape[1]),
        "tfidf_configuration": {
            "analyzer": "char",
            "ngram_range": [3, 5],
            "min_df": 2,
            "sublinear_tf": True,
            "fit_on": "training text only",
        },
        "logistic_regression_configuration": {
            "class_weight": "balanced",
            "max_iter": 1000,
            "random_state": RANDOM_SEED,
            "solver": "liblinear",
        },
        "training_class_counts": {
            str(key): int(value)
            for key, value in train_labels.value_counts().sort_index().items()
        },
        "test_class_counts": {
            str(key): int(value)
            for key, value in test_labels.value_counts().sort_index().items()
        },
        "saved_vectorizer": str(VECTORIZER_PATH),
        "saved_model": str(MODEL_PATH),
        "evaluation_metrics": "Not calculated in Phase 6.",
    }
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(train_model(), indent=2))
