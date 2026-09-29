import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_PATH = PROJECT_ROOT / "data" / "processed" / "xss_test.csv"
VECTORIZER_PATH = PROJECT_ROOT / "models" / "xss_tfidf_vectorizer.joblib"
MODEL_PATH = PROJECT_ROOT / "models" / "xss_logistic_regression.joblib"
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORT_PATH = REPORTS_DIR / "ml_evaluation.json"
PREDICTIONS_PATH = REPORTS_DIR / "ml_test_predictions.csv"
POSITIVE_LABEL = 1
REPRESENTATIVE_LIMIT = 10


def find_column(frame: pd.DataFrame, expected_name: str) -> str:
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


def load_test_data() -> tuple[pd.Series, pd.Series]:
    frame = pd.read_csv(TEST_PATH, encoding="utf-8")
    text_column = find_column(frame, "text")
    label_column = find_column(frame, "label")

    if frame[text_column].isna().any() or frame[label_column].isna().any():
        raise ValueError("The held-out test set contains missing text or labels.")

    labels = frame[label_column].astype(int)
    if not set(labels.unique()).issubset({0, 1}):
        raise ValueError(f"Unexpected labels found: {sorted(labels.unique())}")

    return frame[text_column].astype(str), labels


def misclassified_examples(
    text: pd.Series,
    actual: pd.Series,
    predicted: pd.Series,
    probabilities: pd.Series,
    expected_error: str,
) -> list[dict]:
    rows = []
    for index in text.index:
        actual_label = int(actual.loc[index])
        predicted_label = int(predicted.loc[index])
        if expected_error == "false_positive" and not (
            actual_label == 0 and predicted_label == 1
        ):
            continue
        if expected_error == "false_negative" and not (
            actual_label == 1 and predicted_label == 0
        ):
            continue

        rows.append(
            {
                "text": str(text.loc[index]),
                "actual_label": actual_label,
                "predicted_label": predicted_label,
                "xss_probability": float(probabilities.loc[index]),
            }
        )
    return rows[:REPRESENTATIVE_LIMIT]


def evaluate_model() -> dict:
    text, actual = load_test_data()
    vectorizer = joblib.load(VECTORIZER_PATH)
    model = joblib.load(MODEL_PATH)

    features = vectorizer.transform(text)
    predicted = pd.Series(model.predict(features), index=text.index, dtype=int)
    probabilities = pd.Series(
        model.predict_proba(features)[:, POSITIVE_LABEL],
        index=text.index,
        dtype=float,
    )

    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    false_positive_count = int(((actual == 0) & (predicted == 1)).sum())
    false_negative_count = int(((actual == 1) & (predicted == 0)).sum())

    predictions = pd.DataFrame(
        {
            "text": text,
            "actual_label": actual,
            "predicted_label": predicted,
            "xss_probability": probabilities,
        }
    )
    predictions["error_type"] = "correct"
    predictions.loc[
        (predictions["actual_label"] == 0)
        & (predictions["predicted_label"] == 1),
        "error_type",
    ] = "false_positive"
    predictions.loc[
        (predictions["actual_label"] == 1)
        & (predictions["predicted_label"] == 0),
        "error_type",
    ] = "false_negative"

    report = {
        "dataset": {
            "test_file": str(TEST_PATH),
            "samples": int(len(actual)),
            "text_column": "text",
            "label_column": "label",
            "positive_class": {
                "label": POSITIVE_LABEL,
                "meaning": "XSS",
            },
            "class_counts": {
                str(key): int(value)
                for key, value in actual.value_counts().sort_index().items()
            },
        },
        "model": {
            "name": "LogisticRegression",
            "model_file": str(MODEL_PATH),
            "vectorizer_file": str(VECTORIZER_PATH),
            "vectorizer": {
                "analyzer": vectorizer.analyzer,
                "ngram_range": list(vectorizer.ngram_range),
                "min_df": vectorizer.min_df,
                "sublinear_tf": vectorizer.sublinear_tf,
                "features": int(features.shape[1]),
            },
        },
        "metrics": {
            "accuracy": float(accuracy_score(actual, predicted)),
            "precision_xss": float(
                precision_score(actual, predicted, pos_label=POSITIVE_LABEL, zero_division=0)
            ),
            "recall_xss": float(
                recall_score(actual, predicted, pos_label=POSITIVE_LABEL, zero_division=0)
            ),
            "f1_xss": float(
                f1_score(actual, predicted, pos_label=POSITIVE_LABEL, zero_division=0)
            ),
        },
        "confusion_matrix": {
            "labels": [0, 1],
            "rows_actual_columns_predicted": matrix.tolist(),
            "true_negative": int(matrix[0, 0]),
            "false_positive": int(matrix[0, 1]),
            "false_negative": int(matrix[1, 0]),
            "true_positive": int(matrix[1, 1]),
        },
        "misclassifications": {
            "false_positive_count": false_positive_count,
            "false_negative_count": false_negative_count,
            "representative_false_positives": misclassified_examples(
                text, actual, predicted, probabilities, "false_positive"
            ),
            "representative_false_negatives": misclassified_examples(
                text, actual, predicted, probabilities, "false_negative"
            ),
        },
        "limitations": [
            "Results apply only to this selected dataset and held-out split.",
            "The test set is strongly imbalanced toward benign records.",
            "A correct test prediction does not prove behavior in every browser or application context.",
            "Misclassification examples are offline analysis data and were not sent to external services.",
        ],
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    predictions.to_csv(PREDICTIONS_PATH, index=False, encoding="utf-8")
    return report


if __name__ == "__main__":
    print(json.dumps(evaluate_model(), indent=2))
