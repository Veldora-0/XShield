import json
import sys
import time
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

# Allow direct execution with `python scripts\evaluate_all.py`.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.detector.hybrid_detector import detect_text as detect_hybrid_text
from app.detector.rule_engine import detect_text as detect_rule_text


TEST_PATH = PROJECT_ROOT / "data" / "processed" / "xss_test.csv"
MODEL_PATH = PROJECT_ROOT / "models" / "xss_logistic_regression.joblib"
VECTORIZER_PATH = PROJECT_ROOT / "models" / "xss_tfidf_vectorizer.joblib"
REPORTS_DIR = PROJECT_ROOT / "reports"
JSON_REPORT_PATH = REPORTS_DIR / "evaluation_results.json"
TEXT_REPORT_PATH = REPORTS_DIR / "evaluation_report.txt"
CONFUSION_MATRIX_PATHS = {
    "rule_based": REPORTS_DIR / "rule_confusion_matrix.json",
    "ml": REPORTS_DIR / "ml_confusion_matrix.json",
    "hybrid": REPORTS_DIR / "hybrid_confusion_matrix.json",
}
POSITIVE_LABEL = 1
RULE_SCORE_THRESHOLD = 1
ML_PROBABILITY_THRESHOLD = 0.35
HYBRID_SIGNAL_THRESHOLD = 0.35
REPRESENTATIVE_LIMIT = 5


def load_test_data() -> tuple[pd.Series, pd.Series]:
    frame = pd.read_csv(TEST_PATH, encoding="utf-8")
    columns = {str(column).strip().casefold(): str(column) for column in frame.columns}
    if "text" not in columns or "label" not in columns:
        raise ValueError(f"Expected text and label columns; found {list(frame.columns)}")
    text = frame[columns["text"]]
    labels = frame[columns["label"]]
    if text.isna().any() or labels.isna().any():
        raise ValueError("Evaluation data contains missing text or labels.")
    labels = labels.astype(int)
    if not set(labels.unique()).issubset({0, 1}):
        raise ValueError(f"Unexpected labels: {sorted(labels.unique())}")
    return text.astype(str), labels


def calculate_metrics(actual: pd.Series, predicted: pd.Series) -> dict:
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    return {
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
        "confusion_matrix": {
            "labels": [0, 1],
            "rows_actual_columns_predicted": matrix.tolist(),
            "true_negative": int(matrix[0, 0]),
            "false_positive": int(matrix[0, 1]),
            "false_negative": int(matrix[1, 0]),
            "true_positive": int(matrix[1, 1]),
        },
    }


def error_examples(
    text: pd.Series,
    actual: pd.Series,
    predicted: pd.Series,
    signal: pd.Series,
) -> dict:
    examples = {}
    for error_name, actual_label, predicted_label in (
        ("false_positives", 0, 1),
        ("false_negatives", 1, 0),
    ):
        rows = []
        for index in text.index:
            if int(actual.loc[index]) == actual_label and int(predicted.loc[index]) == predicted_label:
                rows.append(
                    {
                        "text": str(text.loc[index]),
                        "actual_label": int(actual.loc[index]),
                        "predicted_label": int(predicted.loc[index]),
                        "signal": float(signal.loc[index]),
                    }
                )
        examples[error_name] = rows[:REPRESENTATIVE_LIMIT]
    return examples


def evaluate_rule(text: pd.Series, actual: pd.Series) -> tuple[dict, pd.Series, pd.Series, float]:
    start = time.perf_counter()
    scores = pd.Series(
        [float(detect_rule_text(value)["score"]) for value in text],
        index=text.index,
    )
    elapsed = time.perf_counter() - start
    predicted = (scores >= RULE_SCORE_THRESHOLD).astype(int)
    result = calculate_metrics(actual, predicted)
    result["threshold"] = RULE_SCORE_THRESHOLD
    result["threshold_meaning"] = "Any positive rule score is classified as suspicious."
    return result, predicted, scores, elapsed


def evaluate_ml(
    text: pd.Series,
    actual: pd.Series,
    vectorizer,
    model,
) -> tuple[dict, pd.Series, pd.Series, float]:
    start = time.perf_counter()
    features = vectorizer.transform(text)
    probabilities = pd.Series(model.predict_proba(features)[:, POSITIVE_LABEL], index=text.index)
    elapsed = time.perf_counter() - start
    predicted = (probabilities >= ML_PROBABILITY_THRESHOLD).astype(int)
    result = calculate_metrics(actual, predicted)
    result["threshold"] = ML_PROBABILITY_THRESHOLD
    result["threshold_meaning"] = "Probability at or above 0.5 is classified as XSS."
    result["tfidf_features"] = int(features.shape[1])
    return result, predicted, probabilities, elapsed


def evaluate_hybrid(
    text: pd.Series,
    actual: pd.Series,
) -> tuple[dict, pd.Series, pd.Series, float, list[dict]]:
    start = time.perf_counter()
    results = [detect_hybrid_text(value) for value in text]
    elapsed = time.perf_counter() - start
    signals = pd.Series(
        [float(result["hybrid"]["hybrid_signal"]) for result in results],
        index=text.index,
    )
    predicted = (signals >= HYBRID_SIGNAL_THRESHOLD).astype(int)
    result = calculate_metrics(actual, predicted)
    result["threshold"] = HYBRID_SIGNAL_THRESHOLD
    result["threshold_meaning"] = "Hybrid signal at or above 0.5 is classified as XSS."
    return result, predicted, signals, elapsed, results


def evaluate_all() -> dict:
    text, actual = load_test_data()
    vectorizer = joblib.load(VECTORIZER_PATH)
    model = joblib.load(MODEL_PATH)

    rule_result, rule_predicted, rule_signal, rule_seconds = evaluate_rule(text, actual)
    ml_result, ml_predicted, ml_signal, ml_seconds = evaluate_ml(
        text, actual, vectorizer, model
    )
    hybrid_result, hybrid_predicted, hybrid_signal, hybrid_seconds, hybrid_details = (
        evaluate_hybrid(text, actual)
    )

    methods = {
        "rule_based": {
            "metrics": rule_result,
            "errors": error_examples(text, actual, rule_predicted, rule_signal),
        },
        "ml": {
            "metrics": ml_result,
            "errors": error_examples(text, actual, ml_predicted, ml_signal),
        },
        "hybrid": {
            "metrics": hybrid_result,
            "errors": error_examples(text, actual, hybrid_predicted, hybrid_signal),
        },
    }

    report = {
        "dataset": {
            "source": "HttpParamsDataset",
            "source_reference": "Kaggle/Original HttpParamsDataset repository",
            "test_file": str(TEST_PATH),
            "samples": int(len(actual)),
            "class_counts": {
                str(key): int(value)
                for key, value in actual.value_counts().sort_index().items()
            },
            "label_mapping": {"0": "BENIGN", "1": "XSS"},
            "same_test_set_for_all_methods": True,
        },
        "thresholds": {
            "rule_score": RULE_SCORE_THRESHOLD,
            "ml_probability": ML_PROBABILITY_THRESHOLD,
            "hybrid_signal": HYBRID_SIGNAL_THRESHOLD,
            "experimental": True,
            "note": "Thresholds were documented evaluation parameters and were not optimized on this test set.",
        },
        "methods": methods,
        "performance": {
            "local_measurement_only": True,
            "samples": int(len(actual)),
            "rule_total_seconds": rule_seconds,
            "ml_total_seconds": ml_seconds,
            "hybrid_total_seconds": hybrid_seconds,
            "rule_average_ms": rule_seconds / len(actual) * 1000,
            "ml_average_ms": ml_seconds / len(actual) * 1000,
            "hybrid_average_ms": hybrid_seconds / len(actual) * 1000,
        },
        "model": {
            "model_file": str(MODEL_PATH),
            "vectorizer_file": str(VECTORIZER_PATH),
            "vectorizer_fitted_on_training_only": True,
            "tfidf_features": int(len(vectorizer.vocabulary_)),
            "hybrid_weight_configuration": {
                "rule_weight": 0.5,
                "ml_weight": 0.5,
            },
        },
        "limitations": [
            "Metrics apply only to the selected HttpParamsDataset held-out test split.",
            "The test set is strongly imbalanced toward benign records.",
            "The rule threshold is an experimental binary interpretation of any matched rule.",
            "The ML and hybrid thresholds were not optimized on this test set.",
            "Local timing measurements are not production-scale performance claims.",
            "Dataset strings were processed as offline data and were not executed or sent externally.",
        ],
    }
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    JSON_REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    TEXT_REPORT_PATH.write_text(render_text_report(report), encoding="utf-8")
    for method, path in CONFUSION_MATRIX_PATHS.items():
        path.write_text(
            json.dumps(report["methods"][method]["metrics"]["confusion_matrix"], indent=2),
            encoding="utf-8",
        )
    return report


def render_text_report(report: dict) -> str:
    dataset = report["dataset"]
    lines = [
        "XShield Comparative Evaluation Report",
        "======================================",
        "",
        f"Evaluation samples: {dataset['samples']}",
        f"Class counts: {dataset['class_counts']}",
        "All methods use the same held-out test set.",
        "",
        "Metrics (positive class: XSS / label 1)",
        "---------------------------------------",
        "Method       Accuracy     Precision    Recall       F1",
    ]
    for name, label in (
        ("rule_based", "Rule-Based"),
        ("ml", "ML"),
        ("hybrid", "Hybrid"),
    ):
        metrics = report["methods"][name]["metrics"]
        lines.append(
            f"{label:<12} {metrics['accuracy']:.8f} "
            f"{metrics['precision_xss']:.8f} {metrics['recall_xss']:.8f} "
            f"{metrics['f1_xss']:.8f}"
        )
        lines.append(f"  confusion matrix: {metrics['confusion_matrix']['rows_actual_columns_predicted']}")
        lines.append(
            f"  false positives: {metrics['confusion_matrix']['false_positive']}; "
            f"false negatives: {metrics['confusion_matrix']['false_negative']}"
        )
    lines.extend(
        [
            "",
            "Thresholds",
            "----------",
            json.dumps(report["thresholds"], indent=2),
            "",
            "Local timing observations",
            "-------------------------",
            json.dumps(report["performance"], indent=2),
            "",
            "Limitations",
            "-----------",
            *[f"- {item}" for item in report["limitations"]],
        ]
    )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(json.dumps(evaluate_all(), indent=2))
