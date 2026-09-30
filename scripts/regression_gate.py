"""Automated Candidate Evaluation & Regression Gate for ML Benchmark v2.

This module acts as an automated quality gate. It verifies that any candidate ML model
strictly avoids regressions against Benchmark v1 (zero false positives, recall >= 96.2%),
meets Benchmark v2 targets, passes all qualitative probes, and stays within latency bounds.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sys
import time
from typing import Any, Callable

import joblib
import numpy as np

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.qualitative_suite import evaluate_qualitative_suite, QUALITATIVE_TEST_CASES


# Gate thresholds and criteria
V1_MAX_FALSE_POSITIVES = 0
V1_MIN_RECALL = 0.96226  # Baseline is 96.226% (102/106)
V2_MIN_PRECISION = 0.990
V2_MIN_RECALL = 0.950
QUALITATIVE_BENIGN_MIN_PASS = 1.0  # Zero false positives allowed on benign categories
QUALITATIVE_MALICIOUS_MIN_PASS = 0.89  # Baseline is 17/19 = 89.47%
MAX_MEAN_INFERENCE_MS = 2.0  # Latency limit per payload


class RegressionGate:
    """Evaluates candidate models against strict regression and security criteria."""

    def __init__(
        self,
        model_path: Path | str | None = None,
        vectorizer_path: Path | str | None = None,
        v1_test_path: Path | str = PROJECT_ROOT / "data" / "processed" / "xss_test.csv",
        v2_test_path: Path | str = PROJECT_ROOT / "data" / "processed" / "v2" / "benchmark_v2.csv",
    ) -> None:
        self.model_path = Path(model_path) if model_path else PROJECT_ROOT / "models" / "xss_logistic_regression.joblib"
        self.vectorizer_path = Path(vectorizer_path) if vectorizer_path else PROJECT_ROOT / "models" / "xss_tfidf_vectorizer.joblib"
        self.v1_test_path = Path(v1_test_path)
        self.v2_test_path = Path(v2_test_path)

        self.model = None
        self.vectorizer = None
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        if self.model_path.exists() and self.vectorizer_path.exists():
            self.model = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)

    def evaluate_dataset(self, csv_path: Path) -> dict[str, Any]:
        """Compute precision, recall, confusion matrix, and accuracy on a benchmark CSV."""
        if not csv_path.exists():
            raise FileNotFoundError(f"Benchmark dataset not found: {csv_path}")
        if self.model is None or self.vectorizer is None:
            raise RuntimeError("Model and vectorizer artifacts must be loaded.")

        texts = []
        actuals = []
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                t = row.get("text", "")
                lbl = row.get("label", "")
                if t is not None and lbl in {"0", "1"}:
                    texts.append(str(t))
                    actuals.append(int(lbl))

        y_true = np.array(actuals, dtype=int)
        x_vec = self.vectorizer.transform(texts)
        y_prob = self.model.predict_proba(x_vec)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)

        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))

        accuracy = float((tp + tn) / len(y_true)) if len(y_true) > 0 else 0.0
        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        return {
            "total_samples": len(y_true),
            "accuracy": round(accuracy, 5),
            "precision": round(precision, 5),
            "recall": round(recall, 5),
            "f1": round(f1, 5),
            "true_positive": tp,
            "false_positive": fp,
            "true_negative": tn,
            "false_negative": fn,
        }

    def measure_latency(self, iterations: int = 200) -> float:
        """Measure average per-sample inference latency in milliseconds."""
        if self.model is None or self.vectorizer is None:
            raise RuntimeError("Model and vectorizer artifacts must be loaded.")

        sample_inputs = [
            "<script>alert(1)</script>",
            "Order ID: 104928 - Shipment delivered",
            '<img src=x onerror="alert(document.cookie)">',
            "Please review the JavaScript alert modal",
        ]
        # Warm up
        for s in sample_inputs:
            vec = self.vectorizer.transform([s])
            self.model.predict_proba(vec)

        start_time = time.perf_counter()
        total_predictions = 0
        for _ in range(iterations):
            for s in sample_inputs:
                vec = self.vectorizer.transform([s])
                self.model.predict_proba(vec)
                total_predictions += 1
        elapsed = time.perf_counter() - start_time
        mean_ms = (elapsed / total_predictions) * 1000.0
        return round(mean_ms, 3)

    def _build_evaluator(self) -> Callable[[str], dict[str, Any]]:
        """Construct a hybrid prediction function bound to this gate's model and vectorizer."""
        from app.detector.rule_engine import detect_text as detect_rule_text
        from app.risk.risk_engine import assess_risk
        from app.response.action_engine import assess_action

        model = self.model
        vectorizer = self.vectorizer

        def evaluator(text: str) -> dict[str, Any]:
            rule_result = detect_rule_text(text)
            x_vec = vectorizer.transform([text])
            prob = float(model.predict_proba(x_vec)[0, 1])
            ml_result = {
                "prediction": "xss" if prob >= 0.5 else "benign",
                "probability": prob,
                "label": 1 if prob >= 0.5 else 0,
            }
            normalized_rule_score = max(0.0, min(1.0, rule_result["score"] / 100))
            hybrid_signal = max(0.0, min(1.0, 0.5 * normalized_rule_score + 0.5 * prob))
            agreement = (
                "both_suspicious" if rule_result["is_suspicious"] and prob >= 0.5
                else "rule_only" if rule_result["is_suspicious"]
                else "ml_only" if prob >= 0.5
                else "both_benign"
            )
            hybrid_dict = {
                "rule_result": rule_result,
                "ml_result": ml_result,
                "hybrid": {
                    "rule_score_normalized": normalized_rule_score,
                    "ml_score": prob,
                    "rule_weight": 0.5,
                    "ml_weight": 0.5,
                    "rule_contribution": 0.5 * normalized_rule_score,
                    "ml_contribution": 0.5 * prob,
                    "hybrid_signal": hybrid_signal,
                    "agreement": agreement,
                },
            }
            risk_result = assess_risk(hybrid_dict)
            action_result = assess_action(risk_result)
            return {
                "ml_probability": prob,
                "rule_suspicious": rule_result["is_suspicious"],
                "action": action_result["action"],
                "risk_level": risk_result["risk_level"],
                "risk_score": risk_result["risk_score"],
            }

        return evaluator

    def run_all_gates(self) -> dict[str, Any]:
        """Run all regression gates and return a formal pass/fail certification."""
        violations = []
        gate_results: dict[str, Any] = {}

        # Gate 1: Benchmark v1 Evaluation
        v1_metrics = self.evaluate_dataset(self.v1_test_path)
        gate_results["benchmark_v1"] = v1_metrics

        if v1_metrics["false_positive"] > V1_MAX_FALSE_POSITIVES:
            violations.append(
                f"Gate 1 Failed (V1 Precision): {v1_metrics['false_positive']} false positives detected (max allowed: {V1_MAX_FALSE_POSITIVES})."
            )
        if v1_metrics["recall"] < V1_MIN_RECALL:
            violations.append(
                f"Gate 1 Failed (V1 Recall): Recall {v1_metrics['recall']} is below baseline threshold {V1_MIN_RECALL} (FN: {v1_metrics['false_negative']})."
            )

        # Gate 2: Benchmark v2 Evaluation (optional until dataset is created)
        if self.v2_test_path.exists():
            v2_metrics = self.evaluate_dataset(self.v2_test_path)
            gate_results["benchmark_v2"] = v2_metrics
            if v2_metrics["precision"] < V2_MIN_PRECISION:
                violations.append(
                    f"Gate 2 Failed (V2 Precision): {v2_metrics['precision']} is below required {V2_MIN_PRECISION}."
                )
            if v2_metrics["recall"] < V2_MIN_RECALL:
                violations.append(
                    f"Gate 2 Failed (V2 Recall): {v2_metrics['recall']} is below required {V2_MIN_RECALL}."
                )
        else:
            gate_results["benchmark_v2"] = {"status": "SKIPPED_NOT_YET_BUILT"}

        # Gate 3: Qualitative Test Battery
        eval_fn = self._build_evaluator()
        qual_report = evaluate_qualitative_suite(predict_fn=eval_fn)
        gate_results["qualitative_suite"] = {
            "total": qual_report["total_cases"],
            "passed": qual_report["passed_cases"],
            "pass_rate_pct": qual_report["pass_rate_pct"],
            "category_summary": qual_report["category_summary"],
        }

        # Check qualitative benign preservation (Categories G and H)
        benign_passed = True
        for cat in ("G", "H"):
            cat_stats = qual_report["category_summary"].get(cat, {})
            if cat_stats.get("failed", 0) > 0:
                benign_passed = False
                violations.append(
                    f"Gate 3 Failed (Qualitative Benign): Category {cat} ({cat_stats.get('category_name')}) had {cat_stats.get('failed')} failures."
                )

        # Check qualitative malicious defense
        malicious_total = sum(
            stats["total"]
            for cat, stats in qual_report["category_summary"].items()
            if cat not in ("G", "H")
        )
        malicious_passed = sum(
            stats["passed"]
            for cat, stats in qual_report["category_summary"].items()
            if cat not in ("G", "H")
        )
        malicious_rate = malicious_passed / malicious_total if malicious_total > 0 else 0.0
        if malicious_rate < QUALITATIVE_MALICIOUS_MIN_PASS:
            violations.append(
                f"Gate 3 Failed (Qualitative Malicious): Pass rate {round(malicious_rate*100, 1)}% is below minimum {round(QUALITATIVE_MALICIOUS_MIN_PASS*100, 1)}%."
            )

        # Gate 4: Latency constraint
        latency_ms = self.measure_latency()
        gate_results["mean_latency_ms"] = latency_ms
        if latency_ms > MAX_MEAN_INFERENCE_MS:
            violations.append(
                f"Gate 4 Failed (Latency): Mean inference {latency_ms} ms exceeds limit {MAX_MEAN_INFERENCE_MS} ms."
            )

        passed_overall = len(violations) == 0
        verdict = "ACCEPT_CANDIDATE" if passed_overall else "REJECT_CANDIDATE"

        return {
            "verdict": verdict,
            "passed": passed_overall,
            "violations": violations,
            "violation_count": len(violations),
            "gate_results": gate_results,
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run regression gates on baseline or candidate ML model.")
    parser.add_argument("--candidate", action="store_true", help="Evaluate models/candidate_v2/ artifacts.")
    args = parser.parse_args()

    if args.candidate:
        cand_model = PROJECT_ROOT / "models" / "candidate_v2" / "xss_logistic_regression.joblib"
        cand_vec = PROJECT_ROOT / "models" / "candidate_v2" / "xss_tfidf_vectorizer.joblib"
        print(f"Evaluating CANDIDATE V2 artifacts at {cand_model}...")
        gate = RegressionGate(model_path=cand_model, vectorizer_path=cand_vec)
    else:
        print("Evaluating BASELINE PRODUCTION artifacts...")
        gate = RegressionGate()

    result = gate.run_all_gates()
    print("=" * 60)
    print(f"XSHIELD REGRESSION GATE VERDICT: {result['verdict']}")
    print("=" * 60)
    if result["passed"]:
        print("All regression criteria successfully satisfied.")
    else:
        print(f"FAILED with {result['violation_count']} violation(s):")
        for v in result["violations"]:
            print(f"  - {v}")
    print("\nSummary Metrics:")
    print(f"  V1 Test: Precision={result['gate_results']['benchmark_v1']['precision']}, Recall={result['gate_results']['benchmark_v1']['recall']}, FP={result['gate_results']['benchmark_v1']['false_positive']}, FN={result['gate_results']['benchmark_v1']['false_negative']}")
    if "benchmark_v2" in result["gate_results"] and "precision" in result["gate_results"]["benchmark_v2"]:
        v2_res = result["gate_results"]["benchmark_v2"]
        print(f"  V2 Benchmark: Precision={v2_res['precision']}, Recall={v2_res['recall']}, FP={v2_res['false_positive']}, FN={v2_res['false_negative']}")
    print(f"  Qualitative Pass Rate: {result['gate_results']['qualitative_suite']['pass_rate_pct']}% ({result['gate_results']['qualitative_suite']['passed']}/{result['gate_results']['qualitative_suite']['total']})")
    print(f"  Mean Latency: {result['gate_results']['mean_latency_ms']} ms/sample")
