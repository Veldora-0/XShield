"""Comprehensive Evaluation and Comparison Runner for Baseline V1 vs Candidate V2.

Computes side-by-side performance on:
- Frozen Benchmark V1 (3,967 samples)
- Benchmark V2 (3,175 samples)
- Qualitative Battery (25 curated probe cases)
- Inference Latency and Model Artifact Size
Saves full report to reports/candidate_v2/evaluation_report.json.
"""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.qualitative_suite import evaluate_qualitative_suite, QUALITATIVE_TEST_CASES
from scripts.regression_gate import RegressionGate

V1_MODEL_PATH = PROJECT_ROOT / "models" / "xss_logistic_regression.joblib"
V1_VEC_PATH = PROJECT_ROOT / "models" / "xss_tfidf_vectorizer.joblib"

V2_MODEL_PATH = PROJECT_ROOT / "models" / "candidate_v2" / "xss_logistic_regression.joblib"
V2_VEC_PATH = PROJECT_ROOT / "models" / "candidate_v2" / "xss_tfidf_vectorizer.joblib"

BENCHMARK_V1_PATH = PROJECT_ROOT / "data" / "processed" / "xss_test.csv"
BENCHMARK_V2_PATH = PROJECT_ROOT / "data" / "processed" / "v2" / "benchmark_v2.csv"
REPORT_PATH = PROJECT_ROOT / "reports" / "candidate_v2" / "evaluation_report.json"


def evaluate_model_on_dataset(model, vectorizer, csv_path: Path) -> dict[str, Any]:
    texts = []
    labels = []
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = row.get("text", "")
            lbl = row.get("label", "")
            if t is not None and lbl in {"0", "1"}:
                texts.append(str(t))
                labels.append(int(lbl))

    y_true = np.array(labels, dtype=int)
    x_vec = vectorizer.transform(texts)
    y_prob = model.predict_proba(x_vec)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    return {
        "dataset": csv_path.name,
        "total_samples": len(y_true),
        "benign_samples": int(np.sum(y_true == 0)),
        "xss_samples": int(np.sum(y_true == 1)),
        "accuracy": round(acc, 5),
        "precision": round(prec, 5),
        "recall": round(rec, 5),
        "f1": round(f1, 5),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "confusion_matrix": cm.tolist(),
    }


def measure_model_latency(model, vectorizer, iterations: int = 500) -> float:
    samples = [
        "<script>alert(1)</script>",
        "Order ID: 104928 - Shipment delivered",
        '<img src=x onerror="alert(document.cookie)">',
        "Please review the JavaScript alert modal component",
    ]
    # Warm up
    for s in samples:
        model.predict_proba(vectorizer.transform([s]))

    start = time.perf_counter()
    for _ in range(iterations):
        for s in samples:
            model.predict_proba(vectorizer.transform([s]))
    elapsed = time.perf_counter() - start
    return round((elapsed / (iterations * len(samples))) * 1000.0, 3)


def run_comprehensive_evaluation() -> dict[str, Any]:
    print("Loading Baseline V1 Artifacts...")
    v1_model = joblib.load(V1_MODEL_PATH)
    v1_vec = joblib.load(V1_VEC_PATH)

    print("Loading Candidate V2 Artifacts...")
    v2_model = joblib.load(V2_MODEL_PATH)
    v2_vec = joblib.load(V2_VEC_PATH)

    # 1. Benchmark V1
    print("\nEvaluating on Frozen Benchmark V1...")
    v1_on_bm1 = evaluate_model_on_dataset(v1_model, v1_vec, BENCHMARK_V1_PATH)
    v2_on_bm1 = evaluate_model_on_dataset(v2_model, v2_vec, BENCHMARK_V1_PATH)

    # 2. Benchmark V2
    print("Evaluating on Benchmark V2...")
    v1_on_bm2 = evaluate_model_on_dataset(v1_model, v1_vec, BENCHMARK_V2_PATH)
    v2_on_bm2 = evaluate_model_on_dataset(v2_model, v2_vec, BENCHMARK_V2_PATH)

    # 3. Qualitative Suite
    print("Evaluating Qualitative Test Battery...")
    gate_v1 = RegressionGate(model_path=V1_MODEL_PATH, vectorizer_path=V1_VEC_PATH)
    gate_v2 = RegressionGate(model_path=V2_MODEL_PATH, vectorizer_path=V2_VEC_PATH)

    qual_v1 = evaluate_qualitative_suite(predict_fn=gate_v1._build_evaluator())
    qual_v2 = evaluate_qualitative_suite(predict_fn=gate_v2._build_evaluator())

    # 4. Latency
    print("Measuring Inference Latency...")
    lat_v1 = measure_model_latency(v1_model, v1_vec)
    lat_v2 = measure_model_latency(v2_model, v2_vec)

    # 5. Model Sizes & Vocab
    v1_size_kb = round(os.path.getsize(V1_MODEL_PATH) / 1024, 1) + round(os.path.getsize(V1_VEC_PATH) / 1024, 1)
    v2_size_kb = round(os.path.getsize(V2_MODEL_PATH) / 1024, 1) + round(os.path.getsize(V2_VEC_PATH) / 1024, 1)

    v1_vocab = len(v1_vec.vocabulary_)
    v2_vocab = len(v2_vec.vocabulary_)

    report = {
        "timestamp": pd.Timestamp.now(tz="UTC").isoformat(),
        "summary_comparison": {
            "vocabulary_size": {"v1": v1_vocab, "v2": v2_vocab, "delta": v2_vocab - v1_vocab},
            "artifact_size_kb": {"v1": v1_size_kb, "v2": v2_size_kb, "delta": round(v2_size_kb - v1_size_kb, 1)},
            "mean_latency_ms": {"v1": lat_v1, "v2": lat_v2, "delta": round(lat_v2 - lat_v1, 3)},
            "qualitative_pass_rate": {
                "v1": f"{qual_v1['passed_cases']}/{qual_v1['total_cases']} ({qual_v1['pass_rate_pct']}%)",
                "v2": f"{qual_v2['passed_cases']}/{qual_v2['total_cases']} ({qual_v2['pass_rate_pct']}%)",
            },
        },
        "benchmark_v1_results": {"v1_baseline": v1_on_bm1, "v2_candidate": v2_on_bm1},
        "benchmark_v2_results": {"v1_baseline": v1_on_bm2, "v2_candidate": v2_on_bm2},
        "qualitative_v1": {
            "passed": qual_v1["passed_cases"],
            "total": qual_v1["total_cases"],
            "categories": qual_v1["category_summary"],
        },
        "qualitative_v2": {
            "passed": qual_v2["passed_cases"],
            "total": qual_v2["total_cases"],
            "categories": qual_v2["category_summary"],
        },
        "regression_gate_v2": gate_v2.run_all_gates(),
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nSaved comprehensive report to {REPORT_PATH}")

    # Print summary tables
    print("\n" + "=" * 70)
    print("SIDE-BY-SIDE BENCHMARK COMPARISON: V1 BASELINE vs V2 CANDIDATE")
    print("=" * 70)
    print(f"{'Metric':<25} | {'V1 Baseline':<18} | {'V2 Candidate':<18} | {'Delta':<10}")
    print("-" * 70)

    # Benchmark V1 rows
    print(f"{'V1 BM Accuracy':<25} | {v1_on_bm1['accuracy']*100:.3f}%{'':<11} | {v2_on_bm1['accuracy']*100:.3f}%{'':<11} | {(v2_on_bm1['accuracy'] - v1_on_bm1['accuracy'])*100:+.3f}%")
    print(f"{'V1 BM Precision':<25} | {v1_on_bm1['precision']*100:.3f}%{'':<11} | {v2_on_bm1['precision']*100:.3f}%{'':<11} | {(v2_on_bm1['precision'] - v1_on_bm1['precision'])*100:+.3f}%")
    print(f"{'V1 BM Recall':<25} | {v1_on_bm1['recall']*100:.3f}%{'':<11} | {v2_on_bm1['recall']*100:.3f}%{'':<11} | {(v2_on_bm1['recall'] - v1_on_bm1['recall'])*100:+.3f}%")
    print(f"{'V1 BM F1-Score':<25} | {v1_on_bm1['f1']*100:.3f}%{'':<11} | {v2_on_bm1['f1']*100:.3f}%{'':<11} | {(v2_on_bm1['f1'] - v1_on_bm1['f1'])*100:+.3f}%")
    print(f"{'V1 BM False Positives':<25} | {v1_on_bm1['fp']:<18} | {v2_on_bm1['fp']:<18} | {v2_on_bm1['fp'] - v1_on_bm1['fp']:+d}")
    print(f"{'V1 BM False Negatives':<25} | {v1_on_bm1['fn']:<18} | {v2_on_bm1['fn']:<18} | {v2_on_bm1['fn'] - v1_on_bm1['fn']:+d}")
    print("-" * 70)

    # Benchmark V2 rows
    print(f"{'V2 BM Accuracy':<25} | {v1_on_bm2['accuracy']*100:.3f}%{'':<11} | {v2_on_bm2['accuracy']*100:.3f}%{'':<11} | {(v2_on_bm2['accuracy'] - v1_on_bm2['accuracy'])*100:+.3f}%")
    print(f"{'V2 BM Precision':<25} | {v1_on_bm2['precision']*100:.3f}%{'':<11} | {v2_on_bm2['precision']*100:.3f}%{'':<11} | {(v2_on_bm2['precision'] - v1_on_bm2['precision'])*100:+.3f}%")
    print(f"{'V2 BM Recall':<25} | {v1_on_bm2['recall']*100:.3f}%{'':<11} | {v2_on_bm2['recall']*100:.3f}%{'':<11} | {(v2_on_bm2['recall'] - v1_on_bm2['recall'])*100:+.3f}%")
    print(f"{'V2 BM F1-Score':<25} | {v1_on_bm2['f1']*100:.3f}%{'':<11} | {v2_on_bm2['f1']*100:.3f}%{'':<11} | {(v2_on_bm2['f1'] - v1_on_bm2['f1'])*100:+.3f}%")
    print(f"{'V2 BM False Positives':<25} | {v1_on_bm2['fp']:<18} | {v2_on_bm2['fp']:<18} | {v2_on_bm2['fp'] - v1_on_bm2['fp']:+d}")
    print(f"{'V2 BM False Negatives':<25} | {v1_on_bm2['fn']:<18} | {v2_on_bm2['fn']:<18} | {v2_on_bm2['fn'] - v1_on_bm2['fn']:+d}")
    print("-" * 70)

    # Qualitative and System
    print(f"{'Qualitative Battery':<25} | {qual_v1['passed_cases']}/{qual_v1['total_cases']} ({qual_v1['pass_rate_pct']}%) | {qual_v2['passed_cases']}/{qual_v2['total_cases']} ({qual_v2['pass_rate_pct']}%) | {qual_v2['passed_cases'] - qual_v1['passed_cases']:+d} cases")
    print(f"{'Inference Latency':<25} | {lat_v1:.3f} ms{'':<10} | {lat_v2:.3f} ms{'':<10} | {lat_v2 - lat_v1:+.3f} ms")
    print(f"{'Vocabulary Features':<25} | {v1_vocab:<18,} | {v2_vocab:<18,} | {v2_vocab - v1_vocab:+,}")
    print("=" * 70)

    return report


if __name__ == "__main__":
    run_comprehensive_evaluation()
