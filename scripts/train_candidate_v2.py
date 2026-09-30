"""Training Script for Candidate ML Model v2.

Trains Logistic Regression on Character TF-IDF (3-5 ngrams) using the enriched
data/processed/v2/xss_train_v2.csv dataset and saves artifacts strictly under
models/candidate_v2/.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sys
import time
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAIN_PATH = PROJECT_ROOT / "data" / "processed" / "v2" / "xss_train_v2.csv"
VAL_PATH = PROJECT_ROOT / "data" / "processed" / "v2" / "xss_val_v2.csv"
CANDIDATE_MODEL_DIR = PROJECT_ROOT / "models" / "candidate_v2"
CANDIDATE_MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_ARTIFACT_PATH = CANDIDATE_MODEL_DIR / "xss_logistic_regression.joblib"
VECTORIZER_ARTIFACT_PATH = CANDIDATE_MODEL_DIR / "xss_tfidf_vectorizer.joblib"
METADATA_PATH = CANDIDATE_MODEL_DIR / "training_metadata.json"

RANDOM_SEED = 42


def train_candidate() -> dict[str, Any]:
    print("=" * 60)
    print("STARTING CANDIDATE V2 MODEL TRAINING")
    print("=" * 60)

    # 1. Load data
    print(f"Loading training data from {TRAIN_PATH}...")
    df_train = pd.read_csv(TRAIN_PATH, encoding="utf-8")
    x_train = df_train["text"].astype(str)
    y_train = df_train["label"].astype(int)

    df_val = pd.read_csv(VAL_PATH, encoding="utf-8")
    x_val = df_val["text"].astype(str)
    y_val = df_val["label"].astype(int)

    print(f"Train samples: {len(x_train)} (Benign: {sum(y_train == 0)}, XSS: {sum(y_train == 1)})")
    print(f"Val samples:   {len(x_val)} (Benign: {sum(y_val == 0)}, XSS: {sum(y_val == 1)})")

    # 2. Vectorize
    print("\nFitting Character TF-IDF Vectorizer...")
    start_vec = time.perf_counter()
    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=2,
        sublinear_tf=True,
    )
    x_train_vec = vectorizer.fit_transform(x_train)
    vec_time = time.perf_counter() - start_vec
    vocab_size = len(vectorizer.vocabulary_)
    print(f"Vectorizer fitted in {vec_time:.2f}s. Vocabulary size: {vocab_size:,} features.")

    # 3. Train Classifier
    print("\nTraining Logistic Regression (solver='liblinear', class_weight='balanced')...")
    start_train = time.perf_counter()
    model = LogisticRegression(
        solver="liblinear",
        class_weight="balanced",
        max_iter=1000,
        random_state=RANDOM_SEED,
    )
    model.fit(x_train_vec, y_train)
    train_time = time.perf_counter() - start_train
    print(f"Model trained in {train_time:.2f}s. Iterations: {model.n_iter_[0]}")

    # 4. Evaluate on Validation Set
    print("\nEvaluating on Validation Set...")
    x_val_vec = vectorizer.transform(x_val)
    val_probs = model.predict_proba(x_val_vec)[:, 1]
    val_preds = (val_probs >= 0.5).astype(int)

    val_acc = float(accuracy_score(y_val, val_preds))
    val_prec = float(precision_score(y_val, val_preds, zero_division=0))
    val_rec = float(recall_score(y_val, val_preds, zero_division=0))
    val_f1 = float(f1_score(y_val, val_preds, zero_division=0))

    print(f"Validation Accuracy:  {val_acc * 100:.3f}%")
    print(f"Validation Precision: {val_prec * 100:.3f}%")
    print(f"Validation Recall:    {val_rec * 100:.3f}%")
    print(f"Validation F1 Score:  {val_f1 * 100:.3f}%")

    # 5. Save Artifacts strictly to models/candidate_v2/
    print(f"\nSaving candidate model artifacts to {CANDIDATE_MODEL_DIR}...")
    joblib.dump(model, MODEL_ARTIFACT_PATH)
    joblib.dump(vectorizer, VECTORIZER_ARTIFACT_PATH)

    metadata = {
        "candidate_version": "v2.0-candidate",
        "training_timestamp": pd.Timestamp.now(tz="UTC").isoformat(),
        "random_seed": RANDOM_SEED,
        "dataset": {
            "train_path": str(TRAIN_PATH),
            "val_path": str(VAL_PATH),
            "train_samples": len(x_train),
            "train_benign": int(sum(y_train == 0)),
            "train_xss": int(sum(y_train == 1)),
            "val_samples": len(x_val),
            "val_benign": int(sum(y_val == 0)),
            "val_xss": int(sum(y_val == 1)),
        },
        "vectorizer_config": {
            "analyzer": "char",
            "ngram_range": [3, 5],
            "min_df": 2,
            "sublinear_tf": True,
            "vocabulary_size": vocab_size,
        },
        "classifier_config": {
            "model_type": "LogisticRegression",
            "solver": "liblinear",
            "class_weight": "balanced",
            "max_iter": 1000,
            "random_state": RANDOM_SEED,
            "iterations_run": int(model.n_iter_[0]),
        },
        "validation_metrics": {
            "accuracy": val_acc,
            "precision": val_prec,
            "recall": val_rec,
            "f1": val_f1,
        },
        "artifact_paths": {
            "model": str(MODEL_ARTIFACT_PATH),
            "vectorizer": str(VECTORIZER_ARTIFACT_PATH),
        },
    }

    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Saved metadata to {METADATA_PATH}")
    print("=" * 60)
    print("CANDIDATE V2 MODEL TRAINING COMPLETE")
    print("=" * 60)
    return metadata


if __name__ == "__main__":
    train_candidate()
